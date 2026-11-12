#!/usr/bin/env python3
"""
Backend de gestion avancée des permissions pour cockpit-zfs.

Usage :  zfs-permissions.py <commande> '<json des paramètres>'

Toujours imprime un objet JSON (ASCII, noms non UTF-8 échappés) sur stdout :
    {"ok": true, ...}            en cas de succès
    {"ok": false, "error": ...}  en cas d'échec (code de sortie 0 pour que
                                 l'interface puisse afficher le message)

Commandes :
    inspect          état d'un chemin (propriétés ZFS, mode, ACL, xattrs, attributs)
    audit            parcours et détection d'anomalies de permissions
    set-acl          édition d'ACL POSIX (set / modify / remove), récursif ou non
    reset            réinitialisation des permissions (plusieurs méthodes, voir RESET_METHODS)
    backups          liste des sauvegardes de permissions
    delete-backup    suppression d'une sauvegarde
    delegation       liste des délégations « zfs allow » d'un dataset
    delegate         ajout / retrait d'une délégation « zfs allow / zfs unallow »
    preset           application d'un préréglage de propriétés ACL sur un dataset

Toutes les commandes qui modifient quelque chose acceptent "dry_run": true
(valeur par défaut), qui renvoie le plan sans rien écrire.

Sécurité (le script tourne en root sur des arbres où des utilisateurs écrivent) :
  - le parcours et toutes les modifications se font par descripteurs de
    fichiers ouverts composant par composant avec O_NOFOLLOW : un dossier
    remplacé par un lien symbolique pendant l'opération ne peut pas rediriger
    une écriture hors de l'arbre ;
  - seuls les fichiers réguliers et les dossiers sont ouverts (jamais les
    périphériques, FIFO ou sockets) ;
  - les ACL POSIX sont lues / écrites directement dans les xattrs
    system.posix_acl_access / system.posix_acl_default du descripteur ;
  - les datasets enfants ne sont pas traversés sauf demande explicite ;
  - écriture refusée sur un chemin contenant un lien symbolique, sur / et sur
    les datasets système (montés sur /, /usr, /var…).
"""

import base64
import errno
import fcntl
import fnmatch
import grp
import gzip
import json
import os
import pwd
import re
import stat
import struct
import subprocess
import sys
import time

BACKUP_DIR = os.environ.get("COCKPIT_ZFS_PERM_BACKUP_DIR", "/var/lib/cockpit-zfs/permission-backups")
SAMPLE_LIMIT = 50
FINDING_LIMIT = 200

FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x00000010
FS_APPEND_FL = 0x00000020
PROTECT_FLAGS = FS_IMMUTABLE_FL | FS_APPEND_FL

ACL_PROPS = [
    "type", "mountpoint", "mounted", "readonly", "acltype", "aclmode",
    "aclinherit", "xattr", "dnodesize", "casesensitivity", "normalization",
    "utf8only",
]

NTACL_XATTR = "security.NTACL"
DOSATTRIB_XATTR = "user.DOSATTRIB"
ACCESS_XATTR = "system.posix_acl_access"
DEFAULT_XATTR = "system.posix_acl_default"

OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
OPEN_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC

SPECIAL_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX

# Points de montage de datasets « système » sur lesquels l'écriture est refusée
SYSTEM_MOUNTS = {
    "/", "/etc", "/usr", "/usr/local", "/var", "/var/lib", "/var/log", "/var/cache",
    "/var/tmp", "/var/spool", "/var/mail", "/boot", "/root", "/bin", "/sbin", "/lib",
    "/lib32", "/lib64", "/libx32", "/opt", "/srv", "/tmp", "/run", "/proc", "/sys", "/dev",
}

PRESETS = {
    "posixacl-smb": {
        "label": "ACL POSIX pour SMB (Samba / ksmbd acl_xattr)",
        "props": {"acltype": "posixacl", "xattr": "sa", "dnodesize": "auto"},
    },
    "noacl-unix": {
        "label": "Droits Unix seulement (noacl)",
        "props": {"acltype": "off", "xattr": "sa"},
    },
    "macos-smb": {
        "label": "Partage fréquenté par macOS (streams en xattr SA)",
        "props": {"xattr": "sa", "dnodesize": "auto", "normalization": None},
    },
    "nfsv4": {
        "label": "ACL NFSv4 (FreeBSD / forks TrueNAS seulement)",
        "props": {"acltype": "nfsv4", "aclmode": "passthrough", "aclinherit": "passthrough", "xattr": "sa"},
    },
}

# valeurs équivalentes renvoyées par les différentes versions d'OpenZFS
PROP_ALIASES = {"acltype": {"posix": "posixacl", "noacl": "off"}}

ZFS_DELEGATION_PERMS = [
    "allow", "clone", "create", "destroy", "diff", "hold", "load-key", "change-key",
    "mount", "promote", "receive", "release", "rename", "rollback", "send", "share",
    "snapshot", "bookmark", "groupquota", "groupobjquota", "groupused", "groupobjused",
    "projectid", "projectquota", "projectobjquota", "projectused", "projectobjused",
    "userprop", "userquota", "userobjquota", "userused", "userobjused",
    "aclinherit", "aclmode", "acltype", "atime", "canmount", "casesensitivity",
    "checksum", "compression", "copies", "dedup", "devices", "dnodesize", "exec",
    "filesystem_limit", "keyformat", "keylocation", "logbias", "mountpoint",
    "nbmand", "normalization", "primarycache", "quota", "readonly", "recordsize",
    "refquota", "refreservation", "relatime", "reservation", "secondarycache",
    "setuid", "sharenfs", "sharesmb", "snapdir", "snapshot_limit", "special_small_blocks",
    "sync", "utf8only", "version", "volblocksize", "volsize", "vscan", "xattr", "zoned",
]

RESET_METHODS = {
    "unix-mode": "Mode Unix uniforme (propriétaire, groupe, modes fichiers/dossiers, setgid)",
    "strip-acl": "Retirer toutes les ACL étendues, garder le mode",
    "acl-template": "Appliquer un modèle d'ACL (entrées nommées + ACL par défaut héritables)",
    "inherit-parent": "Propager l'ACL par défaut du dossier racine (comme « remplacer les permissions enfants »)",
    "mirror-reference": "Copier les permissions d'un fichier / dossier de référence",
    "from-snapshot": "Restaurer propriétaires, modes et ACL depuis un snapshot ZFS (sans toucher aux données)",
    "from-backup": "Restaurer une sauvegarde de permissions",
    "clear-ntacl": "Effacer les ACL NT stockées par Samba / ksmbd (security.NTACL, option DOSATTRIB)",
    "orphans": "Réattribuer les fichiers dont l'UID / GID n'existe plus",
    "takeown": "Changer propriétaire / groupe récursivement sans toucher aux modes",
    "chattr-clear": "Retirer les attributs immutable / append-only",
}


class PermError(Exception):
    pass


# --------------------------------------------------------------------------- utilitaires

def run(cmd, check=True):
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = proc.stdout.decode("utf-8", "surrogateescape")
    err = proc.stderr.decode("utf-8", "replace")
    if check and proc.returncode != 0:
        raise PermError("%s : %s" % (" ".join(cmd[:3]), err.strip() or "code %d" % proc.returncode))
    return proc.returncode, out, err


_uid_cache, _gid_cache = {}, {}


def uid_name(uid):
    if uid not in _uid_cache:
        try:
            _uid_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _uid_cache[uid] = None
    return _uid_cache[uid]


def gid_name(gid):
    if gid not in _gid_cache:
        try:
            _gid_cache[gid] = grp.getgrgid(gid).gr_name
        except KeyError:
            _gid_cache[gid] = None
    return _gid_cache[gid]


def _check_name(name, what):
    if not name or "\n" in name or ":" in name or "," in name or name.startswith("-"):
        raise PermError("%s invalide : %r" % (what, name))


def resolve_uid(owner, allow_empty=True):
    if owner is None or owner == "":
        if allow_empty:
            return -1
        raise PermError("Utilisateur requis")
    owner = str(owner)
    if owner.isdigit():
        return int(owner)
    _check_name(owner, "Utilisateur")
    try:
        return pwd.getpwnam(owner).pw_uid
    except KeyError:
        raise PermError("Utilisateur inconnu : %s" % owner)


def resolve_gid(group, allow_empty=True):
    if group is None or group == "":
        if allow_empty:
            return -1
        raise PermError("Groupe requis")
    group = str(group)
    if group.isdigit():
        return int(group)
    _check_name(group, "Groupe")
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        raise PermError("Groupe inconnu : %s" % group)


def parse_mode(value, name):
    if value is None or value == "":
        return None
    try:
        mode = int(str(value), 8)
    except ValueError:
        raise PermError("%s invalide (octal attendu) : %s" % (name, value))
    if mode < 0 or mode > 0o7777:
        raise PermError("%s hors limites : %s" % (name, value))
    return mode


def mode_str(mode):
    return "%04o" % stat.S_IMODE(mode)


def b64(data):
    return None if data is None else base64.b64encode(data).decode("ascii")


def unb64(text):
    return None if text is None else base64.b64decode(text)


def fd_getxattr(fd, name):
    try:
        return os.getxattr(fd, name)
    except OSError as e:
        if e.errno in (errno.ENODATA, errno.EOPNOTSUPP, errno.ENOTSUP):
            return None
        raise


def fd_removexattr(fd, name):
    try:
        os.removexattr(fd, name)
    except OSError as e:
        if e.errno not in (errno.ENODATA, errno.EOPNOTSUPP, errno.ENOTSUP):
            raise


def get_fsflags_fd(fd):
    try:
        buf = fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack("i", 0))
        return struct.unpack("i", buf)[0]
    except OSError:
        return None


def set_fsflags_fd(fd, flags):
    fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack("i", flags))


# --------------------------------------------------------------------------- ACL POSIX (format xattr)

ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
ACL_UNDEFINED_ID = 0xFFFFFFFF
TAG_NAMES = {ACL_USER_OBJ: ("user", False), ACL_USER: ("user", True), ACL_GROUP_OBJ: ("group", False),
             ACL_GROUP: ("group", True), ACL_MASK: ("mask", False), ACL_OTHER: ("other", False)}


def decode_acl(raw):
    """xattr posix_acl v2 → liste de (tag, perm, id|None)."""
    if not raw or len(raw) < 4:
        return []
    (version,) = struct.unpack_from("<I", raw, 0)
    if version != 2:
        raise PermError("Format d'ACL inconnu (version %d)" % version)
    out = []
    for off in range(4, len(raw) - 7, 8):
        tag, perm, ident = struct.unpack_from("<HHI", raw, off)
        out.append((tag, perm & 7, ident if tag in (ACL_USER, ACL_GROUP) else None))
    return out


def encode_acl(entries):
    ents = sorted(entries, key=lambda e: (e[0], e[2] if e[2] is not None else 0))
    data = struct.pack("<I", 2)
    for tag, perm, ident in ents:
        data += struct.pack("<HHI", tag, perm & 7, ident if ident is not None else ACL_UNDEFINED_ID)
    return data


def base_from_mode(mode):
    return [(ACL_USER_OBJ, (mode >> 6) & 7, None), (ACL_GROUP_OBJ, (mode >> 3) & 7, None),
            (ACL_OTHER, mode & 7, None)]


def acl_get(acl, tag):
    for e in acl:
        if e[0] == tag:
            return e[1]
    return None


def is_minimal(acl):
    return not any(e[0] in (ACL_USER, ACL_GROUP, ACL_MASK) for e in acl)


def with_mask(acl, explicit_mask=None):
    """Recalcule le masque (union de la classe groupe) comme setfacl, ou le retire
    s'il n'y a plus d'entrées nommées."""
    named = [e for e in acl if e[0] in (ACL_USER, ACL_GROUP)]
    acl = [e for e in acl if e[0] != ACL_MASK]
    if not named:
        return acl
    if explicit_mask is None:
        explicit_mask = 0
        for e in acl:
            if e[0] in (ACL_USER, ACL_GROUP, ACL_GROUP_OBJ):
                explicit_mask |= e[1]
    return acl + [(ACL_MASK, explicit_mask, None)]


def read_access(fd, st):
    raw = fd_getxattr(fd, ACCESS_XATTR)
    return decode_acl(raw) if raw else base_from_mode(st.st_mode)


def read_default(fd):
    raw = fd_getxattr(fd, DEFAULT_XATTR)
    return decode_acl(raw) if raw else []


def write_access(fd, acl):
    """Écrit l'ACL d'accès ; une ACL minimale devient un simple mode (bits spéciaux conservés)."""
    if is_minimal(acl):
        cur = os.fstat(fd).st_mode
        mode = (stat.S_IMODE(cur) & SPECIAL_BITS) | (acl_get(acl, ACL_USER_OBJ) << 6) \
            | (acl_get(acl, ACL_GROUP_OBJ) << 3) | acl_get(acl, ACL_OTHER)
        os.fchmod(fd, mode)
        fd_removexattr(fd, ACCESS_XATTR)
    else:
        os.setxattr(fd, ACCESS_XATTR, encode_acl(acl))


def write_default(fd, acl):
    if not acl:
        fd_removexattr(fd, DEFAULT_XATTR)
    else:
        os.setxattr(fd, DEFAULT_XATTR, encode_acl(acl))


def strip_access(fd, st):
    """Équivalent de setfacl -b sur l'ACL d'accès : le groupe reprend l'entrée
    group:: réelle (et non le masque)."""
    acl = read_access(fd, st)
    if is_minimal(acl) and fd_getxattr(fd, ACCESS_XATTR) is None:
        return False
    base = [e for e in acl if e[0] in (ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_OTHER)]
    write_access(fd, base)
    return True


def parse_perms(perms):
    """'rwX' → (bits, x_conditionnel)."""
    if not isinstance(perms, str) or not re.fullmatch(r"[r-][w-][xX-]", perms):
        raise PermError("Permissions invalides : %r (format rwx)" % (perms,))
    bits = (4 if perms[0] == "r" else 0) | (2 if perms[1] == "w" else 0) | (1 if perms[2] == "x" else 0)
    return bits, perms[2] == "X"


def resolve_x(bits, cond, is_dir, st_mode):
    """X : exécution seulement pour un dossier ou un fichier déjà exécutable."""
    if cond and (is_dir or st_mode & 0o111):
        bits |= 1
    return bits


def ui_entries_to_acl(entries, is_dir, st_mode, x_to_cond=False):
    """Entrées de l'interface ({tag, qualifier, perms}) → ACL interne."""
    acl = {}
    mask = None
    for e in entries:
        tag = e.get("tag")
        qual = str(e.get("qualifier") or e.get("name") or "")
        perms = e.get("perms", "---")
        if x_to_cond:
            perms = perms.replace("x", "X")
        bits, cond = parse_perms(perms)
        bits = resolve_x(bits, cond, is_dir, st_mode)
        if tag == "user":
            key = (ACL_USER, resolve_uid(qual, False)) if qual else (ACL_USER_OBJ, None)
        elif tag == "group":
            key = (ACL_GROUP, resolve_gid(qual, False)) if qual else (ACL_GROUP_OBJ, None)
        elif tag == "mask":
            if qual:
                raise PermError("mask ne prend pas de qualificatif")
            mask = bits
            continue
        elif tag == "other":
            if qual:
                raise PermError("other ne prend pas de qualificatif")
            key = (ACL_OTHER, None)
        else:
            raise PermError("Étiquette d'ACL invalide : %r" % (tag,))
        acl[key] = (key[0], bits, key[1])
    return list(acl.values()), mask


def fill_base(acl, reference):
    have_tags = {e[0] for e in acl}
    for tag in (ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_OTHER):
        if tag not in have_tags:
            acl.append((tag, acl_get(reference, tag) or 0, None))
    return acl


def acl_to_ui(acl):
    out = []
    for tag, perm, ident in sorted(acl, key=lambda e: (e[0], e[2] or 0)):
        name, named = TAG_NAMES.get(tag, ("?", False))
        qual = ""
        if named:
            n = uid_name(ident) if tag == ACL_USER else gid_name(ident)
            qual = n if n is not None else str(ident)
        out.append({"tag": name, "qualifier": qual,
                    "perms": ("r" if perm & 4 else "-") + ("w" if perm & 2 else "-") + ("x" if perm & 1 else "-")})
    return out


def resolve_x_acl(acl, is_dir, st_mode):
    """Applique X sur une ACL interne dont les bits x viennent d'un modèle « dossier »."""
    if is_dir or st_mode & 0o111:
        return acl
    return [(t, p & 6, i) for (t, p, i) in acl]


# --------------------------------------------------------------------------- ZFS

def zfs_filesystems():
    _c, out, _e = run(["zfs", "list", "-H", "-p", "-t", "filesystem", "-o", "name,mountpoint,mounted"])
    result = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2] == "yes" and parts[1].startswith("/"):
            result.append((parts[0], parts[1]))
    return result


def dataset_for_path(path, filesystems=None):
    best = None
    for name, mnt in filesystems if filesystems is not None else zfs_filesystems():
        if path == mnt or path.startswith(mnt.rstrip("/") + "/"):
            if best is None or len(mnt) > len(best[1]):
                best = (name, mnt)
    return best


def zfs_props(dataset):
    _c, out, _e = run(["zfs", "get", "-H", "-p", "-o", "property,value,source", ",".join(ACL_PROPS), dataset])
    props = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            props[parts[0]] = {"value": parts[1], "source": parts[2]}
    return props


def norm_prop(prop, value):
    return PROP_ALIASES.get(prop, {}).get(value, value)


def acl_mode_for(dataset):
    value = norm_prop("acltype", zfs_props(dataset).get("acltype", {}).get("value", "off"))
    if value == "posixacl":
        return "posix"
    if value == "nfsv4":
        return "nfsv4"
    return "off"


# --------------------------------------------------------------------------- ouverture sûre

def safe_open_child(dfd, name, want=None):
    """Ouvre `name` relatif à `dfd` sans suivre de lien ; seulement fichier régulier
    ou dossier ; vérifie que l'objet ouvert est celui vu par lstat.
    Retourne (fd, fstat) ou lève OSError / PermError."""
    st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    if stat.S_ISLNK(st.st_mode):
        raise PermError("lien symbolique refusé : %s" % name)
    is_dir = stat.S_ISDIR(st.st_mode)
    if not is_dir and not stat.S_ISREG(st.st_mode):
        raise PermError("type de fichier non géré : %s" % name)
    if want == "d" and not is_dir:
        raise PermError("dossier attendu : %s" % name)
    if want == "f" and is_dir:
        raise PermError("fichier attendu : %s" % name)
    fd = os.open(name, OPEN_DIR if is_dir else OPEN_FILE, dir_fd=dfd)
    fst = os.fstat(fd)
    if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
        os.close(fd)
        raise PermError("objet modifié pendant l'opération : %s" % name)
    return fd, fst


def open_nofollow(path, want=None):
    """Ouvre un chemin absolu composant par composant, sans jamais suivre de lien."""
    path = os.path.normpath(path)
    if not path.startswith("/"):
        raise PermError("Chemin absolu attendu")
    fd = os.open("/", OPEN_DIR)
    if path == "/":
        return fd, os.fstat(fd)
    comps = path.strip("/").split("/")
    try:
        for i, comp in enumerate(comps):
            last = i == len(comps) - 1
            try:
                nfd, nst = safe_open_child(fd, comp, want if last else "d")
            except OSError as e:
                raise PermError("%s : %s" % ("/" + "/".join(comps[:i + 1]), e.strerror))
            except PermError as e:
                raise PermError("%s : %s" % ("/" + "/".join(comps[:i + 1]), e))
            os.close(fd)
            fd = nfd
        return fd, nst
    except BaseException:
        os.close(fd)
        raise


def open_rel(root_fd, rel, root_dev=None, want=None):
    """Ouvre `rel` (relatif, séparé par /) sous root_fd sans suivre de lien.
    Si root_dev est fourni, refuse de sortir du système de fichiers racine."""
    if rel in (".", ""):
        fd = os.dup(root_fd)
        return fd, os.fstat(fd)
    comps = [c for c in rel.split("/") if c not in ("", ".")]
    if ".." in comps:
        raise PermError("chemin relatif invalide : %s" % rel)
    fd = os.dup(root_fd)
    try:
        for i, comp in enumerate(comps):
            last = i == len(comps) - 1
            nfd, nst = safe_open_child(fd, comp, want if last else "d")
            os.close(fd)
            fd = nfd
            if root_dev is not None and nst.st_dev != root_dev:
                raise PermError("dans un autre dataset : %s" % rel)
        return fd, nst
    except BaseException:
        os.close(fd)
        raise


# --------------------------------------------------------------------------- cible

class Target:
    def __init__(self, path, dataset, mountpoint, filesystems):
        self.path = path
        self.dataset = dataset
        self.mountpoint = mountpoint
        self.fd = None
        self.st = None
        self.zfs_devs = set()
        self.mount_roots = set()
        for _n, mnt in filesystems:
            try:
                s = os.stat(mnt)
                self.zfs_devs.add(s.st_dev)
                self.mount_roots.add((s.st_dev, s.st_ino))
            except OSError:
                pass

    def open(self):
        self.fd, self.st = open_nofollow(self.path)
        return self

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def resolve_target(params, write=False, path_key="path"):
    path = params.get(path_key)
    if not path and params.get("dataset"):
        path = zfs_props(params["dataset"]).get("mountpoint", {}).get("value")
    if not path:
        raise PermError("Aucun chemin ni dataset fourni")
    if not os.path.isabs(path):
        raise PermError("Chemin absolu attendu : %s" % path)
    norm = os.path.normpath(path)
    real = os.path.realpath(path)
    if write and real != norm:
        raise PermError("%s contient un lien symbolique (cible réelle : %s) : refusé en écriture" % (norm, real))
    target_path = norm if write else real
    if not os.path.lexists(target_path):
        raise PermError("Chemin introuvable : %s" % target_path)
    filesystems = zfs_filesystems()
    ds = dataset_for_path(target_path, filesystems)
    if ds is None:
        raise PermError("%s n'est pas dans un système de fichiers ZFS monté" % target_path)
    if write:
        if target_path == "/":
            raise PermError("Refus d'agir sur /")
        if "/.zfs/" in target_path + "/":
            raise PermError("Les snapshots (.zfs) sont en lecture seule")
        if ds[1] in SYSTEM_MOUNTS and not params.get("allow_system"):
            raise PermError("%s est dans le dataset système %s (monté sur %s) : refusé" % (target_path, ds[0], ds[1]))
    return Target(target_path, ds[0], ds[1], filesystems)


# --------------------------------------------------------------------------- parcours par descripteurs

class Entry:
    __slots__ = ("path", "rel", "fd", "st", "is_dir")

    def __init__(self, path, rel, fd, st):
        self.path = path
        self.rel = rel
        self.fd = fd
        self.st = st
        self.is_dir = stat.S_ISDIR(st.st_mode)


def _race_hook(rel, root_path):
    """Hook de test : COCKPIT_ZFS_PERM_TEST_RACE='{"trigger": rel, "swap": rel, "target": chemin}'
    remplace un dossier par un lien symbolique juste avant l'ouverture de `trigger`."""
    spec = os.environ.get("COCKPIT_ZFS_PERM_TEST_RACE")
    if not spec:
        return
    cfg = json.loads(spec)
    if cfg.get("done") or cfg.get("trigger") != rel:
        return
    victim = os.path.join(root_path, cfg["swap"])
    os.rename(victim, victim + ".orig")
    os.symlink(cfg["target"], victim)
    cfg["done"] = True
    os.environ["COCKPIT_ZFS_PERM_TEST_RACE"] = json.dumps(cfg)


def walk(target, params, errors=None):
    """Génère des Entry ouvertes (fd valide pendant le traitement de l'élément).
    Ne suit jamais les liens, n'ouvre que fichiers réguliers et dossiers, ne
    traverse pas les datasets enfants sauf cross_datasets (et jamais les
    montages non ZFS), ignore .zfs à la racine de chaque dataset."""
    cross = bool(params.get("cross_datasets", False))
    max_depth = params.get("max_depth")
    max_depth = int(max_depth) if max_depth not in (None, "") else None
    include = [p for p in params.get("include", []) if p]
    exclude = [p for p in params.get("exclude", []) if p]
    types = params.get("types", "all")
    recursive = params.get("recursive", True)
    include_root = params.get("include_root", True)
    root = target.path
    root_st = target.st

    def matches(rel, patterns):
        name = os.path.basename(rel)
        return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in patterns)

    def accept(rel, is_dir):
        if types == "files" and is_dir:
            return False
        if types == "dirs" and not is_dir:
            return False
        if include and not matches(rel, include):
            return False
        return True

    def err(path, e):
        if errors is not None:
            errors(path, e)

    if include_root and accept(".", stat.S_ISDIR(root_st.st_mode)):
        yield Entry(root, ".", target.fd, root_st)
    if not recursive or not stat.S_ISDIR(root_st.st_mode):
        return

    def visit(dfd, dst, drel, depth):
        if max_depth is not None and depth >= max_depth:
            return
        try:
            names = sorted(os.listdir(dfd))
        except OSError as e:
            err(root if drel == "." else os.path.join(root, drel), e)
            return
        is_mount_root = (dst.st_dev, dst.st_ino) in target.mount_roots
        for name in names:
            rel = name if drel == "." else drel + "/" + name
            path = os.path.join(root, rel)
            if name == ".zfs" and is_mount_root:
                continue
            try:
                lst = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except OSError as e:
                err(path, e)
                continue
            if not (stat.S_ISDIR(lst.st_mode) or stat.S_ISREG(lst.st_mode)):
                continue  # liens, périphériques, FIFO, sockets : jamais ouverts
            is_dir = stat.S_ISDIR(lst.st_mode)
            if lst.st_dev != dst.st_dev and (not cross or lst.st_dev not in target.zfs_devs):
                continue  # dataset enfant (ou autre montage)
            if exclude and matches(rel, exclude):
                continue
            _race_hook(rel, root)
            try:
                fd, fst = safe_open_child(dfd, name)
            except (OSError, PermError) as e:
                err(path, e)
                continue
            try:
                if accept(rel, is_dir):
                    yield Entry(path, rel, fd, fst)
                if is_dir and stat.S_ISDIR(fst.st_mode):
                    yield from visit(fd, fst, rel, depth + 1)
            finally:
                os.close(fd)

    yield from visit(target.fd, root_st, ".", 0)


# --------------------------------------------------------------------------- sauvegardes

def ensure_backup_dir():
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)


def snapshot_state(fd, st):
    flags = get_fsflags_fd(fd)
    return {
        "t": "d" if stat.S_ISDIR(st.st_mode) else "f",
        "u": st.st_uid, "g": st.st_gid, "m": stat.S_IMODE(st.st_mode),
        "a": b64(fd_getxattr(fd, ACCESS_XATTR)),
        "d": b64(fd_getxattr(fd, DEFAULT_XATTR)) if stat.S_ISDIR(st.st_mode) else None,
        "x": {NTACL_XATTR: b64(fd_getxattr(fd, NTACL_XATTR)), DOSATTRIB_XATTR: b64(fd_getxattr(fd, DOSATTRIB_XATTR))},
        "f": (flags or 0) & PROTECT_FLAGS,
    }


class Backup:
    """Sauvegarde au fil du parcours : l'état de chaque objet est écrit avant sa
    modification (propriétaire, mode, ACL brutes, ACL NT, DOSATTRIB, immutable)."""

    def __init__(self, target, reason, params):
        ensure_backup_dir()
        safe = target.dataset.replace("/", "_")
        stamp = time.strftime("%Y%m%d-%H%M%S") + "-%06d" % (int(time.time() * 1e6) % 1000000)
        backup_id = "%s-%s" % (safe, stamp)
        n = 1
        while os.path.exists(os.path.join(BACKUP_DIR, backup_id + ".json")):
            n += 1
            backup_id = "%s-%s-%d" % (safe, stamp, n)
        self.id = backup_id
        self.base = os.path.join(BACKUP_DIR, backup_id)
        fd = os.open(self.base + ".perm.jsonl.gz", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        self.f = gzip.open(os.fdopen(fd, "wb"), "wb")
        self.count = 0
        self.meta = {
            "id": backup_id, "format": 2, "path": target.path, "dataset": target.dataset,
            "reason": reason, "created": int(time.time()), "entries": 0,
            "options": {k: params.get(k) for k in ("recursive", "include_root", "cross_datasets", "max_depth", "include", "exclude", "types")},
        }

    def record(self, e):
        rec = snapshot_state(e.fd, e.st)
        rec["r"] = b64(os.fsencode(e.rel))
        self.f.write((json.dumps(rec) + "\n").encode("ascii"))
        self.count += 1

    def close(self):
        self.f.close()
        self.meta["entries"] = self.count
        self.meta["size"] = os.path.getsize(self.base + ".perm.jsonl.gz")
        fd = os.open(self.base + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.meta, f, ensure_ascii=True)
        return self.meta


def list_backups(_params):
    if not os.path.isdir(BACKUP_DIR):
        return {"backups": []}
    out = []
    for name in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if name.endswith(".json"):
            try:
                with open(os.path.join(BACKUP_DIR, name)) as f:
                    meta = json.load(f)
                if meta.get("format") == 2:
                    out.append(meta)
            except (OSError, ValueError):
                pass
    return {"backups": out}


def backup_files(backup_id):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", backup_id or ""):
        raise PermError("Identifiant de sauvegarde invalide")
    base = os.path.join(BACKUP_DIR, backup_id)
    if not os.path.exists(base + ".perm.jsonl.gz") or not os.path.exists(base + ".json"):
        raise PermError("Sauvegarde introuvable : %s" % backup_id)
    return base + ".perm.jsonl.gz", base + ".json"


def delete_backup(params):
    data, meta = backup_files(params.get("id"))
    os.unlink(data)
    os.unlink(meta)
    return {"deleted": params.get("id")}


# --------------------------------------------------------------------------- inspect / audit

def describe(path, st=None):
    st = st or os.lstat(path)
    info = {
        "path": path,
        "type": "dir" if stat.S_ISDIR(st.st_mode) else "link" if stat.S_ISLNK(st.st_mode)
        else "file" if stat.S_ISREG(st.st_mode) else "other",
        "mode": mode_str(st.st_mode),
        "symbolic": stat.filemode(st.st_mode),
        "uid": st.st_uid, "owner": uid_name(st.st_uid),
        "gid": st.st_gid, "group": gid_name(st.st_gid),
        "setgid": bool(st.st_mode & stat.S_ISGID),
        "sticky": bool(st.st_mode & stat.S_ISVTX),
    }
    try:
        x = os.listxattr(path, follow_symlinks=False)
    except OSError:
        x = []
    info["xattrs"] = x
    info["has_ntacl"] = NTACL_XATTR in x
    info["has_posix_acl"] = ACCESS_XATTR in x or DEFAULT_XATTR in x
    flags = None
    if stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode):
        try:
            fd = os.open(path, OPEN_DIR if stat.S_ISDIR(st.st_mode) else OPEN_FILE)
            try:
                if (os.fstat(fd).st_ino == st.st_ino):
                    flags = get_fsflags_fd(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
    info["immutable"] = bool(flags and flags & FS_IMMUTABLE_FL)
    info["append_only"] = bool(flags and flags & FS_APPEND_FL)
    return info


def acl_for_path(path, st):
    def get(name):
        try:
            return os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            return None
    raw_a = get(ACCESS_XATTR)
    raw_d = get(DEFAULT_XATTR) if stat.S_ISDIR(st.st_mode) else None
    m = st.st_mode
    return {
        "owner": uid_name(st.st_uid) or str(st.st_uid),
        "group": gid_name(st.st_gid) or str(st.st_gid),
        "flags": ("s" if m & stat.S_ISUID else "-") + ("s" if m & stat.S_ISGID else "-") + ("t" if m & stat.S_ISVTX else "-"),
        "access": acl_to_ui(decode_acl(raw_a) if raw_a else base_from_mode(m)),
        "default": acl_to_ui(decode_acl(raw_d)) if raw_d else [],
    }


def cmd_inspect(params):
    target = resolve_target(params)
    path = target.path
    props = zfs_props(target.dataset)
    st = os.lstat(path)
    info = describe(path, st)
    acl, acl_error = None, None
    try:
        acl = acl_for_path(path, st)
    except PermError as e:
        acl_error = str(e)
    children = []
    limit = int(params.get("children_limit", 300))
    if stat.S_ISDIR(st.st_mode):
        try:
            for de in sorted(os.scandir(path), key=lambda d: d.name)[:limit]:
                if de.name == ".zfs":
                    continue
                try:
                    children.append(describe(de.path, de.stat(follow_symlinks=False)))
                except OSError:
                    pass
        except OSError:
            pass
    warnings = []
    acltype = norm_prop("acltype", props.get("acltype", {}).get("value"))
    xattr = props.get("xattr", {}).get("value")
    if acltype == "posixacl" and xattr != "sa":
        warnings.append("acltype=posixacl avec xattr=%s : chaque ACL devient un fichier caché, préférez xattr=sa" % xattr)
    if acltype == "posixacl":
        for p in ("aclinherit", "aclmode"):
            if props.get(p, {}).get("source") == "local":
                warnings.append("%s n'a aucun effet avec des ACL POSIX sous Linux (s'applique aux ACL NFSv4)" % p)
    if acltype == "off" and info["has_posix_acl"]:
        warnings.append("Des ACL POSIX sont stockées mais ignorées (acltype=off)")
    if info["has_ntacl"]:
        warnings.append("ACL NT présente (security.NTACL) : Samba / ksmbd avec acl_xattr l'affiche au client Windows")
    if os.path.realpath(params.get("path") or path) != os.path.normpath(params.get("path") or path):
        warnings.append("Le chemin demandé contient un lien symbolique : affichage de la cible réelle %s, écriture refusée" % path)
    if target.mountpoint in SYSTEM_MOUNTS:
        warnings.append("Dataset système (monté sur %s) : les modifications sont refusées" % target.mountpoint)
    return {
        "path": path, "dataset": target.dataset, "mountpoint": target.mountpoint,
        "props": props, "info": info, "acl": acl, "acl_error": acl_error,
        "children": children, "warnings": warnings,
        "acl_mode": acl_mode_for(target.dataset),
    }


def cmd_audit(params):
    target = resolve_target(params).open()
    try:
        max_entries = int(params.get("max_entries", 2000000))
        root_st = target.st
        root_setgid = bool(root_st.st_mode & stat.S_ISGID)
        acltype = acl_mode_for(target.dataset)
        kinds = ("world_writable", "orphan_uid", "orphan_gid", "ntacl", "posix_acl", "ignored_posix_acl",
                 "dir_missing_setgid", "foreign_group", "immutable", "setuid")
        findings = {k: [] for k in kinds}
        counts = {k: 0 for k in kinds}
        owners, groups, modes = {}, {}, {}
        total = files = dirs = 0
        truncated = False
        check_flags = bool(params.get("check_flags", True))

        def add(kind, p):
            counts[kind] += 1
            if len(findings[kind]) < FINDING_LIMIT:
                findings[kind].append(p)

        for e in walk(target, dict(params, types="all")):
            total += 1
            if total > max_entries:
                truncated = True
                break
            st = e.st
            dirs += e.is_dir
            files += not e.is_dir
            owners[st.st_uid] = owners.get(st.st_uid, 0) + 1
            groups[st.st_gid] = groups.get(st.st_gid, 0) + 1
            m = mode_str(st.st_mode) + ("d" if e.is_dir else "f")
            modes[m] = modes.get(m, 0) + 1
            if st.st_mode & stat.S_IWOTH and not (e.is_dir and st.st_mode & stat.S_ISVTX):
                add("world_writable", e.path)
            if uid_name(st.st_uid) is None:
                add("orphan_uid", e.path)
            if gid_name(st.st_gid) is None:
                add("orphan_gid", e.path)
            if st.st_gid != root_st.st_gid:
                add("foreign_group", e.path)
            if e.is_dir and root_setgid and not st.st_mode & stat.S_ISGID:
                add("dir_missing_setgid", e.path)
            if not e.is_dir and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                add("setuid", e.path)
            try:
                x = os.listxattr(e.fd)
            except OSError:
                x = []
            if NTACL_XATTR in x:
                add("ntacl", e.path)
            if ACCESS_XATTR in x or DEFAULT_XATTR in x:
                add("ignored_posix_acl" if acltype == "off" else "posix_acl", e.path)
            if check_flags:
                fl = get_fsflags_fd(e.fd)
                if fl and fl & PROTECT_FLAGS:
                    add("immutable", e.path)

        def top(d, namer):
            return [{"id": k, "name": namer(k), "count": v}
                    for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:15]]

        return {
            "path": target.path, "dataset": target.dataset, "acl_mode": acltype,
            "total": total, "files": files, "dirs": dirs, "truncated": truncated,
            "counts": counts, "findings": findings,
            "owners": top(owners, uid_name), "groups": top(groups, gid_name),
            "modes": [{"mode": k[:-1], "kind": "dossier" if k[-1] == "d" else "fichier", "count": v}
                      for k, v in sorted(modes.items(), key=lambda kv: -kv[1])[:20]],
        }
    finally:
        target.close()


# --------------------------------------------------------------------------- application

class Plan:
    def __init__(self, dry_run):
        self.dry_run = dry_run
        self.count = 0
        self.sample = []
        self.commands = []
        self.errors = []
        self.error_count = 0

    def note(self, path, what):
        self.count += 1
        if len(self.sample) < SAMPLE_LIMIT:
            self.sample.append({"path": path, "change": what})

    def command(self, desc):
        if len(self.commands) < 20:
            self.commands.append(desc)

    def error(self, path, err):
        self.error_count += 1
        if len(self.errors) < FINDING_LIMIT:
            self.errors.append({"path": path, "error": getattr(err, "strerror", None) or str(err)})

    def result(self, **extra):
        r = {"dry_run": self.dry_run, "count": self.count, "sample": self.sample,
             "commands": self.commands, "errors": self.errors, "error_count": self.error_count}
        r.update(extra)
        return r


def require_posix(dataset, what):
    mode = acl_mode_for(dataset)
    if mode != "posix":
        raise PermError("%s exige acltype=posixacl sur %s (actuel : %s)" % (what, dataset, mode))


def owner_change_desc(st, uid, gid):
    if (uid == -1 or st.st_uid == uid) and (gid == -1 or st.st_gid == gid):
        return None
    return "propriétaire %s:%s → %s:%s" % (
        uid_name(st.st_uid) or st.st_uid, gid_name(st.st_gid) or st.st_gid,
        (uid_name(uid) or uid) if uid != -1 else "=", (gid_name(gid) or gid) if gid != -1 else "=")


def chown_keep_setid(fd, st, uid, gid):
    """fchown puis réapplique setuid / setgid que le noyau retire au chown."""
    if (uid == -1 or st.st_uid == uid) and (gid == -1 or st.st_gid == gid):
        return False
    os.fchown(fd, uid, gid)
    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
        cur = os.fstat(fd).st_mode
        if stat.S_IMODE(cur) != stat.S_IMODE(st.st_mode):
            os.fchmod(fd, stat.S_IMODE(cur) | (stat.S_IMODE(st.st_mode) & (stat.S_ISUID | stat.S_ISGID)))
    return True


def drive(target, params, plan, backup, fn):
    """Parcourt la cible et applique fn(entry) ; la sauvegarde de chaque objet
    est écrite avant sa modification."""
    for e in walk(target, params, errors=plan.error):
        try:
            if backup is not None:
                backup.record(e)
            fn(e)
        except PermError as err:
            plan.error(e.path, err)
        except OSError as err:
            plan.error(e.path, err)


def begin(params, method, write=True):
    target = resolve_target(params, write=write).open()
    plan = Plan(params.get("dry_run", True))
    backup = None
    if not plan.dry_run and params.get("backup", True) and method != "from-backup":
        backup = Backup(target, "avant %s" % method, params)
    return target, plan, backup


def finish(target, plan, backup, **extra):
    meta = backup.close() if backup is not None else None
    target.close()
    return plan.result(path=target.path, dataset=target.dataset, backup=meta, **extra)


def cmd_set_acl(params):
    action = params.get("action", "modify")
    if action not in ("set", "modify", "remove", "remove-default"):
        raise PermError("Action inconnue : %s" % action)
    target = resolve_target(params, write=True)
    require_posix(target.dataset, "L'édition d'ACL")
    params = dict(params, recursive=params.get("recursive", False))
    access_ui = params.get("access", [])
    default_ui = params.get("default", [])
    cond_x = params.get("files_conditional_x", True)

    # validation complète avant toute écriture
    removals = []
    if action == "remove":
        for e in access_ui + default_ui:
            if e.get("tag") not in ("user", "group") or not e.get("qualifier"):
                continue
            ident = resolve_uid(e["qualifier"], False) if e["tag"] == "user" else resolve_gid(e["qualifier"], False)
            removals.append((ACL_USER if e["tag"] == "user" else ACL_GROUP, ident))
        if not removals:
            raise PermError("Aucune entrée nommée à retirer")
    elif action in ("set", "modify"):
        ui_entries_to_acl(access_ui, True, 0)
        ui_entries_to_acl(default_ui, True, 0)

    target.open()
    plan = Plan(params.get("dry_run", True))
    backup = Backup(target, "avant set-acl %s" % action, params) \
        if not plan.dry_run and params.get("backup", True) else None

    def apply(e):
        if action == "remove-default":
            if e.is_dir and fd_getxattr(e.fd, DEFAULT_XATTR) is not None:
                plan.note(e.path, "ACL par défaut retirée")
                if not plan.dry_run:
                    fd_removexattr(e.fd, DEFAULT_XATTR)
            return
        cur_a = read_access(e.fd, e.st)
        cur_d = read_default(e.fd) if e.is_dir else []
        if action == "remove":
            new_a = with_mask([x for x in cur_a if (x[0], x[2]) not in removals])
            new_d = with_mask([x for x in cur_d if (x[0], x[2]) not in removals]) if cur_d else []
        else:
            given_a, mask_a = ui_entries_to_acl(access_ui, e.is_dir, e.st.st_mode, x_to_cond=cond_x and not e.is_dir)
            given_d, mask_d = ui_entries_to_acl(default_ui, True, 0) if e.is_dir else ([], None)
            if action == "set":
                new_a = with_mask(fill_base(given_a, cur_a), mask_a)
                new_d = with_mask(fill_base(given_d, cur_a), mask_d) if given_d else cur_d
            else:
                merged = {(x[0], x[2]): x for x in cur_a if x[0] != ACL_MASK}
                merged.update({(x[0], x[2]): x for x in given_a})
                new_a = with_mask(list(merged.values()), mask_a)
                if given_d:
                    base_d = cur_d or [x for x in cur_a if x[0] in (ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_OTHER)]
                    md = {(x[0], x[2]): x for x in base_d if x[0] != ACL_MASK}
                    md.update({(x[0], x[2]): x for x in given_d})
                    new_d = with_mask(list(md.values()), mask_d)
                else:
                    new_d = cur_d
        changed = sorted(new_a) != sorted(cur_a) or (e.is_dir and sorted(new_d) != sorted(cur_d))
        if not changed:
            return
        plan.note(e.path, "ACL %s" % action)
        if plan.dry_run:
            return
        write_access(e.fd, new_a)
        if e.is_dir and sorted(new_d) != sorted(cur_d):
            write_default(e.fd, new_d)

    plan.command("ACL écrites par descripteur (xattr system.posix_acl_*)")
    drive(target, params, plan, backup, apply)
    return finish(target, plan, backup)


# --------------------------------------------------------------------------- reset

def reset_unix_mode(params, target, plan, backup):
    uid = resolve_uid(params.get("owner"))
    gid = resolve_gid(params.get("group"))
    fmode = parse_mode(params.get("file_mode"), "Mode fichiers")
    dmode = parse_mode(params.get("dir_mode"), "Mode dossiers")
    if params.get("setgid_dirs") and dmode is not None:
        dmode |= stat.S_ISGID
    if params.get("sticky_dirs") and dmode is not None:
        dmode |= stat.S_ISVTX
    keep_exec = params.get("keep_exec", False)
    strip = params.get("strip_acl", True) and acl_mode_for(target.dataset) == "posix"

    def apply(e):
        st = e.st
        mode = dmode if e.is_dir else fmode
        if mode is not None and not e.is_dir and keep_exec and st.st_mode & stat.S_IXUSR:
            mode |= (mode & 0o444) >> 2
        has_acl = strip and (fd_getxattr(e.fd, ACCESS_XATTR) is not None or
                             (e.is_dir and fd_getxattr(e.fd, DEFAULT_XATTR) is not None))
        changes = []
        oc = owner_change_desc(st, uid, gid)
        if oc:
            changes.append(oc)
        if mode is not None and stat.S_IMODE(st.st_mode) != mode:
            changes.append("mode %s → %04o" % (mode_str(st.st_mode), mode))
        if has_acl:
            changes.append("ACL étendues retirées")
        if not changes:
            return
        plan.note(e.path, ", ".join(changes))
        if plan.dry_run:
            return
        if has_acl:
            strip_access(e.fd, st)
            if e.is_dir:
                fd_removexattr(e.fd, DEFAULT_XATTR)
        if uid != -1 or gid != -1:
            if mode is None:
                chown_keep_setid(e.fd, os.fstat(e.fd), uid, gid)
            else:
                os.fchown(e.fd, uid, gid)
        if mode is not None:
            os.fchmod(e.fd, mode)

    drive(target, params, plan, backup, apply)


def reset_strip_acl(params, target, plan, backup):
    require_posix(target.dataset, "Le retrait d'ACL")
    keep_default = params.get("keep_default", False)

    def apply(e):
        has_a = fd_getxattr(e.fd, ACCESS_XATTR) is not None
        has_d = e.is_dir and not keep_default and fd_getxattr(e.fd, DEFAULT_XATTR) is not None
        if not (has_a or has_d):
            return
        plan.note(e.path, " + ".join(x for x in ("ACL d'accès retirée" if has_a else "",
                                                 "ACL par défaut retirée" if has_d else "") if x))
        if plan.dry_run:
            return
        if has_a:
            strip_access(e.fd, e.st)
        if has_d:
            fd_removexattr(e.fd, DEFAULT_XATTR)

    drive(target, params, plan, backup, apply)


def template_entries(params):
    entries = []
    for e in params.get("entries", []):
        tag = e.get("tag")
        if tag not in ("user", "group"):
            raise PermError("Modèle : seules les entrées user / group nommées sont permises")
        if not e.get("qualifier"):
            raise PermError("Modèle : entrée %s sans nom" % tag)
        entries.append({"tag": tag, "qualifier": e["qualifier"], "perms": e.get("perms", "r-x")})
    return entries


def reset_acl_template(params, target, plan, backup):
    require_posix(target.dataset, "Le modèle d'ACL")
    uid = resolve_uid(params.get("owner"))
    gid = resolve_gid(params.get("group"))
    base = [{"tag": "user", "qualifier": "", "perms": params.get("owner_perms", "rwx")},
            {"tag": "group", "qualifier": "", "perms": params.get("group_perms", "rwx")},
            {"tag": "other", "qualifier": "", "perms": params.get("other_perms", "---")}]
    mask_p = params.get("mask_perms", "rwx")
    model = base + template_entries(params) + [{"tag": "mask", "qualifier": "", "perms": mask_p}]
    ui_entries_to_acl(model, True, 0)  # validation avant toute écriture
    inherit = params.get("inherit", True)
    setgid_dirs = params.get("setgid_dirs", False)

    def apply(e):
        acl, mask = ui_entries_to_acl(model, e.is_dir, e.st.st_mode, x_to_cond=not e.is_dir)
        acl = with_mask(acl, mask)
        plan.note(e.path, "modèle d'ACL appliqué" + (", " + owner_change_desc(e.st, uid, gid) if owner_change_desc(e.st, uid, gid) else ""))
        if plan.dry_run:
            return
        if uid != -1 or gid != -1:
            os.fchown(e.fd, uid, gid)
        write_access(e.fd, acl)
        if e.is_dir:
            write_default(e.fd, with_mask(*ui_entries_to_acl(model, True, 0)) if inherit else [])
        keep = stat.S_IMODE(e.st.st_mode) & (stat.S_ISUID | stat.S_ISGID) if not e.is_dir else 0
        extra = stat.S_ISGID if (e.is_dir and setgid_dirs) else 0
        if keep or extra:
            os.fchmod(e.fd, stat.S_IMODE(os.fstat(e.fd).st_mode) | keep | extra)

    drive(target, params, plan, backup, apply)


def reset_inherit_parent(params, target, plan, backup):
    require_posix(target.dataset, "La propagation d'héritage")
    if not stat.S_ISDIR(target.st.st_mode):
        raise PermError("La propagation exige un dossier racine")
    defaults = read_default(target.fd)
    if not defaults:
        if not params.get("fallback_access", False):
            raise PermError("Le dossier racine n'a pas d'ACL par défaut (cochez « utiliser l'ACL d'accès »)")
        defaults = read_access(target.fd, target.st)
    keep_exec = params.get("keep_exec", True)
    root_uid, root_gid = target.st.st_uid, target.st.st_gid
    realign = params.get("reset_owner_to_root", False)

    def apply(e):
        if e.is_dir:
            new_a, new_d = defaults, defaults
        else:
            new_a = resolve_x_acl(defaults, False, e.st.st_mode if keep_exec else 0)
            new_d = []
        plan.note(e.path, "hérite de %s" % target.path)
        if plan.dry_run:
            return
        if realign:
            chown_keep_setid(e.fd, e.st, root_uid, root_gid)
        write_access(e.fd, new_a)
        if e.is_dir:
            write_default(e.fd, new_d)

    drive(target, dict(params, include_root=False), plan, backup, apply)


def reset_mirror_reference(params, target, plan, backup):
    ref_dir = params.get("reference_dir") or params.get("reference")
    ref_file = params.get("reference_file") or ""
    if not ref_dir:
        raise PermError("Aucun dossier de référence fourni")
    posix = acl_mode_for(target.dataset) == "posix"
    refs = {}
    for kind, path in (("d", ref_dir), ("f", ref_file)):
        if not path:
            continue
        if os.path.realpath(path) != os.path.normpath(path):
            raise PermError("La référence %s est (ou traverse) un lien symbolique : refusé" % path)
        fd, st = open_nofollow(path, want=kind)
        try:
            refs[kind] = {"st": st, "a": read_access(fd, st) if posix else None,
                          "d": read_default(fd) if posix and kind == "d" else []}
        finally:
            os.close(fd)
    copy_owner = params.get("copy_owner", True)

    def apply(e):
        if e.is_dir or "f" in refs:
            ref = refs["d" if e.is_dir else "f"]
            mode = stat.S_IMODE(ref["st"].st_mode)
            acl = ref["a"]
            dacl = ref["d"] if e.is_dir else []
        else:
            # pas de référence fichier : modèle du dossier, x seulement si déjà exécutable (X)
            ref = refs["d"]
            rmode = stat.S_IMODE(ref["st"].st_mode) & 0o777
            mode = rmode if e.st.st_mode & 0o111 else rmode & ~0o111
            acl = resolve_x_acl(ref["a"], False, e.st.st_mode) if ref["a"] else None
            dacl = []
        uid = ref["st"].st_uid if copy_owner else -1
        gid = ref["st"].st_gid if copy_owner else -1
        changes = [c for c in (owner_change_desc(e.st, uid, gid),
                               "mode %s → %04o" % (mode_str(e.st.st_mode), mode) if stat.S_IMODE(e.st.st_mode) != mode else None) if c]
        if posix:
            changes.append("ACL de la référence")
        if not changes:
            return
        plan.note(e.path, ", ".join(changes))
        if plan.dry_run:
            return
        if uid != -1 or gid != -1:
            os.fchown(e.fd, uid, gid)
        if posix:
            write_access(e.fd, acl)       # ACL avant chmod : le masque suit ensuite le mode
            if e.is_dir:
                write_default(e.fd, dacl)
        os.fchmod(e.fd, mode)

    drive(target, params, plan, backup, apply)


def apply_state(fd, cur_st, state, include_xattrs):
    """Réapplique un état (snapshot ou sauvegarde) sur un descripteur."""
    flags = get_fsflags_fd(fd)
    if flags and flags & PROTECT_FLAGS:
        set_fsflags_fd(fd, flags & ~PROTECT_FLAGS)
    os.fchown(fd, state["u"], state["g"])
    raw_a = unb64(state.get("a"))
    if raw_a:
        os.setxattr(fd, ACCESS_XATTR, raw_a)
    else:
        fd_removexattr(fd, ACCESS_XATTR)
    if stat.S_ISDIR(cur_st.st_mode):
        raw_d = unb64(state.get("d"))
        if raw_d:
            os.setxattr(fd, DEFAULT_XATTR, raw_d)
        else:
            fd_removexattr(fd, DEFAULT_XATTR)
    os.fchmod(fd, state["m"])
    if include_xattrs:
        for name, val in (state.get("x") or {}).items():
            raw = unb64(val)
            if raw is None:
                fd_removexattr(fd, name)
            else:
                os.setxattr(fd, name, raw)
    want = state.get("f", 0)
    flags = get_fsflags_fd(fd)
    if flags is not None and (flags & PROTECT_FLAGS) != want:
        set_fsflags_fd(fd, (flags & ~PROTECT_FLAGS) | want)


def state_diff(fd, st, state, include_xattrs):
    cur = snapshot_state(fd, st)
    diffs = []
    if (cur["u"], cur["g"]) != (state["u"], state["g"]):
        diffs.append("propriétaire %s:%s → %s:%s" % (cur["u"], cur["g"], state["u"], state["g"]))
    if cur["m"] != state["m"]:
        diffs.append("mode %04o → %04o" % (cur["m"], state["m"]))
    if cur["a"] != state.get("a") or (cur["t"] == "d" and cur["d"] != state.get("d")):
        diffs.append("ACL")
    if include_xattrs and cur["x"] != (state.get("x") or cur["x"]):
        diffs.append("ACL NT / attributs DOS")
    if cur["f"] != state.get("f", cur["f"]):
        diffs.append("immutable / append-only")
    return diffs


def reset_from_snapshot(params, target, plan, backup):
    snap = params.get("snapshot", "")
    if "@" in snap:
        ds, snap = snap.split("@", 1)
        if ds != target.dataset:
            raise PermError("Le snapshot %s n'appartient pas à %s (le chemin est dans ce dataset)" % (ds, target.dataset))
    if not re.fullmatch(r"[A-Za-z0-9._:+-]+", snap):
        raise PermError("Nom de snapshot invalide")
    snapdir = os.path.join(target.mountpoint, ".zfs", "snapshot", snap)
    try:
        sfd = os.open(snapdir, OPEN_DIR)
    except OSError as e:
        raise PermError("Snapshot %s inaccessible : %s" % (snap, e.strerror))
    rel_root = os.path.relpath(target.path, target.mountpoint)
    try:
        try:
            srfd, srst = open_rel(sfd, rel_root, want="d" if stat.S_ISDIR(target.st.st_mode) else "f")
        except (OSError, PermError) as e:
            raise PermError("%s introuvable dans le snapshot %s (%s)" % (rel_root, snap, e))
    finally:
        os.close(sfd)
    counters = {"missing": 0, "skipped_child": 0}

    def apply(e):
        if e.st.st_dev != target.st.st_dev:
            counters["skipped_child"] += 1  # racine ou contenu d'un dataset enfant : pas dans ce snapshot
            return
        try:
            nfd, nst = open_rel(srfd, e.rel, root_dev=srst.st_dev, want="d" if e.is_dir else "f")
        except (OSError, PermError):
            counters["missing"] += 1
            return
        try:
            state = snapshot_state(nfd, nst)
        finally:
            os.close(nfd)
        state["x"] = None
        diffs = state_diff(e.fd, e.st, state, False)
        if not diffs:
            return
        plan.note(e.path, ", ".join(diffs))
        if not plan.dry_run:
            apply_state(e.fd, e.st, state, False)

    try:
        drive(target, params, plan, backup, apply)
    finally:
        os.close(srfd)
    return {"snapshot": "%s@%s" % (target.dataset, snap), **counters}


def cmd_restore_backup(params):
    data, meta_path = backup_files(params.get("backup_id"))
    with open(meta_path) as f:
        meta = json.load(f)
    requested = os.path.normpath(params.get("path") or meta["path"])
    root_path = meta["path"]
    if requested != root_path and not requested.startswith(root_path.rstrip("/") + "/"):
        raise PermError("La sauvegarde couvre %s, pas %s" % (root_path, requested))
    target = resolve_target({"path": root_path}, write=True).open()
    plan = Plan(params.get("dry_run", True))
    prefix = os.path.relpath(requested, root_path)
    cross = bool((meta.get("options") or {}).get("cross_datasets"))
    include_xattrs = params.get("restore_xattrs", True)
    missing = 0
    try:
        with gzip.open(data, "rb") as f:
            for line in f:
                rec = json.loads(line)
                rel = os.fsdecode(unb64(rec["r"]))
                if prefix != "." and rel != prefix and not rel.startswith(prefix + "/"):
                    continue
                path = target.path if rel == "." else os.path.join(target.path, rel)
                try:
                    fd, st = open_rel(target.fd, rel, root_dev=None if cross else target.st.st_dev, want=rec["t"])
                except (OSError, PermError):
                    missing += 1
                    continue
                try:
                    diffs = state_diff(fd, st, rec, include_xattrs)
                    if diffs:
                        plan.note(path, ", ".join(diffs))
                        if not plan.dry_run:
                            apply_state(fd, st, rec, include_xattrs)
                except OSError as e:
                    plan.error(path, e)
                finally:
                    os.close(fd)
    finally:
        target.close()
    return plan.result(method="from-backup", path=requested, dataset=target.dataset, backup=None,
                       restored_backup=meta, missing=missing)


def reset_clear_ntacl(params, target, plan, backup):
    names = [NTACL_XATTR] + ([DOSATTRIB_XATTR] if params.get("dosattrib") else [])

    def apply(e):
        try:
            x = os.listxattr(e.fd)
        except OSError:
            return
        present = [n for n in names if n in x]
        if not present:
            return
        plan.note(e.path, "retrait de " + ", ".join(present))
        if not plan.dry_run:
            for n in present:
                fd_removexattr(e.fd, n)

    drive(target, params, plan, backup, apply)


def reset_orphans(params, target, plan, backup):
    uid = resolve_uid(params.get("owner"))
    gid = resolve_gid(params.get("group"))
    if uid == -1 and gid == -1:
        raise PermError("Indiquez un propriétaire et / ou un groupe de remplacement")

    def apply(e):
        nu = uid if uid != -1 and uid_name(e.st.st_uid) is None else -1
        ng = gid if gid != -1 and gid_name(e.st.st_gid) is None else -1
        desc = owner_change_desc(e.st, nu, ng)
        if not desc:
            return
        plan.note(e.path, desc)
        if not plan.dry_run:
            chown_keep_setid(e.fd, e.st, nu, ng)

    drive(target, params, plan, backup, apply)


def reset_takeown(params, target, plan, backup):
    uid = resolve_uid(params.get("owner"))
    gid = resolve_gid(params.get("group"))
    if uid == -1 and gid == -1:
        raise PermError("Indiquez un propriétaire et / ou un groupe")
    preserve = params.get("preserve_setid", True)

    def apply(e):
        desc = owner_change_desc(e.st, uid, gid)
        if not desc:
            return
        plan.note(e.path, desc)
        if plan.dry_run:
            return
        if preserve:
            chown_keep_setid(e.fd, e.st, uid, gid)
        else:
            os.fchown(e.fd, uid, gid)

    drive(target, params, plan, backup, apply)


def reset_chattr_clear(params, target, plan, backup):
    def apply(e):
        fl = get_fsflags_fd(e.fd)
        if not fl or not fl & PROTECT_FLAGS:
            return
        plan.note(e.path, "immutable / append-only retirés")
        if not plan.dry_run:
            set_fsflags_fd(e.fd, fl & ~PROTECT_FLAGS)

    drive(target, params, plan, backup, apply)


RESET_IMPL = {
    "unix-mode": reset_unix_mode,
    "strip-acl": reset_strip_acl,
    "acl-template": reset_acl_template,
    "inherit-parent": reset_inherit_parent,
    "mirror-reference": reset_mirror_reference,
    "from-snapshot": reset_from_snapshot,
    "clear-ntacl": reset_clear_ntacl,
    "orphans": reset_orphans,
    "takeown": reset_takeown,
    "chattr-clear": reset_chattr_clear,
}


def cmd_reset(params):
    method = params.get("method")
    if method not in RESET_METHODS:
        raise PermError("Méthode inconnue : %s" % method)
    if method == "from-backup":
        return cmd_restore_backup(params)
    target, plan, backup = begin(params, method)
    try:
        extra = RESET_IMPL[method](params, target, plan, backup) or {}
    except BaseException:
        meta = backup.close() if backup is not None else None
        target.close()
        if meta is not None and meta["entries"] == 0:
            for suffix in (".perm.jsonl.gz", ".json"):
                try:
                    os.unlink(os.path.join(BACKUP_DIR, meta["id"] + suffix))
                except OSError:
                    pass
        raise
    return finish(target, plan, backup, method=method, **extra)


# --------------------------------------------------------------------------- délégation zfs allow

SECTION_KEYS = {
    "Permission sets:": "sets",
    "Create time permissions:": "create",
    "Local permissions:": "local",
    "Descendent permissions:": "descendent",
    "Local+Descendent permissions:": "both",
}


def parse_zfs_allow(text):
    result = []
    current = None
    section = None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = re.match(r"^---- Permissions on (\S+) -+", line)
        if m:
            current = {"dataset": m.group(1), "sets": [], "create": [], "local": [],
                       "descendent": [], "both": []}
            result.append(current)
            section = None
            continue
        if line.strip() in SECTION_KEYS:
            section = SECTION_KEYS[line.strip()]
            continue
        if current is None or section is None or not line.strip():
            continue
        body = line.strip()
        if section == "sets":
            name, _, perms = body.partition(" ")
            current["sets"].append({"name": name, "perms": perms.split(",")})
        elif section == "create":
            current["create"].append({"perms": body.split(",")})
        else:
            parts = body.split(" ", 2)
            if parts[0] == "everyone":
                who_type, who, perms = "everyone", "", parts[1] if len(parts) > 1 else ""
            else:
                who_type, who, perms = parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else ""
            current[section].append({"type": who_type, "who": who, "perms": perms.split(",")})
    return result


def cmd_delegation(params):
    dataset = params.get("dataset")
    if not dataset:
        raise PermError("Dataset requis")
    _c, out, _e = run(["zfs", "allow", dataset])
    return {"dataset": dataset, "entries": parse_zfs_allow(out), "known_perms": ZFS_DELEGATION_PERMS, "raw": out}


def cmd_delegate(params):
    dataset = params.get("dataset")
    op = params.get("op", "allow")
    kind = params.get("kind", "user")
    who = str(params.get("who", "") or "")
    scope = params.get("scope", "both")
    perms = [p.strip() for p in params.get("perms", []) if p.strip()]
    if not dataset or dataset.startswith("-"):
        raise PermError("Dataset requis")
    if op not in ("allow", "unallow"):
        raise PermError("Opération inconnue : %s" % op)
    if not perms and not (op == "unallow" and params.get("all")):
        raise PermError("Aucune permission indiquée")
    for p in perms:
        if not re.fullmatch(r"@?[A-Za-z0-9_][A-Za-z0-9_:.-]*", p):
            raise PermError("Permission invalide : %s" % p)
    if who.startswith("-"):
        raise PermError("Bénéficiaire invalide : %s" % who)
    cmd = ["zfs", op]
    if op == "unallow" and params.get("recursive"):
        cmd.append("-r")
    if kind in ("user", "group", "everyone"):
        if scope == "local":
            cmd.append("-l")
        elif scope == "descendent":
            cmd.append("-d")
    if kind == "user":
        resolve_uid(who, False)
        cmd += ["-u", who]
    elif kind == "group":
        resolve_gid(who, False)
        cmd += ["-g", who]
    elif kind == "everyone":
        cmd.append("-e")
    elif kind == "create":
        cmd.append("-c")
    elif kind == "set":
        if not re.fullmatch(r"@[A-Za-z0-9_][A-Za-z0-9_.-]*", who):
            raise PermError("Nom d'ensemble invalide (format @nom)")
        cmd += ["-s", who]
    else:
        raise PermError("Type de délégation inconnu : %s" % kind)
    if perms:
        cmd.append(",".join(perms))
    cmd.append(dataset)
    if params.get("dry_run", True):
        return {"dry_run": True, "command": " ".join(cmd)}
    run(cmd)
    return {"dry_run": False, "command": " ".join(cmd)}


# --------------------------------------------------------------------------- préréglages

def cmd_preset(params):
    dataset = params.get("dataset")
    preset = PRESETS.get(params.get("preset"))
    if not dataset or not preset:
        if params.get("list"):
            return {"presets": {k: v["label"] for k, v in PRESETS.items()}}
        raise PermError("Dataset et préréglage requis")
    props = zfs_props(dataset)
    changes, commands = [], []
    for k, v in preset["props"].items():
        if v is None:
            continue
        current = props.get(k, {}).get("value")
        if norm_prop(k, current) == norm_prop(k, v):
            continue
        if k in ("normalization", "casesensitivity", "utf8only"):
            changes.append({"prop": k, "from": current, "to": v,
                            "note": "définissable seulement à la création du dataset"})
            continue
        changes.append({"prop": k, "from": current, "to": v})
        commands.append(["zfs", "set", "%s=%s" % (k, v), dataset])
    notes = []
    if params.get("preset") == "macos-smb" and props.get("normalization", {}).get("value") != "formD":
        notes.append("normalization=formD est recommandé pour macOS mais ne se fixe qu'à la création (zfs create -o normalization=formD)")
    if params.get("preset") == "nfsv4":
        notes.append("OpenZFS sous Linux (upstream) refuse acltype=nfsv4 ; la commande échouera hors FreeBSD / TrueNAS")
    if params.get("preset") in ("noacl-unix", "posixacl-smb"):
        notes.append("Changer acltype n'efface pas les ACL existantes : utilisez la réinitialisation « Retirer les ACL » si besoin")
    if params.get("dry_run", True):
        return {"dry_run": True, "changes": changes, "commands": [" ".join(c) for c in commands], "notes": notes}
    errors = []
    for c in commands:
        code, _o, err = run(c, check=False)
        if code != 0:
            errors.append({"command": " ".join(c), "error": err.strip()})
    return {"dry_run": False, "changes": changes, "commands": [" ".join(c) for c in commands],
            "errors": errors, "notes": notes}


# --------------------------------------------------------------------------- main

COMMANDS = {
    "inspect": cmd_inspect,
    "audit": cmd_audit,
    "set-acl": cmd_set_acl,
    "reset": cmd_reset,
    "backups": list_backups,
    "delete-backup": delete_backup,
    "delegation": cmd_delegation,
    "delegate": cmd_delegate,
    "preset": cmd_preset,
    "methods": lambda _p: {"methods": RESET_METHODS, "presets": {k: v["label"] for k, v in PRESETS.items()}},
}


def emit(obj):
    # ASCII : les noms non UTF-8 (surrogates) sont échappés en \udcXX, JSON valide
    sys.stdout.write(json.dumps(obj, ensure_ascii=True) + "\n")


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS:
        emit({"ok": False, "error": "Commande inconnue. Choix : " + ", ".join(COMMANDS)})
        return 0
    try:
        params = json.loads(argv[2]) if len(argv) > 2 and argv[2] else {}
        result = COMMANDS[argv[1]](params)
        result["ok"] = True
        emit(result)
    except PermError as e:
        emit({"ok": False, "error": str(e)})
    except Exception as e:  # erreur inattendue : on renvoie la trace au lieu de planter l'interface
        import traceback
        emit({"ok": False, "error": "%s: %s" % (type(e).__name__, e), "trace": traceback.format_exc()})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
