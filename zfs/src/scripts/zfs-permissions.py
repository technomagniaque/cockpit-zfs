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
import ipaddress
import gzip
import json
import os
import pwd
import re
import shlex
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
    "nfsv4-posix": {
        "label": "Partage NFSv4.1 sur OpenZFS Linux (ACL POSIX traduites par knfsd)",
        "props": {"acltype": "posixacl", "xattr": "sa", "dnodesize": "auto"},
    },
    "nfsv4": {
        "label": "ACL NFSv4 natives (FreeBSD / forks TrueNAS seulement)",
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
    # zfs / zpool en anglais : parse_zfs_allow et les autres analyses lisent leurs libellés
    env = dict(os.environ, LC_ALL="C", LANG="C") if cmd and cmd[0] in ("zfs", "zpool") else None
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
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


# --------------------------------------------------------------------------- NFSv4 (traduction knfsd)
#
# Reproduction de fs/nfsd/nfs4acl.c (Linux) : knfsd stocke des ACL POSIX et les
# présente aux clients NFSv4 comme des ACL NFSv4 (_posix_to_nfsv4_one), puis
# retraduit en POSIX les ACL posées par nfs4_setfacl (nfs4_acl_nfsv4_to_posix).
# OpenZFS upstream sous Linux n'a pas d'ACL NFSv4 natives (acltype=nfsv4).

NFS4_ACE_ALLOW, NFS4_ACE_DENY, NFS4_ACE_AUDIT, NFS4_ACE_ALARM = 0, 1, 2, 3
F_FILE_INHERIT, F_DIR_INHERIT, F_NO_PROPAGATE, F_INHERIT_ONLY = 0x1, 0x2, 0x4, 0x8
F_SUCCESS, F_FAILED, F_GROUP = 0x10, 0x20, 0x40
M_READ_DATA, M_WRITE_DATA, M_APPEND_DATA = 0x1, 0x2, 0x4
M_READ_NAMED, M_WRITE_NAMED, M_EXECUTE, M_DELETE_CHILD = 0x8, 0x10, 0x20, 0x40
M_READ_ATTR, M_WRITE_ATTR = 0x80, 0x100
M_DELETE, M_READ_ACL, M_WRITE_ACL, M_WRITE_OWNER, M_SYNCHRONIZE = 0x10000, 0x20000, 0x40000, 0x80000, 0x100000

NFS4_READ_MODE = M_READ_DATA
NFS4_WRITE_MODE = M_WRITE_DATA | M_APPEND_DATA
NFS4_EXECUTE_MODE = M_EXECUTE
NFS4_ANYONE_MODE = M_READ_ATTR | M_READ_ACL | M_SYNCHRONIZE
NFS4_OWNER_MODE = M_WRITE_ATTR | M_WRITE_ACL
NFS4_INHERITANCE_FLAGS = F_FILE_INHERIT | F_DIR_INHERIT
NFS4_SUPPORTED_FLAGS = NFS4_INHERITANCE_FLAGS | F_INHERIT_ONLY | F_GROUP

# ordre d'affichage de nfs4_getfacl (nfs4-acl-tools)
NFS4_PERM_LETTERS = [("r", M_READ_DATA), ("w", M_WRITE_DATA), ("a", M_APPEND_DATA), ("D", M_DELETE_CHILD),
                     ("d", M_DELETE), ("x", M_EXECUTE), ("t", M_READ_ATTR), ("T", M_WRITE_ATTR),
                     ("n", M_READ_NAMED), ("N", M_WRITE_NAMED), ("c", M_READ_ACL), ("C", M_WRITE_ACL),
                     ("o", M_WRITE_OWNER), ("y", M_SYNCHRONIZE)]
NFS4_FLAG_LETTERS = [("f", F_FILE_INHERIT), ("d", F_DIR_INHERIT), ("n", F_NO_PROPAGATE), ("i", F_INHERIT_ONLY),
                     ("S", F_SUCCESS), ("F", F_FAILED), ("g", F_GROUP)]
NFS4_TYPE_LETTERS = {"A": NFS4_ACE_ALLOW, "D": NFS4_ACE_DENY, "U": NFS4_ACE_AUDIT, "L": NFS4_ACE_ALARM}
NFS4_SPECIAL_WHO = ("OWNER@", "GROUP@", "EVERYONE@")


def _mask_from_posix(perm, is_dir, owner=False):
    mask = NFS4_ANYONE_MODE
    if owner:
        mask |= NFS4_OWNER_MODE
    if perm & 4:
        mask |= NFS4_READ_MODE
    if perm & 2:
        mask |= NFS4_WRITE_MODE
        if is_dir:
            mask |= M_DELETE_CHILD
    if perm & 1:
        mask |= NFS4_EXECUTE_MODE
    return mask


def _deny_mask_from_posix(perm, is_dir):
    mask = 0
    if perm & 4:
        mask |= NFS4_READ_MODE
    if perm & 2:
        mask |= NFS4_WRITE_MODE
        if is_dir:
            mask |= M_DELETE_CHILD
    if perm & 1:
        mask |= NFS4_EXECUTE_MODE
    return mask


def _posix_sorted(acl):
    return sorted(acl, key=lambda e: (e[0], e[2] if e[2] is not None else -1))


def posix_to_nfs4(acl, is_dir, default=False):
    """_posix_to_nfsv4_one() : ACL POSIX (liste (tag, perm, id)) → ACE NFSv4.
    Chaque ACE : {type, flag, mask, who ('OWNER@'|'GROUP@'|'EVERYONE@'|'named'), id, group}."""
    acl = _posix_sorted(acl)
    if len(acl) < 3:
        return []
    owner = users = group = groups = other = 0
    mask = 7
    for tag, perm, _i in acl:
        if tag == ACL_USER_OBJ:
            owner = perm
        elif tag == ACL_GROUP_OBJ:
            group = perm
        elif tag == ACL_USER:
            users |= perm
        elif tag == ACL_GROUP:
            groups |= perm
        elif tag == ACL_OTHER:
            other = perm
        elif tag == ACL_MASK:
            mask = perm
    users &= mask
    group &= mask
    groups &= mask
    eflag = (NFS4_INHERITANCE_FLAGS | F_INHERIT_ONLY) if default else 0
    out = []

    def ace(t, flag, m, who, ident=None, grp=False):
        out.append({"type": t, "flag": flag, "mask": m, "who": who, "id": ident, "group": grp})

    deny = (~owner) & (users | group | groups | other) & 7
    if deny:
        ace(NFS4_ACE_DENY, eflag, _deny_mask_from_posix(deny, is_dir), "OWNER@")
    ace(NFS4_ACE_ALLOW, eflag, _mask_from_posix(owner, is_dir, owner=True), "OWNER@")
    for tag, perm, ident in acl:
        if tag != ACL_USER:
            continue
        deny = (~(perm & mask)) & (groups | group | other) & 7
        if deny:
            ace(NFS4_ACE_DENY, eflag, _deny_mask_from_posix(deny, is_dir), "named", ident)
        ace(NFS4_ACE_ALLOW, eflag, _mask_from_posix(perm & mask, is_dir), "named", ident)
    # groupes : d'abord les ALLOW, puis les DENY (un utilisateur peut être dans plusieurs groupes)
    ace(NFS4_ACE_ALLOW, eflag, _mask_from_posix(group, is_dir), "GROUP@")
    named_groups = [(perm, ident) for tag, perm, ident in acl if tag == ACL_GROUP]
    for perm, ident in named_groups:
        ace(NFS4_ACE_ALLOW, eflag | F_GROUP, _mask_from_posix(perm & mask, is_dir), "named", ident, True)
    deny = (~group) & other & 7
    if deny:
        ace(NFS4_ACE_DENY, eflag, _deny_mask_from_posix(deny, is_dir), "GROUP@")
    for perm, ident in named_groups:
        deny = (~(perm & mask)) & other & 7
        if deny:
            ace(NFS4_ACE_DENY, eflag | F_GROUP, _deny_mask_from_posix(deny, is_dir), "named", ident, True)
    ace(NFS4_ACE_ALLOW, eflag, _mask_from_posix(other, is_dir), "EVERYONE@")
    return out


def nfs4_view(access, default, is_dir):
    """nfsd4_get_nfs4_acl() : ACL d'accès puis ACL par défaut (dossiers seulement)."""
    aces = posix_to_nfs4(access, is_dir)
    if is_dir and default:
        aces += posix_to_nfs4(default, is_dir, default=True)
    return aces


_idmap_cache = {}


def _dns_domain():
    """Comme domain_from_dns() de libnfsidmap : nom canonique de gethostbyname(gethostname()), partie après le
    premier point (délai court). libnfsidmap récent interroge aussi l'enregistrement DNS TXT _nfsv4idmapdomain :
    non consulté ici (pas de requête DNS supplémentaire)."""
    import socket
    import threading
    host = socket.gethostname()
    box = {}

    def lookup():
        try:
            box["name"] = socket.gethostbyname_ex(host)[0]
        except OSError:
            pass
    t = threading.Thread(target=lookup, daemon=True)
    t.start()
    t.join(1.5)
    canon = box.get("name") or ""
    if "." in canon:
        return canon.split(".", 1)[1], "domaine DNS (nom canonique de l'hôte)"
    if "." in host:
        return host.split(".", 1)[1], "domaine DNS (nom d'hôte)"
    return "localdomain", "défaut (aucun domaine trouvé ; vérifiez aussi un éventuel TXT _nfsv4idmapdomain)"


def idmap_info():
    """Domaine NFSv4 (idmapd.conf, sinon domaine DNS) et nfs4_disable_idmapping de nfsd."""
    if "info" in _idmap_cache:
        return _idmap_cache["info"]
    domain, source = None, None
    nobody_user, nobody_group = "nobody", "nobody"   # défauts de nfs-utils (libnfsidmap)
    try:
        section = None
        with open(os.environ.get("COCKPIT_ZFS_IDMAPD_CONF", "/etc/idmapd.conf"), errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line[0] in "#;":
                    continue
                # conffile.c (nfs-utils) : la valeur s'arrête au premier « # » ou « ; », même sans espace
                line = re.split(r"[#;]", line, maxsplit=1)[0].strip()
                if line.startswith("["):
                    section = line.strip("[]").strip().lower()
                elif "=" in line:
                    k, v = (x.strip() for x in line.split("=", 1))
                    k = k.lower()
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                        v = v[1:-1].strip()
                    if section == "general" and k == "domain" and v:
                        domain, source = v, "idmapd.conf"
                    elif section == "mapping" and k == "nobody-user" and v:
                        nobody_user = v
                    elif section == "mapping" and k == "nobody-group" and v:
                        nobody_group = v
    except OSError:
        pass
    if not domain:
        domain, source = _dns_domain()
    disable = None
    try:
        with open("/sys/module/nfsd/parameters/nfs4_disable_idmapping") as f:
            disable = f.read().strip().upper().startswith("Y")
    except OSError:
        pass
    info = {"domain": domain, "domain_source": source, "disable_idmapping": disable,
            "nfsd_loaded": disable is not None, "nobody_user": nobody_user, "nobody_group": nobody_group}
    _idmap_cache["info"] = info
    return info


def nfs4_principal(a, numeric=False):
    if a["who"] != "named":
        return a["who"]
    if numeric:
        return str(a["id"])
    name = gid_name(a["id"]) if a["group"] else uid_name(a["id"])
    info = idmap_info()
    if name is None:
        # rpc.idmapd (idtonameres / nfsdcb IC_IDNAME) : identifiant sans nom → Nobody-User / Nobody-Group BRUT,
        # sans @domaine
        return info["nobody_group"] if a["group"] else info["nobody_user"]
    return "%s@%s" % (name, info["domain"])


def nfs4_ace_text(a, is_dir, numeric=False):
    t = {v: k for k, v in NFS4_TYPE_LETTERS.items()}.get(a["type"], "?")
    flags = "".join(c for c, b in NFS4_FLAG_LETTERS if a["flag"] & b)
    perms = "".join(c for c, b in NFS4_PERM_LETTERS
                    if a["mask"] & b and (c != "D" or is_dir))  # nfs4_getfacl masque D sur un fichier
    return "%s:%s:%s:%s" % (t, flags, nfs4_principal(a, numeric), perms)


def nfs4_render(aces, is_dir, numeric=False):
    return [nfs4_ace_text(a, is_dir, numeric) for a in aces]


def nfs4_explain(acl, default, is_dir):
    """Explications en français des ACE DENY générées et des droits bornés par le masque."""
    notes = []
    for label, a in (("accès", acl), ("défaut", default)):
        if not a:
            continue
        mask = acl_get(a, ACL_MASK)
        aces = posix_to_nfs4(a, is_dir, default=(label == "défaut"))
        for x in aces:
            if x["type"] != NFS4_ACE_DENY:
                continue
            who = nfs4_principal(x)
            if x["who"] == "OWNER@":
                notes.append("[%s] DENY OWNER@ : le propriétaire a moins de droits qu'une autre classe ; "
                             "knfsd refuse explicitement ces droits au propriétaire avant les ALLOW suivants." % label)
            elif x["who"] == "GROUP@":
                notes.append("[%s] DENY GROUP@ : « autres » a plus de droits que le groupe propriétaire ; "
                             "un membre du groupe est donc refusé là où un inconnu serait accepté." % label)
            else:
                notes.append("[%s] DENY %s : cette entrée nommée a moins de droits qu'une classe suivante "
                             "(groupe ou autres) ; knfsd ajoute un refus pour garder la sémantique POSIX." % (label, who))
        if mask is not None:
            for tag, perm, ident in a:
                if tag in (ACL_USER, ACL_GROUP, ACL_GROUP_OBJ) and perm & ~mask & 7:
                    nm = "groupe propriétaire" if tag == ACL_GROUP_OBJ else (
                        (uid_name(ident) if tag == ACL_USER else gid_name(ident)) or str(ident))
                    notes.append("[%s] %s : droits stockés %s bornés par le masque %s, le client NFSv4 ne voit que %s"
                                 % (label, nm, _rwx(perm), _rwx(mask), _rwx(perm & mask)))
    return notes


def _rwx(p):
    return ("r" if p & 4 else "-") + ("w" if p & 2 else "-") + ("x" if p & 1 else "-")


def nfs4_view_for(access, default, is_dir, numeric=False):
    aces = nfs4_view(access, default, is_dir)
    return {
        "aces": [dict(a, text=nfs4_ace_text(a, is_dir, numeric)) for a in aces],
        "text": nfs4_render(aces, is_dir, numeric),
        "deny_count": sum(1 for a in aces if a["type"] == NFS4_ACE_DENY),
        "notes": nfs4_explain(access, default if is_dir else [], is_dir),
    }


class _NoAcl(Exception):
    """Le système de fichiers n'a pas d'ACL POSIX : pas d'attribut ACL côté NFSv4."""


# ---- NFSv3 : protocole NFSACL (fs/nfsd/nfs3acl.c, fs/nfs_common/nfsacl.c)

NFS_ACL_MAX_ENTRIES = 1024   # include/linux/nfsacl.h


def nfsacl_wire(acl):
    """Ce que nfsacl_encode() envoie : une ACL minimale (3 entrées) reçoit un masque
    égal aux droits du groupe (ordre canonique user::, group::, mask::, other::)."""
    if not acl:
        return []
    acl = _posix_sorted(acl)
    if len(acl) == 3:
        return [acl[0], acl[1], (ACL_MASK, acl[1][1], None), acl[2]]
    return acl


def posix_text(acl, numeric=False, prefix=""):
    out = []
    for tag, perm, ident in acl:
        name, named = TAG_NAMES.get(tag, ("?", False))
        qual = ""
        if named:
            n = None if numeric else (uid_name(ident) if tag == ACL_USER else gid_name(ident))
            qual = n if n is not None else str(ident)
        out.append("%s%s:%s:%s" % (prefix, name, qual, _rwx(perm)))
    return out


def nfs3_view(access, default, is_dir, posix_fs, st_mode):
    """Vue d'un client NFSv3 (GETACL du protocole NFSACL). Les identifiants circulent en
    numérique : le client les traduit avec ses propres comptes."""
    notes = []
    if not posix_fs:
        # get_inode_acl() renvoie NULL → posix_acl_from_mode() ; SETACL : set_posix_acl → EOPNOTSUPP
        access = base_from_mode(st_mode)
        default = []
        notes.append("Pas d'ACL POSIX sur ce système de fichiers : GETACL renvoie l'ACL minimale dérivée du mode, "
                     "SETACL (setfacl côté client) échoue avec EOPNOTSUPP")
    wa = nfsacl_wire(access)
    wd = nfsacl_wire(default) if is_dir else []
    over = [label for label, a in (("accès", access), ("défaut", default)) if len(a) > NFS_ACL_MAX_ENTRIES]
    if over:
        notes.append("ACL %s de plus de %d entrées : l'encodage NFSACL échoue et le serveur répond par une erreur "
                     "système RPC : GETACL échoue pour ce fichier" % (" et ".join(over), NFS_ACL_MAX_ENTRIES))
    if len(access) == 3:
        notes.append("ACL minimale : le serveur ajoute mask:: = droits du groupe ; le client Linux la ramène "
                     "en général au simple mode")
    notes.append("Identifiants transmis en numérique (UID / GID) : getfacl côté client affiche les noms de "
                 "SES comptes pour ces numéros, ou les numéros s'il ne les connaît pas")
    if not is_dir:
        notes.append("Pas d'ACL par défaut sur un fichier")
    return {
        "text": posix_text(wa) + posix_text(wd, prefix="default:"),
        "numeric_text": posix_text(wa, numeric=True) + posix_text(wd, numeric=True, prefix="default:"),
        "entries_access": len(access), "entries_default": len(default) if is_dir else 0,
        "limit": NFS_ACL_MAX_ENTRIES, "over_limit": bool(over), "posix_fs": posix_fs,
        "notes": notes,
    }


# ---- sens inverse : nfs4_setfacl → POSIX (nfs4_acl_nfsv4_to_posix)

NFS4_PERM_PARSE = {c: b for c, b in NFS4_PERM_LETTERS}
# alias de nfs4_setfacl 0.3.x, valeurs relevées sur l'outil réel (XDR envoyé) :
# R = 0x120089, W = 0x160196 (+ D sur un dossier), X = 0x1200a0
NFS4_PERM_ALIASES = {
    "R": M_READ_DATA | M_READ_NAMED | M_READ_ATTR | M_READ_ACL | M_SYNCHRONIZE,
    "W": M_WRITE_DATA | M_APPEND_DATA | M_WRITE_NAMED | M_READ_ATTR | M_WRITE_ATTR | M_READ_ACL
    | M_WRITE_ACL | M_SYNCHRONIZE,
    "X": M_EXECUTE | M_READ_ATTR | M_READ_ACL | M_SYNCHRONIZE,
}
# nfs4_setfacl écrit « n » pour no-propagate et refuse « p » (« Bad Ace Flag:p ») malgré son aide
NFS4_FLAG_PARSE = {"f": F_FILE_INHERIT, "d": F_DIR_INHERIT, "n": F_NO_PROPAGATE,
                   "i": F_INHERIT_ONLY, "S": F_SUCCESS, "F": F_FAILED, "g": F_GROUP}


def parse_nfs4_text(text, is_dir=True, client_filter=True, notes=None):
    """Analyse un texte au format nfs4_setfacl (ACE séparées par virgules, espaces ou lignes).

    client_filter : reproduit le filtrage de nfs4_setfacl avant envoi (sur un fichier, il retire
    silencieusement f, d, n, i et le bit D). Un autre client (Windows, macOS) envoie l'ACE telle quelle."""
    aces = []
    for raw in re.split(r"[,\s]+", text or ""):
        tok = raw.strip()
        if not tok or tok.startswith("#"):
            continue
        parts = tok.split(":")
        if len(parts) != 4:
            raise PermError("ACE illisible : %r (format type:flags:principal:perms)" % tok)
        t, fl, who, perms = parts
        if t not in NFS4_TYPE_LETTERS:
            raise PermError("Type d'ACE inconnu %r dans %r (A, D, U ou L)" % (t, tok))
        flag = 0
        for c in fl:
            if c not in NFS4_FLAG_PARSE:
                raise PermError("Drapeau inconnu %r dans %r (nfs4_setfacl : « Bad Ace Flag:%s »%s)"
                                % (c, tok, c, " ; no-propagate s'écrit n" if c == "p" else ""))
            flag |= NFS4_FLAG_PARSE[c]
        mask = 0
        for c in perms:
            if c in NFS4_PERM_PARSE:
                mask |= NFS4_PERM_PARSE[c]
            elif c in NFS4_PERM_ALIASES:
                mask |= NFS4_PERM_ALIASES[c]
                if c == "W" and is_dir:
                    mask |= M_DELETE_CHILD
            else:
                raise PermError("Permission inconnue %r dans %r" % (c, tok))
        if not who:
            raise PermError("Principal vide dans %r" % tok)
        if client_filter and who == "GROUP@":
            flag |= F_GROUP  # nfs4_setfacl marque toujours GROUP@ comme groupe
        if client_filter and not is_dir:
            dropped_f = flag & (NFS4_INHERITANCE_FLAGS | F_NO_PROPAGATE | F_INHERIT_ONLY)
            if dropped_f or mask & M_DELETE_CHILD:
                if notes is not None:
                    notes.append("%s : nfs4_setfacl retire sur un fichier les drapeaux d'héritage et le bit D "
                                 "avant l'envoi" % tok)
                flag &= ~(NFS4_INHERITANCE_FLAGS | F_NO_PROPAGATE | F_INHERIT_ONLY)
                mask &= ~M_DELETE_CHILD
        aces.append({"type": NFS4_TYPE_LETTERS[t], "flag": flag, "mask": mask, "principal": who, "text": tok})
    if not aces:
        raise PermError("Aucune ACE")
    return aces


def _resolve_principal(principal, is_group):
    """Comme l'idmapping de knfsd : OWNER@/GROUP@/EVERYONE@, nom@domaine, ou identifiant
    numérique (accepté quand nfs4_disable_idmapping est actif)."""
    if principal in NFS4_SPECIAL_WHO:
        return {"OWNER@": "OWNER@", "GROUP@": "GROUP@", "EVERYONE@": "EVERYONE@"}[principal], None, None
    info = idmap_info()
    if re.fullmatch(r"[0-9]{1,10}", principal):
        ident = int(principal)
        if ident >= 4294967295:
            raise PermError("Identifiant %s hors limites : le client recevrait NFS4ERR_BADOWNER" % principal)
        return "named", ident, ("principal numérique %s : knfsd ne l'accepte que si nfs4_disable_idmapping "
                                "est actif ET en sec=sys (AUTH_SYS) ; sinon NFS4ERR_BADOWNER" % principal)
    name, _, dom = principal.partition("@")
    note = None
    if not dom:
        note = ("principal « %s » sans @domaine : nfsidmap le refusera probablement (NFS4ERR_BADOWNER) ; "
                "écrivez %s@%s" % (principal, principal, info["domain"]))
    elif dom.lower() != info["domain"].lower():
        note = ("domaine %s différent du domaine NFSv4 du serveur (%s) : nfsidmap le refusera "
                "(NFS4ERR_BADOWNER)" % (dom, info["domain"]))
    try:
        ident = grp.getgrnam(name).gr_gid if is_group else pwd.getpwnam(name).pw_uid
    except KeyError:
        raise PermError("%s %s inconnu sur le serveur : le client recevrait NFS4ERR_BADOWNER"
                        % ("groupe" if is_group else "utilisateur", name))
    return "named", ident, note


class _AceState:
    __slots__ = ("allow", "deny")

    def __init__(self, allow=0, deny=0):
        self.allow, self.deny = allow, deny

    def allow_bits(self, m):
        self.allow |= m & ~self.deny

    def deny_bits(self, m):
        self.deny |= m & ~self.allow


class _PosixState:
    def __init__(self):
        self.valid = 0
        self.owner, self.group, self.other, self.everyone = _AceState(), _AceState(), _AceState(), _AceState()
        self.mask = _AceState()
        self.users = []   # [(uid, _AceState)]
        self.groups = []

    def find(self, arr, ident):
        for i, st in arr:
            if i == ident:
                return st
        st = _AceState(self.everyone.allow, self.everyone.deny)
        arr.append((ident, st))
        return st


def _process_ace(state, who, ident, is_group, atype, mask):
    """process_one_v4_ace()."""
    if who == "OWNER@":
        typ = ACL_USER_OBJ
    elif who == "GROUP@":
        typ = ACL_GROUP_OBJ
    elif who == "EVERYONE@":
        typ = ACL_OTHER
    else:
        typ = ACL_GROUP if is_group else ACL_USER
    state.valid |= typ
    allow = atype == NFS4_ACE_ALLOW
    if typ == ACL_USER_OBJ:
        (state.owner.allow_bits if allow else state.owner.deny_bits)(mask)
    elif typ == ACL_USER:
        st = state.find(state.users, ident)
        if allow:
            st.allow_bits(mask)
        else:
            st.deny_bits(mask)
            state.owner.deny_bits(st.deny)
    elif typ == ACL_GROUP_OBJ:
        if allow:
            state.group.allow_bits(mask)
        else:
            state.group.deny_bits(mask)
            m = state.group.deny
            state.owner.deny_bits(m)
            state.everyone.deny_bits(m)
            for _i, s in state.users + state.groups:
                s.deny_bits(m)
    elif typ == ACL_GROUP:
        st = state.find(state.groups, ident)
        if allow:
            st.allow_bits(mask)
        else:
            st.deny_bits(mask)
            m = st.deny
            state.owner.deny_bits(m)
            state.group.deny_bits(m)
            state.everyone.deny_bits(m)
            for _i, s in state.users + state.groups:
                s.deny_bits(m)
    else:  # ACL_OTHER
        targets = [state.owner, state.group, state.other, state.everyone] + [s for _i, s in state.users + state.groups]
        for s in targets:
            (s.allow_bits if allow else s.deny_bits)(mask)


def _low_mode(perm, is_dir):
    """low_mode_from_nfs4() : pessimiste, tous les bits requis pour accorder rwx."""
    write_mode = NFS4_WRITE_MODE | (M_DELETE_CHILD if is_dir else 0)
    mode = 0
    if perm & NFS4_READ_MODE == NFS4_READ_MODE:
        mode |= 4
    if perm & write_mode == write_mode:
        mode |= 2
    if perm & NFS4_EXECUTE_MODE == NFS4_EXECUTE_MODE:
        mode |= 1
    return mode


def _state_to_acl(state, is_dir, default=False):
    """posix_state_to_acl() puis sort_pacl()."""
    if not state.valid and default:
        return None
    acl = [(ACL_USER_OBJ, _low_mode(state.owner.allow, is_dir), None)]
    for ident, s in state.users:
        acl.append((ACL_USER, _low_mode(s.allow, is_dir), ident))
        state.mask.allow |= s.allow
    acl.append((ACL_GROUP_OBJ, _low_mode(state.group.allow, is_dir), None))
    state.mask.allow |= state.group.allow
    for ident, s in state.groups:
        acl.append((ACL_GROUP, _low_mode(s.allow, is_dir), ident))
        state.mask.allow |= s.allow
    if state.users or state.groups:
        acl.append((ACL_MASK, _low_mode(state.mask.allow, is_dir), None))
    acl.append((ACL_OTHER, _low_mode(state.other.allow, is_dir), None))
    return _posix_sorted(acl)


def nfs4_to_posix(text, is_dir, client_filter=True, existing_default=None, existing_mode=None):
    """nfs4_acl_nfsv4_to_posix() appliqué à un texte nfs4_setfacl.
    existing_default : ACL par défaut actuelle du dossier (conservée si aucune ACE héritable) ;
    existing_mode : mode actuel (setuid / setgid / sticky conservés).
    Retourne {representable, error, access, default, mode, readback, notes}."""
    notes = []
    aces = parse_nfs4_text(text, is_dir, client_filter, notes)
    # 1) décodage XDR : les principaux sont résolus en premier (NFS4ERR_BADOWNER)
    resolved = []
    for a in aces:
        who, ident, note = _resolve_principal(a["principal"], bool(a["flag"] & F_GROUP))
        if note and note not in notes:
            notes.append(note)
        resolved.append((who, ident))
    # 2) traduction (EINVAL → NFS4ERR_ATTRNOTSUPP)
    eff, dfl = _PosixState(), _PosixState()
    ignored = 0
    for a, (who, ident) in zip(aces, resolved):
        if a["type"] not in (NFS4_ACE_ALLOW, NFS4_ACE_DENY):
            return {"representable": False, "aces": aces,
                    "error": "ACE d'audit / d'alarme (%s) non gérée : knfsd renvoie EINVAL, le client voit "
                             "NFS4ERR_ATTRNOTSUPP" % a["text"]}
        if a["flag"] & ~NFS4_SUPPORTED_FLAGS:
            bad = "".join(c for c, b in NFS4_FLAG_LETTERS if a["flag"] & ~NFS4_SUPPORTED_FLAGS & b)
            return {"representable": False, "aces": aces,
                    "error": "Drapeau(x) « %s » non géré(s) dans %s (seuls f, d, i, g sont acceptés) : "
                             "EINVAL → NFS4ERR_ATTRNOTSUPP" % (bad, a["text"])}
        if a["flag"] & NFS4_INHERITANCE_FLAGS and not is_dir:
            return {"representable": False, "aces": aces,
                    "error": "Drapeaux d'héritage sur un fichier (%s) : EINVAL → NFS4ERR_ATTRNOTSUPP" % a["text"]}
        if (a["flag"] & F_GROUP) and a["principal"] in ("OWNER@", "EVERYONE@"):
            notes.append("drapeau g ignoré pour %s" % who)
        mapped = NFS4_READ_MODE | NFS4_WRITE_MODE | NFS4_EXECUTE_MODE | (M_DELETE_CHILD if is_dir else 0)
        ignored |= a["mask"] & ~mapped
        if a["flag"] & NFS4_INHERITANCE_FLAGS == 0:
            _process_ace(eff, who, ident, bool(a["flag"] & F_GROUP), a["type"], a["mask"])
            continue
        if bool(a["flag"] & F_FILE_INHERIT) != bool(a["flag"] & F_DIR_INHERIT):
            notes.append("%s : un seul des drapeaux f / d → knfsd active les deux (ACL par défaut POSIX)" % a["text"])
        _process_ace(dfl, who, ident, bool(a["flag"] & F_GROUP), a["type"], a["mask"])
        if not a["flag"] & F_INHERIT_ONLY:
            _process_ace(eff, who, ident, bool(a["flag"] & F_GROUP), a["type"], a["mask"])
    if dfl.valid:
        if not dfl.valid & ACL_USER_OBJ:
            dfl.owner = _AceState(eff.owner.allow, eff.owner.deny)
        if not dfl.valid & ACL_GROUP_OBJ:
            dfl.group = _AceState(eff.group.allow, eff.group.deny)
        if not dfl.valid & ACL_OTHER:
            dfl.other = _AceState(eff.other.allow, eff.other.deny)
    access = _state_to_acl(eff, is_dir)
    default = _state_to_acl(dfl, is_dir, default=True) if is_dir else None
    default_unchanged = is_dir and default is None
    if default_unchanged:
        # posix_state_to_acl() renvoie NULL pour l'ACL par défaut sans ACE héritable et
        # nfsd_setattr() ne la pose que si na_dpacl != NULL : l'ACL par défaut actuelle reste
        notes.append("Aucune ACE héritable : l'ACL par défaut du dossier est INCHANGÉE (non effacée)")
    if ignored:
        notes.append("Bits sans équivalent POSIX ignorés : %s (seuls r, w+a%s, x comptent ; t, T, c, C, o, y, d, n, N "
                     "sont reconstruits par le serveur)" % (
                         "".join(c for c, b in NFS4_PERM_LETTERS if ignored & b), "+D" if is_dir else ""))
    for a in aces:
        need = NFS4_WRITE_MODE | (M_DELETE_CHILD if is_dir else 0)
        if a["type"] == NFS4_ACE_ALLOW and a["mask"] & NFS4_WRITE_MODE and a["mask"] & need != need:
            notes.append("%s : w sans %s → l'écriture n'est PAS accordée en POSIX (conversion pessimiste)"
                         % (a["text"], "a et D" if is_dir else "a"))
    mode = None
    if access:
        g = acl_get(access, ACL_MASK)
        mode = (acl_get(access, ACL_USER_OBJ) << 6) | ((g if g is not None else acl_get(access, ACL_GROUP_OBJ)) << 3) \
            | acl_get(access, ACL_OTHER)
        # posix_acl_equiv_mode / posix_acl_update_mode ne touchent qu'aux bits rwx
        if existing_mode is not None:
            mode |= existing_mode & SPECIAL_BITS
        else:
            notes.append("setuid / setgid / sticky actuels du fichier sont conservés (seuls les bits rwx changent)")
    readback_default = default if default is not None else (existing_default or [])
    readback = nfs4_view(access, readback_default if is_dir else [], is_dir)
    return {"representable": True, "error": None, "aces": aces,
            "access": acl_to_ui(access),
            "default": None if default_unchanged else (acl_to_ui(default) if default else []),
            "default_unchanged": default_unchanged,
            "current_default": acl_to_ui(existing_default) if default_unchanged and existing_default else [],
            "mode": "%04o" % mode if mode is not None else None,
            "readback": nfs4_render(readback, is_dir), "notes": notes}


def cmd_nfs4_translate(params):
    """Teste un texte nfs4_setfacl : représentable ? ACL POSIX obtenue ? relecture par le client."""
    is_dir = params.get("is_dir")
    existing_default, existing_mode = None, None
    if params.get("path"):
        target = resolve_target(params)
        st = os.lstat(target.path)
        if is_dir is None:
            is_dir = stat.S_ISDIR(st.st_mode)
        if stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode):
            existing_mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISDIR(st.st_mode):
                existing_default = raw_acls_for_path(target.path, st)[1]
    try:
        r = nfs4_to_posix(params.get("acl", ""), bool(is_dir if is_dir is not None else True),
                          client_filter=params.get("client", "nfs4_setfacl") == "nfs4_setfacl",
                          existing_default=existing_default, existing_mode=existing_mode)
    except PermError as e:
        r = {"representable": False, "error": str(e), "aces": []}
    r["is_dir"] = bool(is_dir if is_dir is not None else True)
    r["idmap"] = idmap_info()
    return r


NFS_NO_ACL_MSG = (
    "Sans ACL POSIX sur le système de fichiers (acltype=off, ou nfsv4 qui vaut off sous Linux upstream), "
    "knfsd n'annonce pas l'attribut ACL (aclsupport = 0, fs/nfsd/nfs4xdr.c) et refuse tout SETATTR d'ACL "
    "(check_attr_support → NFS4ERR_ATTRNOTSUPP ; le client voit EOPNOTSUPP) : nfs4_getfacl ET nfs4_setfacl "
    "échouent. En NFSv3, le protocole NFSACL ne renvoie que l'ACL minimale dérivée du mode et SETACL échoue. "
    "Seuls les bits de mode s'appliquent.")


def nfsv4_native_support():
    """Détection sans rien modifier. Sous OpenZFS upstream Linux, acltype=nfsv4 est ACCEPTÉ
    mais se comporte comme off (zfsprops(7)) : un dataset en nfsv4 n'est donc pas un indice.
    Seuls les outils d'une pile patchée (TrueNAS : nfs4xdr_*) en sont un."""
    import shutil
    hints = [b for b in ("nfs4xdr_getfacl", "nfs4xdr_setfacl") if shutil.which(b)]
    supported = bool(hints) or sys.platform.startswith("freebsd")
    return {"supported": supported, "hints": hints,
            "message": "ACL NFSv4 natives disponibles (pile patchée détectée : %s)" % ", ".join(hints) if supported else
            "OpenZFS upstream sous Linux : acltype=nfsv4 est accepté mais équivaut à acltype=off (désactive les "
            "ACL) ; PR openzfs/zfs#16967 non fusionnée. Les clients NFSv4 voient les ACL POSIX traduites par knfsd."}


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


def check_dataset_name(dataset):
    """Nom de dataset ZFS accepté (DATASET_CHARS), jamais « - » en tête : refuse toute option déguisée."""
    if not dataset or not isinstance(dataset, str) or dataset.startswith("-") or not DATASET_CHARS.fullmatch(dataset):
        raise PermError("Nom de dataset invalide : %r" % (dataset,))
    return dataset


def zfs_props(dataset):
    check_dataset_name(dataset)
    _c, out, _e = run(["zfs", "get", "-H", "-p", "-o", "property,value,source", ",".join(ACL_PROPS), "--", dataset])
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


def raw_acls_for_path(path, st):
    """ACL internes (accès, défaut) d'un chemin, sans suivre les liens."""
    def get(name):
        try:
            return os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            return None
    raw_a = get(ACCESS_XATTR)
    raw_d = get(DEFAULT_XATTR) if stat.S_ISDIR(st.st_mode) else None
    return (decode_acl(raw_a) if raw_a else base_from_mode(st.st_mode)), (decode_acl(raw_d) if raw_d else [])


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
    acltype = norm_prop("acltype", props.get("acltype", {}).get("value"))
    child_posix = acltype == "posixacl"
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
                    cst = de.stat(follow_symlinks=False)
                    child = describe(de.path, cst)
                    if child_posix and (stat.S_ISREG(cst.st_mode) or stat.S_ISDIR(cst.st_mode)):
                        ca, cd = raw_acls_for_path(de.path, cst)
                        cv = nfs4_view(ca, cd, stat.S_ISDIR(cst.st_mode))
                        child["nfs4_text"] = nfs4_render(cv, stat.S_ISDIR(cst.st_mode))
                        child["nfs4_numeric_text"] = nfs4_render(cv, stat.S_ISDIR(cst.st_mode), numeric=True)
                        child["nfs4_deny"] = sum(1 for a in cv if a["type"] == NFS4_ACE_DENY)
                    children.append(child)
                except (OSError, PermError):
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
    if acltype == "nfsv4":
        warnings.append("acltype=nfsv4 : sous OpenZFS upstream Linux, se comporte comme acltype=off (ACL désactivées)")
    if acltype in ("off", "nfsv4") and info["has_posix_acl"]:
        warnings.append("Des ACL POSIX sont stockées mais ignorées (acltype=%s)" % acltype)
    if info["has_ntacl"]:
        warnings.append("ACL NT présente (security.NTACL) : Samba / ksmbd avec acl_xattr l'affiche au client Windows")
    if os.path.realpath(params.get("path") or path) != os.path.normpath(params.get("path") or path):
        warnings.append("Le chemin demandé contient un lien symbolique : affichage de la cible réelle %s, écriture refusée" % path)
    if target.mountpoint in SYSTEM_MOUNTS:
        warnings.append("Dataset système (monté sur %s) : les modifications sont refusées" % target.mountpoint)
    nfs4, nfs3 = None, None
    posix_fs = acltype == "posixacl"
    if stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode):
        try:
            ra, rd = raw_acls_for_path(path, st)
            nfs3 = nfs3_view(ra, rd, stat.S_ISDIR(st.st_mode), posix_fs, st.st_mode)
        except PermError as e:
            nfs3 = {"error": str(e)}
        try:
            if not posix_fs:
                raise _NoAcl()
            nfs4 = nfs4_view_for(ra, rd, stat.S_ISDIR(st.st_mode))
            nfs4["numeric_text"] = nfs4_render(nfs4_view(ra, rd, stat.S_ISDIR(st.st_mode)),
                                               stat.S_ISDIR(st.st_mode), numeric=True)
            nfs4["idmap"] = idmap_info()
            if xattr == "dir":
                nfs4["notes"].append("xattr=dir : chaque ACL est un fichier caché, lent à chaque GETATTR NFS ; préférez xattr=sa")
            if info["has_ntacl"]:
                nfs4["notes"].append("security.NTACL (ACL Windows de ksmbd / Samba acl_xattr) est invisible et "
                                     "non appliquée côté NFS : seules les ACL POSIX comptent pour les clients NFSv4")
        except _NoAcl:
            native = nfsv4_native_support()
            nfs4 = {"unsupported": True, "aces": [], "text": [], "numeric_text": [], "deny_count": 0,
                    "idmap": idmap_info(), "native": native,
                    "message": native["message"] if (native["supported"] and acltype == "nfsv4") else NFS_NO_ACL_MSG,
                    "notes": []}
        except PermError as e:
            nfs4 = {"error": str(e)}
    return {
        "path": path, "dataset": target.dataset, "mountpoint": target.mountpoint,
        "props": props, "info": info, "acl": acl, "acl_error": acl_error,
        "children": children, "warnings": warnings,
        "acl_mode": acl_mode_for(target.dataset), "nfs4_view": nfs4, "nfs3_view": nfs3,
    }


def cmd_audit(params):
    target = resolve_target(params).open()
    try:
        max_entries = int(params.get("max_entries", 2000000))
        root_st = target.st
        root_setgid = bool(root_st.st_mode & stat.S_ISGID)
        acltype = acl_mode_for(target.dataset)
        kinds = ("world_writable", "orphan_uid", "orphan_gid", "ntacl", "posix_acl", "ignored_posix_acl",
                 "dir_missing_setgid", "foreign_group", "immutable", "setuid",
                 "nfs4_deny", "nfs4_over_mask", "nfs4_unnamed_principal")
        findings = {k: [] for k in kinds}
        counts = {k: 0 for k in kinds}
        owners, groups, modes = {}, {}, {}
        total = files = dirs = 0
        truncated = False
        check_flags = bool(params.get("check_flags", True))
        check_nfs4 = bool(params.get("check_nfs4", True))

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
                # acltype=nfsv4 = off sous Linux upstream : ACL stockées mais ignorées dans les deux cas
                add("posix_acl" if acltype == "posix" else "ignored_posix_acl", e.path)
            if check_nfs4:
                try:
                    acc = read_access(e.fd, st) if acltype == "posix" else base_from_mode(st.st_mode)
                    dfl = read_default(e.fd) if (e.is_dir and acltype == "posix") else []
                except (OSError, PermError):
                    acc, dfl = base_from_mode(st.st_mode), []
                view = nfs4_view(acc, dfl, e.is_dir)
                if any(a["type"] == NFS4_ACE_DENY for a in view):
                    add("nfs4_deny", e.path)
                for a in (acc, dfl):
                    mk = acl_get(a, ACL_MASK)
                    if mk is not None and any(t in (ACL_USER, ACL_GROUP, ACL_GROUP_OBJ) and p & ~mk & 7
                                              for t, p, _i in a):
                        add("nfs4_over_mask", e.path)
                        break
                if any((t == ACL_USER and uid_name(i) is None) or (t == ACL_GROUP and gid_name(i) is None)
                       for a in (acc, dfl) for t, _p, i in a):
                    add("nfs4_unnamed_principal", e.path)
            if check_flags:
                fl = get_fsflags_fd(e.fd)
                if fl and fl & PROTECT_FLAGS:
                    add("immutable", e.path)

        def top(d, namer):
            return [{"id": k, "name": namer(k), "count": v}
                    for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:15]]

        props = zfs_props(target.dataset)
        nfs4 = dict(idmap_info())
        nfs4.update({
            "xattr": props.get("xattr", {}).get("value"),
            "acltype": norm_prop("acltype", props.get("acltype", {}).get("value")),
            "native": nfsv4_native_support(),
            "orphans": counts["orphan_uid"] + counts["orphan_gid"],
        })
        notes = []
        if nfs4["xattr"] == "dir":
            notes.append("xattr=dir : les ACL sont des fichiers cachés, chaque GETATTR NFS les relit ; passez en xattr=sa")
        if nfs4["acltype"] != "posixacl" and not nfs4["native"]["supported"]:
            notes.append(NFS_NO_ACL_MSG)
        if nfs4["orphans"]:
            notes.append("UID / GID sans nom : avec sec=sys et nfs4_disable_idmapping=Y le client voit le numéro ; "
                         "avec sec=krb5* ou idmapping actif, il voit nobody")
        if counts["ntacl"]:
            notes.append("ACL NT (security.NTACL) présentes : invisibles et non appliquées côté NFS")
        if nfs4["disable_idmapping"] is None:
            notes.append("nfsd n'est pas chargé : nfs4_disable_idmapping inconnu (défaut noyau : Y)")
        nfs4["notes"] = notes
        return {
            "path": target.path, "dataset": target.dataset, "acl_mode": acltype,
            "total": total, "files": files, "dirs": dirs, "truncated": truncated,
            "counts": counts, "findings": findings, "nfs4": nfs4,
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
    check_dataset_name(dataset)
    _c, out, _e = run(["zfs", "allow", "--", dataset])
    return {"dataset": dataset, "entries": parse_zfs_allow(out), "known_perms": ZFS_DELEGATION_PERMS, "raw": out}


# Permissions qu'il est dangereux de déléguer à « tout le monde » (zfs allow -e) : un utilisateur quelconque
# pourrait recevoir un flux contenant des binaires setuid ou des périphériques, créer et monter des datasets,
# détruire ou renommer des données, ou redéléguer lui-même (allow). Les @ensembles sont traités comme
# dangereux : leur contenu peut changer après coup.
EVERYONE_DANGEROUS_PERMS = {"allow", "receive", "setuid", "devices", "create", "mount", "destroy", "rename",
                            "promote", "clone", "zoned"}


def everyone_dangerous(perms):
    return [p for p in perms if p in EVERYONE_DANGEROUS_PERMS or p.startswith("@")]


def cmd_delegate(params):
    dataset = params.get("dataset")
    op = params.get("op", "allow")
    kind = params.get("kind", "user")
    who = str(params.get("who", "") or "")
    scope = params.get("scope", "both")
    perms = [p.strip() for p in params.get("perms", []) if p.strip()]
    if not dataset:
        raise PermError("Dataset requis")
    check_dataset_name(dataset)
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
    cmd.append("--")
    if perms:
        cmd.append(",".join(perms))
    cmd.append(dataset)
    warnings = []
    risky = everyone_dangerous(perms) if (op == "allow" and kind == "everyone") else []
    if risky:
        warnings.append("Délégation à TOUT LE MONDE de permissions dangereuses (%s) : n'importe quel utilisateur "
                        "du système pourra s'en servir (flux setuid via receive, création et montage de datasets, "
                        "destruction, redélégation). Confirmation explicite requise." % ", ".join(risky))
    if params.get("dry_run", True):
        return {"dry_run": True, "command": " ".join(cmd), "warnings": warnings,
                "requires_confirmation": bool(risky)}
    if risky and params.get("confirmer_tout_le_monde") is not True:
        raise PermError("Refusé : délégation à tout le monde de %s sans confirmation explicite "
                        "(paramètre confirmer_tout_le_monde)" % ", ".join(risky))
    run(cmd)
    return {"dry_run": False, "command": " ".join(cmd), "warnings": warnings}


# --------------------------------------------------------------------------- préréglages

def cmd_preset(params):
    dataset = params.get("dataset")
    preset = PRESETS.get(params.get("preset"))
    if not dataset or not preset:
        if params.get("list"):
            return {"presets": {k: v["label"] for k, v in PRESETS.items()}}
        raise PermError("Dataset et préréglage requis")
    check_dataset_name(dataset)
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
        commands.append(["zfs", "set", "%s=%s" % (k, v), "--", dataset])
    notes = []
    if params.get("preset") == "macos-smb" and props.get("normalization", {}).get("value") != "formD":
        notes.append("normalization=formD est recommandé pour macOS mais ne se fixe qu'à la création (zfs create -o normalization=formD)")
    if params.get("preset") == "nfsv4":
        native = nfsv4_native_support()
        notes.append(native["message"])
        if not native["supported"]:
            notes.append("Sous Linux upstream, acltype=nfsv4 = acltype=off : cela DÉSACTIVE les ACL "
                         "(plus d'ACL nfsacl en NFSv3, plus d'attribut ACL en NFSv4). Utilisez « nfsv4-posix ».")
            if not params.get("dry_run", True):
                raise PermError("acltype=nfsv4 équivaut à acltype=off sous OpenZFS upstream Linux (désactive les ACL) : "
                                "rien n'a été modifié")
    if params.get("preset") == "nfsv4-posix":
        notes.append("Export : l'option no_acl est sans effet sur knfsd récent (NFSEXP_NOACL n'est lu nulle part) ; "
                     "sec=krb5i/krb5p pour des noms fiables ; "
                     "NFSv4.1 n'a pas les xattrs utilisateur (NFSv4.2 seulement)")
    if params.get("preset") in ("noacl-unix", "posixacl-smb", "nfsv4-posix"):
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


# --------------------------------------------------------------------------- NFSv3 + NFSv4.1 : exports et sharenfs

# Clés acceptées par OpenZFS dans sharenfs sous Linux (lib/libzfs/os/linux/libzfs_share_nfs.c,
# get_linux_shareopts_cb) + rw / ro (listes d'hôtes séparées par « : »), sec, anon, root_mapping, nosub
# fsuid figure dans la liste d'OpenZFS mais nfs-utils ne le connaît pas : retiré (exportfs ignorerait la ligne
# et toutes les suivantes de zfs.exports).
SHARENFS_KEYS = {
    "all_squash", "anongid", "anonuid", "async", "auth_nlm", "crossmnt", "fsid", "hide",
    "insecure", "insecure_locks", "mountpoint", "mp", "no_acl", "no_all_squash", "no_auth_nlm",
    "no_root_squash", "no_subtree_check", "no_wdelay", "nohide", "refer", "replicas", "root_squash",
    "secure", "secure_locks", "subtree_check", "sync", "wdelay",
    "rw", "ro", "sec", "anon", "root_mapping", "nosub",
}
SHARENFS_CHARS = re.compile(r"[A-Za-z0-9_=,.:@/*\-\[\]]{1,1024}")
EXPORT_OPT_CHARS = re.compile(r"[A-Za-z0-9_=,.:@/\-]{1,1024}")
CLIENT_CHARS = re.compile(r"[A-Za-z0-9_.*?:@/\[\]][A-Za-z0-9_.*?:@/\-\[\]]{0,254}")   # jamais de « - » initial
# options sharenfs qui prennent une valeur ; toutes les autres sont booléennes (« = » interdit)
SHARENFS_VALUE_KEYS = {"anongid", "anonuid", "fsid", "mountpoint", "mp", "refer", "replicas", "rw", "ro", "sec",
                       "anon", "root_mapping"}
SHARENFS_OPTIONAL_VALUE = {"rw", "ro", "mountpoint", "mp"}
SEC_FLAVORS = {"sys", "krb5", "krb5i", "krb5p"}
INVALID_OPT_MSG = (" — une option invalide fait ignorer par exportfs cette ligne ET toutes les lignes suivantes de "
                   "/etc/exports.d/zfs.exports (les autres datasets ne seraient plus exportés)")
DATASET_CHARS = re.compile(r"[A-Za-z0-9_.:\-]+(/[A-Za-z0-9_.:\- ]+)*")


def exports_paths():
    main = os.environ.get("COCKPIT_ZFS_EXPORTS", "/etc/exports")
    d = os.environ.get("COCKPIT_ZFS_EXPORTS_D", "/etc/exports.d")
    files = [main]
    try:
        files += [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".exports")]
    except OSError:
        pass
    return files


def _unescape_export_path(p):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), p)


def escape_export_path(p):
    """Comme nfs_escape_mountpoint() d'OpenZFS (espaces, tabulations, retours, « \\ » en octal), plus « " » :
    xgettok() de nfs-utils bascule en mode guillemets sur « " » et le retire du chemin."""
    return "".join("\\%03o" % ord(c) if c in "\t\n\v\f\r \\\"" else c for c in p)


def _split_tokens(line):
    """Découpe comme xgettok() de nfs-utils : « " » bascule le mode guillemets (et disparaît),
    « # » ne commence un commentaire qu'en début de jeton, hors guillemets."""
    toks, cur, quote, started = [], "", False, False
    for ch in line:
        if ch == '"':
            quote = not quote
            started = True
            continue
        if not quote and ch == "#" and not started:
            break
        if ch.isspace() and not quote:
            if started:
                toks.append(cur)
                cur, started = "", False
            continue
        cur += ch
        started = True
    if started:
        toks.append(cur)
    return toks


def parse_exports_text(text, fname):
    """Lecture minimale d'un fichier exports(5) : chemin, clients et options."""
    entries, logical, start = [], "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        if not logical:
            start = n
        line = raw.rstrip()
        if line.endswith("\\") and not line.endswith("\\\\"):
            logical += line[:-1] + " "
            continue
        logical += line
        body = logical.strip()
        logical = ""
        toks = _split_tokens(body) if body else []
        if not toks:
            continue
        path = _unescape_export_path(toks[0])
        defaults, clients, notes = [], [], []
        for t in toks[1:]:
            if t.startswith("-"):
                defaults = [o for o in t[1:].split(",") if o]
                continue
            m = re.fullmatch(r"([^()]*)(?:\(([^)]*)\))?", t)
            if not m:
                notes.append("élément illisible : %s" % t)
                continue
            host = m.group(1) or "*"
            if not m.group(1) and m.group(2) is not None:
                notes.append("« (%s) » sans hôte : exporté à TOUS les clients (espace avant la parenthèse ?)" % m.group(2))
            opts = defaults + [o for o in (m.group(2) or "").split(",") if o]
            clients.append({"host": host, "options": opts})
        if not clients:
            clients.append({"host": "*", "options": defaults})
            notes.append("aucun client indiqué : exporté à tous (*)")
        npath = os.path.normpath(path)
        entries.append({"path": npath, "realpath": os.path.realpath(npath), "file": fname, "line": start,
                        "clients": clients,
                        "source": "sharenfs" if os.path.basename(fname) == "zfs.exports" else "manuel",
                        "notes": notes})
    return entries


def read_exports():
    out = []
    for f in exports_paths():
        try:
            with open(f, errors="surrogateescape") as fh:
                out += parse_exports_text(fh.read(), f)
        except OSError:
            pass
    return out


def _opt_value(options, key):
    for o in options:
        k, _, v = o.partition("=")
        if k == key:
            return v if _ else True
    return None


def fsid_from_guid(guid):
    h = "%032x" % (int(guid) & ((1 << 128) - 1))
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def _list_datasets(dataset):
    if not dataset or not DATASET_CHARS.fullmatch(dataset) or dataset.startswith("-"):
        raise PermError("Nom de dataset invalide")
    _c, out, _e = run(["zfs", "list", "-H", "-p", "-r", "-t", "filesystem", "-o",
                       "name,mountpoint,mounted,sharenfs,acltype,xattr,guid", "--", dataset])
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        rows.append({"name": parts[0], "mountpoint": parts[1], "mounted": parts[2] == "yes",
                     "sharenfs": parts[3], "acltype": norm_prop("acltype", parts[4]), "xattr": parts[5],
                     "guid": parts[6]})
    _c, out, _e = run(["zfs", "get", "-H", "-p", "-r", "-t", "filesystem", "-o", "name,value,source",
                       "sharenfs", "--", dataset], check=False)
    src = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            src[parts[0]] = parts[2]
    for r in rows:
        r["sharenfs_source"] = src.get(r["name"], "")
        r["path"] = os.path.normpath(r["mountpoint"]) if r["mountpoint"].startswith("/") else None
    return rows


def _oz_split_hosts(value):
    """Découpage exact de foreach_nfs_host_cb() (OpenZFS, libzfs_share_nfs.c, Linux) d'une liste rw= / ro=.
    Renvoie les hôtes tels qu'écrits dans zfs.exports (après retrait du « @ » par get_linux_hostspec)."""
    out = []
    host = value
    while True:
        if host.startswith("["):
            h = host[1:]
            j = h.find("]")
            if j < 0:
                raise PermError("« [ » sans « ] » dans %r : OpenZFS refuse (SA_SYNTAX_ERR)" % value)
            after = h[j + 1:]
            if after == "":
                cur, nxt = h[:j], None
            elif after.startswith("/"):
                c = after.find(":", 1)
                cur, nxt = (h[:j] + after, None) if c < 0 else (h[:j] + after[:c], after[c + 1:])
            elif after.startswith(":"):
                cur, nxt = h[:j], after[1:]
            else:
                raise PermError("Caractère inattendu après « ] » dans %r : OpenZFS refuse (SA_SYNTAX_ERR)" % value)
            bracketed = True
        else:
            c = host.find(":")
            cur, nxt = (host, None) if c < 0 else (host[:c], host[c + 1:])
            bracketed = False
        out.append({"raw": cur, "host": cur[1:] if cur.startswith("@") else cur, "bracketed": bracketed})
        if nxt is None:
            return out
        host = nxt


def sharenfs_lines(value, mountpoint="<mountpoint>"):
    """Simule les lignes que nfs_add_entry() écrit dans zfs.exports. Lève PermError si OpenZFS refuserait."""
    if value == "on":
        value = "rw,crossmnt"
    if value in ("off", "", "-"):
        return []
    opts = [o for o in value.split(",") if o]
    linux = ["no_subtree_check", "mountpoint"]
    for o in opts:
        k, eq, v = o.partition("=")
        if k in ("sec", "ro", "rw"):
            continue
        if k == "anon":
            k = "anonuid"
        if k == "root_mapping":
            linux.append("root_squash")
            k = "anonuid"
        if k == "nosub":
            k = "subtree_check"
        linux.append(k + ("=" + v if eq else ""))
    sec, lines = "sys", []
    for o in opts:
        k, eq, v = o.partition("=")
        if k == "sec":
            sec = v
        elif k in ("rw", "ro"):
            for h in _oz_split_hosts(v if eq else "*"):
                lines.append({"access": k, "host": h["host"], "raw": h["raw"], "bracketed": h["bracketed"],
                              "sec": sec,
                              "line": "%s %s(sec=%s,%s,%s)" % (escape_export_path(mountpoint), h["host"], sec, k,
                                                               ",".join(linux))})
    return lines


def _sharenfs_world(value):
    """Accès (« rw », « ro ») ouverts à TOUS les clients : hôte « * » ou hôte vide (nfs-utils : « No host name
    given », pris comme « * »). Tolérant : une valeur illisible renvoie un ensemble vide."""
    try:
        lines = sharenfs_lines(value)
    except PermError:
        return set()
    return {l["access"] for l in lines if l["host"] in ("*", "")}


def _sharenfs_world_rw(value):
    return bool(_sharenfs_world(value))


def _acl_counts(path):
    try:
        st = os.lstat(path)
        a, d = raw_acls_for_path(path, st)
        return len(a), len(d)
    except (OSError, PermError):
        return None, None


def cmd_nfs_datasets(params):
    """Compatibilité NFSv3 + NFSv4.1 de chaque dataset sous `dataset`."""
    rows = _list_datasets(params.get("dataset"))
    exports = read_exports()
    by_path = {}
    for e in exports:
        by_path.setdefault(e.get("realpath", e["path"]), []).append(e)
    fsid_users = {}
    for e in exports:
        for c in e["clients"]:
            v = _opt_value(c["options"], "fsid")
            if v and v is not True:
                fsid_users.setdefault(str(v).lower(), set()).add(e["path"])
    scan = bool(params.get("scan_acls"))
    max_entries = int(params.get("max_entries", 200000))
    exported = {}
    for r in rows:
        mnt = os.path.realpath(r["path"]) if r["path"] else None
        manual = [e for e in by_path.get(mnt, []) if e["source"] == "manuel"] if mnt else []
        zfs_lines = [e for e in by_path.get(mnt, []) if e["source"] == "sharenfs"] if mnt else []
        r["exports"] = manual + zfs_lines
        r["sharenfs_on"] = r["sharenfs"] not in ("off", "-", "")
        r["exported"] = bool(manual or (r["sharenfs_on"] and r["mounted"]))
        exported[r["name"]] = r
    names = [r["name"] for r in rows]
    for r in rows:
        f = []

        def add(level, code, msg):
            f.append({"level": level, "code": code, "message": msg})
        opts = [o for e in r["exports"] for c in e["clients"] for o in c["options"]]
        if r["sharenfs_on"]:
            opts += [o for o in r["sharenfs"].split(",") if o]
        # parent = l'export le plus proche par CHEMIN de montage (mountpoint personnalisé, legacy, none)
        parent = None
        if r["path"]:
            best = -1
            for other in rows:
                op = other["path"]
                if other is r or not op or not other["exported"] or not other["mounted"]:
                    continue
                if r["path"].startswith(op.rstrip("/") + "/") and len(op) > best:
                    parent, best = other, len(op)
        if not r["mounted"] or not r["path"]:
            add("info", "not_mounted", "Non monté (ou mountpoint=%s) : rien n'est exporté ; sharenfs n'exporte que "
                "les datasets montés (option mountpoint ajoutée par OpenZFS)" % r["mountpoint"])
        elif not r["exported"] and parent:
            p_opts = [o for e in parent["exports"] for c in e["clients"] for o in c["options"]] + \
                (parent["sharenfs"].split(",") if parent["sharenfs_on"] else [])
            if "crossmnt" in p_opts or parent["sharenfs"] == "on":
                add("warning", "implicit_child",
                    "Pas d'export explicite : atteint seulement par traversée grâce à crossmnt sur %s (export implicite "
                    "aux options du parent, géré par mountd), sans fsid propre. Selon la version de nfs-utils, mountd "
                    "peut autoriser le montage direct d'un sous-montage avec crossmnt ; exportez-le explicitement "
                    "pour être sûr (NFSv3 surtout)" % parent["name"])
            else:
                add("error", "hidden_child",
                    "Non exporté alors que %s l'est : en NFSv3 comme en NFSv4.1, le client voit le dossier VIDE du "
                    "point de montage (nfsd_cross_mnt ne traverse que vers un export) : ajoutez un export explicite"
                    % parent["name"])
        if r["exported"] and parent:
            p_opts = [o for e in parent["exports"] for c in e["clients"] for o in c["options"]] + \
                (parent["sharenfs"].split(",") if parent["sharenfs_on"] else [])
            if "crossmnt" not in p_opts and parent["sharenfs"] != "on" and "nohide" not in opts:
                add("info", "v3_mount_separately",
                    "NFSv3 : un client qui monte %s voit ce dossier vide (traversée v3 seulement avec crossmnt sur le "
                    "parent ou nohide ici) ; NFSv4.1 traverse automatiquement. Montez-le séparément en v3, ou ajoutez "
                    "crossmnt au parent" % parent["name"])
        manual = [e for e in r["exports"] if e["source"] == "manuel"]
        if manual and r["sharenfs_on"]:
            add("error", "duplicate",
                "Exporté à la fois par sharenfs (%s) et par %s : pour un même client, c'est la PREMIÈRE entrée lue "
                "qui gagne (/etc/exports avant /etc/exports.d, fichiers dans l'ordre versionsort ; les suivantes sont "
                "marquées « [IGNORED] ») ; pour des clients différents, toutes s'appliquent. Gardez une seule "
                "définition (et ne laissez pas cockpit-file-sharing gérer ce chemin si sharenfs est utilisé)"
                % (r["sharenfs"], ", ".join(sorted({e["file"] for e in manual}))))
        if r["sharenfs_on"] and r["sharenfs_source"].startswith("inherited"):
            add("info", "sharenfs_inherited", "sharenfs hérité (%s) : ce dataset est exporté automatiquement avec les "
                "options du parent" % r["sharenfs_source"])
            if _opt_value(r["sharenfs"].split(","), "fsid"):
                add("error", "fsid_inherited", "fsid défini dans un sharenfs hérité : même fsid que le parent, les "
                    "clients confondront les deux systèmes de fichiers ; mettez fsid en local ou retirez-le")
        if r["sharenfs_on"]:
            try:
                validate_sharenfs(r["sharenfs"])
            except PermError as e:
                add("error", "sharenfs_invalid", "sharenfs=%s : %s" % (r["sharenfs"], e))
            world = _sharenfs_world(r["sharenfs"])
            if world:
                add("warning", "world", "sharenfs=%s exporte vers TOUS les clients (*) en %s" % (
                    r["sharenfs"], " et ".join("lecture-écriture" if a == "rw" else "lecture seule"
                                               for a in sorted(world, reverse=True))))
        for e in manual:
            for n in e["notes"]:
                add("warning", "export_note", "%s:%d : %s" % (e["file"], e["line"], n))
        fsids = {str(_opt_value(c["options"], "fsid")).lower() for e in r["exports"] for c in e["clients"]
                 if _opt_value(c["options"], "fsid") not in (None, True)}
        for v in fsids:
            others = fsid_users.get(v, set()) - {r["path"]}
            if others:
                add("error", "fsid_duplicate", "fsid=%s aussi utilisé par %s : les clients confondraient ces systèmes "
                    "de fichiers" % (v, ", ".join(sorted(others))))
        if r["exported"] and not fsids and not _opt_value(r["sharenfs"].split(","), "fsid"):
            add("info", "no_fsid", "Pas de fsid : nfs-utils dérive l'identifiant du dataset (statfs) ; un fsid "
                "explicite reste stable même après zfs send / receive (le générateur propose fsid=<guid>)")
        if r["exported"] and not _opt_value(opts, "sec"):
            add("info", "sec_default", "Pas de sec= : sec=sys par défaut (UID / GID envoyés par le client)")
        if r["acltype"] != "posixacl":
            add("error" if r["exported"] else "warning", "no_posix_acl",
                "acltype=%s : %s" % (r["acltype"], NFS_NO_ACL_MSG))
        if r["xattr"] == "dir":
            add("warning", "xattr_dir", "xattr=dir : chaque ACL est un fichier caché relu à chaque GETACL / GETATTR ; "
                "passez en xattr=sa")
        over = []
        if r["path"] and r["mounted"] and r["acltype"] == "posixacl":
            na, nd = _acl_counts(r["path"])
            r["root_acl_entries"] = {"access": na, "default": nd}
            if (na or 0) > NFS_ACL_MAX_ENTRIES or (nd or 0) > NFS_ACL_MAX_ENTRIES:
                over.append(r["path"])
            if scan:
                try:
                    tgt = resolve_target({"path": r["path"]}).open()
                    try:
                        count = 0
                        for ent in walk(tgt, {"cross_datasets": False}):
                            count += 1
                            if count > max_entries:
                                add("info", "scan_truncated", "Analyse des ACL arrêtée après %d objets" % max_entries)
                                break
                            a = read_access(ent.fd, ent.st)
                            d = read_default(ent.fd) if ent.is_dir else []
                            if len(a) > NFS_ACL_MAX_ENTRIES or len(d) > NFS_ACL_MAX_ENTRIES:
                                if len(over) < 50:
                                    over.append(ent.path)
                    finally:
                        tgt.close()
                except (OSError, PermError) as e:
                    add("warning", "scan_error", "Analyse des ACL impossible : %s" % e)
        for o in over:
            add("error", "acl_too_long", "%s : ACL de plus de %d entrées : GETACL NFSv3 échoue (l'encodage NFSACL "
                "échoue, le serveur répond par une erreur système RPC). En NFSv4.1, knfsd n'a pas ce plafond ; la "
                "limite est la taille encodée de l'attribut ACL côté client (environ 64 Kio)"
                % (o, NFS_ACL_MAX_ENTRIES))
        r["findings"] = f
        blocking = {"hidden_child", "duplicate", "fsid_duplicate", "fsid_inherited", "no_posix_acl", "acl_too_long",
                    "not_mounted", "implicit_child"}
        ok = r["exported"] and not any(x["code"] in blocking for x in f)
        r["compat"] = {"v3": ok, "v41": ok,
                       "summary": "NFSv3 + NFSv4.1 : prêt" if ok else
                       ("non exporté" if not r["exported"] else "à corriger")}
    return {"dataset": params.get("dataset"), "datasets": rows, "exports": exports,
            "exports_files": exports_paths(),
            "notes": [
                "NFSv3 ne traverse pas les points de montage sans crossmnt / nohide : chaque dataset enfant doit être "
                "exporté explicitement pour être monté directement en NFSv3.",
                "NFSv3 : les ACL POSIX passent telles quelles par le protocole NFSACL (identifiants numériques) ; "
                "NFSv4.1 : knfsd les traduit en ACL NFSv4.",
                "sharenfs (/etc/exports.d/zfs.exports) et cockpit-file-sharing ne doivent pas gérer le même chemin.",
            ]}


def _validate_clients(clients):
    out = []
    for c in clients or []:
        c = str(c).strip()
        if not c:
            continue
        if c.startswith("-") or not CLIENT_CHARS.fullmatch(c):
            raise PermError("Client invalide : %r (un client commençant par « - » serait lu comme options par "
                            "défaut et ferait ignorer le reste du fichier)" % c)
        out.append(c)
    if not out:
        raise PermError("Indiquez au moins un client (adresse, réseau CIDR, nom ou *)")
    return out


def _sharenfs_host(c):
    """Client du format exports → hôte sharenfs (syntaxe OpenZFS)."""
    if c.startswith("@"):
        raise PermError("%s : un @netgroup n'est pas représentable dans sharenfs sous Linux (OpenZFS retire le « @ » "
                        "et en ferait un nom d'hôte) ; utilisez le format /etc/exports" % c)
    try:
        net = ipaddress.ip_network(c, strict=False)
    except ValueError:
        net = None
    if net is not None:
        is_net = "/" in c
        if net.version == 6:
            if is_net:
                return "[%s]/%d" % (net.network_address, net.prefixlen)
            return "[%s]" % ipaddress.ip_address(c)
        return ("@%s" % c) if is_net else c
    if c.startswith("[") or ":" in c:
        raise PermError("Client %r illisible pour sharenfs" % c)
    return c


def cmd_nfs_generate(params):
    """Lignes d'export (ou valeurs sharenfs) pour les datasets sans export explicite.
    N'écrit rien : renvoie le texte à copier ou les commandes à lancer."""
    rows = cmd_nfs_datasets({"dataset": params.get("dataset")})["datasets"]
    fmt = params.get("format", "exports")
    clients = _validate_clients(params.get("clients"))
    options = str(params.get("options", "rw,sync,no_subtree_check,sec=sys")).strip().strip(",")
    if not EXPORT_OPT_CHARS.fullmatch(options):
        raise PermError("Options invalides : %r" % options)
    opt_list = [o for o in options.split(",") if o]
    if any(o.partition("=")[0] == "fsid" for o in opt_list):
        raise PermError("Ne mettez pas fsid dans les options communes : il doit être unique par dataset")
    fsid_mode = params.get("fsid", "guid" if fmt == "exports" else "none")
    include_all = bool(params.get("include_exported"))
    if fmt == "sharenfs" and "*" in clients and len(clients) > 1:
        raise PermError("« * » couvre déjà tous les clients : retirez les autres clients ou retirez « * » "
                        "(sharenfs ne peut pas combiner les deux)")
    lines, commands, skipped, notes = [], [], [], []
    for r in rows:
        if not r["path"] or not r["mounted"]:
            skipped.append({"name": r["name"], "reason": "non monté"})
            continue
        if r["exported"] and not include_all:
            continue
        per = list(opt_list)
        if fsid_mode == "guid":
            per.append("fsid=" + fsid_from_guid(r["guid"]))
            if r["exported"]:
                notes.append("%s est déjà exporté : lui donner ou changer son fsid change les filehandles, les "
                             "clients montés recevront ESTALE (démontez puis remontez-les)" % r["name"])
        if fmt == "exports":
            line = escape_export_path(r["path"]) + " " + " ".join("%s(%s)" % (c, ",".join(per)) for c in clients)
            lines.append({"name": r["name"], "line": line})
        elif fmt == "sharenfs":
            # exports(5) : lecture seule par défaut quand ni rw ni ro n'est donné
            access = "rw" if "rw" in per else "ro"
            hosts = ":".join(_sharenfs_host(c) for c in clients if c != "*")
            secs = [o for o in per if o.partition("=")[0] == "sec"]
            rest = [o for o in per if o not in ("rw", "ro") and o.partition("=")[0] != "sec"
                    and o.partition("=")[0] in SHARENFS_KEYS]
            dropped = [o for o in per if o not in ("rw", "ro") and o.partition("=")[0] not in SHARENFS_KEYS]
            if dropped:
                notes.append("Options sans équivalent sharenfs ignorées : %s" % ", ".join(sorted(set(dropped))))
            # sec= AVANT rw= / ro= : OpenZFS ne l'applique qu'aux hôtes qui le suivent
            value = ",".join(rest + secs + ["%s=%s" % (access, hosts) if hosts else access])
            value = validate_sharenfs(value)
            commands.append({"name": r["name"], "value": value,
                             "command": "zfs set %s %s" % (shlex.quote("sharenfs=" + value),
                                                           shlex.quote(r["name"]))})
        else:
            raise PermError("Format inconnu : %s" % fmt)
    if fsid_mode == "guid":
        notes.append("fsid tiré du GUID du dataset : stable après zfs rename, mais une réplique (zfs send | recv) a "
                     "un autre GUID : copiez la ligne d'export d'origine sur la réplique, ne la régénérez pas")
    if fmt == "exports":
        notes.append("À copier dans /etc/exports ou /etc/exports.d/<nom>.exports, puis : exportfs -ra")
        notes.append("Un export par dataset : NFSv3 peut monter chaque dataset, NFSv4.1 les traverse depuis le parent")
    else:
        notes.append("sharenfs est hérité : un futur dataset enfant sera exporté automatiquement avec les options du parent")
        if fsid_mode == "guid":
            notes.append("fsid défini localement sur chaque dataset ; un nouvel enfant en hériterait : redéfinissez-le")
    return {"format": fmt, "lines": lines, "commands": commands, "skipped": skipped, "notes": notes,
            "text": "\n".join(l["line"] for l in lines) if fmt == "exports" else
            "\n".join(c["command"] for c in commands)}


def _check_host(raw, bracketed, value):
    if raw == "":
        raise PermError("Hôte vide dans %r (« : » en trop ou adresse IPv6 sans crochets) : nfs-utils l'exporterait à "
                        "TOUS les clients (« No host name given » → *). Écrivez l'IPv6 entre crochets : "
                        "[fd00::5] ou [fd00::]/64" % value)
    if raw.startswith("-"):
        raise PermError("Hôte commençant par « - » refusé : %r" % raw)
    if bracketed:
        try:
            if "/" in raw:
                ipaddress.IPv6Network(raw, strict=False)
            else:
                ipaddress.IPv6Address(raw)
        except ValueError:
            raise PermError("Adresse IPv6 invalide entre crochets : %r" % raw)
        return
    if raw.startswith("/"):
        raise PermError("Élément %r dans %r : préfixe sans adresse (IPv6 sans crochets ?)" % (raw, value))
    if raw.startswith("@"):
        try:
            ipaddress.IPv4Network(raw[1:], strict=False)
        except ValueError:
            raise PermError("%r : sous Linux, OpenZFS retire seulement le « @ » ; un groupe réseau (netgroup) "
                            "n'est pas représentable dans sharenfs. Utilisez @a.b.c.d/n pour un réseau IPv4, "
                            "ou /etc/exports pour un @netgroup" % raw)


def _check_option_value(k, eq, v):
    if k not in SHARENFS_VALUE_KEYS:
        if eq:
            raise PermError("%s est une option booléenne : « %s=%s » refusé%s" % (k, k, v, INVALID_OPT_MSG))
        return
    if not eq:
        if k in SHARENFS_OPTIONAL_VALUE:
            return
        raise PermError("%s exige une valeur (%s=…)%s" % (k, k, INVALID_OPT_MSG))
    if k in ("anonuid", "anongid", "anon", "root_mapping"):
        if not re.fullmatch(r"[0-9]{1,10}", v) or int(v) > 4294967295:
            raise PermError("%s=%s : entier 0–4294967295 attendu%s" % (k, v, INVALID_OPT_MSG))
    elif k == "fsid":
        if not (re.fullmatch(r"[0-9]{1,10}", v) and int(v) <= 4294967295) and v != "root" and \
                not re.fullmatch(r"[0-9a-fA-F]{32}", v.replace("-", "")):
            raise PermError("fsid=%s : entier, « root » ou UUID (32 chiffres hexadécimaux) attendu%s"
                            % (v, INVALID_OPT_MSG))
    elif k == "sec":
        flavors = v.split(":")
        if not v or any(f not in SEC_FLAVORS for f in flavors):
            raise PermError("sec=%s : saveurs sys, krb5, krb5i, krb5p séparées par « : »%s" % (v, INVALID_OPT_MSG))
    elif k in ("mountpoint", "mp"):
        if not v.startswith("/"):
            raise PermError("%s=%s : chemin absolu attendu%s" % (k, v, INVALID_OPT_MSG))
    elif k in ("refer", "replicas"):
        if not v:
            raise PermError("%s= vide%s" % (k, INVALID_OPT_MSG))


def validate_sharenfs(value, with_lines=False):
    """Valide une valeur sharenfs comme OpenZFS (clés, découpage des hôtes) et comme nfs-utils (valeurs
    d'options, hôtes non vides), puis refuse les constructions ambiguës (sec= après les hôtes, IPv6 sans
    crochets, netgroup)."""
    value = str(value).strip()
    if value in ("on", "off"):
        return (value, sharenfs_lines(value)) if with_lines else value
    if not SHARENFS_CHARS.fullmatch(value):
        raise PermError("Valeur sharenfs refusée : caractères autorisés A-Z a-z 0-9 _ = , . : @ / * - [ ] "
                        "(pas d'espace, de « ; » ni de retour à la ligne)")
    opts = [o for o in value.split(",") if o]
    if len(opts) != len(value.split(",")):
        raise PermError("Option vide dans %r (virgule en trop)" % value)
    for i, o in enumerate(opts):
        k, eq, v = o.partition("=")
        if k.startswith("-") or k not in SHARENFS_KEYS:
            raise PermError("Option sharenfs inconnue : %s (OpenZFS : SA_SYNTAX_ERR, ou exportfs l'ignorerait)%s"
                            % (k, INVALID_OPT_MSG if k == "fsuid" else ""))
        _check_option_value(k, eq, v)
        if k in ("rw", "ro"):
            if eq and v == "":
                raise PermError("%s= sans hôte : nfs-utils exporterait à TOUS les clients ; écrivez « %s » seul "
                                "si c'est voulu" % (k, k))
            if eq:
                hosts = _oz_split_hosts(v)
                for h in hosts:
                    _check_host(h["raw"], h["bracketed"], v)
                plain = [h["raw"] for h in hosts if not h["bracketed"]]
                run_hex = 0
                for x in plain:
                    run_hex = run_hex + 1 if re.fullmatch(r"@?[0-9A-Fa-f]{1,4}", x) else 0
                    if run_hex >= 3:
                        raise PermError("%r ressemble à une adresse IPv6 sans crochets (OpenZFS la découperait sur "
                                        "« : ») : écrivez [adresse] ou [réseau]/n" % v)
        elif k == "sec":
            if not any(x.partition("=")[0] in ("rw", "ro") for x in opts[i + 1:]):
                raise PermError("sec=%s placé après les hôtes : OpenZFS n'applique sec= qu'aux rw= / ro= qui le "
                                "SUIVENT, ces hôtes resteraient en sec=sys. Placez sec= avant rw= / ro=" % v)
    lines = sharenfs_lines(value)
    return (value, lines) if with_lines else value


def _effective_inheritors(rows, root_name, new_value_local):
    """Datasets dont le sharenfs effectif sera celui de `root_name` : lui-même et les descendants qui en
    héritent (aucune valeur locale ou reçue entre eux)."""
    affected = []
    blocked = []
    for r in rows:
        n = r["name"]
        if n != root_name and not n.startswith(root_name + "/"):
            continue
        if any(n.startswith(b + "/") for b in blocked):
            continue
        if n != root_name and r["sharenfs_source"] in ("local", "received"):
            blocked.append(n)
            continue
        affected.append(r)
    return affected


def _parent_sharenfs(dataset):
    if "/" not in dataset:
        return "off"
    parent = dataset.rsplit("/", 1)[0]
    _c, out, _e = run(["zfs", "get", "-H", "-o", "value", "sharenfs", "--", parent], check=False)
    return out.strip() or "off"


def cmd_nfs_sharenfs(params):
    dataset = params.get("dataset", "")
    if not DATASET_CHARS.fullmatch(dataset or "") or dataset.startswith("-"):
        raise PermError("Nom de dataset invalide")
    op = params.get("op", "set")
    all_rows = _list_datasets(dataset)
    rows = [r for r in all_rows if r["name"] == dataset]
    if not rows:
        raise PermError("Dataset introuvable : %s" % dataset)
    r = rows[0]
    notes = ["sharenfs écrit /etc/exports.d/zfs.exports et relance exportfs : ne gérez pas ce chemin aussi dans "
             "cockpit-file-sharing ou /etc/exports",
             "sharenfs est hérité par les datasets enfants"]
    if op == "set":
        value = validate_sharenfs(params.get("value", ""))
        cmd = ["zfs", "set", "sharenfs=%s" % value, "--", dataset]
        new_value = value
    elif op == "inherit":
        cmd = ["zfs", "inherit", "sharenfs", "--", dataset]
        new_value = _parent_sharenfs(dataset)
        notes.append("Après « zfs inherit », la valeur effective sera celle du parent : %s" % new_value)
    else:
        raise PermError("Opération inconnue : %s" % op)
    affected = _effective_inheritors(all_rows, dataset, new_value)
    for a in affected:
        if a["path"] and a["path"] in SYSTEM_MOUNTS and new_value not in ("off", "-", "") \
                and not params.get("allow_system"):
            raise PermError("%s est monté sur %s (dataset système) : l'exporter par sharenfs est refusé" % (
                a["name"], a["path"]))
    preview = []
    if new_value not in ("off", "-", ""):
        exports = read_exports()
        conflicts = []
        for a in affected:
            if not a["path"]:
                continue
            real = os.path.realpath(a["path"])
            manual = [e for e in exports if e["source"] == "manuel" and e.get("realpath", e["path"]) == real]
            if manual:
                conflicts.append("%s (%s)" % (a["path"], ", ".join(sorted({e["file"] for e in manual}))))
            if a["mounted"]:
                try:
                    preview += [l["line"] for l in sharenfs_lines(new_value, a["path"])]
                except PermError as e:
                    notes.append("La valeur héritée %r serait refusée par OpenZFS : %s" % (new_value, e))
        if conflicts and not params.get("force"):
            raise PermError("Déjà exporté par /etc/exports ou /etc/exports.d (doublon) : %s — retirez ces lignes "
                            "d'abord (ou forcez)" % "; ".join(conflicts))
        if conflicts:
            notes.append("Doublons forcés : %s" % "; ".join(conflicts))
        fsid_new = _opt_value(new_value.split(","), "fsid")
        if fsid_new:
            notes.append("fsid dans sharenfs : les enfants en hériteront (même fsid) ; redéfinissez-le sur chacun")
        world = _sharenfs_world(new_value)
        if world:
            notes.append("ATTENTION : exporté vers TOUS les clients (*) en %s" % " et ".join(
                "lecture-écriture" if a == "rw" else "lecture seule" for a in sorted(world, reverse=True)))
    if r["sharenfs"] not in ("off", "-", "") and new_value != r["sharenfs"] and \
            _opt_value(new_value.split(","), "fsid") != _opt_value(r["sharenfs"].split(","), "fsid"):
        notes.append("Le fsid change : les filehandles changent, les clients déjà montés recevront ESTALE "
                     "(démontez puis remontez-les)")
    if len(affected) > 1:
        notes.append("S'applique aussi aux descendants qui en héritent : %s" % ", ".join(
            a["name"] for a in affected if a["name"] != dataset))
    shown = " ".join(shlex.quote(x) for x in cmd)
    res = {"command": shown, "notes": notes, "affected": [a["name"] for a in affected], "preview": preview}
    if params.get("dry_run", True):
        res.update(dry_run=True, current=r["sharenfs"], current_source=r["sharenfs_source"])
        return res
    run(cmd)
    res["dry_run"] = False
    return res

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
    "nfs4-translate": cmd_nfs4_translate,
    "nfs-datasets": cmd_nfs_datasets,
    "nfs-generate": cmd_nfs_generate,
    "nfs-sharenfs": cmd_nfs_sharenfs,
    "nfsv4-support": lambda _p: dict(nfsv4_native_support(), idmap=idmap_info()),
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
