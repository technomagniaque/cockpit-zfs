#!/usr/bin/env python3
"""
Backend de gestion avancée des permissions pour cockpit-zfs.

Usage :  zfs-permissions.py <commande> '<json des paramètres>'

Toujours imprime un objet JSON sur stdout :
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

Toutes les commandes qui modifient quelque chose acceptent "dry_run": true, qui
renvoie le plan (nombre d'objets touchés, échantillon, commandes) sans rien écrire.
"""

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
CHUNK = 400  # nombre de chemins par invocation de setfacl / chown

FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x00000010
FS_APPEND_FL = 0x00000020

ACL_PROPS = [
    "type", "mountpoint", "mounted", "readonly", "acltype", "aclmode",
    "aclinherit", "xattr", "dnodesize", "casesensitivity", "normalization",
    "utf8only",
]

NTACL_XATTR = "security.NTACL"
DOSATTRIB_XATTR = "user.DOSATTRIB"
POSIX_ACCESS_XATTR = "system.posix_acl_access"
POSIX_DEFAULT_XATTR = "system.posix_acl_default"

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

ZFS_DELEGATION_PERMS = [
    "allow", "clone", "create", "destroy", "diff", "hold", "load-key", "change-key",
    "mount", "promote", "receive", "release", "rename", "rollback", "send", "share",
    "snapshot", "bookmark", "groupquota", "groupobjquota", "groupused", "groupobjused",
    "projectid", "projectquota", "projectobjquota", "projectused", "projectobjused",
    "userprop", "userquota", "userobjquota", "userused", "userobjused",
    # propriétés déléguables les plus utiles
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
    "strip-acl": "Retirer toutes les ACL étendues (setfacl -b), garder le mode",
    "acl-template": "Appliquer un modèle d'ACL (entrées nommées + ACL par défaut héritables)",
    "inherit-parent": "Propager l'ACL par défaut du dossier racine (comme « remplacer les permissions enfants »)",
    "mirror-reference": "Copier les permissions d'un fichier / dossier de référence",
    "from-snapshot": "Restaurer propriétaires, modes et ACL depuis un snapshot ZFS (sans toucher aux données)",
    "from-backup": "Restaurer une sauvegarde de permissions (getfacl)",
    "clear-ntacl": "Effacer les ACL NT stockées par Samba / ksmbd (security.NTACL, option DOSATTRIB)",
    "orphans": "Réattribuer les fichiers dont l'UID / GID n'existe plus",
    "takeown": "Changer propriétaire / groupe récursivement sans toucher aux modes",
    "chattr-clear": "Retirer les attributs immutable / append-only",
}


class PermError(Exception):
    pass


# --------------------------------------------------------------------------- utilitaires

def run(cmd, input_data=None, check=True):
    proc = subprocess.run(
        cmd, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    if check and proc.returncode != 0:
        raise PermError("%s : %s" % (" ".join(cmd[:3]), proc.stderr.strip() or "code %d" % proc.returncode))
    return proc


def have(binary):
    for d in os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").split(":") + ["/usr/sbin", "/sbin"]:
        if os.access(os.path.join(d, binary), os.X_OK):
            return True
    return False


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


def resolve_uid(owner):
    if owner is None or owner == "":
        return -1
    if str(owner).isdigit():
        return int(owner)
    try:
        return pwd.getpwnam(owner).pw_uid
    except KeyError:
        raise PermError("Utilisateur inconnu : %s" % owner)


def resolve_gid(group):
    if group is None or group == "":
        return -1
    if str(group).isdigit():
        return int(group)
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


def list_xattrs(path):
    try:
        return os.listxattr(path, follow_symlinks=False)
    except OSError:
        return []


def get_fsflags(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        buf = fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack("i", 0))
        return struct.unpack("i", buf)[0]
    except OSError:
        return None
    finally:
        os.close(fd)


def set_fsflags(path, flags):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack("i", flags))
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- ZFS

def zfs_filesystems():
    out = run(["zfs", "list", "-H", "-p", "-t", "filesystem", "-o", "name,mountpoint,mounted"]).stdout
    result = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2] == "yes" and parts[1].startswith("/"):
            result.append((parts[0], parts[1]))
    return result


def dataset_for_path(path):
    path = os.path.realpath(path)
    best = None
    for name, mnt in zfs_filesystems():
        if path == mnt or path.startswith(mnt.rstrip("/") + "/"):
            if best is None or len(mnt) > len(best[1]):
                best = (name, mnt)
    return best


def zfs_props(dataset):
    out = run(["zfs", "get", "-H", "-p", "-o", "property,value,source", ",".join(ACL_PROPS), dataset]).stdout
    props = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            props[parts[0]] = {"value": parts[1], "source": parts[2]}
    return props


def resolve_target(params, must_be_dir=False, write=False):
    path = params.get("path")
    if not path and params.get("dataset"):
        props = zfs_props(params["dataset"])
        path = props.get("mountpoint", {}).get("value")
    if not path:
        raise PermError("Aucun chemin ni dataset fourni")
    path = os.path.realpath(path)
    if not os.path.lexists(path):
        raise PermError("Chemin introuvable : %s" % path)
    ds = dataset_for_path(path)
    if ds is None:
        raise PermError("%s n'est pas dans un système de fichiers ZFS monté" % path)
    if write:
        if path == "/":
            raise PermError("Refus d'agir sur /")
        if "/.zfs/" in path + "/":
            raise PermError("Les snapshots (.zfs) sont en lecture seule")
    if must_be_dir and not os.path.isdir(path):
        raise PermError("%s n'est pas un dossier" % path)
    return path, ds[0], ds[1]


def acl_mode_for(dataset):
    """'posix', 'off' ou 'nfsv4' selon acltype."""
    value = zfs_props(dataset).get("acltype", {}).get("value", "off")
    if value in ("posix", "posixacl"):
        return "posix"
    if value == "nfsv4":
        return "nfsv4"
    return "off"


# --------------------------------------------------------------------------- ACL POSIX

ACL_LINE = re.compile(r"^(default:)?(user|group|mask|other)?:([^:]*):([rwxX-]{3})")


def parse_getfacl(text):
    acl = {"owner": None, "group": None, "flags": "", "access": [], "default": []}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("# owner:"):
            acl["owner"] = line.split(":", 1)[1].strip()
            continue
        if line.startswith("# group:"):
            acl["group"] = line.split(":", 1)[1].strip()
            continue
        if line.startswith("# flags:"):
            acl["flags"] = line.split(":", 1)[1].strip()
            continue
        if line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        m = ACL_LINE.match(line)
        if not m:
            continue
        entry = {"tag": m.group(2), "qualifier": m.group(3), "perms": m.group(4)}
        (acl["default"] if m.group(1) else acl["access"]).append(entry)
    return acl


def getfacl(path):
    if not have("getfacl"):
        raise PermError("getfacl introuvable : installer le paquet « acl »")
    return parse_getfacl(run(["getfacl", "-p", "--absolute-names", "--", path]).stdout)


def acl_is_extended(acl):
    if acl["default"]:
        return True
    return any(e["tag"] == "mask" or e["qualifier"] for e in acl["access"])


def entry_spec(entry, default=False):
    tag = entry.get("tag")
    if tag not in ("user", "group", "mask", "other"):
        raise PermError("Étiquette d'ACL invalide : %s" % tag)
    qual = entry.get("qualifier") or entry.get("name") or ""
    if tag in ("mask", "other") and qual:
        raise PermError("%s ne prend pas de qualificatif" % tag)
    perms = entry.get("perms", "---")
    if not re.fullmatch(r"[rwxX-]{1,4}", perms):
        raise PermError("Permissions invalides : %s" % perms)
    if qual and not re.fullmatch(r"[A-Za-z0-9._@\\$-]+", qual):
        raise PermError("Qualificatif invalide : %s" % qual)
    return "%s%s:%s:%s" % ("default:" if default else "", tag, qual, perms)


def strip_exec(perms):
    return perms.replace("x", "-").replace("X", "-")


def build_spec(access, default, for_dir):
    parts = [entry_spec(e) for e in access]
    if for_dir:
        parts += [entry_spec(e, True) for e in default]
    return ",".join(parts)


def chunks(seq, n=CHUNK):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# --------------------------------------------------------------------------- parcours

def walk(root, params):
    """Génère (chemin, lstat) en respectant les filtres. Ne suit jamais les liens
    symboliques et ne traverse pas les datasets enfants sauf demande explicite."""
    cross = bool(params.get("cross_datasets", False))
    max_depth = params.get("max_depth")
    max_depth = int(max_depth) if max_depth not in (None, "") else None
    include = [p for p in params.get("include", []) if p]
    exclude = [p for p in params.get("exclude", []) if p]
    types = params.get("types", "all")  # all | files | dirs
    recursive = params.get("recursive", True)
    include_root = params.get("include_root", True)

    root_st = os.lstat(root)
    root_dev = root_st.st_dev

    def accept(rel, st):
        if stat.S_ISLNK(st.st_mode):
            return False
        is_dir = stat.S_ISDIR(st.st_mode)
        if types == "files" and is_dir:
            return False
        if types == "dirs" and not is_dir:
            return False
        name = os.path.basename(rel)
        if exclude and any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in exclude):
            return False
        if include and not any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in include):
            return False
        return True

    if include_root and accept(".", root_st):
        yield root, root_st
    if not recursive or not stat.S_ISDIR(root_st.st_mode):
        return

    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if max_depth is not None and depth >= max_depth:
            continue
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for de in entries:
            if de.name == ".zfs" and current == root:
                continue
            try:
                st = de.stat(follow_symlinks=False)
            except OSError:
                continue
            rel = os.path.relpath(de.path, root)
            if exclude and stat.S_ISDIR(st.st_mode) and any(
                    fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(de.name, p) for p in exclude):
                continue  # élague le sous-arbre exclu
            if stat.S_ISDIR(st.st_mode):
                if st.st_dev != root_dev and not cross:
                    continue  # dataset enfant ou autre montage
                stack.append((de.path, depth + 1))
            if accept(rel, st):
                yield de.path, st


# --------------------------------------------------------------------------- sauvegardes

def ensure_backup_dir():
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)


def create_backup(path, dataset, reason):
    if not have("getfacl"):
        raise PermError("getfacl introuvable : impossible de sauvegarder (paquet « acl »)")
    ensure_backup_dir()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe = dataset.replace("/", "_")
    backup_id = "%s-%s" % (safe, stamp)
    base = os.path.join(BACKUP_DIR, backup_id)
    proc = subprocess.run(
        ["getfacl", "-R", "-P", "-p", "--absolute-names", "--", path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0 and not proc.stdout:
        raise PermError("getfacl -R a échoué : %s" % proc.stderr.decode(errors="replace").strip())
    with gzip.open(base + ".facl.gz", "wb") as f:
        f.write(proc.stdout)
    entries = proc.stdout.count(b"# file: ")
    meta = {
        "id": backup_id, "path": path, "dataset": dataset, "reason": reason,
        "created": int(time.time()), "entries": entries,
        "size": os.path.getsize(base + ".facl.gz"),
    }
    with open(base + ".json", "w") as f:
        json.dump(meta, f)
    os.chmod(base + ".facl.gz", 0o600)
    os.chmod(base + ".json", 0o600)
    return meta


def list_backups(_params):
    if not os.path.isdir(BACKUP_DIR):
        return {"backups": []}
    out = []
    for name in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if name.endswith(".json"):
            try:
                with open(os.path.join(BACKUP_DIR, name)) as f:
                    out.append(json.load(f))
            except (OSError, ValueError):
                pass
    return {"backups": out}


def backup_files(backup_id):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", backup_id or ""):
        raise PermError("Identifiant de sauvegarde invalide")
    base = os.path.join(BACKUP_DIR, backup_id)
    if not os.path.exists(base + ".facl.gz"):
        raise PermError("Sauvegarde introuvable : %s" % backup_id)
    return base + ".facl.gz", base + ".json"


def delete_backup(params):
    data, meta = backup_files(params.get("id"))
    os.unlink(data)
    if os.path.exists(meta):
        os.unlink(meta)
    return {"deleted": params.get("id")}


# --------------------------------------------------------------------------- inspect / audit

def describe(path, st=None):
    st = st or os.lstat(path)
    info = {
        "path": path,
        "type": "dir" if stat.S_ISDIR(st.st_mode) else "link" if stat.S_ISLNK(st.st_mode) else "file",
        "mode": mode_str(st.st_mode),
        "symbolic": stat.filemode(st.st_mode),
        "uid": st.st_uid, "owner": uid_name(st.st_uid),
        "gid": st.st_gid, "group": gid_name(st.st_gid),
        "setgid": bool(st.st_mode & stat.S_ISGID),
        "sticky": bool(st.st_mode & stat.S_ISVTX),
    }
    x = list_xattrs(path)
    info["xattrs"] = x
    info["has_ntacl"] = NTACL_XATTR in x
    info["has_posix_acl"] = POSIX_ACCESS_XATTR in x or POSIX_DEFAULT_XATTR in x
    flags = get_fsflags(path) if not stat.S_ISLNK(st.st_mode) else None
    info["immutable"] = bool(flags and flags & FS_IMMUTABLE_FL)
    info["append_only"] = bool(flags and flags & FS_APPEND_FL)
    return info


def cmd_inspect(params):
    path, dataset, mountpoint = resolve_target(params)
    props = zfs_props(dataset)
    info = describe(path)
    acl = None
    acl_error = None
    try:
        acl = getfacl(path)
    except PermError as e:
        acl_error = str(e)
    children = []
    limit = int(params.get("children_limit", 300))
    if os.path.isdir(path) and not os.path.islink(path):
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
    acltype = props.get("acltype", {}).get("value")
    xattr = props.get("xattr", {}).get("value")
    if acltype in ("posix", "posixacl") and xattr not in ("sa",):
        warnings.append("acltype=posixacl avec xattr=%s : chaque ACL devient un fichier caché, préférez xattr=sa" % xattr)
    if acltype in ("posix", "posixacl"):
        for p in ("aclinherit", "aclmode"):
            if props.get(p, {}).get("source") == "local":
                warnings.append("%s n'a aucun effet avec des ACL POSIX sous Linux (s'applique aux ACL NFSv4)" % p)
    if acltype == "off" and info["has_posix_acl"]:
        warnings.append("Des ACL POSIX sont stockées mais ignorées (acltype=off)")
    if info["has_ntacl"]:
        warnings.append("ACL NT présente (security.NTACL) : Samba / ksmbd avec acl_xattr l'affiche au client Windows")
    return {
        "path": path, "dataset": dataset, "mountpoint": mountpoint,
        "props": props, "info": info, "acl": acl, "acl_error": acl_error,
        "children": children, "warnings": warnings,
        "acl_mode": acl_mode_for(dataset),
    }


def cmd_audit(params):
    path, dataset, _m = resolve_target(params)
    max_entries = int(params.get("max_entries", 2000000))
    root_st = os.lstat(path)
    root_setgid = bool(root_st.st_mode & stat.S_ISGID)
    acltype = acl_mode_for(dataset)
    findings = {k: [] for k in (
        "world_writable", "orphan_uid", "orphan_gid", "ntacl", "posix_acl",
        "ignored_posix_acl", "dir_missing_setgid", "foreign_group", "immutable",
        "setuid",
    )}
    counts = {k: 0 for k in findings}
    owners, groups, modes = {}, {}, {}
    total = files = dirs = 0
    truncated = False
    check_flags = bool(params.get("check_flags", True))

    def add(kind, p):
        counts[kind] += 1
        if len(findings[kind]) < FINDING_LIMIT:
            findings[kind].append(p)

    for p, st in walk(path, dict(params, types="all")):
        total += 1
        if total > max_entries:
            truncated = True
            break
        is_dir = stat.S_ISDIR(st.st_mode)
        dirs += is_dir
        files += not is_dir
        owners[st.st_uid] = owners.get(st.st_uid, 0) + 1
        groups[st.st_gid] = groups.get(st.st_gid, 0) + 1
        m = mode_str(st.st_mode) + ("d" if is_dir else "f")
        modes[m] = modes.get(m, 0) + 1
        if st.st_mode & stat.S_IWOTH and not (is_dir and st.st_mode & stat.S_ISVTX):
            add("world_writable", p)
        if uid_name(st.st_uid) is None:
            add("orphan_uid", p)
        if gid_name(st.st_gid) is None:
            add("orphan_gid", p)
        if st.st_gid != root_st.st_gid:
            add("foreign_group", p)
        if is_dir and root_setgid and not st.st_mode & stat.S_ISGID:
            add("dir_missing_setgid", p)
        if not is_dir and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            add("setuid", p)
        x = list_xattrs(p)
        if NTACL_XATTR in x:
            add("ntacl", p)
        if POSIX_ACCESS_XATTR in x or POSIX_DEFAULT_XATTR in x:
            add("ignored_posix_acl" if acltype == "off" else "posix_acl", p)
        if check_flags:
            fl = get_fsflags(p)
            if fl and fl & (FS_IMMUTABLE_FL | FS_APPEND_FL):
                add("immutable", p)

    def top(d, namer):
        return [{"id": k, "name": namer(k), "count": v}
                for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:15]]

    return {
        "path": path, "dataset": dataset, "acl_mode": acltype,
        "total": total, "files": files, "dirs": dirs, "truncated": truncated,
        "counts": counts, "findings": findings,
        "owners": top(owners, uid_name), "groups": top(groups, gid_name),
        "modes": [{"mode": k[:-1], "kind": "dossier" if k[-1] == "d" else "fichier", "count": v}
                  for k, v in sorted(modes.items(), key=lambda kv: -kv[1])[:20]],
    }


# --------------------------------------------------------------------------- application

class Plan:
    """Accumule les opérations ; exécute seulement si dry_run est faux."""

    def __init__(self, dry_run):
        self.dry_run = dry_run
        self.count = 0
        self.sample = []
        self.commands = []
        self.errors = []

    def note(self, path, what):
        self.count += 1
        if len(self.sample) < SAMPLE_LIMIT:
            self.sample.append({"path": path, "change": what})

    def command(self, desc):
        if len(self.commands) < 20:
            self.commands.append(desc)

    def error(self, path, err):
        if len(self.errors) < FINDING_LIMIT:
            self.errors.append({"path": path, "error": str(err)})

    def result(self, **extra):
        r = {"dry_run": self.dry_run, "count": self.count, "sample": self.sample,
             "commands": self.commands, "errors": self.errors, "error_count": len(self.errors)}
        r.update(extra)
        return r


def setfacl_batch(plan, args, paths):
    if not paths:
        return
    plan.command("setfacl %s -- <%d chemins>" % (" ".join(args), len(paths)))
    if plan.dry_run:
        return
    for group in chunks(paths):
        proc = run(["setfacl"] + args + ["--"] + group, check=False)
        if proc.returncode != 0:
            for line in proc.stderr.strip().splitlines()[:20]:
                plan.error(group[0], line)


def require_posix(dataset, what):
    mode = acl_mode_for(dataset)
    if mode != "posix":
        raise PermError("%s exige acltype=posixacl sur %s (actuel : %s)" % (what, dataset, mode))
    if not have("setfacl"):
        raise PermError("setfacl introuvable : installer le paquet « acl »")


def apply_owner_mode(plan, p, st, uid, gid, mode):
    changes = []
    if (uid != -1 and st.st_uid != uid) or (gid != -1 and st.st_gid != gid):
        changes.append("propriétaire %s:%s → %s:%s" % (
            uid_name(st.st_uid) or st.st_uid, gid_name(st.st_gid) or st.st_gid,
            (uid_name(uid) or uid) if uid != -1 else "=", (gid_name(gid) or gid) if gid != -1 else "="))
    if mode is not None and stat.S_IMODE(st.st_mode) != mode:
        changes.append("mode %s → %04o" % (mode_str(st.st_mode), mode))
    if not changes:
        return
    plan.note(p, ", ".join(changes))
    if plan.dry_run:
        return
    try:
        if uid != -1 or gid != -1:
            os.chown(p, uid, gid, follow_symlinks=False)
        if mode is not None:
            # chown efface setuid/setgid : on applique le mode après
            os.chmod(p, mode)
    except OSError as e:
        plan.error(p, e)


def cmd_set_acl(params):
    path, dataset, _m = resolve_target(params, write=True)
    require_posix(dataset, "L'édition d'ACL")
    action = params.get("action", "modify")  # set | modify | remove | remove-default
    access = params.get("access", [])
    default = params.get("default", [])
    plan = Plan(params.get("dry_run", True))
    files, dirs = [], []
    for p, st in walk(path, dict(params, recursive=params.get("recursive", False))):
        (dirs if stat.S_ISDIR(st.st_mode) else files).append(p)
    if action == "remove-default":
        setfacl_batch(plan, ["-k"], dirs)
        for p in dirs:
            plan.note(p, "ACL par défaut retirée")
        return plan.result()
    if action == "remove":
        def rm_spec(entries, d=False):
            return ",".join("%s%s:%s" % ("default:" if d else "", e["tag"], e.get("qualifier") or "")
                            for e in entries if e.get("qualifier"))
        fspec = rm_spec(access)
        dspec = ",".join(s for s in (rm_spec(access), rm_spec(default, True)) if s)
        if fspec:
            setfacl_batch(plan, ["-x", fspec], files)
        if dspec:
            setfacl_batch(plan, ["-x", dspec], dirs)
    else:
        flag = "--set" if action == "set" else "-m"
        # files_conditional_x : sur les fichiers, x devient X (exécutable seulement
        # s'il l'est déjà pour une classe), comme le ferait l'héritage Windows.
        if params.get("files_conditional_x", True):
            file_access = [dict(e, perms=e["perms"].replace("x", "X")) for e in access]
        else:
            file_access = access
        fspec = build_spec(file_access, [], False)
        dspec = build_spec(access, default, True)
        if fspec:
            setfacl_batch(plan, [flag, fspec], files)
        if dspec:
            setfacl_batch(plan, [flag, dspec], dirs)
    for p in dirs + files:
        plan.note(p, "ACL %s" % action)
    return plan.result()


# --------------------------------------------------------------------------- reset

def reset_unix_mode(params, path, dataset, plan):
    uid = resolve_uid(params.get("owner"))
    gid = resolve_gid(params.get("group"))
    fmode = parse_mode(params.get("file_mode"), "Mode fichiers")
    dmode = parse_mode(params.get("dir_mode"), "Mode dossiers")
    if params.get("setgid_dirs") and dmode is not None:
        dmode |= stat.S_ISGID
    if params.get("sticky_dirs") and dmode is not None:
        dmode |= stat.S_ISVTX
    keep_exec = params.get("keep_exec", False)
    strip = params.get("strip_acl", True) and acl_mode_for(dataset) == "posix" and have("setfacl")
    with_acl = []
    for p, st in walk(path, params):
        is_dir = stat.S_ISDIR(st.st_mode)
        mode = dmode if is_dir else fmode
        if mode is not None and not is_dir and keep_exec and st.st_mode & stat.S_IXUSR:
            mode |= (mode & 0o444) >> 2  # r → x pour chaque classe qui lit
        apply_owner_mode(plan, p, st, uid, gid, mode)
        if strip:
            x = list_xattrs(p)
            if POSIX_ACCESS_XATTR in x or POSIX_DEFAULT_XATTR in x:
                with_acl.append(p)
    if with_acl:
        for p in with_acl[:SAMPLE_LIMIT]:
            plan.note(p, "ACL étendues retirées")
        plan.count += max(0, len(with_acl) - SAMPLE_LIMIT)
        # setfacl -b recalcule le mode : on le passe avant le chmod final
        setfacl_batch(plan, ["-b"], with_acl)
        if not plan.dry_run:
            for p in with_acl:
                try:
                    st = os.lstat(p)
                    mode = dmode if stat.S_ISDIR(st.st_mode) else fmode
                    if mode is not None:
                        os.chmod(p, mode)
                except OSError as e:
                    plan.error(p, e)


def reset_strip_acl(params, path, dataset, plan):
    require_posix(dataset, "Le retrait d'ACL")
    keep_default = params.get("keep_default", False)
    targets = []
    for p, st in walk(path, params):
        x = list_xattrs(p)
        if POSIX_ACCESS_XATTR in x or (POSIX_DEFAULT_XATTR in x and not keep_default):
            targets.append(p)
            plan.note(p, "ACL d'accès retirée" if keep_default else "ACL d'accès + par défaut retirées")
    if keep_default:
        # retire l'ACL d'accès étendue seulement : --set avec les entrées de base
        plan.command("setfacl --remove-all sauf default (par fichier)")
        if not plan.dry_run:
            for p in targets:
                try:
                    st = os.lstat(p)
                    m = stat.S_IMODE(st.st_mode)
                    base = "u::%s,g::%s,o::%s" % tuple(
                        "".join(c if m & b else "-" for c, b in zip("rwx", bits))
                        for bits in ((0o400, 0o200, 0o100), (0o40, 0o20, 0o10), (0o4, 0o2, 0o1)))
                    defaults = getfacl(p)["default"] if os.path.isdir(p) else []
                    spec = base + ("," + build_spec([], defaults, True) if defaults else "")
                    run(["setfacl", "--set", spec, "--", p])
                except (OSError, PermError) as e:
                    plan.error(p, e)
    else:
        setfacl_batch(plan, ["-b"], targets)


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


def reset_acl_template(params, path, dataset, plan):
    require_posix(dataset, "Le modèle d'ACL")
    uid = resolve_uid(params.get("owner"))
    gid = resolve_gid(params.get("group"))
    owner_p = params.get("owner_perms", "rwx")
    group_p = params.get("group_perms", "rwx")
    other_p = params.get("other_perms", "---")
    mask_p = params.get("mask_perms", "rwx")
    named = template_entries(params)
    inherit = params.get("inherit", True)
    base = [{"tag": "user", "qualifier": "", "perms": owner_p},
            {"tag": "group", "qualifier": "", "perms": group_p}]
    tail = [{"tag": "mask", "qualifier": "", "perms": mask_p},
            {"tag": "other", "qualifier": "", "perms": other_p}]
    dir_access = base + named + tail
    dir_default = dir_access if inherit else []
    # fichiers : X = exécutable seulement si déjà exécutable → on retire x simple
    file_access = [dict(e, perms=e["perms"].replace("x", "X")) for e in dir_access]
    files, dirs = [], []
    for p, st in walk(path, params):
        if uid != -1 or gid != -1:
            apply_owner_mode(plan, p, st, uid, gid, None)
        (dirs if stat.S_ISDIR(st.st_mode) else files).append(p)
        plan.note(p, "modèle d'ACL appliqué")
    setfacl_batch(plan, ["--set", build_spec(dir_access, dir_default, True)], dirs)
    setfacl_batch(plan, ["--set", build_spec(file_access, [], False)], files)
    if params.get("setgid_dirs") and not plan.dry_run:
        for d in dirs:
            try:
                os.chmod(d, stat.S_IMODE(os.lstat(d).st_mode) | stat.S_ISGID)
            except OSError as e:
                plan.error(d, e)


def reset_inherit_parent(params, path, dataset, plan):
    require_posix(dataset, "La propagation d'héritage")
    if not os.path.isdir(path):
        raise PermError("La propagation exige un dossier racine")
    root_acl = getfacl(path)
    defaults = root_acl["default"]
    if not defaults:
        if not params.get("fallback_access", False):
            raise PermError("Le dossier racine n'a pas d'ACL par défaut (cochez « utiliser l'ACL d'accès »)")
        defaults = root_acl["access"]
    keep_exec = params.get("keep_exec", True)
    dir_spec = build_spec(defaults, defaults, True)
    file_entries = [dict(e, perms=e["perms"].replace("x", "X") if keep_exec else strip_exec(e["perms"]))
                    for e in defaults]
    file_spec = build_spec(file_entries, [], False)
    files, dirs = [], []
    for p, st in walk(path, dict(params, include_root=False)):
        (dirs if stat.S_ISDIR(st.st_mode) else files).append(p)
        plan.note(p, "hérite de %s" % path)
    if params.get("reset_owner_to_root"):
        st0 = os.lstat(path)
        for p in dirs + files:
            apply_owner_mode(plan, p, os.lstat(p), st0.st_uid, st0.st_gid, None)
    setfacl_batch(plan, ["--set", dir_spec], dirs)
    setfacl_batch(plan, ["--set", file_spec], files)


def reset_mirror_reference(params, path, dataset, plan):
    ref_dir = params.get("reference_dir") or params.get("reference")
    ref_file = params.get("reference_file") or ref_dir
    if not ref_dir:
        raise PermError("Aucune référence fournie")
    for r in (ref_dir, ref_file):
        if not os.path.exists(r):
            raise PermError("Référence introuvable : %s" % r)
    posix = acl_mode_for(dataset) == "posix" and have("setfacl")
    refs = {}
    for kind, r in (("dir", ref_dir), ("file", ref_file)):
        st = os.lstat(r)
        refs[kind] = {"st": st, "acl": getfacl(r) if posix else None}
    copy_owner = params.get("copy_owner", True)
    files, dirs = [], []
    for p, st in walk(path, params):
        kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
        ref = refs[kind]["st"]
        apply_owner_mode(plan, p, st,
                         ref.st_uid if copy_owner else -1, ref.st_gid if copy_owner else -1,
                         stat.S_IMODE(ref.st_mode))
        (dirs if kind == "dir" else files).append(p)
    if posix:
        for kind, targets in (("dir", dirs), ("file", files)):
            acl = refs[kind]["acl"]
            if acl and acl_is_extended(acl):
                setfacl_batch(plan, ["--set", build_spec(acl["access"], acl["default"], kind == "dir")], targets)
            elif targets:
                setfacl_batch(plan, ["-b"], targets)


def restore_dump(plan, dump_text, live_root, src_root, strict_root):
    """Réécrit un dump getfacl -R (chemins sous src_root) vers live_root puis
    l'applique avec setfacl --restore. Ignore les chemins absents."""
    blocks = dump_text.split("\n\n")
    kept, missing = [], 0
    src_root = src_root.rstrip("/")
    for block in blocks:
        m = re.search(r"^# file: (.*)$", block, re.M)
        if not m:
            continue
        src = m.group(1)
        # getfacl échappe les caractères spéciaux en octal (\040 pour l'espace)
        decoded = re.sub(r"\\([0-7]{3})", lambda mm: chr(int(mm.group(1), 8)), src)
        if decoded != src_root and not decoded.startswith(src_root + "/"):
            continue
        live = live_root.rstrip("/") + decoded[len(src_root):]
        if strict_root and live != strict_root and not live.startswith(strict_root.rstrip("/") + "/"):
            continue
        if not os.path.lexists(live) or os.path.islink(live):
            missing += 1
            continue
        new_block = block.replace("# file: " + src, "# file: " + escape_getfacl_path(live), 1)
        kept.append(new_block)
        plan.note(live, "propriétaire / mode / ACL restaurés")
    plan.command("setfacl --restore=- (%d entrées, %d absentes ignorées)" % (len(kept), missing))
    if not plan.dry_run and kept:
        proc = run(["setfacl", "--restore=-"], input_data="\n\n".join(kept) + "\n", check=False)
        if proc.returncode != 0:
            for line in proc.stderr.strip().splitlines()[:50]:
                plan.error(live_root, line)
    return missing


def escape_getfacl_path(p):
    out = []
    for ch in p:
        if ch in " \t\n\r\\" or ord(ch) < 32:
            out.append("\\%03o" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def reset_from_snapshot(params, path, dataset, mountpoint, plan):
    if not have("setfacl"):
        raise PermError("setfacl introuvable : installer le paquet « acl »")
    snap = params.get("snapshot", "")
    if "@" in snap:
        ds, snap = snap.split("@", 1)
        if ds != dataset:
            raise PermError("Le snapshot %s n'appartient pas à %s (le chemin est dans ce dataset)" % (ds, dataset))
    if not re.fullmatch(r"[A-Za-z0-9._:+-]+", snap):
        raise PermError("Nom de snapshot invalide")
    rel = os.path.relpath(path, mountpoint)
    snap_root = os.path.normpath(os.path.join(mountpoint, ".zfs", "snapshot", snap, rel))
    if not os.path.exists(snap_root):
        raise PermError("%s introuvable dans le snapshot %s" % (rel, snap))
    proc = subprocess.run(["getfacl", "-R", "-P", "-p", "--absolute-names", "--", snap_root],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    missing = restore_dump(plan, proc.stdout, path, snap_root, path)
    return {"snapshot": "%s@%s" % (dataset, snap), "missing": missing}


def reset_from_backup(params, path, plan):
    data, meta_path = backup_files(params.get("backup_id"))
    with open(meta_path) as f:
        meta = json.load(f)
    with gzip.open(data, "rt", errors="surrogateescape") as f:
        dump = f.read()
    missing = restore_dump(plan, dump, meta["path"], meta["path"], path)
    return {"restored_backup": meta, "missing": missing}


def reset_clear_ntacl(params, path, plan):
    names = [NTACL_XATTR]
    if params.get("dosattrib"):
        names.append(DOSATTRIB_XATTR)
    for p, _st in walk(path, params):
        x = list_xattrs(p)
        present = [n for n in names if n in x]
        if not present:
            continue
        plan.note(p, "retrait de " + ", ".join(present))
        if plan.dry_run:
            continue
        for n in present:
            try:
                os.removexattr(p, n, follow_symlinks=False)
            except OSError as e:
                plan.error(p, e)


def reset_orphans(params, path, plan):
    uid = resolve_uid(params.get("owner"))
    gid = resolve_gid(params.get("group"))
    if uid == -1 and gid == -1:
        raise PermError("Indiquez un propriétaire et / ou un groupe de remplacement")
    for p, st in walk(path, params):
        new_uid = uid if uid != -1 and uid_name(st.st_uid) is None else -1
        new_gid = gid if gid != -1 and gid_name(st.st_gid) is None else -1
        if new_uid != -1 or new_gid != -1:
            apply_owner_mode(plan, p, st, new_uid, new_gid, None)


def reset_takeown(params, path, plan):
    uid = resolve_uid(params.get("owner"))
    gid = resolve_gid(params.get("group"))
    if uid == -1 and gid == -1:
        raise PermError("Indiquez un propriétaire et / ou un groupe")
    preserve = params.get("preserve_setid", True)
    for p, st in walk(path, params):
        apply_owner_mode(plan, p, st, uid, gid,
                         stat.S_IMODE(st.st_mode) if preserve and st.st_mode & (stat.S_ISUID | stat.S_ISGID) else None)


def reset_chattr_clear(params, path, plan):
    for p, st in walk(path, params):
        fl = get_fsflags(p)
        if not fl or not fl & (FS_IMMUTABLE_FL | FS_APPEND_FL):
            continue
        plan.note(p, "immutable / append-only retirés")
        if plan.dry_run:
            continue
        try:
            set_fsflags(p, fl & ~(FS_IMMUTABLE_FL | FS_APPEND_FL))
        except OSError as e:
            plan.error(p, e)


def cmd_reset(params):
    method = params.get("method")
    if method not in RESET_METHODS:
        raise PermError("Méthode inconnue : %s" % method)
    path, dataset, mountpoint = resolve_target(params, write=True)
    dry = params.get("dry_run", True)
    plan = Plan(dry)
    backup = None
    if not dry and params.get("backup", True) and method not in ("from-backup",):
        backup = create_backup(path, dataset, "avant %s" % method)
    extra = {}
    if method == "unix-mode":
        reset_unix_mode(params, path, dataset, plan)
    elif method == "strip-acl":
        reset_strip_acl(params, path, dataset, plan)
    elif method == "acl-template":
        reset_acl_template(params, path, dataset, plan)
    elif method == "inherit-parent":
        reset_inherit_parent(params, path, dataset, plan)
    elif method == "mirror-reference":
        reset_mirror_reference(params, path, dataset, plan)
    elif method == "from-snapshot":
        extra = reset_from_snapshot(params, path, dataset, mountpoint, plan)
    elif method == "from-backup":
        extra = reset_from_backup(params, path, plan)
    elif method == "clear-ntacl":
        reset_clear_ntacl(params, path, plan)
    elif method == "orphans":
        reset_orphans(params, path, plan)
    elif method == "takeown":
        reset_takeown(params, path, plan)
    elif method == "chattr-clear":
        reset_chattr_clear(params, path, plan)
    return plan.result(method=method, path=path, dataset=dataset, backup=backup, **extra)


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
    out = run(["zfs", "allow", dataset]).stdout
    return {"dataset": dataset, "entries": parse_zfs_allow(out), "known_perms": ZFS_DELEGATION_PERMS, "raw": out}


def cmd_delegate(params):
    dataset = params.get("dataset")
    op = params.get("op", "allow")  # allow | unallow
    kind = params.get("kind", "user")  # user | group | everyone | create | set
    who = params.get("who", "")
    scope = params.get("scope", "both")  # local | descendent | both
    perms = [p.strip() for p in params.get("perms", []) if p.strip()]
    if not dataset:
        raise PermError("Dataset requis")
    if not perms and not (op == "unallow" and params.get("all")):
        raise PermError("Aucune permission indiquée")
    for p in perms:
        if not re.fullmatch(r"@?[A-Za-z0-9_:.-]+", p):
            raise PermError("Permission invalide : %s" % p)
    cmd = ["zfs", op]
    if op == "unallow" and params.get("recursive"):
        cmd.append("-r")
    if kind in ("user", "group", "everyone"):
        if scope == "local":
            cmd.append("-l")
        elif scope == "descendent":
            cmd.append("-d")
    if kind == "user":
        if not who:
            raise PermError("Utilisateur requis")
        resolve_uid(who)
        cmd += ["-u", who]
    elif kind == "group":
        if not who:
            raise PermError("Groupe requis")
        resolve_gid(who)
        cmd += ["-g", who]
    elif kind == "everyone":
        cmd.append("-e")
    elif kind == "create":
        cmd.append("-c")
    elif kind == "set":
        if not re.fullmatch(r"@[A-Za-z0-9_.-]+", who or ""):
            raise PermError("Nom d'ensemble invalide (format @nom)")
        cmd += ["-s", who]
    else:
        raise PermError("Type de délégation inconnu : %s" % kind)
    if perms:
        cmd.append(",".join(perms))
    cmd.append(dataset)
    if params.get("dry_run", False):
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
        if current == v:
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
        proc = run(c, check=False)
        if proc.returncode != 0:
            errors.append({"command": " ".join(c), "error": proc.stderr.strip()})
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


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS:
        print(json.dumps({"ok": False, "error": "Commande inconnue. Choix : " + ", ".join(COMMANDS)}))
        return 0
    try:
        params = json.loads(argv[2]) if len(argv) > 2 and argv[2] else {}
        result = COMMANDS[argv[1]](params)
        result["ok"] = True
        print(json.dumps(result, ensure_ascii=False))
    except PermError as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
    except Exception as e:  # erreur inattendue : on renvoie la trace au lieu de planter l'interface
        import traceback
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e),
                          "trace": traceback.format_exc()}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
