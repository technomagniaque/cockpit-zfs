#!/usr/bin/env python3
import json, logging
# --- minimal inline logger (works without external module) ---
import sys, os, logging
from logging.handlers import RotatingFileHandler, SysLogHandler
from pathlib import Path

def get_logger(name: str, file_basename: str, app_name: str = "cockpit-zfs") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:  # avoid duplicate handlers if re-imported
        return logger
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # 1) Syslog if available
    for addr in ("/dev/log", "/run/systemd/journal/syslog"):
        try:
            if os.path.exists(addr):
                h = SysLogHandler(address=addr, facility=SysLogHandler.LOG_USER)
                h.setFormatter(logging.Formatter(f"{name}: %(levelname)s: %(message)s"))
                logger.addHandler(h)
                logger.debug(f"Syslog handler attached via {addr}")
                return logger
        except Exception:
            pass

    # 2) User-writable rotating file
    def _candidates():
        xs = os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state"))
        xc = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
        xr = os.environ.get("XDG_RUNTIME_DIR")
        for base in [xs, xc, xr]:
            if base:
                yield os.path.join(base, app_name, "logs", file_basename)
        yield os.path.join(os.path.expanduser("~/.local/state"), app_name, "logs", file_basename)
        yield os.path.join("/tmp", app_name, file_basename)

    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    for path in _candidates():
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=3, delay=True)
            fh.setFormatter(fmt)
            logger.addHandler(fh)
            logger.debug(f"File logger attached at {path}")
            return logger
        except Exception:
            pass

    # 3) Fallback stdout
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.warning("No syslog/file target available; logging to stdout.")
    return logger
# --- end inline logger ---


logger = get_logger("cockpit_zfs_getimportablepools", "getimportablepools.log")

# --- repli CLI `zpool import` (sans python3-libzfs, Debian 13 Trixie) ---
# Script exécuté par `python3 -c` : le code est dupliqué dans
# get-importable-pools.py et get-importable-destroyed-pools.py (garder les deux identiques).
import re
import subprocess

_IMPORT_GROUPS = {"logs": "log", "cache": "cache", "spares": "spare", "special": "special", "dedup": "dedup"}
_VDEV_RE = re.compile(r"^(mirror|raidz[123]?|draid[123]?(?::[0-9a-z:]*)?|replacing|spare)-\d+$")


def _import_vdev_type(name):
    m = _VDEV_RE.match(name)
    if m:
        t = m.group(1)
        if t.startswith("raidz"):
            return "raidz"
        if t.startswith("draid"):
            return "draid"
        return t
    return "file" if name.startswith("/") else "disk"


def _import_vdev_path(name, vtype):
    if vtype == "file":
        return name
    if vtype != "disk":
        return None
    for base in ("/dev/disk/by-id", "/dev/disk/by-vdev", "/dev/disk/by-path", "/dev"):
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    return None


def _import_vdev(name, state):
    vtype = _import_vdev_type(name)
    return {
        "name": name,
        "type": vtype,
        "path": _import_vdev_path(name, vtype),
        "guid": "",
        "status": state,
        "stats": {
            "timestamp": 0, "read_errors": 0, "write_errors": 0, "checksum_errors": 0,
            "ops": [0, 0, 0, 0, 0, 0], "bytes": [0, 0, 0, 0, 0, 0],
            "size": 0, "allocated": 0, "fragmentation": 0, "self_healed": 0,
            "configured_ashift": 0, "logical_ashift": 0, "physical_ashift": 0,
        },
        "children": [],
    }


def _import_prop(value):
    return {"value": value, "rawvalue": value, "parsed": value, "source": "NONE"}


def parse_zpool_import(text):
    """Analyse la sortie texte de `zpool import` / `zpool import -D` (LC_ALL=C).

    Produit la même structure que ZFSImportablePool.asdict() de libzfs pour les
    clés lues par le front (name, guid, status, properties, scan, groups.*) :
    les GUID de vdev et les statistiques d'erreurs ne sont pas affichés par
    `zpool import` et restent vides / à zéro.
    """
    pools = []
    cur = None
    last_key = None
    in_config = False
    stack = []
    group = "data"

    def finish():
        if cur is not None:
            pools.append(cur)

    for raw_line in text.splitlines():
        m = re.match(r"^\s*(pool|id|state|status|action|see|comment|config):\s?(.*)$", raw_line)
        if m and not (in_config and raw_line.startswith("\t")):
            key, val = m.group(1), m.group(2).strip()
            if key == "pool":
                finish()
                cur = {
                    "name": val, "id": "", "guid": "", "hostname": "", "status": "",
                    "error_count": 0, "status_detail": "", "comment": "",
                    "properties": {}, "features": [],
                    "scan": {
                        "function": None, "state": None, "start_time": "None", "end_time": "None",
                        "percentage": None, "bytes_to_process": None, "bytes_processed": None,
                        "bytes_issued": None, "pause": None, "errors": None,
                    },
                    "root_vdev": None,
                    "groups": {"data": [], "log": [], "cache": [], "spare": [], "special": [], "dedup": []},
                }
                in_config = False
                stack = []
                group = "data"
            elif cur is None:
                continue
            elif key == "id":
                cur["id"] = cur["guid"] = val
            elif key == "state":
                cur["status"] = re.sub(r"\s*\(.*\)\s*$", "", val)
                cur["destroyed"] = "DESTROYED" in val
            elif key == "status":
                cur["status_detail"] = val
            elif key == "comment":
                cur["comment"] = val
            elif key == "config":
                in_config = True
            last_key = key
            continue
        if cur is None:
            continue
        if in_config:
            if not raw_line.startswith("\t") or not raw_line.strip():
                continue
            body = raw_line.lstrip("\t")
            depth = (len(body) - len(body.lstrip(" "))) // 2
            tokens = body.split()
            name = tokens[0]
            state = tokens[1] if len(tokens) > 1 else ""
            if depth == 0:
                if name in _IMPORT_GROUPS and len(tokens) == 1:
                    group = _IMPORT_GROUPS[name]
                else:
                    group = "data"
                    if cur["status"] == "" and state:
                        cur["status"] = state
                stack = []
                continue
            vdev = _import_vdev(name, state)
            if depth == 1:
                cur["groups"][group].append(vdev)
                stack = [vdev]
            else:
                parent_idx = depth - 2
                if parent_idx >= len(stack):
                    parent_idx = len(stack) - 1
                if parent_idx < 0:
                    cur["groups"][group].append(vdev)
                    stack = [vdev]
                    continue
                stack[parent_idx]["children"].append(vdev)
                stack = stack[:parent_idx + 1] + [vdev]
        elif last_key in ("status", "action") and raw_line.startswith(" ") and raw_line.strip():
            if last_key == "status":
                cur["status_detail"] = (cur["status_detail"] + " " + raw_line.strip()).strip()
    finish()

    for p in pools:
        p["properties"] = {
            "name": _import_prop(p["name"]),
            "guid": _import_prop(p["guid"]),
            "health": _import_prop(p["status"]),
            "comment": _import_prop(p["comment"] or "-"),
        }
        p["root_vdev"] = {
            "name": p["name"], "type": "root", "path": None, "guid": p["guid"], "status": p["status"],
            "stats": _import_vdev("root", "")["stats"], "children": list(p["groups"]["data"]),
        }
    return pools


def zpool_import_cli(destroyed=False, search_paths=None):
    """Lance `zpool import [-D] [-d …]` et renvoie la liste analysée ([] si aucun pool)."""
    cmd = ["zpool", "import"]
    if destroyed:
        cmd.append("-D")
    for d in search_paths or []:
        if os.path.isdir(d):
            cmd += ["-d", d]
    env = dict(os.environ, LC_ALL="C", LANG="C")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=env)
    if res.returncode != 0 and not res.stdout.strip():
        err = res.stderr.strip()
        if "no pools available" not in err:
            logger.error(f"zpool import failed ({res.returncode}): {err}")
        return []
    pools = parse_zpool_import(res.stdout)
    if destroyed:
        pools = [p for p in pools if p.get("destroyed")]
    return pools
# --- fin du repli CLI ---


def main():
    try:
        logger.info("=" * 80)
        logger.info("Starting a new run of get-importable-pools script")

        try:
            import warnings
            warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*ABCs.*collections.*")
            import libzfs
        except Exception as e:
            logger.warning(f"libzfs import failed: {e} ; repli CLI zpool import")
            print(json.dumps(zpool_import_cli(), indent=4))
            return

        z_pools = []
        try:
            with libzfs.ZFS() as zfs:
                importable = zfs.find_import()
                for p in importable:
                    try:
                        pool = p.asdict()
                        logger.debug(f"Found pool: {{'name': '{pool['name']}', 'status': '{pool['status']}'}}")
                        if "scan" in pool:
                            pool["scan"]["start_time"] = str(pool["scan"]["start_time"])
                            pool["scan"]["end_time"] = str(pool["scan"]["end_time"])
                        z_pools.append(pool)
                    except Exception as pool_error:
                        logger.error(f"Error processing pool: {pool_error}")
        except PermissionError as e:
            logger.error(f"Permission error in find_import: {e}")
            print("[]")
            return

        print(json.dumps(z_pools, indent=4))
    except Exception as e:
        logger.error(f"Exception in main: {e}")
        print("[]")

if __name__ == "__main__":
    main()