#!/usr/bin/env python3
import os, json, subprocess, logging
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


logger = get_logger("cockpit_zfs_getpools", "getpools.log")

# --- repli CLI : analyse de `zpool status` (même forme JSON que libzfs) ---
import re, time
from datetime import datetime

_CLI_ENV = dict(os.environ, LC_ALL="C", LANG="C")
_EMPTY_GROUPS = ("data", "cache", "dedup", "log", "spare", "special")
_SECTION_MAP = {"logs": "log", "log": "log", "cache": "cache", "spares": "spare", "spare": "spare",
                "special": "special", "dedup": "dedup"}
_VDEV_RE = re.compile(r"^(mirror|raidz[0-3]?|draid[0-3]?(?::[^-\s]+)?|replacing|spare|indirect)(?:-\d+)?$")
_HDR_RE = re.compile(r"^\s*(pool|id|state|status|action|see|scan|remove|checkpoint|compatibility|config|errors):(?:\s(.*))?$")
_SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)([BKMGTPEZ]?)$")
_UNITS = {"": 1, "B": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40, "P": 1 << 50, "E": 1 << 60, "Z": 1 << 70}


def _size_to_bytes(text):
    """« 1.23T » ou « 1352331264 » (zpool status -p) -> octets (int)."""
    m = _SIZE_RE.match(str(text).strip())
    if not m:
        return 0
    return int(float(m.group(1)) * _UNITS[m.group(2)])


def _parse_date(text):
    """« Sun Nov  8 00:24:02 2026 » (heure locale) -> « 2026-11-08 00:24:02-05:00 » (comme str(datetime) de libzfs, avec fuseau)."""
    try:
        t = time.strptime(" ".join(str(text).split()), "%a %b %d %H:%M:%S %Y")
        return datetime(*t[:6]).astimezone().isoformat(sep=" ")
    except (ValueError, TypeError):
        return None


def _duration_secs(text):
    """« 00:10:05 » ou « 1 days 02:03:04 » -> secondes."""
    m = re.search(r"(?:(\d+)\s+days?\s+)?(\d+):(\d{2}):(\d{2})", str(text))
    if not m:
        return None
    return int(m.group(1) or 0) * 86400 + int(m.group(2)) * 3600 + int(m.group(3)) * 60 + int(m.group(4))


def _empty_scan():
    return {
        "function": None, "start_time": "None", "end_time": "None", "pause": "None",
        "state": None, "errors": 0, "percentage": 0,
        "total_secs_left": 0, "bytes_issued": 0, "bytes_processed": 0, "bytes_to_process": 0,
    }


def parse_scan(lines):
    """Ligne « scan: » de zpool status (+ continuations) -> dict scan au format libzfs.

    percentage en pourcents (0-100) comme libzfs ; dates au format str(datetime) avec fuseau.
    """
    scan = _empty_scan()
    text = " ".join(" ".join(lines).split())
    if not text or text.startswith("none requested"):
        return scan
    if text.startswith("resilver") or " resilvered" in " " + text.split(",")[0]:
        scan["function"] = "RESILVER"
    elif text.startswith("scrub"):
        scan["function"] = "SCRUB"
    else:
        return scan
    date = r"(\w{3} \w{3} +\d+ \d{2}:\d{2}:\d{2} \d{4})"
    m = re.search(r"(?:repaired|resilvered) (\S+) in (.+?) with (\d+) errors? on " + date, text)
    if m:
        scan["state"] = "FINISHED"
        scan["end_time"] = _parse_date(m.group(4)) or "None"
        scan["errors"] = int(m.group(3))
        secs = _duration_secs(m.group(2))
        try:
            if secs is not None and scan["end_time"] != "None":
                end = datetime.fromisoformat(scan["end_time"])
                scan["start_time"] = datetime.fromtimestamp(end.timestamp() - secs).astimezone().isoformat(sep=" ")
        except ValueError:
            pass
        scan["percentage"] = 100.0
        return scan
    m = re.search(r"canceled on " + date, text)
    if m:
        scan["state"] = "CANCELED"
        scan["end_time"] = _parse_date(m.group(1)) or "None"
        return scan
    m = re.search(r"in progress since " + date, text)
    if m:
        scan["state"] = "SCANNING"
        scan["start_time"] = _parse_date(m.group(1)) or "None"
    m = re.search(r"paused since " + date, text)
    if m:
        scan["state"] = "SCANNING"
        scan["pause"] = _parse_date(m.group(1)) or "None"
        m2 = re.search(r"started on " + date, text)
        if m2:
            scan["start_time"] = _parse_date(m2.group(1)) or "None"
    if scan["state"] is None:
        return scan
    m = re.search(r"(\S+) / (\S+) scanned", text) or re.search(r"(\S+) scanned out of (\S+)", text)
    if m:
        scan["bytes_processed"] = _size_to_bytes(m.group(1))
        scan["bytes_to_process"] = _size_to_bytes(m.group(2))
    m = re.search(r"(\S+) / \S+ issued", text) or re.search(r"(\S+) issued", text)
    if m:
        scan["bytes_issued"] = _size_to_bytes(m.group(1))
    m = re.search(r"(\d+(?:\.\d+)?)% done", text)
    if m:
        scan["percentage"] = float(m.group(1))
    m = re.search(r"((?:\d+\s+days?\s+)?\d+:\d{2}:\d{2}) to go", text)
    if m:
        scan["total_secs_left"] = _duration_secs(m.group(1)) or 0
    return scan


def split_status_sections(text):
    """Découpe la sortie de `zpool status <pool>` en sections (pool, state, status, action, scan, config, errors…)."""
    sections = {}
    key = None
    for line in text.splitlines():
        m = _HDR_RE.match(line)
        if m and (key != "config" or m.group(1) == "errors"):
            key = m.group(1)
            first = (m.group(2) or "").strip()
            sections[key] = [first] if first else []
            continue
        if key:
            sections[key].append(line if key == "config" else line.strip())
    return sections


# Messages « status: » de zpool_status_t (libzfs_status.c / zpool_main.c), du plus spécifique au plus général
_STATUS_CODES = [
    ("currently being resilvered", "RESILVERING"),
    ("is currently being rebuilt", "REBUILDING"),
    ("could not be opened", None),               # MISSING_DEV_R / _NR selon « Sufficient replicas »
    ("are missing from the system", None),
    ("label is missing or invalid", None),       # CORRUPT_LABEL_R / _NR
    ("faulted in response to persistent errors", None),  # FAULTED_DEV_R / _NR
    ("are faulted", None),
    ("has been removed", "REMOVED_DEV"),
    ("has been taken offline", "OFFLINE_DEV"),
    ("unrecoverable error", "FAILING_DEV"),
    ("resulting in data corruption", "CORRUPT_DATA"),
    ("metadata is corrupted", "CORRUPT_POOL"),
    ("suspended", "IO_FAILURE_WAIT"),
    ("intent log", "BAD_LOG"),
    ("errata", "ERRATA"),
    ("features are not enabled", "FEAT_DISABLED"),
    ("on-disk format", "VERSION_OLDER"),
    ("configured to use a non-native block size", "NON_NATIVE_ASHIFT"),
    ("compatibility", "COMPATIBILITY_ERR"),
]


def status_code_from_sections(sections, health):
    """(status_code, status_detail) proches de libzfs : « OK » seulement si zpool status n'annonce rien."""
    detail = " ".join(" ".join(sections.get("status", [])).split())
    if not detail:
        if health in ("ONLINE", "", None):
            return "OK", ""
        return health, f"Pool {health}"
    low = detail.lower()
    replicas = "sufficient replicas" in low
    for needle, code in _STATUS_CODES:
        if needle in low:
            if code is None:
                base = "CORRUPT_LABEL" if "label" in needle else ("FAULTED_DEV" if "fault" in needle else "MISSING_DEV")
                code = base + ("_R" if replicas else "_NR")
            return code, detail
    return "UNKNOWN", detail


def error_count_from_sections(sections):
    """« errors: No known data errors » -> 0 ; « errors: 12 data errors, use '-v' for a list » -> 12."""
    text = " ".join(sections.get("errors", []))
    m = re.search(r"(\d+)\s+data errors?", text)
    return int(m.group(1)) if m else 0


def _err_int(text):
    return _size_to_bytes(text) if text not in (None, "-") else 0


def parse_config_vdevs(pool_name, config_lines):
    """Lignes de « config: » -> groupes de vdevs (data/log/cache/spare/special/dedup), arborescence par indentation."""
    groups = {g: [] for g in _EMPTY_GROUPS}
    section = "data"
    stack = []  # [(indent, vdev)]
    pool_seen = False
    for line in config_lines:
        if not line.strip():
            continue
        parts = line.split()
        raw_name = parts[0]
        if raw_name == "NAME" and "STATE" in parts:
            continue
        indent = len(line.expandtabs(8)) - len(line.expandtabs(8).lstrip())
        if raw_name in _SECTION_MAP and len(parts) == 1:
            section = _SECTION_MAP[raw_name]
            stack = []
            continue
        if not pool_seen and raw_name == pool_name:
            pool_seen = True
            continue
        status = parts[1] if len(parts) > 1 else "ONLINE"
        is_vdev = bool(_VDEV_RE.match(raw_name))
        if is_vdev:
            t = _VDEV_RE.match(raw_name).group(1)
            vtype = "raidz" if t.startswith("raidz") else ("draid" if t.startswith("draid") else t)
            disk_path = None
            name = raw_name
        else:
            vtype = "disk"
            if raw_name.startswith("/dev/"):
                disk_path = raw_name
            else:
                disk_path = next((pfx + raw_name for pfx in ("/dev/disk/by-path/", "/dev/disk/by-vdev/", "/dev/disk/by-id/", "/dev/")
                                  if os.path.exists(pfx + raw_name)), f"/dev/{raw_name}")
            name = os.path.basename(raw_name)
        entry = {
            "name": name,
            "type": vtype,
            "path": disk_path,
            "status": status,
            "guid": "",
            "stats": {
                "read_errors": _err_int(parts[2]) if len(parts) > 2 else 0,
                "write_errors": _err_int(parts[3]) if len(parts) > 3 else 0,
                "checksum_errors": _err_int(parts[4]) if len(parts) > 4 else 0,
            },
            "children": [],
        }
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stack:
            stack[-1][1]["children"].append(entry)
        else:
            groups[section].append(entry)
        if is_vdev:
            stack.append((indent, entry))
    return groups


def _zpool_status_cli(pool_name):
    """Sortie de `zpool status -P -p` (anglais forcé), ou None si la commande échoue."""
    res = subprocess.run(
        ["zpool", "status", "-P", "-p", "--", pool_name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=_CLI_ENV,
    )
    if res.returncode != 0:
        logger.error(f"zpool status {pool_name} failed: {res.stderr.strip()}")
        return None
    return res.stdout


def _parse_vdevs_from_status(pool_name, text=None):
    """VDevs d'un pool à partir de `zpool status` (gardé pour compatibilité)."""
    try:
        if text is None:
            text = _zpool_status_cli(pool_name)
        if not text:
            return {g: [] for g in _EMPTY_GROUPS}
        return parse_config_vdevs(pool_name, split_status_sections(text).get("config", []))
    except Exception as e:
        logger.error(f"Failed to parse vdevs from zpool status: {e}")
        return {g: [] for g in _EMPTY_GROUPS}


def pool_status_cli(pool_name, health):
    """status_code, status_detail, error_count, scan et groupes d'un pool, en un seul `zpool status`."""
    text = _zpool_status_cli(pool_name)
    if text is None:
        return {
            "status_code": "UNKNOWN", "status_detail": "zpool status a échoué (voir le journal getpools.log)",
            "error_count": 0, "scan": _empty_scan(), "groups": {g: [] for g in _EMPTY_GROUPS},
        }
    sections = split_status_sections(text)
    code, detail = status_code_from_sections(sections, health)
    return {
        "status_code": code,
        "status_detail": detail,
        "error_count": error_count_from_sections(sections),
        "scan": parse_scan(sections.get("scan", [])),
        "groups": _parse_vdevs_from_status(pool_name, text),
    }


def _parse_bool_cli(val, default=False):
    s = str(val).strip().lower()
    if s in ("on", "yes", "true", "1"):
        return True
    if s in ("off", "no", "false", "0"):
        return False
    return default


def _parse_int_cli(val, default=0):
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _pool_extra_props_cli(pool_name):
    out = {}
    res = subprocess.run(
        ["zpool", "get", "-Hp", "autoexpand,autoreplace,autotrim,delegation,listsnapshots,readonly,failmode,altroot,ashift,comment", "--", pool_name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=_CLI_ENV
    )
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                out[parts[1]] = parts[2]
    return out


def _pool_root_dataset_cli(pool_name):
    res = subprocess.run(
        ["zfs", "get", "-Hp", "recordsize,compression,dedup,refreservation,available,used", "--", pool_name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=_CLI_ENV
    )
    if res.returncode != 0:
        return None
    props = {}
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            props[parts[1]] = parts[2]
    if not props:
        return None
    rec_bytes = _parse_int_cli(props.get("recordsize"), 131072)
    if rec_bytes >= 1024 and rec_bytes % 1024 == 0:
        rec_val = f"{rec_bytes // 1024}K" if rec_bytes < 1048576 else f"{rec_bytes // 1048576}M"
    else:
        rec_val = str(rec_bytes)
    comp_val = props.get("compression", "off")
    dedup_val = props.get("dedup", "off")
    return {
        "name": pool_name,
        "properties": {
            "recordsize": {"parsed": rec_bytes, "value": rec_val},
            "compression": {"parsed": comp_val if comp_val != "off" else False, "value": comp_val},
            "dedup": {"parsed": dedup_val, "value": dedup_val},
            "refreservation": {"parsed": _parse_int_cli(props.get("refreservation"), 0), "value": props.get("refreservation", "0")},
            "available": {"parsed": _parse_int_cli(props.get("available"), 0), "value": props.get("available", "0")},
            "used": {"parsed": _parse_int_cli(props.get("used"), 0), "value": props.get("used", "0")},
        },
        "children": [],
    }


def _pools_from_zpool_list_min():
    """Permission-friendly fallback when libzfs /dev/zfs is blocked."""
    try:
        # -H (scripted) -p (parsable numbers) -o selected fields
        res = subprocess.run(
            ["zpool", "list", "-Hpo", "name,size,allocated,capacity,free,health,guid"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=_CLI_ENV
        )
        if res.returncode != 0:
            logger.error(f"zpool list failed: {res.stderr.strip()}")
            return []

        pools = []
        for line in res.stdout.strip().splitlines():
            if not line:
                continue
            name, size, alloc, cap, free, health, guid = line.split("\t")
            extra = _pool_extra_props_cli(name)
            pools.append({
                "name": name,
                "status": health,
                "guid": guid,
                "properties": {
                    # un pool FAULTED/UNAVAIL affiche « - » : ne pas faire échouer tout le repli
                    "size": {"parsed": _parse_int_cli(size)},
                    "allocated": {"parsed": _parse_int_cli(alloc)},
                    "capacity": {"rawvalue": _parse_int_cli(cap.rstrip("%"))},
                    "free": {"parsed": _parse_int_cli(free)},
                    "health": {"parsed": health},
                    "autoexpand": {"parsed": _parse_bool_cli(extra.get("autoexpand"), False)},
                    "autoreplace": {"parsed": _parse_bool_cli(extra.get("autoreplace"), False)},
                    "autotrim": {"parsed": extra.get("autotrim", "off")},
                    "delegation": {"parsed": _parse_bool_cli(extra.get("delegation"), True)},
                    "listsnapshots": {"parsed": _parse_bool_cli(extra.get("listsnapshots"), False)},
                    "readonly": {"parsed": _parse_bool_cli(extra.get("readonly"), False)},
                    "failmode": {"parsed": extra.get("failmode", "wait")},
                    "altroot": {"value": extra.get("altroot", "-")},
                    "ashift": {"rawvalue": extra.get("ashift", "0")},
                    "comment": {"value": extra.get("comment", "-")},
                },
                "root_dataset": _pool_root_dataset_cli(name),
                **pool_status_cli(name, health),
            })
        logger.info(f"Pools (fallback) discovered: {len(pools)}")
        return pools
    except Exception as e:
        logger.error(f"Fallback zpool parse failed: {e}")
        return []

def basic_typed_children(children):
    try:
        for i in range(0, len(children)):
            children[i]["properties"]["creation"]["parsed"] = str(children[i]["properties"]["creation"]["parsed"])
            if len(children[i].get("children", [])) >= 1:
                children[i]["children"] = basic_typed_children(children[i]["children"])
        return children
    except Exception as e:
        logger.error(f"Exception in basic_typed_children: {e}")
        return []

def main():
    try:
        logger.info("=" * 80)
        logger.info("Starting a new run of get-pools script")

        try:
            import warnings
            warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*ABCs.*collections.*")
            import libzfs
        except Exception as e:
            logger.error(f"libzfs import failed: {e}")
            print(json.dumps(_pools_from_zpool_list_min(), indent=4))
            return

        try:
            with libzfs.ZFS() as zfs:
                z_pools = []
                for p in zfs.pools:
                    pool = p.asdict()
                    root_dataset = pool.get("root_dataset")
                    if root_dataset is not None:
                        pool["root_dataset"]["properties"]["creation"]["parsed"] = str(
                            pool["root_dataset"]["properties"]["creation"]["parsed"]
                        )
                        if "scan" in pool:
                            pool["scan"]["start_time"] = str(pool["scan"]["start_time"])
                            pool["scan"]["end_time"] = str(pool["scan"]["end_time"])
                            pool["scan"]["pause"] = str(pool["scan"]["pause"])
                        pool["root_dataset"]["children"] = basic_typed_children(pool["root_dataset"]["children"])
                    else:
                        pool["root_dataset"] = None

                    logger.debug(f"Parsed pool data: {{'name': '{pool['name']}', 'status': '{pool['status']}'}}")
                    z_pools.append(pool)

                logger.info(f"Pools discovered: {len(z_pools)}")
                print(json.dumps(z_pools, indent=4, default=str))
        except PermissionError as e:
            logger.error(f"Permission opening libzfs: {e}")
            print(json.dumps(_pools_from_zpool_list_min(), indent=4))
        except Exception as e:
            logger.error(f"Unhandled exception with libzfs: {e}")
            print(json.dumps(_pools_from_zpool_list_min(), indent=4))
    except Exception as e:
        logger.error(f"Exception in main: {e}")
        print("[]")

if __name__ == "__main__":
    main()