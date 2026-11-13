import json
import os
import re
import subprocess
import time
from datetime import datetime

# --- analyse de `zpool status` (copie de get-pools.py : chaque script est exécuté seul par « python3 -c ») ---
_CLI_ENV = dict(os.environ, LC_ALL="C", LANG="C")
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


def _scan_from_zpool_status():
    """Repli sans libzfs : scan de chaque pool à partir de `zpool status -p` (anglais forcé)."""
    res = subprocess.run(["zpool", "status", "-p"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         universal_newlines=True, env=_CLI_ENV)
    if res.returncode != 0:
        raise RuntimeError(f"zpool status a échoué : {res.stderr.strip()}")
    z_pools = {}
    blocks = re.split(r"(?m)^(?=\s*pool:\s)", res.stdout)
    for block in blocks:
        sections = split_status_sections(block)
        if not sections.get("pool"):
            continue
        name = sections["pool"][0]
        scan = parse_scan(sections.get("scan", []))
        scan["name"] = name
        z_pools[name] = scan
    return z_pools


def main():
    try:
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*ABCs.*collections.*")
        import libzfs
    except ImportError:
        try:
            print(json.dumps(_scan_from_zpool_status(), indent=4))
        except Exception as e:
            import sys
            print(f"get-scan-stats: {e}", file=sys.stderr)
            print("{}")
        return

    try:
        with libzfs.ZFS() as zfs:
            z_pools = {}

            for p in zfs.pools:
                pool = p.asdict()
                name = pool.get("name")

                scan = pool.get("scan") or {}
                scan["name"] = name
                scan["start_time"] = str(scan.get("start_time", ""))
                scan["end_time"] = str(scan.get("end_time", ""))
                scan["pause"] = str(scan.get("pause", "None"))
                if scan.get("state", None) is None:
                    scan["state"] = None

                z_pools[name] = scan

        print(json.dumps(z_pools, indent=4))
    except Exception:
        try:
            print(json.dumps(_scan_from_zpool_status(), indent=4))
        except Exception as e:
            import sys
            print(f"get-scan-stats: {e}", file=sys.stderr)
            print("{}")

if __name__ == "__main__":
    main()
