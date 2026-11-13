import json
import os
import re
import subprocess
import sys


def _count(text):
    """Compteur READ/WRITE/CKSUM : entier (zpool status -p) ; « 1.2K » sans -p ne doit pas devenir 0."""
    m = re.match(r"^(\d+(?:\.\d+)?)([KMGTPE]?)$", text or "")
    if not m:
        return 0
    return int(float(m.group(1)) * {"": 1, "K": 1000, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18}[m.group(2)])

def _disk_stats_from_zpool_status():
    """Fallback: parse per-disk info from 'zpool status' when libzfs is unavailable."""
    try:
        res = subprocess.run(
            ["zpool", "status", "-p"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            env=dict(os.environ, LC_ALL="C", LANG="C"),
        )
        if res.returncode != 0:
            print(f"get-disk-stats: zpool status a échoué : {res.stderr.strip()}", file=sys.stderr)
            return {}

        z_pools = {}
        current_pool = None
        in_config = False
        pool_line_seen = False

        for line in res.stdout.splitlines():
            stripped = line.strip()

            m = re.match(r"pool:\s+(\S+)", stripped)
            if m:
                current_pool = m.group(1)
                z_pools[current_pool] = []
                in_config = False
                pool_line_seen = False
                continue

            if stripped.startswith("config:"):
                in_config = True
                continue

            if not in_config or not current_pool:
                continue

            if stripped == "" or stripped.startswith("NAME"):
                continue
            if stripped.startswith("errors:"):
                in_config = False
                continue

            parts = stripped.split()
            if not parts:
                continue
            name = parts[0]
            status = parts[1] if len(parts) > 1 else "ONLINE"

            if name == current_pool and not pool_line_seen:
                pool_line_seen = True
                continue

            # Skip known section keywords and vdev types
            # « logs » et « spares » sont les en-têtes réels de zpool status (ils devenaient des disques)
            if len(parts) == 1 and name in ("cache", "log", "logs", "dedup", "spare", "spares", "special"):
                continue

            is_vdev = any(name.startswith(p) for p in
                         ["mirror", "raidz", "draid", "replacing", "spare"])
            if is_vdev:
                continue

            # This is a leaf disk
            read_err = parts[2] if len(parts) > 2 else "0"
            write_err = parts[3] if len(parts) > 3 else "0"
            cksum_err = parts[4] if len(parts) > 4 else "0"

            z_pools[current_pool].append({
                "name": name,
                "stats": {
                    "read_errors": _count(read_err),
                    "write_errors": _count(write_err),
                    "checksum_errors": _count(cksum_err),
                },
                "guid": "",
                "status": status,
            })

        return z_pools
    except Exception as e:
        print(f"get-disk-stats: {e}", file=sys.stderr)
        return {}


def get_disks(group):
    disks = []
    for vdev in group:
        if vdev.get('type') == 'disk':
            disks.append({
                'name': vdev.get('name'),
                'stats': vdev.get('stats', {}),
                'guid': vdev.get('guid'),
                'status': vdev.get('status'),
            })
        else:
            children = vdev.get('children') or []
            disks.extend(get_disks(children))
    return disks

def main():
    try:
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*ABCs.*collections.*")
        import libzfs
    except ImportError:
        print(json.dumps(_disk_stats_from_zpool_status(), indent=4))
        return

    try:
        with libzfs.ZFS() as zfs:
            z_pools = {}

            for p in zfs.pools:
                pool = p.asdict()
                name = pool.get('name')
                disks = []

                groups = pool.get('groups') or {}
                for group_name, group in groups.items():
                    disks.extend(get_disks(group or []))

                z_pools[name] = disks

        print(json.dumps(z_pools, indent=4))
    except Exception:
        print(json.dumps(_disk_stats_from_zpool_status(), indent=4))

if __name__ == '__main__':
    main()
