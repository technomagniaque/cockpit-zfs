#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*ABCs.*collections.*")
import datetime
import json
import os
import re
import subprocess
import sys
from typing import Optional

try:
    import libzfs
except ImportError:
    libzfs = None


def basic_typed_children(children):
    for i in range(len(children)):
        children[i]['properties']['creation']['parsed'] = str(children[i]['properties']['creation']['parsed'])
        if len(children[i]['children']) >= 1:
            children[i]['children'] = basic_typed_children(children[i]['children'])
    return children


def _prop(snap, name) -> Optional[dict]:
    """
    Safely extract a ZFS property from a snapshot into an asdict()-like shape (avoiding asdict() due to crashing with large amounts of datasets):
    { "value": ..., "rawvalue": ..., "parsed": ... }
    Returns None if unavailable.
    """
    try:
        p = snap.properties.get(name)
        if p is None:
            return None
        out = {}
        if hasattr(p, "value"):
            out["value"] = str(p.value)
        if hasattr(p, "rawvalue"):
            out["rawvalue"] = str(p.rawvalue)
        if hasattr(p, "parsed"):
            out["parsed"] = str(p.parsed)
        return out
    except Exception:
        return None


def _safe_snapshot_dict(snap):
    """
    Build a safe dict for a snapshot WITHOUT calling asdict() (which would
    trigger holds lookups). Shaped to match the fields your UI expects.
    """
    name = snap.name  # "pool/dataset@snap"
    dataset = name.split("@", 1)[0] if "@" in name else name
    snap_name = name.split("@", 1)[1] if "@" in name else ""
    pool = dataset.split("/", 1)[0] if dataset else ""

    guid = _prop(snap, "guid") or {"value": ""}  # UI uses properties.guid.value
    creation = _prop(snap, "creation") or {"rawvalue": "0", "parsed": "", "value": ""}
    referenced = _prop(snap, "referenced") or {}
    used = _prop(snap, "used") or {}

    return {
        "name": name,
        "id": guid.get("value", "") or name,          # fallback to name if guid missing
        "snapshot_name": snap_name,                   # UI uses snapshot.snapshot_name
        "dataset": dataset,
        "pool": pool,
        "mountpoint": "",                             # snapshots typically not mounted
        "type": "snapshot",
        "properties": {
            "guid": guid,
            "creation": creation,
            "referenced": referenced,
            "used": used,
            # UI reads snapshot.properties.clones.parsed; keep a safe default
            "clones": {"parsed": []},
        },
        "holds": {},
    }


# Noms de pool / dataset acceptés (comme DATASET_CHARS de zfs-permissions.py) ; jamais « - » en tête.
DATASET_CHARS = re.compile(r"[A-Za-z0-9_.:\-]+(/[A-Za-z0-9_.:\- ]+)*")
_CLI_ENV = dict(os.environ, LC_ALL="C", LANG="C")
_SNAP_PROPS = ["name", "guid", "creation", "referenced", "used", "clones"]


class SnapshotListError(RuntimeError):
    pass


def _valid_name(name):
    return bool(name) and not name.startswith("-") and bool(DATASET_CHARS.fullmatch(name))


def _creation_parsed(raw):
    """Même rendu que str(datetime) de libzfs (heure locale)."""
    try:
        return str(datetime.datetime.fromtimestamp(int(raw)))
    except (ValueError, TypeError, OverflowError, OSError):
        return raw


def _zfs_list(flags, props, extra):
    cmd = ["zfs", "list", flags, ",".join(props)] + extra
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, env=_CLI_ENV)
    if res.returncode != 0:
        raise SnapshotListError(f"{' '.join(cmd[:4])} a échoué : {res.stderr.strip()}")
    rows = {}
    for line in res.stdout.splitlines():
        if not line:
            continue
        cols = line.split("\t")
        if len(cols) != len(props):
            print(f"Warning: zfs list: ligne inattendue : {line!r}", file=sys.stderr)
            continue
        rows[cols[0]] = dict(zip(props, cols))
    return rows


def _snapshots_from_zfs_list(filter_dataset: Optional[str] = None, filter_pool: Optional[str] = None) -> str:
    """Repli CLI (`zfs list -t snapshot`) lorsque python3-libzfs est absent (Debian 13 Trixie).

    Même forme que libzfs : `value` lisible (1.2G, date), `rawvalue` brut (octets, epoch),
    `parsed` typé (octets ; str(datetime) pour creation). Une erreur de `zfs list` est écrite
    sur stderr et fait sortir le script en erreur (le front l'affiche dans la console).
    """
    for n in (filter_dataset, filter_pool):
        if n is not None and not _valid_name(n):
            raise SnapshotListError(f"nom de dataset ou de pool invalide : {n!r}")
    target = []
    if filter_dataset:
        target = ["--", filter_dataset]
    elif filter_pool:
        target = ["-r", "--", filter_pool]

    z_datasets = {}
    for name in _zfs_list("-Hpo", ["name"], ["-t", "filesystem,volume"] + target):
        z_datasets[name] = []

    snap_target = ["-r", "-d", "1", "--", filter_dataset] if filter_dataset else target
    raw = _zfs_list("-Hpo", _SNAP_PROPS, ["-t", "snapshot"] + snap_target)
    human = _zfs_list("-Ho", _SNAP_PROPS, ["-t", "snapshot"] + snap_target)

    for name, row in raw.items():
        if "@" not in name:
            continue
        hrow = human.get(name, row)
        dataset, snap_name = name.split("@", 1)
        if filter_dataset and dataset != filter_dataset:
            continue
        pool = dataset.split("/", 1)[0] if dataset else ""
        if filter_pool and pool != filter_pool:
            continue
        clones_raw = row["clones"]
        clones_list = [] if clones_raw in ("-", "") else [c for c in clones_raw.split(",") if c]

        def size(prop):
            try:
                parsed = int(row[prop])
            except ValueError:
                parsed = 0
            return {"value": hrow[prop], "rawvalue": row[prop], "parsed": parsed}

        z_datasets.setdefault(dataset, []).append({
            "name": name,
            "id": row["guid"] or name,
            "snapshot_name": snap_name,
            "dataset": dataset,
            "pool": pool,
            "mountpoint": "",
            "type": "snapshot",
            "properties": {
                "guid": {"value": row["guid"], "rawvalue": row["guid"], "parsed": row["guid"]},
                "creation": {"value": hrow["creation"], "rawvalue": row["creation"],
                             "parsed": _creation_parsed(row["creation"])},
                "referenced": size("referenced"),
                "used": size("used"),
                "clones": {"parsed": clones_list, "value": clones_raw},
            },
            "holds": {},
        })
    return json.dumps(z_datasets, indent=4)


def get_all_snapshots():
    if libzfs is None:
        return _snapshots_from_zfs_list()
    try:
        with libzfs.ZFS() as zfs:
            z_datasets = {}
            for d in zfs.datasets:
                snaps = []
                for snap in d.snapshots:
                    try:
                        snaps.append(_safe_snapshot_dict(snap))
                    except libzfs.ZFSException:
                        # Snapshot vanished or is otherwise inaccessible; skip it
                        continue
                    except Exception:
                        # Be defensive against any unexpected property access errors
                        continue
                z_datasets[d.name] = snaps
        return json.dumps(z_datasets, indent=4)
    except Exception:
        return _snapshots_from_zfs_list()


def get_snapshots_by_dataset(dataset_name):
    if libzfs is None:
        return _snapshots_from_zfs_list(filter_dataset=dataset_name)
    try:
        with libzfs.ZFS() as zfs:
            z_datasets = {}
            try:
                d = zfs.get_dataset(dataset_name)
            except libzfs.ZFSException:
                return json.dumps({}, indent=4)

            snaps = []
            for snap in d.snapshots:
                try:
                    snaps.append(_safe_snapshot_dict(snap))
                except libzfs.ZFSException:
                    continue
                except Exception:
                    continue
            z_datasets[d.name] = snaps
        return json.dumps(z_datasets, indent=4)
    except Exception:
        return _snapshots_from_zfs_list(filter_dataset=dataset_name)


def get_snapshots_by_pool(pool_name):
    if libzfs is None:
        return _snapshots_from_zfs_list(filter_pool=pool_name)
    try:
        with libzfs.ZFS() as zfs:
            z_datasets = {}
            for d in zfs.datasets:
                # Be defensive: d.pool may be missing in some edge cases
                if getattr(d.pool, "name", None) == pool_name:
                    snaps = []
                    for snap in d.snapshots:
                        try:
                            snaps.append(_safe_snapshot_dict(snap))
                        except libzfs.ZFSException:
                            continue
                        except Exception:
                            continue
                    z_datasets[d.name] = snaps
        return json.dumps(z_datasets, indent=4)
    except Exception:
        return _snapshots_from_zfs_list(filter_pool=pool_name)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get-snapshots.py [all | dataset:<name> | pool:<name>]")
        return

    command = sys.argv[1]
    snapshots = None

    try:
        snapshots = _dispatch(command)
    except SnapshotListError as e:
        print(f"get-snapshots: {e}", file=sys.stderr)
        sys.exit(1)
    if snapshots:
        print(snapshots)


def _dispatch(command):
    snapshots = None
    if command == 'all':
        snapshots = get_all_snapshots()
    elif command.startswith('dataset:'):
        dataset_name = command.split(':', 1)[1]
        snapshots = get_snapshots_by_dataset(dataset_name)
    elif command.startswith('pool:'):
        pool_name = command.split(':', 1)[1]
        snapshots = get_snapshots_by_pool(pool_name)
    else:
        raise SnapshotListError("commande invalide : 'all', 'dataset:<nom>' ou 'pool:<nom>'")
    return snapshots


if __name__ == '__main__':
    main()
