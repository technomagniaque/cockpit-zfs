#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*ABCs.*collections.*")
import json
import subprocess
import sys


def basic_typed_children(children):
    for i in range(0, len(children)):
        children[i]['properties']['creation']['parsed'] = str(children[i]['properties']['creation']['parsed'])

        if len(children[i]['children']) >= 1:
            children[i]['children'] = basic_typed_children(children[i]['children'])

    return children


def _parse_int(val, default=0):
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _parse_bool(val, default=False):
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("on", "yes", "true", "1"):
        return True
    if s in ("off", "no", "false", "0"):
        return False
    return default


def _datasets_from_zfs_list():
    """Fallback CLI (`zfs list` / `zfs get`) lorsque python3-libzfs est absent (Debian 13 Trixie)."""
    try:
        props = [
            "name", "type", "guid", "creation", "atime", "casesensitivity",
            "compression", "dedup", "dnodesize", "encryption", "encryptionroot",
            "keystatus", "logbias", "mlslabel", "mountpoint", "mounted",
            "quota", "readonly", "recordsize", "refquota", "available", "used",
            "usedbychildren", "usedbydataset", "usedbyrefreservation",
            "usedbysnapshots", "volblocksize", "volsize", "sync", "xattr", "acltype",
        ]
        res = subprocess.run(
            ["zfs", "list", "-Hpo", ",".join(props), "-t", "filesystem,volume"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
        )
        if res.returncode != 0:
            return []

        custom_map = {}
        res_custom = subprocess.run(
            ["zfs", "get", "-Hpo", "name,value", "cockpit:encrypted", "-t", "filesystem,volume"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
        )
        if res_custom.returncode == 0:
            for cline in res_custom.stdout.strip().splitlines():
                parts = cline.split("\t", 1)
                if len(parts) == 2:
                    custom_map[parts[0]] = parts[1]

        by_name = {}
        roots = []
        for line in res.stdout.strip().splitlines():
            if not line:
                continue
            cols = line.split("\t")
            if len(cols) < len(props):
                continue
            row = dict(zip(props, cols))
            name = row["name"]
            pool_name = name.split("/", 1)[0]
            ds_type = row["type"].upper()
            enc_val = row["encryption"]
            cockpit_enc = custom_map.get(name, "-")
            is_encrypted = (enc_val not in ("off", "-")) or _parse_bool(cockpit_enc, False)

            ds = {
                "name": name,
                "pool": pool_name,
                "type": ds_type,
                "id": name,
                "mountpoint": row["mountpoint"],
                "encrypted": is_encrypted,
                "key_loaded": row["keystatus"] == "available",
                "children": [],
                "properties": {
                    "guid": {"parsed": row["guid"], "value": row["guid"]},
                    "encryption": {"parsed": enc_val, "value": enc_val},
                    "keystatus": {"parsed": row["keystatus"], "value": row["keystatus"]},
                    "creation": {"parsed": row["creation"], "rawvalue": row["creation"], "value": row["creation"]},
                    "atime": {"parsed": _parse_bool(row["atime"], True), "value": row["atime"]},
                    "casesensitivity": {"parsed": row["casesensitivity"], "value": row["casesensitivity"]},
                    "compression": {"parsed": row["compression"], "value": row["compression"]},
                    "dedup": {"parsed": row["dedup"], "value": row["dedup"]},
                    "dnodesize": {"parsed": row["dnodesize"], "value": row["dnodesize"]},
                    "encryptionroot": {"parsed": row["encryptionroot"], "value": row["encryptionroot"]},
                    "logbias": {"parsed": row["logbias"], "value": row["logbias"]},
                    "mlslabel": {"parsed": row["mlslabel"], "value": row["mlslabel"]},
                    "mountpoint": {"parsed": row["mountpoint"], "value": row["mountpoint"]},
                    "Quota": {"parsed": _parse_int(row["quota"]), "value": row["quota"]},
                    "quota": {"parsed": _parse_int(row["quota"]), "value": row["quota"]},
                    "readonly": {"parsed": _parse_bool(row["readonly"], False), "value": row["readonly"]},
                    "recordsize": {"parsed": _parse_int(row["recordsize"], 131072), "value": row["recordsize"]},
                    "refquota": {"parsed": _parse_int(row["refquota"]), "value": row["refquota"]},
                    "Refquota": {"parsed": _parse_int(row["refquota"]), "value": row["refquota"]},
                    "available": {"parsed": _parse_int(row["available"]), "value": row["available"]},
                    "used": {"parsed": _parse_int(row["used"]), "value": row["used"]},
                    "usedbychildren": {"parsed": _parse_int(row["usedbychildren"]), "value": row["usedbychildren"]},
                    "usedbydataset": {"parsed": _parse_int(row["usedbydataset"]), "value": row["usedbydataset"]},
                    "usedbyrefreservation": {"parsed": _parse_int(row["usedbyrefreservation"]), "value": row["usedbyrefreservation"]},
                    "usedbysnapshots": {"parsed": _parse_int(row["usedbysnapshots"]), "value": row["usedbysnapshots"]},
                    "volsize": {"parsed": _parse_int(row["volsize"]), "value": row["volsize"]},
                    "volblocksize": {"parsed": _parse_int(row["volblocksize"]), "value": row["volblocksize"]},
                    "sync": {"parsed": row["sync"], "value": row["sync"]},
                    "mounted": {"parsed": _parse_bool(row["mounted"], False), "value": row["mounted"]},
                    "xattr": {"parsed": row["xattr"], "value": row["xattr"]},
                    "acltype": {"parsed": row["acltype"], "value": row["acltype"]},
                    "cockpit:encrypted": {"parsed": cockpit_enc, "value": cockpit_enc},
                },
            }
            by_name[name] = ds
            if "/" in name:
                parent_name = name.rsplit("/", 1)[0]
                if parent_name in by_name:
                    by_name[parent_name]["children"].append(ds)
                else:
                    roots.append(ds)
            else:
                roots.append(ds)
        return roots
    except Exception as e:
        print(f"Warning: fallback zfs list failed: {e}", file=sys.stderr)
        return []


def main():
    try:
        import libzfs
    except ImportError:
        print(json.dumps(_datasets_from_zfs_list(), indent=4))
        return

    try:
        with libzfs.ZFS() as zfs:
            z_datasets = []

            for p in zfs.datasets:
                try:
                    dataset = p.asdict()

                    # Only include filesystems and volumes (zvols)
                    if dataset.get('type') not in ('FILESYSTEM', 'VOLUME'):
                        continue

                    dataset['properties']['creation']['parsed'] = str(dataset['properties']['creation']['parsed'])

                    dataset['children'] = basic_typed_children(dataset['children'])

                    z_datasets.append(dataset)
                except Exception as e:
                    print(f"Warning: skipping dataset: {e}", file=sys.stderr)
                    continue

        print(json.dumps(z_datasets, indent=4))
    except Exception:
        print(json.dumps(_datasets_from_zfs_list(), indent=4))


if __name__ == '__main__':
    main()
