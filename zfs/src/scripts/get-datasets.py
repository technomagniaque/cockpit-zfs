#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*ABCs.*collections.*")
import datetime
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


# Propriétés lues par le repli CLI ; toutes existent dans OpenZFS 2.x pour les
# systèmes de fichiers et les volumes (`-` quand elles ne s'appliquent pas).
_FALLBACK_PROPS = [
    "name", "type", "guid", "creation", "atime", "casesensitivity",
    "compression", "dedup", "dnodesize", "encryption", "encryptionroot",
    "keystatus", "logbias", "mlslabel", "mountpoint", "mounted",
    "quota", "readonly", "recordsize", "refquota", "available", "used",
    "usedbychildren", "usedbydataset", "usedbyrefreservation",
    "usedbysnapshots", "volblocksize", "volsize", "sync", "xattr", "acltype",
    "canmount", "aclinherit", "checksum", "refreservation", "snapshot_count",
]

# Propriétés dont libzfs expose `parsed` sous forme d'entier (octets ou compteur).
_INT_PROPS = {
    "quota", "refquota", "available", "used", "usedbychildren", "usedbydataset",
    "usedbyrefreservation", "usedbysnapshots", "volblocksize", "volsize",
    "recordsize", "refreservation", "snapshot_count",
}
# Propriétés on/off ou yes/no dont libzfs expose `parsed` sous forme de booléen.
_BOOL_PROPS = {"atime", "readonly", "mounted"}


def _zfs_list_rows(props, raw):
    """`zfs list -H[p]o` → {nom: {propriété: valeur}} ; None si la commande échoue."""
    flags = "-Hpo" if raw else "-Ho"
    res = subprocess.run(
        ["zfs", "list", flags, ",".join(props), "-t", "filesystem,volume"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
    )
    if res.returncode != 0:
        print(f"Warning: zfs list {flags} failed: {res.stderr.strip()}", file=sys.stderr)
        return None
    rows = {}
    order = []
    for line in res.stdout.splitlines():
        if not line:
            continue
        cols = line.split("\t")
        if len(cols) != len(props):
            print(f"Warning: zfs list: unexpected line: {line!r}", file=sys.stderr)
            continue
        row = dict(zip(props, cols))
        rows[row["name"]] = row
        order.append(row["name"])
    return rows, order


def _creation_parsed(raw):
    """Même rendu que str(datetime) de libzfs (heure locale)."""
    try:
        return str(datetime.datetime.fromtimestamp(int(raw)))
    except (ValueError, TypeError, OverflowError, OSError):
        return raw


def _prop(name, raw, value):
    if name in _INT_PROPS:
        default = 131072 if name == "recordsize" else 0
        parsed = _parse_int(raw, default)
    elif name in _BOOL_PROPS:
        parsed = _parse_bool(raw, name == "atime")
    elif name == "creation":
        parsed = _creation_parsed(raw)
    else:
        parsed = raw
    return {"parsed": parsed, "rawvalue": raw, "value": value}


def _datasets_from_zfs_list():
    """Repli CLI (`zfs list` / `zfs get`) lorsque python3-libzfs est absent (Debian 13 Trixie).

    Produit la même forme que libzfs : une liste PLATE de tous les systèmes de
    fichiers et volumes (`zfs.datasets` parcourt aussi les descendants), chacun
    avec ses enfants directs dans `children`. `value` est la valeur lisible
    (`zfs list -Ho` : 128K, none, date…), `rawvalue` la valeur brute (`-Hpo`),
    `parsed` la valeur typée (entier, booléen).
    """
    try:
        props = _FALLBACK_PROPS
        raw_res = _zfs_list_rows(props, raw=True)
        if raw_res is None:
            return []
        raw_rows, order = raw_res
        fmt_res = _zfs_list_rows(props, raw=False)
        fmt_rows = fmt_res[0] if fmt_res is not None else {}

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
        else:
            print(f"Warning: zfs get cockpit:encrypted failed: {res_custom.stderr.strip()}", file=sys.stderr)

        by_name = {}
        flat = []
        for name in order:
            row = raw_rows[name]
            fmt = fmt_rows.get(name, row)
            pool_name = name.split("/", 1)[0]
            enc_val = row["encryption"]
            cockpit_enc = custom_map.get(name, "-")
            is_encrypted = (enc_val not in ("off", "-")) or _parse_bool(cockpit_enc, False)

            properties = {}
            for prop in props:
                if prop in ("name", "type"):
                    continue
                properties[prop] = _prop(prop, row[prop], fmt.get(prop, row[prop]))
            # alias historiques attendus par certains écrans
            properties["Quota"] = properties["quota"]
            properties["Refquota"] = properties["refquota"]
            properties["cockpit:encrypted"] = {"parsed": cockpit_enc, "rawvalue": cockpit_enc, "value": cockpit_enc}

            ds = {
                "name": name,
                "pool": pool_name,
                "type": row["type"].upper(),
                "id": name,
                "mountpoint": row["mountpoint"],
                "encrypted": is_encrypted,
                "key_loaded": row["keystatus"] == "available",
                "children": [],
                "properties": properties,
            }
            by_name[name] = ds
            flat.append(ds)
            if "/" in name:
                parent = by_name.get(name.rsplit("/", 1)[0])
                if parent is not None:
                    parent["children"].append(ds)
        return flat
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
