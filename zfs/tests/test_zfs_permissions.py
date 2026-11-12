#!/usr/bin/env python3
"""
Tests du backend zfs-permissions.py avec un faux binaire « zfs ».

Exécution (root requis pour chown / security.* ; paquet acl requis) :
    sudo python3 -m unittest zfs/tests/test_zfs_permissions.py -v

Le faux zfs annonce un dataset tank/data monté sur un dossier temporaire ;
le système de fichiers sous-jacent doit supporter les ACL POSIX (ext4, xfs, zfs).
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "src", "scripts", "zfs-permissions.py")

FAKE_ZFS = textwrap.dedent(r'''
    #!/usr/bin/env python3
    import os, sys
    root = os.environ["FAKE_ROOT"]
    acltype = os.environ.get("FAKE_ACLTYPE", "posixacl")
    args = sys.argv[1:]
    log = os.environ.get("FAKE_LOG")
    if log:
        with open(log, "a") as f:
            f.write(" ".join(args) + "\n")
    if args[0] == "list":
        print("tank\t-\tno")
        print("tank/data\t%s\tyes" % root)
    elif args[0] == "get":
        props = {"type": "filesystem", "mountpoint": root, "mounted": "yes", "readonly": "off",
                 "acltype": acltype, "aclmode": "discard", "aclinherit": "restricted", "xattr": "sa",
                 "dnodesize": "legacy", "casesensitivity": "sensitive", "normalization": "none",
                 "utf8only": "off"}
        for p in args[args.index("property,value,source") + 1].split(","):
            print("%s\t%s\tdefault" % (p, props[p]))
    elif args[0] == "allow":
        print("---- Permissions on tank/data ------------------------------------------")
        print("Permission sets:")
        print("\t@backup send,snapshot,hold")
        print("Create time permissions:")
        print("\tdestroy")
        print("Local permissions:")
        print("\tuser bob create,mount")
        print("Local+Descendent permissions:")
        print("\tgroup staff @backup")
        print("\teveryone diff")
    elif args[0] in ("set", "unallow"):
        pass
    else:
        sys.exit(1)
''').lstrip()


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("setfacl"), "root + paquet acl requis")
class PermissionsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="zfsperm-")
        self.root = os.path.join(self.tmp, "data")
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.root)
        os.makedirs(self.bin)
        with open(os.path.join(self.bin, "zfs"), "w") as f:
            f.write(FAKE_ZFS)
        os.chmod(os.path.join(self.bin, "zfs"), 0o755)
        self.env = dict(os.environ, FAKE_ROOT=self.root, PATH=self.bin + ":" + os.environ["PATH"],
                        FAKE_LOG=os.path.join(self.tmp, "zfs.log"),
                        COCKPIT_ZFS_PERM_BACKUP_DIR=os.path.join(self.tmp, "backups"))
        # arbre : data/{a/{f1,x.sh},b/f2}, fichier sans propriétaire
        os.makedirs(os.path.join(self.root, "a"))
        os.makedirs(os.path.join(self.root, "b"))
        for p in ("a/f1", "b/f2"):
            open(os.path.join(self.root, p), "w").close()
        with open(os.path.join(self.root, "a/x.sh"), "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(os.path.join(self.root, "a/x.sh"), 0o755)
        os.chown(os.path.join(self.root, "b/f2"), 54321, 54321)  # orphelin

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, cmd, **params):
        out = subprocess.run([sys.executable, SCRIPT, cmd, json.dumps(params)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        return data

    def ok(self, cmd, **params):
        data = self.call(cmd, **params)
        self.assertTrue(data["ok"], data)
        return data

    def p(self, rel):
        return os.path.join(self.root, rel)

    def mode(self, rel):
        return stat.S_IMODE(os.lstat(self.p(rel)).st_mode)

    def acl(self, rel):
        return subprocess.run(["getfacl", "-p", "-c", self.p(rel)], stdout=subprocess.PIPE, text=True).stdout

    # ------------------------------------------------------------------ lecture
    def test_inspect(self):
        d = self.ok("inspect", path=self.root)
        self.assertEqual(d["dataset"], "tank/data")
        self.assertEqual(d["acl_mode"], "posix")
        self.assertEqual({c["path"] for c in d["children"]}, {self.p("a"), self.p("b")})
        self.assertIn("user", [e["tag"] for e in d["acl"]["access"]])

    def test_refuse_outside_zfs(self):
        d = self.call("inspect", path="/etc")
        self.assertFalse(d["ok"])

    def test_audit_detects_orphans_and_ntacl(self):
        os.setxattr(self.p("a/f1"), "security.NTACL", b"\x01\x02")
        d = self.ok("audit", path=self.root)
        self.assertEqual(d["counts"]["orphan_uid"], 1)
        self.assertEqual(d["counts"]["ntacl"], 1)
        self.assertEqual(d["total"], 6)

    # ------------------------------------------------------------------ ACL
    def test_set_acl_dry_run_then_apply(self):
        entry = [{"tag": "user", "qualifier": "nobody", "perms": "rwx"}]
        d = self.ok("set-acl", path=self.root, recursive=True, access=entry, default=entry, dry_run=True)
        self.assertNotIn("user:nobody", self.acl("a"))
        self.assertGreater(d["count"], 0)
        self.ok("set-acl", path=self.root, recursive=True, access=entry, default=entry, dry_run=False)
        self.assertIn("default:user:nobody:rwx", self.acl("a"))
        # fichier non exécutable : X ne donne pas x
        self.assertIn("user:nobody:rw-", self.acl("a/f1"))
        self.assertIn("user:nobody:rwx", self.acl("a/x.sh"))

    def test_set_acl_refused_when_acltype_off(self):
        self.env["FAKE_ACLTYPE"] = "off"
        d = self.call("set-acl", path=self.root, access=[{"tag": "user", "qualifier": "nobody", "perms": "r--"}])
        self.assertFalse(d["ok"])
        self.assertIn("posixacl", d["error"])

    # ------------------------------------------------------------------ reset
    def test_unix_mode_with_setgid_and_keep_exec(self):
        subprocess.run(["setfacl", "-m", "u:nobody:rwx", self.p("a/f1")], check=True)
        self.ok("reset", method="unix-mode", path=self.root, owner="root", group="root",
                file_mode="0664", dir_mode="0775", setgid_dirs=True, keep_exec=True,
                strip_acl=True, dry_run=False, backup=False)
        self.assertEqual(self.mode("a"), 0o2775)
        self.assertEqual(self.mode("a/f1"), 0o664)
        self.assertEqual(self.mode("a/x.sh"), 0o775)
        self.assertNotIn("nobody", self.acl("a/f1"))
        self.assertEqual(os.lstat(self.p("b/f2")).st_uid, 0)

    def test_dry_run_changes_nothing(self):
        before = self.mode("a")
        d = self.ok("reset", method="unix-mode", path=self.root, dir_mode="0700", dry_run=True)
        self.assertTrue(d["dry_run"])
        self.assertEqual(self.mode("a"), before)

    def test_orphans(self):
        self.ok("reset", method="orphans", path=self.root, owner="nobody", group="nogroup"
                if self._has_group("nogroup") else "root", dry_run=False, backup=False)
        self.assertEqual(os.lstat(self.p("b/f2")).st_uid, 65534)
        self.assertEqual(os.lstat(self.p("a/f1")).st_uid, 0)

    def test_inherit_parent(self):
        subprocess.run(["setfacl", "-d", "-m", "g:root:rwx,u::rwx,g::r-x,o::---", self.root], check=True)
        self.ok("reset", method="inherit-parent", path=self.root, dry_run=False, backup=False)
        self.assertIn("default:group:root:rwx", self.acl("a"))
        self.assertIn("group:root:rw-", self.acl("a/f1"))

    def test_template(self):
        self.ok("reset", method="acl-template", path=self.root, owner_perms="rwx", group_perms="rwx",
                other_perms="---", entries=[{"tag": "user", "qualifier": "nobody", "perms": "r-x"}],
                inherit=True, dry_run=False, backup=False)
        self.assertIn("default:user:nobody:r-x", self.acl("b"))
        self.assertIn("user:nobody:r--", self.acl("b/f2"))
        self.assertEqual(self.mode("b/f2") & 0o007, 0)

    def test_backup_and_restore(self):
        os.chmod(self.p("a/f1"), 0o640)
        d = self.ok("reset", method="unix-mode", path=self.root, file_mode="0600", dry_run=False, backup=True,
                    **{})
        backup_id = d["backup"]["id"]
        self.assertEqual(self.mode("a/f1"), 0o600)
        self.ok("reset", method="from-backup", path=self.root, backup_id=backup_id, dry_run=False)
        self.assertEqual(self.mode("a/f1"), 0o640)
        self.assertEqual(self.mode("a/x.sh"), 0o755)
        lst = self.ok("backups")
        self.assertIn(backup_id, [b["id"] for b in lst["backups"]])
        self.ok("delete-backup", id=backup_id)

    def test_from_snapshot(self):
        # faux snapshot : même arborescence sous .zfs/snapshot/s1 avec d'autres modes
        snap = os.path.join(self.root, ".zfs", "snapshot", "s1")
        os.makedirs(os.path.join(snap, "a"))
        open(os.path.join(snap, "a", "f1"), "w").close()
        os.makedirs(os.path.join(self.root, "a", "avec espace"))
        os.makedirs(os.path.join(snap, "a", "avec espace"))
        os.chmod(os.path.join(snap, "a", "f1"), 0o604)
        os.chmod(os.path.join(snap, "a", "avec espace"), 0o711)
        subprocess.run(["setfacl", "-m", "u:nobody:r--", os.path.join(snap, "a", "f1")], check=True)
        d = self.ok("reset", method="from-snapshot", path=self.p("a"), snapshot="tank/data@s1",
                    dry_run=False, backup=False)
        self.assertEqual(self.mode("a/f1") & 0o707, 0o604)
        self.assertIn("user:nobody:r--", self.acl("a/f1"))
        self.assertEqual(self.mode("a/avec espace"), 0o711)
        self.assertEqual(d["error_count"], 0, d["errors"])

    def test_clear_ntacl(self):
        os.setxattr(self.p("a/f1"), "security.NTACL", b"\x01")
        os.setxattr(self.p("a/f1"), "user.DOSATTRIB", b"\x01")
        self.ok("reset", method="clear-ntacl", path=self.root, dry_run=False, backup=False)
        x = os.listxattr(self.p("a/f1"))
        self.assertNotIn("security.NTACL", x)
        self.assertIn("user.DOSATTRIB", x)

    def test_mirror_reference(self):
        ref = os.path.join(self.tmp, "ref")
        os.makedirs(ref)
        os.chmod(ref, 0o750)
        self.ok("reset", method="mirror-reference", path=self.root, reference_dir=ref,
                types="dirs", dry_run=False, backup=False)
        self.assertEqual(self.mode("a"), 0o750)

    def test_exclude_glob_prunes(self):
        self.ok("reset", method="unix-mode", path=self.root, file_mode="0600", exclude=["b"],
                dry_run=False, backup=False)
        self.assertEqual(self.mode("a/f1"), 0o600)
        self.assertNotEqual(self.mode("b/f2"), 0o600)

    def test_refuse_write_on_root_and_snapshot(self):
        d = self.call("reset", method="unix-mode", path=os.path.join(self.root, ".zfs", "x"), dry_run=False)
        self.assertFalse(d["ok"])

    # ------------------------------------------------------------------ zfs allow
    def test_delegation_parse(self):
        d = self.ok("delegation", dataset="tank/data")
        e = d["entries"][0]
        self.assertEqual(e["sets"][0]["name"], "@backup")
        self.assertEqual(e["local"][0], {"type": "user", "who": "bob", "perms": ["create", "mount"]})
        self.assertEqual(e["both"][1]["type"], "everyone")
        self.assertEqual(e["create"][0]["perms"], ["destroy"])

    def test_delegate_command(self):
        d = self.ok("delegate", dataset="tank/data", kind="group", who="root", scope="descendent",
                    perms=["snapshot", "mount"], dry_run=True)
        self.assertEqual(d["command"], "zfs allow -d -g root snapshot,mount tank/data")

    def test_preset_plan(self):
        d = self.ok("preset", dataset="tank/data", preset="posixacl-smb", dry_run=True)
        self.assertEqual(d["commands"], ["zfs set dnodesize=auto tank/data"])

    @staticmethod
    def _has_group(name):
        import grp
        try:
            grp.getgrnam(name)
            return True
        except KeyError:
            return False


if __name__ == "__main__":
    unittest.main()
