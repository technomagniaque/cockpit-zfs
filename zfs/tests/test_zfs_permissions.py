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
    child = os.environ.get("FAKE_CHILD")
    if args[0] == "list":
        print("tank\t-\tno")
        print("tank/data\t%s\tyes" % root)
        if child:
            print("tank/data/child\t%s\tyes" % child)
    elif args[0] == "get":
        mnt = child if (child and args[-1] == "tank/data/child") else root
        props = {"type": "filesystem", "mountpoint": mnt, "mounted": "yes", "readonly": "off",
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
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="zfsperm-"))
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
        for m in getattr(self, "mounts", []):
            subprocess.run(["umount", "-l", m], stderr=subprocess.DEVNULL)
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


    # ------------------------------------------------------------------ régressions de la revue
    def _outside(self):
        out = os.path.join(self.tmp, "outside")
        os.makedirs(out, exist_ok=True)
        victim = os.path.join(out, "shadow")
        with open(victim, "w") as f:
            f.write("secret")
        os.chmod(victim, 0o600)
        os.chown(victim, 0, 0)
        return out, victim

    def _victim_state(self, victim):
        st = os.lstat(victim)
        return stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, self.acl_abs(victim)

    def acl_abs(self, path):
        return subprocess.run(["getfacl", "-p", "-c", path], stdout=subprocess.PIPE, text=True).stdout

    def _swap_dir_for_link(self, rel, target):
        d = self.p(rel)
        shutil.rmtree(d)
        os.symlink(target, d)

    def test_backup_restore_through_symlinked_dir_stays_inside(self):
        out, victim = self._outside()
        os.makedirs(self.p("x"))
        with open(self.p("x/shadow"), "w"):
            pass
        os.chmod(self.p("x/shadow"), 0o666)
        os.chown(self.p("x/shadow"), 1234, 1234)
        d = self.ok("reset", method="clear-ntacl", path=self.root, dry_run=False, backup=True)
        before = self._victim_state(victim)
        self._swap_dir_for_link("x", out)
        r = self.ok("reset", method="from-backup", path=self.root, backup_id=d["backup"]["id"], dry_run=False)
        self.assertEqual(self._victim_state(victim), before)
        self.assertGreaterEqual(r["missing"], 1)

    def test_snapshot_restore_through_symlinked_dir_stays_inside(self):
        out, victim = self._outside()
        snap = os.path.join(self.root, ".zfs", "snapshot", "s1", "x")
        os.makedirs(snap)
        with open(os.path.join(snap, "shadow"), "w"):
            pass
        os.chmod(os.path.join(snap, "shadow"), 0o666)
        os.chown(os.path.join(snap, "shadow"), 1234, 1234)
        os.symlink(out, self.p("x"))
        before = self._victim_state(victim)
        self.ok("reset", method="from-snapshot", path=self.root, snapshot="s1", dry_run=False, backup=False)
        self.assertEqual(self._victim_state(victim), before)

    def _race_env(self, trigger, swap, target):
        self.env["COCKPIT_ZFS_PERM_TEST_RACE"] = json.dumps({"trigger": trigger, "swap": swap, "target": target})

    def test_race_dir_swapped_during_walk(self):
        out, victim = self._outside()
        os.makedirs(self.p("x"))
        open(self.p("x/shadow"), "w").close()
        before = self._victim_state(victim)
        for method, extra in (("acl-template", {"entries": [{"tag": "user", "qualifier": "nobody", "perms": "rw-"}], "other_perms": "rw-"}),
                              ("takeown", {"owner": "nobody"}),
                              ("unix-mode", {"file_mode": "4777", "owner": "nobody"})):
            if os.path.islink(self.p("x")):
                os.unlink(self.p("x"))
                os.rename(self.p("x.orig"), self.p("x"))
            for trigger in ("x", "x/shadow"):
                if os.path.islink(self.p("x")):
                    os.unlink(self.p("x"))
                    os.rename(self.p("x.orig"), self.p("x"))
                self._race_env(trigger, "x", out)
                self.ok("reset", method=method, path=self.root, dry_run=False, backup=False, **extra)
                self.assertEqual(self._victim_state(victim), before, (method, trigger))
        self.env.pop("COCKPIT_ZFS_PERM_TEST_RACE")

    def _mount_child(self):
        child = self.p("child")
        os.makedirs(child)
        r = subprocess.run(["mount", "-t", "tmpfs", "-o", "size=1m", "tmpfs", child], stderr=subprocess.PIPE)
        if r.returncode != 0:
            self.skipTest("montage tmpfs impossible : %s" % r.stderr.decode().strip())
        self.mounts = [child]
        os.chmod(child, 0o700)
        os.chown(child, 1234, 1234)
        open(os.path.join(child, "doc"), "w").close()
        os.chown(os.path.join(child, "doc"), 1234, 1234)
        self.env["FAKE_CHILD"] = child
        return child

    def test_child_dataset_not_touched(self):
        child = self._mount_child()
        snap = os.path.join(self.root, ".zfs", "snapshot", "s1")
        os.makedirs(os.path.join(snap, "child"))  # point de montage vide dans le snapshot
        os.makedirs(os.path.join(snap, "a"))
        self.ok("reset", method="from-snapshot", path=self.root, snapshot="s1", dry_run=False, backup=False)
        st = os.lstat(child)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid), (0o700, 1234))
        d = self.ok("reset", method="unix-mode", path=self.root, owner="root", dir_mode="0755", file_mode="0644",
                    dry_run=False, backup=True)
        self.assertEqual(os.lstat(child).st_uid, 1234)
        self.assertEqual(os.lstat(os.path.join(child, "doc")).st_uid, 1234)
        r = self.ok("reset", method="from-backup", path=self.root, backup_id=d["backup"]["id"], dry_run=True)
        self.assertFalse(any("child" in s["path"] for s in r["sample"]))
        # traversée explicite
        self.ok("reset", method="takeown", path=self.root, owner="root", cross_datasets=True, dry_run=False, backup=False)
        self.assertEqual(os.lstat(os.path.join(child, "doc")).st_uid, 0)

    def test_write_refused_on_symlinked_target(self):
        out, _victim = self._outside()
        os.symlink(out, self.p("Projets"))
        d = self.call("reset", method="unix-mode", path=self.p("Projets"), file_mode="0600", dry_run=True)
        self.assertFalse(d["ok"])
        self.assertIn("lien symbolique", d["error"])

    def test_write_refused_on_system_dataset(self):
        self.env["FAKE_ROOT"] = "/"
        d = self.call("reset", method="unix-mode", path="/etc", file_mode="0600", dry_run=True)
        self.assertFalse(d["ok"])

    def test_strip_keep_default_keeps_group_obj(self):
        f = self.p("a/f1")
        subprocess.run(["setfacl", "-m", "g::r-x,g:nogroup:rwx,m::rwx", f], check=True)
        subprocess.run(["setfacl", "-d", "-m", "g::r-x,g:nogroup:rwx", self.p("a")], check=True)
        self.ok("reset", method="strip-acl", path=self.root, keep_default=True, dry_run=False, backup=False)
        self.assertIn("group::r-x", self.acl("a/f1"))
        self.assertNotIn("mask", self.acl("a/f1"))
        self.assertEqual(self.mode("a/f1") & 0o070, 0o050)
        self.assertIn("default:group:nogroup:rwx", self.acl("a"))

    def test_mirror_reference_symlink_refused(self):
        ref = os.path.join(self.tmp, "ref")
        os.makedirs(ref)
        link = os.path.join(self.tmp, "reflink")
        os.symlink(ref, link)
        d = self.call("reset", method="mirror-reference", path=self.root, reference_dir=link, dry_run=True)
        self.assertFalse(d["ok"])

    def test_mirror_without_file_reference_uses_conditional_x(self):
        ref = os.path.join(self.tmp, "ref")
        os.makedirs(ref)
        os.chmod(ref, 0o750)
        self.ok("reset", method="mirror-reference", path=self.root, reference_dir=ref, dry_run=False, backup=False)
        self.assertEqual(self.mode("a"), 0o750)
        self.assertEqual(self.mode("a/f1"), 0o640)
        self.assertEqual(self.mode("a/x.sh"), 0o750)

    def test_latin1_names(self):
        snap = os.path.join(self.root, ".zfs", "snapshot", "s1")
        os.makedirs(snap)
        for base in (self.root, snap):
            p = os.path.join(base.encode(), b"caf\xe9")
            open(p, "w").close()
        os.chmod(os.path.join(snap.encode(), b"caf\xe9"), 0o604)
        live = os.path.join(self.root.encode(), b"caf\xe9")
        original = stat.S_IMODE(os.lstat(live).st_mode)
        out = subprocess.run([sys.executable, SCRIPT, "reset", json.dumps(
            {"method": "from-snapshot", "path": self.root, "snapshot": "s1", "dry_run": False, "backup": True})],
            stdout=subprocess.PIPE, env=self.env)
        out.stdout.decode("ascii")  # sortie ASCII pure
        d = json.loads(out.stdout)
        self.assertTrue(d["ok"], d)
        self.assertEqual(stat.S_IMODE(os.lstat(live).st_mode), 0o604)
        os.chmod(live, 0o600)
        self.ok("reset", method="from-backup", path=self.root, backup_id=d["backup"]["id"], dry_run=False)
        # la sauvegarde a été prise avant la restauration depuis le snapshot
        self.assertEqual(stat.S_IMODE(os.lstat(live).st_mode), original)

    def test_special_files_never_opened(self):
        import importlib.util
        os.mkfifo(self.p("a/fifo"))
        dev = self.p("a/null")
        try:
            os.mknod(dev, stat.S_IFCHR | 0o600, os.makedev(1, 3))
        except OSError:
            dev = None
        saved = dict(os.environ)
        os.environ.update(self.env)
        try:
            spec = importlib.util.spec_from_file_location("zp_test", SCRIPT)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            opened = []
            real_open = os.open

            def spy(path, *a, **kw):
                opened.append(path)
                return real_open(path, *a, **kw)
            os.open = spy
            try:
                mod.cmd_audit({"path": self.root})
                mod.cmd_reset({"method": "chattr-clear", "path": self.root, "dry_run": False, "backup": False})
                mod.cmd_inspect({"path": self.p("a")})
            finally:
                os.open = real_open
        finally:
            os.environ.clear()
            os.environ.update(saved)
        names = [os.path.basename(p) if isinstance(p, str) else p for p in opened]
        self.assertNotIn("fifo", names)
        if dev:
            self.assertNotIn("null", names)

    def test_setuid_kept_after_orphan_chown(self):
        os.chmod(self.p("b/f2"), 0o4755)
        self.ok("reset", method="orphans", path=self.root, owner="root", dry_run=False, backup=False)
        self.assertEqual(self.mode("b/f2"), 0o4755)
        self.assertEqual(os.lstat(self.p("b/f2")).st_uid, 0)

    def test_delegate_rejects_option_like_perm(self):
        d = self.call("delegate", dataset="tank/data", kind="user", who="root", perms=["-d"])
        self.assertFalse(d["ok"])
        d = self.ok("delegate", dataset="tank/data", kind="user", who="root", perms=["mount"])
        self.assertTrue(d["dry_run"])  # simulation par défaut

    def test_preset_posix_alias(self):
        self.env["FAKE_ACLTYPE"] = "posix"
        d = self.ok("preset", dataset="tank/data", preset="posixacl-smb", dry_run=True)
        self.assertNotIn("acltype", " ".join(d["commands"]))

    def test_set_acl_remove_requires_named_entry(self):
        d = self.call("set-acl", path=self.root, action="remove", access=[{"tag": "other", "qualifier": "", "perms": "---"}], dry_run=True)
        self.assertFalse(d["ok"])

    def test_backup_ids_unique(self):
        ids = {self.ok("reset", method="clear-ntacl", path=self.root, dry_run=False, backup=True)["backup"]["id"] for _ in range(3)}
        self.assertEqual(len(ids), 3)

    def test_set_acl_backup_and_restore(self):
        entry = [{"tag": "user", "qualifier": "nobody", "perms": "rwx"}]
        d = self.ok("set-acl", path=self.root, recursive=True, action="modify", access=entry, default=[], dry_run=False, backup=True)
        self.assertIn("user:nobody", self.acl("a/f1"))
        self.ok("reset", method="from-backup", path=self.root, backup_id=d["backup"]["id"], dry_run=False)
        self.assertNotIn("user:nobody", self.acl("a/f1"))

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


# --------------------------------------------------------------------------- NFSv4 (traduction knfsd)

def _load_backend():
    import importlib.util
    spec = importlib.util.spec_from_file_location("zfs_permissions_backend", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ZP = _load_backend()
U_OBJ, U, G_OBJ, G, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def view(acl, default=None, is_dir=False, numeric=True):
    return ZP.nfs4_render(ZP.nfs4_view(acl, default or [], is_dir), is_dir, numeric=numeric)


class Nfs4TranslationTest(unittest.TestCase):
    """Cas dérivés de fs/nfsd/nfs4acl.c (_posix_to_nfsv4_one, nfs4_acl_nfsv4_to_posix)."""

    def test_mode_seul_fichier(self):
        self.assertEqual(view(ZP.base_from_mode(0o644)),
                         ["A::OWNER@:rwatTcCy", "A::GROUP@:rtcy", "A::EVERYONE@:rtcy"])

    def test_mode_seul_dossier_delete_child(self):
        self.assertEqual(view(ZP.base_from_mode(0o755), is_dir=True),
                         ["A::OWNER@:rwaDxtTcCy", "A::GROUP@:rxtcy", "A::EVERYONE@:rxtcy"])

    def test_deny_owner_et_group(self):
        # propriétaire r--, groupe rwx : DENY OWNER@ des bits accordés plus loin
        self.assertEqual(view(ZP.base_from_mode(0o477)),
                         ["D::OWNER@:wax", "A::OWNER@:rtTcCy", "A::GROUP@:rwaxtcy", "A::EVERYONE@:rwaxtcy"])
        # autres rwx, groupe --- : DENY GROUP@ après les ALLOW de groupe
        self.assertEqual(view(ZP.base_from_mode(0o707)),
                         ["A::OWNER@:rwaxtTcCy", "A::GROUP@:tcy", "D::GROUP@:rwax", "A::EVERYONE@:rwaxtcy"])

    def test_masque_restrictif_et_nommes(self):
        acl = [(U_OBJ, 7, None), (U, 7, 1001), (G_OBJ, 7, None), (G, 6, 2001), (MASK, 5, None), (OTHER, 0, None)]
        self.assertEqual(view(acl), [
            "A::OWNER@:rwaxtTcCy",
            "A::1001:rxtcy",          # rwx borné par le masque r-x
            "A::GROUP@:rxtcy",
            "A:g:2001:rtcy",          # rw- & r-x = r--
            "A::EVERYONE@:tcy",
        ])
        notes = ZP.nfs4_explain(acl, [], False)
        self.assertTrue(any("masque" in n for n in notes))

    def test_nomme_moins_que_autres_genere_deny(self):
        acl = [(U_OBJ, 7, None), (U, 0, 1001), (G_OBJ, 5, None), (MASK, 5, None), (OTHER, 4, None)]
        self.assertEqual(view(acl), [
            "A::OWNER@:rwaxtTcCy", "D::1001:rx", "A::1001:tcy", "A::GROUP@:rxtcy", "A::EVERYONE@:rtcy"])

    def test_acl_par_defaut_dossier(self):
        acc = ZP.base_from_mode(0o750)
        dfl = [(U_OBJ, 7, None), (G_OBJ, 5, None), (G, 7, 0), (MASK, 7, None), (OTHER, 0, None)]
        self.assertEqual(view(acc, dfl, is_dir=True), [
            "A::OWNER@:rwaDxtTcCy", "A::GROUP@:rxtcy", "A::EVERYONE@:tcy",
            "A:fdi:OWNER@:rwaDxtTcCy", "A:fdi:GROUP@:rxtcy", "A:fdig:0:rwaDxtcy", "A:fdi:EVERYONE@:tcy"])
        # l'ACL par défaut n'existe pas pour un fichier
        self.assertEqual(len(view(acc, dfl, is_dir=False)), 3)

    def test_nom_avec_domaine(self):
        acl = [(U_OBJ, 7, None), (U, 7, 0), (G_OBJ, 7, None), (MASK, 7, None), (OTHER, 0, None)]
        dom = ZP.idmap_info()["domain"]
        self.assertIn("A::root@%s:rwaxtcy" % dom, view(acl, numeric=False))

    # ---- sens inverse
    def test_nfs4_vers_posix_simple(self):
        r = ZP.nfs4_to_posix("A::OWNER@:rwatTcCy A::GROUP@:rtcy A::EVERYONE@:tcy", False)
        self.assertTrue(r["representable"])
        self.assertEqual(r["mode"], "0640")
        self.assertEqual(r["readback"], ["A::OWNER@:rwatTcCy", "A::GROUP@:rtcy", "A::EVERYONE@:tcy"])

    def test_ecriture_pessimiste(self):
        # w sans a : pas d'écriture POSIX (low_mode_from_nfs4)
        r = ZP.nfs4_to_posix("A::OWNER@:rw A::GROUP@: A::EVERYONE@:", False)
        self.assertEqual(r["mode"], "0400")
        self.assertTrue(any("pessimiste" in n for n in r["notes"]))
        # sur un dossier, il faut aussi D
        self.assertEqual(ZP.nfs4_to_posix("A::OWNER@:rwax", True)["mode"], "0500")
        self.assertEqual(ZP.nfs4_to_posix("A::OWNER@:rwaDx", True)["mode"], "0700")

    def test_deny_avant_allow(self):
        # DENY puis ALLOW du même bit : refusé (allow_bits ignore les bits déjà refusés)
        r = ZP.nfs4_to_posix("D::EVERYONE@:w A::EVERYONE@:rwa", False)
        self.assertEqual(r["mode"], "0444")
        # DENY d'un groupe nommé : propagé au propriétaire et aux autres entrées
        r = ZP.nfs4_to_posix("A::OWNER@:rwa D:g:root:w A::EVERYONE@:r", False)
        self.assertEqual(r["access"][0], {"tag": "user", "qualifier": "", "perms": "rw-"})

    def test_nomme_herite_de_everyone(self):
        # find_uid() : un nommé vu après EVERYONE@ part des bits déjà accordés à tout le monde
        r = ZP.nfs4_to_posix("A::OWNER@:rwa A::EVERYONE@:r A::root:wa", False)
        self.assertIn({"tag": "user", "qualifier": "root", "perms": "rw-"}, r["access"])
        self.assertIn({"tag": "mask", "qualifier": "", "perms": "rw-"}, r["access"])

    def test_defaut_complete_par_effectif(self):
        r = ZP.nfs4_to_posix("A::OWNER@:rwaDx A::GROUP@:rx A::EVERYONE@: A:fdi:OWNER@:rwaDx", True)
        self.assertEqual(r["default"], [{"tag": "user", "qualifier": "", "perms": "rwx"},
                                        {"tag": "group", "qualifier": "", "perms": "r-x"},
                                        {"tag": "other", "qualifier": "", "perms": "---"}])

    def test_einval(self):
        self.assertIn("ATTRNOTSUPP", ZP.nfs4_to_posix("U::EVERYONE@:r", False)["error"])
        self.assertIn("ATTRNOTSUPP", ZP.nfs4_to_posix("A:S:OWNER@:r", True)["error"])
        self.assertIn("ATTRNOTSUPP", ZP.nfs4_to_posix("A:n:OWNER@:r", True)["error"])
        # client autre que nfs4_setfacl : héritage sur un fichier → EINVAL
        self.assertIn("fichier", ZP.nfs4_to_posix("A:fd:OWNER@:r", False, client_filter=False)["error"])
        # nfs4_setfacl retire lui-même f/d/i et D sur un fichier
        r = ZP.nfs4_to_posix("A:fd:OWNER@:rwaD", False)
        self.assertTrue(r["representable"])
        self.assertTrue(any("retire" in n for n in r["notes"]))

    def test_principal_inconnu(self):
        with self.assertRaises(ZP.PermError):
            ZP.nfs4_to_posix("A::utilisateur-inexistant-xyz@dom:r", False)

    def test_aliases_et_drapeau_p(self):
        a = ZP.parse_nfs4_text("A::OWNER@:R,A::OWNER@:W,A::OWNER@:X", is_dir=True)
        self.assertEqual([x["mask"] for x in a], [0x120089, 0x1601d6, 0x1200a0])
        with self.assertRaises(ZP.PermError):
            ZP.parse_nfs4_text("A:p:OWNER@:r")


SHIM_C = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
static ssize_t rd(void *v, size_t size) {
  const char *p = getenv("NFS4_XDR_IN"); FILE *f; char b[65536]; size_t n;
  if (!p || !(f = fopen(p, "rb"))) { errno = ENODATA; return -1; }
  n = fread(b, 1, sizeof b, f); fclose(f);
  if (!size) return n; if (size < n) { errno = ERANGE; return -1; } memcpy(v, b, n); return n; }
ssize_t getxattr(const char *p, const char *n, void *v, size_t s) {
  if (strcmp(n, "system.nfs4_acl")) { errno = ENODATA; return -1; } return rd(v, s); }
ssize_t lgetxattr(const char *p, const char *n, void *v, size_t s) { return getxattr(p, n, v, s); }
int setxattr(const char *p, const char *n, const void *v, size_t s, int fl) {
  const char *o = getenv("NFS4_XDR_OUT"); FILE *f; if (!o) return 0;
  f = fopen(o, "wb"); fwrite(v, 1, s, f); fclose(f); return 0; }
int lsetxattr(const char *p, const char *n, const void *v, size_t s, int fl) { return setxattr(p, n, v, s, fl); }
"""


@unittest.skipUnless(shutil.which("nfs4_getfacl") and shutil.which("gcc"), "nfs4-acl-tools + gcc requis")
class Nfs4ToolsReferenceTest(unittest.TestCase):
    """Compare le rendu et l'analyse avec les vrais nfs4_getfacl / nfs4_setfacl, via un
    LD_PRELOAD qui remplace l'xattr system.nfs4_acl par un fichier XDR."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="nfs4ref-")
        src = os.path.join(cls.tmp, "shim.c")
        with open(src, "w") as f:
            f.write(SHIM_C)
        cls.shim = os.path.join(cls.tmp, "shim.so")
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", cls.shim, src], check=True)
        os.makedirs(os.path.join(cls.tmp, "d"))
        open(os.path.join(cls.tmp, "f"), "w").close()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def xdr(aces):
        import struct
        out = struct.pack(">I", len(aces))
        for a in aces:
            who = (ZP.nfs4_principal(a, numeric=True)).encode()
            out += struct.pack(">III", a["type"], a["flag"], a["mask"]) + struct.pack(">I", len(who)) \
                + who + b"\0" * ((4 - len(who) % 4) % 4)
        return out

    @staticmethod
    def unxdr(data):
        import struct
        n = struct.unpack(">I", data[:4])[0]
        o, out = 4, []
        for _ in range(n):
            t, fl, m = struct.unpack(">III", data[o:o + 12])
            o += 12
            ln = struct.unpack(">I", data[o:o + 4])[0]
            o += 4
            out.append((t, fl, m, data[o:o + ln].decode()))
            o += ln + (4 - ln % 4) % 4
        return out

    def env(self, **kw):
        return dict(os.environ, LD_PRELOAD=self.shim, **kw)

    def test_rendu_identique_a_nfs4_getfacl(self):
        cases = [
            (ZP.base_from_mode(0o644), [], False),
            (ZP.base_from_mode(0o477), [], False),
            (ZP.base_from_mode(0o2775), [(U_OBJ, 7, None), (G_OBJ, 7, None), (G, 5, 0), (MASK, 7, None), (OTHER, 5, None)], True),
            ([(U_OBJ, 7, None), (U, 1, 1001), (G_OBJ, 6, None), (G, 7, 2001), (MASK, 6, None), (OTHER, 4, None)], [], True),
        ]
        for acc, dfl, is_dir in cases:
            aces = ZP.nfs4_view(acc, dfl, is_dir)
            path = os.path.join(self.tmp, "in.xdr")
            with open(path, "wb") as f:
                f.write(self.xdr(aces))
            out = subprocess.run(["nfs4_getfacl", os.path.join(self.tmp, "d" if is_dir else "f")],
                                 env=self.env(NFS4_XDR_IN=path), capture_output=True, text=True).stdout
            lines = [l for l in out.splitlines() if l and not l.startswith("#")]
            self.assertEqual(lines, ZP.nfs4_render(aces, is_dir, numeric=True))

    def test_analyse_identique_a_nfs4_setfacl(self):
        empty = os.path.join(self.tmp, "empty.xdr")
        with open(empty, "wb") as f:
            f.write(b"\0\0\0\0")
        for target, is_dir in (("d", True), ("f", False)):
            for text in ("A::OWNER@:rwaDdxtTnNcCoy", "A:fdig:1000:R", "D::EVERYONE@:W", "A:n:OWNER@:X",
                         "A:fdi:OWNER@:rwaD", "A:S:GROUP@:r"):
                out = os.path.join(self.tmp, "out.xdr")
                if os.path.exists(out):
                    os.unlink(out)
                subprocess.run(["nfs4_setfacl", "-s", text, os.path.join(self.tmp, target)],
                               env=self.env(NFS4_XDR_IN=empty, NFS4_XDR_OUT=out), capture_output=True)
                with open(out, "rb") as f:
                    ref = self.unxdr(f.read())
                mine = [(a["type"], a["flag"], a["mask"], a["principal"])
                        for a in ZP.parse_nfs4_text(text, is_dir=is_dir)]
                self.assertEqual(mine, ref, (target, text))


class _Nfs4CommandTests:
    """Tests de commandes NFSv4, greffés sur PermissionsTest (même banc d'essai,
    sans réexécuter les tests hérités)."""

    def test_inspect_vue_nfs4(self):
        subprocess.run(["setfacl", "-m", "u:nobody:rwx,m::r-x", self.p("a/f1")], check=True)
        d = self.ok("inspect", path=self.p("a/f1"))
        v = d["nfs4_view"]
        self.assertIn("A::65534:rxtcy", v["numeric_text"])
        self.assertTrue(any("masque" in n for n in v["notes"]))
        parent = self.ok("inspect", path=self.p("a"))
        child = [c for c in parent["children"] if c["path"].endswith("/f1")][0]
        # propriétaire rw-, nommé r-x effectif : knfsd commence par DENY OWNER@ x
        self.assertEqual(child["nfs4_text"][:2], ["D::OWNER@:x", "A::OWNER@:rwatTcCy"])

    def test_audit_nfs4(self):
        os.chmod(self.p("a/f1"), 0o477)
        subprocess.run(["setfacl", "-m", "u:12345:rwx,m::r--", self.p("a/x.sh")], check=True)
        d = self.ok("audit", path=self.root)
        self.assertGreaterEqual(d["counts"]["nfs4_deny"], 1)
        self.assertIn(self.p("a/f1"), d["findings"]["nfs4_deny"])
        self.assertIn(self.p("a/x.sh"), d["findings"]["nfs4_over_mask"])
        self.assertIn(self.p("a/x.sh"), d["findings"]["nfs4_unnamed_principal"])
        self.assertIn("domain", d["nfs4"])
        self.assertFalse(d["nfs4"]["native"]["supported"])

    def test_translate(self):
        d = self.ok("nfs4-translate", acl="A::OWNER@:rwatTcCy,A::GROUP@:rtcy,A::EVERYONE@:", path=self.p("a/f1"))
        self.assertTrue(d["representable"])
        self.assertFalse(d["is_dir"])
        self.assertEqual(d["mode"], "0640")
        d = self.ok("nfs4-translate", acl="L::EVERYONE@:r", is_dir=True)
        self.assertFalse(d["representable"])

    def test_preset_nfsv4(self):
        d = self.ok("preset", dataset="tank/data", preset="nfsv4-posix", dry_run=True)
        self.assertEqual(d["commands"], ["zfs set dnodesize=auto tank/data"])
        d = self.ok("preset", dataset="tank/data", preset="nfsv4", dry_run=True)
        self.assertTrue(any("acltype=off" in n for n in d["notes"]))
        d = self.call("preset", dataset="tank/data", preset="nfsv4", dry_run=False)
        self.assertFalse(d["ok"])


for _name, _fn in list(vars(_Nfs4CommandTests).items()):
    if _name.startswith("test_"):
        setattr(PermissionsTest, _name, _fn)

class _Nfs4ReviewTests:
    """Corrections de la revue NFSv4 (greffées sur PermissionsTest)."""

    def test_translate_default_inchangee(self):
        # dossier avec ACL par défaut existante ; ACL envoyée sans ACE héritable
        subprocess.run(["setfacl", "-d", "-m", "u:nobody:rwx", self.p("a")], check=True)
        d = self.ok("nfs4-translate", acl="A::OWNER@:rwaDxtTcCy,A::GROUP@:rxtcy,A::EVERYONE@:rxtcy",
                    path=self.p("a"))
        self.assertTrue(d["representable"])
        self.assertTrue(d["default_unchanged"])
        self.assertIsNone(d["default"])
        self.assertTrue(any("INCHANGÉE" in n for n in d["notes"]))
        # la relecture inclut l'ACL par défaut actuelle (ACE d'héritage)
        self.assertTrue(any(":fdi:" in t for t in d["readback"]), d["readback"])

    def test_native_support_ignore_dataset_nfsv4(self):
        self.env["FAKE_ACLTYPE"] = "nfsv4"
        d = self.ok("nfsv4-support")
        self.assertFalse(d["supported"])
        self.assertIn("acltype=off", d["message"])

    def test_inspect_sans_acl_posix(self):
        self.env["FAKE_ACLTYPE"] = "off"
        d = self.ok("inspect", path=self.p("a"))
        self.assertTrue(d["nfs4_view"]["unsupported"])
        self.assertEqual(d["nfs4_view"]["text"], [])
        self.assertIn("ATTRNOTSUPP", d["nfs4_view"]["message"])
        self.assertFalse(d["nfs3_view"]["posix_fs"])
        self.assertTrue(any("EOPNOTSUPP" in n for n in d["nfs3_view"]["notes"]))
        self.assertNotIn("nfs4_text", d["children"][0])

    def test_principal_numerique_strict(self):
        for bad in ("²", "4294967295", "12345678901"):
            d = self.ok("nfs4-translate", acl="A::%s:r,A::OWNER@:rw,A::GROUP@:r,A::EVERYONE@:" % bad, is_dir=False)
            self.assertFalse(d["representable"], bad)
            self.assertIn("BADOWNER", d["error"])
        d = self.ok("nfs4-translate", acl="A::OWNER@:rw,A::GROUP@:r,A::EVERYONE@:,A::1234:r", is_dir=False)
        self.assertTrue(any("nfs4_disable_idmapping" in n for n in d["notes"]))
        d = self.ok("nfs4-translate", acl="A::OWNER@:rw,A::GROUP@:r,A::EVERYONE@:,A::root:r", is_dir=False)
        self.assertTrue(any("sans @domaine" in n for n in d["notes"]))

    def test_badowner_avant_einval(self):
        # principal inconnu ET drapeau d'héritage sur un fichier : BADOWNER d'abord (décodage XDR)
        d = self.ok("nfs4-translate", acl="A:fd:inconnu-xyz@x:r", is_dir=False, client="autre")
        self.assertFalse(d["representable"])
        self.assertIn("BADOWNER", d["error"])

    def test_mode_conserve_bits_speciaux(self):
        os.chmod(self.p("a"), 0o2775)
        d = self.ok("nfs4-translate", acl="A::OWNER@:rwaDxtTcCy,A::GROUP@:rxtcy,A::EVERYONE@:", path=self.p("a"))
        self.assertEqual(d["mode"], "2750")

    def test_inspect_vue_nfs3(self):
        d = self.ok("inspect", path=self.p("a/f1"))
        v = d["nfs3_view"]
        self.assertEqual(v["text"], ["user::rw-", "group::r--", "mask::r--", "other::r--"])
        self.assertEqual(v["entries_access"], 3)
        self.assertFalse(v["over_limit"])
        subprocess.run(["setfacl", "-m", "u:nobody:rwx", self.p("a/f1")], check=True)
        v = self.ok("inspect", path=self.p("a/f1"))["nfs3_view"]
        self.assertIn("user:65534:rwx", v["numeric_text"])

    def test_principal_sans_nom_devient_nobody(self):
        subprocess.run(["setfacl", "-m", "u:54321:r", self.p("a/f1")], check=True)
        d = self.ok("inspect", path=self.p("a/f1"))
        self.assertTrue(any(":nobody@" in t for t in d["nfs4_view"]["text"]), d["nfs4_view"]["text"])
        self.assertTrue(any(":54321:" in t for t in d["nfs4_view"]["numeric_text"]))


for _name, _fn in list(vars(_Nfs4ReviewTests).items()):
    if _name.startswith("test_"):
        setattr(PermissionsTest, _name, _fn)


FAKE_ZFS_NFS = textwrap.dedent(r"""
    #!/usr/bin/env python3
    import json, os, sys
    ds = json.load(open(os.environ["FAKE_DATASETS"]))
    args = sys.argv[1:]
    with open(os.environ["FAKE_LOG"], "a") as f:
        f.write(" ".join(args) + "\n")
    def sel(name):
        return [d for d in ds if d["name"] == name or d["name"].startswith(name + "/")]
    if args[0] == "list":
        if "-r" in args:
            for d in sel(args[-1]):
                print("\t".join([d["name"], d["mountpoint"], d.get("mounted", "yes"), d.get("sharenfs", "off"),
                                 d.get("acltype", "posix"), d.get("xattr", "sa"), str(d.get("guid", 1))]))
        else:
            for d in ds:
                print("%s\t%s\t%s" % (d["name"], d["mountpoint"], d.get("mounted", "yes")))
    elif args[0] == "get":
        if "sharenfs" in args and "-r" in args:
            for d in sel(args[-1]):
                print("%s\t%s\t%s" % (d["name"], d.get("sharenfs", "off"), d.get("src", "default")))
        else:
            d = [x for x in ds if x["name"] == args[-1]][0]
            props = {"type": "filesystem", "mountpoint": d["mountpoint"], "mounted": "yes", "readonly": "off",
                     "acltype": d.get("acltype", "posix"), "aclmode": "discard", "aclinherit": "restricted",
                     "xattr": d.get("xattr", "sa"), "dnodesize": "legacy", "casesensitivity": "sensitive",
                     "normalization": "none", "utf8only": "off"}
            for p in args[args.index("property,value,source") + 1].split(","):
                print("%s\t%s\tdefault" % (p, props[p]))
    elif args[0] in ("set", "inherit"):
        pass
    else:
        sys.exit(1)
""").lstrip()


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("setfacl"), "root + paquet acl requis")
class NfsDatasetsTest(unittest.TestCase):
    """Sous-onglet NFS : NFSv3 + NFSv4.1 sur tous les datasets, exports, sharenfs."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="zfsnfs-"))
        self.root = os.path.join(self.tmp, "tank")
        for d in ("", "child", "child2", "child2/sub dir"):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        with open(os.path.join(self.bin, "zfs"), "w") as f:
            f.write(FAKE_ZFS_NFS)
        os.chmod(os.path.join(self.bin, "zfs"), 0o755)
        self.exports = os.path.join(self.tmp, "exports")
        self.exports_d = os.path.join(self.tmp, "exports.d")
        os.makedirs(self.exports_d)
        self.log = os.path.join(self.tmp, "zfs.log")
        self.dsfile = os.path.join(self.tmp, "ds.json")
        self.env = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], FAKE_LOG=self.log,
                        FAKE_DATASETS=self.dsfile, COCKPIT_ZFS_EXPORTS=self.exports,
                        COCKPIT_ZFS_EXPORTS_D=self.exports_d,
                        COCKPIT_ZFS_PERM_BACKUP_DIR=os.path.join(self.tmp, "backups"))
        self.set_datasets([
            {"name": "tank/data", "mountpoint": self.root, "guid": 1111},
            {"name": "tank/data/child", "mountpoint": self.p("child"), "guid": 2222},
            {"name": "tank/data/child2", "mountpoint": self.p("child2"), "guid": 3333},
            {"name": "tank/data/child2/sub", "mountpoint": self.p("child2/sub dir"), "guid": 4444},
        ])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, rel):
        return os.path.join(self.root, rel)

    def set_datasets(self, ds):
        with open(self.dsfile, "w") as f:
            json.dump(ds, f)

    def write_exports(self, text, name=None):
        with open(os.path.join(self.exports_d, name) if name else self.exports, "w") as f:
            f.write(text)

    def call(self, cmd, **params):
        out = subprocess.run([sys.executable, SCRIPT, cmd, json.dumps(params)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def ok(self, cmd, **params):
        d = self.call(cmd, **params)
        self.assertTrue(d["ok"], d)
        return d

    def readlog(self):
        if not os.path.exists(self.log):
            return ""
        with open(self.log) as f:
            return f.read()

    def ds(self, d, name):
        return [x for x in d["datasets"] if x["name"] == name][0]

    def codes(self, d, name):
        return {f["code"] for f in self.ds(d, name)["findings"]}

    def test_enfant_non_exporte_et_montage_v3(self):
        self.write_exports("%s 10.0.0.0/24(rw,sync,fsid=1)\n%s 10.0.0.0/24(rw,fsid=2)\n" % (self.root, self.p("child2")))
        d = self.ok("nfs-datasets", dataset="tank/data")
        self.assertIn("hidden_child", self.codes(d, "tank/data/child"))
        self.assertFalse(self.ds(d, "tank/data/child")["compat"]["v3"])
        self.assertIn("v3_mount_separately", self.codes(d, "tank/data/child2"))
        self.assertTrue(self.ds(d, "tank/data/child2")["compat"]["v41"])
        self.assertTrue(self.ds(d, "tank/data")["compat"]["v3"])
        # sous-dataset dont le chemin contient une espace : enfant de child2, non exporté
        self.assertIn("hidden_child", self.codes(d, "tank/data/child2/sub"))

    def test_crossmnt_parent(self):
        self.write_exports("%s *(rw,crossmnt,fsid=1)\n" % self.root)
        d = self.ok("nfs-datasets", dataset="tank/data")
        self.assertIn("implicit_child", self.codes(d, "tank/data/child"))

    def test_doublon_sharenfs_et_exports(self):
        self.set_datasets([{"name": "tank/data", "mountpoint": self.root, "sharenfs": "rw=@10.0.0.0/24",
                            "src": "local", "guid": 1}])
        self.write_exports("%s 10.0.0.0/24(rw)\n" % self.root)
        d = self.ok("nfs-datasets", dataset="tank/data")
        self.assertIn("duplicate", self.codes(d, "tank/data"))

    def test_fsid_doublon_et_herite(self):
        self.write_exports("%s *(rw,fsid=7)\n%s *(rw,fsid=7)\n" % (self.root, self.p("child")))
        d = self.ok("nfs-datasets", dataset="tank/data")
        self.assertIn("fsid_duplicate", self.codes(d, "tank/data/child"))
        self.set_datasets([
            {"name": "tank/data", "mountpoint": self.root, "sharenfs": "rw=@10.0.0.0/24,fsid=9", "src": "local"},
            {"name": "tank/data/child", "mountpoint": self.p("child"), "sharenfs": "rw=@10.0.0.0/24,fsid=9",
             "src": "inherited from tank/data"}])
        self.write_exports("")
        d = self.ok("nfs-datasets", dataset="tank/data")
        self.assertIn("fsid_inherited", self.codes(d, "tank/data/child"))
        self.assertIn("sharenfs_inherited", self.codes(d, "tank/data/child"))

    def test_acltype_off_et_monde(self):
        self.set_datasets([{"name": "tank/data", "mountpoint": self.root, "acltype": "off", "sharenfs": "on",
                            "src": "local"}])
        d = self.ok("nfs-datasets", dataset="tank/data")
        c = self.codes(d, "tank/data")
        self.assertIn("no_posix_acl", c)
        self.assertIn("world", c)
        self.assertFalse(self.ds(d, "tank/data")["compat"]["v3"])

    def test_generer_exports(self):
        self.write_exports("%s 10.0.0.0/24(rw,fsid=1)\n" % self.root)
        with open(self.exports) as f:
            before = f.read()
        d = self.ok("nfs-generate", dataset="tank/data", clients=["10.0.0.0/24"], format="exports")
        names = [l["name"] for l in d["lines"]]
        self.assertEqual(names, ["tank/data/child", "tank/data/child2", "tank/data/child2/sub"])
        line = [l["line"] for l in d["lines"] if l["name"] == "tank/data/child2/sub"][0]
        self.assertIn("sub\\040dir 10.0.0.0/24(rw,sync,no_subtree_check,sec=sys,fsid=", line)
        self.assertIn("fsid=00000000-0000-0000-0000-00000000115c", line)   # 4444 = 0x115c
        with open(self.exports) as f:
            self.assertEqual(f.read(), before)   # rien n'est écrit
        # les lignes générées, une fois ajoutées, rendent tout compatible
        self.write_exports(before + d["text"] + "\n")
        d2 = self.ok("nfs-datasets", dataset="tank/data")
        self.assertTrue(all(x["compat"]["v3"] and x["compat"]["v41"] for x in d2["datasets"]),
                        [(x["name"], x["findings"]) for x in d2["datasets"]])

    def test_generer_sharenfs(self):
        d = self.ok("nfs-generate", dataset="tank/data", clients=["10.0.0.0/24", "hote1"], format="sharenfs")
        cmd = [c for c in d["commands"] if c["name"] == "tank/data"][0]
        self.assertEqual(cmd["value"], "rw=@10.0.0.0/24:hote1,sync,no_subtree_check,sec=sys")
        d = self.call("nfs-generate", dataset="tank/data", clients=["a;b"], format="exports")
        self.assertFalse(d["ok"])
        d = self.call("nfs-generate", dataset="tank/data", clients=["*"], options="rw,fsid=3")
        self.assertFalse(d["ok"])

    def test_edition_sharenfs(self):
        d = self.ok("nfs-sharenfs", dataset="tank/data/child", value="rw=@10.0.0.0/24,crossmnt")
        self.assertTrue(d["dry_run"])
        self.assertEqual(d["command"], "zfs set sharenfs=rw=@10.0.0.0/24,crossmnt tank/data/child")
        self.assertNotIn("set", self.readlog())
        for bad in ("rw;id", "rw\nro", "-d", "rw,bogus", "rw ro"):
            self.assertFalse(self.call("nfs-sharenfs", dataset="tank/data/child", value=bad)["ok"], bad)
        self.write_exports("%s *(rw)\n" % self.p("child"))
        self.assertFalse(self.call("nfs-sharenfs", dataset="tank/data/child", value="on")["ok"])
        self.ok("nfs-sharenfs", dataset="tank/data/child", value="on", force=True, dry_run=False)
        self.assertIn("set sharenfs=on tank/data/child", self.readlog())
        self.ok("nfs-sharenfs", dataset="tank/data/child", op="inherit", dry_run=False)
        self.assertIn("inherit sharenfs tank/data/child", self.readlog())
        self.assertFalse(self.call("nfs-sharenfs", dataset="-r tank", value="on")["ok"])
        self.assertFalse(self.call("nfs-datasets", dataset="-r")["ok"])
        self.assertFalse(self.call("nfs-generate", dataset="-r", clients=["*"])["ok"])

    def test_parse_exports(self):
        e = ZP.parse_exports_text('/a\\040b host1(rw,sync) -ro \\\n  host2 "/q x" (rw)\n# c\n/z (rw)\n', "/etc/exports")
        self.assertEqual(e[0]["path"], "/a b")
        self.assertEqual(e[0]["clients"][1], {"host": "host2", "options": ["ro"]})
        self.assertEqual(e[1]["clients"][0]["host"], "*")
        self.assertTrue(e[1]["notes"])


if __name__ == "__main__":
    unittest.main()
