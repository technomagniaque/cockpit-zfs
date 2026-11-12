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


if __name__ == "__main__":
    unittest.main()
