"""Backup tests use synthetic files only; never access deployment defaults."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout


BACKUP_SCRIPT = Path(__file__).resolve().parents[1] / "deploy/backup.py"
spec = importlib.util.spec_from_file_location("namiya_deployment_backup", BACKUP_SCRIPT)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupTests(unittest.TestCase):
    def setUp(self):
        instance = Path(__file__).resolve().parents[1] / "instance"
        instance.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="backup-tests-", dir=instance)
        root = Path(self.directory.name)
        self.database = root / "synthetic.db"
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE synthetic (id INTEGER PRIMARY KEY, value TEXT)")
            connection.execute("INSERT INTO synthetic (value) VALUES (?)", ("synthetic backup row",))
        self.environment = root / "synthetic.env"
        self.environment.write_text("SECRET_KEY=synthetic-only\nMAIL_PASSWORD='ignore unclosed quoted value\n")
        self.key = root / "external keys" / "key #1.pem"
        self.key.parent.mkdir()
        self.key.write_bytes(b"synthetic private key bytes; not a real credential\n")
        self.key.chmod(0o600)
        self.release = root / "release"
        self.release.mkdir()
        (self.release / "app.txt").write_text("synthetic application content\n")
        self.backups = root / "backups"
        self.arguments = dict(database_path=self.database, environment_path=self.environment,
                              release_path=self.release, backup_root=self.backups)

    def tearDown(self):
        self.directory.cleanup()

    def configure_key(self, path=None):
        with self.environment.open("a") as output:
            output.write("PASSWORD_TRANSPORT_PRIVATE_KEY_FILE=" + shlex.quote(str(path or self.key)) + "\n")

    def snapshot(self):
        output = io.StringIO()
        with redirect_stdout(output):
            target = backup.backup_snapshot(**self.arguments)
        self.assertEqual(output.getvalue(), "")
        return target

    def test_external_key_database_config_and_release_are_complete_and_private(self):
        self.configure_key()
        # This function must be safe even when used outside the systemd UMask.
        previous = os.umask(0o022)
        try:
            target = self.snapshot()
        finally:
            os.umask(previous)
        self.assertEqual((target / "password-transport.pem").read_bytes(), self.key.read_bytes())
        self.assertEqual((target / "namiya.env").read_bytes(), self.environment.read_bytes())
        self.assertEqual((target / "release.txt").read_text().strip(), str(self.release.resolve()))
        self.assertTrue((target / "COMPLETE").is_file())
        for directory in (self.backups, target):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for entry in target.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600, entry.name)
        with sqlite3.connect(target / "worryshop.db") as connection:
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(connection.execute("SELECT value FROM synthetic").fetchone()[0], "synthetic backup row")
        with tarfile.open(target / "code.tar.gz") as archive:
            self.assertEqual(archive.extractfile("./app.txt").read(), b"synthetic application content\n")

    def test_missing_configured_key_never_creates_complete_marker(self):
        self.configure_key(self.key.with_name("does-not-exist.pem"))
        with self.assertRaisesRegex(RuntimeError, "private key is unavailable"):
            self.snapshot()
        snapshots = list(self.backups.iterdir())
        self.assertEqual(len(snapshots), 1)
        self.assertFalse((snapshots[0] / "COMPLETE").exists())

    def test_legacy_environment_without_key_still_completes(self):
        target = self.snapshot()
        self.assertTrue((target / "COMPLETE").is_file())
        self.assertFalse((target / "password-transport.pem").exists())

    def test_config_parser_reads_only_target_and_never_executes_shell(self):
        self.assertIsNone(backup.password_key_path("MAIL_PASSWORD='unclosed\n# PASSWORD_TRANSPORT_PRIVATE_KEY_FILE=/ignore\n"))
        self.assertEqual(backup.password_key_path("export PASSWORD_TRANSPORT_PRIVATE_KEY_FILE='/first'\n"
                                                 "PASSWORD_TRANSPORT_PRIVATE_KEY_FILE=\"/last path#literal\" # comment\n"),
                         Path("/last path#literal"))
        self.assertEqual(backup.password_key_path("PASSWORD_TRANSPORT_PRIVATE_KEY_FILE=/etc/key#literal.pem"),
                         Path("/etc/key#literal.pem"))
        for value in ("", '""', "relative/path.pem", "'unterminated"):
            with self.assertRaises(RuntimeError):
                backup.password_key_path("PASSWORD_TRANSPORT_PRIVATE_KEY_FILE=" + value)
        sentinel = Path(self.directory.name) / "must-not-exist"
        literal = "/tmp/$(touch " + str(sentinel) + ")"
        self.assertEqual(backup.password_key_path("PASSWORD_TRANSPORT_PRIVATE_KEY_FILE=" + shlex.quote(literal)), Path(literal))
        self.assertFalse(sentinel.exists())

    def test_symlink_key_fails_without_complete(self):
        link = self.key.with_name("symlink.pem")
        link.symlink_to(self.key)
        self.configure_key(link)
        with self.assertRaisesRegex(RuntimeError, "private key is unavailable"):
            self.snapshot()
        self.assertFalse(any(self.backups.glob("*/COMPLETE")))

    @unittest.skipUnless(Path("/usr/bin/python3").is_file(), "system Python unavailable")
    def test_system_python_runs_backup_without_application_dependencies(self):
        self.configure_key()
        program = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('backup', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
target = module.backup_snapshot(**json.loads(sys.argv[2]))
assert (target / 'COMPLETE').is_file()
assert (target / 'password-transport.pem').is_file()
assert not any(name in sys.modules for name in ('flask', 'cryptography', 'dotenv'))
print('stdlib backup passed')
"""
        arguments = json.dumps({key: str(value) for key, value in self.arguments.items()})
        result = subprocess.run(["/usr/bin/python3", "-I", "-S", "-c", program, str(BACKUP_SCRIPT), arguments],
                                capture_output=True, text=True, check=True, timeout=30)
        self.assertEqual(result.stdout.strip(), "stdlib backup passed")


if __name__ == "__main__":
    unittest.main()
