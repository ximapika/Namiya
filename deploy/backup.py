"""Root-only online SQLite backup, including external password transport keys.

Keep this module standard-library-only: the systemd unit uses /usr/bin/python3,
not the application's virtual environment. Environment values are never run as
shell commands or expanded, and no secret values are printed.
"""
from contextlib import closing, contextmanager
import os
import re
import shlex
import sqlite3
import stat
import tarfile
from datetime import datetime, timezone
from pathlib import Path


KEY_SETTING = "PASSWORD_TRANSPORT_PRIVATE_KEY_FILE"


def password_key_path(environment_text):
    """Read only the key-file setting; support plain or shell-quoted paths.

    Missing settings allow old snapshots to remain usable. A present but empty
    or malformed setting must fail instead of reporting a key-less backup as
    complete. Last assignment wins, matching an EnvironmentFile.
    """
    configured = None
    found = False
    pattern = re.compile(r"^\s*(?:export\s+)?" + KEY_SETTING + r"\s*=\s*(.*)$")
    for line in environment_text.splitlines():
        match = pattern.match(line)
        if match:
            found = True
            configured = match.group(1)
    if not found:
        return None
    try:
        # A '#' inside an unquoted filename is literal. Only allow trailing
        # comments after an explicitly quoted value, so a filename can never
        # silently be truncated and cause us to back up a different key.
        quoted = configured.startswith(("'", '"'))
        values = shlex.split(configured, comments=quoted, posix=True)
    except ValueError:
        raise RuntimeError("Invalid " + KEY_SETTING + " configuration.") from None
    if len(values) != 1 or not values[0] or "\x00" in values[0]:
        raise RuntimeError("Invalid " + KEY_SETTING + " configuration.")
    path = Path(values[0])
    if not path.is_absolute():
        raise RuntimeError(KEY_SETTING + " must be an absolute path.")
    return path


@contextmanager
def private_output(path):
    """Create a new owner-readable file regardless of the caller's umask."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        os.fchmod(output.fileno(), 0o600)
        yield output
        output.flush()
        os.fsync(output.fileno())


def backup_snapshot(database_path="/var/lib/namiya/worryshop.db",
                    environment_path="/etc/namiya.env",
                    release_path="/opt/namiya/current",
                    backup_root="/var/backups/namiya", now=None):
    """Create and verify a snapshot, returning its path only when complete.

    Failed snapshots remain in place without COMPLETE for diagnosis. The env
    copy retains the original restore location of password-transport.pem; copy
    it back to PASSWORD_TRANSPORT_PRIVATE_KEY_FILE with 0600 permissions before
    starting the restored application. No backups are pruned here.
    """
    root = Path(backup_root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    instant = now or datetime.now(timezone.utc)
    target = root / instant.strftime("daily-%Y%m%dT%H%M%S.%fZ")
    target.mkdir(mode=0o700)
    target.chmod(0o700)

    environment_bytes = Path(environment_path).read_bytes()
    key_path = password_key_path(environment_bytes.decode("utf-8"))
    if key_path is not None:
        try:
            # Match the runtime's regular-file requirement. O_NOFOLLOW also
            # closes the final symlink-swap window when the platform supports it.
            if not stat.S_ISREG(key_path.lstat().st_mode):
                raise OSError("not a regular file")
            descriptor = os.open(key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                 | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise OSError("not a regular file")
                with private_output(target / "password-transport.pem") as output:
                    while True:
                        block = source.read(65536)
                        if not block:
                            break
                        output.write(block)
        except OSError:
            raise RuntimeError("Configured password transport private key is unavailable.") from None

    destination_path = target / "worryshop.db"
    with private_output(destination_path):
        pass
    database_uri = Path(database_path).resolve(strict=True).as_uri() + "?mode=ro"
    with closing(sqlite3.connect(database_uri, uri=True)) as source:
        with closing(sqlite3.connect(str(destination_path))) as destination:
            source.backup(destination)
            destination.commit()
            if destination.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise RuntimeError("Backup integrity check failed.")
    with destination_path.open("rb") as output:
        os.fsync(output.fileno())
    with private_output(target / "namiya.env") as output:
        output.write(environment_bytes)
    release = Path(release_path).resolve(strict=True)
    if not release.is_dir():
        raise RuntimeError("Release path is not a directory.")
    with private_output(target / "release.txt") as output:
        output.write((str(release) + "\n").encode("utf-8"))
    with private_output(target / "code.tar.gz") as output:
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            archive.add(str(release), arcname=".")
    with private_output(target / "COMPLETE"):
        pass
    return target


def main():
    os.umask(0o077)
    target = backup_snapshot()
    print("Backup verified: " + str(target))


if __name__ == "__main__":
    main()
