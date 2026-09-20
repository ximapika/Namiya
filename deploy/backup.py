"""Root-only online SQLite backup; includes config and release for restoration."""
import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def main():
    os.umask(0o077)
    root = Path('/var/backups/namiya')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = root / datetime.now(timezone.utc).strftime('daily-%Y%m%dT%H%M%S.%fZ')
    target.mkdir(mode=0o700)
    try:
        with sqlite3.connect('file:/var/lib/namiya/worryshop.db?mode=ro', uri=True) as source:
            with sqlite3.connect(target / 'worryshop.db') as destination:
                source.backup(destination)
                if destination.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise RuntimeError('Backup integrity check failed')
        shutil.copyfile('/etc/namiya.env', target / 'namiya.env')
        release = Path('/opt/namiya/current').resolve()
        (target / 'release.txt').write_text(str(release) + '\n')
        shutil.make_archive(str(target / 'code'), 'gztar', release)
        (target / 'COMPLETE').touch()
    except Exception:
        # Retain an incomplete snapshot for diagnosis, but never prune backups.
        raise
    print(f'Backup verified: {target}')


if __name__ == '__main__':
    main()
