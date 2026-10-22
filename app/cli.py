import click
import json
from flask.cli import with_appcontext

from .bootstrap import bootstrap_database
from .extensions import db
from .models import User
from .services.accounts import StaleAccountError, cleanup_inactive_accounts, reset_password
from werkzeug.security import generate_password_hash


def register_cli(app) -> None:
    @app.cli.command("init-db")
    @with_appcontext
    def init_db_command() -> None:
        bootstrap_database()
        click.echo("Database initialized and legacy data migrated.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    @with_appcontext
    def create_admin_command(username: str, password: str) -> None:
        existing = User.query.filter_by(username=username.strip()).first()
        if existing:
            try:
                reset_password(existing, password)
            except StaleAccountError as error:
                db.session.rollback()
                raise click.ClickException(str(error)) from None
            existing.is_admin = True
            existing.is_staff = False
            db.session.commit()
            click.echo(f"Updated admin account: {username}")
            return

        user = User(
            username=username.strip(),
            password_hash=generate_password_hash(password, method="scrypt"),
            is_admin=True,
            is_staff=False,
        )
        db.session.add(user)
        db.session.commit()
        click.echo(f"Created admin account: {username}")

    @app.cli.command("cleanup-inactive-accounts")
    @click.option("--days", type=click.IntRange(min=90), default=90, show_default=True,
                  help="Minimum inactivity in days; staff and administrators are always excluded.")
    @click.option("--batch-size", type=click.IntRange(1, 5000), default=500, show_default=True)
    @click.option("--apply", "apply_changes", is_flag=True,
                  help="Delete this batch. Without this flag, only print counts.")
    @with_appcontext
    def cleanup_inactive_command(days: int, batch_size: int, apply_changes: bool) -> None:
        result = cleanup_inactive_accounts(days=days, batch_size=batch_size, apply=apply_changes)
        click.echo(json.dumps(result, ensure_ascii=False, sort_keys=True))
