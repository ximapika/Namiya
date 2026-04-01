import click
from flask.cli import with_appcontext

from .bootstrap import bootstrap_database
from .extensions import db
from .models import User
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
            existing.password_hash = generate_password_hash(password)
            existing.is_admin = True
            existing.is_staff = False
            db.session.commit()
            click.echo(f"Updated admin account: {username}")
            return

        user = User(
            username=username.strip(),
            password_hash=generate_password_hash(password),
            is_admin=True,
            is_staff=False,
        )
        db.session.add(user)
        db.session.commit()
        click.echo(f"Created admin account: {username}")
