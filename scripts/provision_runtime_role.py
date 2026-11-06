"""Provision the least-privileged local VANTAGE runtime role.

This script is for the local Docker Compose development stack only. Production
must provision roles through its controlled database migration process.
"""
from __future__ import annotations

import os

import psycopg
from psycopg import sql


def main() -> None:
    migration_url = os.environ["VANTAGE_MIGRATION_DATABASE_URL"]
    runtime_password = os.environ["VANTAGE_RUNTIME_DB_PASSWORD"]
    database_url = migration_url.replace(
        "postgresql+psycopg://", "postgresql://", 1
    )
    role_name = "vantage_app"
    with psycopg.connect(database_url, autocommit=True) as connection:
        exists = connection.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (role_name,)
        ).fetchone()
        role_statement = (
            sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {} NOSUPERUSER "
                    "NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS")
            if exists
            else sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER "
                         "NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS")
        )
        connection.execute(
            role_statement.format(
                sql.Identifier(role_name), sql.Literal(runtime_password)
            )
        )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE vantage TO {}").format(
                sql.Identifier(role_name)
            )
        )
        connection.execute(
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                sql.Identifier(role_name)
            )
        )
        connection.execute(
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
            ).format(sql.Identifier(role_name))
        )
        connection.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
            ).format(sql.Identifier(role_name))
        )


if __name__ == "__main__":
    main()
