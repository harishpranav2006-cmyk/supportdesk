"""Idempotent schema and login-identifier migrations for SupportDesk."""
import re

from sqlalchemy import inspect, select, insert, update, text
from .database import metadata, versions, users, tickets, comments


def _user_id(connection, email):
    return connection.execute(
        select(users.c.id).where(users.c.email == email)
    ).scalar_one_or_none()


def _rename_email(connection, old_email, new_email):
    old_id = _user_id(connection, old_email)
    if old_id is None:
        return

    new_id = _user_id(connection, new_email)
    if new_id is not None and new_id != old_id:
        raise RuntimeError(
            "Cannot migrate login identifier "
            f"{old_email} to {new_email}: both accounts exist. "
            "Resolve the duplicate accounts before retrying; no data was changed."
        )

    connection.execute(
        update(users).where(users.c.id == old_id).values(email=new_email)
    )


def migrate(engine):
    metadata.create_all(engine)

    with engine.begin() as connection:
        applied = set(connection.execute(select(versions.c.version)).scalars())

        # v2: add ticket workflow fields and clean only tutorial-specific prefixes.
        if 2 not in applied:
            columns = {
                column["name"]
                for column in inspect(connection).get_columns("tickets")
            }
            for name, definition in (
                ("category", "VARCHAR(30) NOT NULL DEFAULT 'general'"),
                ("due_at", "INTEGER"),
                ("version", "INTEGER NOT NULL DEFAULT 1"),
            ):
                if name not in columns:
                    connection.execute(
                        text(f"ALTER TABLE tickets ADD COLUMN {name} {definition}")
                    )

            for index in tickets.indexes:
                index.create(connection, checkfirst=True)

            # Preserve compatibility with databases from the original tutorial build.
            for old, new in (
                ("customer", "customer"),
                ("other", "customer2"),
                ("agent", "agent"),
                ("admin", "admin"),
            ):
                old_email = old + "@demo.local"
                new_email = new + "@assistflow.local"
                if _user_id(connection, old_email) and not _user_id(connection, new_email):
                    _rename_email(connection, old_email, new_email)

            for row in connection.execute(
                select(tickets.c.id, tickets.c.title, tickets.c.description)
            ).mappings().all():
                title = re.sub(r"^DEMO \d{2}:\d{2}:\d{2} - ", "", row["title"])
                description = row["description"].removeprefix("DEMO ONLY: ")
                if title != row["title"] or description != row["description"]:
                    connection.execute(
                        update(tickets)
                        .where(tickets.c.id == row["id"])
                        .values(title=title, description=description)
                    )

            for row in connection.execute(
                select(comments.c.id, comments.c.body)
                .where(comments.c.body.like("DEMO: %"))
            ).mappings().all():
                connection.execute(
                    update(comments)
                    .where(comments.c.id == row["id"])
                    .values(body=row["body"].removeprefix("DEMO: "))
                )

            connection.execute(insert(versions).values(version=2))

        # v3: replace the previous product identity in login identifiers.
        if 3 not in applied:
            for old_email, new_email in (
                ("customer@assistflow.local", "customer@supportdesk.local"),
                ("customer2@assistflow.local", "customer2@supportdesk.local"),
                ("agent@assistflow.local", "agent@supportdesk.local"),
                ("admin@assistflow.local", "admin@supportdesk.local"),
                ("customer@demo.local", "customer@supportdesk.local"),
                ("other@demo.local", "customer2@supportdesk.local"),
                ("customer2@demo.local", "customer2@supportdesk.local"),
                ("agent@demo.local", "agent@supportdesk.local"),
                ("admin@demo.local", "admin@supportdesk.local"),
            ):
                _rename_email(connection, old_email, new_email)

            connection.execute(insert(versions).values(version=3))


if __name__ == "__main__":
    from .main import engine

    migrate(engine())
    print("SupportDesk schema v3 ready; existing user and ticket data preserved.")
