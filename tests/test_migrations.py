import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine, insert, select
from app.database import metadata, users, versions, signup_attempts
from app.migrate import migrate


class SupportDeskMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine("sqlite:///" + str(Path(self.tmp.name) / "migration.db"))
        metadata.create_all(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def test_assistflow_login_is_renamed_without_changing_account(self):
        password_hash = "existing-salt:existing-hash"
        with self.engine.begin() as connection:
            connection.execute(
                insert(users).values(
                    email="customer@assistflow.local",
                    name="Existing Customer",
                    password=password_hash,
                    role="customer",
                )
            )
            connection.execute(insert(versions).values(version=2))
            old_id = connection.execute(
                select(users.c.id).where(users.c.email == "customer@assistflow.local")
            ).scalar_one()

        migrate(self.engine)

        with self.engine.connect() as connection:
            user = connection.execute(
                select(users).where(users.c.email == "customer@supportdesk.local")
            ).mappings().one()
            self.assertEqual(user["id"], old_id)
            self.assertEqual(user["password"], password_hash)
            self.assertEqual(user["name"], "Existing Customer")
            self.assertEqual(user["role"], "customer")
            self.assertIsNone(
                connection.execute(
                    select(users.c.id).where(users.c.email == "customer@assistflow.local")
                ).scalar_one_or_none()
            )

    def test_migration_refuses_to_merge_two_accounts(self):
        with self.engine.begin() as connection:
            connection.execute(
                insert(users),
                [
                    {
                        "email": "customer@assistflow.local",
                        "name": "Old account",
                        "password": "hash-one",
                        "role": "customer",
                    },
                    {
                        "email": "customer@supportdesk.local",
                        "name": "New account",
                        "password": "hash-two",
                        "role": "customer",
                    },
                ],
            )
            connection.execute(insert(versions).values(version=2))

        with self.assertRaisesRegex(RuntimeError, "both accounts exist"):
            migrate(self.engine)

        with self.engine.connect() as connection:
            emails = set(connection.execute(select(users.c.email)).scalars())
            self.assertEqual(
                emails,
                {"customer@assistflow.local", "customer@supportdesk.local"},
            )


    def test_signup_rate_limit_table_is_migrated_and_versioned(self):
        migrate(self.engine)
        with self.engine.connect() as connection:
            tables = set(__import__("sqlalchemy").inspect(connection).get_table_names())
            applied = set(connection.execute(select(versions.c.version)).scalars())
        self.assertIn(signup_attempts.name, tables)
        self.assertIn(4, applied)
        # Re-running migrations is safe and does not duplicate version rows.
        migrate(self.engine)
        with self.engine.connect() as connection:
            self.assertEqual(
                connection.execute(
                    select(versions.c.version).where(versions.c.version == 4)
                ).all().__len__(),
                1,
            )


if __name__ == "__main__":
    unittest.main()
