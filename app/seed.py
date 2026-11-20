"""Explicit account provisioning. No built-in credentials or password resets by default."""
import os
from sqlalchemy import select, insert, update

from .main import db, hash_password, init_db
from .database import users, employee_profiles, employee_managers

ACCOUNTS = [
    ("customer@supportdesk.local", "Harish", "customer", "SUPPORTDESK_CUSTOMER_PASSWORD"),
    ("customer2@supportdesk.local", "Second customer", "customer", "SUPPORTDESK_CUSTOMER2_PASSWORD"),
    ("agent@supportdesk.local", "Priya", "agent", "SUPPORTDESK_AGENT_PASSWORD"),
    ("admin@supportdesk.local", "Administrator", "admin", "SUPPORTDESK_ADMIN_PASSWORD"),
]


def main():
    shared_password = os.environ.get("SUPPORTDESK_INITIAL_PASSWORD")
    passwords = {}
    for email, _name, _role, env_key in ACCOUNTS:
        password = os.environ.get(env_key) or shared_password
        if not password or len(password) < 12:
            raise SystemExit(f"Set {env_key} or SUPPORTDESK_INITIAL_PASSWORD to at least 12 characters.")
        passwords[email] = password

    reset_existing = os.environ.get("SUPPORTDESK_RESET_EXISTING_PASSWORDS") == "true"
    init_db()
    with db() as connection:
        for email, name, role, _env_key in ACCOUNTS:
            existing = connection.execute(
                select(users.c.id).where(users.c.email == email)
            ).scalar_one_or_none()
            password_hash = hash_password(passwords[email])
            if existing is None:
                connection.execute(
                    insert(users).values(
                        email=email,
                        name=name,
                        password=password_hash,
                        role=role,
                    )
                )
            elif reset_existing:
                connection.execute(
                    update(users).where(users.c.id == existing).values(password=password_hash)
                )

            if role in ("agent", "admin"):
                employee_profile = connection.execute(
                    select(employee_profiles.c.user_id).where(employee_profiles.c.user_id == existing)
                ).scalar_one_or_none() if existing is not None else connection.execute(
                    select(users.c.id).where(users.c.email == email)
                ).scalar_one_or_none()
                if employee_profile is None:
                    employee_id = connection.execute(
                        select(users.c.id).where(users.c.email == email)
                    ).scalar_one()
                    connection.execute(insert(employee_profiles).values(
                        user_id=employee_id,
                        designation="Administrator" if role == "admin" else "Support Agent",
                        department="Support",
                        is_active=1,
                        created_by=None,
                        created_at=0,
                    ))

        manager_id = connection.execute(
            select(employee_managers.c.user_id).where(employee_managers.c.singleton_id == 1)
        ).scalar_one_or_none()
        if manager_id is None:
            primary_admin = connection.execute(
                select(users.c.id).where(
                    users.c.email == "admin@supportdesk.local",
                    users.c.role == "admin",
                )
            ).scalar_one_or_none()
            if primary_admin is not None:
                connection.execute(insert(employee_managers).values(
                    singleton_id=1,
                    user_id=primary_admin,
                    granted_by=primary_admin,
                    granted_at=0,
                ))

    print("SupportDesk accounts ready. Existing passwords were retained unless an explicit reset was requested.")


if __name__ == "__main__":
    main()
