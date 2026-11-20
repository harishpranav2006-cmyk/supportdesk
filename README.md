# AssistFlow

A support workspace built with FastAPI, SQLAlchemy and vanilla JavaScript. Customers submit and track requests; administrators assign agents; assigned agents manage progress and replies.

## Features

- Customer isolation, agent assignment permissions and administrator controls enforced by the API.
- Dashboard metrics, searchable/filterable ticket list, board view, activity history and dark mode.
- Priority-based resolution targets, overdue filters and optimistic concurrency checks.
- Excel export for agents and administrators, respecting current filters (up to 5,000 tickets). User text is stored as literal spreadsheet text to prevent formula execution.
- Scrypt password hashes, expiring HttpOnly sessions, password changes that revoke sessions, and basic login throttling.
- SQLite for local development; PostgreSQL support for persistent hosting.

## Run locally

Python 3.12 or newer:

```sh
python -m venv .venv
# Activate .venv using your operating system's activation script.
python -m pip install -r requirements.txt
# Set ASSISTFLOW_INITIAL_PASSWORD privately to a strong password (12+ characters).
python -m app.seed
python -m uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. Login identifiers are `customer@assistflow.local`, `customer2@assistflow.local`, `agent@assistflow.local`, and `admin@assistflow.local`. These are identifiers, not working email inboxes. Local setup uses the supplied initial password; change each account's password in Account settings. No passwords are included in this repository.

Existing SupportDesk installations: back up `supportdesk.db`, install requirements and run `python -m app.migrate`. This preserves accounts, passwords, IDs, tickets and history, migrates the four original login identifiers, and adds the new schema fields. Historical tickets receive no retroactive deadline.

## Database and deployment

Local data is in `supportdesk.db` (override with `ASSISTFLOW_DB`). Inspect it with a SQLite browser. Hosting requires a managed PostgreSQL database: configure `DATABASE_URL` with the provider's connection string and `COOKIE_SECURE=true` in Vercel. Never commit either secrets or database files. Vercel filesystem storage is not used for persistent data.

Before the first deployment, run `python -m app.migrate` against the configured database and provision accounts using `python -m app.seed` with a private initial password; immediately change passwords individually. The local seeding command does not replace existing passwords. Use your PostgreSQL provider's authenticated SQL console to inspect tables (`users`, `tickets`, `comments`, `audit`, `sessions`). Do not share connection strings or password hashes.

The Vercel project uses `app/main.py` as its FastAPI entrypoint. Static assets are copied to `public/static` by `scripts/build.py`. PostgreSQL must be configured and migrated before the app is usable. Deployment completion and production credentials are not implied by this source repository.

## Verification

```sh
python -m unittest discover -s tests -v
node --check app/static/app.js
```

11 API tests cover authentication, role permissions, isolation, assignment and status transitions, activity, logout, validation, pagination, throttling, exports, concurrency and password changes. Tests currently run on SQLite; PostgreSQL integration and live deployment verification are still required.

## Scope

This is an interview portfolio application, not a claim of production certification. Email delivery/reset, attachments, organization tenancy, automated backup/restore drills, distributed rate limiting, accessibility auditing and load testing remain future work. Capacity depends on the database plan and measured workload, not merely database choice.
