# SupportDesk

A role-based customer-support workspace built with FastAPI, SQLAlchemy, and vanilla JavaScript. Customers create and track requests, administrators assign agents, and assigned agents manage replies and ticket status.

## Current features

- Customer ticket isolation enforced by the API.
- Agent and administrator roles with server-side permission checks.
- Ticket assignment, comments, status transitions, and activity history.
- Search, status and priority filters, pagination, and board view.
- Priority-based resolution targets, overdue filters, and optimistic concurrency checks.
- Staff-only Excel export that respects the current filters and protects cells from formula execution.
- Scrypt password hashes, expiring HttpOnly sessions, password changes that revoke sessions, and basic login throttling.
- SQLite for local development and PostgreSQL support for hosted deployments.

## Run locally on Windows

Install Python 3.12 or newer. From the project folder in PowerShell:

\`\`\`powershell
py -3.12 -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt
$env:SUPPORTDESK_INITIAL_PASSWORD = Read-Host 'Set an initial password (12+ characters)'
.\\.venv\\Scripts\\python.exe -m app.seed
.\\.venv\\Scripts\\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
\`\`\`

Open http://127.0.0.1:8000.

## Run locally on macOS or Linux

\`\`\`sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export SUPPORTDESK_INITIAL_PASSWORD='use-a-private-password-of-12-characters-or-more'
python -m app.seed
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
\`\`\`

## Local login identifiers

| Role | Login identifier |
| --- | --- |
| Customer | \`customer@supportdesk.local\` |
| Second customer | \`customer2@supportdesk.local\` |
| Agent | \`agent@supportdesk.local\` |
| Administrator | \`admin@supportdesk.local\` |

These are **local login identifiers**, not working email inboxes. The seed command uses the initial password you provide for any accounts it creates. It does not reset passwords for accounts that already exist. Sign in and change each account password from Account settings.

No default password is stored in the source code. Do not reuse a personal password for local testing or expose seeded accounts to the public internet.

## Database and hosting

Local data is stored in \`supportdesk.db\`. Set \`SUPPORTDESK_DB\` to use a different SQLite file.

For Vercel hosting, configure a managed PostgreSQL database and set:

- \`DATABASE_URL\`: the PostgreSQL connection string.
- \`COOKIE_SECURE=true\`: required when the site is served over HTTPS.
- \`SUPPORTDESK_INITIAL_PASSWORD\`: only when provisioning new accounts with the seed command.

Run \`python -m app.migrate\` against the configured database before the first deployment. Back up the database first. The migration preserves user IDs, password hashes, ticket IDs, comments, and audit history while updating the old login identifiers. If both an old and new address already belong to different accounts, migration stops safely and reports the conflict instead of merging or deleting either account.

Vercel's local filesystem is not used for persistent data. A hosted deployment is not considered usable until its PostgreSQL database is configured, migrated, and verified.

## Verification

\`\`\`sh
python -m unittest discover -s tests -v
node --check app/static/app.js
\`\`\`

The API tests cover authentication, role permissions, customer isolation, assignment, status transitions, activity history, logout, validation, pagination, login throttling, exports, concurrency, and password changes. The automated suite currently uses SQLite; PostgreSQL integration and live hosted-browser testing remain separate release checks.

## Production limitations

This is a substantial portfolio application, but it is **not yet a fully production-ready SaaS**. Email delivery and password-reset links, public customer registration, invitation management, file attachments, organization tenancy, distributed rate limiting, automated backup/restore drills, accessibility auditing, load testing, and production monitoring still need implementation and verification.

Real outbound email requires a domain you control and an email delivery provider. Changing a login identifier to \`@supportdesk.local\` does not create an inbox or send email.

Capacity depends on the managed database plan and measured workload, not simply on choosing PostgreSQL. Do not claim production readiness, real customers, or performance figures without operating and measuring the hosted system.
