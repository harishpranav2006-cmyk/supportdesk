# SupportDesk

A customer-support ticket application built as a software engineering placement portfolio project.

**Status: milestone 1, local working prototype. Not a production deployment.**

Python/FastAPI serves a same-origin HTML/CSS/JavaScript interface and a SQLite database. No paid API, AI model, Node installation, or cloud account is needed. PostgreSQL is planned; this release does not support it yet.

## Run on Windows (PowerShell)

Install Python 3.12, extract this folder, and open it in VS Code or Antigravity. Open its terminal:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:DEMO_PASSWORD = Read-Host 'Choose a local demo password (12+ characters)'
.\.venv\Scripts\python.exe -m app.seed
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. API documentation: http://127.0.0.1:8000/docs.

No environment activation or PowerShell execution-policy change is required. The password prompt is visible input; use a disposable demo password, not a personal password.

## Run on macOS/Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
read -rs -p 'Local demo password (12+ characters): ' DEMO_PASSWORD
export DEMO_PASSWORD
.venv/bin/python -m app.seed
.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

## Local demo accounts

All accounts use the password you chose during the first seed run. No passwords are checked into the code. Re-running seed does not reset existing passwords.

| Account | Role |
| --- | --- |
| customer@demo.local | Customer |
| other@demo.local | Second customer, for access isolation checks |
| agent@demo.local | Support agent |
| admin@demo.local | Administrator |

Seed is explicitly for local demo use. Do not expose these shared-password accounts to the public internet.

## Included workflows

- Sign in/out with server-side sessions, hashed passwords, HttpOnly cookies, and eight-hour expiry.
- Create tickets with title, description, and priority.
- Search and filter tickets, with server-side pagination.
- Customers see and comment only on their own tickets.
- Agents can inspect the team inbox; only the assigned agent can comment/change status.
- Administrators assign/unassign agents and manage ticket status.
- Validated lifecycle: open → in_progress → resolved; resolved can reopen.
- Ticket changes and comments produce audit records in the same transaction.
- Five failed login attempts lock that email for 15 minutes.
- The browser renders user text with textContent, not HTML injection.

## Demo in five minutes

1. Sign in as customer, create a ticket, and add a comment.
2. Sign out; sign in as the second customer. Confirm the first ticket is absent.
3. Sign in as administrator and assign the ticket to the support agent.
4. Sign in as agent, move it to in progress, reply, and resolve it.
5. Return as customer and inspect the conversation and activity trail.
6. Explain why permission checks happen on the server even when buttons are hidden.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Linux/macOS: `.venv/bin/python -m unittest discover -s tests -v`.

Eight integration tests passed in the development environment (Python 3.12). They exercise unauthorized access, customer isolation, assignment restrictions, lifecycle rules, comments, logout invalidation, validation, search/pagination, login throttling, expiry, and request security headers. Tests use a fresh temporary database per test. JavaScript syntax was checked with `node --check app/static/app.js`. Visual browser interactions and a clean Windows installation have not been verified here.

GitHub Actions configuration is included but has not run on GitHub yet. Direct dependencies are pinned to the tested environment; a full transitive lockfile and dependency security review remain future work.

## Structure

- `app/main.py`: database schema, security, validated request models, API routes.
- `app/seed.py`: explicitly creates local demo users.
- `app/static/`: responsive inbox interface.
- `tests/test_api.py`: integration/security-behavior tests.
- `docs/ENGINEERING.md`: design, trade-offs, limitations, and learning exercises.
- `.github/workflows/tests.yml`: continuous integration configuration.

## Configuration

- `SUPPORTDESK_DB`: SQLite file path; defaults to `supportdesk.db` in the current directory.
- `COOKIE_SECURE`: set to `true` when serving behind HTTPS. Local HTTP needs the default `false`.
- `DEMO_PASSWORD`: required only by the local seed command.

## Next milestones

1. PostgreSQL + SQLAlchemy, versioned migrations, database integration tests, and atomic concurrent updates.
2. SLA response deadlines, overdue filtering, and operational metrics.
3. Secure invitation-based user provisioning, password reset, distributed abuse protection, and deployment configuration.
4. Browser workflow tests, accessibility checks, load measurements, and a hosted demo.
5. QueueLab integration for asynchronous notifications; no simulated delivery claims.

This project was started with AI assistance. Before presenting it in interviews, run it, understand the code, make and test your own changes, and accurately describe your contribution. Do not claim production users or performance figures without measurements.
