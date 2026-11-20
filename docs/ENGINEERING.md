# SupportDesk engineering notes

## Architecture

SupportDesk uses a same-origin FastAPI API with SQLAlchemy queries and a vanilla JavaScript browser interface. Session tokens are random and only SHA-256 hashes are persisted. Passwords use scrypt with per-password salts. Authorization is enforced in API handlers, not merely by hiding UI controls.

Customers can access only their own tickets. Agents can read the team inbox but can modify only tickets assigned to them. Administrators assign and unassign agents. Ticket mutations use version checks and create audit events in the same database transaction.

## Database

SQLite is the local development default. PostgreSQL is supported through \`DATABASE_URL\` for hosting. Schema and account-identifier changes are versioned and idempotent in \`app/migrate.py\`. Back up the database before running migrations against existing data.

## Security boundaries

- Passwords are stored as salted scrypt hashes, never plaintext.
- Session cookies are HttpOnly and SameSite Strict, with Secure enabled for HTTPS hosting.
- Customer isolation and agent assignment permissions are checked by the API.
- API writes require JSON and reject browser cross-site fetch metadata.
- Browser-rendered user content is inserted as text, not HTML.
- Login throttling is basic and is not a substitute for distributed abuse protection.

## Known limitations

Email delivery and password recovery are not implemented. Public registration creates customer-role accounts only and currently does not verify email ownership. Organization tenancy, file attachment handling, and internal-only comments are not implemented. Audit history is application-generated and is not tamper-proof against database administrators. PostgreSQL integration tests, accessibility audits, load tests, backup/restore drills, and production monitoring remain required before a real customer launch.

## Interview preparation

Be ready to explain authentication versus authorization, password hashing, HttpOnly cookies, database transactions, foreign keys, customer isolation, role-based permissions, optimistic concurrency, and the trade-offs between SQLite and PostgreSQL.
