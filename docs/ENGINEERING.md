# Engineering notes

AssistFlow uses a same-origin FastAPI API with server-side SQLAlchemy queries and a browser UI. Session tokens are random and only SHA-256 hashes are persisted. Passwords use scrypt with per-password salts. JSON-only writes and same-site cookies reduce CSRF risk; authorization is checked per endpoint.

Customers see only their own tickets. Staff can read workspace tickets, but agents can modify only assigned tickets. Administrators assign agents. Mutations compare a ticket version inside the transaction and record activity. Export has its own staff-only authorization check; it applies list filters and forces user strings to Excel text cells.

SQLite is the local development default. PostgreSQL is the deployment target and requires a managed external database. Schema changes are explicit and idempotent via app.migrate. Back up the local file before migration. Production migrations should run once before deployment with appropriate backups. A larger plan does not replace load testing.

Known limits: per-email login throttling is basic and can race under distributed load; there is no email/password reset service, multi-organization tenancy, attachment handling or operational backup automation. Test coverage uses SQLite, so PostgreSQL and hosted UI verification are separate release checks.
