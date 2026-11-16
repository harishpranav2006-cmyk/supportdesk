# Engineering notes and learning guide

## Architecture

The browser calls same-origin JSON endpoints. FastAPI validates request bodies and authenticates an opaque session cookie. Database helpers execute parameterized SQLite queries. Mutations and their audit events commit together, or roll back together.

SQLite keeps local setup small and reproducible. This is an explicit first-milestone trade-off, not a substitute for the planned PostgreSQL release. Before scaling to concurrent workers, introduce migrations, optimistic concurrency/version checks, and integration tests against PostgreSQL.

## Access model

| Action | Customer | Agent | Admin |
| --- | --- | --- | --- |
| View tickets | Own only | All | All |
| Comment | Own only | Assigned only | All |
| Assign agent | No | No | Yes |
| Change status | No | Assigned only | Yes |
| Create ticket | Yes, owned by self | Yes, owned by self | Yes, owned by self |

A customer's request for another customer's ticket returns 404 so the API does not disclose whether that ID exists. Agents intentionally have team-wide read access; this is a single-organization app, not a multi-tenant SaaS.

## Security design

Passwords use salted scrypt hashes. Session tokens use secure random bytes; only SHA-256 token digests are persisted. Cookies are HttpOnly and SameSite Strict, with a configurable Secure flag. Writes require JSON and reject browser cross-site fetch metadata. No permissive CORS middleware is installed. The content security policy prohibits inline scripts and cross-origin resources. User content is inserted using textContent.

Email-based login throttling is deliberately basic: it is not a complete internet-facing defense and can be abused to temporarily lock another user's account. Add IP-aware limits and monitoring before public deployment. Throttle counters and ticket transitions also need concurrency hardening before multiple production workers. Expired session cleanup runs on successful login; scheduled cleanup is future work.

No signup, email delivery, password recovery, file attachments, organizations, internal-only comments, SLA tracking, or production monitoring is implemented. Audit history is application-generated but not tamper-proof against database administrators. Demo seeding does not provision production accounts. Keep this version bound to localhost.

## Database entities

- users: login identity, password hash, role.
- sessions: token digest, user reference, expiry.
- tickets: customer, optional agent, lifecycle, priority, text, timestamps.
- comments: ticket, author, text, timestamp.
- audit: ticket, actor, change description, timestamp.
- login_attempts: failed attempts and reset time per normalized email.

All relationships use foreign keys. Customer and assignee lookup columns are indexed. Search uses substring matching, which is useful for a small demo but not efficient for large datasets. A future migration should add full-text search and benchmark it with realistic fixture sizes.

## Your first learning tasks

1. Run the five-minute demo in README and explain each role's permissions.
2. Trace POST /api/tickets from browser form to Pydantic validation to SQL insertion and response.
3. Read test_customer_isolation_all_paths. Explain why guessing a ticket ID does not grant access.
4. Add a ticket category field yourself, including validation, storage, UI and a test.
5. Explain why a database transaction should contain both the status update and audit insert.
6. Show what would fail if an agent could assign themselves arbitrary tickets.

## Interview questions to prepare

- Why enforce authorization on every API endpoint?
- What is the difference between authentication and authorization?
- Why store password hashes instead of encrypted passwords?
- Why use HttpOnly cookies rather than browser localStorage for this design?
- How do foreign keys and transactions protect consistency?
- What happens if two agents update the same ticket concurrently? (Current limitation; propose version checks.)
- What changes when SQLite is replaced with PostgreSQL?
- Which tests verify actual business risk rather than merely matching code?

## Acceptance record

Milestone 1: eight integration tests passed; JavaScript syntax check passed. No production-readiness, accessibility conformance, performance, or browser visual QA claim is made. No external service receives messages or customer data. Source code and CI configuration are included for GitHub publication.
