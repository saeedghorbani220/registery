# Server CRM v2 rollout contract

Status: implementation contract for `feat/server-crm-v2-work`.

This document records the product decisions for the next CRM architecture. It
extends the existing cloud-sync contract without changing the robot boundary:
robots remain local and continue to consume the local stores, while the hosted
service becomes the authority for CRM business data.

## 1. Product outcome

- MySQL/MariaDB on the cPanel host is the source of truth for CRM data.
- Desktop clients never connect to MySQL directly. They use the PHP HTTPS API.
- `crm_store.json` remains a local cache/robot compatibility surface, not the
  cross-machine authority.
- A username/password may have more than one simultaneous session and more
  than one enrolled desktop device.
- One username per human remains the recommended operational practice, but a
  shared username is not technically restricted to one active machine.
- Each desktop has its own device identity so sessions and revocation remain
  attributable even when a username is shared.

## 2. Concurrency model

Business records use optimistic concurrency through the existing
`row_version` compare-and-swap protocol. There is no hard edit lock.

`record_presence` is advisory only. It may tell an operator that another
user/device is viewing or editing the same record, but an expired/stale
presence row must never block a write. The server version check is the data
integrity boundary.

A conflicting stale write is never silently accepted. It remains a conflict
until the operator accepts the server value or explicitly reapplies the local
value against the fresh server version.

Financial transaction creation must be append-safe under concurrent clients.
The current customer-local `seq` identity is not sufficient as the final v2
write identity; Phase 4 must introduce a server-safe ordering/identity scheme
before server-authoritative accounting is released.

## 3. Authentication and devices

- User access is username/password -> short-lived user access token + rotating
  refresh family.
- Any authenticated `admin` or `user` may self-enrol the machine they are
  currently using.
- Self-enrolment binds `sync_devices.owner_user_id` to the authenticated user.
- `enrolled_by` remains audit provenance and is not overloaded as ownership.
- Managing/revoking somebody else's device remains admin-only.
- Disabling a user must revoke both user sessions and device sessions owned by
  that user.
- Device secrets remain protected by Windows DPAPI; there is no plaintext
  fallback.

## 4. Legacy migration

The existing `/v1/bootstrap/import` stays a one-shot empty-dataset bootstrap.
It is not repurposed for repeated legacy merges.

Legacy local databases (v1.13.1 and earlier) use a separate admin-only web
migration flow:

1. upload JSON;
2. validate structure and supported legacy shape;
3. normalize into staging rows;
4. detect exact duplicates, possible duplicates, conflicts, invalid records
   and orphan references;
5. show a dry-run/preview;
6. record explicit admin decisions for ambiguous rows;
7. atomically apply the reviewed merge;
8. reconcile counts, relationships and customer balances.

The raw uploaded file is not retained in SQL. A per-tenant SHA-256 fingerprint
makes exact re-upload idempotent. PII may exist in protected staging database
rows because it is business data, but it must never be copied into application
logs or audit metadata.

## 5. Rollout gates

### Phase 0 - baseline and verification infrastructure

- Establish branch-isolated CI.
- Run Windows cloud-client tests on the production OS family.
- Run host migration tests against disposable MariaDB.
- Do not weaken DPAPI/ACL behaviour to make Linux tests pass.

### Phase 1 - host foundation

- Forward migration `002_server_crm_v2_foundation.sql`.
- Explicit device ownership.
- Advisory record presence.
- Legacy import jobs, normalized staging rows and explicit decisions.
- Migration must apply after `001_initial.sql` without destructive statements.

### Phase 2 - multi-device auth

- User self-enrolment.
- Ownership written atomically at enrolment.
- Per-device revoke and user-wide revoke semantics.
- Concurrent sessions for the same username covered by tests.

### Phase 3 - server-authoritative CRM

- Bootstrap before first push on a new/foreign device.
- Durable local outbox and incremental cursor pull remain restart-safe.
- Foreign/unknown dataset epochs are quarantined.

### Phase 4 - concurrency and accounting

- Advisory presence API/UI.
- Same-record concurrent edit scenarios.
- Append-safe financial transaction identity/order.
- Delete/edit and offline/reconnect races.

### Phase 5 - legacy migration center

- Admin-only PHP web UI.
- Staging, dedupe, preview, decisions, atomic apply and reconciliation.
- Repeated imports of distinct legacy sources are supported safely.

### Phase 6+ - UX, reconciliation, stress and rollout

- Connection/device/conflict status in the desktop panel.
- Migration reports and reconciliation.
- Multi-client/network/retry/failure stress tests.
- Staged production rollout with backups and restore drills.

## 6. Non-negotiable safety properties

- No direct desktop MySQL credentials.
- No silent last-write-wins.
- No blind `INSERT IGNORE` migration strategy.
- No hard edit lock as the consistency mechanism.
- No plaintext password/token persistence or logging.
- No destructive edit to already-applied migration `001_initial.sql`.
- No claim that a phase is complete before its verification gate passes.
