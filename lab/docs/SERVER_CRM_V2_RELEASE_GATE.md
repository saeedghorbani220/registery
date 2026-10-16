# Server CRM v1.15 — Release Gate

This file is the release-candidate gate for the phased plan in
`SERVER_CRM_V2_PLAN.md`. A phase is marked implementation-complete only when
its executable gate is present in permanent CI. Production deployment is a
separate operator action and is never inferred from a green source checkout.

## Gate status

| Phase | Required outcome | Permanent evidence |
| --- | --- | --- |
| 0 — baseline | reproducible offline/real-DB verification | `server-crm-v2.yml`, PHP lint, Windows client suites |
| 1 — host foundation | forward-only schema, HTTPS/API auth, deterministic validation | `test_server_crm_v2_schema`, `test_host_api`, migration 001–004 checks |
| 2 — multi-device auth | independent devices/sessions, scoped revocation, protected credentials | `test_server_crm_v2_device_auth`, `test_server_crm_v2_client_devices`, `test_server_crm_v2_authority` |
| 3 — server-authoritative CRM | bootstrap/cursor/outbox/restart safety, epoch quarantine | `test_cloud_transport`, `test_cloud_apply`, `test_cloud_integration`, `test_cloud_state` |
| 4 — concurrency/accounting | optimistic conflicts, append-safe finance, delete/offline races, advisory presence | `test_cloud_conflicts`, `test_server_crm_v2_finance*`, `test_server_crm_v2_database_resilience`, `test_server_crm_v2_presence*` |
| 5 — legacy migration | guarded review/apply/reconciliation and replay safety | `test_server_crm_v2_legacy_import`, `test_server_crm_v2_legacy_apply`, `test_server_crm_v2_legacy_page`, `test_v115_audit_config_switch` |
| 6+ — UX/stress/recovery | operator status, bounded retry/failure behavior, multi-client races, backup/restore | `test_cloud_ui`, `test_cloud_transport`, `test_cloud_integration`, `test_server_crm_v2_database_resilience`, `test_server_crm_v2_backup_restore` |

The compatibility matrix is part of the gate: host transactional paths run on
both MariaDB 11.4 and MySQL 5.7, while the production desktop family runs on
Windows. The advisory-presence path is exercised on both database families.

## Safety invariants

- Desktop clients never receive direct MySQL/MariaDB credentials.
- `row_version` conflict handling remains authoritative; record presence never
  becomes a hard edit lock.
- Financial writes are idempotent and append/void through server serialization
  points rather than generic last-write-wins updates.
- Legacy import is disabled by default and ambiguous decisions fail closed.
- Device/user tokens are not stored in plaintext logs or normal JSON state.
- Applied migration `001_initial.sql` is not rewritten; later changes are
  forward migrations.
- Server backup verification restores into a second database and validates
  operational tables/triggers, not only business rows.

## Release-candidate preflight

Before merge/tagging, all permanent `server-crm-v2` jobs must be green on the
exact PR head. `VERSION` must be `1.15.0`, release notes must exist, migrations
001–004 must be present, and all host PHP must lint. No temporary audit/helper
workflow belongs in the release tree.

For the Windows binary bundle, run `lab/scripts/build_windows_release.py` and
then `lab/scripts/verify_windows_release.py` against the staged tree. The source
repository intentionally does not contain the generated ONNX checkpoints, so a
clean Git checkout is **not** sufficient to manufacture the authoritative
binary bundle. The release builder must be supplied with the previously
validated model artifacts; verification then requires both ONNX models and
forbids shipping `.pt` checkpoints, secrets, or runtime state.

## Operator-only rollout gate

Green CI means **ready for staged rollout**, not “already deployed”. The actual
production gate requires access to the real cPanel/DB and operator-controlled
Windows installations:

1. Take a database backup and preserve `host/config/config.php`.
2. Deploy the host package and run migrations 001–004 plus `bin/smoke-test.php`.
3. Validate one enrolled Windows client, then two simultaneous clients.
4. If legacy data is imported, open the migration switch only for the review
   window, reconcile the result, then disable it again.
5. Run an on-demand backup and restore it into a separate database; validate
   table counts, finance data, migration verification rows, and device trigger.
6. Keep rollback artifacts (pre-deploy DB backup and previous desktop build)
   until the staged validation is accepted.

Production rollout is complete only after those operator steps are recorded;
source CI cannot truthfully substitute for them.
