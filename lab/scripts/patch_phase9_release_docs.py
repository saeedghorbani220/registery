#!/usr/bin/env python3
"""One-shot Phase 9 patch for the v1.15.0 rollout documentation."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = ROOT / "VERSION"
CHANGELOG = ROOT / "CHANGELOG.md"
INSTALL = ROOT / "host" / "INSTALL.md"
NOTES = ROOT / "RELEASE_NOTES_v1.15.0.md"

CHANGELOG_ENTRY = """## [1.15.0] - 2026-10-15

### Added

- **Reviewed legacy CRM Migration Center for v1.13.1 and older stores.**
  - Added a guarded admin-only browser workflow with server-side kill switch,
    staging, duplicate/conflict review, explicit create/merge/skip/reject
    decisions, source SHA-256 idempotency and atomic apply.
  - Added PII-free before/after migration verification summaries and real
    MariaDB reconciliation coverage for counts, balances, case stages and
    customer/owner/device/period links.
- **Multi-device account lifecycle hardening.**
  - Normal users can self-enrol their own desktop machines; administrators can
    revoke individual devices without terminating unrelated machines.
  - Multiple PCs can use the same username concurrently, while distinct device
    identities keep refresh-token families and revocation independent.
  - The Cloud UI now shows the current device identity and actionable reconnect
    guidance; a stale device id with a missing/revoked protected credential is
    safely re-enrolled after a successful user login.

### Changed

- **Server-authoritative CRM synchronization is the default online workflow.**
  Local JSON remains the robot-compatible cache/outbox rather than a second
  authoritative database.
- **Legacy financial import order is deterministic.** Transaction staging rows
  are sorted by customer and legacy sequence before append-safe server sequence
  allocation, preventing silent reordering of a customer's ledger.
- **Database backups are now fully restorable.** The production backup generator
  discovers every live base table, includes operational tables introduced by
  forward migrations, preserves database triggers, and uses the configured
  migration connection for controlled metadata reads when available.

### Reliability and tests

- Added real-MariaDB lock-wait retry verification proving bounded transaction
  rollback/retry applies a mutation exactly once.
- Added production backup -> second-database restore verification, including
  table counts, legacy migration verification rows, financial data and the
  restored sync-device ownership trigger.
- Permanent CI now covers the server CRM schema, authentication, finance,
  migration, database resilience, backup/restore and Windows cloud client flows.

"""

RELEASE_NOTES = """# IRICA v1.15.0 — Server CRM migration and reliability hardening

IRICA v1.15.0 completes the production hardening of the shared cPanel CRM
workflow introduced in v1.14.0. The online MySQL/MariaDB host is the normal CRM
source of truth, while each Windows installation keeps its local JSON as a
robot-compatible cache and durable outbox.

## Highlights

- **Legacy Migration Center:** an administrator can temporarily enable
  `legacy_import_enabled`, open `legacy-import.php`, upload a v1.13.1-or-older
  `crm_store.json`, review staged create/merge/skip/reject decisions, and apply
  the accepted migration atomically. Raw uploaded JSON is not stored in SQL.
- **Safe multi-PC use:** normal users self-enrol their own PCs. The same username
  may be active on multiple PCs, but each machine has an independent device id
  and refresh-token family so one device can be revoked without disconnecting
  the others. Separate usernames remain recommended for human auditability.
- **Conflict-safe shared CRM:** server row versions remain the concurrency
  authority. Conflicts are surfaced for review instead of silently overwriting
  another operator's edit.
- **Financial integrity:** imported customer transactions remain append-safe and
  now preserve their legacy per-customer ordering before server sequence
  allocation. Rich MariaDB reconciliation checks counts, links, case stages and
  financial sums after migration and after idempotent replay.
- **Recoverable desktop credentials:** the Cloud UI identifies the current PC
  and explains reconnect states. If a stale device id remains after its
  protected device credential is lost or revoked, a successful user login
  self-enrols a replacement device rather than leaving sync stuck.
- **Restorable server backups:** `backup-to-telegram.php` now discovers every
  live base table instead of relying on the synced-entity schema list, includes
  forward-migration operational tables and database triggers, gzip-compresses
  the complete SQL dump, and keeps the public backup response free of SQL/PII.

## Upgrade checklist

1. Back up the existing host database and `config/config.php`.
2. Upload the new `host/` package and preserve the real config file.
3. Run `php bin/migrate.php` and confirm `php bin/migrate.php --status` shows
   migrations 001 through 004 with matching checksums.
4. Run `php bin/smoke-test.php`.
5. Connect one Windows client, then a second client (the same username is
   supported if operationally required) and confirm both show distinct device
   identities and successful sync.
6. For old local CRM data, take a copy of the original JSON, temporarily set
   `legacy_import_enabled => true`, use the Migration Center, reconcile the
   review/apply summary, then immediately set the switch back to `false`.
7. Run an on-demand server backup and periodically test restoring a dump into a
   separate database. A valid restore must include all live base tables and the
   sync-device ownership trigger.

## Compatibility

- PHP 8.1+ and MySQL 5.7+/MariaDB 10.3+ remain the host baseline.
- No desktop client connects directly to MySQL; all synchronization is HTTPS to
  the PHP API.
- Local CRM mode remains available as a compatibility/fallback path, so this is
  a SemVer minor release rather than a breaking 2.0 release.
"""


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected 1 match, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def main() -> None:
    current = VERSION.read_text(encoding="utf-8").strip()
    if current != "1.14.0":
        raise RuntimeError(f"VERSION drifted: expected 1.14.0, found {current}")
    VERSION.write_text("1.15.0\n", encoding="utf-8", newline="\n")

    changelog = CHANGELOG.read_text(encoding="utf-8")
    if "## [1.15.0]" in changelog:
        raise RuntimeError("1.15.0 changelog entry already exists")
    marker = "This project uses [Semantic Versioning](https://semver.org/).\n\n"
    if changelog.count(marker) != 1:
        raise RuntimeError("changelog header anchor drifted")
    CHANGELOG.write_text(changelog.replace(marker, marker + CHANGELOG_ENTRY, 1),
                         encoding="utf-8", newline="\n")

    if NOTES.exists():
        raise RuntimeError("v1.15.0 release notes already exist")
    NOTES.write_text(RELEASE_NOTES, encoding="utf-8", newline="\n")

    replace_once(
        INSTALL,
        "├── migrations/    001_initial.sql, 002_server_crm_v2_foundation.sql, 003_server_crm_v2_device_auth.sql\n",
        "├── migrations/    001_initial.sql through 004_legacy_import_verification.sql\n",
        "migration package list",
    )
    replace_once(
        INSTALL,
        "Fill in every `REPLACE_…` value: `db.host`, `db.port`, `db.dbname`,\n`db.user`, `db.password`, and `db_migrate` (the privileged account from\nstep 1, or `null` if you knowingly gave the app account DDL — don't).\n",
        "Fill in every `REPLACE_…` value under `db`. If the application account\n"
        "is correctly DML-only, set `db_migrate` to a **complete second database\n"
        "connection array** (`host`, `port`, `dbname`, `user`, `password`) for the\n"
        "privileged account from step 1. Use `null` only when the `db` account\n"
        "itself intentionally holds DDL privileges — not recommended.\n",
        "db_migrate instructions",
    )
    replace_once(
        INSTALL,
        "3. Remove shell access you do not need. The four `bin/` scripts are the\n   only CLI surface; they print no credential.\n",
        "3. Remove shell access you do not need. The five `bin/` scripts are the\n"
        "   supported CLI surface: migrate, create-admin, create-user, smoke-test\n"
        "   and backup-to-telegram. They do not print credentials except the\n"
        "   documented one-time generated account password during account setup.\n",
        "bin script count",
    )
    replace_once(
        INSTALL,
        "* **Back up the database nightly**, encrypted at rest, and *test a restore*.\n  The schema is forward-only: the restore path is \"load the dump, then run\n  `php bin/migrate.php --status` and apply anything newer\" — there is no\n  rollback script by design (spec §10.10).\n",
        "* **Back up the database nightly**, encrypted at rest, and *test a restore*.\n"
        "  `backup-to-telegram.php` discovers every live base table from\n"
        "  `information_schema` and includes database triggers, so operational\n"
        "  tables introduced by migrations 002/004 and the device-ownership\n"
        "  trigger from migration 003 are part of the dump. When `db_migrate` is\n"
        "  configured, backup uses that privileged connection for controlled\n"
        "  metadata reads while the runtime app account remains DML-only.\n"
        "* **Restore into a separate database before trusting a backup.** Load the\n"
        "  `.sql` dump, compare the source/restored base-table and trigger counts,\n"
        "  verify representative CRM/financial rows, then run\n"
        "  `php bin/migrate.php --status` against the restored database and apply\n"
        "  only genuinely newer migrations. The schema is forward-only; there is\n"
        "  no destructive down migration (spec §10.10).\n",
        "backup restore runbook",
    )
    print("phase9 release documentation patch applied")


if __name__ == "__main__":
    main()
