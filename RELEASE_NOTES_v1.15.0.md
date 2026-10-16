# IRICA v1.15.0 — Server CRM migration and reliability hardening

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
- Advisory record presence shows when another enrolled PC has the same case open; it never locks editing and expires automatically.
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
