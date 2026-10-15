#!/usr/bin/env python3
"""One-shot documentation alignment for server CRM v2 migration rollout."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALL = ROOT / "host" / "INSTALL.md"
CONFIG = ROOT / "host" / "config" / "config.example.php"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def patch_install() -> None:
    text = INSTALL.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "├── migrations/    001_initial.sql\n",
        "├── migrations/    001_initial.sql, 002_server_crm_v2_foundation.sql, 003_server_crm_v2_device_auth.sql\n",
        "migration tree",
    )
    text = replace_once(
        text,
        "   - Run database migrations (creates all 18 tables).\n",
        "   - Run all pending forward-only database migrations.\n",
        "web setup migration wording",
    )
    text = replace_once(
        text,
        "php bin/migrate.php --status     # what is recorded so far\n"
        "php bin/migrate.php              # applies 001_initial.sql\n"
        "php bin/migrate.php --status     # one row, checksum matches the file\n",
        "php bin/migrate.php --status     # what is recorded so far\n"
        "php bin/migrate.php              # applies every pending migration (001, 002, 003, ...)\n"
        "php bin/migrate.php --status     # every applied migration has a matching checksum\n",
        "migration command comments",
    )

    text = replace_once(
        text,
        "This is the account the desktop client logs in with; it is what mints the\n"
        "first enrolled device (spec §7: enrolment is admin-only).\n",
        "This account can sign in from the desktop client and self-enrol its own\n"
        "machine. Normal users can also self-enrol their own machines; administrators\n"
        "can revoke any machine in the tenant. Device credentials are independent\n"
        "refresh-token families, so signing out or revoking one machine does not\n"
        "implicitly terminate unrelated machines.\n",
        "admin enrolment wording",
    )

    old_accounts = """## 6. Create one account per colleague

`create-admin.php` is single-use by design, so it is not how a second person
gets in. **Every colleague gets their own username** — one account per person,
never a shared login — created by `bin/create-user.php`, the CLI that spec §15
makes the only way to add an account (there is deliberately no HTTP endpoint
for it):
"""
    new_accounts = """## 6. Create user accounts and enrol desktop machines

`create-admin.php` is single-use by design, so it is not how a second person
gets in. Create additional accounts with `bin/create-user.php`; there is
deliberately no public HTTP endpoint for user creation. **One username per
human is strongly recommended** because audit events can then identify who
made a change. The server nevertheless supports multiple simultaneous sessions
and multiple desktop machines for the same username when a shared account is
operationally necessary:
"""
    text = replace_once(text, old_accounts, new_accounts, "account section intro")

    old_role = """* `--role=user` is the **non-administrator**: it reads everything and creates
  and edits cases, but it may not write `settings`, open or close a period,
  delete a record, enrol a device or run an import (spec §7). Use
  `--role=admin` only for somebody who really administers the installation.
"""
    new_role = """* `--role=user` is the **non-administrator**: it reads common CRM data and
  creates and edits cases, but it may not write administrator settings, open
  or close a period, delete protected records, or run a legacy import. It can
  self-enrol and revoke its own desktop machines. Use `--role=admin` only for
  somebody who really administers the installation.
* A user can sign in on more than one PC at the same time. Each PC receives a
  distinct `sync_device_id` and device refresh-token family, so one machine can
  be revoked without disabling the others.
* A shared username is supported, including simultaneous use from two PCs, but
  it weakens human attribution in the audit trail. Prefer separate usernames
  whenever you need to know which person performed an action.
"""
    text = replace_once(text, old_role, new_role, "role and multi-device wording")

    old_connect = """## 9. Connect the desktop client

Set the panel's sync endpoint to `https://api.<domain>/v1` and log in with
the administrator from step 5. The first push from an empty host is the
one-shot import (spec §8): it is accepted exactly once per tenant, replays
byte-for-byte on retry, and every later import is answered
`409 DATASET_NOT_EMPTY`. After it lands, `tenant_state.bootstrap_status`
is `done` and `source_installation_id` records which installation the data
came from.

---

## 10. Backups, restore and rotation
"""
    new_connect = """## 9. Connect the desktop client

Set the panel's sync endpoint to `https://api.<domain>/v1` and log in with a
user account. On a new PC the client self-enrols a machine owned by that user;
the resulting device credential is separate from the user's browser/login
session. The same username may be active on multiple enrolled PCs at once.

For a genuinely empty server, the existing bootstrap path remains a one-shot
initial import (spec §8): it is accepted exactly once per tenant, replays
byte-for-byte on retry, and every later bootstrap import is answered
`409 DATASET_NOT_EMPTY`. After it lands, `tenant_state.bootstrap_status` is
`done` and `source_installation_id` records which installation supplied the
initial dataset.

Do **not** weaken or bypass that one-shot guard to merge old customer files
into a populated server. Use the reviewed Legacy Migration Center below.

---

## 9.5. Migrate a legacy local CRM database (v1.13.1 or older)

The browser migration center is for old local `crm_store.json` databases from
version **1.13.1 or older**, including stores that predate a formal version
marker. It is separate from `/bootstrap/import` and is safe to use when the
online tenant already contains CRM rows.

### Before opening the migration window

1. Apply every host migration and verify the install:
   ```sh
   php bin/migrate.php
   php bin/migrate.php --status
   php bin/smoke-test.php
   ```
2. Take a fresh server database backup and keep the original legacy JSON file
   unchanged. The legacy file contains customer PII; do not paste it into logs,
   tickets, chat rooms, or source control.
3. In `config/config.php`, temporarily enable the migration surface:
   ```php
   'legacy_import_enabled' => true,
   ```
   It is `false` in `config.example.php` by design. Both the page and every
   `/v1/legacy-import/*` API endpoint enforce this switch server-side.
4. Open `https://api.<domain>/legacy-import.php` over HTTPS and sign in with an
   **administrator** account. The page keeps the user access token in browser
   memory only; it does not use cookies, localStorage, or sessionStorage.

### Analyze and review

1. Select the old `crm_store.json`. The browser checks JSON syntax and the
   configured import size limit, then sends it to `POST /v1/legacy-import/analyze`.
2. Analyze is a dry run with respect to live CRM tables. The server normalizes
   the old schema, stores staged normalized records, records the source
   SHA-256, and classifies rows as create, skip, conflict, invalid, or pending.
   The raw uploaded JSON text is **not** stored in the database.
3. Check the summary counts and expand staged rows when you need to inspect the
   normalized source values. Exact or safe matches may already be classified as
   skip; uncertain matches are never silently merged.
4. Resolve every conflict or invalid row explicitly. Available review decisions
   are create, merge, skip, and reject where valid. Merge/skip requires a live
   target UUID. If the server found multiple candidates and therefore supplies
   no target, **do not guess a UUID**: independently verify the intended live
   record, or choose create/reject.
5. Financial transaction rows are append-safe. The legacy transaction sequence
   is not authoritative on a live server; apply locks the customer ledger and
   allocates the next server sequence instead of overwriting an existing entry.

### Apply, reconcile, and close the window

1. Apply is enabled only when the job has zero unresolved staged rows. The
   final write runs in one database transaction: accepted rows commit together
   or the database rolls the whole apply back on an invariant failure.
2. A completed job is replay-safe. Re-applying the same job, or analyzing the
   exact same source file again for the same tenant, does not duplicate the
   migration.
3. Before declaring success, reconcile the old source and online dataset:
   customer, owner, device/case, period and transaction counts; customer
   balances; case stages; customer-device and owner-device links; and done,
   closed and problem totals. Financial sums must match exactly after accounting
   for transactions that were deliberately rejected during review.
4. Immediately close the migration window in `config/config.php`:
   ```php
   'legacy_import_enabled' => false,
   ```
   Reload `https://api.<domain>/legacy-import.php`; it must now return `404`.
   The API routes are disabled by the same switch on their next request.

If a browser request is interrupted, reload the page, sign in again, and resume
with the migration job UUID shown in the review. Do not edit staging tables or
live CRM tables manually to "finish" an interrupted job.

---

## 10. Backups, restore and rotation
"""
    text = replace_once(text, old_connect, new_connect, "desktop and migration runbook")

    text = replace_once(
        text,
        "| `401 AUTH_REQUIRED` on `/sync/*` | no device token, or a device token where a user token is required | the client must enroll first (`POST /sync-devices/enroll`) |\n",
        "| `401 AUTH_REQUIRED` on `/sync/*` | no live device credential, or the wrong token kind was sent | sign in again and let the client self-enrol its machine (`POST /sync-devices/self-enroll`) |\n"
        "| `403 PERMISSION_DENIED` on `/legacy-import/*` | the temporary legacy migration surface is disabled | enable `legacy_import_enabled` only for a reviewed migration window, then turn it off again |\n"
        "| `404` on `/legacy-import.php` | migration mode is disabled, or the page is not present in the deployed package | this is expected after migration; enable the switch only when intentionally migrating |\n",
        "troubleshooting auth and migration",
    )

    INSTALL.write_text(text, encoding="utf-8", newline="\n")


def patch_config() -> None:
    text = CONFIG.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "        'max_import_body_bytes' => 16777216, // POST /bootstrap/import\n",
        "        'max_import_body_bytes' => 16777216, // bootstrap + legacy migration analyze\n",
        "import body comment",
    )
    CONFIG.write_text(text, encoding="utf-8", newline="\n")


def verify() -> None:
    install = INSTALL.read_text(encoding="utf-8")
    config = CONFIG.read_text(encoding="utf-8")
    required = [
        "003_server_crm_v2_device_auth.sql",
        "multiple simultaneous sessions",
        "A shared username is supported",
        "POST /sync-devices/self-enroll",
        "## 9.5. Migrate a legacy local CRM database (v1.13.1 or older)",
        "legacy_import_enabled' => true",
        "legacy_import_enabled' => false",
        "The raw uploaded JSON text is **not** stored",
        "Financial sums must match exactly",
        "it must now return `404`",
    ]
    for needle in required:
        if needle not in install:
            raise RuntimeError(f"missing documentation invariant: {needle}")
    stale = [
        "never a shared login",
        "enrolment is admin-only",
        "delete a record, enrol a device or run an import",
        "applies 001_initial.sql",
        "one row, checksum matches the file",
    ]
    for needle in stale:
        if needle in install:
            raise RuntimeError(f"stale documentation remains: {needle}")
    if "bootstrap + legacy migration analyze" not in config:
        raise RuntimeError("config import-size comment was not updated")


def main() -> None:
    patch_install()
    patch_config()
    verify()
    print("phase5 migration documentation aligned")


if __name__ == "__main__":
    main()
