# Changelog

All notable changes to this project are documented here.
This project uses [Semantic Versioning](https://semver.org/).

## [1.15.0] - 2026-10-15

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

## [1.14.0] - 2026-10-08

### Added

- **Real-Time Online Multi-User Collaboration Mode in CRM.**
  - Instant synchronization between colleagues working on the same account.
  - Zero-latency mutation kick (0ms) and reduced 2.0s worker sync interval.
  - Dynamic 2.5s frontend refresh polling when in online mode.
  - Header pill and Cloud tab status reflecting live "Online Database" operation.
  - Safe, local-first execution keeping background inquiry/registration robots robust and untangled.
- **Smart Initial Data Merge on Onboarding.**
  - Eliminated the `409 DATASET_NOT_EMPTY` blocker on first login.
  - Clicking «انتقال و ادغام پرونده‌های محلی با سرور» automatically queues local records into the outbox for a safe, non-destructive upsert merge with server data.
- **Automated 4-Hour Database Backup to Telegram.**
  - Added standalone host backup script (`host/bin/backup-to-telegram.php`) designed for cPanel cron jobs.
  - Secure PDO table dump + gzip compression + SHA256 checksum + direct Telegram document upload.
  - Concurrency safety with `flock` and temporary file cleanup.
  - New admin route `POST /v1/admin/backup` and panel button «پشتیبان‌گیری فوری ابری به تلگرام» for on-demand backups.

## [1.13.1] - 2026-10-07

### Added

- **Period-based Case Grouping in CRM Devices Tab.** When viewing "All Periods"
  («همهٔ دوره‌ها») in the CRM Devices tab, cases are now grouped into structured
  period cards instead of a single mixed table. Each period group features:
  - Distinct colored border and leading accent bar from an 8-color system palette.
  - Header badge with Persian ordinal title (e.g. «دورهٔ اول»، «دورهٔ دوم») or custom label.
  - Active/closed status pill, date range, and filtered case count.
  - Independent 1-based row numbering per period.
  - Cases without a period are grouped in a neutral card at the bottom.
  - Direct button to open period details modal (`dlgPeriod`).

### Fixed

- **Host Telegram Relay Multipart File Uploads on Shared Hosting.** Resolved
  cURL `there is no photo in the request` failure on cPanel shared hosting:
  - Fixed `telegram.php` cURL option order where `CURLOPT_POST => true` was
    inadvertently resetting `CURLOPT_POSTFIELDS` multipart form-data encoding.
  - Moved uploaded files to local project temp directory (`var/tmp` / `__DIR__`)
    before passing to `CURLFile` to prevent cURL access blocks by `open_basedir`.
  - Added dual upload transport: native multipart alongside automatic Base64
    payload decoding (`photo_base64`), ensuring 100% receipt photo delivery to Telegram.
- **Ambient System Proxy Bypass for Host Relay.** Configured `proxies={'http': None, 'https': None}`
  for host relay mode in `telegram_notify.py` and `panel.py` so desktop panel requests
  reach `api.oneserver.in` directly without being disrupted by local VPN/proxy drops.

## [1.13.0] - 2026-10-07

### Added

- **Host Telegram Relay API (`host/public/telegram.php`).** Dedicated secure PHP relay
  running on cPanel host. Allows desktop panels in restricted network environments to
  deliver messages, notifications, and receipt photos to Telegram without third-party
  VPNs or client proxies. Supports multipart file uploads (`CURLFile`), bot token
  validation, and optional `X-Relay-Secret` authentication.
- **Tri-Mode Telegram Connection Selector.** Added configuration and testing support
  for three connection routes in `telegram_notify.py` and `panel.py`:
  - `host`: Secure host API relay forwarder.
  - `proxy`: Custom client-side SOCKS5/HTTP proxy.
  - `direct`: Cloudflare Worker reverse-proxy or direct Telegram API.
- **Dedicated Telegram Settings in CRM.** Added configuration card in CRM Settings
  tab featuring mode switching, secret token protection, credential persistence, and
  an online connection test button (`/telegram-test`).

### Fixed

- **Form Input Reset in CRM Cloud Sync Tab.** Replaced full `renderBody()` innerHTML
  destruction during 5-second background sync polls with non-destructive `paintCloud()`,
  preventing loss of typed operator input on connection and credentials fields.
- **CRM Handed Stage Transition.** Corrected transition action in `panel.py:stageContinue()`
  for `handed` stage from invalid `__start_payment` to `to_payment`, aligning with
  the backend `crm.py` state machine table.
- **Case Detail Navigation Across All Tabs.** Added case detail inspection buttons and
  unique DOM row IDs (`devrow-{id}`) to completed (`done`), problem (`problem`), and
  closed (`closed`) tabs.
- **Chromium HTML5 Input Validation.** Fixed periodic polling interval input in
  `periodicHtml()` to supply raw ASCII integer values instead of Persian localized
  digits, preventing browser validation errors.
- **Live Signature Synchronization.** Updated `dlgCaseSig()` to incorporate customer
  and passenger entity attributes, ensuring modals refresh live when associated entities
  are updated.

## [1.12.1] - 2026-10-06

### Fixed

- **Data-loss prevention on fresh server connection (Zero-Data Guard).** Added
  `RemoteNotReadyError` in `cloud_sync.apply` and `panel.py`. When connecting
  to an unseeded or pending cloud backend, the local CRM store is strictly
  protected: empty server snapshots will never wipe non-empty local files.
  Background worker logs the condition as `remote_not_ready` without touching
  disk.
- **Dangling foreign key sanitization during one-shot import.** Legacy local stores
  with dangling references on nullable foreign key columns (`customer_id`, `owner_id`,
  `period_id`, `device_id`) are safely sanitized to SQL `NULL` (`None`) during
  `_validate()`. Prevents `UnresolvedReferenceCloudError` and MySQL error 1452 aborts
  while keeping non-nullable constraints fail-closed.

### Added

- **Relocated Cloud Sync directly into CRM interface.** Moved the entire Cloud Sync
  status, enrollment, manual sync trigger, one-shot import, and conflict resolution
  interface into a dedicated tab (`سرور ابری`) in `CRM_PAGE`. Added live cloud
  connectivity pill in the CRM header.
- **Colleague account creation guide.** Step-by-step visual tutorial directly inside
  the CRM Cloud tab explaining how to create new operator users via
  `php bin/create-user.php` on the server and connect colleague machines seamlessly.

## [1.12.0] - 2026-10-06

### Added

- **Multi-machine database synchronization with cPanel host.** Users and CRM
  cases now sync across machines through a centralized MySQL database on
  cPanel hosting (`api.oneserver.in`). Desktop panels synchronize changes
  locally and seamlessly propagate mutations to all connected systems.
- **cPanel host package (PHP 8.1 API).** Standalone, framework-free REST API
  designed for shared hosting environments with MySQL loopback binding.
  Includes 18-table relational schema (`001_initial.sql`), migration runner
  (`migrate.php`), administrator bootstrap (`create-admin.php`), user creation
  (`create-user.php`), health check (`smoke-test.php`), and a secure web-based
  installer (`setup.php`) protected by `setup_key` for shared hosting without
  SSH access.
- **Durable client outbox and state machine.** Append-only `outbox.jsonl` with
  atomic compaction and `os.fsync` durability guarantees. Local mutations are
  enqueued immediately and pushed to the cloud backend with exponential jittered
  backoff.
- **Dual-token authentication and Windows DPAPI storage.** Memory-only 15-minute
  access JWTs and 256-bit rotating refresh tokens. Tokens are securely encrypted
  at rest using Windows DPAPI (`CryptProtectData`) restricted to the current user SID.
- **7-day offline lease.** Operators can work completely offline for up to 7 days
  without disruption. Upon lease expiration, the panel gracefully enters read-only
  mode until network re-authentication.
- **Optimistic Concurrency Control (OCC) and conflict resolution UI.** Concurrent
  edits surface as structured `409 VERSION_CONFLICT` errors rather than silent
  overwrites. Operators can inspect differences in the panel UI and select either
  `keep_local` (re-enqueued with fresh operation ID) or `accept_server`.
- **One-shot bootstrap import.** Single-transaction migration of legacy local
  JSON databases to the cloud store with pre-flight atomic backup (`O_EXCL`),
  SHA-256 payload digest, and server-side lock.
- **Panel UI cloud sync surface.** Real-time sync status pill, device enrollment,
  manual sync triggers, and conflict diff viewer styled to match IRICA design conventions.

### Security

- Argon2id password hashing with constant-time verification.
- DDL-restricted database accounts (`SELECT, INSERT, UPDATE, DELETE` only).
- CSRF, Host, and Origin checks enforced across all state-changing endpoints.
- Strict PII, credential, and token redaction across logs and error responses.

### Tests

- Added 10 test modules covering client transport, outbox, auth, mapper, state
  machine, conflict resolution, host API, schema consistency, and integration.
- Full test suite verified green across 2,118 tests.

## [1.11.1] - 2026-09-30

### Fixed

- **A POST the panel answered no longer reaches the browser as a connection
  error.** The body was read only by the routes that wanted one, so three exits
  answered with the request's bytes still sitting in the socket: the login
  gate's 401, `/driver-update` (whose handler never looks at a body), and
  `do_POST`'s own exception handler. Windows closes a socket that still holds
  unread receive data with RST rather than FIN, and the client's in-flight read
  then dies with `WSAECONNABORTED` — the page showed a bare network failure
  where the route had sent a real status. Pressing «به‌روزرسانی درایور
  مرورگر» with an expired session was the case that reproduced it (16 runs in
  30). `_consume_body` now reads the body once, before any route runs, and every
  route shares the copy; the reads that used to happen per route are unchanged
  in behaviour (no `Content-Length`, or `0`, still parses to `{}`).
- **That read is bounded on both axes.** A declared `Content-Length` above
  `MAX_POST_BODY_BYTES` (1 MiB) is answered `413` before a single byte is read —
  refused, not truncated, since a truncated body would reach the route as valid
  JSON that had silently lost fields — and a body that stops arriving is given
  up on after `POST_BODY_READ_TIMEOUT` (10 s) with `408` instead of holding a
  worker thread for as long as the client keeps the socket open. Both answers
  are deliberate RST cases: waiting out a body the panel has already refused is
  what the cap exists to prevent.
- **A missing `chromedriver_updater` no longer silences the repair.**
  `maybe_update_chromedriver` imported the module *after* recording the attempt,
  so a bundle shipped without it burned the 15-minute cooldown and returned
  `None` with nothing anywhere to say why: no repair for the rest of the window,
  and no way to connect a launch that failed on a version mismatch to a missing
  file. The import now comes first (an `ImportError` costs no cooldown) and
  prints `!!! ChromeDriver auto-update is unavailable`. The per-process latch
  stays claimed, so it is one line per process, not one per launch.
- `verify_windows_release.py` walks lazy imports transitively. Scanning only the
  spawned scripts and the entrypoints missed a whole class of bundle defect: a
  module reached *through* another lazily-imported module was never derived, and
  `chromedriver_updater.py` sits exactly there. Measured on the v1.11.0 bundle:
  the old derivation found 8 candidates and reported nothing absent with the
  file withheld; the new one finds 10 and reports `['chromedriver_updater']`.
  The `APP_FILES` comment in `build_windows_release.py` also named the wrong
  line numbers for the two lazy imports (they are `captcha_collector.py:911`
  and `:971`) and claimed the verifier row made the entry redundant, which is
  false: the row checks the bundle, `APP_FILES` is what builds it.

### Tests

- `test_driver_update_panel` gains 5 tests over the drain: the body is already
  read when the gate runs (so the 401 path is covered), a rejected POST is
  drained, a bodyless POST still reaches the route, an oversized declared body
  is answered `413` without being read, and a body that stops mid-delivery is
  answered `408`.
- `test_driver_autoupdate_hook` gains the missing-module case: no cooldown
  marker, no cooling-down state, one Persian-free `!!!` line on stdout.
- Suite: `Ran 1489 tests` before, `Ran 1495 tests` after, all green.
  `test_driver_update_panel` run 20× in a row: 0 failures (the RST symptom was
  16/30 before the fix).

## [1.11.0] - 2026-09-30

### Added

- **The service repairs its own ChromeDriver.** When Chrome auto-updates, the
  bundled driver goes stale by one major and every robot dies with
  `SessionNotCreatedException`; until now the operator had to find and replace
  `chromedriver.exe` by hand. `check_driver_compat` now gives a detected
  mismatch one bounded chance to repair itself before it prints the Persian
  warning, and `maybe_update_chromedriver` runs on the robot launch path. A
  repair never raises: a failure is reported and the launch proceeds against
  the old driver.
- **`chromedriver_updater.py`**, which resolves the installed Chrome's major
  from the catalogue in `last-known-good-versions-with-downloads.json` /
  `latest-versions-per-milestone-with-downloads.json`, fetches the matching
  `win64` build from Chrome-for-Testing, and installs it. Every request goes
  through the local HTTP CONNECT proxy (`127.0.0.1:18081`) that the Telegram
  service already runs. There is deliberately **no** direct-connection
  fallback: Chrome-for-Testing answers a direct request from Iran with 403, so
  a missing proxy is a reported error and never a silent downgrade.
- **A «به‌روزرسانی درایور مرورگر» button** on the launch page, posting to a new
  `/driver-update` route backed by `update_chromedriver_now`. The route answers
  JSON for every outcome — `updated`, `up-to-date`, `busy`, `disabled`,
  `no-browser-version`, `driver-in-use`, `failed` — and the page renders the
  verdict beside the button. A manual click bypasses the per-process latch and
  the cross-process cooldown (a person asked and is waiting) but not the
  in-process busy latch nor the cross-process lock, so it can never download
  alongside a robot already doing so.
- **`IRICA_NO_DRIVER_UPDATE=1`** turns the whole feature off.

### Changed

- **Atomic install.** The archive is downloaded to a temp file, checked to be a
  zip, checked to hold `chromedriver.exe`, and that binary's `--version` is
  checked to equal the exact CfT build that was requested; only then is the
  current file staged as `.bak` and `os.replace`d in place. A failed download
  can never leave a half-written `chromedriver.exe`. `PermissionError` on the
  replace is split by `winerror` (32/33 = the image is running, 5 = read-only
  destination) so the operator gets the right advice.
- **Cross-process single-flight.** An `msvcrt` byte-range lock beside the
  cooldown marker, refused immediately with `LK_NBLCK`; the kernel releases it
  when the holder dies, so a robot killed mid-update cannot wedge the updater.
  An unopenable lock file still allows the attempt, so a read-only data
  directory degrades to "no lock" rather than "never update".
- **Bounded fetch.** One wall-clock budget per attempt, five attempts with
  jittered exponential backoff, permanent statuses (400/401/403/404/405/410/451)
  not retried. `requests`' timeout is a per-read stall allowance rather than a
  total, so every request is handed `min(nominal, budget left)`; the launch path
  therefore never allows the nominal 180 s. The automatic path gets a 90 s
  budget, and a 15-minute cooldown follows an attempt.
- `build_windows_release.py` ships `chromedriver_updater.py` in the bundle and
  `run_panel_tests.py` registers the new test modules.

### Tests

- 100 new tests: version resolution and catalogue parsing, the mandatory-proxy
  rule, the verification chain and atomic swap, cleanup after a failed
  download, the `.bak` staging and the `winerror` split, the cross-process lock
  (including release when the holder is killed, and the unopenable-lock
  degradation), the kill switch, the launch-path hook with its latch and
  cooldown, and the panel route and button verdicts.
- Suite: `Ran 1389 tests` before, `Ran 1489 tests` after, all green.

## [1.10.1] - 2026-09-25

### Fixed

- **The payment-stage receipt message now reaches every destination.**
  `_fanout` handed every chat the SAME absolute deadline and `_post_confirmed`
  gave the first one the whole remaining budget, so the ~1.4 MB receipt capture
  burned it on a slow link and the remaining chats raised "deadline reached
  after 0 attempts" — never attempted — while the call still returned success
  and the robot printed «ersal shod» with nothing in `logs.jsonl`. The ~150 KB
  payment-link screenshot fit the budget, which is why that one arrived and the
  receipt did not. Each destination now gets its own equal slice of what is
  left of the caller's budget, through the existing `deadline=` kwarg;
  `_post_confirmed` is unchanged.
- **A big photo is shrunk before it is uploaded** (2000 px longest edge, JPEG
  quality 85, only above 300 KiB), once per `send_photo` and not per attempt.
  The file on disk stays byte-identical and any transcode failure falls back to
  uploading the original, so a missing or broken Pillow cannot break a send.
  A full-page receipt capture (~1.4 MB) leaves as under a sixth of that.
- **A missed destination is no longer silent**: one `>>> telegram [NAGHS]` line
  plus one JSONL record in `telegram_delivery.jsonl` (capped at 400 lines) when
  at least one destination did not take the message. A send that reached
  everyone writes nothing, exactly as before.
- **The bot token can no longer reach a log, a record or a raised message**:
  `requests` embeds `/bot<token>/<method>` in its exception text, so the token
  and its URL-quoted form are redacted before truncation in the per-destination
  line, the delivery record and the exception detail.

### Tests

- 32 new tests under `lab/tests/`: budget slices and starvation, the shrink path
  and its fallbacks, the delivery record, the token redaction, and the receipt
  path end to end through `gomrok._telegram_deliver` over a loopback fake API.
- `test_telegram_fanout_budget.py` loads the immutable pre-fix blob of
  `telegram_notify.py` (blob id + sha256 pinned, hard error on mismatch) and
  fails against it with the exact "0 attempts" text the colleagues saw.
- Suite: `Ran 1357 tests` before, `Ran 1389 tests` after, no MISSING/EMPTY,
  with the live data directory byte-identical over every run.

## [1.10.0] - 2026-09-24

### Added

- **A period filter on every case list** (operator request): the four case-list
  tabs — devices, done, problem and closed — share a second filter dimension
  beside the stage chips. «همهٔ دوره‌ها» is the tab's own set and therefore the
  unchanged default; «دورهٔ فعلی» is the live set (in-flight cases plus
  everything registered in the open period, its finished ones included); and
  each period gets a chip, newest first, so a closed period's cases are
  reachable as a list at every stage. Both filters compose with the per-tab
  search, and the query survives a period change.
- **The stage chips follow the period filter.** The chip row is built from the
  filtered base set rather than from the in-flight stages alone, so a selected
  period gains chips for its finished stages (problem / done / closed) —
  without them a period that holds no in-flight case would list its rows with
  no way to isolate one. A stage filter that the new period set cannot produce
  is released to «همه» instead of leaving an empty list with no active chip.
- **An optional Telegram report channel** (operator request): a new
  `report_chat_id` setting, editable in the settings tab, receives a copy of
  every report — the cases report, the finance report, the customer statement —
  and of every inquiry-result message and result screenshot from the gomrok and
  hamta robots.

### Changed

- **Report delivery is additive.** `telegram_notify.send_message` and
  `send_photo` gained `extra_chat_ids`; the configured chat list keeps
  receiving everything it received before, and a configured channel only ever
  gets an additional copy. An empty setting leaves the target list byte for
  byte what it was, a destination that is also in the configured list is
  deduplicated, and one dead destination cannot take a report down with it
  (`_fanout` reports that destination's failure and still delivers to the
  rest).
- **The registration handoff keeps its single destination.** It passes
  `chat_id` (exactly one recipient, extras ignored), because it carries
  passenger personal data; `gomrok.py` is untouched.

## [1.9.1] - 2026-09-23

### Added

- **The inquiry robots now capture the result itself** (operator request):
  until now the panel stored the verdict as text only, and the only image a
  verdict ever produced was a captcha. Each robot now screenshots the result
  element at the moment it renders — on hamta the SweetAlert2 modal
  (`div.swal2-modal`), on gomrok the Wicket feedback panel
  (`[wicketpath$="feedBack_container_error"], .feedbackPanelERROR`) — falling
  back to the full page, and then to nothing, so a capture failure never costs
  the verdict. A new `estelam_shot.py` module owns the path derivation, the
  scroll, the PNG validation and the send, and is imported by both robots as a
  sibling — `gomrok.py` is untouched. Bytes are checked against the PNG magic
  before they are written, so a driver that returns garbage leaves no file
  behind and reports failure instead.
- **One newest screenshot per device per service:** the path is derived from
  the service, the device id and the serial, so each new capture overwrites the
  last one rather than accumulating history. The two services keep separate
  files (`estelam_gomrok_…`, `estelam_hamta_…`) and separate store fields
  (`gomrok_screenshot`, `hamta_screenshot`).
- **An exact capture of the result element, and only that, reaches Telegram.**
  The photo is attached with the report as its caption; the whole-page
  fallback never leaves this machine, because a full-page gomrok capture
  still shows the traveler's national ID and birth date and the send fans
  out to every configured chat, so a page-level picture stays panel-only
  evidence. The plain text report goes alone whenever the capture is missing,
  is not exact, or the upload fails, and a caption is always the previous
  report, byte for byte.
- **Two camera icons per device row** (operator request): the inquiry page
  renders one per service inside its own status grid (`shotBtn(svc)`, gomrok
  and hamta separately, styled by `.stgrid .ibtn.sh`), and the CRM case list
  renders the same pair (`caseShotBtn(d,svc)`). Clicking one opens a modal
  with the image, a download button and a load-failure message. Where the two
  differ is deliberate: the inquiry page reads the device's own store field,
  because `/estelam-state` returns `estelam_load()` verbatim, while the CRM
  state payload forwards only the booleans `has_gomrok_screenshot` and
  `has_hamta_screenshot` (never a capture path), so that button gates on a
  flag and the route stays the single source of truth for the path. The image
  is served by a new containment-checked `/estelam-shot` route modelled on
  `/artifact`: the recorded path is resolved and has to sit inside one of two
  accepted roots, the `screenshots` subdir of the data directory or a
  legacy `screenshots` folder inside the app's own release folder, because
  paths recorded by an older release point inside that release folder. A store
  field inside neither root serves nothing.
- **Four offline suites now cover the capture path** (no browser and no
  network): `test_v1_9_1_capture` drives `estelam_shot.capture_result` and
  both robots against a fake driver; `test_v1_9_1_screenshot` covers the
  store field round trip and the inquiry page's camera icon;
  `test_v1_9_1_routes` pins the `shot_resolve` contract class by class
  (empty field, a real file inside the root, traversal that leaves it, a
  sibling directory whose name only starts with the root, the legacy
  in-release root, a path on another drive) and the route's negative answers
  over real HTTP on an ephemeral port (the 302/401/404 gate, nosniff, and
  the log records); `test_v1_9_1_crm_shot` covers the CRM button's gate
  on the presence flags rather than a path, the dialog's markup, and the
  delete path, where the row goes first and a failing unlink is logged
  instead of raised. All four are registered in `run_panel_tests.py`.
- **Two files joined the release bundle, and their absence fails in opposite
  ways.** `estelam_shot.py` is now in the bundle file list in
  `build_windows_release.py` and in the release verifier's required files;
  `log_utils.py` joined the bundle list too. A build without `estelam_shot.py`
  fails silently: both robots import it inside the blanket handler whose whole
  purpose is to stop a bad capture from swallowing a verdict, so the inquiry
  still completes, each capture logs a failure line, no camera icon ever
  appears and the reports go out as text only. A build without `log_utils.py`
  is the loud case instead, because `panel.py` and `crm.py` import it with
  no guard, so a clean install raises `ImportError` on the first log write.

### Fixed

- **Re-queuing a device no longer pins the last verdict's screenshot to it.**
  `crm_sync_queue` reopened the status and result slots but left the evidence
  slot populated, so a run killed before it reached its own write-back showed
  the previous verdict's image beside a pending status. `gomrok_screenshot`
  and `hamta_screenshot` now reset with the rest, and only for the service
  being queued.
- **A capture failure can no longer swallow the verdict message.** Capture and
  Telegram are in separate `try` blocks and the outcome always carries a string
  `shot` key, so a capture that raises still sends the text report and still
  writes back a store field of the right type.
- **`capture_page` no longer imports the gomrok robot.** The hamta process
  keeps a narrow `sys.path` because `Hamta-solver/` and the gomrok `solver/`
  package share module names (`live_solve`, `config`, `vocab`, `preprocess`,
  `utils`); importing the robot there could alias the wrong solver. The CDP
  call is now direct, with `save_screenshot` as the fallback.
- **The offline test suite no longer touches the network.** `test_estelam_service`
  inherited a real `_capture_result_shot` and was making real Telegram attempts
  against a nonexistent PNG; the capture is now stubbed in the test harness.
- **Deleting a device deletes its captures.** The file name is keyed by the
  device, so a deleted row left its PNGs behind with nothing that could ever
  reach or overwrite them. The store row is removed first and the file is
  unlinked after it, so a failed unlink cannot keep the row alive; the failure
  is logged and never raised into the delete.
- **`/estelam-shot` no longer fills the robot log with false alarms.** A
  device with no capture and a store field pointing outside the roots both
  resolved to the same empty string, so every retry for a missing image wrote
  a security-flavoured record; `estelam_logs.jsonl` keeps only its newest 400
  entries, so a browser retrying a missing image could have evicted the real
  robot diagnostics. The two cases are now told apart, and the
  misconfiguration record carries the file name only, because the panel
  renders this log.

- **The case-detail and period-detail dialogs rendered as an empty box.**
  `openDlg(html, silent)` was called as `openDlg('<div …>', silent
  +'<h3>…' + …)` — the boolean `silent` was a term in the string
  concatenation, so `html` received only the opening `<div>` tag and every
  section after it was added to `silent` and discarded. Clicking «جزئیات
  پرونده» opened a 54px-tall modal holding nothing but the close button, and
  the period dialog was broken the same way. `silent` is now passed as the
  second argument, and a design gate rejects any `openDlg` call that puts it
  back inside the concatenation.

## [1.9.0] - 2026-09-22

### Added

- **Every user-visible list renders newest-first** (operator request): the store
  is append-only, so raw array order was oldest-first and a list that never
  sorted buried the newest row at the bottom. A `newestFirst(rows, stamp)`
  helper now sorts a COPY by the creation stamp — customers, owners,
  identities, the periodic-inquiry list, a period's open and closed cases, and
  the per-customer ledger. The comparison is a total order: stamp first, then
  the store index, because `_now()` is second-resolution and two rows really
  can share a stamp, in which case a pure timestamp sort is unstable and the
  list flips between two orders across the 5 s re-render. STATE is never
  mutated (STATE.devices also feeds the robots), and the ledger's inner
  transaction index is untouched, so only the outer customer order changes.
- **Row numbering in the passenger lists** (operator request): each owner row
  carries a Persian row number counting from the newest, with a matching
  `<th>ردیف</th>` header and bumped colspans.
- **The related-sites box sits bottom-left and is dismissable** (operator
  request): in RTL, `inset-inline-start` is the physical right, where the toast
  stack already lives, so the box overlapped the toasts. It moved to
  `inset-inline-end`, gained an × (`quickBoxHide()` persists
  `localStorage['irica-quickbox']='0'`), and is recovered from the settings
  tab. Dismissal is per-browser — hiding the buttons is a personal comfort
  while the list itself is shared.
- **The related-site buttons are server-backed:** they lived in localStorage,
  so a second machine never saw a link the operator had added and a browser
  data wipe lost them. They are now a `links` list in the shared settings
  (`crm.DEFAULT_SETTINGS` + a `_normalise_settings` merge that backfills the
  defaults for a store from before v1.9). The settings tab edits a draft
  (`draftLinks()` / `settingsLinksPaint`) that repaints only `#linkRows`, so
  unsaved edits in sibling settings cards survive add/remove. URLs must match
  `https?://\S{1,400}` — a `javascript:` URL in a `target=_blank` button would
  run in the panel's own origin — and duplicates are dropped; the batch is
  atomic, so one bad URL writes nothing. A present-but-empty list is a valid
  deliberate "no buttons", a missing or invalid one falls back to the defaults.
- **UI notification sounds** (operator request): one short cue per event
  family — save success, error, warning, modal/form open, tab switch, login
  success, login failure — served from a whitelisted `/sfx/` route (public
  because the login page needs a cue before a session exists; only the seven
  fixed names resolve, via basename + membership). The engine is gated by
  `sound_enabled` (default ON) with a header speaker toggle that mirrors it,
  rate-limited to 350 ms per family, silent when the tab is hidden, wrapped in
  a `catch` because a cue is decoration and never the signal, and the login
  page honours the same switch through a localStorage mirror. The 5 s
  background refresh cues nothing. Assets: Kenney "Interface Sounds", CC0 1.0,
  sha256-pinned and reproducible via `lab/scripts/gen_sfx.py`.

### Changed

- The settings tab's «نمایش» card gained the sound checkbox; the related-sites
  card was rebuilt around the draft row container. `crm_update_settings`
  coerces `sound_enabled` through the same boolean tuple as the other toggles.

## [1.8.1] - 2026-09-21

### Added

- **A case cannot be created outside a reporting period (operator rule):** while
  no period is open, «+ پروندهٔ جدید» is marked unavailable (`aria-disabled`, so
  it stays focusable and the reason is reachable without a mouse) and explains
  itself on hover, on keyboard focus and, when clicked, in a toast —
  `dlgDevice()` refuses the same way. The period bar and both empty states
  (the toolbar note and the empty-list card) now state the rule instead of
  inviting an action that cannot run, and the wording follows the page's own
  vocabulary («دورهٔ باز», not «دورهٔ بازی»).

### Fixed

- **The in-flight spinner no longer dies with the list re-render:** the busy
  state was bound to the DOM element, and the 5-second re-render replaces every
  one of those nodes, so an action still running looked idle. It is now keyed to
  the action itself (accessible name + handler) and re-applied to the freshly
  rendered nodes: the spinner means "this action is still running" until the
  toast that settles it (the 6-second net still covers handlers that never
  toast). Open-only buttons are exempt, so they can never inherit a key.
- **The period dialog comes back:** opening a case from the period detail used
  to replace the dialog for good — and the case modal's own 5-second rebuild
  made even a hand-armed return useless, because it overwrote the origin with
  the case's id. The origin now lives on the case modal and survives a rebuild
  and a child-dialog round trip (dismissing the case returns to the period
  dialog, on the segment the operator was reading).
- **The period dialog refreshes itself:** it stayed frozen while everything
  around it updated. It now rebuilds on the same 5-second tick as the case
  modal, but only when something it actually PRINTS changed — the case fields,
  the customer and passenger identities, the money — so a robot stamping
  `updated` on a case no longer rebuilds the table every tick, and the reading
  position survives a rebuild that does happen. A vanished period closes it with
  a toast.
- **Closing a period from its own dialog dropped the operator on the tab:** the
  confirm replaces the dialog and the confirm path deliberately disarms the
  return, so the close callback now reopens it on the fresh state — unless the
  operator opened something else while the close was in flight.

### Changed

- **The rule is enforced where the write happens:** POST /crm-device
  (action=add) calls `crm.add_device(..., require_period=True)`, which checks
  for an open period INSIDE the store lock and before anything is written —
  a period closing concurrently can no longer slip a period-less case through,
  and a rejected intake leaves no orphan customer. The default remains
  `require_period=False`, so stores that predate periods, scripts and fixtures
  keep the legacy behaviour (an empty `period_id`) and no migration is needed.
- **Two long-broken tests repaired** (they were outside the suite runner, so
  their drift had gone unnoticed): `test_entrypoint_ui_fixes` had been reading
  the login form instead of the pages behind the v1.2.0 gate, and its
  empty-state pin had drifted onto the periods tab's own `if(!ds.length)`
  branch. Both are fixed and the module is registered in the suite.
- **Six pins hardened after a mutation review:** a reviewer reverted each new
  behaviour one at a time and six reverts still passed the suite (the busy
  repaint call moved before the render, the 6-second net deleted, the
  vanished-period branch made unreachable, the action key's handler half
  emptied, the case sync clearing the dialog origin, and the period check
  hoisted above the store lock). Every one of those mutations now fails the
  suite — 18 of 18 caught, verified against a mutated copy of the source.

## [1.8.0] - 2026-09-20

### Added

- **Periods tab (دورهها):** every reporting period is a card — name, open or
  closed, the date range, how many cases it holds (completed / in progress /
  closed), how many passengers are attached, how many customers it touches,
  and the case-linked debit and credit totals. The whole card is the way in:
  a button stretched over it carries the accessible name, so a click anywhere
  on the card opens the detail, while the card's own actions stay clickable
  above it and the focus ring is drawn on the target itself.
- **Period detail dialog:** a wide dialog with a segmented switcher
  پروندهها / مسافرها / مشتریها, a five-cell KPI strip, and tables that answer
  per case — which customer owns it, which passenger is attached («متصل») or
  none («بدون مسافر»), the case stage, its debit and credit columns, and a
  بدهکار / بستانکار / تسویه mark on the balance. The passenger view also lists
  the passengers that belong to no case at all («بدون پرونده»), so reviewing a
  cycle is also when the operator sees who is still free.
- **Icon action buttons:** every table row action in every tab — customers,
  owners, owner archive, devices, completed, problem, identities, periodic
  inquiry, ledger, reports and periods — is now an icon-only button in the
  house SVG language. Each carries an accessible name (`aria-label`) and a
  tooltip with the same text; destructive confirmations and dialog buttons keep
  visible Persian labels on purpose.
- **Shared tooltip layer:** one lazily-created `#tip[role=tooltip]`, positioned
  fixed so a scrolling table can never clip it, flipped below its trigger when
  there is no room above, clamped to the viewport, re-parented into an open
  dialog (a dialog paints above every z-index on the page), shown on hover
  after a short dwell and immediately on keyboard focus, and dismissed on
  leave, scroll, resize, press or Escape.
- **Micro-interactions:** 150 ms hover and 90 ms press feedback, an in-flight
  spinner that swaps in without moving the layout, and a reduced-motion variant
  that keeps the busy state visible without animating it.

### Fixed

- **The bundled chromedriver was a major behind Chrome:** the shipped driver
  was 151 while Chrome had auto-updated to 153, which stops every robot from
  starting. The bundle now carries the matching driver (153.0.8010.52).
- **A period card could not be opened by clicking it:** the stretched target
  sat below the card's own text blocks, so only the padding responded. The
  target now sits above the text and below the action row (verified in a real
  browser with `document.elementFromPoint`).
- **Two icon buttons looked inert on hover:** `.ibtn.ok`/`.ibtn.warn` set their
  own background, which out-ranked the shared hover rule; they now carry their
  own hover response.
- **The busy spinner was invisible under reduced motion:** the icon was hidden
  and the animation disabled, leaving a blank button. The glyph now stays,
  dimmed.
- **Reset-history looked like re-inquire:** «ریست تاریخچه» now uses its own
  glyph and the danger tint instead of sitting next to «استعلام مجدد» with a
  near-identical circular arrow and a louder colour than the non-destructive
  action.
- **A cancelled delete left the row icon spinning:** customer and identity
  deletion used the blocking native `confirm()`; they now use the styled
  confirmation dialog, so a cancel clears the busy state like every other
  action.
- **Period money could be read as the period's full cash:** the card and the
  KPI strip count only the ledger rows linked to the period's cases, which is
  not the same set the period finance report counts. The figures are now
  labelled «بدهکاری پروندهها / بستانکاری پروندهها» and the dialog states the
  difference in a footer note.
- **Tooltip lifecycle:** leaving a trigger (or the window) now takes the chip
  down, jumping between triggers no longer leaves a stale `aria-describedby`,
  and Escape dismisses the chip without swallowing the dialog's own Escape.
- **A focus ring that only worked on modern engines:** the period card's focus
  indication moved from a `:has()` rule to an outline on the target itself.

### Changed

- The completed tab's row actions are the icon set (edit / roll back to the
  previous stage); the period card's duplicate «جزئیات دوره» action was dropped
  because the card itself opens the detail.
- Card money labels name their scope, and the period detail dialog documents
  which rows it counts.

## [1.7.0] - 2026-09-20

### Added

- **Reporting periods (دوره):** cases are grouped into operator-closed
  batches. A period opens from the devices tab («شروع دورهٔ جدید»); every
  case registered while it is open carries its id, and «بستن دوره» locks
  the books so no new case can join it. Periods auto-number (دورهٔ اول،
  دوم …) and the open count is shown in the bar. Closing is deliberately
  not blocked by open cases — the unclosed count is surfaced instead.
- **Period finance report:** the finance dialog gains a «دوره» segment that
  aggregates exactly the cases of one period (receipts, new debits,
  balances). While the period is still open the report prints a warning
  banner «این دوره هنوز بسته نشده است؛ ارقام نهایی نیستند» in the HTML,
  text and Telegram bodies alike; closing the period removes it.
- **Owner archive (بایگانی مسافر‌ها):** passengers whose case reaches
  «تکمیل‌شده» leave the active owners tab and appear in a new archive tab
  with the device, serials, customer and code-delivery date. A stage
  rollback returns the passenger to the active list automatically; closed
  (مختومه) cases are not archived. The active tab shows a button with the
  archived count.
- **Per-case registry fee:** the new-case dialog now carries an editable
  «هزینه ثبت رجیستری» that defaults to the configured settings amount and
  may be changed for this case only. The settings value was already
  persistent; the dialog no longer silently overrode it with a hard-coded
  figure. Leaving the field empty means "use the configured amount"; an
  explicit 0 books a free case.

### Fixed

- **Owner save no longer errors with a raw `TypeError: Failed to fetch`
  (production report):** the POST handler had no safety net, so an exception
  raised mid-route (after the store write had already landed) aborted the
  socket and the browser reported a network error while the row was in fact
  saved. Every POST now answers JSON — a failure surfaces a Persian error,
  and the traceback is logged server-side. GET received the same safety net:
  a report route that raised used to drop the connection (the browser showed
  the raw fetch error) and now answers 500 with a Persian message.
- **The unsavable passenger (production report):** a national code that
  failed the mod-11 checksum produced a generic «کد ملی نامعتبر است» that
  hid the cause. The error is now specific — «رقم کنترلی کد ملی اشتباه
  است؛ رقم دهم را بررسی کنید» for a bad check digit and an exact-length
  message for a wrong digit count.
- **Inquiry order no longer clobbers a finished verdict (production
  report):** queuing a hamta inquiry reset the gomrok status of the same
  device to pending, so running گمرک then همتا wiped the «سالم» verdict.
  The queue sync now resets only the slot of the service actually starting;
  the other service's final result is preserved (verified both orders).
- **A fee typed with the panel's own separator was rejected:** the amount
  field is pre-filled by `fa()`, which groups digits with U+066C «٬», while
  the server stripped only ASCII/arabic separators. Saving an amount of
  1000 Toman or more from the settings tab therefore failed, and the new
  per-case fee field had the same hole. U+066C is now accepted on both
  paths; a negative or non-numeric amount is still rejected instead of
  being silently booked. The fee parser also stopped borrowing the
  received-amount wording («مبلغ دریافتی باید عدد نامنفی باشد») and names
  its own field.
- **A period report called itself «روزانه» and an unknown period id crashed
  the route:** the report heading now names the cycle it belongs to
  («گزارش مالی مشتریان: دورهٔ اول (باز)») with the date range on the
  sub-line, and the footer states how rows are counted. An id that no
  longer resolves answers 400 with «دورهٔ انتخاب‌شده پیدا نشد…» instead of
  aborting the request.
- **Archived passengers were listed by the wrong id:** `archived_owner_ids`
  returned device ids, so the archive tab and the active-passenger filter
  could disagree. Membership is now derived from a single helper, so the
  two views cannot drift.
- **A closed-period warning toast rendered as a plain success:** `toast()`
  gained a `warn` variant, so «دوره بسته شد: N پرونده؛ M پرونده هنوز باز
  است» now shows in the warning colour instead of looking like a clean
  success.

- **A closed period could still render as the open one:** the devices-bar
  badge trusted `settings.current_period_id` and never checked the period
  that id names, so a store carrying a stale pointer showed a closed cycle
  as open. The bar now resolves the id against the period list and requires
  it to be unclosed, and `open_period` re-adopts an unclosed orphan (a
  restore or an interrupted write that lost the pointer) instead of opening
  a second cycle on top of it.
- **One bad report reference answered 400 for every kind of failure:** the
  finance-report route caught a bare `ValueError`, so a server-side data
  problem was reported to the operator as "your period list is stale".
  `ReportRefError(ValueError)` now marks the client-facing case; anything
  else answers 500 with a Persian message and the traceback in the log.
- **The archive could list the same passenger twice:** a legacy store with
  two delivered cases on one owner produced two rows while the badge counts
  owners. The newest case wins, so the list and the count agree.
- **The period anomaly counter could be inflated:** a malformed ledger row
  with no usable case link was counted even when it belongs to no period of
  this cycle. Counting is now scoped exactly like the report rows it warns
  about (daily/weekly are unchanged).
- **The two amount fields did not share their first-pass guard:** the
  received-amount and the per-case fee now validate the raw text against
  the same input class, so a pasted `-5۰0` is refused before `digitsFa`
  can drop the sign.
- **A fee field holding only separators booked a free case:** clearing the
  digits of the pre-filled «۲۴٬۰۰۰٬۰۰۰» leaves «٬» behind; that is now read
  as "no override" (the configured amount applies), never as a silent 0.
- **The ledger note mixed an em dash into a name that has a Persian form:**
  the charge writes «هزینه ثبت رجیستری، <device>» with the house comma.
  Rows booked before this build keep the text they were stored with — the
  ledger is append-only and is never rewritten.
- **The test suite wrote the operator's live inquiry store:** several
  modules seeded `panel.ESTELAM_PATH` directly, so every suite run
  overwrote `%LOCALAPPDATA%\irica\estelam_store.json`. Each module now
  patches the path to a temporary file and cleans it up.

### Changed

- The settings registry fee is the single default; the new-case field is an
  explicit per-case override on the same atomic store write as the receipt.
- Report counting rule for a period: a transaction linked to a case counts
  by that case's period (so a late payment on an old case stays in its own
  period), while a transaction booked directly on the customer ledger with
  no case link counts by its own date. This keeps the cycle's manually
  recorded cash inside its own report, and the rule is printed in the
  report footer.
- The charge is named «هزینه ثبت رجیستری» everywhere it is shown to the
  operator, matching the ledger it writes to.

## [1.6.1] - 2026-09-15

### Added

- **Periodic-inquiry kill-switch in the tab itself (operator request):**
  the «استعلام دوره‌ای گمرک» tab now carries its own فعال/غیرفعال
  switch — a status pill plus a toggle button in the toolbar. While off,
  the scheduler starts no automatic inquiry (the pre-existing
  `scheduler_enabled` gate the server beat already honors), the tab
  shows a banner explaining the state, and the «استعلام بعدی» column
  reads «زمان‌بند خاموش» instead of a misleading countdown. Manual runs
  («شروع فوری استعلام», per-device buttons) keep working, and the
  settings-tab checkbox stays in sync.

## [1.6.0] - 2026-09-15

### Added

- **Amount received on case creation (operator request):** the new-case
  dialog (گام ۱) gains «مبلغ دریافتی (تومان)», default 0. A value above
  zero books a «دریافتی» transaction («دریافتی هنگام ثبت پرونده») on the
  linked customer in the same atomic store write as the auto registry
  fee, tagged to the case. Raw input is validated before digit
  normalization (a typed "-500" or "1.5" can no longer silently book
  500/15), and the submit button double-click-guarded.
- **Customer statement — «صورت‌حساب» (operator request):** a per-customer
  dialog with the classic تاریخ | شرح | بدهکار | بستانکار | مانده layout,
  a running balance after every row, range chips (همه / ۳۰ روز اخیر /
  ۹۰ روز اخیر), voided rows struck through, and چاپ/PDF/Telegram exports
  (self-contained RTL Vazirmatn document; partial Telegram send = 502,
  never a silent success). GET /crm-statement + POST
  /crm-statement-telegram.
- **Per-case invoice — «فاکتور» (operator request):** a button in the
  case modal opens a printable invoice: business header, شمارهٔ فاکتور =
  شناسهٔ پرونده, issue/creation dates (Shamsi), customer + device
  blocks, this case's debits and receipts, «ماندهٔ این پرونده» vs
  «ماندهٔ کل حساب مشتری», and a voided-rows note. GET /crm-invoice.
- **Transaction void — «ابطال» (operator request):** wrong entries are
  voided with a mandatory reason and a second confirmation; the original
  row is struck and a mirrored reversal row («ابطال، دلیل: …») is
  appended — history is never deleted. Voided pairs are excluded from
  EVERY balance and aggregate (JS bal(), customer_balance, finance
  report, statement, invoice) and a live fee/refund pair cannot be
  half-voided (phantom-credit guard). POST /crm-customer action=void_tx.
- **Business identity on printouts:** optional «نام کسب‌وکار» and
  «شمارهٔ تماس کسب‌وکار» in settings, printed atop the statement,
  invoice, and finance report documents when set.

### Fixed

- **Production (coworker report):** «شروع ربات پرداخت» failing with
  «پروفایل ثبت‌نام برای این دستگاه ساخته نشده است» while passengers
  were attached. Root cause: the profiles-store write fails on Windows
  while another process holds profiles.json open, and both error paths
  (attach hook, payment self-heal) swallowed the exception silently.
  Now: the atomic write retries with backoff, the heal retries the
  ensure three times, the 400 error carries the actual «علت: …», and
  profile_ensure_failed log events carry the exception detail. The dead
  national-code dedupe clause in crm_ensure_registration_profile was
  removed (serial-only by design — national matching would link profiles
  whose IMEIs belong to a different device).
- **Production:** voiding a customer's FIRST transaction (index 0) was
  impossible — the panel dispatcher fed the index through a normalizer
  that turns falsy input into an empty string.
- Deleting a device whose fee was already voided no longer books a
  duplicate refund (double-credit guard).
- The printed statement now shows the «ماندهٔ اول» VALUE (was
  label-only), and rows with unparseable dates are excluded consistently
  by every surface with a visible «N تراکنش با تاریخ نامعتبر
  نادیده‌گرفته شد» note.

## [1.5.0] - 2026-09-15

### Added

- **Customer finance reports, daily & weekly (operator request):** a
  «گزارش مالی» button in the customers toolbar opens a report dialog
  with a روزانه/هفتگی switch, previous/next period navigation and a
  امروز/این هفته reset (all date labels Shamsi, computed server-side).
  Headlines: cash receipts («دریافتی‌های نقدی (واریزی)»), new debits
  («بدهکاری‌های جدید») and the total customer balance split into
  بدهکار/بستانکار. Per-customer rows run ماندهٔ اول → بدهکاری /
  بستانکاری → ماندهٔ پایان with a two-segment activity bar; weekly mode
  adds a 7-cell شنبه..جمعه day strip, plus the period's full
  transaction list with kind labels. Exports: چاپ (self-contained RTL
  print document with Vazirmatn), PDF, and Telegram send — a partial
  Telegram send is a 502 with sent/total counts, never a silent
  success. Aggregation lives server-side only
  (`crm.finance_report_aggregate`); totals cover ALL customers while
  the table lists period-active ones; malformed timestamps are counted
  and surfaced («N تراکنش با تاریخ نامعتبر نادیده‌گرفته شد»), and the
  report notes balances are «بر اساس مشتری‌های فعلی» (deleting a
  customer shrinks past reports).
- **Passenger detach with double confirmation (operator request):** the
  passengers tab shows «قطع اتصال» for every bound passenger whose case
  is not تکمیل‌شده. The modal shows passenger, national ID, device +
  serials, customer and current stage. Allowed stages (اتصال مسافر /
  دارای اشکال / مختومه) get the 1:1 warning plus a second
  confirmation; active post-handover cases get guidance instead (roll
  back to گام ۳ or close the case) because freeing a passenger
  mid-registration risks burning it. The server action `detach_owner`
  clears the link AND the registration-profile link (profile kept but
  disabled, mirroring delete_device), leaves the stage untouched,
  refuses mid-robot, and logs one audit event carrying both device and
  owner ids.

### Changed

- **Passenger connect list shows only free passengers (operator
  request):** passengers bound to any case (active, done or closed) are
  no longer offered as disabled options — they are hidden entirely;
  when no free passenger remains the dialog says so and disables
  اتصال. The server-side 1:1 guard remains the backstop.

### Fixed

- Passenger deletion now uses the styled confirm dialog instead of the
  browser's native blocking `confirm()` (dialog-chrome contract, same
  as case deletion).

## [1.4.2] - 2026-09-13

### Changed

- **Shamsi (Persian solar) dates everywhere (operator request):** all
  displayed dates now render as «روز ماه سال» (e.g. «۲۲ شهریور ۱۴۰۵»,
  with time «۲۲ شهریور ۱۴۰۵، ۱۷:۳۰») across the CRM (case table,
  case modal, history, ledger, periodic tab), the estelam panel and
  the old registry panel logs, and the server-built reports
  (text/printable/Telegram). Stored data stays Gregorian ISO — the
  conversion is display-only, so nothing about sorting, syncing or
  existing records changes. Frontend conversion uses the browser's
  Persian calendar locale; server-side reports use a new stdlib
  `jalali.py` module (reference- and leap-year-tested; the duplicated
  conversion copy in crm.py now delegates to it).
- **Case list slimmed (operator request):** the «آخرین تغییر» column
  left the devices table (it remains in the case-detail modal); the
  «تاریخ ثبت» column shows the Shamsi creation date.

## [1.4.1] - 2026-09-13

### Added

- **CRM page-width control (operator request):** a «عرض» button in the
  header opens a small popover with three presets (باریک ۱۰۸۰ / عادی
  ۱۲۴۰ / عریض — capped by the viewport), a fine range slider with a live
  pixel readout, and a reset. The choice persists in the browser and is
  clamped to 900–1920px so it can never overflow; the control lives in
  the header outside the refresh region, so the 5-second background
  refresh never closes it, and Esc/outside-click close it without
  touching the dialog's own Esc path.

## [1.4.0] - 2026-09-13

The product-wide UI/UX overhaul: every page rebuilt on one IRICA design
system, live search and filtering in every CRM tab, and a restructured
case table — built by a five-worker UI/UX team under a reviewed
lead-engineer pipeline (per-workstream reports, independent reviews).

### Added

- **Search & filter bar in every list tab (devices, customers, owners,
  identity pool, periodic, ledger, done/problem/closed):** a sticky
  toolbar with a live search box (icon, clear button, per-tab
  placeholder), Persian/Arabic digit normalization (typing «۰۹۱۲» finds
  "0912", ZWNJ-insensitive), a live result counter, stage filter chips
  on the devices tab («همه» / «نیازمند اقدام» / per active stage), and
  a friendly no-result state with a one-click reset. Typing never loses
  focus, even across the 5-second background refresh.
- **Case table restructured (operator request):** ردیف (row number) |
  دستگاه | مشتری | مسافر | سریال | گام | وضعیت | شناسه | dates —
  the customer column is new, row numbers renumber the filtered view.
- **IRICA design system + brand kit** (`lab/design/`): a 50-icon SVG
  library (RTL mirroring rules, legacy-name mapping), the brand
  monogram/favicon, the light/dark token palette and typography rules.
- **Brand favicon:** the path-drawn IRICA «R» mark (font-independent,
  legible at 16px) replaces the old text-based one.

### Changed

- **Every page rebuilt on one design system** (Vazirmatn font, unified
  light/dark tokens, one icon language — all emojis replaced with
  inline SVGs, consistent buttons/cards/tables): the CRM (primary-button
  contrast raised to 5.2:1, faint text darkened, upgraded tab states,
  table headers/hover, unified empty states, modal inner scroll), the
  estelam panel (sticky blurred top bar with brand mark and a live
  robot-status pill, segmented service switcher, mobile-stacked device
  tables), the old registry panel site-1 (glass header, clickable
  status tiles, restyled profile cards/logs/settings), and the front
  door (login, service-start launch card, service-picker home).
- **Unified brand color** across all pages (light brand #4460e3 for
  AA+ contrast on primary buttons; faint text darkened for
  readability).

### Fixed

- A pre-existing narrow-screen overflow in the estelam panel's device
  table (its fixed columns exceeded the available track width; the
  table now stacks per-device on mobile inside a safe minmax grid),
  duplicate conflicting layout rules in the old registry panel's CSS,
  missing `.btn.ok` / `.logbox` styles in the CRM, and unlabeled
  inputs in the estelam form (a11y).

## [1.3.7] - 2026-09-13

### Changed

- **CRM header redesigned (operator report):** «پنل استعلام‌ها» and
  «سامانه مدیریت گمرک» are now proper navigation buttons (icon + label,
  bordered cards with hover state) instead of bare inconsistent text
  links, and the theme/logout actions sit behind a hairline divider.
- **Devices-tab toolbar tidied (operator report):** the sorting hint no
  longer glues to the «+ پروندهٔ جدید» button — a base `.row` flex rule
  (previously only `.card .row` was styled, so toolbars outside a card
  rendered as a plain block) plus a comfortable gap, and the hint text
  is fully Persian («... خودکار و بدون تکرار اجرا می‌شوند», dropping
  the mixed-English «یک‌بار-per-device»).

## [1.3.6] - 2026-09-13

### Fixed

- **Stale pages after an update (operator report):** HTML responses now
  carry `Cache-Control: no-store` — after a panel update the browser kept
  serving the previous version from heuristic cache until a hard refresh.
  Static assets (fonts) keep normal caching. One hard refresh (Ctrl+F5)
  is still needed once to clear whatever was already cached.

## [1.3.5] - 2026-09-13

### Changed

- **Case-modal action area redesign (operator request):** every action
  cluster now sits in its own framed group — «ابزار این گام» (the step's
  tools), «پرداخت» (payment controls) and a dashed-frame «سایر اقدامات»
  for low-frequency actions — so buttons that do similar work read as one
  unit. Ghost buttons gained a visible border/hover tint (previously
  frameless), and the tool/payment buttons carry inline-SVG icons from one
  stroke language: the emoji payment buttons (🔗 🧾 💳 🙈 👁) were replaced
  with matching SVG icons. Renames for clarity: «بستن ربات» → «توقف ربات
  پرداخت», «ویرایش» → «ویرایش پرونده», «حذف» → «حذف پرونده» (which now
  uses the styled confirmation dialog instead of the browser's native
  blocking confirm).
- **Step guide (توضیحات گام‌ها) redesigned and no longer loses the case:**
  clicking a rail step opens a proper guide card — numbered badge, «گام n
  از ۸» overline, mini progress dots, comfortable description — and closing
  it (button, ×, Esc) RETURNS to the case modal instead of closing
  everything. The red problem dot on failed cases opens a dedicated
  «دارای اشکال در گام ۲» guide with the failure explanation.
- **Launch page defaults to light (operator request):** the /launch card
  that opens on service start was hardcoded dark; it now renders light
  like every other page, with a softened shadow and the CRM brand palette.

## [1.3.4] - 2026-09-13

### Changed

- **Case list owns the full main column (operator request):** the KPI
  strip and the devices summary rail (recent customers / recent cases /
  top debtors) moved into the side aside, stacked above the «تاریخچه»
  card. Previously the case table was boxed in between the KPI row on
  top and a 300px summary rail beside it (plus the 300px history aside
  on the other side) — it now gets the full width of the main column
  and starts at the top of the page. In the narrow desktop aside the
  four KPIs render as a 2x2 grid; below the 1100px breakpoint the aside
  is full-width and the 4-column strip returns. The rail renders only
  on the devices tab, as before, and its rows still focus/flash the
  matching case row.

## [1.3.3] - 2026-09-13

### Changed

- **Passenger passport is optional:** creating or editing a passenger no
  longer requires a passport number. When supplied, it accepts 1-20 Latin
  letters or digits and is stored uppercased.

## [1.3.2] - 2026-09-13

### Fixed

- **Toasts rendered dimmed underneath the case modal (operator report):**
  a `showModal()` dialog renders in the browser top layer, above every
  z-index, so the toast container could never overlay it. While a dialog
  is open the toast container now moves inside the dialog element (and
  back to the body on every close path — ×, Esc, programmatic), so
  notifications always render above the modal and its backdrop at full
  opacity. Fixed positioning is unchanged — the dialog has no
  transform/filter, so the container still anchors to the viewport.

## [1.3.1] - 2026-09-13

The case-modal UX update: three operator-reviewed refinement rounds on the
case-detail modal (live-verified on a scratch panel, independently
reviewed). Frontend-only — panel.py markup/JS plus marker tests.

### Fixed

- **Stale case-detail modal:** the modal now keeps itself in sync — every
  refresh re-renders it when the case's signature (stage, timestamps,
  inquiry/payment status) changes, reopens it after confirm flows that
  replaced it (inquiry, periodic remove/re-add, pay-stop, requeue, skip,
  rollback), and closes it with a named toast when the case is deleted.
  This removes the confusing «این کنش در مرحلهٔ فعلی مجاز نیست» errors
  caused by clicking buttons of an already-advanced stage.
- **Esc no longer resurrects the modal:** closing the dialog via the
  native Esc path disarms the sync machine (a close listener clears the
  modal tracking state), so a dismissed modal cannot pop back open on the
  next background refresh.
- Double-click guard on the «قدم بعدی» hero button: a second POST before
  the first one lands no longer produces a stage-mismatch error.
- Remaining anonymous toasts in the case flow and the periodic tab now
  name their row (case/passenger name), e.g. «...» از استعلام دوره‌ای
  حذف شد.

### Changed

- **Modal action redesign:** one clear primary per step — a «قدم بعدی»
  hero card under the rail (with visible unmet-requirement chips and the
  new destination-labelled continue buttons), stage tools grouped under
  «ابزار این گام», and low-frequency actions (edit, rollback, skip,
  close, delete) in a quiet «سایر اقدامات» row.
- **Step-scoped tools (operator request):** every tool now appears only
  on its own step — manual gomrok/hamta inquiries on step 2 (inquiry),
  the Telegram re-send on step 4 (handed), the periodic-watch toggle on
  step 5 (to_payment), pay controls on steps 5-7. The problem stage shows
  its «بازگشت به صف» as the hero card; the periodic tab still offers the
  watch toggle for every watched stage.
- Creating a case opens the new case's modal immediately; the modal body
  close button was removed (the × and Esc remain).

## [1.3.0] - 2026-09-13

The case-workflow update: a 14-item operator-driven CRM overhaul —
identity-pool inquiries at every stage, per-passenger passports, editable
and rollback-able completed cases, a case table with a detail modal, and a
Telegram registration handoff. Implemented through a reviewed multi-agent
pipeline (2 domains, per-task supervisor verification, 3 independent
reviews); the suite grew 511 -> 749 tests, all green.

### Added

- **Identity-pool inquiries at every stage (item 7):** watch-stage customs
  inquiries now run under the inquiry-identity pool exactly like intake —
  never under the passenger's national code — failing closed with a clear
  Persian error when the pool is empty or invalid. The site's
  "registered under another national code" message (متعلق به این کد ملی
  نیست, operator-provided) is classified as the `advanced` (registered)
  status, so the existing auto-advance join moves handed cases toward
  payment; «یافت نشد» keeps the case polling on its interval.
- **Per-passenger passport:** required (latin letters/digits, 5-20 chars,
  stored uppercased) on every passenger save; legacy records without one
  keep loading unchanged. The registration profile gains an OPTIONAL
  `passport` field (auto-filled from the passenger on create/link, never
  overwritten) with a site-1 form field and route-level validation.
- **Attach-time registration profiles (item 11):** the profile is created
  or linked the moment a passenger is connected to a case (idempotent,
  deduplicated by serial/national) with the handover/auto-advance ensure
  kept as a backstop. `/crm-start-payment` self-heals an empty or stale
  profile link and returns an actionable Persian error (naming the
  recovery) when no passenger is attached — the reported
  «پروفایل ثبت‌نام ساخته نشده» failure is regression-tested.
- **Telegram registration handoff (item 8):** after a successful handover
  tick the panel sends exactly one message
  (`kodmeli = … / imei1 = … / imei2 = … / passport = …`) to the new
  «registration channel/group numeric id» setting. Fail-closed when the
  destination is unset or the passenger's passport is missing; Telegram
  failures never affect the case state; a per-case «ارسال مجدد به تلگرام»
  button; logs carry the device id and destination only.
- **Case management:** a case/device edit modal (primary IMEI locked with
  delete-and-recreate guidance), editable completed cases with a
  strongly-confirmed rollback (done → payment_done, completion timestamps
  cleared), strict section separation (active/completed/problem/closed —
  each case in exactly one section), created/updated/completion timestamps
  on every case surface, and a consistent × close affordance on every
  dialog with ESC support.
- **Case table + detail modal (item 14):** the devices tab is now a clean
  table (id, passenger, device, masked serial, stage, status, created,
  updated) with all per-case actions living in a case-detail modal.

### Fixed

- Silent step-2 customs-inquiry failures (items 1+9): every gomrok inquiry
  affordance surfaces backend errors; gomrok buttons disable with a tooltip
  while the identity pool has no valid entry (hamta unaffected); bulk runs
  report per-device errors.
- "Back at step 5 completed the case" (item 12): no UI or backend path can
  complete a case except the deliver_code tick — the skip-to-done path is
  removed everywhere and an exhaustive 10-stage × 13-action invariant
  matrix pins the contract.
- **Registry-fee double-booking:** correcting a serial typo (delete +
  recreate, forced by the immutable primary IMEI) now books an automatic
  `base_fee_refund` reversal on the customer holding the original row, so
  the ledger stays fee-neutral end to end.
- Auto-advance gave up on a case after a rollback re-advance (stale local
  attempt counter) leaving it stuck at `to_payment` until a manual start.
- `retry_count` UnboundLocalError crashed the customs inquiry robot's
  first-try verdicts (no preceding transient error) before classification
  ran — a latent pre-existing crash, now guarded.
- cp1252 console crash: `/save` and `/activate` dropped their HTTP response
  when printing Persian/profile data on a non-UTF-8 console.
- Double-start guard: a device with a live inquiry run can no longer be
  started again (per-device in-flight refusal; the periodic-tab reset
  button disables while runs are live).
- Owner-record hardening: `update_owner` no longer crashes on hand-edited
  rows lacking `card_no`; spaced 16-digit cards store normalized.
- `last_inquiry_at` writes are under `STORE_LOCK`; the site-2 estelam page
  labels an `advanced` result «ثبت‌شده در گمرک» (success) instead of
  «مسدود/خطر»; the periodic tab marks payment-stage cases «فقط دستی»
  instead of a countdown for inquiries that never run; all copy claiming
  watch inquiries run under the passenger's identity corrected.

### Changed

- Passenger card number is optional (empty allowed; 16 digits still
  enforced when present).
- `telegram_notify.send_message` gained an additive `chat_id` parameter for
  single-destination sends (existing callers and fan-out behavior
  unchanged).
- The test runner's DEFAULT suite grew from 38 to 54 modules.

### Tests

- Suite 511 → 749, all green: 238 new tests across 13 new modules (stage
  transitions, case/ledger/owner-passport integrity, watch identity +
  not-owner classification, inquiry gate, forms/tabs, sections/wiring,
  case list, dialog chrome, profile-ready, review fixes, telegram
  handoff); 5 stale contract tests rewritten; 34 fixtures updated; the
  pre-existing `test_periodic_inquiry_tab` failure fixed and the module
  registered.

### Notes

- `gomrok.py` is untouched in this release (operator decision); passports
  are entered into the portal manually per the operator's workflow.
- Before first use: complete each passenger's passport in the passenger
  tab, and set the registration Telegram channel id in settings — both
  gates fail closed with guidance messages until then.

## [1.2.0] - 2026-09-10

### Added

- Login gate for the whole panel: every fresh visit lands on a login page
  (`/login`); every other route requires a valid session cookie. Unauthenticated
  page requests redirect to `/login`, API requests get HTTP 401 with a Persian
  message, and `/shutdown` is gated like everything else.
- Three operator-provisioned accounts (saeed, hasan, arsalan) seeded on first
  start into `panel_users.json` inside the data directory — PBKDF2-HMAC-SHA256
  (390k iterations, per-user salt), never plaintext. No user-management UI by
  design; the file is created outside the release tree and is excluded from
  bundles by the release verifier.
- Session handling: HttpOnly `SameSite=Lax` cookie with a 7-day sliding server
  session; «خروج (user)» in the CRM header and `POST /logout` destroy the
  session server-side. Restarting the panel logs everyone out (sessions are
  in-memory).
- Brute-force throttle: 5 failed attempts lock the username for 30 seconds
  (HTTP 429); unknown usernames verify against a dummy hash so response timing
  does not reveal account existence. Successful logins are recorded in the CRM
  event log (`login_ok` with the username only).
- Telegram attribution: every outbound Telegram message (reports, robot
  notifications, estelam/hamta/exitban workers) now starts with
  «کاربر: <name>». The acting user is stamped onto child processes at spawn
  time (`IRICA_ACTOR`); panel-initiated sends pass the user explicitly, and
  scheduled background runs are attributed to «سیستم».

### Removed

- The panel-access Cloudflare stack (cloudflare_auth_relay.py on :8751,
  start_cloudflare_relay.py, start_named_cloudflare_tunnel.py,
  cloudflare_named_tunnel.yml and the watchdog section that kept the tunnel
  alive): the panel is a localhost service again, reachable only on
  127.0.0.1:8750. The Telegram relay chain (telegram_api_relay.py +
  cloudflare_http_proxy.py) is untouched.

### Changed

- The release verifier gates page probes behind the login: with
  IRICA_VERIFY_USER/IRICA_VERIFY_PASS set it logs in and checks the pages;
  without credentials it verifies the gate shape (401/302 + login page 200).
- Test harnesses drive the real gate: a shared helper
  (`lab/tests/_auth_harness.py`) seeds a session and injects the cookie into
  every request, so the suite exercises the authenticated paths end to end.

## [1.1.5] - 2026-09-10

### Added

- CRM tabs reorganized around case outcomes: «تکمیل شده‌ها» (completed cases,
  read-only), «دارای اشکال» (problem cases with «بازگشت به صف» and close actions),
  and «مختومه‌ها» (terminated cases with their reason and date). The KPI tile
  now links to the completed tab.
- Terminal case state «مختومه» (closed): an operator can terminate a case from
  the inquiry or problem stage with a mandatory written reason (stored on the
  case with a timestamp). Closed cases reject every further action — the
  scheduler, watch runs, auto-advance, periodic re-inquiry and inquiry starts
  all exclude them — and they can never be rolled back.
- Left summary rail on the devices view: «جدیدترین مشتری‌ها» (newest customers
  with balance pills), «پرونده‌های اخیر» (recent cases; clicking scrolls to and
  flashes the device card), and «بیشترین بدهکاری» (top debtors). Pure
  client-side; no new server routes.
- Ledger trace for terminations: a `case_closed` event records the reason's
  LENGTH only, never the reason text (privacy §12).

### Tests

- Suite grew 409 → 465 (summary-rail 26, tabs/closed 30 including an
  HTTP end-to-end close-case flow); all green.

## [1.1.4] - 2026-09-09 (assets refreshed 2026-09-10)

### Fixed (asset refresh)

- Blank CRM body regression: a missing comma in the page's ICONS object literal
  (introduced with the transaction-detail icon) was a JS syntax error that killed
  the whole CRM page script, leaving only the server-rendered header. Fixed, and
  a permanent regression gate now runs `node --check` over every `<script>` block
  of every served page in the test suite.
- Stage model reworked into the operator's 8-step rail (problem state unnumbered,
  step-2 "not registered" = pass / "registered" = red danger, step-5 periodic
  customs re-inquiry with registered = pass). Published zip/exe/SHA256SUMS assets
  were rebuilt from the fix; the v1.1.4 tag moved to the fix commit.

### Added

- Parallel inquiry runs: several devices can be inquired at the same time,
  each with its own browser (cap 3 concurrent robot processes). The estelam
  store tracks every live run in a `runs` registry (legacy `run_pid` still
  honored); dead pids are pruned on read so the cap tracks reality.
- Per-device "افزودن به استعلام دوره‌ای / حذف از استعلام دوره‌ای" toggle on the
  CRM device card (watch stages).
- Periodic tab: "+ افزودن پرونده" opens a device-picker modal with search,
  10/20/30 page-size selector and pagination; checkboxes choose devices and
  the selected ones are re-added to the periodic inquiry list.
- Stage guide: every step on the numbered stage rail is a button; hovering
  shows a tooltip and clicking opens a modal explaining that stage (what it
  does, what it needs, what continues it).
- Transactions tab: each row has a جزئیات button opening a detail modal with
  customer, time, amount, kind, note, device name, device serial(s) and the
  attached image; the registry-fee note now carries the device name.

### Fixed

- CRM tab counts showed 0 for every tab after a page load until a tab was
  clicked: `refresh()` now re-renders the tab bar after state arrives.
- Stopping the inquiry kills ALL live runs (not just the legacy single pid)
  and resets only the devices those runs owned, so one run's stop no longer
  clobbers a concurrent run's in-flight status.
- Person identity is handed to each robot child through IRICA_PERSON_* env
  vars; with parallel starts the shared store's `person` could previously be
  overwritten before the child read it (wrong owner on the customs form).

## [1.1.3] - 2026-09-09

### Fixed

- Inquiry robot no longer stamps a device as "دارای اشکال" (problem) when the
  site kept rejecting the captcha: captcha/transient exhaustion is now
  status "error" (device NOT evaluated, automatically re-inquirable by the
  next periodic run) with a neutral telegram message, and only genuine
  non-retryable site verdicts remain "problem". Evidence: device e1a4e106
  was misclassified after 25 captcha rejects while the same serial inquired
  healthy on Hamta minutes later.
- Bounded captcha-stall abort: after 12 consecutive captcha-rejected submits
  the inquiry gives up that device for the run (~1.5 min saved per doomed
  device) instead of always burning all 25 attempts.
- Per-attempt telemetry: the retry loop reports every submit (answer,
  confidence, rejected) to the inquiry flow; the panel log now records the
  attempt count, rejected count, and the last 3 answers, so a bad solver
  streak is diagnosable from the log instead of invisible.

## [1.1.2] - 2026-09-08

### Added

- Inquiry gate on the CRM stage machine: advancing a device past the
  inquiry stage (`mark_ready`) now requires BOTH a healthy customs
  result AND a good hamta result recorded in the estelam store.
  Fail-closed: a device with missing or failed inquiries is rejected
  with a Persian action message instead of silently advancing.
- Per-device inquiry actions on the CRM device cards: run customs,
  hamta, or both inquiries for a single device directly from the CRM
  list (confirmation modal first), with last-inquiry time and result
  shown per device.

### Fixed

- Stage rollback (`stage_back`) works across multiple stages and is
  exempt from the inquiry gate.
- Duplicate serial guard: adding a second device with the same IMEI
  serial in one case is rejected.
- New-device modal form hygiene: optional telegram/instagram fields,
  mobile validated (11 digits, `09` prefix), customer picker dropdown
  with a "new customer" option, per-field error messages, styled
  checkboxes, and the device-notes field restored (it was dropped from
  the modal while still being read on submit).

## [1.1.0] - 2026-09-07

### Added

- Customer & case management (CRM) at `/crm`, built plan-first with an
  independent design review (20 findings merged) and TDD throughout
  (83 new tests; suite 233 -> 316):
  - `crm.py`: customers with a Toman ledger, owners (Iranian mod-11
    national checksum, shamsi age 15..99, 16-digit card), a random
    pre-registration identity pool, devices, and a 9-stage case machine
    with timestamped idempotent ticks. Store writes are atomic with a
    seeded `.bak` and corrupt-main recovery.
  - `/crm-*` API routes on the panel; the CRM page (6 tabs) with the
    panel-wide theme; `/crm-report` txt/html/PDF (headless Edge with an
    auto-print HTML fallback) and a telegram report that masks national
    codes and never carries card numbers.
  - Identity-scoped inquiries: pre-registration intake runs under a
    random VALID pool identity; the watch re-inquiry after handover runs
    under the device OWNER's identity (the customs site only reports
    registration to the registering code). Devices at watch stages
    without an owner are rejected, never silently re-identified.
  - Per-device, serialized runs only: CRM never starts the unscoped
    estelam sweep, and its queue sync leaves manual site-2 rows
    byte-identical. `estelam_store.json` saves are atomic with `.bak`.
  - A 60s scheduler beat (kill switch `IRICA_CRM_SCHEDULER_OFF=1`)
    re-inquires due watch devices every configured interval (1..72h,
    default 2) and auto-advances registered devices to payment ONLY on a
    confirmed robot start (attempts capped at 6).
  - Handover auto-links or auto-creates the site-1 registration profile
    (dedupe by IMEI or owner national code — pre-CRM manual devices are
    linked, not duplicated). `crm_store.json` joins the release
    migration list.

## [1.0.16] - 2026-09-07

### Fixed

- Fewer wrong-captcha submissions in BOTH the customs inquiry and the
  customs registration flows (inquiry logged at ~29% of submits). Two
  root causes addressed:
  - The OCR decoder now attaches a confidence score to every read; reads
    below 0.6 (tunable via `IRICA_CAPTCHA_MIN_CONF`) trigger a free captcha
    refresh + re-read (max 3) instead of submitting a fabricated guess.
  - Before reading, the captcha image must stay unchanged across 3
    consecutive fingerprints (bounded 10s), closing the race where the
    page swaps the image between OCR and submit after a slow load / F5
    (12 of 16 logged wrong-captcha retries followed such dirty loads).
- The confidence gate lives in `gomrok.py` (`solve_confidently`) and is
  shared by both robots; the registration robot's main read and its
  in-place retry loop now use it too.

## [1.0.15] - 2026-09-07

### Changed

- Softer dark theme across all panel pages: near-black backgrounds
  (`#0b0c0f` / `#0d1220` / `#0f1115` / `#0b1020`) replaced with a lighter
  graphite-indigo family (`#171a26` base, `#1f2333` cards, `#363d57`
  lines), with brighter muted text and lighter shadows for contrast.
  Applies to the launcher card, the customs panel (dark mode), the inquiry
  panel (dark mode), and the home picker.

## [1.0.14] - 2026-09-07

Visible launch feedback: the desktop shortcut now shows that the service
started, where its UI is, and how to stop it.

### Added

- `panel_tray.pyw` launcher: probes the panel, spawns it detached when down
  (25s bounded poll), fires a Windows toast ("سرویس رجیستری فعال شد"), and
  opens the new `/launch` page in the default browser. Falls back to
  `/site-1` on panels older than 1.0.14; MessageBox on start failure.
- `GET /launch`: self-contained Persian RTL launcher card — live status
  (profiles / running / success / blocked from `/state`), version badge,
  buttons for both panels and a "بستن سرویس" button that POSTs `/shutdown`
  and flips the card to a "service stopped" state.
- `GET /favicon.ico` (inline SVG) to quiet browser 404 noise.

### Changed

- Installer shortcuts and the post-install run now launch `panel_tray.pyw`;
  the autostart task intentionally stays silent (`panel_gui.pyw`).
- The bundle ships `panel_tray.pyw` alongside `panel_gui.pyw`.

## [1.0.13] - 2026-09-07

Inquiry stop button and whole-system shutdown.

### Added

- Device-inquiry card stop button: `POST /profile-device-stop` kills the
  running `profile_inquiry.py` process tree (tracked via
  `device_inquiry_pid`), resets the profile's inquiry state, and reports
  success/failure as a toast; the UI button switches between Run/Stop based
  on live state.
- "بستن سامانه" (close whole system) button on both panels (`/site-1`
  header actions and `/site-2` beside the width/theme buttons):
  `POST /shutdown` kills every running robot/profile process via
  `shutdown_everything()`, then sets `_SHUTDOWN_REQUESTED`; the serve loop
  (`serve_forever` on a helper thread, main thread polling the event) exits
  the panel process cleanly with code 0.
- `system-close-btn` styling shared across both pages.

### Changed

- Profile list redesign from the UI session: stable card anatomy (avatar
  with per-profile hue, identity block, status + run button, footer with
  receipt/payment chips), active-state accent bar, hover elevation, smooth
  inner scroll; `test_dashboard_rewrite.py` updated markers.

## [1.0.12] - 2026-09-06

The installable release: a per-user Windows installer replaces the
unzip-into-a-new-folder upgrade loop.

### Added

- `IRICA-Setup-vX.Y.Z.exe` built with Inno Setup (`lab/scripts/irica.iss`,
  `lab/scripts/build_windows_installer.py`): per-user install to
  `%LOCALAPPDATA%\Programs\IRICA`, no admin rights, in-place upgrades,
  desktop/Start-Menu shortcuts launching `panel_gui.pyw` (console-less), an
  optional autostart task, and an uninstaller that never touches
  `%LOCALAPPDATA%\irica` user data.
- Silent launcher `panel_gui.pyw`: runs the panel without a console window,
  logs crashes to `%LOCALAPPDATA%\irica\panel_crash.log` and shows a
  message box instead of dying silently.
- chromedriver is bundled into `.tools\` by the release build when a copy is
  available; the manual FIRST_RUN download step becomes optional.
- Shared chromedriver resolution in `captcha_collector.resolve_chromedriver()`:
  explicit override -> bundled `.tools` copy -> Selenium Manager. `gomrok2.py`,
  `estelam_hamta.py` and `exitban.py` now route through it instead of their
  own hardcoded paths.
- Chrome/chromedriver version-compat check (`check_driver_compat`): a Persian
  warning names both majors when the driver does not match the installed
  Chrome, so post-Chrome-update robot failures are diagnosable immediately.
- Single-instance gate in `panel.main()`: a second panel start detects the
  running panel via an HTTP probe (including pre-1.0.11 panels via markup
  markers), prints a clear message and opens the running panel instead of
  crashing on the bind.

### Notes

- The installer is unsigned; SmartScreen shows "More info → Run anyway" on
  first run.
- Inno Setup is a build-time-only dependency (installed via winget on demand);
  running the panel or the installer needs nothing beyond the bundle.

## [1.0.11] - 2026-09-06

Panel polish: version badge, profile names on inquiry results, and a release
button for blocked profiles.

### Added

- The panel version (from the bundled `VERSION` file) is now shown on all three
  pages: the site picker, the main dashboard header, and the device-inquiry
  page header (`نسخه x.y.z`).
- Inquiry result rows now carry the profile's own name. The device-inquiry card
  heading shows `پروفایل — سرویس` and every result row prints
  `👤 پروفایل: <name>`, so results are unambiguous when several profiles are
  checked in one session.
- Blocked profiles get a `🔓 آزادسازی و شروع مجدد` button in the edit form.
  `POST /release-blocked` resets `registration_status` to `pending`, drops the
  stored `runtime_error`, re-enables the profile, and clears runtime and
  inquiry bookkeeping (including `device_inquiry_pid` and the
  `running` inquiry statuses) so the profile can be edited and rerun.
  Refusals (busy, not blocked, missing id) return 409 with a Persian message
  and change nothing.

### Notes

- The release route refuses to touch a busy profile; stop the robot first.

## [1.0.10] - 2026-09-05

Dual-SIM devices on the customs login page now work correctly.

### Fixed

- The customs login page shows `دستگاه شما دارای دو اسلات است لطفا شناسه دیگر را نیز
  وارد نمایید` when a device has two SIM slots and the second IMEI is missing. This
  message was unclassified: not fatal, not retryable, not transient. The robot fell
  into the "other error" branch — logged, restarted the browser, and looped forever
  without ever filling the second slot. The marker `دو اسلات` is now in
  `IMEI_FATAL_MARKERS`, so the profile is blocked with the reason shown on the
  card (and the operator can use 📄 کپی to start clean with both IMEIs).
- `fill_imeis` already supports two IMEIs (the profile stores `imeis` as a list of
  up to 2). When `len(imeis) >= 2`, it clicks the "+" button to add the second
  row, fills both, and `verify_imeis` checks both rows. This path was already
  correct; the bug was only the missing fatal classification that caused the
  infinite restart loop before the second slot was ever filled.

## [1.0.9] - 2026-09-05

An IMEI that is already active on the domestic network now blocks its profile
instead of being retried forever.

### Fixed

- On the customs login page the site reports a permanently rejected device as
  `خطا در استعلام imei از سامانه همتا : شناسه (IMEI) وارد شده قبلا در شبکه داخلی
  کشور ثبت و فعال شده و امکان ورود آن وجود ندارد`. That wrapper is also how a
  genuine transient HAMTA inquiry failure arrives, so the message was classified
  as retryable: the robot refreshed the captcha and resubmitted without limit
  (`max_attempts=None`), never reached the fatal branch, and never marked the
  profile unusable. The permanent reason inside the wrapper now wins — the
  profile is marked `blocked`, the busy claim is released, the reason is stored,
  and the robot stops.
- Fatal detection is now a single function, `is_imei_fatal_error()`, consulted
  before every retry decision, so the retry classifier and the post-submit branch
  can no longer disagree. A stale captcha warning sitting on the page alongside a
  permanent rejection can no longer rescue it.
- A HAMTA inquiry failure with no permanent reason (`خطا در دریافت پاسخ از سازمان
  مربوطه`, `لطفا مجددا تلاش کنید`, `Invalid timestamp`) is still retried and
  leaves the profile runnable.
- Cloning a blocked profile now clears its `runtime_error` as well as its status.
  The clone was already reset to `pending`, but it inherited the old reason and
  the card kept showing "غیرقابل ورود" for a profile that was actually runnable.
  The clone is the intended route back to a usable profile, since editing one
  deliberately preserves runtime status.

## [1.0.8] - 2026-09-04

Completes v1.0.7: the settings import now works for the upgrade path the release
notes actually describe.

### Fixed

- v1.0.7 only imported settings that sat in the folder the new code ran from. The
  documented upgrade — unzip the new version into a NEW folder next to the old one
  — left the application folder empty, so nothing was imported and the Telegram
  token had to be entered again, the very problem v1.0.7 set out to remove.
  Sibling install folders are now searched as well: the most recently written one
  wins and is taken as a whole, so `profiles.json` and `estelam_store.json` can
  never come from different installs. A folder only counts as an install if it
  contains `panel.py`, and `IRICA_IMPORT_FROM` names a source explicitly for the
  case where the old install is on another drive.
- The panel prints which folder it imported from, so a wrong source is visible
  immediately instead of silently.

### Added

- `find_legacy_source()` / `imported_from()` in `app_paths.py`, with 12 tests
  covering sibling detection, install-marker filtering, the explicit override, a
  bad override, mtime ordering and the no-mixing rule.

### Fixed (build)

- The release build no longer depends on a single package index. It tries
  `pypi.org`, the runflare mirror and tsinghua in order, logs which one served the
  wheels, and only fails when all of them fail (`IRICA_PIP_INDEX` overrides the
  list). The mirror the build had been pinned to since v1.0.3 stopped serving
  packages — HTTP 200 on `/simple/` but "from versions: none" for every
  requirement — which broke the v1.0.8 build outright.

## [1.0.7] - 2026-09-04

Settings survive an update. The Telegram token, profiles, device inquiries and
logs no longer live inside the program folder, so replacing it never wipes them.

### Fixed

- Configuration, state and logs resolve to a per-user data directory outside the
  release: `%LOCALAPPDATA%\irica` on Windows, `$XDG_DATA_HOME/irica` on POSIX,
  overridable with `IRICA_DATA_DIR` for a portable install. Every module that
  persists anything follows it — the panel, `telegram_notify`, both estelam
  robots, `gomrok`, the Cloudflare relays and the SOCKS5 proxy reader.
- Upgrading needs no manual copying: files found inside an older release folder
  are imported on first run. Copies, not moves, so rolling back to the old build
  still works, and an existing file in the data directory is never overwritten.
- `save_telegram_config` now accepts a list of chat IDs as well as the UI's
  newline/comma text, so what `/telegram-config` returns can be posted straight
  back.
- The screenshot route accepts both the new and the pre-upgrade screenshot roots;
  containment is still enforced against each.

### Added

- `app_paths.py`: data-directory resolution, `data_path`/`data_subdir` (both
  reject path traversal) and one-shot legacy migration.
- The release verifier fails if any config or state path resolves inside the
  bundle, and the release's `FIRST_RUN.txt` documents where settings live.

## [1.0.6] - 2026-09-04

Makes the robot's browser window reviewable by hand: the whole page is now inside
the window, and it can be scrolled with the mouse.

### Fixed

- **Part of the page sat outside the window and could not be scrolled to.** The
  mobile emulation pinned the layout viewport to 932 CSS px (a real iPhone's
  height), but a 430x932 window is 516x932 in practice and 151 px of that is
  browser chrome, so only 781 CSS px of page were ever visible. Two consequences,
  both reported from the field on the customs login page: the bottom 151 CSS px
  were permanently off-window, and on any page shorter than 932 CSS px
  `scrollHeight` equalled `clientHeight`, so there was no scroll range at all --
  mouse wheel and keyboard had nothing to move. The emulated viewport height is
  now `0`, which CDP reads as "do not override this axis": the viewport equals the
  window's real content area, nothing is clipped, the scroll range is correct, and
  it follows a window resize. Layout width (430), pixel ratio (3.0) and the mobile
  user agent are unchanged, so the sites keep serving their mobile pages.

### Added

- **Drag-to-scroll with the mouse**, like a finger on a phone. Mobile emulation
  uses overlay scrollbars that occupy 0 px of layout and cannot be grabbed, and
  no CSS or Chrome flag brings a classic scrollbar back (four approaches were
  measured, all 0 px). `Emulation.setEmitTouchEventsForMouse` makes a mouse drag
  scroll the page instead. Mouse wheel and keyboard (PageDown/End/arrows) work as
  before.
- `captcha_collector.scroll_page(driver, "down"|"up"|"top"|"bottom")` for scripted
  or automated review scrolling.
- `lab/scripts/live_check_manual_scroll.py` (16 checks) and
  `lab/scripts/live_check_captcha_crop.py` (8 checks), which drive real Windows
  mouse input through `SendInput` against the actual robot drivers.

### Verified

- Captcha cropping is **bit-identical** before and after the change: same crop
  size and same SHA-256 of the pixel data (`lab/scripts/probe_crop_ab.py`). The
  crop scale stays 3.0.
- Every robot click path is unaffected with drag-to-scroll active: Selenium
  `.click()`, the project's own touch/pointer/mouse dispatch chain, `send_keys`,
  checkbox toggling and `scrollIntoView`
  (`lab/scripts/probe_click_with_dragscroll.py`).
- Real OS mouse wheel and real OS mouse drag both scroll the robot's window, for
  the customs and HAMTA drivers alike; the bottom of a login-page-sized document
  is fully reachable in both.

## [1.0.5] - 2026-09-04

Hardens the bundled Python runtime so a missing dependency cannot surface on the
operator's machine.

### Fixed

- Added `install.bat` to verify the bundled Python runtime before startup, and
  `run_panel.bat` now runs that verification automatically.
- The `requests` runtime dependencies are installed explicitly and kept inside the
  bundle: `urllib3`, `certifi`, `charset-normalizer`, `idna`.
- Release builds disable user-site packages and verify the complete `requests`
  import closure both before packaging and during bundle verification.

## [1.0.4] - 2026-09-04

Fixes a release-only defect that made every inquiry and registration robot exit
immediately on the user's machine while the panel reported "started".

### Fixed

- **Robots ran under a foreign interpreter.** The panel spawned every robot with
  a hardcoded `C:\Program Files\Python310\python.exe`. Where that install exists
  and carries PyTorch, the captcha solvers selected their torch backend, whose
  modules (`solver/predict.py`, `Hamta-solver/model.py`) are deliberately not
  shipped, so each robot died with `ModuleNotFoundError` before opening a
  browser. Robots now run under the panel's own interpreter — the bundled
  `python.exe` in a release — with `IRICA_ROBOT_PYTHON` as a development
  override. Same fix in the Cloudflare relay launchers.
- **Isolated runtime could not import project modules.** The bundled embedded
  CPython is isolated: `PYTHONPATH` is ignored and a script argument does not put
  its own directory on `sys.path`. `robot_launcher.py` and `panel.py` now repair
  `sys.path` before the first project import; without it the launcher itself, and
  the panel's lazy `import exitban` in `/exitban-inquiry`, failed at runtime.
- **Solver backend selection required only `torch`.** Both solvers now verify the
  whole torch backend (`predict` / `model` importable) before choosing it, so an
  unrelated torch install cannot select a backend that cannot load.
- **Child robots bypassed the launcher.** `estelam_all.py` and
  `profile_inquiry.py` spawn their children through `robot_launcher.py`, so the
  path repair and startup-traceback capture apply to them too.

### Changed

- Release gates run their probe **through `robot_launcher.py` with a script
  argument** — the exact shape the panel uses. The previous `python -c` probe
  supplied a manual `sys.path.insert(0, '.')`, which masked both failures above
  and let v1.0.3 ship green.
- New regression suite `lab/tests/test_robot_interpreter.py` (15 tests) covers
  interpreter resolution, launcher bootstrap under `-I`, child spawns, and solver
  backend selection.

## [1.0.3] - 2026-08-18

Adds optional per-run system diagnostics for troubleshooting robot startup and
runtime failures on other Windows machines.

### Added

- Debug log switch and log viewer under General Settings.
- Timestamped per-run logs under `logs/system/` when enabled.
- Common launcher that captures pre-import failures, environment, arguments,
  stdout/stderr and tracebacks.
- Safe system-log listing and bounded file-reading endpoints.

## [1.0.2] - 2026-08-17

Ships the per-profile device inquiries in the packaged release.

### Added

- **Per-profile device inquiry.** A profile's saved IMEIs can be checked against
  HAMTA, customs, or both from the profile's own *استعلامات* tab; results, status
  and errors are stored on the profile (`POST /profile-device-inquiry`, executed
  by `profile_inquiry.py` as a tracked subprocess).
- **Read-only profile overview.** Selecting a profile shows its data without
  editable inputs; editing is an explicit action.

### Fixed

- **`profile_inquiry.py` was missing from the bundle.** `panel.py` spawns it for
  every inquiry, but it was absent from the packaged file list, so the inquiry
  button would have failed on a user's machine. It now ships, and the verifier
  parses `panel.py` for every script it spawns and fails when any of them is not
  in the bundle — the same class of bug as the v1.0.1 hamta solver, now caught
  structurally rather than by name.
- Inquiry robots honour `IRICA_ESTELAM_STORE`, so a per-profile run uses its own
  temporary store instead of the shared `estelam_store.json`.

## [1.0.1] - 2026-08-17

Fixes the hamta inquiry captcha in the packaged release.

### Fixed

- **Hamta inquiry captcha was broken in the v1.0.0 bundle.** `estelam_hamta.py`
  reads the modal captcha through its own solver package (`Hamta-solver/`), which
  is separate from the gomrok one and was still torch-only; the v1.0.0 bundle
  shipped neither that package nor PyTorch, so the hamta robot raised
  `ModuleNotFoundError: No module named 'live_solve'` the moment it reached the
  captcha. The hamta CRNN is now exported to ONNX (55.0 MB `.pt` → 18.3 MB
  `.onnx`) and the bundle carries a torch-free backend for it.

### Added

- `Hamta-solver/onnx_solve.py` — `OnnxHamtaSolver`, an onnxruntime backend with
  the same surface as `HamtaSolver` (`read_pil` / `read_bgr` / `read_file`) and
  numpy ports of the CTC greedy decode and confidence signals.
- `Hamta-solver/live_solve.load_solver()` now selects a backend: torch when
  importable (development, unchanged), otherwise ONNX.
- `lab/scripts/export_hamta_onnx.py` — exports the hamta checkpoint and refuses
  to leave an artifact behind unless both engines return identical result dicts
  (number, text, confidence and snap distance) on every validation sample.
- Bundle build and verifier now ship and check the hamta solver, and the smoke
  test resolves it through `estelam_hamta.load_solver()` rather than the class,
  so a broken `sys.path` cannot reach a user.

### Changed

- `Hamta-solver/utils.py` and `live_solve.py` import torch lazily, so the modules
  stay importable in a torch-free runtime (`number_decode` only needs the
  pure-python edit distance from `utils`).

## [1.0.0] - 2026-08-17

First packaged Windows x64 release.

### Added

- **Per-profile browser visibility.** Browsers launch headed but parked
  off-screen, so several robots can run without cluttering the desktop and
  without the throttling a truly headless session would suffer. Each running
  profile gets a live show/hide button in the panel (`POST /browser-visibility`,
  Win32 `SetWindowPos`, independent of the Selenium session).
- **Paste button beside every profile input**, normalizing Persian/Arabic digits,
  stripping direction marks, with a select-and-hint fallback when the browser
  denies clipboard access.
- **Already-registered detection.** If the pre-payment invoice page appears right
  after the IMEI step, the profile has already been through the flow: the robot
  captures the invoice, saves the payment link, records the profile as *success*
  (with link and screenshot), reports to the panel log and Telegram, and stops
  instead of burning captcha attempts on a pointless retry.
- **Active-tab highlighting** across every tab strip (main navigation, log
  sub-tabs, profile form tabs, and the inquiry service picker): brand gradient
  fill, white label, and an underline, so the current tab is unambiguous.
- **ONNX captcha solver path.** The CRNN solver can run on `onnxruntime`, which is
  what the packaged release ships; PyTorch is no longer required at runtime.

### Changed

- **Durable profile store.** `profiles.json` is now written atomically
  (temp file + `fsync` + `os.replace`) with a `.bak` of the last good copy and an
  in-process cache. A corrupt or partially written file is never overwritten with
  an empty store, so profiles can no longer vanish under load.
- **imeiStep latency.** A one-shot page probe replaces the fixed captcha wait: a
  healthy page is confirmed in roughly a tenth of a second, and a page that
  loaded without a captcha is detected and refreshed almost immediately instead
  of after a ten-second wait.
- **Bounded Telegram delivery.** Every send carries a hard deadline. On timeout
  the robot logs that the screenshot was kept locally and continues to the next
  step, rather than stalling at the pre-payment stage when Telegram is
  unreachable.
- **Submit is always on.** The auto-submit toggle is gone from the UI; disabling
  it is a debugging-only CLI flag (`--no-submit`).

### Fixed

- `--brand2` was undefined in the inquiry page theme, which made the active
  button's gradient invalid and render blank.
- The log view hard-coded the active class on the profile sub-tab regardless of
  the selected mode.
- A blocked `execute_script` is bounded by the page-load timeout, not the script
  timeout; the page probe now clamps both, so a healthy page is never refreshed
  by mistake.
