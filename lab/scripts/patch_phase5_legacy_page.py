#!/usr/bin/env python3
"""One-shot patch for the guarded browser legacy migration center."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]

PAGE = r'''<?php
/**
 * legacy-import.php — browser shell for the reviewed legacy CRM migration.
 *
 * This page never opens the database. It only talks to the authenticated
 * legacy-import API exposed by index.php. The access token exists in browser
 * memory only and the page is deliberately non-cacheable.
 */
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('html_errors', '0');
error_reporting(E_ALL);

define('HOST_ROOT', dirname(__DIR__));
require_once HOST_ROOT . '/src/Config.php';
require_once HOST_ROOT . '/src/Http.php';

function migrationSecurityHeaders(): void
{
    header('Cache-Control: no-store, no-cache, max-age=0, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header("Content-Security-Policy: default-src 'none'; script-src 'self'; "
        . "style-src 'self'; connect-src 'self'; img-src 'self'; "
        . "base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

migrationSecurityHeaders();

$forwardedProto = isset($_SERVER['HTTP_X_FORWARDED_PROTO'])
    && is_string($_SERVER['HTTP_X_FORWARDED_PROTO'])
    ? $_SERVER['HTTP_X_FORWARDED_PROTO'] : '';
$remoteAddr = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
    ? $_SERVER['REMOTE_ADDR'] : '';
$https = isset($_SERVER['HTTPS']) && is_string($_SERVER['HTTPS'])
    ? $_SERVER['HTTPS'] : '';
if (!Request::isSecureTransport($forwardedProto, $remoteAddr, $https)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "HTTPS is required.\n";
    exit;
}

// The page itself is hidden whenever the API kill-switch is off. Reading the
// literal switch from the source makes a disable take effect on the next
// request even under an aggressive OPcache configuration.
if (!Config::freshBoolean('legacy_import_enabled', false)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "Not found.\n";
    exit;
}

try {
    $config = Config::load();
} catch (Throwable $error) {
    unset($error);
    http_response_code(503);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "Migration center is unavailable.\n";
    exit;
}

$basePath = $config['base_path'] ?? '/v1';
if (!is_string($basePath) || $basePath === '' || $basePath[0] !== '/'
    || str_contains($basePath, '..')) {
    $basePath = '/v1';
}
$basePath = rtrim($basePath, '/');
if ($basePath === '') {
    $basePath = '/v1';
}
$maxUpload = (int) ($config['limits']['max_import_body_bytes'] ?? 16777216);
if ($maxUpload < 1024) {
    $maxUpload = 16777216;
}
$maxUpload = min($maxUpload, 67108864);

header('Content-Type: text/html; charset=UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>IRICA Legacy Migration Center</title>
  <link rel="stylesheet" href="legacy-import.css">
  <script src="legacy-import.js" defer></script>
</head>
<body data-api-base="<?= h($basePath) ?>" data-max-upload-bytes="<?= (int) $maxUpload ?>">
  <main class="shell" id="migration-app">
    <header class="hero">
      <div>
        <p class="eyebrow">IRICA · Server CRM v2</p>
        <h1>Legacy Migration Center</h1>
        <p class="hero-copy">Review and migrate a local CRM JSON database from version 1.13.1 or older into the live server dataset.</p>
      </div>
      <div class="mode-badge" aria-label="Migration mode enabled">Migration mode enabled</div>
    </header>

    <section class="warning" aria-label="Safety notice">
      <strong>Temporary maintenance window.</strong>
      Back up the live database first. Keep this page open only while migrating, and set <code>legacy_import_enabled</code> back to <code>false</code> immediately after verification.
    </section>

    <div id="global-status" class="status" role="status" aria-live="polite">Sign in with an administrator account to begin.</div>

    <section class="card" aria-labelledby="login-heading">
      <div class="section-heading">
        <div><span class="step">1</span><h2 id="login-heading">Administrator sign-in</h2></div>
        <button id="logout-button" class="button button-quiet" type="button" hidden>Sign out</button>
      </div>
      <form id="login-form" class="form-grid" autocomplete="on">
        <label>Username
          <input id="username" name="username" type="text" autocomplete="username" maxlength="80" required>
        </label>
        <label>Password
          <input id="password" name="password" type="password" autocomplete="current-password" required>
        </label>
        <div class="form-action">
          <button class="button button-primary" type="submit">Sign in</button>
        </div>
      </form>
      <p id="session-note" class="muted" hidden>Authenticated. The access token is kept only in this page's memory and is never stored in browser storage.</p>
    </section>

    <section class="card" aria-labelledby="upload-heading">
      <div class="section-heading"><div><span class="step">2</span><h2 id="upload-heading">Analyze a legacy database</h2></div></div>
      <fieldset id="migration-fields" disabled>
        <form id="upload-form" class="form-grid form-grid-wide">
          <label class="file-field">Legacy JSON file
            <input id="source-file" name="source_file" type="file" accept=".json,application/json" required>
            <span id="file-limit" class="hint"></span>
          </label>
          <label>Source version <span class="optional">optional</span>
            <input id="source-version" name="source_version" type="text" maxlength="32" placeholder="e.g. 1.13.1">
            <span class="hint">Leave blank when the old store already contains a version or had no formal version marker.</span>
          </label>
          <div class="form-action">
            <button class="button button-primary" type="submit">Analyze and stage</button>
          </div>
        </form>
        <div class="divider"><span>or resume</span></div>
        <form id="resume-form" class="resume-row">
          <label>Migration job UUID
            <input id="resume-job-id" type="text" maxlength="36" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required>
          </label>
          <button class="button button-secondary" type="submit">Load review</button>
        </form>
      </fieldset>
    </section>

    <section id="review-section" class="card" aria-labelledby="review-heading" hidden>
      <div class="section-heading">
        <div><span class="step">3</span><h2 id="review-heading">Review staged records</h2></div>
        <button id="refresh-review" class="button button-quiet" type="button">Refresh</button>
      </div>
      <dl class="job-meta">
        <div><dt>Job</dt><dd id="job-id">—</dd></div>
        <div><dt>Source version</dt><dd id="job-version">—</dd></div>
        <div><dt>Status</dt><dd id="job-status">—</dd></div>
        <div><dt>Unresolved</dt><dd id="job-unresolved">—</dd></div>
        <div class="hash-row"><dt>SHA-256</dt><dd id="job-hash">—</dd></div>
      </dl>
      <div id="count-grid" class="count-grid" aria-label="Migration counts"></div>
      <p class="muted">Possible conflicts are never merged automatically. Expand a row to inspect its normalized source data. Sensitive data is shown only in this non-cacheable administrator session.</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Entity</th><th>Source key</th><th>Source preview</th><th>Detected</th><th>Decision</th><th>Issues</th><th>Review action</th></tr></thead>
          <tbody id="records-body"></tbody>
        </table>
      </div>
    </section>

    <section id="apply-section" class="card apply-card" aria-labelledby="apply-heading" hidden>
      <div class="section-heading"><div><span class="step">4</span><h2 id="apply-heading">Apply to the live CRM</h2></div></div>
      <p>Apply is atomic: accepted rows commit together or the database transaction rolls back. Replaying the same completed job does not duplicate records.</p>
      <button id="apply-button" class="button button-danger" type="button" disabled>Apply reviewed migration</button>
      <p id="apply-note" class="muted">Resolve every conflict and invalid row before applying.</p>
    </section>
  </main>
</body>
</html>
'''

CSS = r''':root {
  color-scheme: light;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #f3f5f8;
  color: #17202a;
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: #f3f5f8; }
button, input { font: inherit; }
.shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 42px 0 80px; }
.hero { display: flex; align-items: flex-start; justify-content: space-between; gap: 28px; margin-bottom: 22px; }
.eyebrow { margin: 0 0 8px; color: #526173; font-size: 12px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
h1 { margin: 0; font-size: clamp(30px, 5vw, 48px); letter-spacing: -.035em; }
h2 { display: inline; margin: 0; font-size: 20px; }
.hero-copy { max-width: 760px; margin: 10px 0 0; color: #526173; line-height: 1.55; }
.mode-badge { flex: 0 0 auto; border: 1px solid #efb654; background: #fff7e6; color: #7a4a00; border-radius: 999px; padding: 8px 12px; font-size: 13px; font-weight: 800; }
.warning { border-left: 4px solid #d68a00; border-radius: 10px; background: #fff7e6; padding: 16px 18px; line-height: 1.55; margin-bottom: 16px; }
.status { min-height: 46px; display: flex; align-items: center; border-radius: 10px; padding: 12px 16px; margin-bottom: 16px; background: #eaf0f7; color: #33465c; }
.status[data-kind="success"] { background: #e8f7ee; color: #195c32; }
.status[data-kind="error"] { background: #fdecec; color: #8a2424; }
.status[data-kind="warning"] { background: #fff5df; color: #765000; }
.card { background: #fff; border: 1px solid #dde3ea; border-radius: 16px; padding: 22px; margin-top: 16px; box-shadow: 0 8px 26px rgba(22, 34, 49, .045); }
.section-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
.step { display: inline-grid; place-items: center; width: 29px; height: 29px; margin-right: 10px; border-radius: 9px; background: #17202a; color: #fff; font-weight: 800; font-size: 13px; }
.form-grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 14px; align-items: end; }
.form-grid-wide { grid-template-columns: minmax(280px, 1.2fr) minmax(230px, .8fr) auto; }
label { display: grid; gap: 7px; font-size: 13px; font-weight: 750; color: #33465c; }
input { width: 100%; border: 1px solid #cdd6e0; border-radius: 9px; padding: 10px 11px; background: #fff; color: #17202a; outline: none; }
input:focus { border-color: #557ca8; box-shadow: 0 0 0 3px rgba(85, 124, 168, .14); }
fieldset { border: 0; padding: 0; margin: 0; min-width: 0; }
fieldset:disabled { opacity: .56; }
.form-action { display: flex; align-items: flex-end; }
.button { border: 0; border-radius: 9px; padding: 10px 14px; cursor: pointer; font-weight: 800; white-space: nowrap; }
.button:disabled { cursor: not-allowed; opacity: .45; }
.button-primary { background: #1e5e95; color: #fff; }
.button-secondary { background: #e8eef5; color: #20364b; }
.button-quiet { background: transparent; color: #365a7b; border: 1px solid #d3dce6; }
.button-danger { background: #9f2f2f; color: #fff; }
.button-small { padding: 7px 9px; font-size: 12px; }
.hint, .optional, .muted { color: #687789; font-size: 12px; font-weight: 500; line-height: 1.5; }
.divider { display: flex; align-items: center; gap: 12px; color: #8390a0; font-size: 12px; margin: 20px 0 14px; }
.divider::before, .divider::after { content: ""; height: 1px; background: #e2e7ed; flex: 1; }
.resume-row { display: grid; grid-template-columns: minmax(260px, 1fr) auto; gap: 12px; align-items: end; }
.job-meta { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 0 0 16px; }
.job-meta > div { border: 1px solid #e2e7ed; border-radius: 10px; padding: 10px 12px; min-width: 0; }
.job-meta dt { color: #738092; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; }
.job-meta dd { margin: 4px 0 0; font-weight: 800; overflow-wrap: anywhere; }
.job-meta .hash-row { grid-column: 1 / -1; }
.count-grid { display: grid; grid-template-columns: repeat(7, minmax(90px, 1fr)); gap: 8px; margin-bottom: 14px; }
.count-item { border-radius: 10px; background: #f5f7fa; padding: 10px; }
.count-item strong { display: block; font-size: 20px; }
.count-item span { color: #687789; font-size: 11px; text-transform: uppercase; }
.table-wrap { width: 100%; overflow-x: auto; border: 1px solid #e1e6ec; border-radius: 12px; }
table { width: 100%; border-collapse: collapse; min-width: 980px; font-size: 12px; }
th, td { padding: 10px; border-bottom: 1px solid #e8ecf1; text-align: left; vertical-align: top; }
th { background: #f7f9fb; color: #536375; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: 0; }
.badge { display: inline-flex; border-radius: 999px; padding: 4px 7px; background: #edf1f5; color: #3a4d61; font-weight: 800; }
.badge-conflict, .badge-invalid { background: #fdecec; color: #8a2424; }
.badge-create { background: #e8f7ee; color: #195c32; }
.badge-skip { background: #eef1f5; color: #506171; }
.badge-merge { background: #e7f2fb; color: #205b84; }
.badge-reject { background: #f3e9e9; color: #793636; }
.source-details summary { cursor: pointer; font-weight: 700; color: #365a7b; max-width: 260px; }
.source-details pre { max-width: 430px; max-height: 260px; overflow: auto; white-space: pre-wrap; word-break: break-word; background: #f6f8fa; border-radius: 8px; padding: 10px; font-size: 11px; }
.decision-controls { display: grid; gap: 7px; min-width: 210px; }
.decision-buttons { display: flex; flex-wrap: wrap; gap: 5px; }
.target-input { font-size: 11px; padding: 7px; }
.apply-card { border-color: #e7c7c7; }
code { background: rgba(0, 0, 0, .055); padding: 2px 5px; border-radius: 5px; }
[hidden] { display: none !important; }
@media (max-width: 820px) {
  .shell { width: min(100% - 20px, 1180px); padding-top: 24px; }
  .hero { flex-direction: column; }
  .form-grid, .form-grid-wide, .resume-row { grid-template-columns: 1fr; }
  .job-meta { grid-template-columns: 1fr 1fr; }
  .count-grid { grid-template-columns: repeat(3, 1fr); }
  .form-action .button, .resume-row .button { width: 100%; }
}
@media (max-width: 500px) {
  .card { padding: 16px; }
  .job-meta { grid-template-columns: 1fr; }
  .job-meta .hash-row { grid-column: auto; }
  .count-grid { grid-template-columns: 1fr 1fr; }
}
'''

JS = r'''(() => {
  "use strict";

  const body = document.body;
  const apiBase = String(body.dataset.apiBase || "/v1").replace(/\/+$/, "");
  const maxUploadBytes = Number(body.dataset.maxUploadBytes || 16777216);
  const byId = (id) => document.getElementById(id);

  const statusBox = byId("global-status");
  const loginForm = byId("login-form");
  const logoutButton = byId("logout-button");
  const sessionNote = byId("session-note");
  const migrationFields = byId("migration-fields");
  const uploadForm = byId("upload-form");
  const sourceFile = byId("source-file");
  const sourceVersion = byId("source-version");
  const resumeForm = byId("resume-form");
  const resumeJobId = byId("resume-job-id");
  const reviewSection = byId("review-section");
  const applySection = byId("apply-section");
  const applyButton = byId("apply-button");
  const applyNote = byId("apply-note");
  const refreshReview = byId("refresh-review");
  const recordsBody = byId("records-body");
  const countGrid = byId("count-grid");

  let accessToken = "";
  let reviewState = null;
  let busyDecision = "";

  const ERROR_TEXT = Object.freeze({
    AUTH_REQUIRED: "Authentication failed or the session expired. Sign in again.",
    AUTH_EXPIRED: "The administrator session expired. Sign in again.",
    AUTH_REVOKED: "The administrator session was revoked. Sign in again.",
    ROLE_FORBIDDEN: "An administrator account is required for legacy migration.",
    PERMISSION_DENIED: "Legacy migration is disabled on this host. Re-enable the temporary migration window in config.php.",
    BAD_PAYLOAD: "The request was not accepted. Check the selected file or migration job ID.",
    VALIDATION_FAILED: "The legacy data failed validation. Review the staged issues before continuing.",
    VERSION_CONFLICT: "The migration job changed or still needs review. Refresh the review and try again.",
    NOT_FOUND: "The requested migration job or merge target was not found.",
    PAYLOAD_TOO_LARGE: "The selected legacy database exceeds the configured migration upload limit.",
    RATE_LIMITED: "Too many requests. Wait briefly before trying again.",
    DB_UNAVAILABLE: "The migration service cannot reach the database.",
    SERVER_ERROR: "The migration service returned an internal error. Check the server log using the request ID."
  });

  class UiApiError extends Error {
    constructor(code, requestId, status) {
      super(code || "REQUEST_FAILED");
      this.name = "UiApiError";
      this.code = code || "REQUEST_FAILED";
      this.requestId = requestId || "";
      this.status = status || 0;
    }
  }

  function setStatus(message, kind = "info") {
    statusBox.textContent = message;
    statusBox.dataset.kind = kind;
  }

  function errorText(error) {
    if (error instanceof UiApiError) {
      const base = ERROR_TEXT[error.code] || "The migration request failed safely.";
      return error.requestId ? `${base} Request ID: ${error.requestId}` : base;
    }
    return "The browser could not complete the migration request.";
  }

  function apiUrl(path) {
    return `${apiBase}${path}`;
  }

  async function apiCall(path, options = {}) {
    const method = options.method || "GET";
    const useAuth = options.useAuth !== false;
    const headers = {Accept: "application/json"};
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (useAuth) {
      if (!accessToken) {
        throw new UiApiError("AUTH_REQUIRED", "", 401);
      }
      headers.Authorization = `Bearer ${accessToken}`;
    }
    let response;
    try {
      response = await fetch(apiUrl(path), {
        method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer"
      });
    } catch (error) {
      throw new UiApiError("NETWORK_ERROR", "", 0);
    }
    let payload = null;
    try {
      payload = await response.json();
    } catch (error) {
      throw new UiApiError("BAD_RESPONSE", "", response.status);
    }
    if (!response.ok || !payload || payload.ok !== true) {
      const envelope = payload && payload.error && typeof payload.error === "object"
        ? payload.error : {};
      const error = new UiApiError(
        typeof envelope.code === "string" ? envelope.code : "REQUEST_FAILED",
        typeof envelope.request_id === "string" ? envelope.request_id : "",
        response.status
      );
      if (["AUTH_REQUIRED", "AUTH_EXPIRED", "AUTH_REVOKED"].includes(error.code)) {
        clearSession(false);
      }
      throw error;
    }
    return payload;
  }

  function clearNode(node) {
    node.replaceChildren();
  }

  function clearSession(showMessage = true) {
    accessToken = "";
    reviewState = null;
    busyDecision = "";
    migrationFields.disabled = true;
    logoutButton.hidden = true;
    sessionNote.hidden = true;
    loginForm.hidden = false;
    reviewSection.hidden = true;
    applySection.hidden = true;
    clearNode(recordsBody);
    clearNode(countGrid);
    byId("password").value = "";
    if (showMessage) {
      setStatus("Signed out. The in-memory access token has been cleared.", "info");
    }
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
    const units = ["B", "KiB", "MiB", "GiB"];
    let size = bytes;
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  }

  byId("file-limit").textContent = `Configured source limit: ${formatBytes(maxUploadBytes)}.`;

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = byId("username").value.trim();
    const passwordField = byId("password");
    const password = passwordField.value;
    if (!username || !password) {
      setStatus("Enter the administrator username and password.", "error");
      return;
    }
    setStatus("Signing in…", "info");
    try {
      const payload = await apiCall("/auth/login", {
        method: "POST",
        useAuth: false,
        body: {username, password}
      });
      if (!payload.user || payload.user.role !== "admin" || typeof payload.access_token !== "string") {
        throw new UiApiError("ROLE_FORBIDDEN", "", 403);
      }
      accessToken = payload.access_token;
      migrationFields.disabled = false;
      logoutButton.hidden = false;
      sessionNote.hidden = false;
      loginForm.hidden = true;
      setStatus("Administrator session active. Upload the legacy JSON file for dry-run analysis.", "success");
    } catch (error) {
      accessToken = "";
      setStatus(errorText(error), "error");
    } finally {
      passwordField.value = "";
    }
  });

  logoutButton.addEventListener("click", async () => {
    if (accessToken) {
      try {
        await apiCall("/auth/logout", {method: "POST", body: {}});
      } catch (error) {
        // Local sign-out still clears the only browser copy of the token.
      }
    }
    clearSession(true);
  });

  uploadForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = sourceFile.files && sourceFile.files[0];
    if (!file) {
      setStatus("Choose the legacy CRM JSON file first.", "error");
      return;
    }
    if (file.size > maxUploadBytes) {
      setStatus(`The file is ${formatBytes(file.size)}; the configured source limit is ${formatBytes(maxUploadBytes)}.`, "error");
      return;
    }
    let sourceText = "";
    try {
      setStatus("Reading and validating the selected JSON file…", "info");
      sourceText = await file.text();
      JSON.parse(sourceText);
      const bodyPayload = {source_text: sourceText, filename: file.name};
      const version = sourceVersion.value.trim();
      if (version) bodyPayload.source_version = version;
      setStatus("Analyzing and staging. Live CRM rows are not modified during this step…", "info");
      const payload = await apiCall("/legacy-import/analyze", {
        method: "POST",
        body: bodyPayload
      });
      renderReview(payload);
      setStatus("Analysis complete. Review every conflict or invalid row before apply.", "success");
    } catch (error) {
      if (error instanceof SyntaxError) {
        setStatus("The selected file is not valid JSON.", "error");
      } else {
        setStatus(errorText(error), "error");
      }
    } finally {
      sourceText = "";
      sourceFile.value = "";
    }
  });

  resumeForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const jobId = resumeJobId.value.trim();
    if (!jobId) return;
    await loadReview(jobId);
  });

  refreshReview.addEventListener("click", async () => {
    const jobId = reviewState && reviewState.job ? reviewState.job.id : "";
    if (jobId) await loadReview(jobId);
  });

  async function loadReview(jobId) {
    setStatus("Loading staged migration review…", "info");
    try {
      const payload = await apiCall(`/legacy-import/review?job_id=${encodeURIComponent(jobId)}`);
      renderReview(payload);
      setStatus("Migration review refreshed.", "success");
    } catch (error) {
      setStatus(errorText(error), "error");
    }
  }

  function normalizedReview(payload) {
    const records = Array.isArray(payload.records) ? payload.records.map((row) => {
      const detected = String(row.detected_action || row.action || "pending");
      const decision = typeof row.decision === "string" ? row.decision : null;
      return {
        id: String(row.id || ""),
        entity: String(row.entity || ""),
        source_key: String(row.source_key || ""),
        detected_action: detected,
        decision,
        effective_action: String(row.effective_action || decision || detected),
        target_id: typeof row.target_id === "string" ? row.target_id : "",
        record: row.record && typeof row.record === "object" ? row.record : {},
        issues: Array.isArray(row.issues) ? row.issues : []
      };
    }) : [];
    let unresolved = Number(payload.unresolved);
    if (!Number.isFinite(unresolved)) {
      unresolved = records.filter((row) => !row.decision && ["pending", "conflict", "invalid"].includes(row.detected_action)).length;
    }
    return {
      job: payload.job && typeof payload.job === "object" ? payload.job : {},
      counts: payload.counts && typeof payload.counts === "object" ? payload.counts : {},
      unresolved,
      records
    };
  }

  function renderReview(payload) {
    reviewState = normalizedReview(payload);
    const job = reviewState.job;
    byId("job-id").textContent = String(job.id || "—");
    byId("job-version").textContent = String(job.source_version || "unmarked legacy store");
    byId("job-status").textContent = String(job.status || "—");
    byId("job-unresolved").textContent = String(reviewState.unresolved);
    byId("job-hash").textContent = String(job.source_sha256 || "—");
    resumeJobId.value = String(job.id || "");
    renderCounts(reviewState.counts);
    renderRecords(reviewState.records, String(job.status || ""));
    reviewSection.hidden = false;
    applySection.hidden = false;
    const ready = reviewState.unresolved === 0 && job.status === "ready";
    const applied = job.status === "applied";
    applyButton.disabled = !ready;
    if (applied) {
      applyNote.textContent = "This migration job has already been applied. Replaying apply is idempotent, but no second apply is needed.";
    } else if (ready) {
      applyNote.textContent = "Review is complete. Apply will run one atomic database transaction.";
    } else {
      applyNote.textContent = `Resolve ${reviewState.unresolved} staged row(s) before applying.`;
    }
  }

  function renderCounts(counts) {
    clearNode(countGrid);
    ["create", "merge", "skip", "reject", "conflict", "invalid", "pending"].forEach((key) => {
      const box = document.createElement("div");
      box.className = "count-item";
      const value = document.createElement("strong");
      value.textContent = String(Number(counts[key] || 0));
      const label = document.createElement("span");
      label.textContent = key;
      box.append(value, label);
      countGrid.append(box);
    });
  }

  function clipped(value, max = 70) {
    if (value === null || value === undefined || value === "") return "";
    const text = String(value);
    return text.length > max ? `${text.slice(0, max)}…` : text;
  }

  function sourcePreview(row) {
    const record = row.record || {};
    const pieces = [];
    const add = (label, value) => {
      const text = clipped(value);
      if (text) pieces.push(`${label}: ${text}`);
    };
    switch (row.entity) {
      case "customers": add("name", record.full_name); add("mobile", record.mobile); break;
      case "owners": add("name", `${record.first_name || ""} ${record.last_name || ""}`.trim()); add("national", record.national); break;
      case "identities": add("label", record.label); add("national", record.national); break;
      case "crm_devices": add("name", record.name); add("serial", record.serial1); break;
      case "periods": add("number", record.number); add("label", record.label); break;
      case "customer_transactions": add("at", record.at); add("amount", record.amount); add("kind", record.kind); break;
      case "settings": add("business", record.business_name); add("phone", record.business_phone); break;
      default: add("id", record.id); break;
    }
    return pieces.join(" · ") || "Open details";
  }

  function badge(text) {
    const span = document.createElement("span");
    const safe = String(text || "pending").toLowerCase();
    span.className = `badge badge-${safe}`;
    span.textContent = safe;
    return span;
  }

  function textCell(text) {
    const td = document.createElement("td");
    td.textContent = String(text || "—");
    return td;
  }

  function detailsCell(row) {
    const td = document.createElement("td");
    const details = document.createElement("details");
    details.className = "source-details";
    const summary = document.createElement("summary");
    summary.textContent = sourcePreview(row);
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(row.record, null, 2);
    details.append(summary, pre);
    td.append(details);
    return td;
  }

  function issuesCell(row) {
    const td = document.createElement("td");
    if (!row.issues.length) {
      td.textContent = "—";
      return td;
    }
    const list = document.createElement("ul");
    row.issues.forEach((issue) => {
      const item = document.createElement("li");
      const code = issue && typeof issue.code === "string" ? issue.code : "ISSUE";
      const field = issue && typeof issue.field === "string" ? issue.field : "";
      item.textContent = field ? `${code}: ${field}` : code;
      list.append(item);
    });
    td.append(list);
    return td;
  }

  function decisionCell(row, jobStatus) {
    const td = document.createElement("td");
    if (!["conflict", "invalid", "pending"].includes(row.detected_action) || jobStatus === "applied") {
      td.textContent = row.decision || "—";
      return td;
    }
    const wrap = document.createElement("div");
    wrap.className = "decision-controls";
    if (row.decision) {
      const current = document.createElement("span");
      current.textContent = `Current decision: ${row.decision}`;
      current.className = "muted";
      wrap.append(current);
    }
    const target = document.createElement("input");
    target.type = "text";
    target.className = "target-input";
    target.maxLength = 36;
    target.placeholder = "Verified target UUID for merge/skip";
    target.value = row.target_id || "";
    target.setAttribute("aria-label", `Target UUID for ${row.entity} ${row.source_key}`);
    if (row.detected_action !== "invalid") wrap.append(target);

    const buttons = document.createElement("div");
    buttons.className = "decision-buttons";
    const resolutions = row.detected_action === "invalid"
      ? ["reject"] : ["merge", "skip", "create", "reject"];
    resolutions.forEach((resolution) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = resolution === "reject" ? "button button-small button-quiet" : "button button-small button-secondary";
      button.textContent = resolution;
      button.disabled = busyDecision === row.id || ((resolution === "merge" || resolution === "skip") && !target.value.trim());
      if (resolution === "merge" || resolution === "skip") {
        target.addEventListener("input", () => {
          button.disabled = busyDecision === row.id || !target.value.trim();
        });
      }
      button.addEventListener("click", () => submitDecision(row, resolution, target.value.trim()));
      buttons.append(button);
    });
    wrap.append(buttons);
    if (!row.target_id && row.detected_action === "conflict") {
      const hint = document.createElement("span");
      hint.className = "hint";
      hint.textContent = "Multiple live candidates matched. The server will not guess a target; enter a verified UUID or choose create/reject.";
      wrap.append(hint);
    }
    td.append(wrap);
    return td;
  }

  function renderRecords(records, jobStatus) {
    clearNode(recordsBody);
    records.forEach((row) => {
      const tr = document.createElement("tr");
      tr.append(textCell(row.entity));
      tr.append(textCell(row.source_key));
      tr.append(detailsCell(row));
      const detected = document.createElement("td");
      detected.append(badge(row.detected_action));
      tr.append(detected);
      const decision = document.createElement("td");
      decision.append(badge(row.effective_action));
      tr.append(decision);
      tr.append(issuesCell(row));
      tr.append(decisionCell(row, jobStatus));
      recordsBody.append(tr);
    });
  }

  async function submitDecision(row, resolution, targetId) {
    if (!reviewState || !reviewState.job || busyDecision) return;
    if ((resolution === "merge" || resolution === "skip") && !targetId) {
      setStatus("Merge and skip require a verified live target UUID.", "error");
      return;
    }
    busyDecision = row.id;
    setStatus(`Saving ${resolution} decision for ${row.entity}…`, "info");
    try {
      const bodyPayload = {
        job_id: String(reviewState.job.id),
        record_id: row.id,
        resolution
      };
      if (resolution === "merge" || resolution === "skip") bodyPayload.target_id = targetId;
      const payload = await apiCall("/legacy-import/decision", {method: "POST", body: bodyPayload});
      renderReview(payload);
      setStatus("Review decision saved.", "success");
    } catch (error) {
      setStatus(errorText(error), "error");
    } finally {
      busyDecision = "";
    }
  }

  applyButton.addEventListener("click", async () => {
    if (!reviewState || !reviewState.job || applyButton.disabled) return;
    const jobId = String(reviewState.job.id || "");
    const confirmed = window.confirm(
      "Apply this reviewed migration to the live CRM? Accepted rows commit in one database transaction. Verify that a server backup exists before continuing."
    );
    if (!confirmed) return;
    applyButton.disabled = true;
    setStatus("Applying reviewed migration atomically…", "warning");
    try {
      const result = await apiCall("/legacy-import/apply", {
        method: "POST",
        body: {job_id: jobId}
      });
      const counts = result.counts || {};
      setStatus(
        `Migration applied. Created ${Number(counts.created || 0)}, merged ${Number(counts.merged || 0)}, skipped ${Number(counts.skipped || 0)}, rejected ${Number(counts.rejected || 0)}. Verify totals and balances, then disable migration mode.`,
        "success"
      );
      await loadReview(jobId);
    } catch (error) {
      setStatus(errorText(error), "error");
      applyButton.disabled = false;
    }
  });

  window.addEventListener("pagehide", () => {
    accessToken = "";
    reviewState = null;
  });
})();
'''

TEST = r'''# -*- coding: utf-8 -*-
"""Security and delivery gates for the browser legacy migration center."""
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PUBLIC = os.path.join(ROOT, "host", "public")
PAGE = os.path.join(PUBLIC, "legacy-import.php")
JS = os.path.join(PUBLIC, "legacy-import.js")
CSS = os.path.join(PUBLIC, "legacy-import.css")


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


class LegacyMigrationPageStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = read(PAGE)
        cls.js = read(JS)
        cls.css = read(CSS)

    def test_page_is_api_only_and_fail_closed(self):
        self.assertIn("Config::freshBoolean('legacy_import_enabled', false)", self.page)
        self.assertIn("Request::isSecureTransport", self.page)
        self.assertNotIn("Database::", self.page)
        self.assertNotIn("PDO", self.page)
        self.assertNotIn("SELECT ", self.page)
        self.assertNotIn("INSERT ", self.page)
        self.assertNotIn("UPDATE ", self.page)

    def test_page_uses_external_assets_under_a_strict_csp(self):
        self.assertIn("default-src 'none'", self.page)
        self.assertIn("script-src 'self'", self.page)
        self.assertIn("style-src 'self'", self.page)
        self.assertIn("connect-src 'self'", self.page)
        self.assertIn("frame-ancestors 'none'", self.page)
        self.assertNotIn("unsafe-inline", self.page)
        self.assertIn('src="legacy-import.js"', self.page)
        self.assertIn('href="legacy-import.css"', self.page)

    def test_browser_token_is_memory_only(self):
        for forbidden in ("localStorage", "sessionStorage", "document.cookie", "indexedDB"):
            self.assertNotIn(forbidden, self.js)
        self.assertIn('let accessToken = ""', self.js)
        self.assertIn('byId("password").value = ""', self.js)
        self.assertIn('credentials: "omit"', self.js)
        self.assertNotIn("innerHTML", self.js)

    def test_all_migration_steps_use_the_http_api(self):
        for route in (
            "/auth/login", "/auth/logout", "/legacy-import/analyze",
            "/legacy-import/review", "/legacy-import/decision",
            "/legacy-import/apply",
        ):
            self.assertIn(route, self.js)
        self.assertIn("file.text()", self.js)
        self.assertIn("JSON.parse(sourceText)", self.js)
        self.assertIn("window.confirm", self.js)
        self.assertIn("maxUploadBytes", self.js)

    def test_styles_cover_review_and_mobile_layout(self):
        for selector in (".table-wrap", ".decision-controls", ".count-grid", "@media"):
            self.assertIn(selector, self.css)


class LegacyMigrationPageHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        if not cls.php:
            raise unittest.SkipTest("PHP CLI is not available")
        cls.tmp = tempfile.mkdtemp(prefix="irica_legacy_page_")
        cls.config = os.path.join(cls.tmp, "config.php")
        cls._write_config(False)
        cls.port = cls._free_port()
        cls.log = open(os.path.join(cls.tmp, "server.log"), "wb")
        env = dict(os.environ)
        env["IRICA_HOST_CONFIG"] = cls.config
        cls.server = subprocess.Popen(
            [cls.php, "-d", "display_errors=0", "-S", "127.0.0.1:%d" % cls.port,
             "-t", PUBLIC], stdout=cls.log, stderr=subprocess.STDOUT,
            cwd=ROOT, env=env,
        )
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls._wait_ready()

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server is not None and server.poll() is None:
            server.kill()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        log = getattr(cls, "log", None)
        if log is not None and not log.closed:
            log.close()
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    @classmethod
    def _free_port(cls):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    @classmethod
    def _write_config(cls, enabled):
        flag = "true" if enabled else "false"
        source = """<?php
return [
  'base_path' => '/v1',
  'legacy_import_enabled' => %s,
  'db' => ['host'=>'127.0.0.1','port'=>3306,'dbname'=>'unit_db','user'=>'unit_user','password'=>'unit_password'],
  'jwt_secret' => '%s',
  'limits' => ['max_body_bytes'=>1048576,'max_import_body_bytes'=>16777216],
];
""" % (flag, "a" * 64)
        with open(cls.config, "w", encoding="utf-8") as handle:
            handle.write(source)

    @classmethod
    def _request(cls, path):
        request = urllib.request.Request(cls.base + path, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, dict(response.headers.items()), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers.items()), error.read().decode("utf-8", "replace")

    @classmethod
    def _wait_ready(cls):
        deadline = time.time() + 15
        while time.time() < deadline:
            if cls.server.poll() is not None:
                raise AssertionError("PHP test server exited early")
            try:
                status, _headers, _body = cls._request("/legacy-import.css")
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise AssertionError("PHP test server did not become ready")

    def setUp(self):
        self._write_config(False)

    def test_page_is_hidden_while_kill_switch_is_off(self):
        status, headers, body = self._request("/legacy-import.php")
        self.assertEqual(status, 404)
        self.assertEqual(body, "Not found.\n")
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertNotIn("Set-Cookie", headers)

    def test_enabled_page_has_strict_security_headers_and_no_secret_bootstrap(self):
        self._write_config(True)
        status, headers, body = self._request("/legacy-import.php")
        self.assertEqual(status, 200)
        self.assertIn("Legacy Migration Center", body)
        self.assertIn('data-api-base="/v1"', body)
        self.assertIn('data-max-upload-bytes="16777216"', body)
        csp = headers.get("Content-Security-Policy", "")
        for rule in ("default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"):
            self.assertIn(rule, csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("jwt_secret", body)
        self.assertNotIn("unit_password", body)

    def test_disable_takes_effect_on_the_next_request_in_same_server_process(self):
        self._write_config(True)
        self.assertEqual(self._request("/legacy-import.php")[0], 200)
        self._write_config(False)
        self.assertEqual(self._request("/legacy-import.php")[0], 404)

    def test_external_assets_are_reachable_without_dynamic_credentials(self):
        for path, marker in (("/legacy-import.js", "/legacy-import/analyze"),
                             ("/legacy-import.css", ".decision-controls")):
            status, _headers, body = self._request(path)
            self.assertEqual(status, 200)
            self.assertIn(marker, body)


if __name__ == "__main__":
    unittest.main()
'''


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise RuntimeError(f"refusing to overwrite existing file: {path}")
    target.write_text(content, encoding="utf-8", newline="\n")


def patch_workflow() -> None:
    path = ROOT / ".github" / "workflows" / "server-crm-v2.yml"
    text = path.read_text(encoding="utf-8")
    old = "          test_server_crm_v2_legacy_import\n          test_server_crm_v2_legacy_apply\n"
    new = old + "          test_server_crm_v2_legacy_page\n"
    if text.count(old) != 1:
        raise RuntimeError("permanent host test list anchor changed")
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def main() -> None:
    write("host/public/legacy-import.php", PAGE)
    write("host/public/legacy-import.css", CSS)
    write("host/public/legacy-import.js", JS)
    write("lab/tests/test_server_crm_v2_legacy_page.py", TEST)
    patch_workflow()
    print("legacy migration center patch applied")


if __name__ == "__main__":
    main()
