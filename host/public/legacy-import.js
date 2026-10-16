(() => {
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
