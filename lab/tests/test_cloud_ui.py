# -*- coding: utf-8 -*-
"""Cloud sync UI — spec §9 (what the operator must see), §11 (the surface)
and §15.12 (a machine event must never be swallowed), workstream D.

What is pinned here:

* every connection state renders through the SHIPPED ``paintCloud`` in node —
  not a Python twin, which would keep passing while the page drifted;
* the read-only banner is driven by the 7-day lease, and a machine that has
  NEVER signed in is deliberately not read-only;
* every stable code the client can emit has Persian wording, and that wording
  contains no ASCII at all, so a token, a code or a server sentence cannot be
  hiding inside it;
* an error answer always carries a code from that table — never the server's
  own words;
* the cloud POSTs ride the panel's existing CSRF bootstrap, and
  ``IllegalTransitionError`` / ``LeaseExpiredError`` are caught BY NAME at the
  route boundary instead of falling into one of panel.py's generic handlers;
* the worker starts only when a base URL exists and stops at an expired lease;
* ``must_change_password`` is visible;
* no token, credential or PII reaches a rendered string.

Offline throughout: a loopback panel server, mocks and a temp directory. The
live data directory (``%LOCALAPPDATA%\\irica``) is never touched — the runner
points ``IRICA_DATA_DIR`` at a scratch folder before anything imports
``app_paths``.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from unittest.mock import patch

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TESTS = os.path.dirname(os.path.abspath(__file__))
for path in (ROOT, TESTS):
    if path not in sys.path:
        sys.path.insert(0, path)

import app_paths  # noqa: E402
import panel  # noqa: E402
import panel_auth  # noqa: E402
from cloud_sync.errors import (  # noqa: E402
    CLIENT_ERROR_CODES, AuthRequiredError, ConfigError)
from cloud_sync.lease import LEASE_SECONDS, OfflineLease  # noqa: E402
from cloud_sync.state import (  # noqa: E402
    KNOWN_ERROR_CODES, IllegalTransitionError, SyncEvent, SyncState)

NODE = shutil.which("node")


def all_known_codes():
    """Every code the client may emit plus every code workstream A documented."""
    return sorted(set(CLIENT_ERROR_CODES) | set(KNOWN_ERROR_CODES))


def reset_cloud_panel():
    """Forget the cached runtime, the RAM-only actor and the worker globals.

    Nothing here writes to disk: the runtime cache and the worker handle are
    process-wide, so a test that left one behind would decide the next one.
    """
    thread = panel.cloud_worker_stop()
    if thread is not None:
        thread.join(timeout=5)
    panel._CLOUD_RUNTIME = None
    panel._CLOUD_ACTOR = None
    panel._CLOUD_MUST_CHANGE = False
    panel._CLOUD_LAST_BEAT = None
    panel._CLOUD_WORKER_STOP = False
    panel._CLOUD_WORKER_KICK = False
    panel._CLOUD_WORKER_THREAD = None


def fn_body(js, name):
    """The source of `function name(...){...}`, quotes inside it respected."""
    start = js.find("function " + name + "(")
    if start < 0:
        return ""
    i = js.find("{", start)
    if i < 0:
        return ""
    depth, quote, i = 0, "", i
    while i < len(js):
        ch = js[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return js[start:i + 1]
        i += 1
    return ""


def block_after(js, marker, terminator):
    """A top-level `var X = {...};` block ending at `terminator`."""
    start = js.find(marker)
    if start < 0:
        return ""
    end = js.find(terminator, start)
    if end < 0:
        return ""
    return js[start:end + len(terminator)]


def node_syntax(script):
    """`node --check` on `script`; return (code, stderr). Syntax only."""
    if not NODE:
        return None, "node is not installed"
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     encoding="utf-8") as handle:
        handle.write(script)
        path = handle.name
    try:
        proc = subprocess.run([NODE, "--check", path], capture_output=True,
                              text=True, timeout=60)
        return proc.returncode, proc.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def run_node(script, timeout=60):
    """Run `script` with node; return (code, stdout, stderr)."""
    if not NODE:
        return None, "", "node is not installed"
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     encoding="utf-8") as handle:
        handle.write(script)
        path = handle.name
    try:
        proc = subprocess.run([NODE, path], capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# =====================================================================
# 1. The Persian table: one wording per stable code, nothing else
# =====================================================================
class ErrorMessageTableTests(unittest.TestCase):
    def test_every_known_code_is_mapped(self):
        missing = [c for c in all_known_codes()
                   if c not in panel.CLOUD_ERROR_MESSAGES]
        self.assertEqual(missing, [])

    def test_the_two_codes_the_client_can_raise_first_are_mapped(self):
        # Spec §5/§9: these are the answers a host gives most often, and
        # ENROL_REQUIRED is the one that tells the operator what to DO.
        for code in ("AUTH_REQUIRED", "ENROL_REQUIRED"):
            self.assertIn(code, panel.CLOUD_ERROR_MESSAGES)
            self.assertTrue(panel.cloud_error_message(code))

    def test_no_message_can_carry_ascii(self):
        # A code passes manager ruling 8's grammar, so ASCII inside a
        # message could only be a token, a code or a server sentence.
        dirty = {c: m for c, m in panel.CLOUD_ERROR_MESSAGES.items()
                 if re.search(r"[A-Za-z0-9]", m)}
        self.assertEqual(dirty, {})
        self.assertIsNone(re.search(r"[A-Za-z0-9]",
                                    panel.CLOUD_UNKNOWN_MESSAGE))

    def test_messages_follow_the_persian_rules(self):
        for code, message in panel.CLOUD_ERROR_MESSAGES.items():
            self.assertNotIn("—", message, code)          # no em dashes
            self.assertNotIn('"', message, code)           # «گیومه», not quotes
            self.assertNotIn("  ", message, code)          # no double spaces
            self.assertNotIn("ي", message, code)           # Arabic ي
            self.assertNotIn("ك", message, code)           # Arabic ك
            self.assertNotIn("‌ ", message, code)   # ZWNJ never before a space
            self.assertNotIn("‌‌", message, code)     # never a double ZWNJ
        self.assertNotIn("—", panel.CLOUD_UNKNOWN_MESSAGE)

    def test_a_server_sentence_is_never_a_code(self):
        for junk in ("Something broke on our server",
                     "user 09121234567 was not found",
                     "eyJhbGciOiJIUzI1NiJ9.payload",
                     "HTTP 500 Internal Server Error",
                     " auth_required ", "AUTH_REQUIRED and more"):
            self.assertIsNone(panel.cloud_error_message(junk), junk)

    def test_an_unknown_valid_code_gets_generic_wording(self):
        self.assertEqual(panel.cloud_error_message("SOMETHING_NEW"),
                         panel.CLOUD_UNKNOWN_MESSAGE)

    def test_an_unusable_code_is_replaced_not_echoed(self):
        body, status = panel.cloud_error_body("user 09121234567 not found", 400)
        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "SERVER_ERROR")
        self.assertNotIn("0912", json.dumps(body, ensure_ascii=False))

    def test_every_error_body_is_a_persian_sentence_from_the_table(self):
        allowed = allowed_messages()
        for code in all_known_codes():
            body, _status = panel.cloud_error_body(code, 400)
            self.assertFalse(body["ok"])
            self.assertEqual(body["code"], code)
            self.assertIn(body["errors"][0], allowed)


def allowed_messages():
    """Every sentence this module is allowed to put in front of an operator."""
    allowed = set(panel.CLOUD_ERROR_MESSAGES.values())
    allowed.add(panel.CLOUD_UNKNOWN_MESSAGE)
    return allowed


# =====================================================================
# 2. Which word the surface shows
# =====================================================================
class LinkStateTests(unittest.TestCase):
    CASES = (
        ((False, None, False), "unconfigured"),
        ((True, None, False), "error"),
        ((True, "idle", True), "read_only"),       # lease outranks the state
        ((True, "read_only", False), "read_only"),
        ((True, "offline", False), "offline"),
        ((True, "auth_required", False), "auth_required"),
        ((True, "not_enrolled", False), "not_enrolled"),
        ((True, "conflict", False), "conflict"),
        ((True, "disabled", False), "disabled"),
        ((True, "idle", False), "connected"),
        ((True, "syncing", False), "connected"),
    )

    def test_priority_order(self):
        for args, expected in self.CASES:
            self.assertEqual(panel.cloud_link_state(*args), expected, args)


# =====================================================================
# 3. The 7-day lease decides read-only, not "never signed in"
# =====================================================================
class LeaseReadOnlyTests(unittest.TestCase):
    def setUp(self):
        reset_cloud_panel()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(reset_cloud_panel)
        self.lease_path = os.path.join(self.tmp.name, "cloud_sync_lease.json")

    def test_never_granted_is_not_the_read_only_state(self):
        lease = OfflineLease(path=self.lease_path)
        # Writes are refused (fail closed), but this is "not connected",
        # never the seven-day banner §11 names.
        self.assertTrue(lease.is_expired())
        view = panel._cloud_lease_view(lease)
        self.assertEqual(view, {"granted": False, "expired": False,
                                "seconds_left": 0})

    def test_seven_days_later_is_read_only(self):
        lease = OfflineLease(path=self.lease_path)
        lease.grant(at=time.time() - LEASE_SECONDS - 60)
        view = panel._cloud_lease_view(lease)
        self.assertTrue(view["granted"])
        self.assertTrue(view["expired"])
        self.assertEqual(view["seconds_left"], 0)

    def test_a_live_lease_counts_down_without_expiring(self):
        lease = OfflineLease(path=self.lease_path)
        lease.grant()
        view = panel._cloud_lease_view(lease)
        self.assertTrue(view["granted"])
        self.assertFalse(view["expired"])
        self.assertGreater(view["seconds_left"], LEASE_SECONDS - 3600)

    def test_expired_lease_wins_over_a_healthy_state(self):
        runtime = _fake_runtime(
            config=_fake_config(api_base="https://api.x.test"),
            machine=_ok_machine(SyncState.IDLE),
            lease=_fake_lease(granted=1.0, expired=True))
        payload = panel.cloud_status_payload(runtime)
        self.assertTrue(payload["read_only"])
        self.assertEqual(payload["link"], "read_only")
        self.assertEqual(payload["state"], "idle")


# =====================================================================
# 4. The status snapshot: shape, secrets, PII
# =====================================================================
def _walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            for found in _walk_keys(item):
                yield found
    elif isinstance(value, list):
        for item in value:
            for found in _walk_keys(item):
                yield found


class _FakeVault:
    def __init__(self, token="live-user-access-token", device_credentials=True):
        self.user_access_token = token
        self._device_credentials = bool(device_credentials)

    @property
    def has_device_credentials(self):
        return self._device_credentials

    def clear_user(self):
        self.user_access_token = None


class _FakeClient:
    def __init__(self, login_payload=None, login_error=None, vault=None,
                 config=None):
        self.vault = vault if vault is not None else _FakeVault()
        self.config = config
        self._payload = login_payload
        self._error = login_error
        self.logins = []
        self.enrolled = 0
        self.logged_out = 0

    def login(self, username, password):
        self.logins.append((username, password))
        if self._error is not None:
            raise self._error
        if self._payload is not None:
            return self._payload
        return {"access_token": "in-memory", "must_change_password": False,
                "user": {"username": "host-op"}}

    def enroll(self):
        self.enrolled += 1
        if self.config is not None:
            self.config.sync_device_id = "dev-1"
        return {"sync_device_id": "dev-1"}

    def logout(self):
        self.logged_out += 1
        self.vault.clear_user()


class _FakeLease:
    def __init__(self, granted=None, expired=False):
        self.granted_at = granted
        self._expired = expired
        self.grants = 0

    def grant(self, at=None):
        self.grants += 1
        self.granted_at = at if at is not None else time.time()
        self._expired = False
        return self.granted_at

    def is_expired(self):
        return bool(self._expired)

    def remaining(self):
        return 0.0 if self._expired else float(LEASE_SECONDS)


class _FakeMachine:
    def __init__(self, state=SyncState.IDLE, apply_error=None):
        self.state = state
        self.events = []
        self.saves = 0
        self.apply_error = apply_error
        self.pending_changes = 0
        self.conflict_count = 0
        self.last_successful_sync = None
        self.last_error_code = None

    def apply(self, event, **kwargs):
        if self.apply_error is not None:
            raise self.apply_error
        self.events.append(getattr(event, "value", str(event)))
        return self.state

    def save(self):
        self.saves += 1


class _FakeOutbox:
    def __init__(self, pending=0, conflicts=0):
        self._pending = pending
        self._conflicts = conflicts

    def pending_count(self):
        return self._pending

    def conflict_count(self):
        return self._conflicts


class _Config:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _fake_config(**overrides):
    base = {"api_base": "", "tenant_id": "", "sync_device_id": "",
            "source_installation_id": "install-1", "cursor": 0,
            "dataset_epoch": None}
    base.update(overrides)
    return _Config(**base)


def _fake_runtime(config=None, machine=None, lease=None, outbox=None,
                  client=None, worker=None):
    return {
        "config": config if config is not None else _fake_config(),
        "machine": machine if machine is not None else _FakeMachine(),
        "lease": lease if lease is not None else _FakeLease(),
        "outbox": outbox,
        "client": client if client is not None else _FakeClient(),
        "worker": worker,
    }


def _ok_machine(state=SyncState.IDLE, apply_error=None):
    return _FakeMachine(state=state, apply_error=apply_error)


def _fake_lease(granted=None, expired=False):
    return _FakeLease(granted=granted, expired=expired)


class StatusPayloadTests(unittest.TestCase):
    def setUp(self):
        reset_cloud_panel()
        self.addCleanup(reset_cloud_panel)

    def test_the_payload_shape_never_changes(self):
        payload = panel.cloud_status_payload(_fake_runtime())
        self.assertEqual(sorted(payload), sorted(panel._cloud_status_shell()))
        self.assertTrue(payload["ok"])

    def test_unconfigured_is_reported_as_such(self):
        payload = panel.cloud_status_payload(
            _fake_runtime(config=_fake_config(api_base="")))
        self.assertFalse(payload["configured"])
        self.assertEqual(payload["link"], "unconfigured")

    def test_configured_and_idle_is_connected(self):
        payload = panel.cloud_status_payload(
            _fake_runtime(config=_fake_config(api_base="https://api.x.test",
                                              tenant_id="tenant-1",
                                              sync_device_id="dev-1")))
        self.assertTrue(payload["configured"])
        self.assertEqual(payload["link"], "connected")
        self.assertTrue(payload["device_enrolled"])
        self.assertEqual(payload["tenant_id"], "tenant-1")

    def test_counts_and_the_last_code_come_from_the_observables(self):
        machine = _ok_machine()
        machine.last_successful_sync = "2026-10-01T10:00:00Z"
        machine.last_error_code = "NET_TIMEOUT"
        payload = panel.cloud_status_payload(
            _fake_runtime(machine=machine,
                          outbox=_FakeOutbox(pending=3, conflicts=2)))
        self.assertEqual(payload["last_sync"], "2026-10-01T10:00:00Z")
        self.assertEqual(payload["pending"], 3)
        self.assertEqual(payload["conflicts"], 2)
        self.assertEqual(payload["error_code"], "NET_TIMEOUT")
        self.assertEqual(payload["error_message"],
                         panel.cloud_error_message("NET_TIMEOUT"))

    def test_device_identity_is_visible_but_not_a_credential(self):
        device_id = "12345678-1234-4234-8234-123456789abc"
        payload = panel.cloud_status_payload(
            _fake_runtime(config=_fake_config(api_base="https://api.x.test",
                                              sync_device_id=device_id)))
        self.assertTrue(payload["device_enrolled"])
        self.assertEqual(payload["device_id"], device_id)
        keys = " ".join(payload.keys()).lower()
        self.assertNotIn("refresh", keys)
        self.assertNotIn("token", keys)

    def test_an_unknown_but_valid_code_is_shown_with_generic_wording(self):
        # §9: the last error code stays observable, and an unfamiliar one
        # still gets safe wording rather than anybody's sentences.
        machine = _ok_machine()
        machine.last_error_code = "TOTALLY_UNKNOWN_CODE"
        payload = panel.cloud_status_payload(_fake_runtime(machine=machine))
        self.assertEqual(payload["error_code"], "TOTALLY_UNKNOWN_CODE")
        self.assertEqual(payload["error_message"], panel.CLOUD_UNKNOWN_MESSAGE)

    def test_a_value_that_is_not_a_code_is_not_rendered(self):
        machine = _ok_machine()
        machine.last_error_code = "user 09121234567 was not found"
        payload = panel.cloud_status_payload(_fake_runtime(machine=machine))
        self.assertIsNone(payload["error_code"])
        self.assertIsNone(payload["error_message"])

    def test_must_change_password_is_carried(self):
        panel._CLOUD_MUST_CHANGE = True
        payload = panel.cloud_status_payload(
            _fake_runtime(client=_FakeClient(vault=_FakeVault("live"))))
        self.assertTrue(payload["must_change_password"])

    def test_the_actor_disappears_with_the_session_it_came_from(self):
        panel._CLOUD_ACTOR = "host-op"
        client = _FakeClient(vault=_FakeVault("live"))
        self.assertEqual(panel.cloud_status_payload(
            _fake_runtime(client=client))["actor"], "host-op")
        client.vault.user_access_token = None      # RAM-only session gone
        self.assertIsNone(panel.cloud_status_payload(
            _fake_runtime(client=client))["actor"])
        panel._CLOUD_ACTOR = None
        self.assertIsNone(panel.cloud_status_payload(
            _fake_runtime(client=_FakeClient()))["actor"])

    def test_no_token_credential_or_pii_reaches_the_payload(self):
        panel._CLOUD_ACTOR = "host-op"
        panel._CLOUD_MUST_CHANGE = True
        panel._CLOUD_LAST_BEAT = {"at": "2026-10-05T00:00:00Z",
                                  "attempted": True, "applied": 1,
                                  "conflicts": 0, "code": None,
                                  "terminal": "sync_ok"}
        machine = _ok_machine()
        machine.last_successful_sync = "2026-10-05T00:00:00Z"
        payload = panel.cloud_status_payload(_fake_runtime(machine=machine))
        text = json.dumps(payload, ensure_ascii=False)
        for key in _walk_keys(payload):
            lowered = key.lower()
            self.assertNotIn("token", lowered, key)
            if "password" in lowered:
                self.assertEqual(key, "must_change_password", key)
        for forbidden in ("national", "mobile", "email", "phone", "imei",
                          "first_name", "last_name", "authorization"):
            self.assertNotIn(forbidden, text.lower())
        self.assertNotIn("Bearer ", text)
        self.assertNotRegex(text, r"eyJ[A-Za-z0-9_-]{6,}")
        self.assertNotRegex(text, r"\d{10,}")     # phone / national id shapes

    def test_a_runtime_that_cannot_be_built_is_still_an_answer(self):
        with patch.object(panel, "_cloud_runtime",
                          side_effect=ConfigError(code="CONFIG_INVALID")):
            payload = panel.cloud_status_payload()
        self.assertEqual(payload["link"], "error")
        self.assertEqual(payload["error_code"], "CONFIG_INVALID")
        self.assertEqual(payload["error_message"],
                         panel.cloud_error_message("CONFIG_INVALID"))
        self.assertNotIn("errors", payload)   # a status never carries one


# =====================================================================
# 5. The shipped page: CSRF bootstrap, node --check, no secrets
# =====================================================================
class ServedPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = panel.render_page().decode("utf-8")

    def test_the_page_carries_the_csrf_bootstrap(self):
        # Workstream S: every page goes through with_csrf_bootstrap(), and
        # the injected tag must be typed — a bare <script> broke an extract.
        self.assertTrue(panel.CSRF_BOOTSTRAP.lstrip().startswith(
            '<script type="text/javascript">'), panel.CSRF_BOOTSTRAP[:60])
        self.assertIn("X-CSRF-Token", self.html)
        self.assertIn("irica_csrf", self.html)
        self.assertIn("</head>", self.html)

    def test_the_cloud_surface_is_on_the_served_page(self):
        for marker in ("cloud-sync-section", "cloud-readonly-banner",
                       "cloud-must-change", "cloud-conflicts-view",
                       "cloud-action-status", "renderCloudConflicts",
                       "همگام‌سازی ابری", "فقط‌خواندنی",
                       "رمز عبور باید تغییر کند"):
            self.assertIn(marker, self.html, marker)

    @unittest.skipUnless(NODE, "node is not installed: cannot check scripts")
    def test_every_script_slice_parses(self):
        slices = re.findall(r"<script([^>]*)>([\s\S]*?)</script>", self.html)
        self.assertGreaterEqual(len(slices), 2)
        for index, (_attrs, body) in enumerate(slices):
            code, err = node_syntax(body)
            self.assertEqual(code, 0, "script slice %d:\n%s" % (index, err))

    def test_no_credential_shape_reaches_the_page(self):
        self.assertNotRegex(self.html, r"eyJ[A-Za-z0-9_-]{10,}")
        self.assertNotRegex(self.html, r"(?i)bearer\s+\S+")
        self.assertNotIn("access_token", self.html)
        self.assertNotIn("refresh_token", self.html)


# =====================================================================
# 6. The shipped paintCloud, executed in node for every state
# =====================================================================
PAINT_PRELUDE = r"""
function ok(cond,msg){ if(!cond) throw new Error('FAIL: '+msg); }
var ICON={alert:'<svg id=alert></svg>',dot:'<svg id=dot></svg>',
  checkCircle:'<svg id=check></svg>',xCircle:'<svg id=x></svg>',
  lock:'<svg id=lock></svg>',info:'<svg id=info></svg>',
  minusCircle:'<svg id=minus></svg>',user:'<svg id=user></svg>',
  save:'<svg id=save></svg>'};
var FA_DIGITS='۰۱۲۳۴۵۶۷۸۹';
function faDateTime(iso){ return 'AT:'+iso; }
var __REG={};
function mkEl(id){
  var set={};
  return {id:id, className:'', textContent:'', innerHTML:'', disabled:false,
    classList:{
      add:function(c){ set[c]=true; },
      remove:function(c){ delete set[c]; },
      contains:function(c){ return !!set[c]; },
      toggle:function(c,v){ if(v===undefined) v=!set[c]; if(v) set[c]=true;
                            else delete set[c]; return !!v; }
    }};
}
var document={
  getElementById:function(id){
    return Object.prototype.hasOwnProperty.call(__REG,id) ? __REG[id] : null;
  }
};
function freshDom(ids){
  __REG={};
  ids.forEach(function(id){ __REG[id]=mkEl(id); });
}
function el(id){ return __REG[id]; }
var report={shell:null, states:[]};
"""

PAINT_CHECKS = r"""
var IDS=['cloud-sync-section','cloud-pill','cloud-pill-icon','cloud-pill-text',
 'cloud-readonly-banner','cloud-must-change','cloud-actor','cloud-actor-name',
 'cloud-device','cloud-last-sync','cloud-pending','cloud-conflicts','cloud-error-code',
 'cloud-error-line','cloud-error-text','cloud-beat-line','cloud-reconnect','cloud-reconnect-text','cloud-action-status',
 'cloud-login-block','cloud-logout-btn','cloud-sync-btn','cloud-login-btn',
 'cloud-save-btn','cloud-conflicts-view'];

/* --- the shell every state is painted into ------------------------- */
freshDom(IDS);
var shell=cloudShellHtml();
['cloud-sync-section','cloud-readonly-banner','cloud-must-change','cloud-pill',
 'cloud-actor','cloud-device','cloud-last-sync','cloud-pending','cloud-conflicts',
 'cloud-error-code','cloud-error-line','cloud-beat-line','cloud-reconnect','cloud-reconnect-text','cloud-action-status',
 'cloud-sync-btn','cloud-logout-btn','cloud-login-block','cloud-user','cloud-pass',
 'cloud-api','cloud-tenant','cloud-save-btn','cloud-conflicts-view'
].forEach(function(id){
  ok(shell.indexOf('id="'+id+'"')>=0, 'shell is missing #'+id);
});
ok(shell.indexOf('undefined')<0, 'shell contains undefined');
ok(shell.indexOf('role="alert"')>=0, 'the read-only banner is not an alert');
ok(shell.indexOf('role="status"')>=0, 'the action line is not a status');
ok(shell.indexOf('aria-live="polite"')>=0, 'the action line is not announced');
ok(shell.indexOf('onclick=')>=0, 'the actions are not wired');
report.shell={length:shell.length, alerts:(shell.match(/role="alert"/g)||[]).length};

/* --- every connection state renders -------------------------------- */
var CASES=[
 {name:'unconfigured', link:'unconfigured', state:'not_enrolled', label:'پیکربندی‌نشده', cls:'mute', ro:false, configured:false},
 {name:'connected',    link:'connected',    state:'idle',          label:'متصل',           cls:'ok',   ro:false, configured:true},
 {name:'offline',      link:'offline',      state:'offline',       label:'آفلاین',          cls:'bad',  ro:false, configured:true},
 {name:'read-only',    link:'read_only',    state:'read_only',     label:'فقط‌خواندنی',     cls:'warn', ro:true,  configured:true},
 {name:'syncing',      link:'connected',    state:'syncing',       label:'در حال همگام‌سازی', cls:'ok',  ro:false, configured:true},
 {name:'auth-required',link:'auth_required', state:'auth_required', label:'نیازمند ورود',    cls:'warn', ro:false, configured:true},
 {name:'not-enrolled', link:'not_enrolled', state:'not_enrolled',  label:'ثبت‌نشده',        cls:'warn', ro:false, configured:true},
 {name:'conflict',     link:'conflict',     state:'conflict',      label:'نیازمند بررسی تداخل', cls:'warn', ro:false, configured:true, conflicts:2},
 {name:'disabled',     link:'disabled',     state:'disabled',      label:'غیرفعال',         cls:'mute', ro:false, configured:true},
 {name:'error',        link:'error',        state:'',              label:'خطا',             cls:'bad',  ro:false, configured:false}
];
CASES.forEach(function(c){
  freshDom(IDS);
  CLOUD.last={ok:true, link:c.link, state:c.state, configured:c.configured,
              read_only:c.ro, pending:3, conflicts:c.conflicts||0,
              device_id:'12345678-1234-4234-8234-123456789abc',
              last_sync:'2026-10-05T10:00:00Z', error_code:null,
              error_message:null, actor:null, must_change_password:false,
              worker:'running', worker_last:null};
  paintCloud();
  ok(el('cloud-pill').className==='cloud-pill '+c.cls,
     c.name+': pill class is '+el('cloud-pill').className);
  ok(el('cloud-pill-text').textContent===c.label,
     c.name+': pill text is '+el('cloud-pill-text').textContent);
  ok(el('cloud-device').textContent.indexOf('12345678')===0,
     c.name+': device identity is not visible');
  ok(el('cloud-pill-icon').innerHTML.length>0,
     c.name+': the pill has no icon, so colour alone would carry the state');
  ok(el('cloud-readonly-banner').classList.contains('on')===!!c.ro,
     c.name+': wrong read-only banner');
  ok(el('cloud-pending').textContent==='۳', c.name+': pending is not Persian');
  ok(el('cloud-conflicts').textContent===toFa(c.conflicts||0),
     c.name+': conflicts are not Persian');
  ok(el('cloud-last-sync').textContent==='AT:2026-10-05T10:00:00Z',
     c.name+': last sync missing');
  ok(el('cloud-error-code').textContent==='—', c.name+': stray error code');
  ok(el('cloud-error-text').textContent==='', c.name+': stray error text');
  ok(el('cloud-sync-btn').disabled===!c.configured,
     c.name+': sync button ignores the configuration');
  ok(el('cloud-login-block').classList.contains('hidden')===false,
     c.name+': the login form must be reachable while signed out');
  ok(el('cloud-logout-btn').classList.contains('hidden')===true,
     c.name+': sign-out shown while signed out');
  report.states.push(c.name);
});

/* --- the read-only banner is unmistakable -------------------------- */
freshDom(IDS);
CLOUD.last={link:'read_only',state:'read_only',configured:true,read_only:true,
            pending:0,conflicts:0,last_sync:null,actor:null,
            must_change_password:false,worker:'stopped',worker_last:null};
paintCloud();
ok(el('cloud-readonly-banner').classList.contains('on'), 'banner not shown');
ok(el('cloud-beat-line').textContent.indexOf('متوقف')>=0, 'no worker line');
ok(el('cloud-reconnect').classList.contains('on'), 'read-only reconnect guidance hidden');

/* --- must_change_password is a visible instruction ------------------ */
freshDom(IDS);
CLOUD.last={link:'connected',state:'idle',configured:true,read_only:false,
            pending:0,conflicts:0,last_sync:null,actor:'host-op',
            must_change_password:true,worker:'running',worker_last:null};
paintCloud();
ok(el('cloud-must-change').classList.contains('on'), 'password instruction hidden');
ok(el('cloud-actor').classList.contains('on'), 'the acting user is not shown');
ok(el('cloud-actor-name').textContent==='host-op', 'wrong acting user');
ok(el('cloud-login-block').classList.contains('hidden')===true, 'login still shown');
ok(el('cloud-logout-btn').classList.contains('hidden')===false, 'sign-out hidden');
paintCloud();   // a second paint must not duplicate or drift anything
ok(el('cloud-actor-name').textContent==='host-op', 'repaint lost the actor');

/* --- the error line shows a mapped sentence and the code ------------ */
freshDom(IDS);
CLOUD.last={link:'offline',state:'offline',configured:true,read_only:false,
            pending:1,conflicts:0,last_sync:null,actor:null,error_code:'NET_TIMEOUT',
            error_message:__MESSAGE__, must_change_password:false,
            worker:'running',worker_last:null};
paintCloud();
ok(el('cloud-error-line').classList.contains('on'), 'the error line is hidden');
ok(el('cloud-error-text').textContent===__MESSAGE__, 'the error text drifted');
ok(el('cloud-error-code').textContent==='NET_TIMEOUT', 'the code is not shown');

/* --- the conflict seam is mounted by name --------------------------- */
freshDom(IDS);
CLOUD.last={link:'conflict',state:'conflict',configured:true,read_only:false,
            pending:0,conflicts:4,last_sync:null,actor:null,
            must_change_password:false,worker:'running',worker_last:null};
paintCloud();
ok(el('cloud-conflicts-view').classList.contains('on'), 'seam container hidden');
ok(el('cloud-conflicts-view').innerHTML.indexOf(toFa(4))>=0, 'seam has no count');

console.log(JSON.stringify(report));
"""


def paint_script():
    """The shipped cloud functions plus a DOM shim and the assertions."""
    js = panel.PAGE_JS
    message = json.dumps(panel.cloud_error_message("NET_TIMEOUT"),
                         ensure_ascii=False)
    return "".join([
        PAINT_PRELUDE,
        block_after(js, "var CLOUD=", ";\n") + "\n",
        block_after(js, "var CLOUD_LINK=", "\n};") + "\n",
        fn_body(js, "toFa") + "\n",
        fn_body(js, "cloudShellHtml") + "\n",
        fn_body(js, "cloudBeatLine") + "\n",
        fn_body(js, "renderCloudConflicts") + "\n",
        fn_body(js, "paintCloud") + "\n",
        PAINT_CHECKS.replace("__MESSAGE__", message),
    ])


CLOUD_FUNCTIONS = ("cloudShellHtml", "paintCloud", "cloudBeatLine",
                   "renderCloudConflicts", "cloudView", "cloudPost",
                   "cloudLogin", "cloudLogout", "cloudSaveConfig",
                   "cloudSyncNow", "loadCloudStatus", "cloudResult",
                   "cloudSetBusy", "cloudBurst")


def cloud_js():
    """The cloud slice of PAGE_JS, from its state object to showView."""
    js = panel.PAGE_JS
    start = js.find("var CLOUD={last:null")
    end = js.find("\nfunction showView(", start)
    return js[start:end] if start >= 0 and end > start else ""


class ClientStringTests(unittest.TestCase):
    """The page keeps no wording of its own beyond the server's table.

    Everything the cloud surface can say is either a state word, a label or
    a sentence that already exists in panel.CLOUD_ERROR_MESSAGES — so a
    server string, a token or an English fragment has nowhere to land.
    """

    def setUp(self):
        self.js = cloud_js()
        self.assertTrue(self.js, "the cloud JS slice is missing")

    def test_the_unknown_message_is_the_servers_wording(self):
        match = re.search(r"var CLOUD_UNKNOWN_MESSAGE='([^']*)';", self.js)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), panel.CLOUD_UNKNOWN_MESSAGE)

    def test_every_state_label_is_persian_only(self):
        labels = re.findall(r"label:'([^']*)'", self.js)
        self.assertGreaterEqual(len(labels), 9)
        for label in labels:
            self.assertIsNone(re.search(r"[A-Za-z0-9]", label), label)
            self.assertNotIn("—", label, label)

    def test_the_action_phrases_carry_no_ascii(self):
        for phrase in ("در حال انجام…", "انجام شد.",
                       "ارتباط با پنل برقرار نشد؛ دوباره تلاش کنید.",
                       "کارگر همگام‌سازی در حال اجراست.",
                       "کارگر همگام‌سازی متوقف است.",
                       "ارسال گروهی انجام شد.",
                       "چیزی برای ارسال نبود.",
                       "در حال بررسی…"):
            self.assertIn(phrase, self.js, phrase)
            self.assertIsNone(re.search(r"[A-Za-z0-9]", phrase), phrase)
            self.assertNotIn("—", phrase, phrase)

    def test_the_shell_carries_no_ascii_sentence(self):
        shell = fn_body(panel.PAGE_JS, "cloudShellHtml")
        for phrase in ("همگام‌سازی ابری", "فقط‌خواندنی",
                       "رمز عبور باید تغییر کند", "تغییرات در انتظار",
                       "کد آخرین خطا", "آخرین همگام‌سازی موفق",
                       "تداخل‌ها", "کاربر فعال", "ورود به میزبان",
                       "خروج از میزبان", "ذخیره تنظیمات اتصال",
                       "آدرس سرویس ابری", "شناسه‌ی سازمان",
                       "همگام‌سازی اکنون"):
            self.assertIn(phrase, shell, phrase)


class PaintCloudTests(unittest.TestCase):
    """The real paintCloud, run in node — a Python twin would go stale."""

    def setUp(self):
        reset_cloud_panel()
        self.addCleanup(reset_cloud_panel)

    @unittest.skipUnless(NODE, "node is not installed: cannot execute page JS")
    def test_every_state_renders_through_the_shipped_function(self):
        code, out, err = run_node(paint_script())
        self.assertEqual(code, 0, err)
        report = json.loads(out.strip().splitlines()[-1])
        self.assertGreaterEqual(report["shell"]["alerts"], 2)
        for name in ("unconfigured", "connected", "offline", "read-only"):
            self.assertIn(name, report["states"])
        self.assertEqual(len(report["states"]), 10)

    @unittest.skipUnless(NODE, "node is not installed: cannot check scripts")
    def test_every_shipped_cloud_function_parses(self):
        for name in CLOUD_FUNCTIONS:
            body = fn_body(panel.PAGE_JS, name)
            self.assertTrue(body, name + " not found in PAGE_JS")
            code, err = node_syntax(body)
            self.assertEqual(code, 0, "%s:\n%s" % (name, err))


# =====================================================================
# 7. The routes: CSRF in, a coded Persian answer out
# =====================================================================
from test_v1_2_0_login_gate import _GateHarness  # noqa: E402


def _raising_grant(at=None):
    raise OSError("the lease file cannot be written")


class CloudRouteTests(_GateHarness):
    def setUp(self):
        super().setUp()
        reset_cloud_panel()
        self.addCleanup(reset_cloud_panel)

    def _own_origin(self):
        return "http://127.0.0.1:%d" % self.port

    def _session_csrf(self, cookie):
        token = cookie.split("irica_session=", 1)[1].split(";", 1)[0]
        return panel_auth.session_csrf(token) or ""

    # -- the gate ------------------------------------------------------
    def test_status_is_gated(self):
        status, _h, _b = self._op("/cloud-status")
        self.assertEqual(status, 401)

    def test_status_answers_for_a_session(self):
        cookie = self.login()
        status, _h, body = self._op("/cloud-status", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertIn(payload["link"],
                      ("unconfigured", "connected", "offline", "read_only",
                       "auth_required", "not_enrolled", "conflict",
                       "disabled", "error"))

    def test_a_cloud_post_without_the_csrf_header_is_rejected(self):
        cookie = self.login()
        status, _h, body = self._op("/cloud-login", data={
            "username": "u", "password": "p"},
            headers={"Cookie": cookie, "Origin": self._own_origin()})
        self.assertEqual(status, 403)
        self.assertFalse(json.loads(body)["ok"])

    def test_a_cloud_post_with_the_csrf_header_reaches_the_route(self):
        cookie = self.login()
        with patch.object(panel, "_cloud_configured", return_value=False):
            status, _h, body = self.authed("/cloud-sync", cookie, data={})
        # Not 403: the token was accepted and the route itself answered.
        self.assertEqual(status, 409)
        payload = json.loads(body)
        self.assertEqual(payload["code"], "CONFIG_INVALID")
        self.assertIn(payload["errors"][0], allowed_messages())

    def test_cross_origin_cannot_sign_in_to_the_host(self):
        cookie = self.login()
        status, _h, _b = self._op("/cloud-login", data={
            "username": "u", "password": "p"}, headers={
                "Cookie": cookie, "Origin": "http://evil.example",
                "X-CSRF-Token": self._session_csrf(cookie)})
        self.assertEqual(status, 403)

    # -- coded answers, never the server's words -----------------------
    def _post_login(self, runtime, data):
        with patch.object(panel, "_cloud_runtime", return_value=runtime):
            status, _h, body = self.authed("/cloud-login", self.login(),
                                           data=data)
        return status, json.loads(body)

    def test_a_rejected_host_login_is_a_mapped_persian_sentence(self):
        client = _FakeClient(login_error=AuthRequiredError(
            code="AUTH_REQUIRED"))
        password = "S3cr3t-Host-Passw0rd!"
        status, payload = self._post_login(
            _fake_runtime(client=client),
            {"username": "u", "password": password})
        self.assertEqual(status, 401)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "AUTH_REQUIRED")
        self.assertEqual(payload["errors"][0],
                         panel.cloud_error_message("AUTH_REQUIRED"))
        self.assertIn(payload["errors"][0], allowed_messages())
        # The password left the body and reached the client only.
        self.assertEqual(client.logins, [("u", password)])
        self.assertNotIn(password, json.dumps(payload, ensure_ascii=False))
        self.assertNotIn("server", json.dumps(payload, ensure_ascii=False))

    def test_a_missing_field_is_bad_payload_not_a_raw_sentence(self):
        status, payload = self._post_login(_fake_runtime(), {"username": ""})
        self.assertEqual(status, 400)
        self.assertEqual(payload["code"], "BAD_PAYLOAD")
        self.assertIn(payload["errors"][0], allowed_messages())

    def test_a_local_io_failure_is_coded(self):
        lease = _FakeLease()
        lease.grant = _raising_grant
        status, payload = self._post_login(
            _fake_runtime(lease=lease,
                          config=_fake_config(sync_device_id="dev-1"),
                          machine=_ok_machine()),
            {"username": "u", "password": "p"})
        self.assertEqual(status, 500)
        self.assertEqual(payload["code"], "CONFIG_INVALID")
        self.assertIn(payload["errors"][0], allowed_messages())

    # -- §15.12: the two machine faults, caught by name ---------------
    def test_illegal_transition_is_surfaced_not_swallowed(self):
        machine = _ok_machine(apply_error=IllegalTransitionError(
            SyncState.IDLE, SyncEvent.AUTH_OK))
        status, payload = self._post_login(
            _fake_runtime(machine=machine,
                          config=_fake_config(sync_device_id="dev-1")),
            {"username": "u", "password": "p"})
        self.assertEqual(status, 409)
        self.assertEqual(payload["code"], "TRANSITION_NOT_LEGAL")
        self.assertEqual(payload["errors"][0],
                         panel.cloud_error_message("TRANSITION_NOT_LEGAL"))
        self.assertNotEqual(payload["errors"][0], "خطای سرور؛ دوباره تلاش کنید")
        self.assertEqual(machine.saves, 0)   # a refused event is not saved

    def test_a_successful_login_fires_exactly_one_event(self):
        machine = _ok_machine(SyncState.IDLE)
        lease = _FakeLease()
        client = _FakeClient(login_payload={
            "access_token": "eyJ.secret.value", "must_change_password": True,
            "user": {"username": "host-op"}})
        status, payload = self._post_login(
            _fake_runtime(machine=machine, lease=lease, client=client,
                          config=_fake_config(sync_device_id="dev-1")),
            {"username": "u", "password": "p"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["actor"], "host-op")
        self.assertTrue(payload["must_change_password"])
        self.assertEqual(machine.events, ["auth_ok"])
        self.assertEqual(machine.saves, 1)
        self.assertEqual(lease.grants, 1)        # §5: auth renews the lease
        self.assertEqual(client.enrolled, 0)     # already enrolled
        self.assertNotIn("eyJ", json.dumps(payload))

    def test_a_first_login_enrols_and_fires_enrol_only(self):
        machine = _ok_machine(SyncState.NOT_ENROLLED)
        config = _fake_config(api_base="https://api.x.test")
        client = _FakeClient(config=config)
        status, payload = self._post_login(
            _fake_runtime(machine=machine, config=config, client=client),
            {"username": "u", "password": "p"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["enrolled"])
        self.assertEqual(client.enrolled, 1)
        self.assertEqual(machine.events, ["enrol"])

    def test_login_reenrols_when_device_id_is_stale_but_credential_is_gone(self):
        machine = _ok_machine(SyncState.AUTH_REQUIRED)
        config = _fake_config(api_base="https://api.x.test",
                              sync_device_id="revoked-old-device")
        client = _FakeClient(config=config,
                             vault=_FakeVault("live", device_credentials=False))
        status, payload = self._post_login(
            _fake_runtime(machine=machine, config=config, client=client),
            {"username": "u", "password": "p"})
        self.assertEqual(status, 200)
        self.assertEqual(client.enrolled, 1)
        self.assertEqual(config.sync_device_id, "dev-1")
        self.assertEqual(machine.events, ["auth_ok"])
        self.assertTrue(payload["enrolled"])

    def test_signing_out_touches_only_the_session(self):
        machine = _ok_machine()
        client = _FakeClient(vault=_FakeVault("live"))
        panel._CLOUD_ACTOR = "host-op"
        with patch.object(panel, "_cloud_runtime",
                          return_value=_fake_runtime(machine=machine,
                                                     client=client)):
            status, _h, body = self.authed("/cloud-logout", self.login(),
                                           data={})
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertIsNone(payload["actor"])
        self.assertEqual(machine.events, [])     # no state-machine event
        self.assertEqual(machine.saves, 0)
        self.assertIsNone(client.vault.user_access_token)
        self.assertIsNone(panel._CLOUD_ACTOR)


# =====================================================================
# 8. The worker: no configuration -> no thread; expired lease -> no sync
# =====================================================================
class WorkerTests(unittest.TestCase):
    def setUp(self):
        reset_cloud_panel()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(reset_cloud_panel)
        patcher = patch.object(app_paths, "data_dir",
                               return_value=self.tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _configure(self):
        from cloud_sync.config import load_config
        config = load_config()
        config.api_base = "https://sync.example.test"
        config.save()

    def test_no_configuration_means_no_worker_thread(self):
        self.assertFalse(panel._cloud_configured())
        self.assertIsNone(panel.cloud_worker_start())
        self.assertIsNone(panel._CLOUD_WORKER_THREAD)
        # The beat does not reach the network either.
        note = panel.cloud_worker_beat()
        self.assertEqual(note.get("skipped"), "not_configured")

    def test_configuration_starts_and_stops_the_thread(self):
        self._configure()
        self.assertTrue(panel._cloud_configured())
        with patch.object(panel, "cloud_worker_beat",
                          side_effect=lambda: panel._cloud_note_beat(
                              skipped="test")):
            thread = panel.cloud_worker_start()
            self.assertIsNotNone(thread)
            self.assertTrue(thread.is_alive())
            self.assertIs(thread, panel.cloud_worker_start())  # no second one
            stopped = panel.cloud_worker_stop()
            self.assertIs(stopped, thread)
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

    def test_a_kick_asks_for_one_beat_without_blocking(self):
        self._configure()
        beats = []
        with patch.object(panel, "cloud_worker_beat",
                          side_effect=lambda: beats.append(1)):
            thread = panel.cloud_worker_start()
            self.assertIsNotNone(thread)
            panel.cloud_worker_kick()
            deadline = time.time() + 5
            while not beats and time.time() < deadline:
                time.sleep(0.05)
            panel.cloud_worker_stop()
            thread.join(timeout=5)
        self.assertTrue(beats, "a kick produced no beat")

    def test_a_never_granted_lease_neither_syncs_nor_goes_read_only(self):
        self._configure()
        runtime = panel._cloud_runtime(refresh=True)
        machine = runtime["machine"]
        calls = []
        runtime["worker"].run_once = lambda **kw: calls.append(kw)
        note = panel.cloud_worker_beat()
        self.assertEqual(note.get("skipped"), "awaiting_login")
        self.assertEqual(calls, [])
        self.assertIsNot(machine.state, SyncState.READ_ONLY)

    def test_an_expired_lease_stops_the_worker_and_fires_once(self):
        self._configure()
        runtime = panel._cloud_runtime(refresh=True)
        machine = runtime["machine"]
        machine.apply(SyncEvent.ENROL)               # NOT_ENROLLED -> IDLE
        runtime["lease"].grant(at=time.time() - LEASE_SECONDS - 60)
        calls = []
        runtime["worker"].run_once = lambda **kw: calls.append(kw)
        note = panel.cloud_worker_beat()
        self.assertEqual(note.get("code"), "LEASE_EXPIRED")
        self.assertEqual(calls, [])                   # never reached the socket
        self.assertIs(machine.state, SyncState.READ_ONLY)
        # A second beat must not fire the event again.
        note = panel.cloud_worker_beat()
        self.assertEqual(note.get("code"), "LEASE_EXPIRED")
        self.assertEqual(panel._cloud_beat_view()["message"],
                         panel.cloud_error_message("LEASE_EXPIRED"))

    def test_unconfigured_beat_records_no_network_attempt(self):
        runtime = panel._cloud_runtime(refresh=True)
        runtime["worker"].run_once = lambda **kw: (_ for _ in ()).throw(
            AssertionError("run_once must not run without configuration"))
        note = panel.cloud_worker_beat()
        self.assertEqual(note.get("skipped"), "not_configured")


# =====================================================================
# 9. §15.12 in the source: the faults are caught BY NAME
# =====================================================================
class NamedFaultCatchTests(unittest.TestCase):
    """A generic `except Exception` at a route would hide a machine event.

    panel.py already has dozens of them, so the requirement is checked on
    the source itself: the named handlers must exist, in the right
    functions, and before any generic one.
    """

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "panel.py"), encoding="utf-8") as handle:
            cls.source = handle.read()
        cls.lines = cls.source.splitlines(keepends=True)

    def _function(self, name):
        """The source of one top-level def, cut with the parser — never with
        a brace count, which f-strings like `f"http://{HOST}"` would fool."""
        import ast
        for node in ast.parse(self.source).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and node.name == name:
                return "".join(self.lines[node.lineno - 1:node.end_lineno])
        self.fail(name + " not found")

    def test_the_route_guard_catches_both_faults_by_name(self):
        body = self._function("_cloud_route_guard")
        self.assertIn("except IllegalTransitionError", body)
        self.assertIn("except LeaseExpiredError", body)
        self.assertIn('cloud_error_body("TRANSITION_NOT_LEGAL"', body)
        self.assertIn('cloud_error_body("LEASE_EXPIRED"', body)

    def test_the_worker_beat_catches_both_faults_by_name(self):
        body = self._function("cloud_worker_beat")
        self.assertIn("except IllegalTransitionError", body)
        self.assertIn("except LeaseExpiredError", body)

    def test_the_worker_loop_catches_both_faults_by_name(self):
        body = self._function("_cloud_worker_loop")
        self.assertIn("except IllegalTransitionError", body)
        self.assertIn("except LeaseExpiredError", body)
        # Specific handlers must come before the generic backstop, or the
        # generic one wins and the event disappears.
        self.assertLess(body.find("except IllegalTransitionError"),
                        body.find("except Exception"))
        self.assertLess(body.find("except LeaseExpiredError"),
                        body.find("except Exception"))

    def test_lease_expiry_stops_without_a_second_event(self):
        body = self._function("_cloud_stop_for_lease")
        self.assertIn("SyncState.READ_ONLY", body)
        self.assertIn("except IllegalTransitionError", body)

    def test_every_cloud_route_goes_through_the_guard(self):
        for route in ("/cloud-config", "/cloud-login", "/cloud-logout",
                      "/cloud-sync"):
            self.assertIn('self.path == "%s"' % route, self.source)
        self.assertEqual(self.source.count("*_cloud_route_guard("), 4)
        self.assertIn('elif route == "/cloud-status"', self.source)

    def test_the_worker_is_started_from_main(self):
        body = self._function("main")
        self.assertIn("cloud_worker_start()", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
