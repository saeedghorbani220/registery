"""
panel.py — panel-e tahte-web baraye modiriyat-e PROFILE-ha-ye robot-e irica.

Faghat ba ketabkhane-ye standard-e Python kar mikonad (http.server).

Mafhoom-ha:
  - PROFILE: yek majmue-ye vorudi (title/national/birth/mobile/imeis + switch-ha).
    hame dar `profiles.json` zakhire mishavand.
  - profile-e ACTIVE be `inputs.json` sync mishavad ta gomrok.py (bedun-e taghyir)
    az an bekhanad.
  - LOG-ha: gomrok.py rvidaad-ha-ye mohem (khata/natije) ra dar `logs.jsonl`
    minevisad; in panel anha ra (ba serial/IMEI) namayesh midahad.

Ejra:
    python panel.py
sepas boro be:  http://127.0.0.1:8750
"""
import functools
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# The embedded Windows runtime may inherit a cp1252 stream even though the panel
# emits Persian diagnostics. One unguarded print would then abort startup (or the
# clean-shutdown path) before the HTTP server can keep serving the UI.
def _configure_output_stream(stream):
    if stream is None or not hasattr(stream, "reconfigure"):
        return
    # backslashreplace cannot itself raise on an undecodable byte, so a single
    # attempt covers a read-only or already-closed host stream as well.
    try:
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, OSError, ValueError):
        pass


_configure_output_stream(sys.stdout)
_configure_output_stream(sys.stderr)

HERE = os.path.dirname(os.path.abspath(__file__))
# The packaged release runs on an embedded CPython that is ISOLATED (see
# python*._pth): PYTHONPATH is ignored and the script's directory is NOT added to
# sys.path. Top-level imports here are stdlib only, so the panel starts either
# way, but `app_paths` below and the lazy project imports further down
# (`import exitban` in the /exitban-inquiry route) would raise
# ModuleNotFoundError without this.
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import app_paths  # noqa: E402  (needs HERE on sys.path first)

# Config, state and logs live outside the release folder so an update does not
# require copying them by hand. Anything left inside an older release folder is
# copied in once, here, before any path constant is resolved.
_MIGRATED_FILES = app_paths.bootstrap()
DATA_DIR = app_paths.data_dir()

import panel_auth  # noqa: E402  (needs HERE on sys.path first)

# The three operator accounts are NOT seeded here. robots import this module
# too (gomrok.py, exitban.py, ...), and their stdout is a log file — seeding
# here would print a freshly generated password into gomrok_worker.log. The
# seed happens in main(), the one place that both owns the accounts and has a
# console to print the one-time password on.


def _resolve_robot_python():
    """Interpreter that runs the robots.

    Robots MUST run under the interpreter that owns the dependencies shipped
    next to them. The packaged release ships its own embedded CPython (no torch,
    ONNX solver) and no torch-only solver modules; a foreign interpreter that
    happens to have torch installed makes the solver packages pick their torch
    backend and die with ModuleNotFoundError before the browser even opens --
    the v1.0.3 field failure. `sys.executable` is the panel's own interpreter,
    which is by construction the right one.

    `IRICA_ROBOT_PYTHON` overrides it for development, and only when it points
    at a real file, so a stale value can never break the robots.
    """
    override = str(os.environ.get("IRICA_ROBOT_PYTHON") or "").strip()
    if override and os.path.isfile(override):
        return override
    return sys.executable


ROBOT_PYTHON = _resolve_robot_python()

ROBOT_LOG_PATH = app_paths.data_path("gomrok_worker.log")
INPUTS_PATH = app_paths.data_path("inputs.json")
PROFILES_PATH = app_paths.data_path("profiles.json")
LOGS_PATH = app_paths.data_path("logs.jsonl")
SITE2_NOTIF_PATH = app_paths.data_path("site2_notif.json")
TELEGRAM_PATH = app_paths.data_path("telegram_config.json")
TELEGRAM_HEALTH_PATH = app_paths.data_path("telegram_health.json")
EXITBAN_ERRORS_PATH = app_paths.data_path("exitban_errors.jsonl")
SYSTEM_LOG_DIR = app_paths.data_subdir("logs", "system")
SYSTEM_DEBUG_CONFIG_PATH = app_paths.data_path("system_debug.json")
HOST, PORT = "127.0.0.1", 8750

# ---------------------------------------------------- request authenticity
# The panel is loopback-only, so the realistic attacker is a hostile page in
# the operator's own browser: it may POST to 127.0.0.1:8750 and, for a simple
# request, needs no CORS preflight. Three independent checks close that off:
#   * Host must name a loopback literal  -> stops DNS rebinding / host-header
#     spoofing (an attacker's rebound domain is never one of those names).
#   * Origin, or Referer when Origin is absent, must be this panel's own
#     origin -> stops a cross-site POST outright.
#   * the POST must carry the session's CSRF token in a header -> a cross-site
#     page cannot read it (it lives in an HttpOnly-scoped session and a
#     SameSite=Strict cookie pair) and cannot set it without a preflight.
# Everything answers with the normal {"ok": false, "errors": [...]} envelope.
CSRF_HEADER = "X-CSRF-Token"
CSRF_COOKIE = "irica_csrf"

_SOURCE_HOST_REJECT = "آدرس میزبان درخواست نامعتبر است"
_SOURCE_ORIGIN_REJECT = ("درخواست از منبع نامعتبر؛ پنل فقط درخواست‌های خودش "
                         "را می‌پذیرد")
_CSRF_REJECT = ("نشانی امنیتی درخواست نامعتبر است؛ صفحه را دوباره "
                "بارگذاری کنید")


def _host_label(host_header):
    """The Host header with its port removed: '127.0.0.1:8750' -> '127.0.0.1'.

    The port is deliberately ignored: the defence is about WHICH NAME addressed
    the panel (a rebound domain), and the tests — like any second instance —
    legitimately listen on a port other than PORT.
    """
    raw = str(host_header or "").strip()
    if raw.startswith("["):                      # [::1]:8750
        end = raw.find("]")
        return raw[1:end] if end > 1 else raw
    return raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw


def _is_loopback_label(label):
    """True only for a name that can denote nothing but THIS machine.

    `HOST` itself plus the literal loopback names. An attacker's DNS record
    can point at 127.0.0.1 but can never BE one of these, which is what makes
    the Host rule a real rebinding defence rather than a cosmetic check.
    """
    name = str(label or "").strip().lower().rstrip(".")
    if not name:
        return False
    if name == HOST.strip().lower():
        return True
    if name in ("localhost", "localhost.localdomain",
                "::1", "0:0:0:0:0:0:0:1"):
        return True
    if re.fullmatch(r"127(?:\.\d{1,3}){3}", name):
        return all(0 <= int(part) <= 255 for part in name.split("."))
    return False


# The browser's one-line CSRF client. Injected into every served page just
# before </head> at render time, so the page templates themselves — and the
# tests that slice them out and run them in node — stay untouched. The typed
# `<script type=...>` form is deliberate: the page-JS extractors in the suite
# split on the bare `<script>` marker and must keep seeing exactly the page's
# own blocks. It reads the readable irica_csrf cookie that login sets and adds
# the token to every POST as a header; without the cookie (before a session) it
# installs nothing.
CSRF_BOOTSTRAP = r"""<script type="text/javascript">(function(){
if(typeof document==='undefined'||typeof fetch!=='function')return;
var m=/(?:^|;\s*)irica_csrf=([^;]+)/.exec(document.cookie||'');
if(!m)return;
var t;try{t=decodeURIComponent(m[1]);}catch(e){return;}
if(!t)return;
var native=window.fetch;
window.fetch=function(input,init){
  init=init||{};
  var method=String(init.method||(input&&input.method)||'GET').toUpperCase();
  if(method!=='POST')return native.call(window,input,init);
  var cfg={};for(var k in init)cfg[k]=init[k];
  var h=cfg.headers;
  if(h&&typeof h.set==='function'){h.set('X-CSRF-Token',t);}
  else if(Array.isArray(h)){cfg.headers=h.concat([['X-CSRF-Token',t]]);}
  else{var o={};for(var j in (h||{}))o[j]=h[j];o['X-CSRF-Token']=t;cfg.headers=o;}
  return native.call(window,input,cfg);
};
})();
</script>"""


def with_csrf_bootstrap(html):
    """Insert CSRF_BOOTSTRAP before the page's </head>, once."""
    at = html.find("</head>")
    if at < 0:
        return html
    return html[:at] + CSRF_BOOTSTRAP + html[at:]

# The panel reads every POST body before any route runs, so that read needs
# limits on both axes. The largest body the panel's own forms send is a few KB
# of JSON, so a megabyte is generous headroom, and no client on loopback needs
# longer than a moment to deliver one. Both limits exist to bound what a single
# request can cost the server, not to validate the payload: a body over the cap
# is refused rather than truncated, and a body that stops arriving is given up
# on. See Handler._consume_body.
MAX_POST_BODY_BYTES = 1024 * 1024
POST_BODY_READ_TIMEOUT = 10.0

# v1.9: the UI notification cues the panel plays. Exactly these seven names
# exist on disk (built by lab/scripts/gen_sfx.py) and the /sfx/ route serves
# nothing else. Keys are the cue families the front end asks for.
SFX_FILES = {
    "ui-ok.wav", "ui-error.wav", "ui-warn.wav", "ui-open.wav",
    "ui-tab.wav", "ui-login.wav", "ui-login-error.wav",
}
_SFX_CACHE = {}


def _sfx_cache(name):
    """Read a cue once per process (~150 KB total). Never raises: a missing
    file costs the cue, not the panel."""
    if name in _SFX_CACHE:
        return _SFX_CACHE[name]
    path = os.path.join(HERE, "sfx", name)
    try:
        with open(path, "rb") as handle:
            _SFX_CACHE[name] = handle.read()
    except OSError:
        _SFX_CACHE[name] = None
    return _SFX_CACHE[name]

_STORE_LOCK = threading.RLock()
_STORE_LOCK_PATH = PROFILES_PATH + ".lock"
# Akharin store-e salem (be tafkik-e masir-e file) ke movaffagh khonde/neveshte shode.
# Agar profiles.json be dalile write-e nimekare/harab-shode movaqatan ghabel-e khandan
# nabashad, load_store IN cache ra barmigardanad va HARGEZ file-e mojood ra ba yek
# profile-e khali baznevisi nemikonad (jelogiri az pak-shodan-e profile-ha zir-e bar).
_LAST_GOOD_STORE = {}


class StoreUnreadableError(RuntimeError):
    """profiles.json vojood darad ama na khodash na backup-ash ghabel-e parse nist."""


@contextmanager
def _locked_store():
    """Lock-e beyn-processi; chand gomrok.py yek profile ra claim nakonand."""
    import msvcrt
    with _STORE_LOCK:
        os.makedirs(os.path.dirname(_STORE_LOCK_PATH), exist_ok=True)
        with open(_STORE_LOCK_PATH, "a+b") as lock_file:
            if os.path.getsize(_STORE_LOCK_PATH) == 0:
                lock_file.write(b"0")
                lock_file.flush()
            lock_file.seek(0)
            while True:
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)

PROFILE_DEFAULTS = {
    "id": "", "title": "", "national": "", "birth": "", "mobile": "", "telegram_chat_id": "",
    "first_name": "", "last_name": "", "father_name": "", "birth_certificate_no": "",
    # v1.5 item 11: OPTIONAL latin passport number, carried for the operator's
    # manual portal workflow. Never required — start_profile's missing-list
    # deliberately does NOT include it (robot side out of scope).
    "passport": "",
    "imeis": ["", ""], "no_confirm_check": False, "submit": True,
    "debugging": False, "manual_manage": False,
    # Morurgar be tore pishfarz makhfi (off-screen) ejra mishavad ta manabe-e
    # system zir-e bar-e chand robot-e hamzaman hedar naravad. Panel in flag ra
    # taghir midahad va robot-e dar-hal-e-ejra an-ra donbal mikonad.
    "browser_visible": False,
    "registration_status": "pending", "success_at": "", "payment_link": "",
    "runtime_error": "",
    "run_status": "idle", "runner_id": "", "busy_since": "",
    "receipt_screenshot": "", "payment_screenshot": "",
    "runner_pid": 0,
    "enabled": True,
    "heartbeat_at": "",
    "exitban_status": "not_checked",
    "exitban_result": "",
    "exitban_checked_at": "",
    "device_inquiry_pid": 0,
    "device_inquiry_service": "",
    "device_inquiry_started_at": "",
    "gomrok_inquiry_status": "not_checked",
    "gomrok_inquiry_results": [],
    "gomrok_inquiry_error": "",
    "gomrok_inquiry_checked_at": "",
    "hamta_inquiry_status": "not_checked",
    "hamta_inquiry_results": [],
    "hamta_inquiry_error": "",
    "hamta_inquiry_checked_at": "",
}


def _new_id():
    return uuid.uuid4().hex[:8]


def _clean_profile(p):
    """Yek profile-e vorudi ra tamiz/normal mikonad."""
    out = dict(PROFILE_DEFAULTS)
    out.update({k: p.get(k, v) for k, v in PROFILE_DEFAULTS.items()})
    out["id"] = (p.get("id") or "").strip() or _new_id()
    for k in ("title", "national", "birth", "mobile", "telegram_chat_id", "first_name",
              "last_name", "father_name", "birth_certificate_no", "registration_status",
              "success_at", "payment_link", "runtime_error", "run_status", "runner_id", "busy_since",
              "receipt_screenshot", "payment_screenshot", "heartbeat_at", "exitban_status",
              "exitban_result", "exitban_checked_at", "device_inquiry_service",
              "device_inquiry_started_at", "gomrok_inquiry_status", "gomrok_inquiry_error",
              "gomrok_inquiry_checked_at", "hamta_inquiry_status", "hamta_inquiry_error",
              "hamta_inquiry_checked_at"):
        out[k] = str(out.get(k) or "").strip()
    # Optional passport (v1.5 item 11): normalize strip+uppercase, NEVER
    # reject — legacy rows without the key simply default to "" and stay
    # valid. Format enforcement lives in the /save route only.
    out["passport"] = str(out.get("passport") or "").strip().upper()
    for key in ("gomrok_inquiry_results", "hamta_inquiry_results"):
        out[key] = list(out.get(key) or [])
    imeis = out.get("imeis") or []
    if not isinstance(imeis, list):
        imeis = [str(imeis)]
    out["imeis"] = [str(x).strip() for x in imeis if x and str(x).strip()]
    out["no_confirm_check"] = bool(out.get("no_confirm_check"))
    # Auto-submit (zadan-e 'edame') digar switch-e UI nadarad va HAMISHE roshan ast.
    # Halat-haye debugging va manual_manage tanzimat-e khodeshan ra dast-nakhorde
    # negah midarand (in do az panel be robot pas mishavand va rooye
    # jarayan-e submit dar gomrok.py asar-e khodeshan ra darand).
    out["submit"] = True
    out["debugging"] = bool(out.get("debugging"))
    out["manual_manage"] = bool(out.get("manual_manage"))
    out["browser_visible"] = bool(out.get("browser_visible"))
    out["enabled"] = bool(out.get("enabled", True))
    try:
        out["runner_pid"] = int(out.get("runner_pid") or 0)
    except (TypeError, ValueError):
        out["runner_pid"] = 0
    try:
        out["device_inquiry_pid"] = int(out.get("device_inquiry_pid") or 0)
    except (TypeError, ValueError):
        out["device_inquiry_pid"] = 0
    # title-e hushmand: agar khali bud -> kod-e melli ya 'profile-e no'
    if not out["title"]:
        out["title"] = out["national"] or "پروفایل جدید"
    return out


_EXITBAN_CLEAR_TEXT = "شخص با کد ملی ثبت‌شده ممنوع‌الخروج نمی‌باشد."


def _classify_exitban_result(text, status=""):
    status = str(status or "").strip().lower()
    if status in ("clear", "blocked"):
        return status
    normalized = " ".join(str(text or "").replace("‌", "").split())
    if "ممنوعالخروج نمیباشد" in normalized:
        return "clear"
    return "blocked"


def record_exitban_error(profile_id, message):
    message = str(message or "").strip()
    message = __import__("re").sub(r"(?<!\d)\d{10}(?!\d)", "[REDACTED]", message)
    row = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "profile_id": str(profile_id or ""),
        "message": message[:1000],
    }
    with open(EXITBAN_ERRORS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def record_exitban_result(profile_id, text, status=""):
    """Natije-ye estelam ra baraye haman profile atomically zakhire mikonad."""
    text = str(text or "").strip()
    if not text:
        return False
    with _locked_store():
        store = load_store()
        for profile in store.get("profiles", []):
            if profile.get("id") != str(profile_id or ""):
                continue
            profile["exitban_status"] = _classify_exitban_result(text, status)
            profile["exitban_result"] = text
            profile["exitban_checked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            save_store(store)
            return True
    return False


_DEVICE_INQUIRY_SERVICES = {"hamta", "gomrok", "all"}
_DEVICE_INQUIRY_FINAL = {"healthy", "problem", "advanced", "good", "registered", "blocked"}


def _device_inquiry_summary(results, error=""):
    if error:
        return "error"
    statuses = {str(item.get("status") or "error") for item in results}
    if not statuses:
        return "error"
    return "complete" if statuses <= _DEVICE_INQUIRY_FINAL else "error"


def record_profile_device_inquiry(profile_id, service, results, error=""):
    service = str(service or "").strip().lower()
    if service not in ("hamta", "gomrok") or not isinstance(results, list):
        return False
    clean = []
    for item in results:
        if isinstance(item, dict):
            clean.append({"serial": str(item.get("serial") or "").strip(),
                          "serial2": str(item.get("serial2") or "").strip(),
                          "status": str(item.get("status") or "error").strip(),
                          "result": str(item.get("result") or "").strip(),
                          "checked_at": str(item.get("checked_at") or "").strip()})
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", [])
                        if p.get("id") == str(profile_id or "")), None)
        if not profile:
            return False
        profile[f"{service}_inquiry_results"] = clean
        profile[f"{service}_inquiry_status"] = _device_inquiry_summary(clean, error)
        profile[f"{service}_inquiry_error"] = str(error or "").strip()
        profile[f"{service}_inquiry_checked_at"] = now
        requested = str(profile.get("device_inquiry_service") or "")
        if requested == service or (requested == "all" and
                all(profile.get(f"{name}_inquiry_status") not in ("running", "not_checked")
                    for name in ("gomrok", "hamta"))):
            profile["device_inquiry_pid"] = 0
        save_store(store)
        return True
    return False


def _backup_path():
    return PROFILES_PATH + ".bak"


# Set by shutdown_everything(); main()'s serve loop polls it and exits cleanly.
_SHUTDOWN_REQUESTED = threading.Event()


def stop_profile_inquiry(profile_id):
    """Stop the profile's device-inquiry robot (profile_inquiry.py tree).

    Kills the tracked pid (device_inquiry_pid) when alive, resets the running
    inquiry bookkeeping, and reports a calm no-op when nothing is running.
    Returns (ok, message) — ok is False only when the profile does not exist.
    """
    profile_id = str(profile_id or "").strip()
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", [])
                        if p.get("id") == profile_id), None)
        if not profile:
            return False, "پروفایل پیدا نشد"
        pid = int(profile.get("device_inquiry_pid") or 0)
        running = bool(pid and _pid_alive(pid))
        services = [name for name in ("gomrok", "hamta")
                    if profile.get(f"{name}_inquiry_status") == "running"]
        if running:
            profile["device_inquiry_pid"] = 0
            profile["device_inquiry_service"] = ""
            for name in services or ["gomrok", "hamta"]:
                profile[f"{name}_inquiry_status"] = "not_checked"
                profile[f"{name}_inquiry_error"] = "توقف دستی توسط کاربر"
            save_store(store)
    if running:
        stop_profile_process(pid)
        return True, "استعلام متوقف شد و مرورگر بسته شد"
    return True, "استعلامی برای این پروفایل در حال اجرا نیست"


def shutdown_everything():
    """Stop every robot this panel spawned, then ask main() to exit.

    Kills: busy gomrok/gomrok2 runners, per-profile device inquiries and the
    estelam (site-2) run. Returns a small summary for the HTTP response.
    """
    stopped = []
    with _locked_store():
        store = load_store()
        for profile in store.get("profiles", []):
            pids = []
            if profile.get("run_status") == "busy" and profile.get("runner_pid"):
                pids.append(int(profile["runner_pid"]))
            inquiry_pid = int(profile.get("device_inquiry_pid") or 0)
            if inquiry_pid:
                pids.append(inquiry_pid)
                profile["device_inquiry_pid"] = 0
                profile["device_inquiry_service"] = ""
                for name in ("gomrok", "hamta"):
                    if profile.get(f"{name}_inquiry_status") == "running":
                        profile[f"{name}_inquiry_status"] = "not_checked"
                        profile[f"{name}_inquiry_error"] = "بستن سامانه توسط کاربر"
            if profile.get("run_status") == "busy":
                profile["run_status"] = "idle"
                profile["runner_id"] = ""
                profile["busy_since"] = ""
                profile["runner_pid"] = 0
                profile["heartbeat_at"] = ""
            if pids:
                stopped.extend(pids)
        save_store(store)
    estelam_pid = int(estelam_load().get("run_pid") or 0)
    if estelam_pid:
        stopped.append(estelam_pid)
        estelam_stop()
    for pid in stopped:
        stop_profile_process(pid)
    _SHUTDOWN_REQUESTED.set()
    return {"ok": True, "stopped": stopped}


def _parse_store_file(path):
    """File ra parse mikonad. Barmigardanad store-e tamiz ya None (nabood/harab)."""
    if not os.path.exists(path):
        return None
    try:
        if os.path.getsize(path) == 0:
            return None
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    raw = data.get("profiles")
    if not isinstance(raw, list):
        return None
    profs = [_clean_profile(p) for p in raw if isinstance(p, dict)]
    active = data.get("active_id") or (profs[0]["id"] if profs else "")
    if profs and active not in [p["id"] for p in profs]:
        active = profs[0]["id"]
    return {"profiles": profs, "active_id": active}


def load_store():
    """profiles.json ra mikhanad: {profiles:[...], active_id:"..."}.

    Tartib-e manba'-ha (mohem baraye jelogiri az pak-shodan-e profile-ha):
      1) khod-e profiles.json
      2) profiles.json.bak (nokhse-ye salem-e ghabli)
      3) cache-e in process (_LAST_GOOD_STORE)
    Agar file VOJOOD DARAD vali hich-kodam ghabel-e khandan nabood,
    StoreUnreadableError partab mishavad — DAR IN HALAT file BAZNEVISI NEMISHAVAD.
    Faghat vaghti file asan nabashad, mohajerat az inputs.json anjam mishavad.
    """
    store = _parse_store_file(PROFILES_PATH)
    if store is not None:
        _LAST_GOOD_STORE[PROFILES_PATH] = store
        return store

    file_exists = os.path.exists(PROFILES_PATH)
    if file_exists:
        recovered = _parse_store_file(_backup_path())
        if recovered is not None:
            print(">>> HOSHDAR: profiles.json kharab bood — az profiles.json.bak barmigardanim.")
            _LAST_GOOD_STORE[PROFILES_PATH] = recovered
            return recovered
        cached = _LAST_GOOD_STORE.get(PROFILES_PATH)
        if cached is not None:
            print(">>> HOSHDAR: profiles.json kharab bood — az cache-e process estefade shod.")
            return {"profiles": [dict(p) for p in cached["profiles"]],
                    "active_id": cached["active_id"]}
        raise StoreUnreadableError(
            "profiles.json ghabel-e khandan nist va backup/cache ham vojood nadarad")

    # File asan nist: mohajerat-e narm az inputs.json-e ghadimi.
    profs = []
    if os.path.exists(INPUTS_PATH):
        try:
            with open(INPUTS_PATH, encoding="utf-8") as f:
                old = json.load(f)
            if old:
                profs = [_clean_profile(old)]
        except (OSError, ValueError):
            pass
    if not profs:
        profs = [_clean_profile({})]
    store = {"profiles": profs, "active_id": profs[0]["id"]}
    save_store(store)
    return store


def save_store(store):
    """Store ra ATOMIC minevisad: tmp + fsync + os.replace, ba yek backup-e salem.

    Rooye Windows write-e mostaghim rooye profiles.json ba'd az truncate,
    agar process/system zir-e bar ghat' shavad, file-e khali/nimekare baja
    migozarad — hamin baes-e 'khali shodan-e profile-ha' mishod.
    """
    profs = [_clean_profile(p) for p in store.get("profiles", [])]
    active = store.get("active_id") or (profs[0]["id"] if profs else "")
    if profs and active not in [p["id"] for p in profs]:
        active = profs[0]["id"]
    clean = {"profiles": profs, "active_id": active}
    payload = json.dumps(clean, ensure_ascii=False, indent=2)

    # backup-e nokhse-ye salem-e ghabli (faghat agar khod-esh salem bashad)
    if _parse_store_file(PROFILES_PATH) is not None:
        try:
            shutil.copyfile(PROFILES_PATH, _backup_path())
        except OSError as exc:
            print(f">>> HOSHDAR: backup-e profiles.json anjam nashod: {exc}")

    directory = os.path.dirname(os.path.abspath(PROFILES_PATH)) or "."
    os.makedirs(directory, exist_ok=True)
    # Bounded retry (production fix 2026-09-15): on Windows, os.replace fails
    # with PermissionError while ANY other process holds profiles.json open
    # (editor/backup/antivirus). A short retry absorbs transient overlaps;
    # persistent contention still raises and surfaces to the caller.
    last_exc = None
    for attempt in range(3):
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=".profiles-",
                                            suffix=".tmp", dir=directory)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, PROFILES_PATH)
            tmp_path = None
            last_exc = None
            break
        except OSError as exc:
            last_exc = exc
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        if attempt < 2:
            time.sleep(0.35 * (attempt + 1))
    if last_exc is not None:
        raise last_exc

    _LAST_GOOD_STORE[PROFILES_PATH] = clean
    sync_active_to_inputs(clean)
    return clean


def mark_profile_success(title="", national="", imei="", payment_link=""):
    """Profile-e motabegh ra vaghti be pardakht resid movaffagh mikonad."""
    import time
    store = load_store()
    title, national, imei = str(title).strip(), str(national).strip(), str(imei).strip()
    target = None
    for p in store.get("profiles", []):
        if national and p.get("national") == national:
            target = p
            break
        if imei and imei in (p.get("imeis") or []):
            target = p
            break
        if title and p.get("title") == title:
            target = p
    if not target:
        return False
    target["registration_status"] = "success"
    target["success_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    target["payment_link"] = str(payment_link or "").strip()
    save_store(store)
    return True


def mark_profile_unusable(profile_id, error_text):
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", [])
                        if p.get("id") == str(profile_id)), None)
        if not profile:
            return False
        profile["registration_status"] = "blocked"
        profile["enabled"] = False
        profile["runtime_error"] = (
            "این پروفایل دیگر قابل ورود نیست: " + str(error_text or "").strip())
        profile["run_status"] = "idle"
        profile["runner_id"] = ""
        profile["busy_since"] = ""
        profile["runner_pid"] = 0
        profile["heartbeat_at"] = ""
        save_store(store)
        return True


def app_version_text():
    """Version of the running panel, read once from VERSION beside this file."""
    global _APP_VERSION
    if not _APP_VERSION:
        try:
            with open(os.path.join(HERE, "VERSION"), encoding="utf-8") as f:
                _APP_VERSION = f.read().strip()
        except OSError:
            _APP_VERSION = ""
    return _APP_VERSION


_APP_VERSION = ""


def release_blocked_profile_with_reason(profile_id):
    """Unblock a blocked profile so the operator can edit and rerun it.

    Only a profile that is actually blocked AND not busy is reset. Everything
    the start gate refuses on is cleared: registration_status -> pending,
    runtime_error dropped, runtime bookkeeping reset, inquiry bookkeeping back
    to not_checked, and the profile re-enabled (mark_profile_unusable disabled
    it). Returns (ok, message) — message is Persian for the panel UI.
    """
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", [])
                        if p.get("id") == str(profile_id or "")), None)
        if not profile:
            return False, "پروفایلی با این شناسه پیدا نشد"
        if profile.get("run_status") == "busy":
            return False, "پروفایل در حال اجراست؛ اول ربات را متوقف کنید"
        if profile.get("registration_status") != "blocked":
            return False, "این پروفایل مسدود نیست؛ نیازی به آزادسازی ندارد"
        profile["registration_status"] = "pending"
        profile["runtime_error"] = ""
        profile["run_status"] = "idle"
        profile["runner_id"] = ""
        profile["busy_since"] = ""
        profile["runner_pid"] = 0
        profile["heartbeat_at"] = ""
        profile["device_inquiry_pid"] = 0
        profile["device_inquiry_service"] = ""
        profile["device_inquiry_started_at"] = ""
        profile["gomrok_inquiry_status"] = "not_checked"
        profile["hamta_inquiry_status"] = "not_checked"
        profile["enabled"] = True
        save_store(store)
        return True, f"پروفایل «{profile.get('title') or profile_id}» آزاد شد"


def release_blocked_profile(profile_id):
    """Boolean wrapper kept for callers that ignore the reason message."""
    return release_blocked_profile_with_reason(profile_id)[0]


def merge_profile_update(current, submitted):
    """Field-haye runtime/status ra dar edit-e form az dast nemidahad."""
    merged = dict(current or {})
    merged.update(submitted or {})
    return merged


def clone_profile(profile_id):
    with _locked_store():
        store = load_store()
        source = next((p for p in store.get("profiles", []) if p.get("id") == profile_id), None)
        if not source:
            return None
        base = source.get("title") or source.get("national") or "پروفایل"
        existing = {p.get("title") for p in store.get("profiles", [])}
        number = 2
        while f"{base} {number}" in existing:
            number += 1
        clone = dict(source)
        clone.update({
            "id": _new_id(), "title": f"{base} {number}",
            "registration_status": "pending", "success_at": "", "payment_link": "",
            "runtime_error": "",
            "run_status": "idle", "runner_id": "", "busy_since": "", "runner_pid": 0,
            "heartbeat_at": "", "exitban_status": "not_checked", "exitban_result": "",
            "exitban_checked_at": "", "device_inquiry_pid": 0, "device_inquiry_service": "",
            "device_inquiry_started_at": "", "gomrok_inquiry_status": "not_checked",
            "gomrok_inquiry_results": [], "gomrok_inquiry_error": "",
            "gomrok_inquiry_checked_at": "", "hamta_inquiry_status": "not_checked",
            "hamta_inquiry_results": [], "hamta_inquiry_error": "",
            "hamta_inquiry_checked_at": "",
            "receipt_screenshot": "", "payment_screenshot": "",
        })
        clone = _clean_profile(clone)
        store["profiles"].append(clone)
        store["active_id"] = clone["id"]
        save_store(store)
        return clone


def claim_profile(profile_id=None):
    """Avalin profile-e azad va takmil-nashode ra atomically be yek robot midahad."""
    with _locked_store():
        store = load_store()
        profiles = store.get("profiles", [])
        active = store.get("active_id")
        ordered = ([p for p in profiles if p.get("id") == profile_id] if profile_id else
                   sorted(profiles, key=lambda p: p.get("id") != active))
        for p in ordered:
            if p.get("run_status") == "busy" and not _pid_alive(p.get("runner_pid")):
                p["run_status"], p["runner_id"], p["busy_since"], p["runner_pid"], p["heartbeat_at"] = "idle", "", "", 0, ""
            if (((not p.get("enabled", True)) and not profile_id) or p.get("run_status") == "busy" or
                    p.get("registration_status") == "success"):
                continue
            runner_id = uuid.uuid4().hex
            p["run_status"] = "busy"
            p["runner_id"] = runner_id
            p["busy_since"] = time.strftime("%Y-%m-%d %H:%M:%S")
            p["heartbeat_at"] = p["busy_since"]
            p["runner_pid"] = os.getpid()
            # har ejra ba morurgar-e makhfi shoru mishavad (off-screen).
            p["browser_visible"] = False
            save_store(store)
            result = dict(p)
            result["runner_id"] = runner_id
            return result
    return None


def _robot_command(python_executable, script, *args):
    return [python_executable, os.path.join(HERE, "robot_launcher.py"),
            os.path.join(HERE, script)] + [str(arg) for arg in args]


def start_profile_process(profile_id, actor=None):
    command = _robot_command(ROBOT_PYTHON, "gomrok.py", "--profile-id", profile_id)
    child_env = _robot_child_env(actor)
    log_file = open(ROBOT_LOG_PATH, "a", encoding="utf-8")
    try:
        process = subprocess.Popen(command, cwd=HERE, env=child_env, stdin=subprocess.DEVNULL,
                                   stdout=log_file, stderr=log_file)
    finally:
        log_file.close()
    return {"pid": process.pid, "profile_id": str(profile_id)}


def start_profile2_process(profile_id, actor=None):
    command = _robot_command(ROBOT_PYTHON, "gomrok2.py", "--profile-id", profile_id)
    child_env = _robot_child_env(actor)
    log_file = open(ROBOT_LOG_PATH, "a", encoding="utf-8")
    try:
        process = subprocess.Popen(command, cwd=HERE, env=child_env, stdin=subprocess.DEVNULL,
                                   stdout=log_file, stderr=log_file)
    finally:
        log_file.close()
    return {"pid": process.pid, "profile_id": str(profile_id)}


def start_site2_manual_process(actor=None):
    command = _robot_command(ROBOT_PYTHON, "gomrok2.py", "--no-panel")
    child_env = _robot_child_env(actor)
    log_file = open(ROBOT_LOG_PATH, "a", encoding="utf-8")
    try:
        process = subprocess.Popen(command, cwd=HERE, env=child_env, stdin=subprocess.DEVNULL,
                                   stdout=log_file, stderr=log_file)
    finally:
        log_file.close()
    return {"pid": process.pid}


def start_profile2(profile_id, actor=None):
    profile_id = str(profile_id or "").strip()
    with _locked_store():
        profile = next((p for p in load_store().get("profiles", []) if p.get("id") == profile_id), None)
        if not profile:
            return 404, {"error": "profile not found"}
        if profile.get("run_status") == "busy":
            return 409, {"error": "profile is already running"}
        if profile.get("registration_status") == "blocked":
            return 409, {"error": "این پروفایل قابل استفاده نیست"}
    try:
        runtime = start_profile2_process(profile_id, actor=actor)
    except (OSError, ValueError):
        return 500, {"error": "شروع ربات سایت دوم انجام نشد"}
    # profile-ra INJA busy nemikonim; khod-e gomrok2.py ba claim_profile() an-ra
    # busy + runner_id mikonad (mesl-e start_profile). faghat pid-ra sabt mikonim
    # ta ta zaman-e claim, clear_stale_busy_profiles process-e zende-ra nakoshad.
    set_profile_runtime(profile_id, runtime["pid"])
    return 200, {"ok": True, "profile_id": profile_id, "pid": runtime["pid"]}


def start_profile(profile_id, actor=None):
    profile_id = str(profile_id or "").strip()
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", []) if p.get("id") == profile_id), None)
        if not profile:
            return 404, {"error": "profile not found"}
        if profile.get("run_status") == "busy":
            return 409, {"error": "profile is already running"}
        if profile.get("registration_status") == "success":
            return 409, {"error": "profile is already complete"}
        if profile.get("registration_status") == "blocked":
            return 409, {"error": "این پروفایل قابل استفاده نیست؛ خطای غیرقابل‌ورود ثبت شده است"}
        missing = []
        if not profile.get("manual_manage"):
            if not profile.get("national"):
                missing.append("کد ملی")
            if not profile.get("birth"):
                missing.append("تاریخ تولد")
            if not profile.get("imeis"):
                missing.append("سریال / IMEI")
        if missing:
            return 422, {"error": "اطلاعات پروفایل ناقص است", "missing": missing}
    try:
        runtime = start_profile_process(profile_id, actor=actor)
    except (OSError, ValueError):
        return 500, {"error": "شروع ربات انجام نشد"}
    set_profile_runtime(profile_id, runtime["pid"])
    return 200, {"ok": True, "profile_id": profile_id, "pid": runtime["pid"]}


def start_profile_device_inquiry(profile_id, service, actor=None):
    profile_id = str(profile_id or "").strip()
    service = str(service or "").strip().lower()
    if service not in _DEVICE_INQUIRY_SERVICES:
        return 400, {"error": "نوع استعلام نامعتبر است"}
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", []) if p.get("id") == profile_id), None)
        if not profile:
            return 404, {"error": "پروفایل پیدا نشد"}
        missing = []
        if not profile.get("imeis"):
            missing.append("سریال / IMEI")
        if service in ("gomrok", "all"):
            if not profile.get("national"):
                missing.append("کد ملی")
            if not profile.get("birth"):
                missing.append("تاریخ تولد")
        if missing:
            return 422, {"error": "اطلاعات پروفایل ناقص است", "missing": missing}
        old_pid = int(profile.get("device_inquiry_pid") or 0)
        if old_pid and _pid_alive(old_pid):
            return 409, {"error": "یک استعلام برای این پروفایل در حال اجرا است"}

    command = _robot_command(ROBOT_PYTHON, "profile_inquiry.py",
                             "--profile-id", profile_id, "--service", service)
    child_env = _robot_child_env(actor)
    log_file = open(ROBOT_LOG_PATH, "a", encoding="utf-8")
    try:
        process = subprocess.Popen(command, cwd=HERE, env=child_env,
                                   stdin=subprocess.DEVNULL, stdout=log_file, stderr=log_file)
    except OSError:
        return 500, {"error": "شروع ربات استعلام انجام نشد"}
    finally:
        log_file.close()
    with _locked_store():
        store = load_store()
        profile = next(p for p in store["profiles"] if p["id"] == profile_id)
        profile["device_inquiry_pid"] = process.pid
        profile["device_inquiry_service"] = service
        profile["device_inquiry_started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        for name in (("gomrok", "hamta") if service == "all" else (service,)):
            profile[f"{name}_inquiry_status"] = "running"
            profile[f"{name}_inquiry_error"] = ""
        save_store(store)
    return 200, {"ok": True, "profile_id": profile_id, "service": service, "pid": process.pid}


def start_exitban_process(profile_id, actor=None):
    log_path = app_paths.data_path("exitban_worker.log")
    command = _robot_command(ROBOT_PYTHON, "exitban.py",
                             "--profile-id", profile_id, "--submit")
    log_file = open(log_path, "a", encoding="utf-8")
    try:
        process = subprocess.Popen(command, cwd=HERE, env=_robot_child_env(actor), stdin=subprocess.DEVNULL,
                                   stdout=log_file, stderr=log_file)
    finally:
        log_file.close()
    return {"pid": process.pid, "profile_id": str(profile_id)}


def stop_profile_process(pid):
    if not pid or not _pid_alive(pid):
        return False
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
            return result.returncode == 0
        os.kill(int(pid), signal.SIGTERM)
        return True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def stop_profile(profile_id):
    profile_id = str(profile_id or "").strip()
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", []) if p.get("id") == profile_id), None)
        if not profile:
            return 404, {"error": "profile not found"}
        pid = int(profile.get("runner_pid") or 0)
    stopped = stop_profile_process(pid) if pid else False
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", []) if p.get("id") == profile_id), None)
        if profile and profile.get("run_status") == "busy":
            profile["run_status"] = "idle"
            profile["runner_id"] = ""
            profile["busy_since"] = ""
            profile["runner_pid"] = 0
            profile["heartbeat_at"] = ""
            save_store(store)
    return 200, {"ok": True, "stopped": stopped, "profile_id": profile_id}


def set_profile_runtime(profile_id, pid, runner_id=""):
    with _locked_store():
        store = load_store()
        for profile in store.get("profiles", []):
            if profile.get("id") == profile_id:
                profile["runner_pid"] = int(pid or 0)
                if runner_id:
                    profile["runner_id"] = runner_id
                save_store(store)
                return True
    return False


def _pid_alive(pid):
    import ctypes
    if not pid:
        return False
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return False
    ctypes.windll.kernel32.CloseHandle(handle)
    return True


def _heartbeat_stale(value, max_age=120):
    try:
        stamp = time.mktime(time.strptime(str(value), "%Y-%m-%d %H:%M:%S"))
        return time.time() - stamp > max_age
    except (TypeError, ValueError):
        return True


def heartbeat_profile(profile_id, runner_id):
    with _locked_store():
        store = load_store()
        for p in store.get("profiles", []):
            if p.get("id") == profile_id and p.get("runner_id") == runner_id and p.get("run_status") == "busy":
                p["heartbeat_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                save_store(store)
                return True
    return False


def clear_stale_busy_profiles():
    """Lock-haye process-hayi ke digar zende nistand ra pak mikonad."""
    changed = False
    with _locked_store():
        store = load_store()
        for p in store.get("profiles", []):
            if p.get("run_status") != "busy":
                continue
            heartbeat = p.get("heartbeat_at") or p.get("busy_since")
            if (p.get("runner_pid") and _pid_alive(p["runner_pid"]) and
                    not _heartbeat_stale(heartbeat)):
                continue
            p["run_status"], p["runner_id"], p["busy_since"], p["runner_pid"], p["heartbeat_at"] = "idle", "", "", 0, ""
            # robot morde ast: darkhast-e namayesh-e morurgar ham bi-ma'ni ast.
            p["browser_visible"] = False
            changed = True
        if changed:
            save_store(store)
    return changed


def get_browser_visibility(profile_id):
    """Flag-e namayesh-e morurgar baraye in profile (None = profile peyda nashod).

    Robot-e dar-hal-e-ejra in-ra har chand sanie mikhanad; pas SABOK negah dashte
    mishavad (bedun-e lock-e beyn-processi) va dar soorat-e kharabi-ye movaqat-e
    file, None barmigardanad ta robot vaziat-e fe'li-ye khod ra hefz konad.
    """
    profile_id = str(profile_id or "").strip()
    if not profile_id:
        return None
    try:
        store = load_store()
    except StoreUnreadableError:
        return None
    for p in store.get("profiles", []):
        if p.get("id") == profile_id:
            return bool(p.get("browser_visible"))
    return None


def set_browser_visibility(profile_id, visible):
    """Darkhast-e namayesh/makhfi-kardan-e morurgar ra rooye profile sabt mikonad."""
    profile_id = str(profile_id or "").strip()
    if not profile_id:
        return 422, {"error": "profile id is required"}
    with _locked_store():
        store = load_store()
        profile = next((p for p in store.get("profiles", []) if p.get("id") == profile_id), None)
        if not profile:
            return 404, {"error": "profile not found"}
        if profile.get("run_status") != "busy":
            return 409, {"error": "این پروفایل در حال اجرا نیست"}
        profile["browser_visible"] = bool(visible)
        save_store(store)
    return 200, {"ok": True, "profile_id": profile_id, "browser_visible": bool(visible)}


def release_profile(profile_id, runner_id):
    with _locked_store():
        store = load_store()
        for p in store.get("profiles", []):
            if p.get("id") == profile_id and p.get("runner_id") == runner_id:
                p["run_status"], p["runner_id"], p["busy_since"], p["runner_pid"], p["heartbeat_at"] = "idle", "", "", 0, ""
                save_store(store)
                return True
    return False


def record_profile_output(profile_id, runner_id="", receipt="", payment="", link=""):
    with _locked_store():
        store = load_store()
        for p in store.get("profiles", []):
            if p.get("id") != profile_id:
                continue
            if runner_id and p.get("runner_id") not in ("", runner_id):
                return False
            p["registration_status"] = "success"
            p["success_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            p["receipt_screenshot"] = str(receipt or "")
            p["payment_screenshot"] = str(payment or "")
            p["payment_link"] = str(link or "")
            save_store(store)
            return True
    return False


def load_system_debug_config():
    try:
        with open(SYSTEM_DEBUG_CONFIG_PATH, encoding="utf-8") as handle:
            data = json.load(handle) or {}
    except (OSError, ValueError):
        data = {}
    # Default ON: browser-run logs are the primary post-mortem evidence.
    return {"enabled": bool(data.get("enabled", True))}


def save_system_debug_config(data):
    clean = {"enabled": bool((data or {}).get("enabled"))}
    os.makedirs(os.path.dirname(SYSTEM_DEBUG_CONFIG_PATH), exist_ok=True)
    with open(SYSTEM_DEBUG_CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(clean, handle, ensure_ascii=False, indent=2)
    return clean


def list_system_logs():
    os.makedirs(SYSTEM_LOG_DIR, exist_ok=True)
    logs = []
    for name in os.listdir(SYSTEM_LOG_DIR):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.log", name):
            continue
        path = os.path.join(SYSTEM_LOG_DIR, name)
        try:
            stat = os.stat(path)
        except OSError:
            continue
        logs.append({"name": name, "size": stat.st_size,
                     "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))})
    logs.sort(key=lambda item: item["modified"], reverse=True)
    return logs[:200]


def read_system_log(name, max_bytes=512000):
    name = str(name or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.log", name):
        raise ValueError("invalid log name")
    root = os.path.realpath(SYSTEM_LOG_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if os.path.commonpath([root, path]) != root or not os.path.isfile(path):
        raise FileNotFoundError(name)
    with open(path, "rb") as handle:
        size = os.path.getsize(path)
        if size > max_bytes:
            handle.seek(size - max_bytes)
            handle.readline()
        raw = handle.read(max_bytes)
    return raw.decode("utf-8", errors="replace")


def _robot_child_env(actor=None):
    child_env = os.environ.copy()
    child_env["IRICA_ACTOR"] = str(actor or "").strip() or "سیستم"
    child_env.pop("PYTHONPATH", None)
    child_env.pop("VIRTUAL_ENV", None)
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"
    child_env["IRICA_SYSTEM_DEBUG"] = "1" if load_system_debug_config()["enabled"] else "0"
    child_env["IRICA_SYSTEM_LOG_DIR"] = SYSTEM_LOG_DIR
    return child_env


def load_telegram_config():
    try:
        with open(TELEGRAM_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    ids = cfg.get("chat_ids") or ([cfg.get("chat_id")] if cfg.get("chat_id") else [])
    mode = str(cfg.get("mode") or "").strip().lower()
    if mode not in ("host", "proxy", "direct"):
        if cfg.get("relay_url"):
            mode = "host"
        elif cfg.get("proxy_url"):
            mode = "proxy"
        elif cfg.get("api_base") and str(cfg["api_base"]).strip() != "https://api.telegram.org":
            mode = "direct"
        else:
            mode = "host"
    return {
        "mode": mode,
        "relay_url": str(cfg.get("relay_url") or "https://api.oneserver.in/telegram.php").strip(),
        "relay_secret": str(cfg.get("relay_secret") or "").strip(),
        "proxy_url": str(cfg.get("proxy_url") or "").strip(),
        "api_base": str(cfg.get("api_base") or "https://api.telegram.org").strip(),
        "bot_token": str(cfg.get("bot_token") or "").strip(),
        "chat_ids": [str(x).strip() for x in ids if str(x).strip()],
    }


def save_telegram_config(cfg):
    """Token and secret only change when the user provides a new non-empty value.
    (UI never sends stored tokens, so blank = 'keep current').

    `chat_ids` accepts both list and newline/comma-separated strings.
    """
    current = load_telegram_config()
    incoming_token = str(cfg.get("bot_token") or "").strip()
    incoming_secret = str(cfg.get("relay_secret") or "").strip()
    incoming_ids = cfg.get("chat_ids") or ""
    if isinstance(incoming_ids, (list, tuple)):
        raw_ids = [str(x) for x in incoming_ids]
    else:
        raw_ids = str(incoming_ids).replace(",", "\n").splitlines()
    mode = str(cfg.get("mode") or current.get("mode") or "host").strip().lower()
    if mode not in ("host", "proxy", "direct"):
        mode = "host"
    clean = {
        "mode": mode,
        "relay_url": str(cfg.get("relay_url") or current.get("relay_url") or "https://api.oneserver.in/telegram.php").strip(),
        "relay_secret": incoming_secret if ("relay_secret" in cfg and incoming_secret) else current.get("relay_secret", ""),
        "proxy_url": str(cfg.get("proxy_url") or "").strip(),
        "api_base": str(cfg.get("api_base") or "https://api.telegram.org").strip(),
        "bot_token": incoming_token or current.get("bot_token", ""),
        "chat_ids": [x.strip() for x in raw_ids if x.strip()],
    }
    with open(TELEGRAM_PATH, "w", encoding="utf-8") as f:
        json.dump(clean, f, ensure_ascii=False, indent=2)
    return public_telegram_config()


def public_telegram_config():
    """Version without secrets for the UI — tokens never leak to the browser."""
    cfg = load_telegram_config()
    return {
        "mode": cfg.get("mode", "host"),
        "relay_url": cfg.get("relay_url", "https://api.oneserver.in/telegram.php"),
        "relay_secret_set": bool(str(cfg.get("relay_secret") or "").strip()),
        "proxy_url": cfg.get("proxy_url", ""),
        "api_base": cfg.get("api_base", "https://api.telegram.org"),
        "chat_ids": cfg.get("chat_ids", []),
        "token_set": bool(str(cfg.get("bot_token") or "").strip()),
    }


# =====================================================================
# Cloud sync surface (spec §5, §9, §11) — workstream D
# =====================================================================
# Panel-side only: it drives cloud_sync, never re-implements it, and every
# import of that package is local so panel.py still imports and starts when
# the sync package cannot be loaded at all.

#: Persian wording for every stable code the client can emit (spec §11).
#: Keys are codes, never sentences. A code has already passed manager
#: ruling 8's grammar before it can reach this table, so a phone number, a
#: token or a server sentence is structurally impossible here; the server's
#: own `error.message` is never accepted anywhere in this section.
CLOUD_ERROR_MESSAGES = {
    "AUTH_REQUIRED": "نام کاربری یا رمز عبور پذیرفته نشد؛ دوباره تلاش کنید.",
    "AUTH_EXPIRED": "نشست میزبان منقضی شده است؛ دوباره وارد شوید.",
    "AUTH_REVOKED": "دسترسی این دستگاه لغو شده است؛ با مدیر سامانه تماس بگیرید.",
    "ENROL_REQUIRED": "این دستگاه هنوز در میزبان ثبت نشده است؛ ابتدا وارد شوید.",
    "BAD_PAYLOAD": "پاسخ میزبان قابل خواندن نبود؛ دوباره تلاش کنید.",
    "VERSION_CONFLICT": "برخی رکوردها هم‌زمان ویرایش شده‌اند؛ تداخل‌ها را بررسی کنید.",
    "HTTP_400": "درخواست نامعتبر بود؛ تنظیمات اتصال را بررسی کنید.",
    "HTTP_403": "مجوز کافی نیست؛ با مدیر سامانه تماس بگیرید.",
    "HTTP_404": "آدرس میزبان یافت نشد؛ تنظیمات اتصال را بررسی کنید.",
    "HTTP_409": "تداخل داده رخ داده است؛ تداخل‌ها را بررسی کنید.",
    "HTTP_429": "درخواست‌ها زیاد بود؛ کمی بعد دوباره تلاش کنید.",
    "HTTP_500": "میزبان خطای داخلی دارد؛ کمی بعد دوباره تلاش کنید.",
    "HTTP_ERROR": "میزبان این درخواست را نپذیرفت؛ تنظیمات اتصال را بررسی کنید.",
    "SERVER_ERROR": "پاسخ میزبان قابل استفاده نبود؛ دوباره تلاش کنید.",
    "NET_TIMEOUT": "پاسخ میزبان دیر رسید؛ اتصال اینترنت را بررسی کنید.",
    "NET_UNREACHABLE": "ارتباط با میزبان برقرار نشد؛ اتصال اینترنت را بررسی کنید.",
    "QUEUE_FULL": "صف انتظار پر است؛ پیش از ادامه، وضعیت را بررسی کنید.",
    "LEASE_EXPIRED": ("مهلت کارکرد آفلاین به پایان رسیده است؛ دستگاه "
                      "فقط‌خواندنی شده و باید دوباره وارد شوید."),
    "IMPORT_REJECTED": "انتقال داده‌ها پذیرفته نشد؛ با مدیر سامانه تماس بگیرید.",
    "CONFIG_INVALID": "پیکربندی اتصال نامعتبر است؛ تنظیمات را دوباره وارد کنید.",
    "SECRET_UNAVAILABLE": "ذخیره‌ی امن در دسترس نیست؛ اتصال برقرار نمی‌شود.",
    "TRANSITION_NOT_LEGAL": ("این عملیات در وضعیت فعلی مجاز نیست؛ صفحه را "
                             "تازه‌سازی کنید."),
    "UNRESOLVED_REFERENCE": ("رکورد وابسته‌ای روی این دستگاه پیدا نشد؛ "
                             "تداخل‌ها را بررسی کنید."),
    "DATASET_NOT_EMPTY": "داده‌های میزبان خالی نیست؛ امکان انتقال مجدد وجود ندارد.",
    "IMPORT_CONFLICT": "شناسه یا محتوای انتقال با نسخه قبلی همخوانی ندارد.",
    "REMOTE_NOT_READY": "سرور ابری هنوز آماده نیست یا پرونده‌ها به آن منتقل نشده‌اند.",
    "BOOTSTRAP_REQUIRED": "ابتدا همگام‌سازی اولیه با سرور باید کامل شود",
    "DATASET_EPOCH_MISMATCH": "نسخهٔ دیتابیس سرور با کش این سیستم متفاوت است؛ همگام‌سازی برای جلوگیری از بازنویسی متوقف شد",
}

#: A code that fits the grammar but is unknown to this build: still generic
#: Persian, never the code's origin and never a server sentence.
CLOUD_UNKNOWN_MESSAGE = "خطای همگام‌سازی؛ کد آن را به پشتیبانی اعلام کنید."

#: Why the worker did nothing, in words. These are states, not faults, so
#: they carry no code; everything that IS a fault goes through the table.
CLOUD_BEAT_WORDS = {
    "disabled": "همگام‌سازی خاموش است.",
    "not_configured": "هنوز پیکربندی نشده است.",
    "awaiting_login": "در انتظار ورود به میزبان.",
    "remote_not_ready": "سرور ابری آماده نیست (در انتظار انتقال پرونده‌ها).",
}

#: Codes that mean "the host session is not usable" (spec §9: surface, stop).
_CLOUD_AUTH_CODES = frozenset({"AUTH_REQUIRED", "AUTH_EXPIRED", "AUTH_REVOKED"})

#: The host user the panel is acting as. RAM only, like the tokens behind it
#: (spec §5): nothing on disk ever remembers who signed in.
_CLOUD_ACTOR = None
_CLOUD_ROLE = None
_CLOUD_MUST_CHANGE = False
#: The last worker beat, for the "is my edit draining?" line (spec §9).
_CLOUD_LAST_BEAT = None
_CLOUD_RUNTIME = None
_CLOUD_RUNTIME_LOCK = threading.RLock()


def cloud_error_message(code):
    """The Persian text for a stable `code`, or None when it is not a code.

    Only a string matching cloud_sync.state's code grammar is ever looked
    up; anything else — a server sentence, a token, a fragment — returns
    None and is therefore never rendered (spec §6, §11).
    """
    if not isinstance(code, str) or not code:
        return None
    from cloud_sync.state import ERROR_CODE_RE, MAX_CODE_LENGTH
    if len(code) > MAX_CODE_LENGTH or ERROR_CODE_RE.match(code) is None:
        return None
    return CLOUD_ERROR_MESSAGES.get(code, CLOUD_UNKNOWN_MESSAGE)


def cloud_error_body(code, status=400):
    """The panel's own envelope carrying one mapped code (spec §11).

    An unusable `code` is replaced rather than shown: the response always
    names a code this build can translate.
    """
    if cloud_error_message(code) is None:
        code = "SERVER_ERROR"
    return {"ok": False, "errors": [cloud_error_message(code)],
            "code": code}, status


def _cloud_build_runtime():
    """Assemble config / machine / lease / outbox / client / worker.

    Construction only: nothing here talks to the network, and the objects
    are built from the data directory (spec §5). Any failure surfaces as a
    coded CloudSyncError or OSError and is answered by the route guard.
    """
    from cloud_sync.auth import TokenVault
    from cloud_sync.client import SyncClient
    from cloud_sync.config import load_config
    from cloud_sync.lease import OfflineLease
    from cloud_sync.outbox import Outbox, OutboxWorker, OUTBOX_FILE_NAME
    from cloud_sync.state import SyncStateMachine

    config = load_config()
    machine = SyncStateMachine.load()
    lease = OfflineLease.load()
    # cloud_sync/outbox.py names its file "cloud_sync/outbox.jsonl", but
    # app_paths.data_path() takes plain file names only, so the constant
    # raises before the queue can be read. Resolve the very same location
    # the constant names and hand it over explicitly; the queue keeps the
    # path its owner intends, and nothing in cloud_sync is modified here.
    outbox_path = os.path.join(app_paths.data_subdir("cloud_sync"),
                               os.path.basename(OUTBOX_FILE_NAME))
    outbox = Outbox(path=outbox_path)
    client = SyncClient(config=config, vault=TokenVault())
    return {
        "config": config,
        "machine": machine,
        "lease": lease,
        "outbox": outbox,
        "client": client,
        # Auth hooks are NOT wired here: bind_auth() is bound for the length
        # of one worker beat only, so a host login route fires exactly one
        # event of its own instead of one from the client as well (§15.12).
        "worker": OutboxWorker(outbox, client, machine, lease),
    }


def _cloud_runtime(refresh=False):
    """The cached sync runtime; `refresh` rebuilds it after a config write."""
    global _CLOUD_RUNTIME
    with _CLOUD_RUNTIME_LOCK:
        if refresh or _CLOUD_RUNTIME is None:
            _CLOUD_RUNTIME = _cloud_build_runtime()
        return _CLOUD_RUNTIME


def cloud_link_state(configured, state_value, read_only):
    """One word for the whole connection, in the priority §11 asks for."""
    if not configured:
        return "unconfigured"
    if state_value is None:
        return "error"
    if read_only or state_value == "read_only":
        return "read_only"
    if state_value in ("disabled", "offline", "auth_required",
                       "not_enrolled", "conflict"):
        return state_value
    return "connected"


def _cloud_lease_view(lease):
    """The 7-day lease as the operator needs to see it (spec §5).

    `granted` separates "has never signed in" from "signed in more than
    seven days ago": only the second is the read-only state §11 names.
    """
    if lease is None:
        return {"granted": False, "expired": False, "seconds_left": 0}
    granted = getattr(lease, "granted_at", None) is not None
    expired = bool(granted and lease.is_expired())
    remaining = 0
    if granted:
        try:
            remaining = max(0, int(lease.remaining()))
        except (TypeError, ValueError):
            remaining = 0
    return {"granted": granted, "expired": expired, "seconds_left": remaining}


def _cloud_counts(machine, outbox):
    """Pending and conflict counts (spec §9). The outbox is the truth for
    the queue; the machine's own counters answer when it will not load."""
    pending = int(getattr(machine, "pending_changes", 0) or 0)
    conflicts = int(getattr(machine, "conflict_count", 0) or 0)
    if outbox is None:
        return pending, conflicts
    try:
        p_val = getattr(outbox, "pending_count", 0)
        pending = int(p_val() if callable(p_val) else p_val)
        c_val = getattr(outbox, "conflict_count", 0)
        conflicts = max(conflicts, int(c_val() if callable(c_val) else c_val))
    except (OSError, ValueError, TypeError):
        pass
    return pending, conflicts


def _cloud_actor(client):
    """The host user shown where the panel shows `__ACTOR__`, else None.

    RAM only (spec §5): once the user access token is gone from memory the
    chip empties, because there is no longer a live session behind it.
    """
    if not _CLOUD_ACTOR:
        return None
    vault = getattr(client, "vault", None)
    if vault is not None and getattr(vault, "user_access_token", None) is None:
        return None
    return _CLOUD_ACTOR


def _cloud_status_shell(**overrides):
    """Every key /cloud-status can return, so the shape never changes."""
    payload = {
        "ok": True,
        "configured": False,
        "link": "unconfigured",
        "state": "",
        "read_only": False,
        "lease": {"granted": False, "expired": False, "seconds_left": 0},
        "api_base": "",
        "tenant_id": "",
        "device_enrolled": False,
        "device_id": "",
        "last_sync": None,
        "pending": 0,
        "conflicts": 0,
        "error_code": None,
        "error_message": None,
        "actor": None,
        "must_change_password": False,
        "worker": "stopped",
        "worker_last": None,
        "role": None,
        "can_import": False,
    }
    payload.update(overrides)
    return payload


def cloud_status_payload(runtime=None):
    """GET /cloud-status: one JSON snapshot for the settings surface (§11).

    Strictly a read — no network, no state-machine event. Every value is a
    stable code, a count, a timestamp, a boolean or the non-secret
    transport configuration: never a token, never a server sentence.
    """
    from cloud_sync.errors import CloudSyncError
    if runtime is None:
        try:
            runtime = _cloud_runtime()
        except CloudSyncError as exc:
            code = exc.code
            return _cloud_status_shell(link="error", error_code=code,
                                       error_message=cloud_error_message(code),
                                       worker_last=_cloud_beat_view())
        except (OSError, ValueError):
            return _cloud_status_shell(
                link="error", error_code="CONFIG_INVALID",
                error_message=cloud_error_message("CONFIG_INVALID"),
                worker_last=_cloud_beat_view())
    config = runtime.get("config")
    machine = runtime.get("machine")
    outbox = runtime.get("outbox")
    client = runtime.get("client")
    configured = bool(getattr(config, "api_base", None))
    lease_view = _cloud_lease_view(runtime.get("lease"))
    state_value = getattr(getattr(machine, "state", None), "value", None)
    read_only = lease_view["expired"] or state_value == "read_only"
    pending, conflicts = _cloud_counts(machine, outbox)
    error_code = getattr(machine, "last_error_code", None)
    if cloud_error_message(error_code) is None:
        error_code = None
    thread = _CLOUD_WORKER_THREAD
    actor = _cloud_actor(client)
    role = _CLOUD_ROLE if actor else None
    can_import = bool(
        getattr(config, "sync_device_id", None)
        and role == "admin"
        and (getattr(config, "cursor", 0) == 0
             or getattr(machine, "last_successful_sync", None) is None)
    )
    return _cloud_status_shell(
        configured=configured,
        link=cloud_link_state(configured, state_value, read_only),
        state=state_value or "",
        read_only=read_only,
        lease=lease_view,
        api_base=(getattr(config, "api_base", "") or ""),
        tenant_id=(getattr(config, "tenant_id", "") or ""),
        device_enrolled=bool(getattr(config, "sync_device_id", None)),
        device_id=(getattr(config, "sync_device_id", "") or ""),
        last_sync=getattr(machine, "last_successful_sync", None),
        pending=pending,
        conflicts=conflicts,
        error_code=error_code,
        error_message=cloud_error_message(error_code),
        actor=actor,
        must_change_password=bool(_CLOUD_MUST_CHANGE),
        worker=("running" if thread is not None and thread.is_alive()
                else "stopped"),
        worker_last=_cloud_beat_view(),
        role=role,
        can_import=can_import,
    )


def _cloud_save_machine(runtime):
    """Persist a transition so the next start resumes from it.

    An OSError is deliberately NOT caught: at a route the guard turns it
    into CONFIG_INVALID, and in the worker the loop records it. Losing a
    transition silently is what cloud_sync/state.py warns about.
    """
    machine = runtime.get("machine")
    if machine is not None:
        machine.save()


def _cloud_actor_name(payload, fallback):
    """The host username to render where the panel renders `__ACTOR__`.

    Prefers the server's own `user.username`; falls back to what the
    operator typed. Printable characters only, capped at 64, so a hostile
    or careless server cannot push markup or a paragraph into the chip.
    """
    candidate = None
    if isinstance(payload, dict):
        user = payload.get("user")
        if isinstance(user, dict):
            candidate = user.get("username")
    if not isinstance(candidate, str) or not candidate.strip():
        candidate = fallback
    candidate = "".join(ch for ch in str(candidate)
                        if ch.isprintable()).strip()
    return candidate[:64]


def cloud_save_config(payload):
    """Persist the transport settings and (re)start the worker (spec §5).

    Validation stays in cloud_sync.config — the rules that refuse a
    non-HTTPS base off-loopback are the client's, and duplicating them here
    is how the two would drift.
    """
    from cloud_sync.config import CloudConfig, load_config
    if not isinstance(payload, dict):
        raise ValueError("cloud config body must be an object")
    api_base = str(payload.get("api_base") or "").strip()
    tenant_id = str(payload.get("tenant_id") or "").strip()
    if not api_base:
        raise ValueError("cloud config requires an api_base")
    current = load_config().to_dict()
    current["api_base"] = api_base
    current["tenant_id"] = tenant_id or None
    # from_dict re-runs every validation on the assembled record, and keeps
    # the device id, installation id and cursor that are already on disk.
    CloudConfig.from_dict(current).save()
    cloud_worker_start()
    return cloud_status_payload(_cloud_runtime(refresh=True)), 200


def _cloud_apply_login_event(runtime):
    """Fire exactly ONE event for a successful login (manager ruling 12).

    The choice is exhaustive over the state set, so the event is legal from
    every state; a race with the worker can still refuse it, and that
    refusal propagates to the route, which reports it by name instead of
    letting the panel's generic handler swallow it.
    """
    from cloud_sync.state import SyncEvent, SyncState
    machine = runtime["machine"]
    if machine is None:
        return
    state = machine.state
    if state is SyncState.NOT_ENROLLED:
        event = SyncEvent.ENROL
    elif state is SyncState.DISABLED:
        event = SyncEvent.ENABLE
    else:
        event = SyncEvent.AUTH_OK
    machine.apply(event)
    _cloud_save_machine(runtime)


def cloud_login(username, password):
    """Sign in to the host (spec §5, §11). Raises; the route maps faults.

    The password goes to ``/auth/login`` and nowhere else — never stored,
    never logged, never echoed back. On success the panel keeps only what
    §5 allows in RAM (the user tokens) plus the username it must show.
    """
    global _CLOUD_ACTOR, _CLOUD_MUST_CHANGE, _CLOUD_ROLE
    username = str(username or "").strip()
    password = str(password or "")
    if not username or not password:
        # Surfaced by the route as BAD_PAYLOAD from the Persian table.
        raise ValueError("cloud login requires a username and a password")
    runtime = _cloud_runtime()
    client = runtime["client"]
    payload = client.login(username, password)
    # A completed authentication renews the 7-day offline lease (spec §5).
    runtime["lease"].grant()
    _CLOUD_ACTOR = _cloud_actor_name(payload, username)
    _CLOUD_MUST_CHANGE = bool(payload.get("must_change_password"))
    user_info = payload.get("user") if isinstance(payload, dict) else None
    _CLOUD_ROLE = user_info.get("role") if isinstance(user_info, dict) else None
    if (not runtime["config"].sync_device_id
            or not client.vault.has_device_credentials):
        # A stale device id is not proof that this PC can authenticate. If
        # refresh rejection removed the protected credential, a successful
        # user login self-enrols a replacement machine identity explicitly.
        client.enroll()
    _cloud_apply_login_event(runtime)
    cloud_worker_start()
    cloud_worker_kick()
    try:
        cloud_worker_beat()
    except Exception:
        pass
    return {"ok": True, "actor": _CLOUD_ACTOR,
            "must_change_password": _CLOUD_MUST_CHANGE,
            "enrolled": bool(runtime["config"].sync_device_id)}, 200


def cloud_logout():
    """Sign out of the host. Local data, queue and state stay untouched —
    spec §11's disconnect must never cost the operator a saved edit."""
    global _CLOUD_ACTOR, _CLOUD_MUST_CHANGE, _CLOUD_ROLE
    from cloud_sync.errors import CloudSyncError
    runtime = _cloud_runtime()
    client = runtime["client"]
    try:
        client.logout()
    except CloudSyncError as exc:
        # A session that is already dead is signed out as far as this panel
        # is concerned; anything else (network, server) is the operator's.
        if exc.code not in _CLOUD_AUTH_CODES:
            raise
    finally:
        vault = getattr(client, "vault", None)
        clear = getattr(vault, "clear_user", None)
        if callable(clear):
            clear()
        _CLOUD_ACTOR = None
        _CLOUD_MUST_CHANGE = False
        _CLOUD_ROLE = None
    return {"ok": True, "actor": None, "must_change_password": False}, 200


def cloud_sync_now():
    """Wake the worker immediately so "my edit was sent" is visible rather
    than assumed (spec §9). Never runs a batch on the request thread."""
    if not _cloud_configured():
        return cloud_error_body("CONFIG_INVALID", 409)
    thread = cloud_worker_start()
    cloud_worker_kick()
    try:
        cloud_worker_beat()
    except Exception:
        pass
    return {"ok": True, "queued": True,
            "worker": "running" if thread is not None else "stopped"}, 200


def _cloud_configured():
    """Whether a base URL exists. A predicate, so it must never raise: an
    unreadable or malformed config counts as unconfigured and therefore as
    a closed door to the network (fail closed, not open)."""
    try:
        from cloud_sync.config import load_config
        return bool(load_config().api_base)
    except Exception:
        return False


def _cloud_note_beat(**fields):
    """Record one worker beat for /cloud-status (spec §9 observability)."""
    global _CLOUD_LAST_BEAT
    entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    entry.update(fields)
    _CLOUD_LAST_BEAT = entry
    return entry


def _cloud_beat_view():
    """The last worker beat with its Persian sentence already attached.

    Built here so there is exactly one place that turns a code into words
    (spec §11): the page never keeps its own copy of the table.
    """
    if not _CLOUD_LAST_BEAT:
        return None
    view = dict(_CLOUD_LAST_BEAT)
    view["message"] = (CLOUD_BEAT_WORDS.get(view.get("skipped"))
                       or cloud_error_message(view.get("code")))
    return view


def _cloud_stop_for_lease(runtime):
    """An expired lease stops network sync entirely (manager ruling 11).

    Fires LEASE_EXPIRED exactly once — never while the machine is already
    READ_ONLY — and never reaches the socket.
    """
    from cloud_sync.state import IllegalTransitionError, SyncEvent, SyncState
    machine = runtime["machine"]
    if machine is not None and machine.state is not SyncState.READ_ONLY:
        try:
            machine.apply(SyncEvent.LEASE_EXPIRED)
        except IllegalTransitionError:
            # DISABLED has no LEASE_EXPIRED edge: recorded, not swallowed.
            return _cloud_note_beat(code="TRANSITION_NOT_LEGAL")
        _cloud_save_machine(runtime)
    return _cloud_note_beat(code="LEASE_EXPIRED")


def cloud_worker_beat():
    """One synchronous outbox beat (spec §9). Returns a JSON-safe note.

    Never raises. The two state-machine faults are caught BY NAME here and
    again in the loop (manager ruling 12): a transition landing in one of
    panel.py's generic handlers is precisely the silent drift spec §15.12
    exists to prevent.
    """
    from cloud_sync.errors import CloudSyncError
    from cloud_sync.lease import LeaseExpiredError
    from cloud_sync.state import IllegalTransitionError
    try:
        if os.environ.get("IRICA_CLOUD_WORKER_OFF") == "1":
            return _cloud_note_beat(skipped="disabled")
        runtime = _cloud_runtime()
        if not runtime["config"].api_base:
            # Nothing reaches the network before the operator configured a
            # base URL (spec §11 "not configured").
            return _cloud_note_beat(skipped="not_configured")
        lease = runtime["lease"]
        if lease.granted_at is None:
            # Never authenticated: this is "not connected", NOT the 7-day
            # read-only state, so no LEASE_EXPIRED event is owed (spec §5).
            return _cloud_note_beat(skipped="awaiting_login")
        if lease.is_expired():
            return _cloud_stop_for_lease(runtime)
        # A fresh/legacy client must materialize server authority before
        # the outbox is allowed to send its first mutation. This also repairs
        # old configs that had a cursor but pre-date dataset_epoch tracking.
        pull_result = None
        if (getattr(runtime["config"], "sync_device_id", None)
                and getattr(runtime["config"], "dataset_epoch", None) is None):
            try:
                pull_result = cloud_pull_step(runtime)
            except CloudSyncError as exc:
                return _cloud_note_beat(code=exc.code)
            if pull_result.get("skipped"):
                return _cloud_note_beat(skipped=pull_result.get("skipped"))

        worker = runtime["worker"]
        previous = worker.bind_auth()
        try:
            outcome = worker.run_once()
        finally:
            worker.unbind_auth(previous)
        _cloud_save_machine(runtime)

        if (pull_result is None
                and getattr(runtime["config"], "sync_device_id", None)
                and hasattr(runtime.get("client"), "pull_all")
                and not lease.is_expired()
                and getattr(outcome, "code", None) not in _CLOUD_AUTH_CODES
                and getattr(outcome, "terminal", None) not in ("auth_failed", "lease_expired")):
            try:
                pull_result = cloud_pull_step(runtime)
            except (LeaseExpiredError, IllegalTransitionError):
                raise
            except CloudSyncError as exc:
                if exc.code in _CLOUD_AUTH_CODES:
                    return _cloud_note_beat(code=exc.code)
                return _cloud_note_beat(code=exc.code)

        skipped = pull_result.get("skipped") if (pull_result and not getattr(outcome, "attempted", False) and not getattr(outcome, "code", None)) else None
        return _cloud_note_beat(
            attempted=bool(getattr(outcome, "attempted", False)),
            applied=int(getattr(outcome, "applied", 0) or 0),
            conflicts=int(getattr(outcome, "conflicts", 0) or 0),
            code=getattr(outcome, "code", None),
            terminal=getattr(outcome, "terminal", None),
            skipped=skipped,
            pulled=(pull_result.get("pulled", 0) if pull_result else 0))
    except LeaseExpiredError:
        return _cloud_note_beat(code="LEASE_EXPIRED")
    except IllegalTransitionError:
        return _cloud_note_beat(code="TRANSITION_NOT_LEGAL")


_CLOUD_WORKER_INTERVAL = 15.0
_CLOUD_WORKER_THREAD = None
_CLOUD_WORKER_CV = threading.Condition()
_CLOUD_WORKER_STOP = False
_CLOUD_WORKER_KICK = False


def _cloud_worker_interval_resolved():
    """Return worker poll interval in seconds: 2.0s for online real-time sync, 15.0s for local."""
    try:
        import crm as crm_mod
        settings = (crm_mod._store_read().get("settings") or {})
        mode = str(settings.get("database_mode") or "online").strip().lower()
        if mode == "local":
            return 15.0
        return 2.0
    except Exception:
        return 2.0


def _cloud_worker_loop():
    """The sync beat: bounded interval, daemon, never a tight loop.

    Same shape as _crm_scheduler_loop: a fault becomes an observable note
    and the loop lives on. The two machine faults are caught BY NAME
    before the generic backstop, and no message text is ever recorded.
    """
    from cloud_sync.lease import LeaseExpiredError
    from cloud_sync.state import IllegalTransitionError
    global _CLOUD_WORKER_KICK
    while True:
        with _CLOUD_WORKER_CV:
            if not (_CLOUD_WORKER_STOP or _CLOUD_WORKER_KICK):
                # One bounded wait; a kick or a stop notifies and returns
                # early, a timeout returns after resolved interval (2.0s in online mode).
                _CLOUD_WORKER_CV.wait(_cloud_worker_interval_resolved())
            if _CLOUD_WORKER_STOP:
                return
            _CLOUD_WORKER_KICK = False
        try:
            cloud_worker_beat()
        except IllegalTransitionError:
            _cloud_note_beat(code="TRANSITION_NOT_LEGAL")
        except LeaseExpiredError:
            _cloud_note_beat(code="LEASE_EXPIRED")
        except Exception:
            # Never raise into the panel. Only a stable code is recorded —
            # never the exception text (spec §5: no free text, no data).
            _cloud_note_beat(code="SERVER_ERROR", fault="UNEXPECTED")


def cloud_worker_start():
    """Start the beat thread, or None when it is off or unconfigured.

    Started from main() like crm_scheduler_start(), and again by the config
    route: nothing runs before a base URL exists (spec §9, §11).
    """
    global _CLOUD_WORKER_THREAD, _CLOUD_WORKER_STOP, _CLOUD_WORKER_KICK
    if os.environ.get("IRICA_CLOUD_WORKER_OFF") == "1":
        return None
    if _CLOUD_WORKER_THREAD is not None and _CLOUD_WORKER_THREAD.is_alive():
        return _CLOUD_WORKER_THREAD
    if not _cloud_configured():
        return None
    with _CLOUD_WORKER_CV:
        _CLOUD_WORKER_STOP = False
        _CLOUD_WORKER_KICK = False
        thread = threading.Thread(target=_cloud_worker_loop,
                                  name="cloud-sync", daemon=True)
        _CLOUD_WORKER_THREAD = thread
    thread.start()
    return thread


def cloud_worker_stop():
    """Ask the beat to end. Returns the thread so a caller can join it."""
    global _CLOUD_WORKER_STOP, _CLOUD_WORKER_KICK
    with _CLOUD_WORKER_CV:
        _CLOUD_WORKER_STOP = True
        _CLOUD_WORKER_KICK = False
        _CLOUD_WORKER_CV.notify_all()
    return _CLOUD_WORKER_THREAD


def cloud_worker_kick():
    """Ask for one beat now, without blocking the request that asked."""
    global _CLOUD_WORKER_KICK
    with _CLOUD_WORKER_CV:
        _CLOUD_WORKER_KICK = True
        _CLOUD_WORKER_CV.notify_all()


def _cloud_presence_target(entity, local_id, runtime):
    """Map one local CRM id to the server UUID used by record_presence."""
    from cloud_sync import mapper
    entity = str(entity or "").strip()
    local_id = str(local_id or "").strip()
    canon = "crm_devices" if entity in ("device", "devices", "crm_devices") else entity
    allowed = {"crm_devices", "customers", "owners", "identities", "periods"}
    if canon not in allowed or not local_id:
        raise ValueError("invalid presence target")
    install = getattr(runtime.get("config"), "source_installation_id", None)
    if not install:
        raise ValueError("presence requires source installation id")
    return canon, mapper.legacy_to_uuid(install, canon, local_id)


def cloud_presence_heartbeat(payload):
    if not isinstance(payload, dict):
        raise ValueError("presence body must be an object")
    runtime = _cloud_runtime()
    entity, entity_id = _cloud_presence_target(
        payload.get("entity"), payload.get("entity_id"), runtime)
    lease_id = str(payload.get("lease_id") or "").strip() or None
    return runtime["client"].presence_heartbeat(entity, entity_id, lease_id), 200


def cloud_presence_close(payload):
    if not isinstance(payload, dict):
        raise ValueError("presence close body must be an object")
    lease_id = str(payload.get("lease_id") or "").strip()
    if not lease_id:
        raise ValueError("presence close requires lease_id")
    runtime = _cloud_runtime()
    return runtime["client"].presence_close(lease_id), 200


def _cloud_route_guard(action, *args):
    """Run one cloud POST action at the route boundary (spec §15.12).

    `IllegalTransitionError` and `LeaseExpiredError` are caught BY NAME and
    turned into a coded Persian answer. panel.py already has dozens of
    generic `except Exception` sites; a machine event landing in one of
    them would vanish without a trace, which is exactly what ruling 12
    forbids.
    """
    from cloud_sync.errors import CloudSyncError
    from cloud_sync.lease import LeaseExpiredError
    from cloud_sync.state import IllegalTransitionError
    try:
        return action(*args)
    except IllegalTransitionError:
        return cloud_error_body("TRANSITION_NOT_LEGAL", 409)
    except LeaseExpiredError:
        return cloud_error_body("LEASE_EXPIRED", 409)
    except CloudSyncError as exc:
        return cloud_error_body(
            exc.code, 401 if exc.code in _CLOUD_AUTH_CODES else 400)
    except (TypeError, ValueError):
        return cloud_error_body("BAD_PAYLOAD", 400)
    except OSError:
        return cloud_error_body("CONFIG_INVALID", 500)


def _cloud_versions_path():
    return os.path.join(app_paths.data_subdir("cloud_sync"),
                        "cloud_sync_versions.json")


def _load_cloud_versions(path=None):
    if path is None:
        path = _cloud_versions_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    versions = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if ":" in k and isinstance(v, int):
                entity, _, cid = k.partition(":")
                versions[(entity, cid)] = v
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) == 3:
                e, cid, v = item
                if isinstance(v, int):
                    versions[(str(e), str(cid))] = v
    return versions


def _save_cloud_versions(versions, path=None):
    if path is None:
        path = _cloud_versions_path()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    serialized = {f"{e}:{cid}": v for (e, cid), v in versions.items()
                  if isinstance(v, int)}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(serialized, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class _DirtySet(set):
    """Holds (entity, id) pairs and bare ids for tests, but iterates only pairs for apply.py."""
    def __iter__(self):
        for item in set.__iter__(self):
            if isinstance(item, tuple) and len(item) == 2:
                yield item


def _cloud_dirty_set(outbox):
    dirty = _DirtySet()
    if outbox is None:
        return dirty
    entries_fn = getattr(outbox, "entries", None)
    if not callable(entries_fn):
        return dirty
    try:
        entries = entries_fn()
    except Exception:
        return dirty
    for e in entries:
        op = getattr(e, "operation", None) or {}
        entity = op.get("entity")
        oid = op.get("id")
        if entity and oid:
            dirty.add((entity, oid))
            dirty.add(oid)
        conf = getattr(e, "conflict", None) or {}
        centity = conf.get("entity")
        cid = conf.get("id")
        if centity and cid:
            dirty.add((centity, cid))
            dirty.add(cid)
    return dirty


def _cloud_enqueue_mutation(entity, legacy_id, record=None, kind="upsert", transport=None):
    """Enqueue a local CRM mutation into the cloud outbox (spec §9).

    Never raises: offline or unconfigured states leave local operations untouched.
    """
    if not _cloud_configured():
        return
    try:
        from cloud_sync.config import load_config
        from cloud_sync import ids as _ids, mapper
        config = load_config()
        inst = getattr(config, "source_installation_id", None)
        if not inst:
            return

        canon = "crm_devices" if entity in ("device", "devices", "crm_devices") else \
                "customers" if entity in ("customer", "customers") else \
                "owners" if entity in ("owner", "owners") else \
                "identities" if entity in ("identity", "identities") else \
                "periods" if entity in ("period", "periods") else \
                "settings" if entity == "settings" else \
                "customer_transactions" if entity == "customer_transactions" else entity

        cloud_id = mapper.legacy_to_uuid(inst, canon, str(legacy_id)) if legacy_id else None
        if canon == "settings":
            cloud_id = mapper.legacy_to_uuid(inst, "settings", mapper.SETTINGS_LEGACY_KEY)
        elif canon == "customer_transactions" and isinstance(record, dict) and "id" in record:
            cloud_id = record["id"]

        runtime = _cloud_runtime()
        outbox = runtime.get("outbox")
        if outbox is None:
            return

        versions = _load_cloud_versions()
        base_ver = versions.get((canon, cloud_id), 0)

        wire_record = None
        if kind == "upsert" and record is not None:
            clean_rec = record
            if canon == "settings" and isinstance(record, dict) and "database_mode" in record:
                clean_rec = {k: v for k, v in record.items() if k != "database_mode"}
            wire_record = mapper.to_row(canon, clean_rec, source_installation_id=inst)
            if canon == "customer_transactions":
                cloud_id = wire_record["id"]

        op = {
            "kind": kind,
            "entity": canon,
            "id": cloud_id,
            "base_version": base_ver,
            "record": wire_record,
        }
        if transport:
            op["transport"] = str(transport)
        outbox.enqueue(op)
        cloud_worker_kick()
    except Exception:
        pass


def cloud_pull_step(runtime=None):
    """Run one pull cycle: bootstrap snapshot if cursor == 0, else pull_all.

    Dirty local records are never clobbered (spec §9). Versions are persisted
    to cloud_sync_versions.json. State machine exceptions (LeaseExpiredError,
    IllegalTransitionError) are never swallowed.
    """
    from cloud_sync import apply
    from cloud_sync.apply import FileStore
    from cloud_sync.errors import RemoteNotReadyError
    from cloud_sync.lease import LeaseExpiredError

    if runtime is None:
        runtime = _cloud_runtime()
    config = runtime["config"]
    client = runtime["client"]
    lease = runtime["lease"]
    outbox = runtime["outbox"]

    if not getattr(config, "api_base", None) or not getattr(config, "sync_device_id", None):
        return {"pulled": 0, "skipped": "not_enrolled"}
    if lease and lease.is_expired():
        raise LeaseExpiredError()

    import crm as crm_mod
    store = FileStore(crm_mod._store_path())
    versions_path = _cloud_versions_path()
    versions = _load_cloud_versions(versions_path)
    dirty = _cloud_dirty_set(outbox)
    source_installation_id = getattr(config, "source_installation_id", None)

    pulled_pages = 0
    with crm_mod.STORE_LOCK:
        if getattr(config, "dataset_epoch", None) is None:
            snapshot = client.bootstrap()
            try:
                apply.apply_snapshot(
                    snapshot,
                    store=store,
                    source_installation_id=source_installation_id,
                    versions=versions,
                    dirty=dirty,
                )
            except RemoteNotReadyError:
                return {"pulled": 0, "skipped": "remote_not_ready"}
            # Cross-file commit order is deliberate: local CRM bytes first
            # (inside apply_snapshot), then row versions, and only then the
            # cursor/epoch marker. A crash can cause a harmless re-bootstrap,
            # but can never make a restart skip an unapplied snapshot.
            _save_cloud_versions(versions, versions_path)
            client.commit_bootstrap(snapshot)
            pulled_pages = 1
        else:
            def _handler(page):
                apply.apply_changes(
                    page,
                    store=store,
                    source_installation_id=source_installation_id,
                    versions=versions,
                    dirty=dirty,
                )
                _save_cloud_versions(versions, versions_path)

            pulled_pages = client.pull_all(_handler)

    return {"pulled": pulled_pages}


def cloud_conflicts_payload(runtime=None):
    """GET /cloud-conflicts: list of parked conflicts for the operator (spec §11)."""
    if runtime is None:
        try:
            runtime = _cloud_runtime()
        except Exception:
            return {"ok": True, "conflicts": []}
    outbox = runtime.get("outbox")
    if outbox is None:
        return {"ok": True, "conflicts": []}
    entries_fn = getattr(outbox, "conflicts", None)
    if not callable(entries_fn):
        return {"ok": True, "conflicts": []}
    try:
        conflicts_list = entries_fn()
    except Exception:
        return {"ok": True, "conflicts": []}
    out = []
    for e in conflicts_list:
        op = getattr(e, "operation", None) if isinstance(getattr(e, "operation", None), dict) else {}
        conf = getattr(e, "conflict", None) if isinstance(getattr(e, "conflict", None), dict) else {}
        out.append({
            "operation_id": getattr(e, "operation_id", ""),
            "entity": op.get("entity") or conf.get("entity") or "",
            "id": op.get("id") or conf.get("id") or "",
            "local_record": op.get("record"),
            "server_record": conf.get("server_record"),
            "server_version": conf.get("server_version"),
        })
    return {"ok": True, "conflicts": out}


def _apply_conflict_server_record(runtime, entity, record_id, server_record,
                                  server_version=None, operation_id=None):
    """Apply the accepted server record to crm_store.json under STORE_LOCK."""
    from cloud_sync import mapper
    import crm as crm_mod
    config = runtime.get("config")
    source_installation_id = getattr(config, "source_installation_id", None)
    with crm_mod.STORE_LOCK:
        doc = crm_mod._store_read()
        if not isinstance(doc, dict):
            doc = {}

        if server_record is None:
            # Server deleted the record
            if entity == "settings":
                # Settings row is never deleted wholesale; preserve local-only settings
                pass
            elif entity == "customer_transactions":
                parts = str(record_id).split("/", 1)
                if len(parts) == 2:
                    cust_id, seq_str = parts
                    try:
                        seq = int(seq_str)
                        for c in doc.get("customers", []):
                            if c.get("id") == cust_id and "transactions" in c:
                                if 0 <= seq < len(c["transactions"]):
                                    c["transactions"].pop(seq)
                    except ValueError:
                        pass
            else:
                store_key = "devices" if entity in ("devices", "crm_devices") else entity
                if store_key in doc and isinstance(doc[store_key], list):
                    doc[store_key] = [r for r in doc[store_key] if r.get("id") != record_id]
        else:
            index = {}
            if source_installation_id:
                try:
                    index = mapper.reference_index(doc, source_installation_id=source_installation_id)
                except Exception:
                    pass
            rec = None
            if isinstance(server_record, dict):
                # from_row resolves foreign keys from UUID back to legacy 8-hex ids.
                # If unresolved, do not fall back to raw UUIDs (avoids leaking UUIDs into local store).
                try:
                    rec = mapper.from_row(entity, server_record, reference_index=index)
                except Exception:
                    rec = None
            else:
                rec = server_record

            if rec is None:
                # Could not resolve foreign keys safely; do not corrupt local store
                return

            if entity == "settings":
                if isinstance(rec, dict):
                    # Only update allowlisted fields, preserving local-only secrets/paths
                    for k, v in rec.items():
                        if k in mapper.SETTINGS_ALLOWLIST:
                            doc.setdefault("settings", {})[k] = v
            elif entity == "customer_transactions":
                if isinstance(rec, dict):
                    cust_ref = rec.get("customer_id") or (str(record_id).split("/", 1)[0] if "/" in str(record_id) else None)
                    seq = rec.get("seq")
                    if seq is None and "/" in str(record_id):
                        try:
                            seq = int(str(record_id).split("/", 1)[1])
                        except ValueError:
                            seq = None
                    for c in doc.get("customers", []):
                        if c.get("id") == cust_ref:
                            txs = c.setdefault("transactions", [])
                            if seq is not None and isinstance(seq, int) and 0 <= seq < len(txs):
                                txs[seq] = rec
                            else:
                                txs.append(rec)
            else:
                store_key = "devices" if entity in ("devices", "crm_devices") else entity
                rows = doc.setdefault(store_key, [])
                replaced = False
                target_id = rec.get("id") if isinstance(rec, dict) else record_id
                for idx, existing in enumerate(rows):
                    if existing.get("id") in (target_id, record_id):
                        if entity == "customers" and isinstance(rec, dict) and "transactions" not in rec:
                            rec["transactions"] = existing.get("transactions", [])
                        rows[idx] = rec
                        replaced = True
                        break
                if not replaced and isinstance(rec, dict):
                    rows.append(rec)

        crm_mod._store_write(doc)

        if server_version is not None and entity:
            versions_path = _cloud_versions_path()
            versions = _load_cloud_versions(versions_path)
            cloud_id = operation_id or record_id
            versions[(entity, cloud_id)] = server_version
            if record_id:
                versions[(entity, record_id)] = server_version
            _save_cloud_versions(versions, versions_path)


def cloud_resolve_conflict(payload):
    """POST /cloud-resolve-conflict: operator chooses keep_local or accept_server."""
    from cloud_sync.lease import LeaseExpiredError
    from cloud_sync.state import SyncEvent

    if not isinstance(payload, dict):
        return cloud_error_body("BAD_PAYLOAD", 400)
    operation_id = str(payload.get("operation_id") or "").strip()
    resolution = str(payload.get("resolution") or "").strip()
    if not operation_id or resolution not in ("keep_local", "accept_server"):
        return cloud_error_body("BAD_PAYLOAD", 400)

    runtime = _cloud_runtime()
    lease = runtime.get("lease")
    if lease and lease.is_expired():
        raise LeaseExpiredError()

    outbox = runtime.get("outbox")
    if outbox is None:
        return cloud_error_body("CONFIG_INVALID", 500)

    entry = outbox.get(operation_id)
    if entry is None:
        return cloud_error_body("HTTP_404", 404)
    if getattr(entry, "parked", None) != "conflict":
        return cloud_error_body("TRANSITION_NOT_LEGAL", 409)

    conflict = getattr(entry, "conflict", None) or {}
    machine = runtime.get("machine")

    if resolution == "keep_local":
        server_version = conflict.get("server_version")
        if entry.operation is not None and server_version is not None:
            entry.operation["base_version"] = server_version
        new_op_id = str(uuid.uuid4())
        outbox.release(operation_id, new_operation_id=new_op_id)
        if machine is not None and getattr(machine, "conflict_count", 0) > 0:
            if machine.can(SyncEvent.CONFLICTS_RESOLVED):
                machine.apply(SyncEvent.CONFLICTS_RESOLVED, conflicts_cleared=1)
                _cloud_save_machine(runtime)
        cloud_worker_kick()
        return {"ok": True, "resolved": "keep_local"}, 200

    if resolution == "accept_server":
        server_record = conflict.get("server_record")
        entity = (entry.operation or {}).get("entity") or conflict.get("entity")
        record_id = (entry.operation or {}).get("id") or conflict.get("id")
        server_version = conflict.get("server_version")

        _apply_conflict_server_record(
            runtime=runtime,
            entity=entity,
            record_id=record_id,
            server_record=server_record,
            server_version=server_version,
            operation_id=operation_id,
        )
        outbox.mark_done(operation_id, result="conflict_server_accepted")
        if machine is not None and getattr(machine, "conflict_count", 0) > 0:
            if machine.can(SyncEvent.CONFLICTS_RESOLVED):
                machine.apply(SyncEvent.CONFLICTS_RESOLVED, conflicts_cleared=1)
                _cloud_save_machine(runtime)
        return {"ok": True, "resolved": "accept_server"}, 200


def cloud_run_import():
    """POST /cloud-import: one-shot bootstrap import (spec §8), admin only."""
    from cloud_sync import importer
    from cloud_sync.lease import LeaseExpiredError

    runtime = _cloud_runtime()
    client = runtime["client"]
    config = runtime["config"]
    lease = runtime["lease"]

    if lease and lease.is_expired():
        raise LeaseExpiredError()

    vault = getattr(client, "vault", None)
    user_token = getattr(vault, "user_access_token", None) if vault else None
    if not _CLOUD_ACTOR or not user_token:
        return cloud_error_body("AUTH_REQUIRED", 401)

    if _CLOUD_ROLE != "admin":
        return cloud_error_body("HTTP_403", 403)

    if not getattr(config, "sync_device_id", None):
        return cloud_error_body("ENROL_REQUIRED", 400)

    send = getattr(client, "import_document", None)
    if not callable(send):
        return cloud_error_body("CONFIG_INVALID", 500)

    import crm as crm_mod
    backup_dir = app_paths.data_subdir("backups")

    result = importer.run_import(
        crm_mod._store_read,
        send=send,
        source_installation_id=config.source_installation_id,
        backup_dir=backup_dir,
    )

    if not result.ok:
        code = result.code or "IMPORT_REJECTED"
        if code == importer.DATASET_NOT_EMPTY:
            # Smart Data Merge:
            # The cloud server already holds business rows (from an earlier import or another user).
            # Instead of failing with 409 DATASET_NOT_EMPTY, enqueue local records into
            # the cloud outbox as upserts, kick the sync worker, and pull server data.
            local_data = crm_mod._store_read()
            merged_count = 0

            for ent_name, ent_canon, id_key in [
                ("customers", "customers", "id"),
                ("owners", "owners", "id"),
                ("identities", "identities", "id"),
                ("devices", "crm_devices", "id"),
                ("periods", "periods", "id"),
            ]:
                items = local_data.get(ent_name) or []
                for item in items:
                    if isinstance(item, dict) and item.get(id_key):
                        _cloud_enqueue_mutation(ent_canon, str(item[id_key]), item, kind="upsert")
                        merged_count += 1

            for cust in local_data.get("customers") or []:
                if isinstance(cust, dict):
                    cid = cust.get("id")
                    for seq, tx in enumerate(cust.get("transactions") or [], start=1):
                        tx_rec = dict(tx)
                        tx_rec["customer_id"] = cid
                        tx_rec["seq"] = seq
                        _cloud_enqueue_mutation("customer_transactions", f"{cid}/{seq}", tx_rec, kind="upsert")
                        merged_count += 1

            if local_data.get("settings"):
                _cloud_enqueue_mutation("settings", "settings/settings", local_data["settings"], kind="upsert")
                merged_count += 1

            cloud_worker_kick()
            try:
                cloud_pull_step(runtime)
            except Exception:
                pass
            cloud_worker_beat()

            return {
                "ok": True,
                "merged": True,
                "count": merged_count,
                "rows": merged_count,
                "message": "اطلاعات محلی با موفقیت با داده‌های سرور ادغام و همگام‌سازی شد.",
                "imported": True
            }, 200

        status = 409 if code in (importer.DATASET_NOT_EMPTY, importer.IMPORT_CONFLICT) else 400
        return cloud_error_body(code, status)

    if result.cursor:
        set_cursor = getattr(config, "set_cursor", None)
        if callable(set_cursor):
            set_cursor(result.cursor)
        elif hasattr(config, "cursor"):
            config.cursor = result.cursor
        if result.dataset_epoch:
            set_epoch = getattr(config, "set_epoch", None)
            if callable(set_epoch):
                set_epoch(result.dataset_epoch)
            elif hasattr(config, "dataset_epoch"):
                config.dataset_epoch = result.dataset_epoch
        save_fn = getattr(config, "save", None)
        if callable(save_fn):
            save_fn()

    return {"ok": True, "backup_path": result.backup_path, "imported": True, "rows": getattr(result, "rows", 0)}, 200


def cloud_run_backup_now():
    """POST /cloud-backup-now: trigger on-demand database backup on host, admin only."""
    from cloud_sync.lease import LeaseExpiredError

    runtime = _cloud_runtime()
    client = runtime["client"]
    lease = runtime["lease"]

    if lease and lease.is_expired():
        raise LeaseExpiredError()

    vault = getattr(client, "vault", None)
    user_token = getattr(vault, "user_access_token", None) if vault else None
    if not _CLOUD_ACTOR or not user_token:
        return cloud_error_body("AUTH_REQUIRED", 401)

    if _CLOUD_ROLE != "admin":
        return cloud_error_body("HTTP_403", 403)

    trigger = getattr(client, "trigger_backup", None)
    if not callable(trigger):
        _req = getattr(client, "_request", None)
        if callable(_req):
            res = _req("POST", "/admin/backup", body={}, acting=True)
            return {"ok": True, "message": "پشتیبان‌گیری پایگاه داده ابری انجام و به تلگرام ارسال شد.", "details": res}, 200
        return cloud_error_body("CONFIG_INVALID", 500)

    res = trigger()
    return {"ok": True, "message": "پشتیبان‌گیری پایگاه داده ابری انجام و به تلگرام ارسال شد.", "details": res}, 200


def test_telegram_api(attempts=3):
    """Connectivity/auth test via getMe; does not send a message."""
    import requests
    cfg = load_telegram_config()
    token = str(cfg.get("bot_token") or "").strip()
    base = str(cfg.get("api_base") or "").rstrip("/")
    mode = str(cfg.get("mode") or "").strip().lower()
    if not mode:
        if cfg.get("relay_url"):
            mode = "host"
        elif cfg.get("proxy_url"):
            mode = "proxy"
        elif base:
            mode = "direct"
        else:
            mode = "host"

    result = {
        "ok": False,
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "api_base": base,
        "mode": mode,
        "used_base": "",
        "message": "تنظیمات API تلگرام کامل نیست.",
    }
    if not token or (mode == "direct" and not base):
        _write_telegram_health(result)
        return result

    post_kwargs = {}
    if mode == "host":
        relay = str(cfg.get("relay_url") or "https://api.oneserver.in/telegram.php").rstrip("/")
        req_url = f"{relay}?method=getMe&token={token}"
        secret = str(cfg.get("relay_secret") or "").strip()
        headers = {"X-Telegram-Bot-Token": token}
        if secret:
            headers["X-Relay-Secret"] = secret
        post_kwargs["headers"] = headers
        post_kwargs["proxies"] = {"http": None, "https": None}
        used_target = relay
    elif mode == "proxy":
        proxy = str(cfg.get("proxy_url") or "").strip()
        if proxy:
            post_kwargs["proxies"] = {"http": proxy, "https": proxy}
        base_url = "https://api.telegram.org"
        req_url = f"{base_url}/bot{token}/getMe"
        used_target = f"proxy ({proxy})" if proxy else base_url
    else:  # direct
        base_url = base or "https://api.telegram.org"
        req_url = f"{base_url}/bot{token}/getMe"
        used_target = base_url

    last_message = result["message"]
    for attempt in range(1, max(1, int(attempts)) + 1):
        try:
            if mode == "host":
                response = requests.post(req_url, timeout=20, **post_kwargs)
            else:
                response = requests.get(req_url, timeout=20, **post_kwargs)
            try:
                payload = response.json()
            except Exception:
                payload = {}
            if response.ok and payload.get("ok"):
                username = str((payload.get("result") or {}).get("username") or "ربات")
                result.update(ok=True, used_base=used_target,
                              message=f"ارتباط API تلگرام برقرار است — @{username}")
                result["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
                _write_telegram_health(result)
                return result
            last_message = str(payload.get("description") or
                               f"پاسخ نامعتبر API ({response.status_code})")
        except Exception as exc:
            last_message = f"ارتباط API تلگرام ناموفق بود: {type(exc).__name__}"
        if attempt < attempts:
            time.sleep(1.5 * attempt)
    result["message"] = last_message
    result["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_telegram_health(result)
    return result


def run_telegram_test(data=None):
    """Run full telegram test: checks getMe and optionally sends a test message to chats."""
    data = data if isinstance(data, dict) else {}
    send_msg = bool(data.get("send_message", True))
    api_res = test_telegram_api(attempts=1)
    if not api_res.get("ok"):
        return {"ok": False, "message": api_res.get("message", "خطا در اتصال به تلگرام")}
    if send_msg:
        import telegram_notify
        cfg = load_telegram_config()
        chat_ids = cfg.get("chat_ids") or []
        target_chat = data.get("chat_id")
        targets = [str(target_chat).strip()] if target_chat else chat_ids
        if not targets:
            return {"ok": True, "message": api_res.get("message") + " — شناسه‌ای برای ارسال پیام تنظیم نشده است."}
        try:
            telegram_notify.send_message(
                "پیام آزمایشی از پنل ایریکا — ارتباط تلگرام با موفقیت برقرار است.",
                extra_chat_ids=targets if not target_chat else None,
                chat_id=target_chat if target_chat else None,
                timeout=20,
            )
            return {"ok": True, "message": api_res.get("message") + " و پیام آزمایشی ارسال شد."}
        except Exception as e:
            return {"ok": False, "message": f"{test_res.get('message')} اما ارسال پیام با خطا مواجه شد: {e}"}
    return {"ok": True, "message": api_res.get("message")}


def _write_telegram_health(result):
    try:
        with open(TELEGRAM_HEALTH_PATH, "w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
    except OSError:
        pass
    return result


def _startup_telegram_bootstrap():
    """Ba bala amadan-e panel: zanjire-ye relay ra bala biavar, sepas test kon.
    Agar bar-e aval javab nadad (tunnel taze sabt mishavad), dobare talash kon."""
    health = test_telegram_api(attempts=3)
    if not health.get("ok"):
        time.sleep(6)
        health = test_telegram_api(attempts=3)
    tag = "OK" if health.get("ok") else "FAIL"
    print(f">>> Telegram API health [{tag}]: {health.get('message')}")
    return health


def load_telegram_health():
    try:
        with open(TELEGRAM_HEALTH_PATH, encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {"ok": False, "ts": "", "message": "تست ارتباط API هنوز انجام نشده است."}


def sync_active_to_inputs(store):
    """profile-e active ra be inputs.json (format-i ke gomrok.py mikhanad) minevisad."""
    active = None
    for p in store.get("profiles", []):
        if p["id"] == store.get("active_id"):
            active = p
            break
    if not active and store.get("profiles"):
        active = store["profiles"][0]
    if not active:
        return
    inp = {
        "title": active["title"],
        "national": active["national"],
        "birth": active["birth"],
        "mobile": active["mobile"],
        "telegram_chat_id": active["telegram_chat_id"],
        "imeis": active["imeis"],
        "no_confirm_check": active["no_confirm_check"],
        "submit": active["submit"],
        "debugging": active["debugging"],
        "manual_manage": active["manual_manage"],
    }
    with open(INPUTS_PATH, "w", encoding="utf-8") as f:
        json.dump(inp, f, ensure_ascii=False, indent=2)


def load_logs(limit=200):
    """logs.jsonl ra mikhanad va list-e rvidaad-ha (jadidtar avval) barmigardanad."""
    if not os.path.exists(LOGS_PATH):
        return []
    out = []
    try:
        with open(LOGS_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    out.reverse()  # jadidtar avval
    return out[:limit]


def log_site2_success(national=""):
    """Rvidaad-e movaffaghiat-e vorud-e site2: yek log dar logs.jsonl +yek
    notif-e jadid baraye panel-e site2 (dashboard-new.html an-ra flash mikonad)."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    national = str(national or "").strip()
    message = (f"کد ملی {national} در {ts} با موفقیت وارد حساب کاربری در سایت دوم شد"
               if national else f"در {ts} با موفقیت وارد حساب کاربری در سایت دوم شد")
    rec = {
        "ts": ts, "title": "", "national": national, "imei": "",
        "step": "ورود موفق", "status": "success", "message": message,
    }
    import log_utils
    log_utils.append_jsonl(LOGS_PATH, rec)
    try:
        with open(SITE2_NOTIF_PATH, "w", encoding="utf-8") as f:
            json.dump({"ts": ts, "message": message}, f, ensure_ascii=False)
    except Exception as e:
        print(f">>> (notif-e site2 na-shod: {e})")
    return message


def load_site2_notif():
    if not os.path.exists(SITE2_NOTIF_PATH):
        return {}
    try:
        with open(SITE2_NOTIF_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# ---------------- servis-e ESTELAM-e dastgah (jaygozin-e site-2) ----------------
ESTELAM_PATH = os.environ.get("IRICA_ESTELAM_STORE") or app_paths.data_path("estelam_store.json")
ESTELAM_LOGS_PATH = app_paths.data_path("estelam_logs.jsonl")
_ESTELAM_LOCK = threading.RLock()

ESTELAM_STATUS_FA = {
    "pending": "در انتظار استعلام",
    "running": "در حال استعلام",
    "healthy": "سالم (شناسه در گمرک ورودی یافت نشد)",
    "problem": "دارای اشکال",
    # Pool semantics: 'advanced' = registered under the passenger's code —
    # the SUCCESS signal for the watch stages (same wording as the CRM tab,
    # v1.5 review item 2), not a warning.
    "advanced": "ثبت‌شده در گمرک (رفتن به مرحله بعد)",
    "error": "خطای ربات",
}

# Badge-e KUTAH-e sotoon-e vaziat baraye GOMROK — ham-shakl-e badge-haye HAMTA.
# (motn-e kamel/tozihat dar sotoon-e «نتیجه» va modal-e «مشاهده کامل» miayad,
#  vagarna badge-e gomrok chand-khati mishavad va jadval ra mikeshad)
ESTELAM_BADGE_FA = {
    "pending": "در انتظار",
    "running": "در حال استعلام",
    "healthy": "مجاز (قابل ثبت)",
    "problem": "مسدود/خطر",
    "advanced": "ثبت‌شده",
    "error": "خطای ربات",
}


def estelam_load():
    with _ESTELAM_LOCK:
        data = {"person": {"national": "", "birth": "", "mobile": ""}, "devices": [],
                "run_pid": 0, "run_started": "", "run_device_id": ""}
        for candidate in (ESTELAM_PATH, ESTELAM_PATH + ".bak"):
            if not os.path.exists(candidate):
                continue
            try:
                with open(candidate, encoding="utf-8") as f:
                    loaded = json.load(f) or {}
                person = dict(data["person"])
                person.update(loaded.get("person") or {})
                data.update(loaded)          # run_pid/run_started/... gom nashavand
                data["person"] = person
                data["devices"] = list(loaded.get("devices") or [])
                if candidate == ESTELAM_PATH and \
                        not os.path.exists(ESTELAM_PATH + ".bak"):
                    # Seed the fallback so a future corrupt main never leaves
                    # us with zero copies (review F6).
                    try:
                        with open(ESTELAM_PATH + ".bak", "w",
                                  encoding="utf-8") as bak:
                            json.dump(data, bak, ensure_ascii=False, indent=2)
                    except OSError:
                        pass
                break                        # main read fine — skip the .bak
            except Exception:
                continue                     # corrupt main -> try the .bak
        _estelam_migrate_devices(data["devices"])
        return data


def _estelam_migrate_devices(devices):
    """Field-haye jadid (name / gomrok_at / hamta_at) ra roo-ye record-haye
    GHADIMI-ye estelam_store.json misazad ta UI khali nabinad. Baraye device-i
    ke estelam-e nahayi dashte vali zaman-ash sabt nashode, az 'updated' (ya
    'created') estefade mishavad."""
    for device in devices:
        device.setdefault("name", "")
        fallback = str(device.get("updated") or device.get("created") or "")
        if "gomrok_at" not in device:
            device["gomrok_at"] = (
                fallback if str(device.get("status") or "") in _ESTELAM_FINAL else "")
        if "hamta_at" not in device:
            device["hamta_at"] = (
                fallback if str(device.get("hamta_status") or "") in _ESTELAM_FINAL else "")


def estelam_save(data):
    """Atomic save with one .bak generation (review F6): the old main file
    becomes the backup; on the very first save the backup is seeded from the
    new content so a corrupt main NEVER leaves zero fallbacks. A corrupt
    main falls back to the .bak on read."""
    with _ESTELAM_LOCK:
        tmp_path = ESTELAM_PATH + ".tmp"
        bak_path = ESTELAM_PATH + ".bak"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        try:
            if os.path.exists(ESTELAM_PATH):
                os.replace(ESTELAM_PATH, bak_path)
            else:
                with open(bak_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
        os.replace(tmp_path, ESTELAM_PATH)
        return data


def set_profile_enabled(profile_id, enabled):
    """Enable/disable a profile unless it is busy (used by CRM device delete)."""
    with _locked_store():
        store = load_store()
        changed = False
        for profile in store.get("profiles", []):
            if profile.get("id") == str(profile_id) and profile.get("run_status") != "busy":
                profile["enabled"] = bool(enabled)
                changed = True
        if changed:
            save_store(store)
        return changed


def load_crm_logs(limit=300):
    """CRM JSONL event log tail (newest last), same shape as estelam logs."""
    import crm as crm_mod
    out = []
    path = crm_mod.log_path()
    try:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        continue
    except OSError:
        return []
    return out[-limit:]


def crm_state_payload():
    """crm store + joined per-device estelam results for /crm-state."""
    import crm as crm_mod
    data = crm_mod.store_read()
    est = estelam_load()
    est_by_id = {str(d.get("id")): d for d in est.get("devices", [])}
    pay_by_pid = {}
    try:
        store = load_store()
        pay_by_pid = {str(p.get("id")): p for p in store.get("profiles", [])}
    except Exception:
        pay_by_pid = {}
    enriched = []
    for device in data.get("devices", []):
        row = dict(device)
        est_row = est_by_id.get(str(device.get("id"))) or {}
        row["estelam"] = {k: est_row.get(k, "") for k in
                          ("status", "result", "hamta_status", "hamta_result",
                           "gomrok_at", "hamta_at", "updated")}
        # v1.9.1: the camera icon renders only when the device carries a capture
        # slot, so the slot's presence must travel with the state payload.
        # /estelam-shot resolves the path itself from estelam_store, so only the
        # presence flag is forwarded — never the path (the route stays the
        # single source of truth for it).
        row["estelam"].update(
            {"has_gomrok_screenshot": bool(est_row.get(_SHOT_FIELD["gomrok"])),
             "has_hamta_screenshot": bool(est_row.get(_SHOT_FIELD["hamta"]))})
        profile = pay_by_pid.get(str(device.get("profile_id") or ""))
        row["pay"] = {k: (profile or {}).get(k, "" if k != "browser_visible"
                                             else False) for k in
                      ("run_status", "runner_pid", "browser_visible",
                       "payment_link", "receipt_screenshot",
                       "payment_screenshot", "registration_status")}
        enriched.append(row)
    out = dict(data)
    out["devices"] = enriched
    live_runs = estelam_live_runs()
    out["estelam_running"] = bool(live_runs)
    out["estelam_runs"] = live_runs
    # v1.7: the owner archive is computed server-side (never stored) so the
    # owners tab can exclude completed-case passengers and the archive tab
    # can list them with their case details.
    out["archived_owners"] = crm_mod.archived_owners(data)
    # v1.7: the period bar renders from the store's own period records.
    out["periods"] = data.get("periods") or []
    return out


def crm_sync_queue(device_id, service="gomrok"):
    """Upsert the CRM device's estelam queue row and reset ONLY the service
    about to run to pending (review F2b — the robots skip rows carrying a
    final status). The OTHER service's final result stays untouched: clobbering
    it here reset a healthy gomrok verdict to pending whenever a hamta run
    followed it (v1.7 bug: inquiry order must not matter).
    ALL reads/writes go through estelam_load/estelam_save (_ESTELAM_LOCK);
    non-CRM rows stay byte-identical (review F18)."""
    import crm as crm_mod
    data = crm_mod.store_read()
    device = next((d for d in data.get("devices", [])
                   if d.get("id") == device_id), None)
    if not device:
        return ["دستگاه پیدا نشد"]
    customer = next((c for c in data.get("customers", [])
                     if c.get("id") == device.get("customer_id")), None)
    # Only the service(s) about to run are re-queued. Each robot skips rows
    # that already carry a final status for its own slot, so re-queuing a
    # slot that is not about to run would DESTROY a finished verdict, while
    # failing to re-queue one that IS about to run makes that robot skip the
    # device. "all" runs both, so it re-queues both.
    reset_keys = []
    if service in ("gomrok", "all"):
        reset_keys += ["status", "result"]
    if service in ("hamta", "all"):
        reset_keys += ["hamta_status", "hamta_result"]
    if not reset_keys:
        # Unknown or empty service falls back to the gomrok slot. Normalise it
        # here rather than repeating the fallback below, so the status reset and
        # the screenshot reset can never disagree about which slot was re-queued
        # (they did: an unknown service used to reopen gomrok's status while
        # leaving gomrok's screenshot pinned).
        service = "gomrok"
        reset_keys = ["status", "result"]
    # v1.9.1: the evidence slot is reopened with the status slot. A run killed
    # before it reaches its own _panel_set_device would otherwise leave last
    # verdict's screenshot pinned to a re-queued device, and the file is
    # overwritten by the new capture anyway, so only the dangling reference
    # would survive.
    if service in ("gomrok", "all"):
        reset_keys.append(_SHOT_FIELD["gomrok"])
    if service in ("hamta", "all"):
        reset_keys.append(_SHOT_FIELD["hamta"])
    reset_keys = tuple(reset_keys)
    est = estelam_load()
    row = next((d for d in est.get("devices", [])
                if str(d.get("id")) == str(device_id)), None)
    if row:
        for key in reset_keys:
            row[key] = "pending" if key.endswith("status") else ""
        row["customer_id"] = device.get("customer_id") or ""
    else:
        # A brand-new queue row: the service about to run starts pending;
        # the other service's slot stays unknown ("") so a later run of it
        # is not falsely reported as a clean result.
        gomrok_status, gomrok_result = (
            ("pending", "") if service != "hamta" else ("", ""))
        hamta_status, hamta_result = (
            ("pending", "") if service != "gomrok" else ("", ""))
        row = {
            "id": str(device_id),
            "name": device.get("name") or "",
            "serial1": device.get("serial1") or "",
            "serial2": device.get("serial2") or "",
            "status": gomrok_status,
            "result": gomrok_result,
            "hamta_status": hamta_status,
            "hamta_result": hamta_result,
            "customer_id": device.get("customer_id") or "",
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "customer_name": (customer or {}).get("full_name") or "",
        }
        est.setdefault("devices", []).append(row)
    estelam_save(est)
    return []


def crm_periodic_toggle(device_id, remove=True):
    """Operator control for the periodic gomrok inquiry list (CRM tab):
    remove=True opts the device OUT of auto periodic runs; remove=False
    re-enrolls it. Devices reaching `handed` are enrolled by default."""
    import crm as crm_mod
    with crm_mod.STORE_LOCK:
        data = crm_mod.store_read()
        device = next((d for d in data.get("devices", [])
                       if d.get("id") == device_id), None)
        if not device:
            return {"ok": False, "errors": ["دستگاه پیدا نشد"]}
        if device.get("stage") == "closed":
            return {"ok": False, "errors": [
                "پروندهٔ این دستگاه مختومه شده است — تغییر استعلام دوره‌ای مجاز نیست"]}
        device["periodic_opt_out"] = bool(remove)
        device["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
        crm_mod.store_write(data)
        crm_mod.crm_log("info", "periodic_opt_out" if remove
                        else "periodic_opt_in", device_id=device_id)
        return {"ok": True, "device": device, "errors": []}


def crm_start_inquiry(device_id, service="gomrok", origin="manual",
                      actor=None):
    """CRM-scoped inquiry start (plan section 2):
      - identity: a random valid POOL entry for EVERY inquiry (pool-only
        contract, user item 7 — intake and watch stages alike); the old
        stage-based routing (owner identity for the watch stages, F1) was
        removed — the owner is needed for registration and handover, never
        as the inquiry identity. Fails closed exactly like intake when no
        valid pool entry exists, so the request is never sent;
      - materialize it into store['person'] (F3 — no new store keys);
      - sync + reset the CRM row and start ONE device (F2 — never the
        unscoped sweep that would swallow the operator's manual site-2 rows).
    """
    import crm as crm_mod
    if len(estelam_live_runs()) >= ESTELAM_MAX_CONCURRENT:
        return {"ok": False, "errors": [
            f"سقف اجرای همزمان استعلام ({ESTELAM_MAX_CONCURRENT}) پر است — بعداً تلاش می‌شود"]}
    if service not in ESTELAM_SERVICES:
        service = "gomrok"
    person = {"national": "", "birth": "", "mobile": ""}
    if service != "hamta":
        data = crm_mod.store_read()
        device = next((d for d in data.get("devices", [])
                       if d.get("id") == device_id), None)
        if not device:
            return {"ok": False, "errors": ["دستگاه پیدا نشد"]}
        if device.get("stage") == "closed":
            return {"ok": False, "errors": [
                "پروندهٔ این دستگاه مختومه شده است — استعلام مجاز نیست"]}
        person, errors = crm_mod.identity_for_stage(device_id)
        if errors:
            crm_mod.crm_log("warn", "inquiry_identity_missing",
                            device_id=device_id, errors="; ".join(errors))
            return {"ok": False, "errors": errors}
        person_errors = validate_estelam_person(person)
        if person_errors:
            return {"ok": False, "errors": person_errors}
        estelam_save_person(person)
    errors = crm_sync_queue(device_id, service=service)
    if errors:
        return {"ok": False, "errors": errors}
    result = estelam_start(device_id=device_id, service=service,
                           actor=actor)
    if result.get("ok"):
        # Locked read-modify-write (v1.5 review item 9): a bare
        # read -> mutate -> write here could clobber a concurrent
        # store_write (scheduler/auto-advance ticks) — same pattern
        # as every other device mutation in this module.
        with crm_mod.STORE_LOCK:
            data = crm_mod.store_read()
            device = next((d for d in data.get("devices", [])
                           if d.get("id") == device_id), None)
            if device:
                device["last_inquiry_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                crm_mod.store_write(data)
        crm_mod.crm_log("info", "inquiry_started", device_id=device_id,
                        service=service, origin=origin,
                        person_masked=crm_mod.mask_national(person.get("national")))
    else:
        crm_mod.crm_log("warn", "inquiry_start_failed", device_id=device_id,
                        service=service, detail=str(result))
    return result


def crm_ensure_registration_profile(device_id):
    """At handover: link the site-1 profile or create one (review F9).
    Dedupe first — an operator-registered device links to its EXISTING
    profile instead of creating a duplicate. Returns the profile id or "".
    """
    import crm as crm_mod
    data = crm_mod.store_read()
    device = next((d for d in data.get("devices", [])
                   if d.get("id") == device_id), None)
    if not device:
        return ""
    if device.get("profile_id"):
        store = load_store()
        if next((p for p in store.get("profiles", [])
                 if p.get("id") == device["profile_id"]), None):
            return device["profile_id"]          # already linked (idempotent)
    owner = next((o for o in data.get("owners", [])
                  if o.get("id") == device.get("owner_id")), None)
    serial1 = str(device.get("serial1") or "").strip()
    store = load_store()
    profile = None
    # Dedupe is SERIAL-ONLY by design (production fix 2026-09-15): matching a
    # profile by the passenger's national code could link a profile whose
    # imeis belong to a DIFFERENT device — the robot would then register the
    # wrong IMEI. The same passenger on a new device intentionally gets a
    # fresh profile. (The old national clause here was dead code — a
    # misplaced parenthesis made the generator always truthy — and was
    # removed rather than activated.)
    if serial1:
        profile = next((p for p in store.get("profiles", [])
                        if serial1 in (p.get("imeis") or [])), None)
    if profile is None:
        profile = {
            "id": uuid.uuid4().hex[:12],
            "title": f"{device.get('name')} — "
                     f"{(owner or {}).get('first_name', '')} "
                     f"{(owner or {}).get('last_name', '')}".strip(" —"),
            "national": (owner or {}).get("national", ""),
            "birth": (owner or {}).get("birth", ""),
            "mobile": (owner or {}).get("mobile", ""),
            "passport": str((owner or {}).get("passport") or "").strip(),
            "imeis": [s for s in (serial1, device.get("serial2") or "") if s],
            "enabled": False,
            "registration_status": "pending",
        }
        store.setdefault("profiles", []).append(profile)
        save_store(store)
        crm_mod.crm_log("info", "profile_created", device_id=device_id,
                        profile_id=profile["id"])
    else:
        # Fill-once passport (v1.5 item 11): an EMPTY profile passport takes
        # the attached owner's; a non-empty value is NEVER overwritten (the
        # operator's manual entry wins). Idempotent — after the first fill
        # the profile side is non-empty and this becomes a no-op.
        owner_passport = str((owner or {}).get("passport") or "").strip()
        if owner_passport and not str(profile.get("passport") or "").strip():
            profile["passport"] = owner_passport
            save_store(store)
            crm_mod.crm_log("info", "profile_passport_filled",
                            device_id=device_id, profile_id=profile["id"])
        crm_mod.crm_log("info", "profile_linked", device_id=device_id,
                        profile_id=profile["id"])
    with crm_mod.STORE_LOCK:
        data = crm_mod.store_read()
        dev = next((d for d in data.get("devices", [])
                    if d.get("id") == device_id), None)
        if dev:
            dev["profile_id"] = profile["id"]
            dev["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            crm_mod.store_write(data)
    return profile["id"]


HANDOFF_STAGES = ("handed", "to_payment", "payment", "payment_done", "done")


def crm_send_registration_handoff(device_id, actor=None):
    """v1.5 B10: hand the registration data (national code, IMEIs, passport)
    to the registration Telegram destination after handover. FAIL-CLOSED on
    every error shape — unset destination, missing passport, send failure:
    the caller's handover stays committed and only the notice differs. The
    body is sensitive, so it targets ONLY the configured registration chat
    (send_message chat_id=); never the configured fanout list. Returns
    (sent, notice) with a Persian operator notice, "" on success. Log lines
    carry device_id and the destination id ONLY (plan §12)."""
    import crm as crm_mod
    data = crm_mod.store_read()
    settings = data.get("settings") or {}
    destination = str(settings.get("registration_chat_id") or "").strip()
    if not destination:
        crm_mod.crm_log("info", "registration_handoff_skipped",
                        device_id=device_id, reason="no_destination")
        return False, ("مقصد تلگرام ثبت مسافری تنظیم نشده — "
                       "از بخش تنظیمات مشخص کنید")
    device = next((d for d in data.get("devices", [])
                   if d.get("id") == device_id), None)
    owner = next((o for o in data.get("owners", [])
                  if o.get("id") == (device or {}).get("owner_id")), None)
    if not device or not str((owner or {}).get("passport") or "").strip():
        crm_mod.crm_log("info", "registration_handoff_skipped",
                        device_id=device_id, reason="no_passport")
        return False, ("برای ارسال اطلاعات ثبت، ابتدا شمارهٔ گذرنامهٔ مسافر را "
                       "در بخش اطلاعات مسافر کامل کنید")
    body = "\n".join((
        f"kodmeli = {owner.get('national') or ''}",
        f"imei1 = {device.get('serial1') or ''}",
        f"imei2 = {device.get('serial2') or ''}",
        f"passport = {owner.get('passport') or ''}",
    ))
    try:
        import telegram_notify
        telegram_notify.send_message(body, chat_id=destination, timeout=20,
                                     actor=actor)
    except Exception:
        # No exception text in the log — ids only (plan §12).
        crm_mod.crm_log("warn", "registration_handoff_failed",
                        device_id=device_id, destination=destination)
        return False, "ارسال اطلاعات ثبت به تلگرام ناموفق بود"
    crm_mod.crm_log("info", "registration_handoff_sent",
                    device_id=device_id, destination=destination)
    return True, ""


def _crm_is_due(device, settings):
    last = str(device.get("last_inquiry_at") or "")
    if not last:
        return True
    try:
        last_ts = time.mktime(time.strptime(last, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return True
    hours = int(settings.get("watch_interval_hours") or 2)
    return (time.time() - last_ts) >= hours * 3600


def crm_html_to_pdf(html, timeout_s=60):
    """Render HTML to PDF with headless Edge (--print-to-pdf); None when Edge
    is unavailable so callers fall back to the printable HTML (plan §6)."""
    import shutil
    import subprocess
    import tempfile
    edge = shutil.which("msedge")
    if not edge:
        for candidate in (
                os.path.join(os.environ.get("PROGRAMFILES(X86)", ""),
                             "Microsoft\\Edge\\Application\\msedge.exe"),
                os.path.join(os.environ.get("PROGRAMFILES", ""),
                             "Microsoft\\Edge\\Application\\msedge.exe"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""),
                             "Microsoft\\Edge\\Application\\msedge.exe")):
            if candidate and os.path.isfile(candidate):
                edge = candidate
                break
    if not edge:
        return None
    fd, html_path = tempfile.mkstemp(suffix=".html")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(html)
        pdf_path = html_path + ".pdf"
        command = [edge, "--headless", "--disable-gpu",
                   "--no-pdf-header-footer",
                   f"--print-to-pdf={pdf_path}", html_path]
        try:
            subprocess.run(command, timeout=timeout_s,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired:
            return None
        if not os.path.exists(pdf_path) or os.path.getsize(pdf_path) < 200:
            return None
        with open(pdf_path, "rb") as handle:
            return handle.read()
    finally:
        for path in (html_path, html_path + ".pdf"):
            try:
                os.remove(path)
            except OSError:
                pass


_CRM_SCHEDULER_THREAD = None
_CRM_SCHEDULER_STOP = threading.Event()


def _crm_scheduler_loop():
    """60s cadence scheduler beat (plan section 5). Daemon thread; IRICA_CRM_
    SCHEDULER_OFF=1 is the operator kill-switch. Exceptions never kill the
    loop — they are logged and the beat is skipped."""
    while not _CRM_SCHEDULER_STOP.wait(60):
        try:
            crm_scheduler_tick()
            crm_auto_advance_scan()
        except Exception as exc:
            try:
                crm.crm_log("error", "scheduler_exception", detail=str(exc))
            except Exception:
                pass


def crm_scheduler_start():
    global _CRM_SCHEDULER_THREAD
    if os.environ.get("IRICA_CRM_SCHEDULER_OFF") == "1":
        return None
    if _CRM_SCHEDULER_THREAD and _CRM_SCHEDULER_THREAD.is_alive():
        return _CRM_SCHEDULER_THREAD
    _CRM_SCHEDULER_STOP.clear()
    _CRM_SCHEDULER_THREAD = threading.Thread(target=_crm_scheduler_loop,
                                             name="crm-scheduler", daemon=True)
    _CRM_SCHEDULER_THREAD.start()
    return _CRM_SCHEDULER_THREAD


def crm_scheduler_stop():
    _CRM_SCHEDULER_STOP.set()


def crm_scheduler_tick(origin="scheduler"):
    """One scheduler beat: start at most ONE due watch-stage device per tick;
    parallelism is bounded by ESTELAM_MAX_CONCURRENT (v1.1.4) instead of a
    single-run gate."""
    import crm as crm_mod
    data = crm_mod.store_read()
    if not (data.get("settings") or {}).get("scheduler_enabled"):
        return {"ok": False, "started": []}
    if len(estelam_live_runs()) >= ESTELAM_MAX_CONCURRENT:
        crm_mod.crm_log("info", "scheduler_skipped_cap")
        return {"ok": False, "started": []}
    watch = {"handed", "to_payment"}
    started = []
    for device in data.get("devices", []):
        if device.get("stage") not in watch:
            continue
        if device.get("periodic_opt_out"):
            continue
        if not _crm_is_due(device, data.get("settings") or {}):
            continue
        result = crm_start_inquiry(device["id"], service="gomrok",
                                   origin=origin)
        if result.get("ok"):
            started.append({"device_id": device["id"],
                            "pid": result.get("pid")})
            crm_mod.crm_log("info", "scheduler_started",
                            device_id=device["id"])
        else:
            crm_mod.crm_log("warn", "scheduler_start_failed",
                            device_id=device["id"],
                            detail="; ".join(result.get("errors") or []))
        break                      # one device per tick — serialized runs
    return {"ok": bool(started), "started": started}


def crm_auto_advance_scan():
    """Join 'advanced' watch rows to to_payment, and (when the device has
    auto_advance) start payment. The stage moves to payment ONLY on a 200
    from start_profile (review F5); failures keep the device in to_payment
    with advance_attempts capped at 6 (operator-visible give-up). Retry
    scans pick to_payment devices with attempts>0 back up (F5)."""
    import crm as crm_mod
    moved, started, errors = [], [], []
    if estelam_is_running():
        return {"ok": False, "moved": moved, "started": started}
    est = estelam_load()
    advanced_ids = {str(d.get("id")) for d in est.get("devices", [])
                    if str(d.get("status") or "") == "advanced"}
    data = crm_mod.store_read()
    for device in data.get("devices", []):
        stage = device.get("stage")
        attempts = int(device.get("advance_attempts") or 0)
        is_new = stage == "handed" and str(device.get("id")) in advanced_ids
        is_retry = stage == "to_payment" and attempts > 0 and attempts < 6
        if is_new:
            with crm_mod.STORE_LOCK:
                fresh = crm_mod.store_read()
                dev = next((d for d in fresh.get("devices", [])
                            if d.get("id") == device.get("id")), None)
                if not dev:
                    continue
                dev["stage"] = "to_payment"
                dev["advance_attempts"] = 0
                dev["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                crm_mod.store_write(fresh)
            # The store reset above also resets THIS scan's local counter: a
            # rollback to handed must restart payment attempts from zero, not
            # give up on the stale pre-rollback value (v1.5 review item 1).
            attempts = 0
            moved.append(device["id"])
            crm_mod.crm_log("info", "registered_detected", device_id=device["id"])
        elif not is_retry:
            continue
        if not device.get("auto_advance"):
            continue
        if attempts >= 6:
            crm_mod.crm_log("error", "auto_advance_gave_up",
                            device_id=device["id"])
            continue
        profile_id = crm_ensure_registration_profile(device["id"])
        if not profile_id:
            errors.append({"device_id": device["id"],
                           "error": "پروفایل ثبت‌نام ساخته نشد"})
            continue
        status, payload = start_profile(profile_id)
        if status == 200:
            with crm_mod.STORE_LOCK:
                fresh = crm_mod.store_read()
                dev = next((d for d in fresh.get("devices", [])
                            if d.get("id") == device.get("id")), None)
                if dev:
                    dev["stage"] = "payment"
                    dev["advance_attempts"] = 0
                    dev["payment_started_at"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S")
                    crm_mod.store_write(fresh)
            started.append(device["id"])
            crm_mod.crm_log("info", "auto_payment_started",
                            device_id=device["id"], profile_id=profile_id)
        else:
            detail = str((payload or {}).get("error") or status) \
                if isinstance(payload, dict) else str(status)
            with crm_mod.STORE_LOCK:
                fresh = crm_mod.store_read()
                dev = next((d for d in fresh.get("devices", [])
                            if d.get("id") == device.get("id")), None)
                if dev:
                    dev["advance_attempts"] = int(
                        dev.get("advance_attempts") or 0) + 1
                    crm_mod.store_write(fresh)
            crm_mod.crm_log("warn", "auto_payment_failed",
                            device_id=device["id"], detail=detail,
                            attempt=attempts + 1)
            errors.append({"device_id": device["id"], "error": detail})
    return {"ok": True, "moved": moved, "started": started, "errors": errors}


def crm_advance_logged(device_id, action, **payload):
    """Stage machine + CRM event log (plan section 12)."""
    import crm as crm_mod
    device, errors = crm_mod.advance(device_id, action, **payload)
    if not errors:
        crm_mod.crm_log("info", "stage", device_id=device_id, action=action,
                        to_stage=str((device or {}).get("stage") or ""))
        if action == "close_case":
            # Closure trace: record THAT it happened and the reason's length —
            # never the reason text itself (free-text personal data, §12).
            crm_mod.crm_log("info", "case_closed", device_id=device_id,
                            reason_len=len(str(payload.get("reason") or "")))
    else:
        crm_mod.crm_log("warn", "stage_rejected", device_id=device_id,
                        action=action, errors="; ".join(errors))
    return device, errors


def _locked_store_rmw(func):
    """Run `func` with crm.STORE_LOCK held for its whole body.

    crm.store_read() and crm.store_write() are each individually locked, but
    not TOGETHER: a read at one end of a function and a write at the other can
    still straddle a concurrent mutator. store_write serialises the WHOLE
    document, so the loser silently drops the other side's change. Wrapping
    makes that window atomic while leaving the body — a hundred lines of
    validation — byte-for-byte untouched.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        import crm as crm_mod
        with crm_mod.STORE_LOCK:
            return func(*args, **kwargs)
    return wrapper


@_locked_store_rmw
def crm_update_settings(fields):
    import crm as crm_mod
    data = crm_mod.store_read()
    settings = data.get("settings") or {}
    errors = []
    if "watch_interval_hours" in fields:
        try:
            hours = int(crm_mod.normalize_digits(fields["watch_interval_hours"]))
        except (TypeError, ValueError):
            hours = 0
        if not 1 <= hours <= 72:
            errors.append("بازهٔ استعلام باید بین ۱ تا ۷۲ ساعت باشد")
        else:
            settings["watch_interval_hours"] = hours
    for key in ("scheduler_enabled", "auto_advance_default",
                "telegram_report_full_data", "sound_enabled"):
        if key in fields:
            settings[key] = bool(fields[key])
    if "database_mode" in fields:
        val = str(fields.get("database_mode") or "").strip().lower()
        if val in ("online", "local"):
            settings["database_mode"] = val
            cloud_worker_kick()
    if "registry_fee_amount" in fields:
        raw = str(fields.get("registry_fee_amount") or "").strip()
        # The field arrives pre-filled from the panel's own fa() formatter,
        # which groups with U+066C «٬»; the old strip-list here omitted it,
        # so re-saving any amount over 999 failed with «عدد نامنفی».
        text = crm_mod._amount_digits(raw)
        try:
            fee = int(text) if text else -1
        except (TypeError, ValueError):
            fee = -1
        if fee < 0:
            errors.append("هزینه ثبت رجیستری باید عدد نامنفی باشد (تومان)")
        else:
            settings["registry_fee_amount"] = fee
    if "registration_chat_id" in fields:
        # v1.5 B10: the registration handoff destination — a numeric Telegram
        # chat id (groups/channels are negative, e.g. -1001234567890).
        # Empty clears it (handoff then fails closed with a notice).
        raw = str(fields.get("registration_chat_id") or "").strip()
        if not raw:
            settings["registration_chat_id"] = ""
        elif re.fullmatch(r"-?\d+", raw):
            settings["registration_chat_id"] = raw
        else:
            errors.append("شناسهٔ تلگرام باید عددی باشد (مثلاً -1001234567890)")
    if "report_chat_id" in fields:
        # v1.10 (operator request): the optional report channel. Same numeric
        # rule as the registration destination above; empty clears it, and
        # that means no copy anywhere — the configured chats keep getting
        # everything (telegram_notify.report_extra_chat_ids is additive).
        raw = str(fields.get("report_chat_id") or "").strip()
        if not raw:
            settings["report_chat_id"] = ""
        elif re.fullmatch(r"-?\d+", raw):
            settings["report_chat_id"] = raw
        else:
            errors.append("شناسهٔ کانال تلگرام باید عددی باشد (مثلاً -1001234567890)")
    # v1.6: optional business identity for the statement/invoice/finance
    # headers. Trimmed free text, max 80 chars; empty clears the header.
    for key, label in (("business_name", "نام کسب‌وکار"),
                       ("business_phone", "شمارهٔ تماس کسب‌وکار")):
        if key in fields:
            value = str(fields.get(key) or "").strip()
            if len(value) > 80:
                errors.append(f"{label} حداکثر ۸۰ کاراکتر باشد")
            else:
                settings[key] = value
    # v1.9: the related-site buttons are shared with every browser, so they
    # are stored here and not in localStorage. A link is a {name, url} pair;
    # url is required and must be a plain http(s) link (a javascript: URL in a
    # target=_blank button would run in the panel's own origin), and name is
    # trimmed to what the button can actually display.
    if "links" in fields:
        raw_links = fields["links"]
        cleaned = []
        seen = set()
        for item in raw_links if isinstance(raw_links, list) else []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()
            name = str(item.get("name") or "").strip()
            if not url:
                continue
            if not re.fullmatch(r"https?://\S{1,400}", url, flags=re.IGNORECASE):
                errors.append("آدرس سایت باید با http یا https شروع شود")
                continue
            if url in seen:
                continue
            seen.add(url)
            cleaned.append({"name": name[:60] if name else url, "url": url})
        # An empty list is allowed: the box is optional and the operator may
        # want no buttons at all. _normalise_settings fills the defaults only
        # when the key is missing/invalid, never when it is deliberately [].
        # Assigned after the error gate below, so a rejected batch leaves the
        # in-memory settings exactly as the caller passed them.
        if errors:
            return None, errors
        settings["links"] = cleaned
    if errors:
        return None, errors
    data["settings"] = settings
    crm_mod.store_write(data)
    _cloud_enqueue_mutation("settings", "settings/settings", settings)
    crm_mod.crm_log("info", "settings", interval=settings.get("watch_interval_hours"),
                    scheduler=settings.get("scheduler_enabled"))
    return settings, []


def validate_estelam_person(person):
    """Barmigardanad list-e khata-haye farsi (khali = motabar)."""
    errors = []
    national = str((person or {}).get("national") or "").strip()
    birth = str((person or {}).get("birth") or "").strip()
    mobile = str((person or {}).get("mobile") or "").strip()
    if not re.fullmatch(r"\d{10}", national):
        errors.append("کد ملی باید ۱۰ رقم عدد باشد")
    if not re.fullmatch(r"1[34]\d{2}/\d{2}/\d{2}", birth):
        errors.append("تاریخ تولد باید به شکل ۱۳۷۵/۰۴/۲۹ باشد")
    if not re.fullmatch(r"09\d{9}", mobile):
        errors.append("شماره موبایل باید ۱۱ رقم و با ۰۹ شروع شود")
    return errors


def validate_estelam_device(device):
    errors = []
    name = str((device or {}).get("name") or "").strip()
    serial1 = str((device or {}).get("serial1") or "").strip()
    serial2 = str((device or {}).get("serial2") or "").strip()
    if not name:
        errors.append("نام دستگاه الزامی است")
    elif len(name) > 40:
        errors.append("نام دستگاه حداکثر ۴۰ کاراکتر باشد")
    if not serial1:
        errors.append("سریال اول الزامی است")
    for label, value in (("سریال اول", serial1), ("سریال دوم", serial2)):
        if value and not re.fullmatch(r"\d{15}", value):
            errors.append(f"{label} باید ۱۵ رقم عدد باشد")
    return errors


def estelam_save_person(person):
    data = estelam_load()
    data["person"] = {
        "national": str((person or {}).get("national") or "").strip(),
        "birth": str((person or {}).get("birth") or "").strip(),
        "mobile": str((person or {}).get("mobile") or "").strip(),
    }
    return estelam_save(data)


def estelam_add_device(device):
    data = estelam_load()
    record = {
        "id": _new_id(),
        "name": str((device or {}).get("name") or "").strip(),
        "serial1": str((device or {}).get("serial1") or "").strip(),
        "serial2": str((device or {}).get("serial2") or "").strip(),
        "status": "pending",
        "result": "",
        "messages": [],
        "hamta_status": "pending",
        "hamta_result": "",
        # zaman-e akharin estelam-e har servis ("" = hanooz estelam nashode)
        "gomrok_at": "",
        "hamta_at": "",
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "updated": "",
    }
    data["devices"].append(record)
    estelam_save(data)
    return record


def estelam_delete_device(device_id):
    data = estelam_load()
    keep, gone = [], []
    for d in data["devices"]:
        (gone if str(d.get("id")) == str(device_id) else keep).append(d)
    data["devices"] = keep
    # v1.9.1: the captures are keyed by device id, so a deleted row leaves its
    # PNGs behind with nothing that can ever reach or overwrite them. Delete
    # the store row first: an unlink failure must not keep the row alive.
    result = estelam_save(data)
    for d in gone:
        for key in _SHOT_FIELD.values():
            path = shot_resolve(d.get(key))
            if path:
                try:
                    import estelam_shot
                    if not estelam_shot.discard(path):
                        estelam_log("shot", f"could not delete the capture for "
                                            f"{device_id!r}: the file is still on disk")
                except Exception as exc:
                    estelam_log("shot", f"could not delete the capture for "
                                        f"{device_id!r}: {exc}")
    return result


# Vaziat-haye NAHAYI (na 'pending'/'running') — residan be in-ha ya'ni yek estelam
# vaghe'an anjam shode, pas zaman-e estelam bayad mohr shavad.
_ESTELAM_FINAL = {"healthy", "problem", "advanced", "error",
                  "good", "registered", "blocked", "success", "unknown"}


def estelam_set_device(device_id, **fields):
    """Robot-ha (estelam_gomrok.py / estelam_hamta.py) natije ra ba in tabe'
    minevisand. Ba residan be yek vaziat-e NAHAYI, zaman-e estelam-e haman
    servis (gomrok_at / hamta_at) mohr mishavad."""
    data = estelam_load()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    for device in data["devices"]:
        if str(device.get("id")) == str(device_id):
            device.update(fields)
            if str(fields.get("status") or "") in _ESTELAM_FINAL:
                device["gomrok_at"] = now
            if str(fields.get("hamta_status") or "") in _ESTELAM_FINAL:
                device["hamta_at"] = now
            device["updated"] = now
            break
    estelam_save(data)
    return data


def estelam_reset_pending():
    data = estelam_load()
    for device in data["devices"]:
        if device.get("status") == "running":
            device["status"] = "pending"
        if device.get("hamta_status") == "running":
            device["hamta_status"] = "pending"
    return estelam_save(data)


def estelam_reset_pending_stale():
    """Agar process-e estelam mordeh bashad, device-haye 'running'-e ja-mandeh
    ra be 'pending' bar migardanad (vagarna panel baraye hamishe running neshan
    midahad)."""
    data = estelam_load()
    stuck = [d for d in data["devices"]
             if d.get("status") == "running" or d.get("hamta_status") == "running"]
    if not stuck:
        return data
    pid = data.get("run_pid")
    if pid and _pid_alive(int(pid)):
        return data
    for device in stuck:
        if device.get("status") == "running":
            device["status"] = "pending"
        if device.get("hamta_status") == "running":
            device["hamta_status"] = "pending"
    return estelam_save(data)


# service -> (script, arg-haye ezafe baraye khandan-e device az store)
ESTELAM_SERVICES = {
    "gomrok": ("estelam_gomrok.py", []),
    "hamta": ("estelam_hamta.py", ["--from-store"]),
    "all": ("estelam_all.py", []),
}
ESTELAM_SERVICE_FA = {"gomrok": "گمرک", "hamta": "همتا", "all": "همه استعلام‌ها"}
# v1.9.1: the store field holding a service's result image. One map for the
# re-queue reset, the CRM presence flags and the /estelam-shot route.
_SHOT_FIELD = {"gomrok": "gomrok_screenshot", "hamta": "hamta_screenshot"}


def shot_resolve(raw):
    """Resolve a recorded capture path, or "" if it is not inside the roots.

    The store field is never trusted: it is the only capture input that is not
    recomputed, so every reader (the /estelam-shot route, the delete path) has
    to prove containment before opening or unlinking the file.

    Screenshots live in the data directory, but paths recorded by an older
    release point inside that release folder, so both roots are accepted --
    containment is still enforced against each of them (same contract as
    /artifact). realpath("") returns the CWD, so an empty field is rejected
    before resolving rather than looking like an escape attempt.
    """
    raw = str(raw or "")
    if not raw:
        return ""
    path = os.path.realpath(raw)
    for root in (app_paths.data_subdir("screenshots"),
                 os.path.join(HERE, "screenshots")):
        try:
            if os.path.commonpath([os.path.realpath(root), path]) == \
                    os.path.realpath(root):
                return path
        except (ValueError, OSError):
            continue
    return ""


def start_estelam_process(device_id=None, service="gomrok", person=None,
                          actor=None):
    script, base_args = ESTELAM_SERVICES.get(service, ESTELAM_SERVICES["gomrok"])
    command = _robot_command(ROBOT_PYTHON, script, *base_args)
    if device_id:
        command += ["--device-id", str(device_id)]
    child_env = _robot_child_env(actor)
    # Race-free identity handoff (v1.1.4 parallel runs): the child reads its own
    # identity from env instead of the shared store, which a parallel start may
    # overwrite between spawn and the child's first read.
    for key in ("national", "birth", "mobile"):
        value = str((person or {}).get(key) or "").strip()
        if value:
            child_env["IRICA_PERSON_" + key.upper()] = value
    log_file = open(ROBOT_LOG_PATH, "a", encoding="utf-8")
    try:
        process = subprocess.Popen(command, cwd=HERE, env=child_env,
                                   stdin=subprocess.DEVNULL,
                                   stdout=log_file, stderr=log_file)
    finally:
        log_file.close()
    return {"pid": process.pid}


def estelam_start(device_id=None, service="gomrok", actor=None):
    """Ghabl az ejra: etela'at-e shakhs bayad KAMEL va MOTABAR bashad."""
    if service not in ESTELAM_SERVICES:
        service = "gomrok"
    data = estelam_load()
    errors = validate_estelam_person(data.get("person"))
    # HAMTA faghat serial mikhahad (bedun-e login), pas etela'at-e shakhs lazem nist;
    # gomrok/all be kod-e melli va tarikh-e tavallod niaz darand.
    if errors and service != "hamta":
        return {"ok": False, "errors": ["اطلاعات شخص برای استعلام را پر کنید"] +errors}
    live_runs = estelam_live_runs()
    if len(live_runs) >= ESTELAM_MAX_CONCURRENT:
        return {"ok": False, "errors": [
            f"سقف اجرای همزمان استعلام ({ESTELAM_MAX_CONCURRENT}) پر است — بعداً تلاش می‌شود"]}
    # Per-device in-flight guard (v1.5 review item 4): an inquiry reset clears
    # last_inquiry_at making the device instantly due again; without this
    # check the scheduler or a manual click could double-start the SAME
    # device while its run is still alive. Other devices keep starting in
    # parallel under the global cap — this is per-device only.
    if device_id and any(str(run.get("device_id") or "") == str(device_id)
                         for run in live_runs):
        return {"ok": False,
                "errors": ["استعلام این دستگاه همین حالا در حال اجراست"]}
    targets = data.get("devices") or []
    if device_id:
        targets = [d for d in targets if str(d.get("id")) == str(device_id)]
    elif service == "hamta":
        targets = [d for d in targets
                   if str(d.get("hamta_status") or "pending") in ("pending", "error", "")]
    else:
        targets = [d for d in targets
                   if str(d.get("status") or "pending") in ("pending", "error", "")]
    if not targets:
        return {"ok": False, "errors": ["دستگاهی برای استعلام وجود ندارد"]}
    runtime = start_estelam_process(device_id, service=service,
                                    person=data.get("person") or {},
                                    actor=actor)
    data = estelam_load()
    data["run_pid"] = runtime.get("pid")
    data["run_device_id"] = str(device_id or "")
    data["run_service"] = service
    data["run_started"] = time.strftime("%Y-%m-%d %H:%M:%S")
    # Multi-run registry: every spawned robot process is tracked so several
    # single-device inquiries can run in parallel (cap ESTELAM_MAX_CONCURRENT).
    runs = [r for r in (data.get("runs") or [])
            if str(r.get("pid")) != str(runtime.get("pid"))]
    runs.append({"pid": runtime.get("pid"),
                 "device_id": str(device_id or ""),
                 "service": service,
                 "started": data["run_started"]})
    data["runs"] = runs
    estelam_save(data)
    estelam_log("info", f"استعلام {ESTELAM_SERVICE_FA.get(service, service)} شروع شد "
                        f"({len(targets)} دستگاه) — pid {runtime.get('pid')}",
                step="مدیریت")
    return {"ok": True, "pid": runtime.get("pid"), "count": len(targets),
            "service": service}


ESTELAM_MAX_CONCURRENT = 3   # parallel robot processes (each opens its own browser)


def estelam_is_running():
    """Any live inquiry run? (kept for backward compatibility)"""
    return bool(estelam_live_runs())


def estelam_live_runs():
    """Pids of live inquiry runs from the runs registry.

    The registry is the store's `runs` list; the legacy single `run_pid`
    slot is honored for rows written by older builds. Dead pids are
    pruned on read so the cap tracks reality, not stale crashes.
    """
    data = estelam_load()
    runs = []
    seen = set()
    for entry in data.get("runs") or []:
        try:
            pid = int(entry.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        if pid > 0 and pid not in seen and _pid_alive(pid):
            runs.append({"pid": pid,
                         "device_id": str(entry.get("device_id") or ""),
                         "service": str(entry.get("service") or "gomrok"),
                         "started": str(entry.get("started") or "")})
            seen.add(pid)
    legacy = data.get("run_pid")
    try:
        legacy = int(legacy or 0)
    except (TypeError, ValueError):
        legacy = 0
    if legacy > 0 and legacy not in seen and _pid_alive(legacy):
        runs.append({"pid": legacy,
                     "device_id": str(data.get("run_device_id") or ""),
                     "service": str(data.get("run_service") or "gomrok"),
                     "started": str(data.get("run_started") or "")})
    return runs


def estelam_runtime():
    """Vaziat-e process-e estelam baraye bakhsh-e modiriat-e panel."""
    data = estelam_load()
    devices = data.get("devices") or []
    counts = {}
    hamta_counts = {}
    for device in devices:
        key = str(device.get("status") or "pending")
        counts[key] = counts.get(key, 0) +1
        hkey = str(device.get("hamta_status") or "pending")
        hamta_counts[hkey] = hamta_counts.get(hkey, 0) +1
    service = str(data.get("run_service") or "gomrok")
    return {
        "running": estelam_is_running(),
        "pid": data.get("run_pid") or 0,
        "started": data.get("run_started") or "",
        "device_id": data.get("run_device_id") or "",
        "service": service,
        "service_fa": ESTELAM_SERVICE_FA.get(service, service),
        "total": len(devices),
        "counts": counts,
        "hamta_counts": hamta_counts,
    }


def estelam_stop():
    """Tamam-e ejra-haye estelam (va morurgar-e farzandashan) ra mibandad.

    Parallel runs (v1.1.4): every live pid in the runs registry is killed;
    only the devices those runs actually owned are reset from `running` so
    a concurrent run's in-flight status is never clobbered by a neighbor's
    stop.
    """
    live = estelam_live_runs()
    stopped_pids = []
    for run in live:
        if stop_profile_process(run["pid"]):
            stopped_pids.append(run["pid"])
    data = estelam_load()
    data["run_pid"] = 0
    data["runs"] = []
    stopped_ids = {str(r["device_id"]) for r in live if r["device_id"]}
    for device in data["devices"]:
        owned = (not stopped_ids) or (str(device.get("id")) in stopped_ids)
        if owned and device.get("status") == "running":
            device["status"] = "pending"
            device["result"] = "توقف دستی توسط کاربر"
        if owned and device.get("hamta_status") == "running":
            device["hamta_status"] = "pending"
            device["hamta_result"] = "توقف دستی توسط کاربر"
    estelam_save(data)
    estelam_log("warn" if stopped_pids else "info",
                (f"{len(stopped_pids)} اجرای استعلام متوقف شد"
                 if stopped_pids
                 else "اجرای فعالی برای توقف پیدا نشد"),
                step="مدیریت")
    return {"ok": True, "stopped": bool(stopped_pids),
            "stopped_count": len(stopped_pids),
            "runtime": estelam_runtime()}


def estelam_restart(actor=None):
    """Stop +start-e dobare (hamun scope-e ejra-ye ghabli)."""
    prev = estelam_load()
    previous = prev.get("run_device_id") or ""
    service = prev.get("run_service") or "gomrok"
    estelam_stop()
    time.sleep(0.6)
    result = estelam_start(previous or None, service=service,
                           actor=actor)
    result["restarted"] = True
    return result


def estelam_log(status, message, step="", serial="", device_id=""):
    """Yek rvidaad-e servis-e estelam (panel +robot har do minevisand)."""
    record = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "step": step or "",
        "serial": serial or "",
        "device_id": device_id or "",
        "message": message or "",
    }
    import log_utils
    log_utils.append_jsonl(ESTELAM_LOGS_PATH, record)
    return record


def load_estelam_logs(limit=300):
    out = []
    try:
        if not os.path.exists(ESTELAM_LOGS_PATH):
            return []
        with open(ESTELAM_LOGS_PATH, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        return []
    out.reverse()
    return out[:limit]


def clear_estelam_logs():
    try:
        if os.path.exists(ESTELAM_LOGS_PATH):
            os.remove(ESTELAM_LOGS_PATH)
    except OSError:
        pass
    return {"ok": True}


def filter_profile_logs(logs, profile):
    title = str(profile.get("title") or "")
    national = str(profile.get("national") or "")
    return [log for log in logs if (title and log.get("title") == title) or
            (national and log.get("national") == national)]


def sync_shared_identity(profile):
    """Fields-e moshtarak-e basic/identity yek source darند."""
    profile["national"] = str(profile.get("national") or "").strip()
    profile["birth"] = str(profile.get("birth") or "").strip()
    profile["identity_national"] = profile["national"]
    profile["identity_birth"] = profile["birth"]
    return profile


def clear_logs():
    try:
        if os.path.exists(LOGS_PATH):
            os.remove(LOGS_PATH)
    except Exception:
        pass


PAGE_HEAD = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل ربات گمرک</title>
<link rel="icon" href="data:,">
<style>
  /* IRICA design system — registry operations dashboard (site-1).
     Light by default; dark via html[data-theme="dark"]. Icons are inline
     SVG only (no emoji). Logical properties for RTL. */
  @font-face{
    font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-var.woff2') format('woff2-variations');
    font-weight:100 900;font-style:normal;font-display:swap;
  }
  @font-face{
    font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-Bold.woff2') format('woff2');
    font-weight:700;font-style:normal;font-display:swap;
  }
  :root{
    --bg:#f4f6fb;--card:#ffffff;--card2:#f7f8fd;--line:rgba(27,32,54,.10);
    --line-strong:rgba(27,32,54,.16);--txt:#1b2036;--muted:#5c6484;--faint:#687291;
    --brand:#4460e3;--brand-hover:#3757cf;--brand-soft:rgba(68,96,227,.10);
    --on-brand:#ffffff;--ok:#0c7d4f;--ok-soft:rgba(15,157,99,.12);
    --busy:#b9770e;--busy-soft:rgba(185,119,14,.13);
    --danger:#d93752;--danger-soft:rgba(217,55,82,.10);
    --info:#2f6fd6;--mono:Consolas,ui-monospace,Menlo,monospace;
    --shadow-1:0 1px 2px rgba(16,20,40,.05),0 1px 6px rgba(16,20,40,.04);
    --shadow-2:0 4px 14px rgba(16,20,40,.10),0 1px 3px rgba(16,20,40,.06);
    --ring:0 0 0 3px rgba(68,96,227,.30);
  }
  html[data-theme="dark"]{
    --bg:#101322;--card:#181c2e;--card2:#1f2438;--line:rgba(255,255,255,.08);
    --line-strong:rgba(255,255,255,.14);--txt:#eef1fb;--muted:#aeb6d0;--faint:#848cad;
    --brand:#7d95ff;--brand-hover:#93a7ff;--brand-soft:rgba(125,149,255,.12);
    --on-brand:#0e1330;--ok:#3ad28b;--ok-soft:rgba(58,210,139,.13);
    --busy:#f6b94b;--busy-soft:rgba(246,185,75,.13);
    --danger:#ff6678;--danger-soft:rgba(255,102,120,.13);
    --info:#9db9ff;
    --shadow-1:0 1px 2px rgba(0,0,0,.35),0 1px 6px rgba(0,0,0,.25);
    --shadow-2:0 6px 18px rgba(0,0,0,.45),0 2px 5px rgba(0,0,0,.3);
    --ring:0 0 0 3px rgba(125,149,255,.30);
  }
  * { box-sizing:border-box; }
  html { color-scheme:light; scrollbar-gutter:stable; }
  html[data-theme="dark"] { color-scheme:dark; }
  body {
    margin:0; min-height:100vh; color:var(--txt);
    font-family:Vazirmatn,"Segoe UI",Tahoma,sans-serif;
    font-size:14px; line-height:1.6; -webkit-font-smoothing:antialiased;
    background:radial-gradient(1000px 520px at 85% -12%,rgba(79,107,239,.10),transparent 60%),
               radial-gradient(760px 440px at 6% 6%,rgba(124,92,245,.07),transparent 55%),
               var(--bg);
  }
  html[data-theme="dark"] body {
    background:radial-gradient(1000px 520px at 85% -12%,rgba(125,149,255,.05),transparent 60%),
               var(--bg);
  }
  button,input,textarea { font:inherit; }
  :is(a,button,input,select,textarea):focus-visible { outline:none; box-shadow:var(--ring); }
  .ic { flex:none; vertical-align:-2px; }
  .hidden { display:none !important; }
  /* --- layout: row-reverse keeps the profile rail on the right (RTL) --- */
  .layout { display:flex; flex-direction:row-reverse; min-height:100vh; }
  .main { flex:1; min-width:0; display:flex; flex-direction:column; align-items:center;
    padding:14px clamp(14px,2.5vw,36px) 72px; }
  .card { width:100%; max-width:1180px; }
  /* --- sticky glass header: monogram + version + theme toggle --- */
  .head {
    position:sticky; top:10px; z-index:40; margin-bottom:16px;
    display:grid; grid-template-columns:minmax(0,1fr) auto; gap:10px 14px;
    padding:12px 14px; border:1px solid var(--line); border-radius:14px;
    background:color-mix(in srgb,var(--card) 86%,transparent);
    backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px);
    box-shadow:var(--shadow-1);
  }
  .product-lockup { grid-column:1; grid-row:1; display:flex; align-items:center; gap:12px; min-width:0; }
  .logo { width:40px; height:40px; border-radius:12px; flex:none; display:grid; place-items:center;
    background:linear-gradient(135deg,var(--brand),#7c5cf5); color:var(--on-brand);
    font-size:19px; font-weight:800; box-shadow:var(--shadow-1); }
  .eyebrow { font-size:11px; font-weight:600; color:var(--muted); }
  h1 { font-size:16px; margin:0; }
  .panel-title { font-size:17px; font-weight:750; letter-spacing:-.2px;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .head-actions { grid-column:2; grid-row:1; display:flex; align-items:center; gap:8px;
    flex-wrap:wrap; justify-content:flex-end; }
  .home-btn,.theme-btn {
    display:inline-flex; align-items:center; gap:7px; min-height:34px; padding:6px 12px;
    border:1px solid var(--line); border-radius:10px; background:var(--card); color:var(--txt);
    text-decoration:none; font-size:12px; font-weight:600; font-family:inherit; cursor:pointer;
    box-shadow:var(--shadow-1); white-space:nowrap;
    transition:border-color .15s,color .15s,background .15s;
  }
  .home-btn .ic,.theme-btn .ic { color:var(--muted); }
  .home-btn:hover,.theme-btn:hover { border-color:var(--brand); color:var(--brand); background:var(--brand-soft); }
  .home-btn:hover .ic,.theme-btn:hover .ic { color:var(--brand); }
  .system-close-btn {
    display:inline-flex; align-items:center; gap:7px; min-height:34px; padding:6px 13px;
    border:1px solid var(--danger-soft); border-radius:10px; background:var(--danger-soft);
    color:var(--danger); font-size:12px; font-weight:650; font-family:inherit; cursor:pointer;
    transition:.15s; white-space:nowrap;
  }
  .system-close-btn:hover { background:var(--danger); color:#fff; border-color:var(--danger); }
  .active-profile-banner {
    grid-column:1; grid-row:2; display:block; min-width:0; padding:7px 12px;
    border:1px solid var(--line); border-radius:10px; background:var(--card2);
    color:var(--txt); font-size:12.5px; font-weight:650;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  }
  .active-profile-banner:before { content:""; display:inline-block; width:7px; height:7px;
    border-radius:50%; background:var(--ok); margin-inline-end:8px; }
  .irica-version { grid-column:2; grid-row:2; align-self:center; justify-self:end;
    padding:3px 11px; border:1px solid var(--line); border-radius:999px;
    color:var(--muted); font-size:11px; direction:ltr; white-space:nowrap; }
  /* --- status rail: clickable summary tiles (also filters the list) --- */
  .stats { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:0 0 14px; }
  .stat {
    display:flex; flex-direction:column; align-items:center; justify-content:center; gap:2px;
    min-height:74px; padding:12px 8px; border:1px solid var(--line); border-radius:12px;
    background:var(--card); box-shadow:var(--shadow-1); cursor:pointer; user-select:none;
    transition:border-color .15s,background .15s,box-shadow .15s;
  }
  .stat:hover { border-color:var(--line-strong); box-shadow:var(--shadow-2); }
  .stat.active { border-color:var(--brand); background:color-mix(in srgb,var(--brand) 6%,var(--card));
    box-shadow:0 0 0 2px color-mix(in srgb,var(--brand) 14%,transparent); }
  .stat .n { font-size:22px; font-weight:750; line-height:1.15; font-variant-numeric:tabular-nums; }
  .stat .l { font-size:11px; color:var(--muted); }
  .stat.s-total .n{color:var(--txt)} .stat.s-running .n{color:var(--busy)}
  .stat.s-ready .n{color:var(--brand)} .stat.s-success .n{color:var(--ok)}
  .stat.s-blocked .n{color:var(--danger)}
  /* --- segmented tab bar --- */
  .nav-tabs { display:flex; gap:4px; margin:0 0 16px; padding:4px;
    border:1px solid var(--line); border-radius:12px; background:var(--card); }
  .nav-tab {
    flex:1; display:flex; align-items:center; justify-content:center; gap:7px; min-height:38px;
    padding:8px 10px; border:0; border-radius:9px; background:transparent; color:var(--muted);
    font-family:inherit; font-size:12.5px; font-weight:600; cursor:pointer;
    transition:color .15s,background .15s;
  }
  .nav-tab .ic { color:var(--faint); }
  .nav-tab:hover { color:var(--txt); background:var(--brand-soft); }
  .nav-tab:hover .ic { color:var(--brand); }
  .nav-tab.active { background:var(--brand); color:var(--on-brand);
    box-shadow:0 2px 8px color-mix(in srgb,var(--brand) 30%,transparent); }
  .nav-tab.active .ic { color:var(--on-brand); }
  /* --- views as cards --- */
  #view-form,#view-logs,#view-telegram { padding:20px; border:1px solid var(--line);
    border-radius:14px; background:var(--card); box-shadow:var(--shadow-1); }
  .profile-editor-empty { min-height:340px; display:flex; flex-direction:column; align-items:center;
    justify-content:center; gap:8px; padding:40px; text-align:center; color:var(--muted); }
  .profile-editor-empty .empty-icon { width:48px; height:48px; display:grid; place-items:center;
    margin-bottom:4px; border:1px solid transparent; border-radius:13px;
    background:var(--brand-soft); color:var(--brand); }
  .profile-editor-empty strong { color:var(--txt); font-size:15px; font-weight:650; }
  .profile-editor-empty p { max-width:420px; margin:0; font-size:12.5px; line-height:1.8; }
  .section-title { margin:0 0 14px; padding:0; border:0; background:none;
    color:var(--txt); font-size:15.5px; font-weight:700; }
  .profile-tabs { display:flex; gap:4px; max-width:520px; margin:0 0 18px; padding:4px;
    border-radius:10px; background:var(--card2); }
  .profile-tab { flex:1; padding:8px 12px; border:0; border-radius:8px; background:transparent;
    color:var(--muted); font-family:inherit; font-size:12px; font-weight:600; cursor:pointer;
    transition:.15s; }
  .profile-tab:hover { color:var(--txt); }
  .profile-tab.active { background:var(--card); color:var(--brand); box-shadow:var(--shadow-1); }
  #view-base,#view-identity { display:block; max-width:920px; }
  /* --- forms --- */
  label { display:block; margin:12px 0 5px; font-size:12px; font-weight:600; color:var(--muted); }
  input[type=text],input[type=password],textarea {
    width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:10px;
    background:var(--card2); color:var(--txt); font-family:inherit; font-size:13px; outline:none;
    transition:border-color .15s,box-shadow .15s,background .15s;
  }
  input[type=text]:hover,input[type=password]:hover,textarea:hover { border-color:var(--line-strong); }
  input[type=text]:focus,input[type=password]:focus,textarea:focus {
    border-color:var(--brand); background:var(--card); }
  textarea { min-height:96px; resize:vertical; }
  input.ltr,textarea.ltr { direction:ltr; text-align:left; }
  textarea.ltr { font-family:var(--mono); font-size:12.5px; }
  .hint { font-size:11px; color:var(--muted); margin-top:5px; }
  .sub { color:var(--muted); font-size:12.5px; margin:2px 0; }
  .field-row { display:flex; gap:7px; align-items:stretch; }
  .field-row > input[type=text] { flex:1 1 auto; min-width:0; }
  .paste-btn { flex:0 0 auto; display:inline-flex; align-items:center; justify-content:center; gap:6px;
    min-width:46px; padding:0 11px; border:1px solid var(--line); border-radius:10px;
    background:var(--card); color:var(--muted); font-family:inherit; font-size:11.5px; cursor:pointer;
    transition:.15s; }
  .paste-btn:hover { color:var(--brand); border-color:var(--brand); background:var(--brand-soft); }
  .paste-btn.ok { color:var(--ok); border-color:var(--ok); background:var(--ok-soft); }
  .paste-btn.err { color:var(--danger); border-color:var(--danger); background:var(--danger-soft); }
  .imei-row { display:flex; gap:7px; align-items:center; margin-bottom:8px; }
  .imei-row input { flex:1; }
  .icon-btn { width:40px; height:40px; flex:0 0 auto; display:inline-flex; align-items:center;
    justify-content:center; border:1px solid var(--line); border-radius:10px; background:var(--card2);
    color:var(--muted); font-size:17px; cursor:pointer; transition:.15s; }
  .icon-btn:hover { color:var(--danger); border-color:var(--danger); background:var(--danger-soft); }
  .add-btn { width:max-content; margin-top:4px; padding:8px 12px; border:1px dashed var(--line-strong);
    border-radius:10px; background:transparent; color:var(--brand); font-family:inherit;
    font-size:12.5px; cursor:pointer; transition:.15s; }
  .add-btn:hover { border-color:var(--brand); background:var(--brand-soft); }
  /* --- switches --- */
  .switches { margin-top:16px; display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }
  .switch { display:flex; align-items:center; justify-content:space-between; gap:10px; min-height:64px;
    padding:11px 12px; border:1px solid var(--line); border-radius:12px; background:var(--card2); }
  .switch .t { font-size:12.5px; font-weight:600; }
  .switch .d { font-size:10.5px; color:var(--muted); margin-top:2px; line-height:1.7; }
  .toggle { position:relative; width:44px; height:24px; flex:0 0 auto; }
  .toggle input { display:none; }
  .track { position:absolute; inset:0; border-radius:999px; cursor:pointer;
    background:color-mix(in srgb,var(--muted) 30%,transparent); transition:background .18s; }
  .track:before { content:""; position:absolute; width:18px; height:18px; border-radius:50%;
    background:var(--card); top:3px; inset-inline-start:3px; transition:inset-inline-start .18s;
    box-shadow:0 1px 2px rgba(16,20,40,.25); }
  .toggle input:checked +.track { background:var(--brand); }
  .toggle input:checked +.track:before { inset-inline-start:23px; }
  .toggle.danger input:checked +.track { background:var(--danger); }
  .save { width:auto; min-width:190px; margin-top:20px; padding:11px 18px; border:0; border-radius:10px;
    background:var(--brand); color:var(--on-brand); font-family:inherit; font-size:13px; font-weight:650;
    cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:7px;
    transition:background .15s; box-shadow:var(--shadow-1); }
  .save:hover { background:var(--brand-hover); }
  .save:disabled { opacity:.55; cursor:not-allowed; }
  .toast { margin-top:12px; text-align:center; font-size:12.5px; color:var(--ok); opacity:0;
    transition:opacity .3s; min-height:18px; }
  .toast.show { opacity:1; }
  /* --- profile rail (right side) --- */
  .sidebar { width:400px; flex:0 0 auto; display:flex; flex-direction:column; gap:10px; overflow:hidden;
    padding:16px 14px; background:var(--card); border-inline-start:1px solid var(--line); }
  .side-sec-title { display:flex; align-items:center; justify-content:space-between; gap:8px;
    margin:0 2px; font-size:12px; font-weight:650; color:var(--muted); }
  .side-sec-title > span:last-child { display:inline-flex; align-items:center; gap:8px; }
  #profile-count { font-size:11px; color:var(--faint); }
  .add-prof { width:100%; padding:11px 14px; border:0; border-radius:10px; background:var(--brand);
    color:var(--on-brand); font-family:inherit; font-size:13px; font-weight:650; cursor:pointer;
    transition:background .15s; box-shadow:var(--shadow-1); }
  .add-prof:hover { background:var(--brand-hover); }
  .profile-search-wrap { position:relative; }
  .profile-search-icon { position:absolute; inset-inline-start:12px; top:50%; transform:translateY(-50%);
    color:var(--faint); pointer-events:none; display:inline-flex; }
  #profile-search { width:100%; min-height:40px; padding:9px 12px; padding-inline-start:36px;
    padding-inline-end:32px; border:1px solid var(--line); border-radius:10px; background:var(--card2);
    color:var(--txt); font-family:inherit; font-size:12.5px; outline:none;
    transition:border-color .15s,box-shadow .15s; }
  #profile-search:focus { border-color:var(--brand); box-shadow:var(--ring); }
  .search-clear { position:absolute; inset-inline-end:4px; top:50%; transform:translateY(-50%);
    width:28px; height:28px; border:0; border-radius:8px; background:transparent; color:var(--faint);
    font-size:17px; cursor:pointer; display:none; }
  .search-clear:hover { color:var(--danger); }
  .search-clear.visible { display:block; }
  .view-switch { display:inline-flex; border:1px solid var(--line); border-radius:9px; overflow:hidden;
    background:var(--card); }
  .view-switch button { display:inline-flex; align-items:center; justify-content:center; width:30px;
    height:26px; border:0; background:transparent; color:var(--faint); cursor:pointer; transition:.15s; }
  .view-switch button+button { border-inline-start:1px solid var(--line); }
  .view-switch button:hover { color:var(--txt); }
  .view-switch button.active { background:var(--brand-soft); color:var(--brand); }
  /* profile list frame (internal scroll) */
  #prof-list { flex:1 1 auto; overflow-y:auto; overflow-x:hidden; min-height:200px; padding:6px;
    border:1px solid var(--line); border-radius:14px; background:var(--card2);
    scroll-behavior:smooth; scrollbar-width:thin; }
  #prof-list::-webkit-scrollbar { width:9px; }
  #prof-list::-webkit-scrollbar-thumb { background:color-mix(in srgb,var(--brand) 30%,var(--line));
    border-radius:9px; }
  /* loading skeletons */
  .prof-skeleton { display:flex; align-items:center; gap:10px; padding:12px; margin-bottom:8px;
    border:1px solid var(--line); border-radius:12px; background:var(--card); }
  .prof-skeleton .sk-av, .prof-skeleton .sk-l1, .prof-skeleton .sk-l2 { border-radius:7px;
    background:linear-gradient(100deg,var(--card2) 40%,color-mix(in srgb,var(--brand) 8%,var(--card2)) 50%,var(--card2) 60%);
    background-size:220% 100%; animation:skpulse 1.3s linear infinite; }
  .prof-skeleton .sk-av { width:38px; height:38px; border-radius:50%; flex:0 0 auto; }
  .prof-skeleton .sk-lines { flex:1; min-width:0; }
  .prof-skeleton .sk-l1 { height:12px; width:55%; margin-bottom:7px; }
  .prof-skeleton .sk-l2 { height:9px; width:80%; }
  @keyframes skpulse { from{background-position:120% 0} to{background-position:-120% 0} }
  @media (prefers-reduced-motion: reduce){ .prof-skeleton .sk-av,.prof-skeleton .sk-l1,.prof-skeleton .sk-l2{animation:none} }
  /* empty states */
  .profiles-empty { padding:26px 14px; border:1px dashed var(--line-strong); border-radius:12px;
    text-align:center; color:var(--muted); font-size:12.5px; }
  .profiles-empty .pe-icon { display:inline-flex; margin-bottom:8px; color:var(--faint); }
  .profiles-empty .pe-hint { font-size:11px; margin-top:5px; color:var(--faint); }
  /* --- profile cards: stable anatomy (avatar / identity / status+run / footer) --- */
  .prof-item { position:relative; background:var(--card); border:1px solid var(--line);
    border-radius:12px; padding:12px; margin-bottom:8px; box-shadow:var(--shadow-1);
    transition:border-color .15s,box-shadow .15s,transform .15s; }
  .prof-item:hover { border-color:var(--line-strong); box-shadow:var(--shadow-2); transform:translateY(-1px); }
  .prof-item:focus-within { border-color:var(--brand); }
  .prof-item.active { border-color:var(--brand);
    background:color-mix(in srgb,var(--brand) 5%,var(--card));
    box-shadow:0 0 0 2px color-mix(in srgb,var(--brand) 15%,transparent),var(--shadow-1); }
  .prof-item.active::before { content:""; position:absolute; inset-inline-start:-1px; top:10px; bottom:10px;
    width:3px; border-radius:3px; background:var(--brand); }
  .prof-head { display:flex; align-items:center; gap:10px; min-width:0; }
  .prof-avatar { flex:0 0 auto; width:38px; height:38px; border-radius:50%; cursor:pointer;
    display:flex; align-items:center; justify-content:center; color:#fff; font-size:13.5px; font-weight:700;
    background:linear-gradient(135deg,hsl(var(--av,220) 60% 52%),hsl(calc(var(--av,220) + 42) 60% 42%));
    user-select:none; }
  .prof-item.active .prof-avatar { box-shadow:0 0 0 2px var(--card),0 0 0 4px color-mix(in srgb,var(--ok) 55%,transparent); }
  .prof-id { flex:1 1 auto; min-width:0; }
  .prof-title { font-size:13px; font-weight:700; display:flex; align-items:center; gap:6px; min-width:0; }
  .prof-title-text { flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; cursor:pointer; }
  .prof-title-text:hover { color:var(--brand); }
  .profile-number { display:inline-flex; min-width:22px; height:22px; padding:0 5px; align-items:center;
    justify-content:center; border-radius:7px; background:var(--card2); border:1px solid var(--line);
    color:var(--muted); font-size:10.5px; font-weight:700; }
  .prof-meta { font-size:11px; color:var(--muted); margin-top:3px; direction:ltr; text-align:right;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .mdot { opacity:.55; }
  .imei-chip { display:inline-block; font-size:9.5px; font-weight:700; padding:1px 7px; border-radius:99px;
    border:1px solid var(--line); background:var(--card2); color:var(--muted); }
  .prof-side { flex:0 0 auto; display:flex; flex-direction:column; align-items:flex-end; gap:6px; }
  /* status badge (ready / busy / success / blocked / off) */
  .p-badge { display:inline-flex; align-items:center; gap:5px; font-size:10.5px; font-weight:650;
    padding:3px 9px; border-radius:999px; border:1px solid transparent; white-space:nowrap; }
  .p-badge .d { width:6px; height:6px; border-radius:50%; background:currentColor; flex:none; }
  .p-badge.b-ready{color:var(--brand);background:var(--brand-soft)}
  .p-badge.b-busy{color:var(--busy);background:var(--busy-soft)}
  .p-badge.b-success{color:var(--ok);background:var(--ok-soft)}
  .p-badge.b-blocked{color:var(--danger);background:var(--danger-soft)}
  .p-badge.b-off{color:var(--muted);background:color-mix(in srgb,var(--muted) 10%,transparent)}
  .b-busy .d{animation:pulse-dot 1s steps(2) infinite}
  @keyframes pulse-dot{50%{opacity:.3}}
  /* run / stop / blocked buttons */
  .mini-btn { flex:1 1 60px; display:inline-flex; align-items:center; justify-content:center; gap:5px;
    min-height:30px; padding:6px 8px; border:1px solid var(--line); border-radius:8px; background:var(--card);
    color:var(--muted); font-family:inherit; font-size:10.5px; font-weight:600; cursor:pointer; transition:.15s; }
  .mini-btn:hover { color:var(--txt); border-color:var(--brand); }
  .mini-btn.on { color:var(--ok); border-color:var(--ok); }
  .mini-btn.start { color:#fff; border-color:transparent; background:var(--ok); }
  .mini-btn.start:hover { background:color-mix(in srgb,var(--ok) 86%,#000); }
  .mini-btn.stop { color:#fff; border-color:transparent; background:var(--danger); }
  .mini-btn.stop:hover { background:color-mix(in srgb,var(--danger) 86%,#000); }
  .mini-btn.del { color:var(--danger); border-color:var(--danger-soft); background:var(--danger-soft); }
  .mini-btn.del:hover { color:#fff; border-color:transparent; background:var(--danger); }
  .mini-btn.blocked { color:var(--danger); border-color:color-mix(in srgb,var(--danger) 30%,var(--line));
    background:var(--danger-soft); cursor:not-allowed; opacity:.8; }
  .mini-btn.profile-run-primary { flex:0 0 auto; min-width:106px; min-height:32px; padding:7px 11px;
    border-radius:9px; font-size:11.5px; font-weight:700; white-space:nowrap; }
  /* inline status alerts on a card */
  .prof-alert { display:flex; gap:8px; align-items:flex-start; margin-top:9px; padding:9px 11px;
    border-radius:10px; font-size:11.5px; line-height:1.6; }
  .prof-alert .ai { flex:0 0 auto; display:inline-flex; margin-top:1px; }
  .prof-alert b { font-size:11.5px; }
  .prof-alert .ad { margin-top:2px; opacity:.85; }
  .prof-alert.danger { border:1px solid color-mix(in srgb,var(--danger) 30%,var(--line));
    background:var(--danger-soft); color:var(--danger); }
  .prof-alert.ok { border:1px solid color-mix(in srgb,var(--ok) 30%,var(--line));
    background:var(--ok-soft); color:var(--ok); }
  /* show/hide the running robot browser */
  .prof-browser-row { margin-top:8px; }
  .browser-btn { position:relative; width:100%; display:inline-flex; align-items:center;
    justify-content:center; gap:6px; min-height:32px; padding:7px 10px; border-radius:9px;
    cursor:pointer; font-family:inherit; font-size:11px; font-weight:600; transition:.15s;
    border:1px dashed color-mix(in srgb,var(--brand) 45%,var(--line));
    background:var(--brand-soft); color:var(--brand); }
  .browser-btn:hover { background:color-mix(in srgb,var(--brand) 16%,transparent); border-style:solid; }
  .browser-btn.visible { border-style:solid; border-color:color-mix(in srgb,var(--busy) 45%,var(--line));
    background:var(--busy-soft); color:var(--busy); }
  .browser-btn[disabled] { opacity:.55; cursor:progress; }
  /* artifact chips (receipt / payment / payment link) */
  .prof-foot { display:flex; align-items:center; justify-content:space-between; gap:8px; margin-top:10px;
    flex-wrap:wrap; }
  .artifact-links { display:flex; flex-wrap:wrap; gap:5px; }
  .artifact-links a { display:inline-flex; align-items:center; gap:4px; padding:3px 9px; border-radius:99px;
    border:1px solid color-mix(in srgb,var(--ok) 30%,var(--line)); background:var(--ok-soft);
    color:var(--ok); text-decoration:none; font-size:10.5px; font-weight:650; transition:.15s; }
  .artifact-links a:hover { background:color-mix(in srgb,var(--ok) 18%,transparent); }
  /* icon action row + progressive disclosure (more) */
  .prof-actions { display:flex; flex-wrap:wrap; gap:6px; margin-top:9px; }
  .ibtn { position:relative; width:34px; height:34px; flex:0 0 auto; display:inline-flex;
    align-items:center; justify-content:center; cursor:pointer; border:1px solid var(--line);
    border-radius:9px; background:var(--card); color:var(--faint); transition:.15s; }
  .ibtn:hover { color:var(--txt); border-color:var(--brand); background:var(--brand-soft); }
  .ibtn.on { color:var(--ok); border-color:color-mix(in srgb,var(--ok) 40%,var(--line));
    background:var(--ok-soft); }
  .ibtn.danger:hover { color:var(--danger); border-color:var(--danger); background:var(--danger-soft); }
  .ibtn.warn:hover { color:var(--busy); border-color:var(--busy); background:var(--busy-soft); }
  .ibtn::after { content:attr(data-tip); position:absolute; bottom:calc(100% + 7px); right:50%;
    transform:translate(50%,4px); white-space:nowrap; font-size:11px; font-weight:650;
    padding:5px 9px; border-radius:8px; background:var(--txt); color:var(--bg); opacity:0;
    pointer-events:none; transition:.15s; z-index:40; box-shadow:var(--shadow-2); }
  .ibtn::before { content:''; position:absolute; bottom:calc(100% + 2px); right:50%;
    transform:translateX(50%); border:5px solid transparent; border-top-color:var(--txt);
    opacity:0; pointer-events:none; transition:.15s; z-index:40; }
  .ibtn:hover::after,.ibtn:focus-visible::after { opacity:1; transform:translate(50%,0); }
  .ibtn:hover::before,.ibtn:focus-visible::before { opacity:1; }
  .more-btn { display:inline-flex; align-items:center; justify-content:center; width:34px; height:34px;
    border:1px solid var(--line); border-radius:9px; background:var(--card); color:var(--faint);
    cursor:pointer; font-size:15px; transition:.15s; }
  .more-btn:hover { color:var(--txt); border-color:var(--brand); background:var(--brand-soft); }
  .prof-actions .ibtn:nth-child(n+4) { display:none; }
  .prof-item.expanded .prof-actions .ibtn:nth-child(n+4) { display:inline-flex; }
  /* compact list mode */
  #prof-list.compact .prof-item { padding:8px 10px; margin-bottom:6px; }
  #prof-list.compact .prof-avatar { width:30px; height:30px; font-size:12px; }
  #prof-list.compact .prof-actions,
  #prof-list.compact .prof-foot { display:none; }
  #prof-list.compact .mini-btn.profile-run-primary { min-width:84px; padding:5px 9px; font-size:11px; }
  /* --- logs --- */
  .log-item { background:var(--card2); border:1px solid var(--line); border-radius:12px;
    padding:10px 12px; margin-bottom:8px; border-inline-start:3px solid var(--faint); }
  .log-item.error { border-inline-start-color:var(--danger); }
  .log-item.success { border-inline-start-color:var(--ok); }
  .log-item.warn { border-inline-start-color:var(--busy); }
  .log-item.info { border-inline-start-color:var(--info); }
  .log-top { display:flex; justify-content:space-between; align-items:center; gap:8px;
    font-size:11.5px; color:var(--muted); }
  .log-step { display:inline-flex; align-items:center; gap:6px; min-width:0; }
  .log-item.error .log-step .ic { color:var(--danger); }
  .log-item.success .log-step .ic { color:var(--ok); }
  .log-item.warn .log-step .ic { color:var(--busy); }
  .log-item.info .log-step .ic { color:var(--info); }
  .log-ts { font-size:10.5px; color:var(--faint);
    white-space:nowrap; }
  .log-msg { font-size:12.5px; margin-top:5px; line-height:1.7; }
  .log-serial { direction:ltr; text-align:right; font-size:11.5px; color:var(--brand); margin-top:5px;
    font-family:var(--mono); letter-spacing:.5px; }
  .log-empty { color:var(--muted); text-align:center; padding:32px; font-size:12.5px; }
  /* --- inquiries --- */
  .settings-section,.inquiry-card { background:var(--card2); border:1px solid var(--line);
    border-radius:14px; padding:16px; margin:14px 0; }
  .settings-section h3,.inquiry-card h3 { margin:0 0 8px; font-size:14px; font-weight:700; }
  .inquiry-picker { display:grid; grid-template-columns:repeat(3,1fr); gap:7px; margin:14px 0; }
  .inquiry-picker button { min-height:38px; border:1px solid var(--line); background:var(--card);
    color:var(--muted); border-radius:9px; cursor:pointer; font-family:inherit; font-size:12px;
    font-weight:600; transition:.15s; }
  .inquiry-picker button:hover { border-color:var(--brand); color:var(--brand); }
  .inquiry-picker button.active { background:var(--brand); color:var(--on-brand); border-color:transparent; }
  .inquiry-actions { display:flex; gap:10px; align-items:stretch; flex-wrap:wrap; }
  .inquiry-actions .save { flex:1; min-width:170px; margin-top:0; }
  .inquiry-stop { flex:0 0 auto; min-width:150px; margin-top:0; padding:11px 18px; border:0;
    border-radius:10px; background:var(--danger); color:#fff; font-size:12.5px; font-weight:650;
    cursor:pointer; font-family:inherit; display:inline-flex; align-items:center; justify-content:center;
    gap:7px; transition:.15s; }
  .inquiry-stop:hover { background:color-mix(in srgb,var(--danger) 86%,#000); }
  .inquiry-stop:disabled { opacity:.45; cursor:not-allowed; }
  .device-results { display:grid; gap:10px; margin:12px 0 16px; }
  .device-result { border:1px solid var(--line); border-inline-start:3px solid var(--faint);
    background:var(--card); border-radius:10px; padding:12px; }
  .device-result.good { border-inline-start-color:var(--ok); }
  .device-result.bad { border-inline-start-color:var(--danger); }
  .device-result.running { border-inline-start-color:var(--busy); }
  .device-result-head { display:flex; align-items:center; gap:8px; justify-content:space-between;
    flex-wrap:wrap; }
  .device-result-head .serial { direction:ltr; font-family:var(--mono); font-size:12px; font-weight:700; }
  .device-result-profile { color:var(--muted); font-size:11px; margin-top:5px; }
  .device-result-text { color:var(--muted); font-size:12px; line-height:1.8; white-space:pre-line;
    word-break:break-word; margin-top:7px; }
  .device-result-time { font-size:10.5px; color:var(--faint); margin-top:6px; }
  .exitban-result-card { border-radius:12px; padding:14px 16px; margin:12px 0;
    border:1px solid var(--line); background:var(--card); }
  .exitban-result-card.not_checked { border-color:var(--line); background:var(--card2); color:var(--muted); }
  .exitban-result-card.clear { border-color:color-mix(in srgb,var(--ok) 35%,var(--line));
    background:var(--ok-soft); color:var(--ok); }
  .exitban-result-card.blocked { border-color:color-mix(in srgb,var(--danger) 35%,var(--line));
    background:var(--danger-soft); color:var(--danger); }
  .exitban-result-head { display:flex; justify-content:space-between; gap:12px; align-items:center;
    font-weight:700; }
  .exitban-result-text { margin-top:10px; line-height:1.8; font-size:13px; }
  .exitban-result-time { margin-top:8px; font-size:10.5px; opacity:.75; text-align:right; }
  .soon { display:inline-flex; align-items:center; color:var(--busy); background:var(--busy-soft);
    border-radius:999px; padding:4px 11px; font-size:11px; font-weight:600; }
  /* blocked-profile release panel */
  .release-row { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-top:14px;
    padding:12px 14px; border:1px solid color-mix(in srgb,var(--danger) 30%,var(--line));
    border-radius:12px; background:var(--danger-soft); }
  .release-btn { display:inline-flex; align-items:center; gap:7px; border:0; background:var(--danger);
    color:#fff; border-radius:10px; padding:10px 16px; font-family:inherit; font-size:12.5px;
    font-weight:650; cursor:pointer; transition:.15s; }
  .release-btn:hover { background:color-mix(in srgb,var(--danger) 86%,#000); }
  .release-hint { color:var(--muted); font-size:11.5px; line-height:1.7; }
  /* --- system debug + logs viewer --- */
  .system-debug-card { display:grid; gap:12px; }
  .system-debug-row { display:flex; align-items:center; justify-content:space-between; gap:12px;
    flex-wrap:wrap; }
  .system-debug-help { color:var(--muted); font-size:11.5px; line-height:1.8; }
  .system-log-list { display:grid; gap:7px; max-height:260px; overflow:auto; }
  .system-log-item { display:flex; align-items:center; gap:8px; border:1px solid var(--line);
    border-radius:9px; padding:8px 10px; background:var(--card); }
  .system-log-name { direction:ltr; text-align:left; font-family:var(--mono); font-weight:700;
    font-size:11px; flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .system-log-meta { color:var(--faint); font-size:10px; white-space:nowrap; }
  .system-log-open { display:inline-flex; align-items:center; gap:5px; border:1px solid var(--brand);
    color:var(--brand); background:transparent; border-radius:8px; padding:5px 10px; cursor:pointer;
    font-family:inherit; font-size:11px; font-weight:650; transition:.15s; }
  .system-log-open:hover { background:var(--brand-soft); }
  .system-log-viewer { min-height:230px; max-height:440px; overflow:auto; white-space:pre-wrap;
    word-break:break-word; direction:ltr; text-align:left; padding:12px; border:1px solid var(--line);
    border-radius:10px; background:#0b0f1c; color:#cdd9f0; font-family:var(--mono); font-size:11px;
    line-height:1.7; }
  /* telegram token state (never displayed) */
  .token-badge { display:inline-flex; align-items:center; gap:6px; margin:0 0 8px; padding:5px 11px;
    border-radius:999px; font-size:11.5px; font-weight:650; border:1px solid transparent; }
  .token-badge.ok { color:var(--ok); background:var(--ok-soft); }
  .token-badge.warn { color:var(--busy); background:var(--busy-soft); }
  #tg_token { -webkit-text-security:disc; user-select:none; }
  /* --- cloud sync surface (spec §11): one state pill, never colour alone,
     fixed-height facts so a state change cannot shift the layout --- */
  .cloud-card { display:grid; gap:13px; }
  .cloud-banner { display:none; gap:11px; align-items:flex-start; padding:13px 15px;
    border:1px solid color-mix(in srgb,var(--busy) 45%,var(--line));
    border-inline-start:5px solid var(--busy); border-radius:12px;
    background:var(--busy-soft); color:var(--txt); }
  .cloud-banner.on { display:flex; }
  .cloud-banner .cloud-banner-b { font-size:13.5px; font-weight:750; color:var(--busy); }
  .cloud-banner .cloud-banner-p { margin:6px 0 0; font-size:12px; line-height:1.85; }
  .cloud-state-row { display:flex; align-items:center; gap:10px; flex-wrap:wrap; min-height:32px; }
  .cloud-pill { display:inline-flex; align-items:center; gap:7px; min-inline-size:168px;
    justify-content:flex-start; padding:6px 13px; border-radius:999px; border:1px solid transparent;
    font-size:12px; font-weight:700; }
  .cloud-pill .ic { flex:none; }
  .cloud-pill.ok { color:var(--ok); background:var(--ok-soft);
    border-color:color-mix(in srgb,var(--ok) 30%,var(--line)); }
  .cloud-pill.warn { color:var(--busy); background:var(--busy-soft);
    border-color:color-mix(in srgb,var(--busy) 30%,var(--line)); }
  .cloud-pill.bad { color:var(--danger); background:var(--danger-soft);
    border-color:color-mix(in srgb,var(--danger) 30%,var(--line)); }
  .cloud-pill.mute { color:var(--muted); background:var(--card); border-color:var(--line); }
  .cloud-actor { display:none; align-items:center; gap:7px; font-size:12px; color:var(--muted); }
  .cloud-actor.on { display:inline-flex; }
  .cloud-actor b { color:var(--txt); font-weight:700; }
  .cloud-facts { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:9px; }
  .cloud-fact { display:flex; flex-direction:column; justify-content:space-between; gap:6px;
    min-height:64px; padding:11px 12px; border:1px solid var(--line); border-radius:11px;
    background:var(--card); }
  .cloud-fact-l { font-size:10.5px; color:var(--muted); line-height:1.6; }
  .cloud-fact-v { font-size:15px; font-weight:750; color:var(--txt); word-break:break-word; }
  .cloud-fact-v.cloud-code { direction:ltr; text-align:right; font-family:var(--mono);
    font-size:12.5px; letter-spacing:.4px; color:var(--busy); overflow-wrap:anywhere; }
  .cloud-error { display:none; gap:8px; align-items:flex-start; padding:10px 13px; border-radius:10px;
    border:1px solid color-mix(in srgb,var(--danger) 35%,var(--line));
    background:var(--danger-soft); color:var(--danger); font-size:12.5px; line-height:1.8; }
  .cloud-error.on { display:flex; }
  .cloud-status { min-height:18px; font-size:12px; color:var(--muted); line-height:1.7; }
  .cloud-status.ok { color:var(--ok); }
  .cloud-status.bad { color:var(--danger); }
  .cloud-actions { display:flex; gap:9px; flex-wrap:wrap; }
  .cloud-btn { width:auto; min-width:172px; margin-top:0; padding:11px 16px; border:0;
    border-radius:10px; background:var(--brand); color:var(--on-brand); font-family:inherit;
    font-size:12.5px; font-weight:650; cursor:pointer; display:inline-flex; align-items:center;
    justify-content:center; gap:7px; transition:background .15s,opacity .15s;
    box-shadow:var(--shadow-1); }
  .cloud-btn:hover { background:var(--brand-hover); }
  .cloud-btn[disabled] { opacity:.55; cursor:progress; }
  .cloud-btn.ghost { background:transparent; color:var(--danger);
    border:1px solid color-mix(in srgb,var(--danger) 40%,var(--line)); box-shadow:none; }
  .cloud-btn.ghost:hover { background:var(--danger-soft); }
  .cloud-btn.ghost[disabled] { opacity:.55; }
  .cloud-btn.mini { min-width:auto; padding:6px 12px; font-size:11.5px; }
  .cloud-block { display:grid; gap:10px; padding-top:13px; border-top:1px dashed var(--line); }
  .cloud-block > strong { font-size:12.5px; font-weight:700; }
  .cloud-fields { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:9px; }
  .cloud-field { display:grid; gap:6px; min-width:0; }
  .cloud-field label { font-size:11px; color:var(--muted); }
  .cloud-field input { min-height:40px; }
  .cloud-notice { display:none; gap:8px; align-items:flex-start; padding:10px 13px; border-radius:10px;
    border:1px solid color-mix(in srgb,var(--busy) 40%,var(--line));
    background:var(--busy-soft); color:var(--busy); font-size:12.5px; line-height:1.8; }
  .cloud-notice.on { display:flex; }
  .cloud-conflicts { display:none; gap:9px; padding-top:13px;
    border-top:1px dashed var(--line); }
  .cloud-conflicts.on { display:grid; }
  .cloud-conflict-count { font-size:12.5px; color:var(--muted); margin-bottom:4px; }
  .cloud-conflict-card { display:grid; gap:9px; padding:12px; border:1px solid var(--line); border-radius:10px; background:var(--card2); }
  .cloud-conflict-head { display:flex; justify-content:space-between; align-items:center; font-size:12.5px; }
  .cloud-conflict-table { width:100%; border-collapse:collapse; font-size:11.5px; margin:4px 0; }
  .cloud-conflict-table th, .cloud-conflict-table td { padding:5px 8px; border:1px solid var(--line); text-align:start; }
  .cloud-conflict-table th { background:var(--card); color:var(--muted); font-weight:600; }
  .cloud-conflict-table td.diff-loc { color:var(--brand); }
  .cloud-conflict-table td.diff-srv { color:var(--ok); }
  .cloud-conflict-actions { display:flex; gap:8px; flex-wrap:wrap; }
  @media (max-width:900px){
    .cloud-facts { grid-template-columns:repeat(2,minmax(0,1fr)); }
    .cloud-fields { grid-template-columns:minmax(0,1fr); }
  }
  /* --- read-only profile overview --- */
  .profile-overview { display:grid; gap:16px; }
  .profile-overview-head { display:flex; align-items:flex-start; justify-content:space-between; gap:16px;
    padding:16px; border:1px solid var(--line); border-radius:12px; background:var(--card2); }
  .profile-overview-title { margin:0; font-size:17px; font-weight:750; }
  .profile-overview-meta { margin-top:4px; color:var(--muted); font-size:12px; }
  .profile-overview-edit { display:inline-flex; align-items:center; gap:7px; border:1px solid var(--brand);
    background:transparent; color:var(--brand); border-radius:10px; padding:9px 13px; cursor:pointer;
    font-family:inherit; font-size:12px; font-weight:650; white-space:nowrap; transition:.15s; }
  .profile-overview-edit:hover { background:var(--brand-soft); }
  .readonly-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
  .readonly-field { min-height:72px; padding:12px 14px; border:1px solid var(--line); border-radius:10px;
    background:var(--card2); }
  .readonly-field.wide { grid-column:1/-1; }
  .readonly-label { display:block; color:var(--muted); font-size:10.5px; margin-bottom:6px; }
  .readonly-value { display:block; color:var(--txt); font-size:13.5px; font-weight:650; line-height:1.7;
    word-break:break-word; }
  .readonly-value.ltr { direction:ltr; text-align:right; font-family:var(--mono); letter-spacing:0; }
  .readonly-imeis { display:flex; flex-wrap:wrap; gap:7px; }
  .readonly-imei { direction:ltr; padding:6px 10px; border:1px solid var(--line); border-radius:8px;
    background:var(--card); color:var(--txt); font-family:var(--mono); font-size:12px; font-weight:700; }
  .readonly-flags { display:flex; flex-wrap:wrap; gap:7px; margin-top:10px; }
  .readonly-flag { padding:5px 10px; border-radius:8px; border:1px solid var(--line); color:var(--muted);
    background:var(--card); font-size:11px; }
  /* --- floating log notifications (top-left) --- */
  .lognotif-wrap { position:fixed; top:14px; left:14px; z-index:70; display:flex;
    flex-direction:column; gap:8px; width:min(360px,86vw); pointer-events:none; }
  .lognotif { pointer-events:auto; background:var(--card); border:1px solid var(--line);
    border-inline-start:4px solid var(--brand); border-radius:12px; padding:10px 30px 10px 12px;
    box-shadow:var(--shadow-2); position:relative; opacity:0; transform:translateX(-14px);
    transition:.25s; }
  .lognotif.show { opacity:1; transform:translateX(0); }
  .lognotif.s-success,.lognotif.s-healthy { border-inline-start-color:var(--ok); }
  .lognotif.s-error,.lognotif.s-problem { border-inline-start-color:var(--danger); }
  .lognotif.s-warn,.lognotif.s-retry,.lognotif.s-advanced { border-inline-start-color:var(--busy); }
  .lognotif .t { font-size:12.5px; font-weight:700; display:flex; gap:6px; align-items:center; min-width:0; }
  .lognotif .m { font-size:11.5px; color:var(--muted); margin-top:4px; line-height:1.6;
    max-height:54px; overflow:hidden; }
  .lognotif .x { position:absolute; top:4px; inset-inline-end:5px; border:0; background:transparent;
    color:var(--faint); font-size:15px; cursor:pointer; padding:2px 6px; border-radius:6px; }
  .lognotif .x:hover { color:var(--danger); }
  .lognotif .sn { font-size:10.5px; color:var(--info); direction:ltr; margin-top:3px;
    font-family:var(--mono); }
  .notif-toggle { position:fixed; top:14px; left:14px; z-index:69; display:inline-flex;
    align-items:center; gap:7px; font-size:11.5px; font-weight:600; padding:6px 12px;
    border-radius:999px; border:1px solid var(--line); cursor:pointer; background:var(--card);
    color:var(--muted); font-family:inherit; box-shadow:var(--shadow-1); }
  .notif-toggle:hover { color:var(--txt); border-color:var(--line-strong); }
  /* --- telegram API health toast --- */
  .api-health-toast { position:fixed; top:16px; left:50%; transform:translate(-50%,-18px);
    z-index:2147483000; min-width:min(520px,calc(100vw - 28px)); max-width:720px;
    border:1px solid var(--line); border-inline-start:5px solid var(--busy); border-radius:12px;
    padding:12px 44px 12px 16px; background:var(--card); color:var(--txt); box-shadow:var(--shadow-2);
    opacity:0; pointer-events:none; transition:.22s; font-size:13px; line-height:1.7; }
  .api-health-toast.show { opacity:1; transform:translate(-50%,0); pointer-events:auto; }
  .api-health-toast.ok { border-inline-start-color:var(--ok); }
  .api-health-toast.fail { border-inline-start-color:var(--danger); }
  .api-health-toast .api-meta { display:none; color:var(--muted); font-size:11px;
    /* v1.4.2 (H review): the meta line now carries a Shamsi date — LTR
       direction scrambled it; the URL renders fine under bidi. */
    font-family:var(--mono); }
  .api-health-toast:hover .api-meta { display:block; }
  .api-health-toast button { position:absolute; top:6px; inset-inline-end:8px; border:0;
    background:transparent; color:var(--faint); font-size:20px; cursor:pointer; }
  /* --- responsive --- */
  @media(max-width:1100px){
    .sidebar{width:350px;padding:14px 12px}
    .main{padding:12px 16px 64px}
    .switches{grid-template-columns:1fr}
  }
  @media(max-width:900px){
    .layout{display:block}
    .sidebar{width:auto;max-height:none;border-inline-start:0;border-block-start:1px solid var(--line)}
    #prof-list{max-height:56vh}
    .head{grid-template-columns:minmax(0,1fr);top:8px}
    .head-actions{grid-column:1;grid-row:auto;justify-content:flex-start}
    .active-profile-banner{grid-column:1;grid-row:auto}
    .irica-version{grid-column:1;grid-row:auto;justify-self:start}
    .stats{grid-template-columns:repeat(3,1fr)}
  }
  @media(max-width:640px){
    .panel-title{font-size:15.5px}
    .stats{grid-template-columns:repeat(2,1fr)}
    .stats .stat:first-child{grid-column:1/-1}
    #view-form,#view-logs,#view-telegram{padding:14px}
    .nav-tabs{overflow-x:auto;flex-wrap:nowrap}
    .nav-tab{min-width:118px}
    .readonly-grid{grid-template-columns:1fr}
    .readonly-field.wide{grid-column:auto}
    .profile-overview-head{flex-direction:column}
    .inquiry-picker{grid-template-columns:1fr}
    .device-result-head{align-items:flex-start;flex-direction:column}
    .switches{grid-template-columns:1fr}
    .home-btn span{display:none}
  }
</style>
</head>
<body>
<div id="api-health-toast" class="api-health-toast" role="status" aria-live="polite">
  <button type="button" aria-label="بستن" onclick="this.parentElement.classList.remove('show')">×</button>
  <div id="api-health-message">در حال بررسی ارتباط API تلگرام…</div>
  <div id="api-health-meta" class="api-meta"></div>
</div>
<div class="layout">
  <div class="main">
    <div class="card">
      <header class="head">
        <div class="product-lockup">
          <div class="logo" aria-hidden="true">R</div>
          <div>
            <div class="eyebrow">مرکز عملیات گمرک</div>
            <h1 class="panel-title">داشبورد مدیریت پرونده‌ها</h1>
          </div>
        </div>
        <div class="head-actions">
          <a href="/" class="home-btn" title="بازگشت به انتخاب سامانه" aria-label="بازگشت به انتخاب سامانه"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg><span>سامانه‌ها</span></a>
          <a href="/crm" class="home-btn" title="مدیریت مشتریان و پرونده‌ها" aria-label="مدیریت مشتریان و پرونده‌ها"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span>CRM</span></a>
          <button type="button" id="theme-toggle" class="theme-btn" onclick="toggleTheme()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg><span>حالت تاریک</span></button>
          <button type="button" class="system-close-btn" onclick="closeWholeSystem()" title="همهٔ ربات‌ها متوقف و پنل خاموش می‌شود"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><path d="M12 2v10"/></svg><span>بستن سامانه</span></button>
        </div>
        <div class="active-profile-banner" id="subtitle">پروفایل فعال: در حال بارگذاری...</div>
        <div class="irica-version">نسخه __VERSION__</div>
      </header>
      <div class="stats" id="stats" aria-label="خلاصه وضعیت پروفایل‌ها">
        <div class="stat s-total"   data-filter="all"     title="نمایش همه"><div class="n" id="st-total">۰</div><div class="l">کل</div></div>
        <div class="stat s-running" data-filter="running" title="فیلتر در حال اجرا"><div class="n" id="st-running">۰</div><div class="l">در حال اجرا</div></div>
        <div class="stat s-ready"   data-filter="ready"   title="فیلتر آماده اجرا"><div class="n" id="st-ready">۰</div><div class="l">آماده</div></div>
        <div class="stat s-success" data-filter="success" title="فیلتر ثبت موفق"><div class="n" id="st-success">۰</div><div class="l">موفق</div></div>
        <div class="stat s-blocked" data-filter="blocked" title="فیلتر مسدود"><div class="n" id="st-blocked">۰</div><div class="l">مسدود</div></div>
      </div>
      <div class="nav-tabs" id="main-tabs" role="tablist">
        <div class="nav-tab active" id="tab-form" onclick="viewProfile(activeId)"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5"/></svg>پروفایل انتخاب‌شده</div>
        <div class="nav-tab" id="tab-logs" onclick="showView('logs')"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 6h13M8 12h13M8 18h13"/><path d="M3.5 6h.01M3.5 12h.01M3.5 18h.01"/></svg>لاگ‌ها</div>
        <div class="nav-tab" id="tab-telegram" onclick="showView('telegram')"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>تنظیمات کلی</div>
      </div>
      <div id="view-form"></div>
      <div id="view-logs" class="hidden"></div>
      <div id="view-telegram" class="hidden"></div>
    </div>
  </div>
  <div class="sidebar">
    <div class="side-sec-title"><span>پروفایل‌ها</span><span style="display:inline-flex;align-items:center;gap:8px"><span id="profile-count"></span><span class="view-switch" role="group" aria-label="حالت نمایش لیست"><button type="button" id="vw-comfortable" aria-pressed="true" title="نمایش کارت کامل" onclick="setProfView('comfortable')"><svg class="ic" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button><button type="button" id="vw-compact" aria-pressed="false" title="نمایش فشرده" onclick="setProfView('compact')"><svg class="ic" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6h10M4 12h10M4 18h10"/></svg></button></span></span></div>
    <button class="add-prof" onclick="newProfile()">+ پروفایل جدید</button>
    <div class="profile-search-wrap">
      <span class="profile-search-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg></span>
      <input id="profile-search" type="search" autocomplete="off" placeholder="جستجو: نام، کد ملی، موبایل یا سریال" oninput="filterProfiles(this.value)">
      <button type="button" id="profile-search-clear" class="search-clear" aria-label="پاک کردن جستجو" onclick="clearProfileSearch()">×</button>
    </div>
    <div id="prof-list"><div class="prof-skeleton" aria-hidden="true"><div class="sk-av"></div><div class="sk-lines"><div class="sk-l1"></div><div class="sk-l2"></div></div></div><div class="prof-skeleton" aria-hidden="true"><div class="sk-av"></div><div class="sk-lines"><div class="sk-l1"></div><div class="sk-l2"></div></div></div><div class="prof-skeleton" aria-hidden="true"><div class="sk-av"></div><div class="sk-lines"><div class="sk-l1"></div><div class="sk-l2"></div></div></div></div>
  </div>
</div>
<div id="lognotif-wrap" class="lognotif-wrap" aria-live="polite"></div>
<button type="button" id="notif-toggle" class="notif-toggle" onclick="toggleLogNotif()"></button>
<script>
"""

PAGE_JS = r"""
var STORE = __STORE_JSON__;
var LOGS = __LOGS_JSON__;
var TELEGRAM = __TELEGRAM_JSON__;
var activeId = STORE.active_id;
var logMode='profile';
var statusFilter='all';
var FA_DIGITS='۰۱۲۳۴۵۶۷۸۹';
/* IRICA icon language: inline stroke SVG only (no emoji anywhere on the page). */
var ICON={
  moon:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
  sun:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  user:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5"/></svg>',
  search:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg>',
  power:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><path d="M12 2v10"/></svg>',
  pin:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 21s-7-6.1-7-11a7 7 0 0 1 14 0c0 4.9-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>',
  pencil:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>',
  copy:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2.5"/><path d="M5 15H4.5A2.5 2.5 0 0 1 2 12.5v-8A2.5 2.5 0 0 1 4.5 2h8A2.5 2.5 0 0 1 15 4.5V5"/></svg>',
  trash:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6.5h16"/><path d="M9.5 6.5V4h5v2.5"/><path d="M6.5 6.5l.7 13.2A1.3 1.3 0 0 0 8.5 21h7a1.3 1.3 0 0 0 1.3-1.3l.7-13.2"/><path d="M10 10.5v6.5M14 10.5v6.5"/></svg>',
  play:'<svg class="ic" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.5 4.8 19.4 12 7.5 19.2z"/></svg>',
  stop:'<svg class="ic" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="1.5"/></svg>',
  ban:'<svg class="ic" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M5.7 5.7 18.3 18.3"/></svg>',
  eye:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeOff:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7c1.8 0 3.4.5 4.7 1.3M22 12s-3.6 7-10 7c-1.8 0-3.4-.5-4.7-1.3"/><path d="m3 3 18 18"/></svg>',
  receipt:'<svg class="ic" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 3h14v18l-2.3-1.6-2.3 1.6-2.4-1.6-2.3 1.6L5 21V3z"/><path d="M9 8h6M9 12h6M9 16h4"/></svg>',
  card:'<svg class="ic" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="5" width="20" height="14" rx="2.5"/><path d="M2 10h20"/></svg>',
  link:'<svg class="ic" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 14a5 5 0 0 0 7.1.4l2.1-2.1a5 5 0 0 0-7.1-7.1l-1.2 1.2"/><path d="M14 10a5 5 0 0 0-7.1-.4l-2.1 2.1a5 5 0 0 0 7.1 7.1l1.2-1.2"/></svg>',
  check:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m8.2 12.4 2.6 2.6 5.4-5.6"/></svg>',
  checkCircle:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m8.5 12.2 2.4 2.4 4.8-5"/></svg>',
  xCircle:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/></svg>',
  alert:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2 20h20L12 3z"/><path d="M12 10v4"/><path d="M12 17.2h.01"/></svg>',
  info:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg>',
  dot:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/></svg>',
  minusCircle:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></svg>',
  clipboard:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>',
  save:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8M7 3v5h8"/></svg>',
  unlock:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.9-1"/></svg>',
  lock:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="10" width="15" height="10.5" rx="2.5"/><path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"/><path d="M12 14.5v3"/></svg>',
  bell:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/></svg>',
  bellOff:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8.7 3A6 6 0 0 1 18 8c0 2.5.6 4.3 1.4 5.6"/><path d="M17 17H3s3-2 3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/><path d="m3 3 18 18"/></svg>',
  code:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 17 6-5-6-5"/><path d="M12 19h8"/></svg>',
  pointer:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3l7.07 16.97 2.51-7.39 7.39-2.51L3 3z"/></svg>'
};
function toFa(n){return String(n).replace(/\d/g,function(d){return FA_DIGITS[d];});}
/* Jalali calendar display helpers: stored values stay ISO Gregorian and are
   converted only at render time. Empty/invalid input renders as an em-dash. */
function faDate(iso){
  var d=new Date(String(iso||'').replace(' ','T'));
  if(isNaN(d))return String(iso||'—');
  try{return d.toLocaleDateString('fa-IR-u-ca-persian',{day:'numeric',month:'long',year:'numeric'});}catch(e){return String(iso||'—');}
}
function faDateTime(iso){
  var d=new Date(String(iso||'').replace(' ','T'));
  if(isNaN(d))return String(iso||'—');
  try{return d.toLocaleDateString('fa-IR-u-ca-persian',{day:'numeric',month:'long',year:'numeric'})+'، '+d.toLocaleTimeString('fa-IR',{hour:'2-digit',minute:'2-digit'});}catch(e){return String(iso||'—');}
}
function statusOf(p){
  if(p.run_status==='busy')             return {key:'running',cls:'b-busy',   label:'در حال اجرا'};
  if(p.registration_status==='success') return {key:'success',cls:'b-success',label:'موفق'};
  if(p.registration_status==='blocked') return {key:'blocked',cls:'b-blocked',label:'مسدود'};
  if(!p.enabled)                        return {key:'off',    cls:'b-off',    label:'غیرفعال'};
  return {key:'ready',cls:'b-ready',label:'آماده'};
}
function setStatusFilter(f){
  statusFilter=(statusFilter===f&&f!=='all')?'all':f;
  renderProfiles();
}
var savedTheme=localStorage.getItem('irica-theme')||'light';
document.documentElement.setAttribute('data-theme',savedTheme);
function toggleTheme(){
  var dark=document.documentElement.getAttribute('data-theme')==='dark';
  var next=dark?'light':'dark'; document.documentElement.setAttribute('data-theme',next);
  localStorage.setItem('irica-theme',next); updateThemeButton();
}
function updateThemeButton(){
  var btn=document.getElementById('theme-toggle'); if(!btn)return;
  var dark=document.documentElement.getAttribute('data-theme')==='dark';
  btn.innerHTML=(dark?ICON.sun:ICON.moon)+'<span>'+(dark?'حالت روشن':'حالت تاریک')+'</span>';
}
setInterval(function(){fetch('/state').then(function(r){return r.json();}).then(function(s){if(s&&s.error){return;}STORE=s;renderProfiles();}).catch(function(){});},3000);

function getProf(id){ return STORE.profiles.find(function(p){return p.id===id;}); }

function profileRunButton(p,extraClass){
  var cls='mini-btn '+(extraClass||'');
  if(p.registration_status==='blocked') return '<button class="'+cls+' blocked" disabled>'+ICON.ban+' غیرقابل ورود</button>';
  if(p.run_status==='busy') return '<button class="'+cls+' stop" onclick="stopProfile(\''+p.id+'\','+p.runner_pid+')">'+ICON.stop+' توقف ربات</button>';
  if(p.registration_status!=='success') return '<button class="'+cls+' start" onclick="startProfile(\''+p.id+'\')">'+ICON.play+' شروع به کار</button>';
  return '';
}

/* Dokme-ye namayesh/makhfi-kardan-e morurgar (faghat baraye profile-e dar-hal-e-ejra).
   Morurgar hamishe headed ast vali be tore pishfarz off-screen negah dashte mishavad. */
function profileBrowserButton(p){
  if(p.run_status!=='busy') return '';
  var visible=Boolean(p.browser_visible);
  return '<button type="button" class="browser-btn'+(visible?' visible':'')+'" '+
    'data-tip="'+(visible?'مرورگر روی صفحه است — کلیک: مخفی کردن برای صرفه‌جویی منابع':'مرورگر مخفی است — کلیک: نمایش برای مدیریت زنده')+'" '+
    'onclick="setBrowserVisible(\''+p.id+'\','+(!visible)+')">'+
    (visible?ICON.eyeOff+' مخفی کردن مرورگر':ICON.eye+' نمایش مرورگر')+'</button>';
}

function setBrowserVisible(id,visible){
  var buttons=document.querySelectorAll('[data-profile-id="'+id+'"] .browser-btn');
  buttons.forEach(function(b){b.disabled=true;});
  fetch('/browser-visibility',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:id,visible:visible})})
  .then(function(r){return r.json().then(function(d){return {ok:r.ok,data:d};});})
  .then(function(res){
    if(!res.ok){alert(res.data.error||'تغییر وضعیت مرورگر انجام نشد');buttons.forEach(function(b){b.disabled=false;});return;}
    var p=getProf(id); if(p)p.browser_visible=Boolean(res.data.browser_visible);
    renderProfiles();
  })
  .catch(function(){buttons.forEach(function(b){b.disabled=false;});});
}

function normalizeProfileSearch(value){
  var fa='۰۱۲۳۴۵۶۷۸۹', ar='٠١٢٣٤٥٦٧٨٩';
  return String(value||'').trim().toLowerCase().replace(/[۰-۹]/g,function(c){return fa.indexOf(c);}).replace(/[٠-٩]/g,function(c){return ar.indexOf(c);});
}

function filterProfiles(value){
  var input=document.getElementById('profile-search');
  if(input && input.value!==value) input.value=value;
  var clear=document.getElementById('profile-search-clear'); if(clear)clear.classList.toggle('visible',Boolean(value));
  renderProfiles();
}

function clearProfileSearch(){
  var input=document.getElementById('profile-search'); if(input)input.value='';
  filterProfiles(''); if(input)input.focus();
}

function profileMatchesSearch(p,query){
  if(!query)return true;
  var fields=[p.title,p.national,p.mobile].concat(p.imeis||[]);
  return fields.some(function(value){return normalizeProfileSearch(value).indexOf(query)!==-1;});
}

function renderProfiles(){
  var el=document.getElementById('prof-list'); el.innerHTML='';
  el.classList.toggle('compact',profView==='compact');
  updateProfViewButtons();
  var input=document.getElementById('profile-search');
  var query=normalizeProfileSearch(input?input.value:'');
  var all=STORE.profiles||[];
  // ---- stats ----
  var counts={all:all.length,running:0,ready:0,success:0,blocked:0,off:0};
  all.forEach(function(p){counts[statusOf(p).key]++;});
  [['st-total',counts.all],['st-running',counts.running],['st-ready',counts.ready],['st-success',counts.success],['st-blocked',counts.blocked]].forEach(function(pair){
    var node=document.getElementById(pair[0]); if(node)node.textContent=toFa(pair[1]);
  });
  document.querySelectorAll('#stats .stat').forEach(function(s){s.classList.toggle('active',s.getAttribute('data-filter')===statusFilter);});
  // ---- filter (status +search) ----
  var profiles=STORE.profiles.slice().reverse().filter(function(p){
    if(statusFilter!=='all' && statusOf(p).key!==statusFilter) return false;
    return profileMatchesSearch(p,query);
  });
  var count=document.getElementById('profile-count'); if(count)count.textContent=(profiles.length!==all.length)?(toFa(profiles.length)+' از '+toFa(all.length)):(toFa(all.length)+' مورد');
  if(!profiles.length){
    el.innerHTML=(all.length?'<div class="profiles-empty"><div class="pe-icon" aria-hidden="true">'+ICON.search+'</div>پروفایلی با این مشخصات پیدا نشد.<div class="pe-hint">عبارت جستجو یا فیلتر وضعیت را تغییر دهید.</div></div>'
                           :'<div class="profiles-empty"><div class="pe-icon" aria-hidden="true">'+ICON.user+'</div>هنوز پروفایلی ثبت نشده است.<div class="pe-hint">با دکمه «+پروفایل جدید» اولین پروفایل را بسازید.</div></div>');
    return;
  }
  profiles.forEach(function(p){
    var isActive=(p.id===activeId);
    var profileNumber=STORE.profiles.indexOf(p)+1;
    var st=statusOf(p);
    var imei=(p.imeis&&p.imeis[0])||'';
    var d=document.createElement('div');
    d.className='prof-item'+(isActive?' active':'');
    d.setAttribute('data-profile-id',p.id);
    // stable anatomy: avatar+identity+side(status,run) -> alerts -> footer(artifacts) -> actions
    var artifacts=(p.receipt_screenshot?'<a target="_blank" href="/artifact?id='+encodeURIComponent(p.id)+'&kind=receipt">'+ICON.receipt+' رسید</a>':'')+
      (p.payment_screenshot?'<a target="_blank" href="/artifact?id='+encodeURIComponent(p.id)+'&kind=payment">'+ICON.card+' پرداخت</a>':'')+
      (p.payment_link?'<a target="_blank" href="'+escHtml(p.payment_link)+'">'+ICON.link+' لینک پرداخت</a>':'');
    var alerts=
      (p.registration_status==='blocked'?'<div class="prof-alert danger"><span class="ai">'+ICON.ban+'</span><div><b>غیرقابل ورود — تلاش متوقف شد</b><div class="ad">'+escHtml(p.runtime_error||'خطای غیرقابل ورود ثبت شده است')+'</div></div></div>':'')+
      (p.registration_status==='success'?'<div class="prof-alert ok"><span class="ai">'+ICON.check+'</span><div><b>موفق — مرحله پرداخت</b></div></div>':'');
    var browserRow=(p.run_status==='busy'?'<div class="prof-browser-row">'+profileBrowserButton(p)+'</div>':'');
    d.innerHTML=
      '<div class="prof-head">'+
        '<div class="prof-avatar" style="--av:'+avatarColorOf(p)+'" aria-hidden="true" onclick="viewProfile(\''+p.id+'\')">'+escHtml(initialsOf(p))+'</div>'+
        '<div class="prof-id">'+
          '<div class="prof-title"><span class="profile-number" title="شماره پروفایل">'+toFa(profileNumber)+'</span>'+
          '<span class="prof-title-text" onclick="viewProfile(\''+p.id+'\')" title="'+escHtml(p.title||p.national||'بدون عنوان')+'">'+escHtml(p.title||p.national||'بدون عنوان')+'</span></div>'+
          '<div class="prof-meta">'+escHtml(p.national||'—')+(p.mobile?'<span class="mdot"> • </span>'+escHtml(p.mobile):'')+
          (imei?'<span class="mdot"> • </span><span class="imei-chip" title="سریال اول: '+escHtml(imei)+'">'+escHtml(imei)+'</span>':'')+'</div>'+
        '</div>'+
        '<div class="prof-side"><span class="p-badge '+st.cls+'"><span class="d"></span>'+st.label+'</span>'+profileRunButton(p,'profile-run-primary')+'</div>'+
      '</div>'+
      alerts+browserRow+
      (artifacts?'<div class="prof-foot"><div class="artifact-links">'+artifacts+'</div></div>':'')+
      '<div class="prof-actions">'+
        '<button class="ibtn'+(p.enabled?' on':'')+'" data-tip="'+(p.enabled?'فعال است — کلیک: غیرفعال کردن':'غیرفعال است — کلیک: فعال کردن')+'" '+
          'onclick="toggleProfile(\''+p.id+'\','+(!p.enabled)+')">'+ICON.power+'</button>'+
        '<button class="ibtn'+(isActive?' on':'')+'" data-tip="'+(isActive?'پروفایل فعال جاری':'انتخاب به‌عنوان پروفایل فعال')+'" '+
          'onclick="activateProfile(\''+p.id+'\')">'+ICON.pin+'</button>'+
        '<button class="ibtn" data-tip="مشاهده اطلاعات پروفایل" onclick="viewProfile(\''+p.id+'\')">'+ICON.user+'</button>'+
        '<button class="ibtn" data-tip="ویرایش اطلاعات پروفایل" onclick="editProfile(\''+p.id+'\')">'+ICON.pencil+'</button>'+
        '<button class="ibtn" data-tip="کپی گرفتن از این پروفایل" onclick="cloneProfile(\''+p.id+'\')">'+ICON.copy+'</button>'+
        '<button class="ibtn danger" data-tip="حذف کامل این پروفایل" onclick="deleteProfile(\''+p.id+'\')">'+ICON.trash+'</button>'+
        '<button type="button" class="more-btn" data-tip="اکشن‌های بیشتر" aria-expanded="false" onclick="toggleCardMore(this)">⋯</button>'+
      '</div>';
    el.appendChild(d);
  });
}

/* avatar: رنگ پایدار از کدملی/نام + حروف اول نام */
function avatarColorOf(p){
  var s=String(p.national||p.title||p.id||'x');
  var h=0; for(var i=0;i<s.length;i++){h=(h*31+s.charCodeAt(i))>>>0;}
  return h%360;
}
function initialsOf(p){
  var t=String(p.title||'').trim();
  if(t)return t.slice(0,2);
  var n=String(p.national||'').trim();
  return n?n.slice(0,2):'؟';
}
/* progressive disclosure: ویرایش/کپی/حذف پشت دکمه ⋯ */
function toggleCardMore(btn){
  var card=btn.closest('.prof-item'); if(!card)return;
  card.classList.toggle('expanded');
  var open=card.classList.contains('expanded');
  btn.textContent=open?'×':'⋯';
  btn.setAttribute('aria-expanded',open?'true':'false');
  btn.setAttribute('data-tip',open?'بستن اکشن‌ها':'اکشن‌های بیشتر');
}
/* حالت نمایش لیست: کارت کامل یا فشرده (persist) */
var profView=localStorage.getItem('irica-profview')||'comfortable';
function setProfView(v){
  profView=(v==='compact')?'compact':'comfortable';
  localStorage.setItem('irica-profview',profView);
  renderProfiles();
}
function updateProfViewButtons(){
  ['vw-comfortable','vw-compact'].forEach(function(id){
    var b=document.getElementById(id); if(!b)return;
    var on=(id==='vw-compact')===(profView==='compact');
    b.classList.toggle('active',on);
    b.setAttribute('aria-pressed',on?'true':'false');
  });
}

function escHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/* ---- paste-e kenar-e har kadar-e vorudi ---------------------------------- */
function withPaste(inputHtml){
  return '<div class="field-row">'+inputHtml+
    '<button type="button" class="paste-btn" title="پیست از کلیپ‌بورد" aria-label="پیست کردن در این کادر" onclick="pasteInto(this)">'+
    '<span class="paste-ico" aria-hidden="true">'+ICON.clipboard+'</span><span class="paste-label">پیست</span></button></div>';
}

/* Text-e clipboard ra tamiz mikonad: raqam-haye farsi/arabi -> ASCII,
   hazf-e mark-haye jahat/ZWNJ va faseleha (baraye field-haye adadi-ye .ltr). */
function normalizePasted(text,isNumericField){
  var out=String(text==null?'':text).replace(/[\u200b-\u200f\u202a-\u202e\ufeff]/g,'');
  out=out.replace(/[۰-۹]/g,function(c){return String('۰۱۲۳۴۵۶۷۸۹'.indexOf(c));})
         .replace(/[٠-٩]/g,function(c){return String('٠١٢٣٤٥٦٧٨٩'.indexOf(c));});
  out=out.replace(/[\r\n\t]+/g,' ').trim();
  if(isNumericField) out=out.replace(/\s+/g,'');
  return out;
}

function flashPasteBtn(btn,cls,label){
  var labelEl=btn.querySelector('.paste-label'); var previous=labelEl?labelEl.textContent:'';
  btn.classList.remove('ok','err'); btn.classList.add(cls);
  if(labelEl&&label)labelEl.textContent=label;
  setTimeout(function(){btn.classList.remove(cls); if(labelEl&&label)labelEl.textContent=previous;},1400);
}

function applyPastedValue(input,btn,raw){
  var isNumeric=input.classList.contains('ltr');
  var value=normalizePasted(raw,isNumeric);
  if(!value){ flashPasteBtn(btn,'err','خالی'); return; }
  input.value=value;
  input.dispatchEvent(new Event('input',{bubbles:true}));
  input.focus();
  flashPasteBtn(btn,'ok','✓');
}

function pasteInto(btn){
  var row=btn.closest('.field-row')||btn.parentNode;
  var input=row?row.querySelector('input[type=text]'):null;
  if(!input)return;
  if(!navigator.clipboard||!navigator.clipboard.readText){
    input.focus(); input.select();
    btn.title='مرورگر اجازه خواندن کلیپ‌بورد نمی‌دهد — با Ctrl+V پیست کنید';
    flashPasteBtn(btn,'err','Ctrl+V'); return;
  }
  navigator.clipboard.readText().then(function(text){
    applyPastedValue(input,btn,text);
  }).catch(function(){
    input.focus(); input.select();
    btn.title='دسترسی به کلیپ‌بورد رد شد — با Ctrl+V پیست کنید';
    flashPasteBtn(btn,'err','Ctrl+V');
  });
}

function buildExitbanResult(p){
  var status=p.exitban_status||'not_checked';
  var titles={not_checked:'هنوز استعلامی انجام نشده است',clear:'ممنوع‌الخروج نیست',blocked:'ممنوع‌الخروج است'};
  var icons={not_checked:ICON.minusCircle,clear:ICON.checkCircle,blocked:ICON.alert};
  var text=p.exitban_result||'پس از انجام استعلام، نتیجه رسمی در این کادر نمایش داده می‌شود.';
  return '<div id="exitban-result-card" class="exitban-result-card '+status+'">'+
    '<div class="exitban-result-head"><span>'+icons[status]+' '+titles[status]+'</span></div>'+
    '<div class="exitban-result-text">'+escHtml(text)+'</div>'+
    (p.exitban_checked_at?'<div class="exitban-result-time">'+escHtml(faDateTime(p.exitban_checked_at))+'</div>':'')+'</div>';
}

function renderProfileEditorEmpty(){
  var el=document.getElementById('view-form'); if(!el)return;
  el.innerHTML='<div class="profile-editor-empty"><div class="empty-icon" aria-hidden="true">'+ICON.pencil+'</div><strong>پروفایلی برای ویرایش انتخاب نشده</strong><p>برای ویرایش، یک پروفایل را از منوی سمت راست انتخاب کنید.</p></div>';
  var subtitle=document.getElementById('subtitle');
  if(subtitle)subtitle.textContent='برای شروع، یک پروفایل را انتخاب کنید';
}

function readonlyField(label,value,cls,wide){
  return '<div class="readonly-field'+(wide?' wide':'')+'"><span class="readonly-label">'+escHtml(label)+'</span><span class="readonly-value '+(cls||'')+'">'+escHtml(value||'ثبت نشده')+'</span></div>';
}
function buildProfileOverview(p){
  var imeis=(p.imeis||[]).map(function(v){return '<span class="readonly-imei">'+escHtml(v)+'</span>';}).join('')||'<span class="readonly-value">سریالی ثبت نشده است</span>';
  return '<div class="profile-overview">'+
    '<div class="profile-overview-head"><div><h2 class="profile-overview-title">'+escHtml(p.title||p.national||'بدون عنوان')+'</h2><div class="profile-overview-meta">نمایش اطلاعات ثبت‌شده این پروفایل</div></div><button type="button" class="profile-overview-edit" onclick="editProfile(\''+p.id+'\')">'+ICON.pencil+' ویرایش اطلاعات</button></div>'+
    '<div class="profile-tabs">'+
      '<button type="button" aria-label="تب اطلاعات پایه" class="profile-tab active" onclick="showProfileSection(\'base\')">اطلاعات پایه</button>'+
      '<button type="button" aria-label="تب اطلاعات هویتی" class="profile-tab" onclick="showProfileSection(\'identity\')">اطلاعات هویتی</button>'+
      '<button type="button" aria-label="تب استعلامات" class="profile-tab" onclick="showProfileSection(\'inquiries\')">استعلامات</button>'+
    '</div>'+
    '<div id="view-base"><div class="readonly-grid">'+
      readonlyField('عنوان پروفایل',p.title||'')+readonlyField('کد ملی',p.national||'','ltr')+
      readonlyField('تاریخ تولد',p.birth||'','ltr')+readonlyField('شماره موبایل',p.mobile||'','ltr')+
      '<div class="readonly-field wide"><span class="readonly-label">سریال‌های IMEI</span><div class="readonly-imeis">'+imeis+'</div></div>'+
    '</div><div class="readonly-flags"><span class="readonly-flag">'+(p.no_confirm_check?'تأیید خودکار خاموش':'تأیید خودکار روشن')+'</span><span class="readonly-flag">'+(p.debugging?'حالت دیباگ روشن':'حالت دیباگ خاموش')+'</span><span class="readonly-flag">'+(p.manual_manage?'مدیریت دستی روشن':'مدیریت دستی خاموش')+'</span></div></div>'+
    '<div id="view-identity" class="hidden"><div class="section-title">اطلاعات هویتی</div><div class="readonly-grid">'+
      readonlyField('نام',p.first_name||'')+readonlyField('نام خانوادگی',p.last_name||'')+
      readonlyField('نام پدر',p.father_name||'')+readonlyField('شماره شناسنامه',p.birth_certificate_no||'','ltr')+
      readonlyField('کد ملی',p.national||'','ltr')+readonlyField('تاریخ تولد',p.birth||'','ltr')+
    '</div></div>'+
    '<div id="view-profile-inquiries" class="hidden">'+buildDeviceInquiryPanel(p)+'<div class="inquiry-card"><h3>استعلام ممنوع‌الخروجی</h3>'+buildExitbanResult(p)+'<button type="button" class="save" onclick="runExitbanInquiry(activeId)">استعلام آنلاین خروج از کشور</button><div id="exitban-status" class="hint"></div></div><div class="inquiry-card"><h3>استعلام اقساط و وام پرداخت‌نشده</h3><span class="soon">به‌زودی</span></div></div>'+
  '</div>';
}
function viewProfile(id){
  activeId=id;
  var p=getProf(id); if(!p){renderProfileEditorEmpty();return;}
  document.getElementById('view-form').innerHTML=buildProfileOverview(p);
  setActiveBanner(p,'پروفایل انتخاب‌شده');
  renderProfiles();
  showView('form');
}

function buildForm(p){
  var imeis=(p.imeis&&p.imeis.length)?p.imeis:[''];
  return '<form id="f" onsubmit="saveProfile(event)">'+
    '<div class="section-title">اطلاعات پایه</div>'+
    '<div class="profile-tabs">'+
      '<button type="button" aria-label="تب اطلاعات پایه" class="profile-tab active" onclick="showProfileSection(\'base\')">اطلاعات پایه</button>'+
      '<button type="button" aria-label="تب اطلاعات هویتی" class="profile-tab" onclick="showProfileSection(\'identity\')">اطلاعات هویتی</button>'+
      '<button type="button" aria-label="تب استعلامات" class="profile-tab" onclick="showProfileSection(\'inquiries\')">استعلامات</button>'+
    '</div>'+
    '<div id="view-base">'+
    withPaste('<input type="text" name="title" value="'+escHtml(p.title||'')+'" placeholder="مثلاً علی رضایی">')+
    '<label>کد ملی</label>'+
    withPaste('<input type="text" name="national" class="ltr" value="'+escHtml(p.national||'')+'" placeholder="۱۰ رقم" oninput="syncSharedField(\'identity_national\',this.value)">')+
    '<label>تاریخ تولد (شمسی)</label>'+
    withPaste('<input type="text" name="birth" class="ltr" value="'+escHtml(p.birth||'')+'" placeholder="۱۳۶۶/۱۰/۱" oninput="syncSharedField(\'identity_birth\',this.value)">')+
    '<label>شماره موبایل</label>'+
    withPaste('<input type="text" name="mobile" class="ltr" value="'+escHtml(p.mobile||'')+'" placeholder="۰۹۱۴...">')+
    '<label>کدهای IMEI</label>'+
    '<div id="imeis"></div>'+
    '<button type="button" class="add-btn" onclick="addImei(\'\')">+افزودن IMEI</button>'+
    '<div class="switches">'+
      '<div class="switch"><div><div class="t">زدن تیک «قبول دارم»</div><div class="d">اگر خاموش باشد تیک زده نمی‌شود</div></div>'+
        '<label class="toggle"><input type="checkbox" id="confirm_on"'+(p.no_confirm_check?'':' checked')+'><span class="track"></span></label></div>'+
      '<div class="switch"><div><div class="t">'+ICON.code+' حالت دیباگ</div><div class="d">قبل از هر مرحله مکث می‌کند</div></div>'+
        '<label class="toggle"><input type="checkbox" id="debug_on"'+(p.debugging?' checked':'')+'><span class="track"></span></label></div>'+
      '<div class="switch"><div><div class="t">'+ICON.pointer+' مدیریت دستی</div><div class="d">صفحه اول باز می‌شود؛ خودت تا کد ۴رقمی برو، تیک بزن، دکمه بالای صفحه را بزن → brute-force</div></div>'+
        '<label class="toggle"><input type="checkbox" id="manual_on"'+(p.manual_manage?' checked':'')+'><span class="track"></span></label></div>'+
    '</div>'+
    '</div>'+
    '<div id="view-identity" class="hidden">'+
    '<div class="section-title">اطلاعات هویتی</div>'+
    '<label>نام</label>'+withPaste('<input type="text" name="first_name" value="'+escHtml(p.first_name||'')+'">')+
    '<label>نام خانوادگی</label>'+withPaste('<input type="text" name="last_name" value="'+escHtml(p.last_name||'')+'">')+
    '<label>نام پدر</label>'+withPaste('<input type="text" name="father_name" value="'+escHtml(p.father_name||'')+'">')+
    '<label>تاریخ تولد</label>'+withPaste('<input type="text" name="identity_birth" class="ltr" value="'+escHtml(p.birth||'')+'" oninput="syncSharedField(\'birth\',this.value)">')+
    '<label>شماره شناسنامه</label>'+withPaste('<input type="text" name="birth_certificate_no" class="ltr" value="'+escHtml(p.birth_certificate_no||'')+'">')+
    '<label>کد ملی</label>'+withPaste('<input type="text" name="identity_national" class="ltr" value="'+escHtml(p.national||'')+'" oninput="syncSharedField(\'national\',this.value)">')+
    '<label>شمارهٔ گذرنامه</label>'+withPaste('<input type="text" name="passport" class="ltr" value="'+escHtml(p.passport||'')+'">')+
    '<div class="hint">شمارهٔ گذرنامهٔ مسافر — برای فرآیند ثبت (اختیاری)</div>'+
    '</div>'+
    '<div id="view-profile-inquiries" class="hidden">'+
      buildDeviceInquiryPanel(p)+
      '<div class="inquiry-card"><h3>استعلام ممنوع‌الخروجی</h3>'+buildExitbanResult(p)+'<button type="button" class="save" onclick="runExitbanInquiry(activeId)">استعلام آنلاین خروج از کشور</button><div id="exitban-status" class="hint"></div></div>'+
      '<div class="inquiry-card"><h3>استعلام اقساط و وام پرداخت‌نشده</h3><span class="soon">به‌زودی</span></div>'+
    '</div>'+
    (p.registration_status==='blocked'?'<div class="release-row"><button type="button" class="release-btn" onclick="releaseBlockedProfile(activeId)">'+ICON.unlock+' آزادسازی و شروع مجدد</button><span class="release-hint">پروفایل آزاد می‌شود و بعد از ذخیرهٔ ویرایش می‌توانید دوباره ربات را اجرا کنید</span></div>':'')+
    '<button type="submit" class="save">'+ICON.save+' ذخیره پروفایل</button>'+
    '<div class="toast" id="toast"></div>'+
  '</form>';
}

function releaseBlockedProfile(id){
  if(!confirm('آزادسازی این پروفایل و پاک شدن دلیل مسدودی؟')) return;
  fetch('/release-blocked',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
    .then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data};});})
    .then(function(res){
      if(!res.ok){alert(res.data.message||res.data.error||'آزادسازی انجام نشد');return;}
      STORE=res.data.store||STORE;
      if(res.data.store){STORE=res.data.store;activeId=STORE.active_id;}
      var t=document.getElementById('toast');
      if(t){t.style.color='var(--ok)';t.textContent='✓ '+res.data.message;t.classList.add('show');
        setTimeout(function(){t.classList.remove('show');},3500);}
      renderProfiles();
      var p=getProf(id); if(p){editProfile(id);}
    })
    .catch(function(){alert('ارتباط با پنل برقرار نشد');});
}

function addImei(val){
  var wrap=document.getElementById('imeis');
  var row=document.createElement('div'); row.className='imei-row';
  row.innerHTML='<input type="text" class="ltr" placeholder="۱۵ رقم" value="'+escHtml(val||'')+'">'+
    '<button type="button" class="paste-btn" title="پیست از کلیپ‌بورد" aria-label="پیست کردن در این کادر" onclick="pasteInto(this)"><span class="paste-ico" aria-hidden="true">'+ICON.clipboard+'</span><span class="paste-label">پیست</span></button>'+
    '<button type="button" class="icon-btn" title="حذف">×</button>';
  row.querySelector('.icon-btn').onclick=function(){row.remove();};
  wrap.appendChild(row);
}

function showProfileSection(section){
  var target = section==='inquiries' ? 'profile-inquiries' : section;
  ['base','identity','profile-inquiries'].forEach(function(name){
    var el=document.getElementById('view-'+name); if(el) el.classList.toggle('hidden',name!==target);
  });
  document.querySelectorAll('.profile-tab').forEach(function(btn){btn.classList.toggle('active',btn.getAttribute('aria-label') === 'تب '+(section==='base'?'اطلاعات پایه':section==='identity'?'اطلاعات هویتی':'استعلامات'));});
}

function syncSharedField(name,value){
  var f=document.getElementById('f'); if(f&&f.elements[name]) f.elements[name].value=value;
}

function setActiveBanner(p,prefix){
  var el=document.getElementById('subtitle'); if(!el||!p)return;
  el.textContent=(prefix||'پروفایل فعال')+': '+(p.title||p.national||'بدون عنوان');
}

function editProfile(id){
  activeId=id;
  var p=getProf(id)||{};
  document.getElementById('view-form').innerHTML=buildForm(p);
  setActiveBanner(p,'ویرایش پروفایل');
  (p.imeis&&p.imeis.length?p.imeis:['']).forEach(addImei);
  renderProfiles();
  showView('form');
}

function activateProfile(id){
  fetch('/activate',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:id})})
  .then(function(r){return r.json();})
  .then(function(res){
    STORE=res; activeId=res.active_id;
    renderProfiles();
    var p=getProf(activeId);
    if(p) viewProfile(activeId);
  });
}

function startProfile(id){
  fetch('/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
    .then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data};});})
    .then(function(res){
      if(!res.ok){alert((res.data.error||'خطا در شروع ربات')+(res.data.missing?' — '+res.data.missing.join('، '):''));return;}
      STORE=res.data;renderProfiles();
    }).catch(function(){alert('ارتباط با پنل برای شروع ربات برقرار نشد.');});
}

function stopProfile(id,pid){
  fetch('/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,pid:pid})})
    .then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data};});})
    .then(function(res){if(!res.ok){alert(res.data.error||'توقف ربات انجام نشد');return;}STORE=res.data;renderProfiles();})
    .catch(function(){alert('ارتباط با پنل برای توقف ربات برقرار نشد.');});
}

function toggleProfile(id,enabled){
  fetch('/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,enabled:enabled})})
  .then(function(r){return r.json();}).then(function(res){STORE=res;renderProfiles();});
}

function deleteProfile(id){
  if(STORE.profiles.length<=1){alert('حداقل یک پروفایل باید باشد.');return;}
  if(!confirm('حذف شود؟')) return;
  fetch('/delete',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:id})})
  .then(function(r){return r.json();})
  .then(function(res){
    STORE=res; activeId=res.active_id;
    renderProfiles();
    if(id===activeId||!getProf(activeId)) viewProfile(res.active_id);
  });
}

function newProfile(){
  fetch('/new',{method:'POST'})
  .then(function(r){return r.json();})
  .then(function(res){
    STORE=res; activeId=res.active_id;
    renderProfiles();
    editProfile(res.active_id);
  });
}

function cloneProfile(id){
  fetch('/clone',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
  .then(function(r){return r.json();}).then(function(res){
    STORE=res; activeId=res.active_id; renderProfiles(); editProfile(activeId);
  });
}

function saveProfile(e){
  e.preventDefault();
  var f=document.getElementById('f');
  var imeis=[];
  document.querySelectorAll('#imeis input').forEach(function(i){if(i.value.trim())imeis.push(i.value.trim());});
  var p=getProf(activeId)||{};
  var payload={
    id:activeId,
    title:f.title.value.trim(),
    national:f.national.value.trim(),
    birth:f.birth.value.trim(),
    mobile:f.mobile.value.trim(),
    first_name:f.first_name.value.trim(),
    last_name:f.last_name.value.trim(),
    father_name:f.father_name.value.trim(),
    birth_certificate_no:f.birth_certificate_no.value.trim(),
    passport:f.passport.value.trim(),
    imeis:imeis,
    no_confirm_check:!document.getElementById('confirm_on').checked,
    debugging:document.getElementById('debug_on').checked,
    manual_manage:document.getElementById('manual_on').checked
  };
  fetch('/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
  .then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data};});})
  .then(function(res){
    if(!res.ok){
      /* v1.5 item 11: a 400 (e.g. malformed passport) must NOT assign the
         error body to STORE — surface it on the toast, red like the catch. */
      var t=document.getElementById('toast');
      t.style.color='var(--danger)'; t.textContent='✕ '+(res.data&&res.data.error||'خطا در ذخیره');
      t.classList.add('show');
      return;
    }
    STORE=res.data; activeId=res.data.active_id;
    renderProfiles();
    var t=document.getElementById('toast');
    t.style.color='var(--ok)'; t.textContent='✓ ذخیره شد — حالا ربات را اجرا کن';
    t.classList.add('show'); setTimeout(function(){t.classList.remove('show');},3000);
  })
  .catch(function(){
    var t=document.getElementById('toast');
    t.style.color='var(--danger)'; t.textContent='✕ خطا در ذخیره';
    t.classList.add('show');
  });
}

function renderLogs(){
  var el=document.getElementById('view-logs'); el.innerHTML='';
  var p=getProf(activeId)||{};
  var own=filterLogsForProfile(LOGS,p);
  var mode=arguments[0]||logMode;
  logMode=mode;
  el.innerHTML='<div class="nav-tabs"><div class="nav-tab'+(mode!=='all'?' active':'')+'" id="log-tab-profile" onclick="renderLogs(\'profile\')">لاگ پروفایل</div><div class="nav-tab'+(mode==='all'?' active':'')+'" id="log-tab-all" onclick="renderLogs(\'all\')">لاگ کلی</div></div><div id="log-list"></div>';
  var list=mode==='all'?LOGS:own;
  var listEl=document.getElementById('log-list');
  if(!list.length){listEl.innerHTML='<div class="log-empty">هنوز لاگی ثبت نشده</div>';return;}
  list.forEach(function(log){
    var d=document.createElement('div'); d.className='log-item '+(log.status||'');
    var icon={'error':ICON.xCircle,'success':ICON.checkCircle,'warn':ICON.alert,'info':ICON.info}[log.status]||ICON.dot;
    d.innerHTML='<div class="log-top"><span class="log-step">'+icon+' '+escHtml(log.step||'')+'</span><span class="log-ts">'+escHtml(faDateTime(log.ts))+'</span></div><div class="log-msg">'+escHtml(log.message||'')+'</div>'+(log.title?'<div class="hint">'+ICON.user+' '+escHtml(log.title)+'</div>':'');
    listEl.appendChild(d);
  });
}

function filterLogsForProfile(logs,p){return logs.filter(function(x){return (p.title&&x.title===p.title)||(p.national&&x.national===p.national);});}

function refreshLogs(){
  fetch('/logs',{cache:'no-store'}).then(function(r){return r.json();}).then(function(logs){
    LOGS=logs;
    notifyNewLogs(logs);
    var view=document.getElementById('view-logs');
    if(view && !view.classList.contains('hidden')) renderLogs(logMode);
  });
}
setInterval(refreshLogs,10000);

/* ---- notification-e OPTIONAL baraye log-haye JADID (bala-chap) ---- */
var NOTIF_ON=localStorage.getItem('irica-lognotif')!=='0';
var NOTIF_SEEN={};
var NOTIF_READY=false;
var NOTIF_ICON={success:ICON.checkCircle,error:ICON.xCircle,warn:ICON.alert,info:ICON.info};

function logKey(l){return (l.ts||'')+'|'+(l.step||'')+'|'+(l.message||'').slice(0,60);}

function updateNotifToggle(){
  var b=document.getElementById('notif-toggle'); if(!b)return;
  b.innerHTML=(NOTIF_ON?ICON.bell:ICON.bellOff)+'<span>'+(NOTIF_ON?'اعلان لاگ: روشن':'اعلان لاگ: خاموش')+'</span>';
  b.style.top=(NOTIF_ON?'auto':'14px');
  b.style.bottom=(NOTIF_ON?'14px':'auto');
}
function toggleLogNotif(){
  NOTIF_ON=!NOTIF_ON;
  localStorage.setItem('irica-lognotif',NOTIF_ON?'1':'0');
  if(!NOTIF_ON) document.getElementById('lognotif-wrap').innerHTML='';
  updateNotifToggle();
}

function notifyNewLogs(logs){
  var fresh=[];
  (logs||[]).forEach(function(l){
    var k=logKey(l);
    if(!NOTIF_SEEN[k]){NOTIF_SEEN[k]=1;fresh.push(l);}
  });
  if(!NOTIF_READY){NOTIF_READY=true;return;}   // bar-e aval hame ghadimi hastand
  if(!NOTIF_ON)return;
  fresh.slice(0,4).forEach(function(l,i){setTimeout(function(){pushLogNotif(l);},i*220);});
}

function pushLogNotif(l){
  var wrap=document.getElementById('lognotif-wrap'); if(!wrap)return;
  var st=l.status||'info';
  var d=document.createElement('div');
  d.className='lognotif s-'+st;
  d.innerHTML='<button class="x" aria-label="بستن" onclick="this.parentNode.remove()">×</button>'+
    '<div class="t">'+(NOTIF_ICON[st]||ICON.dot)+' <span>'+escHtml(l.step||'رویداد جدید')+'</span>'+
    '<span style="margin-inline-start:auto;font-size:10.5px;color:var(--muted)">'+escHtml(faDateTime(l.ts))+'</span></div>'+
    (l.imei?'<div class="sn">سریال: '+escHtml(l.imei)+'</div>':'')+
    (l.title?'<div class="sn">'+ICON.user+' '+escHtml(l.title)+'</div>':'')+
    '<div class="m">'+escHtml(l.message||'')+'</div>';
  wrap.appendChild(d);
  requestAnimationFrame(function(){d.classList.add('show');});
  while(wrap.children.length>4) wrap.removeChild(wrap.firstChild);
  setTimeout(function(){
    d.classList.remove('show');
    setTimeout(function(){if(d.parentNode)d.remove();},300);
  },9000);
}

var PROFILE_INQUIRY_SERVICE='hamta';
var PROFILE_INQUIRY_FA={hamta:'استعلام همتا',gomrok:'استعلام گمرک',all:'استعلام گمرک و همتا'};
var PROFILE_RESULT_FA={not_checked:'انجام نشده',running:'در حال استعلام',complete:'تکمیل شده',error:'نیازمند بررسی',healthy:'قابل ثبت در گمرک',good:'فاقد ثبت قانونی در شبکه',registered:'قانونی ثبت شده',problem:'مسدود/خطر',advanced:'مسدود/خطر',blocked:'مسدود/خطر'};

function profileResultClass(status){
  if(status==='running'||status==='not_checked')return 'running';
  return ['healthy','good','registered','complete'].indexOf(status)>=0?'good':'bad';
}
function profileInquiryLabel(p,service){
  var svc=service==='hamta'?'همتا':service==='gomrok'?'گمرک':'گمرک و همتا';
  return (p.title||p.national||'بدون عنوان')+' — '+svc;
}
function buildServiceResults(p,service){
  var state=p[service+'_inquiry_status']||'not_checked';
  var rows=p[service+'_inquiry_results']||[];
  var error=p[service+'_inquiry_error']||'';
  if(state==='not_checked'&&!rows.length)return '<div class="device-result running"><strong>'+profileInquiryLabel(p,service)+'</strong><div class="device-result-text">هنوز استعلامی برای سریال‌های این پروفایل ثبت نشده است.</div></div>';
  if(state==='running'&&!rows.length)return '<div class="device-result running"><strong>در حال استعلام '+profileInquiryLabel(p,service)+'</strong><div class="device-result-text">نتیجه هر سریال پس از پایان ربات در همین بخش نمایش داده می‌شود.</div></div>';
  var html=rows.map(function(row){
    var st=row.status||'error';
    var serialDisplay = escHtml(row.serial||'--');
    if (row.serial2) {
        serialDisplay += ' / ' + escHtml(row.serial2);
    }
    return '<div class="device-result '+profileResultClass(st)+'"><div class="device-result-head"><span class="serial">'+serialDisplay+'</span><strong>'+(PROFILE_RESULT_FA[st]||escHtml(st))+'</strong></div><div class="device-result-profile">'+ICON.user+' پروفایل: '+escHtml(p.title||p.national||'بدون عنوان')+'</div><div class="device-result-text">'+escHtml(row.result||'بدون توضیح')+'</div>'+(row.checked_at?'<div class="device-result-time">'+escHtml(faDateTime(row.checked_at))+'</div>':'')+'</div>';
  }).join('');
  if(error)html+='<div class="device-result bad"><strong>خطای اجرا — '+profileInquiryLabel(p,service)+'</strong><div class="device-result-text">'+escHtml(error)+'</div></div>';
  return html;
}
function buildDeviceInquiryPanel(p){
  var service=PROFILE_INQUIRY_SERVICE;
  var results=service==='all'?buildServiceResults(p,'gomrok')+buildServiceResults(p,'hamta'):buildServiceResults(p,service);
  var running=p.device_inquiry_pid&&((p.gomrok_inquiry_status==='running')||(p.hamta_inquiry_status==='running'));
  return '<div class="inquiry-card" id="device-inquiry-card"><h3>استعلام وضعیت دستگاه‌ها'+(p?' — '+profileInquiryLabel(p,service):'')+'</h3><p class="hint">سریال‌های ذخیره‌شده در همین پروفایل بررسی می‌شوند.</p><div class="inquiry-picker" role="group" aria-label="نوع استعلام دستگاه"><button type="button" class="'+(service==='hamta'?'active':'')+'" onclick="selectProfileInquiry(\'hamta\')">استعلام همتا</button><button type="button" class="'+(service==='gomrok'?'active':'')+'" onclick="selectProfileInquiry(\'gomrok\')">استعلام گمرک</button><button type="button" class="'+(service==='all'?'active':'')+'" onclick="selectProfileInquiry(\'all\')">استعلام گمرک و همتا</button></div><div class="device-results">'+results+'</div><div class="inquiry-actions"><button type="button" class="save" id="profile-inquiry-start" '+(running?'disabled':'')+' onclick="runProfileDeviceInquiry(activeId)">'+(running?'در حال استعلام…':PROFILE_INQUIRY_FA[service])+'</button><button type="button" class="inquiry-stop" id="profile-inquiry-stop" '+(running?'':'disabled')+' onclick="stopProfileDeviceInquiry(activeId)">'+ICON.stop+' توقف استعلام</button></div><div id="profile-inquiry-status" class="hint"></div></div>';
}
function selectProfileInquiry(service){
  PROFILE_INQUIRY_SERVICE=service;
  var p=getProf(activeId)||{};
  var card=document.getElementById('device-inquiry-card');
  if(card){var wrap=document.createElement('div');wrap.innerHTML=buildDeviceInquiryPanel(p);card.replaceWith(wrap.firstChild);}
}

function refreshProfileDeviceInquiry(id,startedAt){
  fetch('/state',{cache:'no-store'}).then(function(r){return r.json();}).then(function(store){
    if(store.error)return;
    STORE=store; var p=getProf(id); if(!p)return;
    var card=document.getElementById('device-inquiry-card');
    if(card){var wrap=document.createElement('div');wrap.innerHTML=buildDeviceInquiryPanel(p);card.replaceWith(wrap.firstChild);}
    var running=p.device_inquiry_pid&&((p.gomrok_inquiry_status==='running')||(p.hamta_inquiry_status==='running'));
    if(running&&Date.now()-startedAt<900000)setTimeout(function(){refreshProfileDeviceInquiry(id,startedAt);},1500);
  }).catch(function(){if(Date.now()-startedAt<900000)setTimeout(function(){refreshProfileDeviceInquiry(id,startedAt);},2500);});
}
function runProfileDeviceInquiry(id){
  var status=document.getElementById('profile-inquiry-status');
  if(status)status.textContent='در حال آماده‌سازی استعلام سریال‌های پروفایل…';
  fetch('/profile-device-inquiry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,service:PROFILE_INQUIRY_SERVICE})})
    .then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data};});})
    .then(function(res){
      if(!res.ok){if(status)status.textContent=(res.data.error||'شروع استعلام انجام نشد')+(res.data.missing?' — '+res.data.missing.join('، '):'');return;}
      if(status)status.textContent='استعلام شروع شد؛ نتایج در همین بخش به‌روز می‌شوند.';
      refreshProfileDeviceInquiry(id,Date.now());
    }).catch(function(){if(status)status.textContent='خطا در ارتباط با پنل';});
}

function stopProfileDeviceInquiry(id){
  var status=document.getElementById('profile-inquiry-status');
  if(!confirm('استعلام این پروفایل متوقف شود؟ مرورگر و فرآیند استعلام بسته می‌شوند.'))return;
  if(status)status.textContent='در حال توقف استعلام…';
  fetch('/profile-device-stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
    .then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data};});})
    .then(function(res){
      if(!res.ok){if(status)status.textContent=res.data.message||res.data.error||'توقف استعلام انجام نشد';return;}
      if(status)status.textContent=res.data.message||'استعلام متوقف شد.';
      STORE=res.data.store||STORE;
      renderProfiles();
      var p=getProf(id);
      if(p){var card=document.getElementById('device-inquiry-card');
        if(card){var wrap=document.createElement('div');wrap.innerHTML=buildDeviceInquiryPanel(p);card.replaceWith(wrap.firstChild);}}
    }).catch(function(){if(status)status.textContent='خطا در ارتباط با پنل';});
}

function closeWholeSystem(){
  if(!confirm('کل سامانه بسته شود؟ همهٔ ربات‌ها و استعلام‌های در حال اجرا متوقف می‌شوند و پنل خاموش می‌شود.'))return;
  fetch('/shutdown',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .catch(function(){});
  var banner=document.createElement('div');
  banner.style.cssText='position:fixed;top:0;left:0;right:0;z-index:9999;background:#b91c1c;color:#fff;'+
    'padding:14px;text-align:center;font-family:Tahoma,sans-serif;font-size:14px;font-weight:bold';
  banner.textContent='در حال بستن سامانه… همهٔ ربات‌ها متوقف شدند؛ این صفحه تا چند ثانیه دیگر در دسترس نخواهد بود.';
  document.body.appendChild(banner);
  setTimeout(function(){
    banner.textContent='سامانه بسته شد. برای اجرای مجدد، میان‌بر IRICA را باز کنید.';
    setTimeout(function(){location.reload();},4000);
  },1500);
}

function refreshExitbanResult(id, startedAt){
  fetch('/state').then(function(r){return r.json();}).then(function(store){
    STORE=store; var p=getProf(id); var card=document.getElementById('exitban-result-card');
    if(card&&p){var wrap=document.createElement('div');wrap.innerHTML=buildExitbanResult(p);card.replaceWith(wrap.firstChild);}
    if(!p) return;
    if(p.exitban_status==='not_checked' && Date.now()-startedAt<130000){
      setTimeout(function(){refreshExitbanResult(id,startedAt);},1000);
      return;
    }
    var status=document.getElementById('exitban-status');
    if(status) status.textContent=p.exitban_status==='not_checked'?'نتیجه در زمان تعیین‌شده دریافت نشد.':'نتیجه در پنل ثبت شد.';
  }).catch(function(){
    if(Date.now()-startedAt<130000) setTimeout(function(){refreshExitbanResult(id,startedAt);},1500);
  });
}

function runExitbanInquiry(id){
  var status=document.getElementById('exitban-status');
  if(status) status.textContent='در حال بررسی اطلاعات پروفایل...';
  fetch('/exitban-inquiry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})})
    .then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data};});})
    .then(function(res){
      if(!res.ok){ if(status) status.textContent=res.data.error+(res.data.missing?' — '+res.data.missing.join('، '):''); return; }
      if(status) status.textContent='فرم در Chrome باز شد؛ نتیجه پس از اتمام ربات اینجا نمایش داده می‌شود.';
      refreshExitbanResult(id,Date.now());
    }).catch(function(){if(status) status.textContent='خطا در شروع فرم استعلام';});
}


function showApiHealth(h){
  var box=document.getElementById('api-health-toast');
  if(!box||!h)return;
  box.classList.remove('ok','fail'); box.classList.add(h.ok?'ok':'fail','show');
  document.getElementById('api-health-message').innerHTML=(h.ok?ICON.check:ICON.alert)+' '+escHtml(h.message||'نتیجه تست نامشخص است');
  document.getElementById('api-health-meta').textContent=(h.api_base||'')+(h.ts?' • '+faDateTime(h.ts):'');
  clearTimeout(window.__apiToastTimer);
  window.__apiToastTimer=setTimeout(function(){
    if(!box.matches(':hover'))box.classList.remove('show');
  },h.ok?9000:16000);
}
function refreshApiHealth(run){
  fetch(run?'/telegram-health?run=1':'/telegram-health',{cache:'no-store'})
    .then(function(r){return r.json();}).then(showApiHealth)
    .catch(function(){showApiHealth({ok:false,message:'ارتباط پنل با تست API برقرار نشد.'});});
}

var SYSTEM_DEBUG={enabled:false};
var SYSTEM_LOGS=[];
function renderSystemLogs(){
  var list=document.getElementById('system-log-list'); if(!list)return;
  if(!SYSTEM_LOGS.length){list.innerHTML='<div class="hint">هنوز لاگ سیستمی ساخته نشده است.</div>';return;}
  list.innerHTML=SYSTEM_LOGS.map(function(item){return '<div class="system-log-item"><span class="system-log-name">'+escHtml(item.name)+'</span><span class="system-log-meta">'+escHtml(faDateTime(item.modified))+'</span><button type="button" class="system-log-open" onclick="openSystemLog(\''+escHtml(item.name)+'\')">مشاهده</button></div>';}).join('');
}
function loadSystemLogs(){
  fetch('/system-logs',{cache:'no-store'}).then(function(r){return r.json();}).then(function(data){SYSTEM_LOGS=data.logs||[];renderSystemLogs();}).catch(function(){});
}
function openSystemLog(name){
  fetch('/system-log?name='+encodeURIComponent(name),{cache:'no-store'}).then(function(r){return r.json();}).then(function(data){
    var viewer=document.getElementById('system-log-viewer'); if(viewer)viewer.textContent=data.content||data.error||'لاگ خالی است';
  }).catch(function(){var viewer=document.getElementById('system-log-viewer');if(viewer)viewer.textContent='خطا در خواندن لاگ';});
}
function toggleSystemDebug(enabled){
  fetch('/system-debug-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:enabled})}).then(function(r){return r.json();}).then(function(data){SYSTEM_DEBUG=data;renderTelegram();});
}
function renderTelegram(){
  var tokenState = TELEGRAM.token_set
    ? '<span class="token-badge ok">'+ICON.lock+' توکن ذخیره شده و محافظت‌شده است</span>'
    : '<span class="token-badge warn">'+ICON.alert+' توکنی ثبت نشده است</span>';
  document.getElementById('view-telegram').innerHTML='<div class="settings-section"><h3>تنظیمات کلی</h3><p class="hint">تنظیمات عمومی پنل و ربات در این بخش قرار می‌گیرد.</p></div>'+
    '<div class="settings-section system-debug-card"><div class="system-debug-row"><div><h3>Debug log سیستمی</h3><div class="system-debug-help">با فعال‌سازی، هر اجرای ربات یک فایل مستقل و تاریخ‌دار در پوشه logs/system داخل پوشه‌ی داده می‌سازد.</div></div><label class="toggle"><input id="system-debug-toggle" type="checkbox" '+(SYSTEM_DEBUG.enabled?'checked':'')+' onchange="toggleSystemDebug(this.checked)"><span class="track"></span></label></div><div class="system-debug-row"><strong>لاگ‌های موجود</strong><button type="button" class="system-log-open" onclick="loadSystemLogs()">به‌روزرسانی فهرست</button></div><div id="system-log-list" class="system-log-list"></div><pre id="system-log-viewer" class="system-log-viewer">یک فایل لاگ را برای مشاهده انتخاب کنید.</pre></div>'+
    '<label>API Base</label><input id="tg_api" type="text" class="ltr" value="'+escHtml(TELEGRAM.api_base||'https://api.telegram.org')+'">'+
    '<label>توکن ربات</label>'+tokenState+
    '<input id="tg_token" type="password" class="ltr" autocomplete="off" placeholder="'+(TELEGRAM.token_set?'برای تغییر، توکن جدید را وارد کنید (خالی = بدون تغییر)':'توکن ربات را وارد کنید')+'">'+
    '<label>Chat IDها (هر کدام یک خط)</label><textarea id="tg_ids" class="ltr">'+escHtml((TELEGRAM.chat_ids||[]).join('\n'))+'</textarea>'+
    '<button class="save" onclick="saveTelegram()">'+ICON.save+' ذخیره تنظیمات تلگرام</button><div class="toast" id="tg_toast"></div>'+
    '<p class="hint">این تنظیمات بیرون از پوشه‌ی برنامه ذخیره می‌شوند، پس با نصب نسخه‌ی جدید پاک نمی‌شوند و لازم نیست دوباره وارد شوند.</p>';
  renderSystemLogs();
  loadSystemLogs();
}

function saveTelegram(){
  fetch('/telegram-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    api_base:document.getElementById('tg_api').value,bot_token:document.getElementById('tg_token').value,
    chat_ids:document.getElementById('tg_ids').value})}).then(function(r){return r.json();}).then(function(res){
      TELEGRAM=res; var t=document.getElementById('tg_toast'); t.textContent='✓ ذخیره شد'; t.classList.add('show');
      renderTelegram();   // input-e token dobare khali/masked shavad
      refreshApiHealth(true);
  });
}

/* ------------------------------------------------------------------
   Cloud sync surface (spec §11). CLOUD.last is the only thing paintCloud
   reads, so a background poll repaints the status cells and never the
   form fields — a half-typed password survives every refresh.
   ------------------------------------------------------------------ */
var CLOUD={last:null,timer:null,burst:null,busy:false};
/* Mirrors panel.CLOUD_UNKNOWN_MESSAGE — the one sentence shown when an
   answer arrives without a coded error of its own (spec §11). Kept equal to
   the Python table by a test, so the two cannot drift apart. */
var CLOUD_UNKNOWN_MESSAGE='خطای همگام‌سازی؛ کد آن را به پشتیبانی اعلام کنید.';
/* The state pill never relies on colour: every entry carries an icon and
   a word (spec §11, and the panel's own icon language — no emoji). */
var CLOUD_LINK={
  unconfigured:{cls:'mute',icon:'dot',label:'پیکربندی‌نشده'},
  connected:{cls:'ok',icon:'checkCircle',label:'متصل'},
  syncing:{cls:'ok',icon:'dot',label:'در حال همگام‌سازی'},
  offline:{cls:'bad',icon:'xCircle',label:'آفلاین'},
  read_only:{cls:'warn',icon:'alert',label:'فقط‌خواندنی'},
  auth_required:{cls:'warn',icon:'lock',label:'نیازمند ورود'},
  not_enrolled:{cls:'warn',icon:'info',label:'ثبت‌نشده'},
  conflict:{cls:'warn',icon:'alert',label:'نیازمند بررسی تداخل'},
  disabled:{cls:'mute',icon:'minusCircle',label:'غیرفعال'},
  error:{cls:'bad',icon:'xCircle',label:'خطا'}
};

function cloudShellHtml(){
  return '<div class="settings-section" id="cloud-sync-section">'+
    '<h3>همگام‌سازی ابری</h3>'+
    '<p class="hint">وضعیت اتصال، صف انتظار و کد آخرین خطای همگام‌سازی در این بخش دیده می‌شود.</p>'+
    '<div class="cloud-banner" id="cloud-readonly-banner" role="alert">'+ICON.alert+
      '<div><span class="cloud-banner-b">دستگاه در حالت فقط‌خواندنی است</span>'+
      '<p class="cloud-banner-p">مهلت کارکرد آفلاین هفت‌روزه به پایان رسیده است. تا زمانی که دوباره وارد نشوید، ویرایش‌های محلی پذیرفته نمی‌شوند؛ خواندن داده‌ها ادامه دارد.</p></div></div>'+
    '<div class="cloud-notice" id="cloud-must-change" role="alert">'+ICON.alert+
      '<div><span class="cloud-banner-b">رمز عبور باید تغییر کند</span>'+
      '<p class="cloud-banner-p">برای ادامه، رمز عبور میزبان خود را در سامانه‌ی میزبان تغییر دهید.</p></div></div>'+
    '<div class="cloud-state-row">'+
      '<span class="cloud-pill mute" id="cloud-pill"><span id="cloud-pill-icon">'+ICON.dot+'</span><span id="cloud-pill-text">در حال بررسی…</span></span>'+
      '<span class="cloud-actor" id="cloud-actor">'+ICON.user+'<span>کاربر فعال:</span><b id="cloud-actor-name"></b></span>'+
    '</div>'+
    '<div class="cloud-facts">'+
      '<div class="cloud-fact"><span class="cloud-fact-l">این دستگاه</span><span class="cloud-fact-v cloud-code" id="cloud-device">ثبت‌نشده</span></div>'+
      '<div class="cloud-fact"><span class="cloud-fact-l">آخرین همگام‌سازی موفق</span><span class="cloud-fact-v" id="cloud-last-sync">—</span></div>'+
      '<div class="cloud-fact"><span class="cloud-fact-l">تغییرات در انتظار</span><span class="cloud-fact-v" id="cloud-pending">۰</span></div>'+
      '<div class="cloud-fact"><span class="cloud-fact-l">تداخل‌ها</span><span class="cloud-fact-v" id="cloud-conflicts">۰</span></div>'+
      '<div class="cloud-fact"><span class="cloud-fact-l">کد آخرین خطا</span><span class="cloud-fact-v cloud-code" id="cloud-error-code">—</span></div>'+
    '</div>'+
    '<div class="cloud-error" id="cloud-error-line" role="alert">'+ICON.alert+'<span id="cloud-error-text"></span></div>'+
    '<div class="cloud-notice" id="cloud-reconnect" role="status">'+ICON.info+
      '<div><span class="cloud-banner-b">اتصال این دستگاه نیاز به بازسازی دارد</span>'+
      '<p class="cloud-banner-p" id="cloud-reconnect-text"></p></div></div>'+
    '<div class="cloud-status" id="cloud-beat-line" role="status"></div>'+
    '<div class="cloud-status" id="cloud-action-status" role="status" aria-live="polite"></div>'+
    '<div class="cloud-actions">'+
      '<button type="button" class="cloud-btn" id="cloud-sync-btn" onclick="cloudSyncNow()" disabled><span class="cloud-lbl">همگام‌سازی اکنون</span></button>'+
      '<button type="button" class="cloud-btn ghost hidden" id="cloud-import-btn" onclick="cloudImportPrompt()"><span class="cloud-lbl">انتقال پرونده‌های فعلی به سرور (Import)</span></button>'+
      '<button type="button" class="cloud-btn ghost hidden" id="cloud-logout-btn" onclick="cloudLogout()"><span class="cloud-lbl">خروج از میزبان</span></button>'+
    '</div>'+
    '<div class="cloud-block">'+
      '<strong>تنظیمات اتصال</strong>'+
      '<div class="cloud-fields">'+
        '<div class="cloud-field"><label for="cloud-api">آدرس سرویس ابری</label>'+
          '<input id="cloud-api" type="text" class="ltr" autocomplete="off" spellcheck="false" placeholder="https://api.example.com"></div>'+
        '<div class="cloud-field"><label for="cloud-tenant">شناسه‌ی سازمان</label>'+
          '<input id="cloud-tenant" type="text" class="ltr" autocomplete="off" spellcheck="false"></div>'+
      '</div>'+
      '<button type="button" class="cloud-btn" id="cloud-save-btn" onclick="cloudSaveConfig()"><span class="cloud-lbl">ذخیره تنظیمات اتصال</span></button>'+
    '</div>'+
    '<div class="cloud-block hidden" id="cloud-login-block">'+
      '<strong>ورود به میزبان</strong>'+
      '<div class="cloud-fields">'+
        '<div class="cloud-field"><label for="cloud-user">نام کاربری میزبان</label>'+
          '<input id="cloud-user" type="text" class="ltr" autocomplete="username" spellcheck="false"></div>'+
        '<div class="cloud-field"><label for="cloud-pass">رمز عبور میزبان</label>'+
          '<input id="cloud-pass" type="password" class="ltr" autocomplete="current-password"></div>'+
      '</div>'+
      '<button type="button" class="cloud-btn" id="cloud-login-btn" onclick="cloudLogin()"><span class="cloud-lbl">ورود به میزبان</span></button>'+
    '</div>'+
    /* SEAM — workstream E mounts the local-vs-server conflict chooser here;
       paintCloud() calls renderCloudConflicts(container, status) every paint. */
    '<div class="cloud-conflicts" id="cloud-conflicts-view"></div>'+
    '</div>';
}

function paintCloud(){
  if(!document.getElementById('cloud-sync-section'))return;
  var s=CLOUD.last;
  var link=s&&s.link?s.link:'unconfigured';
  if(link==='connected'&&s&&s.state==='syncing')link='syncing';
  var meta=CLOUD_LINK[link]||CLOUD_LINK.error;
  var pill=document.getElementById('cloud-pill');
  pill.className='cloud-pill '+meta.cls;
  document.getElementById('cloud-pill-icon').innerHTML=ICON[meta.icon]||ICON.dot;
  document.getElementById('cloud-pill-text').textContent=meta.label;
  document.getElementById('cloud-readonly-banner').classList.toggle('on',Boolean(s&&s.read_only));
  document.getElementById('cloud-must-change').classList.toggle('on',Boolean(s&&s.must_change_password));
  var name=s&&s.actor?String(s.actor):'';
  document.getElementById('cloud-actor').classList.toggle('on',Boolean(name));
  document.getElementById('cloud-actor-name').textContent=name;
  var deviceId=s&&s.device_id?String(s.device_id):'';
  var deviceText=deviceId?(deviceId.length>12?deviceId.slice(0,8)+'…'+deviceId.slice(-4):deviceId):'ثبت‌نشده';
  document.getElementById('cloud-device').textContent=deviceText;
  document.getElementById('cloud-device').title=deviceId;
  document.getElementById('cloud-last-sync').textContent=(s&&s.last_sync)?faDateTime(s.last_sync):'—';
  document.getElementById('cloud-pending').textContent=toFa(s?Number(s.pending||0):0);
  document.getElementById('cloud-conflicts').textContent=toFa(s?Number(s.conflicts||0):0);
  document.getElementById('cloud-error-code').textContent=(s&&s.error_code)?s.error_code:'—';
  var msg=(s&&s.error_message)?String(s.error_message):'';
  document.getElementById('cloud-error-line').classList.toggle('on',Boolean(msg));
  document.getElementById('cloud-error-text').textContent=msg;
  var reconnect=document.getElementById('cloud-reconnect');
  var reconnectText=document.getElementById('cloud-reconnect-text');
  var needsReconnect=Boolean(s&&['not_enrolled','auth_required','read_only'].indexOf(s.link)>=0);
  if(reconnect)reconnect.classList.toggle('on',needsReconnect);
  if(reconnectText){
    if(needsReconnect){
      reconnectText.textContent=s.link==='not_enrolled'
        ?'با نام کاربری و رمز عبور میزبان وارد شوید؛ این رایانه با شناسه‌ی مستقل ثبت می‌شود.'
        :(s.link==='read_only'
          ?'مهلت آفلاین تمام شده است؛ برای تازه‌سازی مجوز این رایانه دوباره وارد میزبان شوید.'
          :'نشست ابری قابل استفاده نیست؛ دوباره وارد میزبان شوید. اگر اعتبار دستگاه لغو شده یا از دست رفته باشد، ورود موفق یک شناسه‌ی دستگاه تازه ثبت می‌کند.');
    }else{reconnectText.textContent='';}
  }
  document.getElementById('cloud-beat-line').textContent=cloudBeatLine(s);
  document.getElementById('cloud-login-block').classList.toggle('hidden',Boolean(name));
  document.getElementById('cloud-logout-btn').classList.toggle('hidden',!Boolean(name));
  var syncBtn=document.getElementById('cloud-sync-btn');
  if(syncBtn)syncBtn.disabled=Boolean(CLOUD.busy)||!(s&&s.configured);
  var importBtn=document.getElementById('cloud-import-btn');
  if(importBtn)importBtn.classList.toggle('hidden',!(s&&s.can_import));
  renderCloudConflicts(document.getElementById('cloud-conflicts-view'),s);
}

/* The queue-draining line (spec §9): what the last worker beat did, in
   words the server already mapped — never an exception message. */
function cloudBeatLine(s){
  if(!s)return '';
  var line=s.worker==='running'?'کارگر همگام‌سازی در حال اجراست.':'کارگر همگام‌سازی متوقف است.';
  var b=s.worker_last;
  if(!b)return line;
  if(b.message)return line+' '+b.message;
  if(b.attempted)return line+' ارسال گروهی انجام شد.';
  return line+' چیزی برای ارسال نبود.';
}

var CLOUD_CONFLICTS_CACHE=null;
var CLOUD_CONFLICTS_FETCHING=false;
var CLOUD_ENTITY_NAMES={
  'customers':'مشتری',
  'customer_transactions':'تراکنش مشتری',
  'owners':'مسافر / مالک',
  'identities':'استخر هویتی',
  'devices':'دستگاه / پرونده',
  'crm_devices':'دستگاه / پرونده',
  'periods':'دوره مالی',
  'settings':'تنظیمات'
};

function renderCloudConflicts(container,s){
  if(!container)return;
  if(s&&Number(s.conflicts||0)>0){
    container.classList.add('on');
    var count=toFa(s.conflicts);
    var head='<div class="cloud-conflict-count"><strong>تداخل‌ها:</strong> '+count+' مورد در انتظار تصمیم شماست.</div>';
    if(typeof CLOUD_CONFLICTS_CACHE!=='undefined'&&CLOUD_CONFLICTS_CACHE&&CLOUD_CONFLICTS_CACHE.length>0){
      var cards='';
      for(var i=0;i<CLOUD_CONFLICTS_CACHE.length;i++){
        var c=CLOUD_CONFLICTS_CACHE[i];
        var ent=(typeof CLOUD_ENTITY_NAMES!=='undefined'&&CLOUD_ENTITY_NAMES[c.entity])?CLOUD_ENTITY_NAMES[c.entity]:(c.entity||'مورد');
        cards+='<div class="cloud-conflict-card">'+
          '<div class="cloud-conflict-head"><strong>'+escHtml(ent)+'</strong> <span class="kbd ltr">'+escHtml(c.id||'')+'</span></div>'+
          diffHtml(c.local_record,c.server_record)+
          '<div class="cloud-conflict-actions">'+
            '<button type="button" class="cloud-btn mini" onclick="resolveCloudConflict(\''+c.operation_id+'\',\'keep_local\',this)"><span class="cloud-lbl">نگه‌داشتن تغییرات من (روی سرور ذخیره شود)</span></button>'+
            '<button type="button" class="cloud-btn mini ghost" onclick="resolveCloudConflict(\''+c.operation_id+'\',\'accept_server\',this)"><span class="cloud-lbl">پذیرش نسخه سرور (تغییرات محلی لغو شود)</span></button>'+
          '</div>'+
        '</div>';
      }
      container.innerHTML=head+cards;
    }else{
      container.innerHTML=head+'<div class="hint">در حال دریافت اطلاعات تداخل‌ها…</div>';
      if(typeof fetch==='function'&&typeof fetchCloudConflicts==='function'&&!CLOUD_CONFLICTS_FETCHING){
        fetchCloudConflicts();
      }
    }
  }else{
    container.classList.remove('on');
    container.innerHTML='';
    if(typeof CLOUD_CONFLICTS_CACHE!=='undefined')CLOUD_CONFLICTS_CACHE=null;
  }

  function diffHtml(loc,srv){
    loc=loc||{}; srv=srv||{};
    var keys={};
    for(var k in loc)keys[k]=true;
    for(var k in srv)keys[k]=true;
    var rows='';
    for(var key in keys){
      var lv=loc[key], sv=srv[key];
      var ls=(lv===undefined||lv===null)?'—':(typeof lv==='object'?JSON.stringify(lv):String(lv));
      var ss=(sv===undefined||sv===null)?'—':(typeof sv==='object'?JSON.stringify(sv):String(sv));
      if(ls!==ss){
        rows+='<tr><th>'+escHtml(key)+'</th><td class="diff-loc">'+escHtml(ls)+'</td><td class="diff-srv">'+escHtml(ss)+'</td></tr>';
      }
    }
    if(!rows)return '<div class="hint">تغییر فیلد مشخصی ثبت نشده است.</div>';
    return '<table class="cloud-conflict-table"><thead><tr><th>فیلد</th><th>نسخه محلی (من)</th><th>نسخه سرور</th></tr></thead><tbody>'+rows+'</tbody></table>';
  }
}

function fetchCloudConflicts(){
  CLOUD_CONFLICTS_FETCHING=true;
  fetch('/cloud-conflicts',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      CLOUD_CONFLICTS_FETCHING=false;
      if(d&&d.ok&&Array.isArray(d.conflicts)){
        CLOUD_CONFLICTS_CACHE=d.conflicts;
        var el=document.getElementById('cloud-conflicts-view');
        if(el)renderCloudConflicts(el,CLOUD.last);
      }
    })
    .catch(function(){
      CLOUD_CONFLICTS_FETCHING=false;
    });
}

function resolveCloudConflict(opId,resolution,btn){
  if(btn)btn.disabled=true;
  cloudPost('/cloud-resolve-conflict',{operation_id:opId,resolution:resolution},function(){
    CLOUD_CONFLICTS_CACHE=null;
    loadCloudStatus();
  });
}

function cloudImportPrompt(){
  if(confirm('آیا از انتقال پرونده‌های فعلی به سرور (Import) اطمینان دارید؟ این عملیات فقط یک بار انجام می‌شود.')){
    cloudPost('/cloud-import',{},function(){
      loadCloudStatus();
    });
  }
}

function loadCloudStatus(){
  return fetch('/cloud-status',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){CLOUD.last=(d&&typeof d==='object')?d:null;paintCloud();return d;})
    .catch(function(){paintCloud();return null;});
}

function cloudView(on){
  if(on){
    if(CLOUD.timer)return;
    loadCloudStatus();
    CLOUD.timer=setInterval(loadCloudStatus,4000);
  }else{
    if(CLOUD.timer){clearInterval(CLOUD.timer);CLOUD.timer=null;}
    if(CLOUD.burst){clearInterval(CLOUD.burst);CLOUD.burst=null;}
  }
}

/* After an action, poll a few times quickly so "the queue is draining" is
   seen happening instead of assumed (spec §9). */
function cloudBurst(){
  if(CLOUD.burst)clearInterval(CLOUD.burst);
  var n=0;
  CLOUD.burst=setInterval(function(){
    n++;loadCloudStatus();
    if(n>=8){clearInterval(CLOUD.burst);CLOUD.burst=null;}
  },1200);
}

function cloudSetBusy(on,label){
  CLOUD.busy=on;
  ['cloud-sync-btn','cloud-login-btn','cloud-save-btn','cloud-logout-btn','cloud-import-btn'].forEach(function(id){
    var b=document.getElementById(id); if(b)b.disabled=on;
  });
  var st=document.getElementById('cloud-action-status');
  if(!st)return;
  st.className='cloud-status';
  st.textContent=label||'';
}

function cloudResult(ok,text,code){
  var st=document.getElementById('cloud-action-status');
  if(st){
    st.className='cloud-status'+(ok?' ok':' bad');
    st.textContent=text+(code?' ['+code+']':'');
  }
  paintCloud();
}

/* One POST path for every cloud action: loading -> success/failure, the
   error placed under the action that caused it, and the code shown next
   to the mapped Persian sentence (spec §11 — never the server's words). */
function cloudPost(path,body,onOk){
  cloudSetBusy(true,'در حال انجام…');
  return fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body||{})})
    .then(function(r){return r.json();})
    .then(function(d){
      cloudSetBusy(false,'');
      if(d&&d.ok){cloudResult(true,'انجام شد.');if(onOk)onOk(d);}
      else{cloudResult(false,(d&&d.errors&&d.errors[0])?d.errors[0]:CLOUD_UNKNOWN_MESSAGE,d&&d.code);}
      loadCloudStatus();cloudBurst();
    })
    .catch(function(){
      cloudSetBusy(false,'');
      cloudResult(false,'ارتباط با پنل برقرار نشد؛ دوباره تلاش کنید.');
      loadCloudStatus();cloudBurst();
    });
}

function cloudSaveConfig(){
  cloudPost('/cloud-config',{api_base:document.getElementById('cloud-api').value,
    tenant_id:document.getElementById('cloud-tenant').value},function(d){CLOUD.last=d;paintCloud();});
}

function cloudLogin(){
  var u=document.getElementById('cloud-user'),p=document.getElementById('cloud-pass');
  var username=u.value,password=p.value;
  p.value='';   // the credential leaves the DOM the moment it is sent (§5)
  cloudPost('/cloud-login',{username:username,password:password},function(){u.value='';});
}

function cloudLogout(){cloudPost('/cloud-logout',{},null);}
function cloudSyncNow(){cloudPost('/cloud-sync',{},null);}

function showView(v){
  document.getElementById('view-form').classList.toggle('hidden',v!=='form');
  document.getElementById('view-logs').classList.toggle('hidden',v!=='logs');
  document.getElementById('view-telegram').classList.toggle('hidden',v!=='telegram');
  document.getElementById('tab-form').classList.toggle('active',v==='form');
  document.getElementById('tab-logs').classList.toggle('active',v==='logs');
  document.getElementById('tab-telegram').classList.toggle('active',v==='telegram');
  if(v==='logs') renderLogs();
  if(v==='telegram'){
    fetch('/system-debug-config',{cache:'no-store'}).then(function(r){return r.json();}).then(function(data){SYSTEM_DEBUG=data;renderTelegram();}).catch(function(){renderTelegram();});
  }
  cloudView(v==='telegram');   // poll the sync surface only while it is on screen
}

// init
var statsBar=document.getElementById('stats');
if(statsBar) statsBar.addEventListener('click',function(e){
  var tile=e.target.closest('.stat'); if(tile) setStatusFilter(tile.getAttribute('data-filter'));
});
renderProfiles();
updateThemeButton();
refreshApiHealth(false);
if(getProf(activeId)) viewProfile(activeId); else renderProfileEditorEmpty();
updateNotifToggle();
notifyNewLogs(LOGS);   // baseline: hame-ye log-haye avvaliye seen mishavand
"""

PAGE_TAIL = """
</script>
</body>
</html>"""


def render_page():
    store = load_store()
    logs = load_logs()
    js = PAGE_JS
    js = js.replace("__STORE_JSON__", json.dumps(store, ensure_ascii=False))
    js = js.replace("__LOGS_JSON__", json.dumps(logs, ensure_ascii=False))
    js = js.replace("__TELEGRAM_JSON__", json.dumps(public_telegram_config(), ensure_ascii=False))
    version = app_version_text() or "—"
    head = PAGE_HEAD.replace("__VERSION__", version)
    tail = PAGE_TAIL.replace("__VERSION__", version)
    html = head + js + tail
    return with_csrf_bootstrap(html).encode("utf-8")


HOME_PAGE = """<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>انتخاب سامانه گمرک</title><style>
/* IRICA design system — light entry skin (system picker, no theme toggle). */
@font-face{
  font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-var.woff2') format('woff2-variations');
  font-weight:100 900;font-style:normal;font-display:swap;
}
@font-face{
  font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-Bold.woff2') format('woff2');
  font-weight:700;font-style:normal;font-display:swap;
}
:root{
  --bg:#f4f6fb;--card:#ffffff;--card2:#f7f8fd;--line:rgba(27,32,54,.10);
  --line-strong:rgba(27,32,54,.16);--txt:#1b2036;--muted:#5c6484;
  --brand:#4460e3;--brand-hover:#3757cf;--brand-soft:rgba(68,96,227,.10);
  --on-brand:#ffffff;--ok:#0c7d4f;--ok-soft:rgba(15,157,99,.12);
  --danger:#d93752;--danger-soft:rgba(217,55,82,.10);--warn:#b9770e;
  --shadow-1:0 1px 2px rgba(16,20,40,.05),0 1px 6px rgba(16,20,40,.04);
  --shadow-2:0 4px 14px rgba(16,20,40,.10),0 1px 3px rgba(16,20,40,.06);
  --ring:0 0 0 3px rgba(68,96,227,.30);
}
*{box-sizing:border-box}
html{color-scheme:light}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:32px 16px;
  background:radial-gradient(1000px 520px at 85% -12%,rgba(79,107,239,.12),transparent 60%),
             radial-gradient(760px 440px at 6% 6%,rgba(124,92,245,.08),transparent 55%),
             var(--bg);
  color:var(--txt);font-family:Vazirmatn,"Segoe UI",Tahoma,sans-serif;
  font-size:14px;line-height:1.7;-webkit-font-smoothing:antialiased}
.wrap{width:min(980px,94vw)}
.top{text-align:center;margin-bottom:26px}
.mono{width:56px;height:56px;border-radius:14px;margin:0 auto 14px;
  background:linear-gradient(135deg,var(--brand),#7c5cf5);color:var(--on-brand);
  display:grid;place-items:center;font-size:24px;font-weight:800;box-shadow:var(--shadow-1)}
h1{font-size:30px;font-weight:800;margin:0 0 6px}.sub{color:var(--muted);margin:0}
.irica-version{margin-top:12px;font-size:11.5px;color:var(--muted);border:1px solid var(--line);
  background:var(--card);border-radius:999px;padding:3px 12px;display:inline-block}
/* live stats strip */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0 auto 28px;max-width:640px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 10px;text-align:center;box-shadow:var(--shadow-1)}
.stat .n{font-size:24px;font-weight:800;line-height:1.2}
.stat .l{font-size:11.5px;color:var(--muted);margin-top:3px}
.stat.total .n{color:var(--brand)}.stat.running .n{color:var(--warn)}.stat.success .n{color:var(--ok)}.stat.blocked .n{color:var(--danger)}
.sites{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.site{display:flex;flex-direction:column;padding:24px;border:1px solid var(--line);border-radius:18px;
  color:inherit;text-decoration:none;background:var(--card);box-shadow:var(--shadow-1);
  transition:transform .18s,border-color .18s,box-shadow .18s}
.site:hover{transform:translateY(-5px);border-color:var(--brand);box-shadow:var(--shadow-2)}
.site:focus-visible{outline:none;box-shadow:var(--ring),var(--shadow-2)}
.tile{display:grid;place-items:center;width:48px;height:48px;border-radius:13px;flex:none;
  background:var(--brand-soft);color:var(--brand);margin-bottom:16px}
.site h2{font-size:17.5px;font-weight:750;margin:0 0 8px}.site p{color:var(--muted);font-size:13px;line-height:1.9;margin:0 0 14px;flex:1}
.tags{display:flex;flex-wrap:wrap;gap:7px}
.tag{font-size:11px;color:var(--muted);background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:3px 10px}
.go{display:flex;align-items:center;gap:6px;margin-top:14px;padding-top:14px;
  border-top:1px solid var(--line);font-size:12.5px;font-weight:600;color:var(--brand)}
.go svg{transition:transform .18s}.site:hover .go svg{transform:translateX(-4px)}
.foot{margin-top:26px;text-align:center;color:var(--muted);font-size:12px}
.foot b{color:var(--txt);font-weight:700}
@media(max-width:880px){.sites{grid-template-columns:1fr}.site p{flex:none}}
@media(max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}h1{font-size:25px}}
</style></head><body><main class="wrap">
<div class="top">
  <div class="mono">R</div>
  <h1>سامانه مدیریت گمرک</h1>
  <p class="sub">سامانه موردنظر را انتخاب کنید</p>
  <div class="irica-version">نسخه __VERSION__</div>
</div>
<section class="stats" id="stats" aria-label="خلاصه وضعیت">
  <div class="stat total"><div class="n" id="s-total">—</div><div class="l">کل پروفایل‌ها</div></div>
  <div class="stat running"><div class="n" id="s-running">—</div><div class="l">در حال اجرا</div></div>
  <div class="stat success"><div class="n" id="s-success">—</div><div class="l">ثبت موفق</div></div>
  <div class="stat blocked"><div class="n" id="s-blocked">—</div><div class="l">مسدود</div></div>
</section>
<div class="sites">
<a class="site" data-site="crm" href="/crm">
  <span class="tile"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg></span>
  <h2>پنل یکپارچه رجیستری</h2>
  <p>چرخهٔ کامل دستگاه: استعلام، اتصال مسافر، تحویل، پرداخت و ثبت‌نام؛ با دفتر حساب مشتری و گزارش‌ها.</p>
  <div class="tags"><span class="tag">CRM</span><span class="tag">پرونده</span><span class="tag">گزارش</span></div>
  <span class="go">ورود به سامانه<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg></span>
</a>
<a class="site" data-site="2" href="/site-2">
  <span class="tile"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg></span>
  <h2>استعلام سلامت دستگاه</h2>
  <p>استعلام وضعیت دستگاه از سایت گمرک (فقط صفحه اول) با یک پروفایل شخص و لیست دستگاه‌ها.</p>
  <div class="tags"><span class="tag">استعلام سلامت</span><span class="tag">افزودن عمده</span><span class="tag">ترتیب تصادفی</span></div>
  <span class="go">ورود به سامانه<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg></span>
</a>
<a class="site" data-site="1" href="/site-1">
  <span class="tile"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 22h18"/><path d="M6 18v-7"/><path d="M10 18v-7"/><path d="M14 18v-7"/><path d="M18 18v-7"/><path d="m12 2 8 5H4l8-5Z"/></svg></span>
  <h2>پنل قدیمی رجیستری</h2>
  <p>پنل کامل: ویرایش پروفایل، لاگ‌ها، استعلامات و تنظیمات.</p>
  <div class="tags"><span class="tag">ویرایش کامل</span><span class="tag">لاگ‌ها</span><span class="tag">استعلام خروج</span></div>
  <span class="go">ورود به سامانه<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg></span>
</a>
</div>
<div class="foot">پنل روی <b>__PANEL_URL__</b> در حال اجراست · به‌روزرسانی خودکار هر ۵ ثانیه</div>
</main>
<script>
var FA='۰۱۲۳۴۵۶۷۸۹';
function toFa(n){return String(n).replace(/[0-9]/g,function(d){return FA[d];});}
function statusKey(p){
  if(p.run_status==='busy')return'running';
  if(p.registration_status==='success')return'success';
  if(p.registration_status==='blocked')return'blocked';
  return'ready';
}
function refresh(){
  fetch('/state',{cache:'no-store'}).then(function(r){return r.json();}).then(function(s){
    if(!s||s.error)return;
    var ps=s.profiles||[],c={running:0,success:0,blocked:0};
    ps.forEach(function(p){var k=statusKey(p);if(c[k]!==undefined)c[k]++;});
    document.getElementById('s-total').textContent=toFa(ps.length);
    document.getElementById('s-running').textContent=toFa(c.running);
    document.getElementById('s-success').textContent=toFa(c.success);
    document.getElementById('s-blocked').textContent=toFa(c.blocked);
  }).catch(function(){});
}
refresh();setInterval(refresh,5000);
</script>
</body></html>"""


LAUNCH_PAGE = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IRICA — سرویس رجیستری</title>
<link rel="icon" href="/favicon.ico">
<style>
  /* IRICA design system — light entry skin (launch card, no theme toggle).
     v1.3.5 (operator request) kept: light by default, like every other page. */
  @font-face{
    font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-var.woff2') format('woff2-variations');
    font-weight:100 900;font-style:normal;font-display:swap;
  }
  @font-face{
    font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-Bold.woff2') format('woff2');
    font-weight:700;font-style:normal;font-display:swap;
  }
  :root{
    --bg:#f4f6fb;--card:#ffffff;--card2:#f7f8fd;--line:rgba(27,32,54,.10);
    --line-strong:rgba(27,32,54,.16);--txt:#1b2036;--muted:#5c6484;
    --brand:#4460e3;--brand-hover:#3757cf;--brand-soft:rgba(68,96,227,.10);
    --on-brand:#ffffff;--ok:#0c7d4f;--ok-soft:rgba(15,157,99,.12);
    --danger:#d93752;--danger-soft:rgba(217,55,82,.10);
    --shadow-1:0 1px 2px rgba(16,20,40,.05),0 1px 6px rgba(16,20,40,.04);
    --shadow-2:0 4px 14px rgba(16,20,40,.10),0 1px 3px rgba(16,20,40,.06);
    --ring:0 0 0 3px rgba(68,96,227,.30);
  }
  *{box-sizing:border-box; margin:0; padding:0;}
  html{color-scheme:light}
  body{
    font-family:Vazirmatn,"Segoe UI",Tahoma,sans-serif; background:
      radial-gradient(900px 480px at 85% -10%,rgba(79,107,239,.13),transparent 60%),
      radial-gradient(720px 420px at 6% 8%,rgba(124,92,245,.09),transparent 55%),
      var(--bg);
    color:var(--txt); min-height:100vh; display:flex; align-items:center;
    justify-content:center; padding:24px; font-size:14px; line-height:1.7;
    -webkit-font-smoothing:antialiased;
  }
  .card{
    width:100%; max-width:430px; background:var(--card); border:1px solid var(--line);
    border-radius:18px; padding:30px 26px; box-shadow:var(--shadow-2);
  }
  .logo{width:56px; height:56px; border-radius:14px; margin:0 auto 14px;
    background:linear-gradient(135deg,var(--brand),#7c5cf5);
    display:flex; align-items:center; justify-content:center;
    color:var(--on-brand); font-size:24px; font-weight:800; box-shadow:var(--shadow-1);}
  h1{font-size:17px; font-weight:750; text-align:center; margin-bottom:4px;}
  .status{
    display:flex; align-items:center; justify-content:center; gap:8px;
    font-size:13px; font-weight:700; margin:12px 0 18px; padding:9px 12px;
    border-radius:10px; background:var(--ok-soft); color:var(--ok);
    border:1px solid rgba(15,157,99,.25);
  }
  .status.off{background:var(--danger-soft); color:var(--danger);
    border-color:rgba(217,55,82,.25);}
  .dot{width:9px; height:9px; border-radius:50%; background:var(--ok);
    box-shadow:0 0 0 3px rgba(15,157,99,.18); animation:pulse 2s infinite;}
  .status.off .dot{background:var(--danger); animation:none;
    box-shadow:0 0 0 3px rgba(217,55,82,.18);}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
  .stats{display:flex; gap:8px; margin-bottom:18px;}
  .stat{flex:1; text-align:center; background:var(--card2); border:1px solid var(--line);
    border-radius:12px; padding:10px 6px;}
  .stat b{display:block; font-size:19px; font-weight:800;}
  .stat span{font-size:10.5px; color:var(--muted);}
  .btn{width:100%; display:flex; align-items:center; justify-content:center; gap:9px;
    border:none; border-radius:12px; padding:12px; font-size:14px; font-weight:700;
    cursor:pointer; margin-bottom:10px; color:var(--on-brand); transition:.15s;
    font-family:inherit;}
  .btn svg{flex:none;}
  .btn:hover{filter:brightness(1.08); transform:translateY(-1px);}
  .btn:disabled{opacity:.55; cursor:wait; transform:none;}
  .btn:focus-visible{outline:none; box-shadow:var(--ring);}
  .b-open{background:linear-gradient(135deg,var(--brand),#7c5cf5);}
  .b-estelam,.b-open2,.b-driver{background:var(--card); color:var(--txt); border:1px solid var(--line-strong);}
  .b-estelam:hover,.b-open2:hover,.b-driver:hover{filter:none; border-color:var(--brand);
    background:var(--brand-soft); color:var(--brand);}
  .b-stop{background:var(--danger-soft); color:var(--danger);
    border:1px solid rgba(217,55,82,.25);}
  .b-stop:hover{filter:none; background:rgba(217,55,82,.16);}
  .note{display:none; text-align:center; font-size:12.5px; font-weight:700;
    color:var(--muted); line-height:1.9; padding:0 0 10px;}
  .foot{margin-top:14px; display:flex; align-items:center; justify-content:space-between;
    font-size:11px; color:var(--muted); direction:ltr;}
  .badge{padding:2px 9px; border-radius:99px; border:1px solid var(--line);
    background:var(--card2); font-weight:700;}
  .off-msg{display:none; text-align:center; font-size:13px; color:var(--muted);
    line-height:1.9; padding:12px 0 4px;}
</style>
</head>
<body>
<div class="card">
  <div class="logo">R</div>
  <h1>سرویس رجیستری IRICA</h1>
  <div class="status" id="status"><span class="dot"></span><span id="status-text">در حال بررسی…</span></div>
  <div class="stats">
    <div class="stat"><b id="s-total">—</b><span>پروفایل</span></div>
    <div class="stat"><b id="s-run">—</b><span>در حال کار</span></div>
    <div class="stat"><b id="s-success">—</b><span>موفق</span></div>
    <div class="stat"><b id="s-blocked">—</b><span>مسدود</span></div>
  </div>
  <button class="btn b-open" id="btn-crm" onclick="location.href='/crm'">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>
    پنل یکپارچه رجیستری</button>
  <button class="btn b-estelam" id="btn-estelam" onclick="location.href='/site-2'">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
    پنل استعلام‌ها</button>
  <button class="btn b-open2" id="btn-open" onclick="location.href='/site-1'">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 22h18"/><path d="M6 18v-7"/><path d="M10 18v-7"/><path d="M14 18v-7"/><path d="M18 18v-7"/><path d="m12 2 8 5H4l8-5Z"/></svg>
    پنل قدیمی رجیستری</button>
  <button class="btn b-driver" id="btn-driver">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></svg>
    به‌روزرسانی درایور مرورگر</button>
  <button class="btn b-stop" id="btn-stop">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.02"/></svg>
    بستن سرویس</button>
  <div class="note" id="drv-note"></div>
  <div class="off-msg" id="off-msg">سرویس خاموش شد.<br>این صفحه را ببندید؛ برای اجرای دوباره، میان‌بر دسکتاپ را اجرا کنید.</div>
  <div class="foot">
    <span>127.0.0.1:8750</span>
    <span class="badge">نسخه <span id="v">…</span></span>
  </div>
</div>
<script>
var toFa=function(n){return String(n).replace(/\d/g,function(d){return '۰۱۲۳۴۵۶۷۸۹'[d]})};
function fill(s){
  var ps=s.profiles||[];
  var running=ps.filter(function(p){return p.runner_pid||p.device_inquiry_pid}).length;
  var ok=ps.filter(function(p){return p.registration_status==='success'}).length;
  var bl=ps.filter(function(p){return p.registration_status==='blocked'}).length;
  document.getElementById('s-total').textContent=toFa(ps.length);
  document.getElementById('s-run').textContent=toFa(running);
  document.getElementById('s-success').textContent=toFa(ok);
  document.getElementById('s-blocked').textContent=toFa(bl);
}
fetch('/state').then(function(r){return r.json()}).then(fill).catch(function(){});
fetch('/site-1').then(function(r){return r.text()}).then(function(t){
  var m=t.match(/نسخه\s*([0-9.]+)/);
  document.getElementById('v').textContent=m?m[1]:'?';
  document.getElementById('status-text').textContent='سرویس رجیستری فعال است';
}).catch(function(){
  document.getElementById('status').classList.add('off');
  document.getElementById('status-text').textContent='سرویس در دسترس نیست';
});
document.getElementById('btn-stop').onclick=function(){
  var b=this; var orig=b.innerHTML; b.disabled=true; b.textContent='در حال بستن…';
  fetch('/shutdown',{method:'POST'}).then(function(r){return r.json()}).then(function(){
    b.textContent='سرویس بسته شد ✓'; b.style.filter='grayscale(.4)';
    document.getElementById('status').classList.add('off');
    document.getElementById('status-text').textContent='سرویس خاموش شد';
    document.getElementById('off-msg').style.display='block';
  }).catch(function(){
    b.disabled=false; b.innerHTML=orig;
  });
};
document.getElementById('btn-driver').onclick=function(){
  var b=this; var orig=b.innerHTML; var note=document.getElementById('drv-note');
  var msgs={
    'updated':['درایور مرورگر به‌روز شد','var(--ok)'],
    'up-to-date':['درایور مرورگر از قبل به‌روز بود','var(--ok)'],
    'disabled':['به‌روزرسانی خودکار درایور غیرفعال است','var(--muted)'],
    'no-browser-version':['نسخه Chrome نصب‌شده خوانده نشد','var(--danger)'],
    'busy':['یک به‌روزرسانی درایور در حال اجراست؛ چند لحظه بعد دوباره تلاش کنید','var(--muted)'],
    'driver-in-use':['فایل درایور در حال استفاده است؛ ابتدا ربات‌ها را ببندید و دوباره تلاش کنید','var(--danger)']
  };
  b.disabled=true; b.textContent='در حال به‌روزرسانی…';
  note.style.display='none'; note.removeAttribute('title');
  fetch('/driver-update',{method:'POST'}).then(function(r){return r.json()}).then(function(res){
    b.disabled=false; b.innerHTML=orig;
    var pair=msgs[res.status]||['به‌روزرسانی درایور ناموفق بود؛ اتصال پروکسی را بررسی کنید','var(--danger)'];
    var text=pair[0]+(res.version?' (نسخه '+res.version+')':'');
    if(res.status==='updated'||res.status==='up-to-date'){text+=' ✓';}
    note.textContent=text;
    note.title=res.detail||'';
    note.style.color=pair[1];
    note.style.display='block';
  }).catch(function(){
    b.disabled=false; b.innerHTML=orig;
    note.textContent='ارتباط با سرویس برقرار نشد';
    note.style.color='var(--danger)';
    note.style.display='block';
  });
};
</script>
</body></html>"""


def render_launch_page():
    return with_csrf_bootstrap(LAUNCH_PAGE).encode("utf-8")


def render_home_page():
    html = HOME_PAGE.replace("__PANEL_URL__", f"{HOST}:{PORT}")
    html = html.replace("__VERSION_TAG__",
                        f'<span class="irica-version">نسخه {app_version_text() or "—"}</span>')
    html = html.replace("__VERSION__", app_version_text() or "—")
    return with_csrf_bootstrap(html).encode("utf-8")


def render_site_two_page():
    with open(os.path.join(HERE, "dashboard-new.html"), encoding="utf-8") as f:
        # Not routed today, but the moment it is its POSTs would need the
        # token like every other page, so the client goes in here too.
        return with_csrf_bootstrap(f.read()).encode("utf-8")


ESTELAM_PAGE = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>استعلام سلامت دستگاه</title>
<link rel="icon" href="data:,">
<style>
  /* Bundled Vazirmatn — offline, no external fetch. Light theme is the
     default; html[data-theme="dark"] swaps every token below. */
  @font-face{
    font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-var.woff2') format('woff2-variations');
    font-weight:100 900;font-style:normal;font-display:swap;
  }
  @font-face{
    font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-Bold.woff2') format('woff2');
    font-weight:700;font-style:normal;font-display:swap;
  }

  :root{
    --bg:#f4f6fb;--card:#ffffff;--card2:#f7f8fd;--line:rgba(27,32,54,.10);
    --line-strong:rgba(27,32,54,.16);--txt:#1b2036;--muted:#5c6484;--faint:#687291;
    --brand:#4460e3;--brand-hover:#3757cf;--brand-soft:rgba(68,96,227,.10);--on-brand:#ffffff;
    --ok:#0c7d4f;--ok-soft:rgba(15,157,99,.12);
    --busy:#b9770e;--busy-soft:rgba(185,119,14,.13);
    --danger:#d93752;--danger-soft:rgba(217,55,82,.10);
    --info:#2f6fd6;
    --pill-neutral-bg:rgba(27,32,54,.06);--pill-neutral-fg:#5c6484;
    --pill-ok-bg:rgba(15,157,99,.13);--pill-ok-fg:#0b7a4d;
    --pill-danger-bg:rgba(217,55,82,.12);--pill-danger-fg:#b72740;
    --pill-warn-bg:rgba(185,119,14,.14);--pill-warn-fg:#92590a;
    --logbg:#f8f9fe;--scroll:rgba(27,32,54,.20);--sn:#4257a8;
    --shadow-1:0 1px 2px rgba(16,20,40,.05),0 1px 6px rgba(16,20,40,.04);
    --shadow-2:0 4px 14px rgba(16,20,40,.10),0 1px 3px rgba(16,20,40,.06);
    --ring:0 0 0 3px rgba(68,96,227,.30);
  }
  html[data-theme="dark"]{
    --bg:#101322;--card:#181c2e;--card2:#1f2438;--line:rgba(255,255,255,.08);
    --line-strong:rgba(255,255,255,.14);--txt:#eef1fb;--muted:#aeb6d0;--faint:#848cad;
    --brand:#7d95ff;--brand-hover:#93a7ff;--brand-soft:rgba(125,149,255,.12);--on-brand:#0e1330;
    --ok:#3ad28b;--ok-soft:rgba(58,210,139,.13);
    --busy:#f6b94b;--busy-soft:rgba(246,185,75,.13);
    --danger:#ff6678;--danger-soft:rgba(255,102,120,.13);
    --info:#9db9ff;
    --pill-neutral-bg:rgba(255,255,255,.07);--pill-neutral-fg:#a9b7e0;
    --pill-ok-bg:rgba(58,210,139,.14);--pill-ok-fg:#3ad28b;
    --pill-danger-bg:rgba(255,102,120,.14);--pill-danger-fg:#ff6678;
    --pill-warn-bg:rgba(246,185,75,.14);--pill-warn-fg:#f6b94b;
    --logbg:#141828;--scroll:rgba(255,255,255,.16);--sn:#8ea2d8;
    --shadow-1:0 1px 2px rgba(0,0,0,.35),0 1px 6px rgba(0,0,0,.25);
    --shadow-2:0 6px 18px rgba(0,0,0,.45),0 2px 5px rgba(0,0,0,.30);
    --ring:0 0 0 3px rgba(125,149,255,.30);
  }
  *{box-sizing:border-box}
  html{color-scheme:light}
  html[data-theme="dark"]{color-scheme:dark}
  body{margin:0;background:var(--bg);color:var(--txt);
    font-family:Vazirmatn,"Segoe UI",Tahoma,sans-serif;
    font-size:14px;line-height:1.6;padding:0 14px 70px;-webkit-font-smoothing:antialiased}
  :is(a,button,input,select,textarea):focus-visible{outline:none;box-shadow:var(--ring)}
  .ic{flex:none;vertical-align:-2px}
  /* main frame width: interactive (drag grips at the edges + presets),
     persisted in localStorage; --wrapw is set by JS. */
  .wrap{width:min(var(--wrapw,1620px),100%);margin:0 auto;position:relative}
  .wgrip{position:absolute;top:0;bottom:0;width:12px;cursor:ew-resize;z-index:5;
          display:flex;align-items:center;justify-content:center}
  .wgrip.l{inset-inline-start:-14px}
  .wgrip.r{inset-inline-end:-14px}
  .wgrip::before{content:"";width:4px;height:56px;border-radius:99px;background:var(--line);
                 transition:background .15s,height .15s}
  .wgrip:hover::before,.wgrip.drag::before{background:var(--brand);height:96px}
  body.wresize{cursor:ew-resize;user-select:none}
  /* sticky topbar: brand monogram + live run pill + navigation + frame tools */
  .topbar{position:sticky;top:0;z-index:40;border-bottom:1px solid var(--line);
    background:color-mix(in srgb,var(--bg) 88%,transparent);
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
  .tb-in{width:min(var(--wrapw,1620px),100%);margin:0 auto;display:flex;align-items:center;
    gap:10px;flex-wrap:wrap;padding:10px 0}
  .brand{display:flex;align-items:center;gap:11px;min-width:0}
  .brand .mono{width:38px;height:38px;border-radius:11px;flex:none;background:var(--brand);
    color:var(--on-brand);display:grid;place-items:center;font-size:16px;font-weight:800}
  .brand h1{font-size:16.5px;font-weight:750;margin:0;letter-spacing:-.2px;white-space:nowrap}
  .brand .sub{font-size:11px;color:var(--muted);margin-top:1px;font-weight:400}
  @media(max-width:600px){.brand h1{white-space:normal;font-size:15px}
    .brand .sub{display:none}}
  .irica-version{font-size:11px;color:var(--muted);border:1px solid var(--line);
    border-radius:999px;padding:3px 11px;direction:ltr;align-self:center;white-space:nowrap}
  /* live robot-status pill in the topbar (mirrors #run-state) */
  .runpill{display:inline-flex;align-items:center;gap:7px;padding:5px 12px;border-radius:999px;
    background:var(--pill-neutral-bg);color:var(--muted);font-size:12px;font-weight:650;
    border:1px solid var(--line);white-space:nowrap}
  .runpill .rp-dot{width:8px;height:8px;border-radius:99px;background:var(--faint);flex:none}
  .runpill.on{background:var(--busy-soft);color:var(--busy);border-color:transparent}
  .runpill.on .rp-dot{background:var(--busy);animation:pulse 1.6s infinite}
  .tb-tools{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-inline-start:auto}
  .tb-sep{width:1px;height:24px;align-self:center;background:var(--line);margin-inline-end:2px}
  .navlink{display:inline-flex;align-items:center;gap:8px;padding:7px 13px;
    border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--txt);
    text-decoration:none;font-size:12.5px;font-weight:500;box-shadow:var(--shadow-1);
    transition:border-color .15s,color .15s,background .15s;white-space:nowrap}
  .navlink .ic{color:var(--muted)}
  .navlink:hover{border-color:var(--brand);color:var(--brand);background:var(--brand-soft)}
  .navlink:hover .ic{color:var(--brand)}
  .system-close-btn{display:inline-flex;align-items:center;gap:7px;padding:8px 13px;border-radius:10px;
    font-size:12.5px;font-weight:650;border:1px solid var(--danger-soft);
    background:var(--danger-soft);color:var(--danger);cursor:pointer;font-family:inherit;
    transition:.15s;align-self:center;white-space:nowrap}
  .system-close-btn:hover{background:var(--danger);color:#fff;border-color:var(--danger)}
  /* frame width presets + theme toggle */
  .wbar{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
  .wbar .wlab{color:var(--muted);font-size:11.5px}
  .wbar .wbtn,.tbtn{background:var(--card);border:1px solid var(--line);color:var(--muted);
    border-radius:9px;padding:5px 11px;font-size:12px;cursor:pointer;font-family:inherit;
    display:inline-flex;align-items:center;gap:6px;min-height:28px;
    transition:color .15s,border-color .15s,background .15s}
  .wbar .wbtn:hover,.tbtn:hover{color:var(--txt);border-color:var(--line-strong);background:var(--card2)}
  .wbar .wbtn.on{background:var(--brand);border-color:transparent;color:var(--on-brand);font-weight:650}
  /* layout: person card sidebar (start side, sticky) + main column */
  .cols{display:grid;grid-template-columns:330px minmax(0,1fr);gap:16px;align-items:start;
    padding-top:18px}
  .side{position:sticky;top:82px}
  .side .grid{grid-template-columns:1fr}
  .side .card{margin-bottom:0}
  @media(max-width:900px){
    .cols{grid-template-columns:minmax(0,1fr)}
    .wgrip{display:none}
    .side{position:static}
  }
  /* cards */
  .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;
    margin-bottom:16px;box-shadow:var(--shadow-1)}
  .card h2{display:flex;align-items:center;gap:10px;margin:0 0 4px;font-size:15px;font-weight:650}
  .card h2 .hicon{width:28px;height:28px;border-radius:9px;background:var(--brand-soft);
    color:var(--brand);display:grid;place-items:center;flex:none}
  .hint{color:var(--muted);font-size:12.5px;margin:0 0 14px}
  .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
  @media(max-width:760px){.grid{grid-template-columns:1fr}}
  label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px;font-weight:500}
  input{width:100%;padding:9px 12px;border-radius:10px;border:1px solid var(--line);
        background:var(--card);color:var(--txt);font-family:inherit;font-size:13.5px;
        direction:ltr;text-align:left;transition:border-color .15s,box-shadow .15s}
  input::placeholder{color:var(--faint)}
  input:focus{outline:none;border-color:var(--brand);box-shadow:var(--ring)}
  /* buttons: bordered base, brand-filled primary, soft danger, quiet ghost */
  button{border:1px solid transparent;border-radius:10px;padding:8px 15px;font-family:inherit;
         font-size:13px;font-weight:650;cursor:pointer;color:var(--on-brand);background:var(--brand);
         display:inline-flex;align-items:center;gap:7px;min-height:34px;line-height:1.5;
         transition:background .15s,border-color .15s,color .15s}
  button:hover{background:var(--brand-hover)}
  button.ghost{background:var(--card);border-color:var(--line-strong);color:var(--txt)}
  button.ghost:hover{background:var(--brand-soft);border-color:var(--brand);color:var(--brand)}
  button.ok{background:var(--ok);color:#fff}
  button.ok:hover{filter:brightness(1.08);background:var(--ok)}
  button.warn{background:var(--busy-soft);color:var(--busy)}
  button.warn:hover{background:var(--busy-soft);filter:brightness(.97)}
  button.danger{background:var(--danger-soft);color:var(--danger)}
  button.danger:hover{background:var(--danger);color:#fff}
  button:disabled{opacity:.5;cursor:not-allowed}
  .row{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
  .errbox{margin-top:12px;border-inline-start:3px solid var(--danger);background:var(--danger-soft);
          border-radius:10px;padding:10px 12px;font-size:12.5px;display:none}
  .errbox.show{display:block}
  .errbox ul{margin:0;padding-inline-start:18px}
  /* device table */
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:start;vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:11.5px;white-space:nowrap}
  tbody tr:hover td{background:var(--card2)}
  tbody tr:last-child td{border-bottom:none}
  td.mono{direction:ltr;text-align:left;font-family:Consolas,ui-monospace,monospace}
  /* the HAMTA result is long and multi-line: it must wrap, not overflow */
  td.res{white-space:pre-line;line-height:1.6;word-break:break-word;max-width:0}
  #dev-list{overflow-x:auto}
  #dev-list table{table-layout:fixed}
  #dev-list col.c-idx{width:44px}
  #dev-list col.c-sn{width:200px}
  #dev-list col.c-st{width:225px}
  #dev-list col.c-act{width:225px}
  #dev-list td.c-num{text-align:center;color:var(--faint);font-weight:650}
  .dev-name{font-weight:650;font-size:13px;margin-bottom:4px;word-break:break-word}
  /* mobile: the device table stacks into per-device blocks; every selector
     the JS and live checks rely on (#dev-list tbody tr, td.res, …) is kept */
  @media(max-width:760px){
    #dev-list thead{display:none}
    #dev-list table,#dev-list tbody,#dev-list tr,#dev-list td{display:block;width:auto}
    #dev-list table{table-layout:auto}
    #dev-list tr{border-bottom:1px solid var(--line);padding:10px 0}
    #dev-list tr:last-child{border-bottom:none}
    #dev-list td{border-bottom:none;padding:5px 0}
    #dev-list td.c-num{display:none}
    #dev-list td.res{max-width:none}
  }
  /* status grid: (hamta/gomrok) x (label, badge, shot icon, inquiry time) —
     no nested tables so the main table's row selectors stay intact */
  .stgrid{display:grid;grid-template-columns:auto auto auto 1fr;gap:5px 8px;align-items:center}
  .stgrid .slab{color:var(--muted);font-size:10.5px;white-space:nowrap}
  .stgrid .when{color:var(--faint);font-size:11px;white-space:nowrap}
  /* v1.9.1: the shot icon sits in its own grid cell (a wrapper keeps the
     ibtn from stretching to the row height). The `.ibtn` base lives in
     PAGE_HEAD and CRM_PAGE, which this page does not include, so the icon
     needs its own minimal definition here -- without it the camera renders
     as a native grey button. Same reason the tooltip is a plain `title`:
     the `data-tip` layer (CSS ::after in PAGE_HEAD, JS in CRM_PAGE) is not
     part of this page either. */
  .stgrid .shot-w{display:inline-flex;align-items:center}
  .stgrid .ibtn.sh{width:26px;height:26px;min-width:26px;padding:0;
    display:inline-flex;align-items:center;justify-content:center;
    border:1px solid var(--line-strong);border-radius:8px;
    background:var(--card);color:var(--muted);cursor:pointer;
    transition:color .13s,border-color .13s,background .13s}
  .stgrid .ibtn.sh:hover{color:var(--brand);border-color:var(--brand);
    background:var(--brand-soft)}
  .stgrid .ibtn.sh:focus-visible{outline:none;border-color:var(--brand);
    box-shadow:0 0 0 3px var(--brand-soft)}
  .stgrid .ibtn.sh .ic{width:13px;height:13px}
  /* serials one and two stacked in a single column (less width) */
  .mono.sn1,.mono.sn2{direction:ltr;text-align:left;font-family:Consolas,ui-monospace,monospace;line-height:1.5}
  .mono.sn2{color:var(--muted);font-size:12px;margin-top:2px}
  .mono.sn2::before{content:"↳ ";color:var(--line)}
  /* status badges + runtime chips: soft pills with a leading status dot */
  .badge{display:inline-flex;align-items:center;gap:6px;padding:2.5px 9px;border-radius:999px;
    font-size:11px;font-weight:650;white-space:nowrap}
  .badge::before{content:"";width:5px;height:5px;border-radius:99px;background:currentColor;flex:none}
  .b-pending{background:var(--pill-neutral-bg);color:var(--pill-neutral-fg)}
  .b-running{background:var(--pill-warn-bg);color:var(--pill-warn-fg)}
  .b-healthy{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .b-problem{background:var(--pill-danger-bg);color:var(--pill-danger-fg)}
  .b-advanced{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .b-error{background:var(--pill-danger-bg);color:var(--pill-danger-fg)}
  .b-good{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .b-registered{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .b-blocked{background:var(--pill-danger-bg);color:var(--pill-danger-fg)}
  .b-unknown{background:var(--pill-warn-bg);color:var(--pill-warn-fg)}
  .empty{color:var(--muted);text-align:center;padding:26px 18px;font-size:13px;
    border:1px dashed var(--line-strong);border-radius:12px}
  /* service picker: segmented control (the page's signature element) */
  .svc-pick{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
  .svc-pick label{margin:0;font-size:12.5px;color:var(--muted);font-weight:500}
  .svc-btns{display:inline-flex;gap:4px;background:var(--card2);
            border:1px solid var(--line);border-radius:12px;padding:4px}
  .svc-btns .svc{background:transparent;border:1px solid transparent;color:var(--muted);
                 border-radius:9px;padding:7px 14px;font-size:12.5px;font-weight:650;
                 cursor:pointer;font-family:inherit;min-height:32px;
                 transition:color .15s,background .15s,box-shadow .15s}
  .svc-btns .svc:hover{color:var(--txt)}
  .svc-btns .svc.on{background:var(--brand);border-color:transparent;color:var(--on-brand);
                    box-shadow:var(--shadow-1)}
  /* status column: hamta and gomrok badges stacked with a small label */
  .stack{display:flex;align-items:center;gap:6px;margin-bottom:4px}
  .stack:last-child{margin-bottom:0}
  .slab{color:var(--muted);font-size:10.5px;min-width:26px}
  .res2{color:var(--muted);font-size:12px;margin-top:3px}
  /* run console strip */
  .runbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;background:var(--card2);
          border:1px solid var(--line);border-radius:12px;padding:12px 14px}
  .dot{width:10px;height:10px;border-radius:99px;background:var(--faint);flex:0 0 auto}
  .dot.on{background:var(--busy);box-shadow:0 0 0 4px color-mix(in srgb,var(--busy) 18%,transparent);
          animation:pulse 1.6s infinite}
  @keyframes pulse{50%{box-shadow:0 0 0 9px transparent}}
  .runbar .st{font-size:13.5px;font-weight:650}
  .runbar .meta{font-size:11.5px;color:var(--faint)}
  .chips{display:flex;gap:7px;flex-wrap:wrap;margin-inline-start:auto}
  .chip{font-size:11.5px;padding:3px 10px;border-radius:999px;font-weight:600;
        background:var(--pill-neutral-bg);color:var(--pill-neutral-fg)}
  .chip.healthy{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .chip.problem,.chip.error{background:var(--pill-danger-bg);color:var(--pill-danger-fg)}
  .chip.running{background:var(--pill-warn-bg);color:var(--pill-warn-fg)}
  .chip.advanced{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .chip.good,.chip.success{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .chip.registered{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .chip.blocked{background:var(--pill-danger-bg);color:var(--pill-danger-fg)}
  .chip.unknown{background:var(--pill-warn-bg);color:var(--pill-warn-fg)}
  /* interactive log console */
  .logtools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
  .filters{display:flex;gap:6px;flex-wrap:wrap}
  .f{font-size:11.5px;padding:5px 11px;border-radius:999px;border:1px solid var(--line);
     background:transparent;color:var(--muted);cursor:pointer;min-height:28px;
     transition:color .15s,border-color .15s,background .15s}
  .f:hover{color:var(--txt);border-color:var(--line-strong);background:var(--card2)}
  .f.on{background:var(--brand);border-color:transparent;color:var(--on-brand);font-weight:650}
  .srch{position:relative;flex:1 1 190px;min-width:150px;display:inline-flex;align-items:center}
  .srch .ic{position:absolute;inset-inline-start:11px;color:var(--faint);pointer-events:none}
  .srch input[type=search]{width:100%;padding:8px 12px;padding-inline-start:32px;
    direction:rtl;text-align:right}
  .logbox{height:340px;overflow-y:auto;overflow-x:hidden;border:1px solid var(--line);
          border-radius:12px;background:var(--logbg);padding:8px}
  .logbox::-webkit-scrollbar{width:9px}
  .logbox::-webkit-scrollbar-thumb{background:var(--scroll);border-radius:9px}
  .li{border:1px solid var(--line);border-inline-start-width:3px;border-radius:10px;
      padding:9px 11px;margin-bottom:7px;background:var(--card);cursor:pointer;
      transition:background .15s,transform .15s,box-shadow .15s}
  .li:hover{background:var(--card2);transform:translateY(-1px);box-shadow:var(--shadow-1)}
  .li.s-healthy{border-inline-start-color:var(--ok)}
  .li.s-problem,.li.s-error{border-inline-start-color:var(--danger)}
  .li.s-retry,.li.s-advanced,.li.s-warn,.li.s-running{border-inline-start-color:var(--busy)}
  .li.s-info{border-inline-start-color:var(--brand)}
  .li .h{display:flex;justify-content:space-between;gap:8px;align-items:center;font-size:12px}
  .li .h b{font-size:12.5px;font-weight:650}
  .li .h b .ic{color:currentColor}
  .li .ts{color:var(--faint);font-size:11px}
  .li .sn{color:var(--sn);font-size:11.5px;direction:ltr;margin-top:3px;
    font-family:Consolas,ui-monospace,monospace}
  .li .msg{font-size:12.5px;margin-top:5px;line-height:1.6;max-height:36px;overflow:hidden}
  .li.open .msg{max-height:none}
  .li .more{font-size:11px;color:var(--faint);margin-top:4px}
  .logempty{color:var(--muted);text-align:center;padding:26px;font-size:13px}
  /* live log notifications (top corner) */
  .lognotif-wrap{position:fixed;top:14px;inset-inline-end:14px;z-index:70;display:flex;
    flex-direction:column;gap:8px;width:min(360px,86vw);pointer-events:none}
  .lognotif{pointer-events:auto;background:var(--card);border:1px solid var(--line);
    border-inline-start:4px solid var(--brand);border-radius:12px;padding:10px 12px;
    padding-inline-end:34px;
    box-shadow:var(--shadow-2);position:relative;opacity:0;
    transform:translateX(-14px);transition:.26s}
  .lognotif.show{opacity:1;transform:translateX(0)}
  .lognotif.s-healthy{border-inline-start-color:var(--ok)}
  .lognotif.s-problem,.lognotif.s-error{border-inline-start-color:var(--danger)}
  .lognotif.s-retry,.lognotif.s-advanced,.lognotif.s-warn,.lognotif.s-running{border-inline-start-color:var(--busy)}
  .lognotif .t{font-size:12.5px;font-weight:700;display:flex;gap:6px;align-items:center}
  .lognotif .m{font-size:11.5px;color:var(--muted);margin-top:4px;line-height:1.6;
    max-height:54px;overflow:hidden}
  .lognotif .sn{font-size:10.5px;color:var(--sn);direction:ltr;margin-top:3px;
    font-family:Consolas,ui-monospace,monospace}
  .lognotif .x{position:absolute;top:6px;inset-inline-end:8px;border:0;background:transparent;
    color:var(--muted);font-size:15px;cursor:pointer;padding:1px 5px;min-height:0}
  .lognotif .x:hover{color:var(--txt);background:transparent}
  .notif-toggle{position:fixed;bottom:14px;inset-inline-end:14px;z-index:69;font-size:11.5px;
    padding:6px 11px;border-radius:999px;border:1px solid var(--line);cursor:pointer;
    background:var(--card);color:var(--muted);font-family:inherit;box-shadow:var(--shadow-1);
    display:inline-flex;align-items:center;gap:7px;min-height:0}
  .notif-toggle:hover{color:var(--txt);border-color:var(--line-strong);background:var(--card2)}
  .bulkbar{background:var(--card2);border:1px solid var(--line);border-radius:12px;
    padding:14px;margin-top:14px;display:none}
  .bulkbar.show{display:block}
  .bulkbar .n{font-size:12.5px;color:var(--busy);margin-bottom:10px;font-weight:600}
  .toast{position:fixed;top:16px;left:50%;transform:translate(-50%,-18px);z-index:60;
         min-width:min(420px,92vw);background:var(--card);border:1px solid var(--line);
         border-inline-start-width:4px;border-radius:12px;padding:12px 14px;
         padding-inline-end:38px;
         box-shadow:var(--shadow-2);opacity:0;pointer-events:none;transition:.28s}
  .toast.show{opacity:1;transform:translate(-50%,0);pointer-events:auto}
  .toast.ok{border-inline-start-color:var(--ok)}
  .toast.fail{border-inline-start-color:var(--danger)}
  .toast .t{font-size:13.5px;font-weight:700}
  .toast .m{font-size:11.5px;color:var(--muted);display:none;direction:ltr;text-align:left;margin-top:5px;
    font-family:Consolas,ui-monospace,monospace}
  .toast:hover .m{display:block}
  .toast button{position:absolute;top:6px;inset-inline-end:8px;background:transparent;border:0;
    color:var(--muted);font-size:16px;padding:2px 6px;min-height:0}
  .toast button:hover{background:transparent;color:var(--txt)}
  /* result column: short excerpt + full-text modal */
  .res-short{white-space:pre-line;line-height:1.6;word-break:break-word}
  .res-more{margin-top:6px;background:transparent;border:1px solid var(--line-strong);
            color:var(--brand);border-radius:8px;padding:3px 10px;font-size:11.5px;
            font-weight:650;cursor:pointer;font-family:inherit;min-height:26px}
  .res-more:hover{border-color:var(--brand);background:var(--brand-soft)}
  .modal{position:fixed;inset:0;z-index:90;display:none;align-items:center;justify-content:center;
         background:rgba(8,12,26,.55);padding:20px}
  .modal.show{display:flex}
  .modal .box{background:var(--card);border:1px solid var(--line);border-radius:16px;
              width:min(760px,94vw);max-height:86vh;display:flex;flex-direction:column;
              box-shadow:var(--shadow-2)}
  .modal .hd{display:flex;align-items:center;justify-content:space-between;gap:10px;
             padding:14px 16px;border-bottom:1px solid var(--line)}
  .modal .hd h3{margin:0;font-size:15px}
  .modal .hd .sn{font-size:11.5px;color:var(--muted);direction:ltr;
    font-family:Consolas,ui-monospace,monospace}
  .modal .bd{padding:16px;overflow:auto;white-space:pre-line;line-height:1.75;font-size:13.5px}
  .modal .ft{padding:12px 16px;border-top:1px solid var(--line);display:flex;gap:8px;justify-content:flex-start}
  .modal .x{background:transparent;border:0;color:var(--muted);font-size:20px;cursor:pointer;padding:0 6px;min-height:0}
  .modal .x:hover{color:var(--txt);background:transparent}
</style>
</head>
<body>
<div id="toast" class="toast" role="status" aria-live="polite">
  <button type="button" onclick="hideToast()" aria-label="بستن">×</button>
  <div class="t" id="toast-title">—</div>
  <div class="m" id="toast-meta"></div>
</div>
<div class="modal" id="res-modal" role="dialog" aria-modal="true" aria-labelledby="res-modal-title"
     onclick="if(event.target===this)closeResModal()">
  <div class="box">
    <div class="hd">
      <div>
        <h3 id="res-modal-title">متن کامل نتیجه</h3>
        <div class="sn" id="res-modal-sn"></div>
      </div>
      <button type="button" class="x" onclick="closeResModal()" aria-label="بستن">×</button>
    </div>
    <div class="bd" id="res-modal-body"></div>
    <div class="ft">
      <button type="button" class="ghost" onclick="copyResModal()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg><span>کپی متن</span></button>
      <button type="button" onclick="closeResModal()">بستن</button>
    </div>
  </div>
</div>
<div class="modal" id="shot-modal" role="dialog" aria-modal="true" aria-labelledby="shot-modal-title"
     onclick="if(event.target===this)closeShotModal()">
  <div class="box">
    <div class="hd">
      <div>
        <h3 id="shot-modal-title">عکس نتیجهٔ استعلام</h3>
        <div class="sn" id="shot-modal-sn"></div>
      </div>
      <button type="button" class="x" onclick="closeShotModal()" aria-label="بستن">×</button>
    </div>
    <div class="bd" id="shot-modal-body"><img id="shot-modal-img" alt="عکس نتیجهٔ استعلام" style="max-width:100%;height:auto;border-radius:10px;border:1px solid var(--line)"></div>
    <div class="ft">
      <button type="button" class="ghost" id="shot-modal-dl" onclick="shotDownload()"><span id="shot-modal-dl-ic"></span><span>دانلود عکس</span></button>
      <button type="button" onclick="closeShotModal()">بستن</button>
    </div>
  </div>
</div>
<header class="topbar">
  <div class="tb-in">
    <div class="brand">
      <div class="mono" aria-hidden="true">R</div>
      <div>
        <h1>استعلام سلامت دستگاه</h1>
        <div class="sub">استعلام همتا و گمرک، یکجا</div>
      </div>
    </div>
    <div class="irica-version">نسخه __VERSION__</div>
    <div class="runpill" id="top-run-pill"><span class="rp-dot"></span><span class="rp-t">در حال بارگذاری…</span></div>
    <div class="tb-tools">
      <div class="wbar">
        <span class="wlab">عرض کادر:</span>
        <button type="button" class="wbtn" data-w="1080" onclick="setWrapW(1080)">معمولی</button>
        <button type="button" class="wbtn" data-w="1620" onclick="setWrapW(1620)">عریض</button>
        <button type="button" class="wbtn" data-w="max" onclick="setWrapW('max')">تمام‌عرض</button>
        <button type="button" class="tbtn" id="theme-btn" onclick="toggleTheme()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg><span>حالت تاریک</span></button>
      </div>
      <span class="tb-sep" aria-hidden="true"></span>
      <a class="navlink" href="/"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>انتخاب سامانه</a>
      <a class="navlink" href="/crm"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>مدیریت پرونده‌ها</a>
      <button type="button" class="system-close-btn" onclick="closeWholeSystem()" title="همهٔ ربات‌ها متوقف و پنل خاموش می‌شود"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg><span>بستن سامانه</span></button>
    </div>
  </div>
</header>
<div class="wrap">
  <div class="wgrip r" id="wgrip-r" title="کشیدن برای تغییر عرض"></div>
  <div class="wgrip l" id="wgrip-l" title="کشیدن برای تغییر عرض"></div>

  <div class="cols">
  <aside class="side">
  <div class="card">
    <h2><span class="hicon"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>اطلاعات شخص</h2>
    <p class="hint">یک پروفایل ثابت؛ برای همه استعلام‌ها استفاده می‌شود.</p>
    <div class="grid">
      <div><label for="p-national">کد ملی (۱۰ رقم)</label><input id="p-national" inputmode="numeric" maxlength="10" placeholder="0012345678"></div>
      <div><label for="p-birth">تاریخ تولد (۱۳۷۵/۰۴/۲۹)</label><input id="p-birth" maxlength="10" placeholder="1375/04/29"></div>
      <div><label for="p-mobile">شماره موبایل (۰۹...)</label><input id="p-mobile" inputmode="numeric" maxlength="11" placeholder="09121234567"></div>
    </div>
    <div class="row"><button onclick="savePerson()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg><span>ذخیره اطلاعات شخص</span></button></div>
    <div class="errbox" id="p-err"></div>
  </div>
  </aside>

  <div class="colmain">
  <div class="card">
    <h2><span class="hicon"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg></span>اطلاعات دستگاه</h2>
    <p class="hint">نام دستگاه +سریال ۱۵ رقمی. سریال دوم اختیاری است (دو سیم‌کارت).</p>
    <div class="row">
      <button onclick="startSingle()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg><span>افزودن دستگاه</span></button>
      <button class="ghost" onclick="startBulk()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg><span>افزودن عمده</span></button>
    </div>

    <div class="bulkbar" id="dev-form">
      <div class="n" id="dev-form-note"></div>
      <div class="grid">
        <div><label for="d-name">نام دستگاه</label><input id="d-name" maxlength="40" placeholder="آیفون ۱۷ محمد" style="direction:rtl;text-align:right"></div>
        <div><label for="d-s1">سریال اول</label><input id="d-s1" inputmode="numeric" maxlength="15" placeholder="356938035643809"></div>
        <div><label for="d-s2">سریال دوم (اختیاری)</label><input id="d-s2" inputmode="numeric" maxlength="15" placeholder=""></div>
      </div>
      <div class="row" id="dev-form-actions"></div>
      <div class="errbox" id="d-err"></div>
    </div>
  </div>

  <div class="card">
    <h2><span class="hicon"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></span>مدیریت اجرای استعلام</h2>
    <p class="hint">کنترل مرورگر و پروسه استعلام در حال اجرا.</p>
    <div class="svc-pick">
      <label>نوع استعلام:</label>
      <div class="svc-btns" id="svc-btns">
        <button type="button" class="svc on" data-svc="hamta" onclick="pickSvc('hamta')">استعلام همتا</button>
        <button type="button" class="svc" data-svc="gomrok" onclick="pickSvc('gomrok')">استعلام گمرک</button>
        <button type="button" class="svc" data-svc="all" onclick="pickSvc('all')">انجام همه استعلام‌ها</button>
      </div>
    </div>
    <div class="runbar">
      <span class="dot" id="run-dot"></span>
      <span class="st" id="run-state">در حال بارگذاری…</span>
      <span class="meta" id="run-meta"></span>
      <span class="chips" id="run-chips"></span>
    </div>
    <div class="row">
      <button class="ok" id="btn-start-all" onclick="startAll()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>شروع استعلام (در انتظارها)</span></button>
      <button class="danger" onclick="stopRun()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="5" width="14" height="14" rx="2"/></svg><span>توقف و بستن مرورگر</span></button>
      <button class="warn" onclick="restartRun()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg><span>راه‌اندازی مجدد</span></button>
      <button class="ghost" onclick="retryFailed()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg><span>تلاش مجدد ناموفق‌ها</span></button>
      <button class="ghost" onclick="refreshAll()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg><span>به‌روزرسانی وضعیت</span></button>
    </div>
    <div class="errbox" id="run-err"></div>
  </div>

  <div class="card">
    <h2><span class="hicon"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg></span>دستگاه‌ها</h2>
    <p class="hint">نتیجه «سالم» یعنی پیام «شناسه ... در گمرک ورودی یافت نشد» گرفته شده است.</p>
    <div id="dev-list"></div>
  </div>

  <div class="card">
    <h2><span class="hicon"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>لاگ اجراهای اخیر</h2>
    <p class="hint">روی هر لاگ کلیک کنید تا جزئیات کامل باز شود.</p>
    <div class="logtools">
      <div class="filters" id="log-filters"></div>
      <div class="srch"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input type="search" id="log-q" placeholder="جستجو در پیام یا سریال…" aria-label="جستجو در پیام یا سریال" oninput="renderLogs()"></div>
      <button class="ghost" onclick="clearLogs()"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg><span>پاک کردن لاگ</span></button>
    </div>
    <div class="logbox" id="log-box"></div>
  </div>
  </div>
  </div>
</div>
<div id="lognotif-wrap" class="lognotif-wrap" aria-live="polite"></div>
<button type="button" id="notif-toggle" class="notif-toggle" onclick="toggleLogNotif()"></button>
<script>
var STATE={person:{},devices:[]};
var MODE='';   // '' | 'single' | 'bulk'
var FA_STATUS=__STATUS_JSON__;          /* motn-e kamel (baraye tooltip/chips) */
var BADGE_FA=__BADGE_JSON__;            /* motn-e KUTAH-e badge-e gomrok */
var HAMTA_FA={pending:'در انتظار',running:'در حال استعلام',good:'مجاز (قابل ثبت)',
  registered:'ثبت‌شده (قانونی)',blocked:'مسدود/خطر',success:'موفق',
  unknown:'نامشخص',error:'خطای ربات'};

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function digits(s){return String(s||'').replace(/[^0-9]/g,'');}
/* Jalali calendar display helpers: stored values stay ISO Gregorian and are
   converted only at render time. Empty/invalid input renders as an em-dash. */
function faDate(iso){
  var d=new Date(String(iso||'').replace(' ','T'));
  if(isNaN(d))return String(iso||'—');
  try{return d.toLocaleDateString('fa-IR-u-ca-persian',{day:'numeric',month:'long',year:'numeric'});}catch(e){return String(iso||'—');}
}
function faDateTime(iso){
  var d=new Date(String(iso||'').replace(' ','T'));
  if(isNaN(d))return String(iso||'—');
  try{return d.toLocaleDateString('fa-IR-u-ca-persian',{day:'numeric',month:'long',year:'numeric'})+'، '+d.toLocaleTimeString('fa-IR',{hour:'2-digit',minute:'2-digit'});}catch(e){return String(iso||'—');}
}

/* Inline SVG icon set — display only, no emoji anywhere on the page. */
function icsvg(p){return '<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none"'+
  ' stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'+
  ' aria-hidden="true">'+p+'</svg>';}
var IC={
  sun:icsvg('<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>'),
  moon:icsvg('<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>'),
  bell:icsvg('<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>'),
  bellOff:icsvg('<path d="M13.73 21a2 2 0 0 1-3.46 0"/><path d="M18.63 13A17.89 17.89 0 0 1 18 8"/><path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14"/><path d="M18 8a6 6 0 0 0-9.33-5"/><line x1="1" y1="1" x2="23" y2="23"/>'),
  play:icsvg('<polygon points="5 3 19 12 5 21 5 3"/>'),
  save:icsvg('<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>'),
  check:icsvg('<polyline points="20 6 9 17 4 12"/>'),
  eye:icsvg('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'),
  camera:icsvg('<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>'),
  download:icsvg('<path d="M12 3.5v11M7.5 10 12 14.5 16.5 10"/><path d="M4.5 16.5v2a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-2"/>'),
  okc:icsvg('<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'),
  oct:icsvg('<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'),
  tri:icsvg('<path d="M10.29 3.86L.86 18a2 2 0 0 0 1.71 3h16.86a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'),
  rot:icsvg('<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>'),
  xc:icsvg('<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'),
  info:icsvg('<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>')
};

function showToast(ok,title,meta){
  var t=document.getElementById('toast');
  document.getElementById('toast-title').textContent=title;
  document.getElementById('toast-meta').textContent=meta||'';
  t.classList.remove('ok','fail');t.classList.add(ok?'ok':'fail');t.classList.add('show');
  clearTimeout(t._h);t._h=setTimeout(hideToast,ok?4500:8000);
}
function hideToast(){document.getElementById('toast').classList.remove('show');}

function showErrors(id,list){
  var box=document.getElementById(id);
  if(!list||!list.length){box.classList.remove('show');box.innerHTML='';return;}
  box.innerHTML='<ul>'+list.map(function(e){return '<li>'+esc(e)+'</li>';}).join('')+'</ul>';
  box.classList.add('show');
}

function fillPerson(){
  var p=STATE.person||{};
  document.getElementById('p-national').value=p.national||'';
  document.getElementById('p-birth').value=p.birth||'';
  document.getElementById('p-mobile').value=p.mobile||'';
}

function renderDevices(){
  var el=document.getElementById('dev-list');
  var ds=STATE.devices||[];
  if(!ds.length){el.innerHTML='<div class="empty">هنوز دستگاهی افزوده نشده است</div>';return;}
  // JADID-tarin dastgah BALA: tartib-e store bar asas-e 'created' ast, pas ma'koos
  // mishavad (fallback: agar created barabar bud, tartib-e vorud-e ma'koos).
  var sorted=ds.map(function(d,i){return {d:d,i:i};}).sort(function(a,b){
    var ca=String(a.d.created||''), cb=String(b.d.created||'');
    if(ca!==cb) return cb<ca?-1:1;
    return b.i-a.i;
  }).map(function(x){return x.d;});
  var rows=sorted.map(function(d,idx){
    var sn='<div class="mono sn1">'+esc(d.serial1||'')+'</div>'+
           (d.serial2?'<div class="mono sn2">'+esc(d.serial2)+'</div>':'');
    var nm='<div class="dev-name">'+esc(d.name||'—')+'</div>';
    var gs=d.status||'pending', hs=d.hamta_status||'pending';
    // badge-e gomrok KUTAH (مجاز/مسدود) mesl-e hamta; motn-e kamel dar tooltip +sotoon-e natije
    var gb='<span class="badge b-'+esc(gs)+'" title="'+esc(FA_STATUS[gs]||gs)+'">'+
           esc(BADGE_FA[gs]||FA_STATUS[gs]||gs)+'</span>';
    var hb='<span class="badge b-'+esc(hs)+'" title="'+esc(HAMTA_FA[hs]||hs)+'">'+
           esc(HAMTA_FA[hs]||hs)+'</span>';
    // zir-sotoon-e DOVVOM-e vaziat: zaman-e estelam ('--' agar anjam nashode)
    var ht=fmtWhen(d.hamta_at), gt=fmtWhen(d.gomrok_at);
    // The camera appears only when the store holds a capture for this slot.
    // /estelam-state returns estelam_load() verbatim, so the path sits at the
    // device top level -- and showShotModal below tests exactly this field, so
    // the icon can never render for something the click would then report as
    // missing.
    function shotBtn(svc){
      var field=svc==='hamta'?'hamta_screenshot':'gomrok_screenshot';
      if(!d[field])return '';
      var fa=svc==='hamta'?'همتا':'گمرک';
      return '<span class="shot-w">'+
        '<button type="button" class="ibtn sh" title="مشاهدهٔ عکس نتیجهٔ '+fa+'"'+
        ' aria-label="مشاهدهٔ عکس نتیجهٔ '+fa+'"'+
        ' onclick="showShotModal(\''+esc(d.id)+'\',\''+svc+'\')">'+IC.camera+'</button></span>';
    }
    // sotoon-e natije: 80 character-e aval +dokme-ye «مشاهده کامل» (modal).
    // (natije-ye HAMTA momken ast sad-ha character bashad va jadval ra bekeshad)
    var res;
    if(SVC==='hamta') res=resCell(d,'hamta');
    else if(SVC==='gomrok') res=resCell(d,'gomrok');
    else res=resCell(d,'gomrok','گمرک: ')+
             '<div class="res2">'+resCell(d,'hamta','همتا: ')+'</div>';
    // NOKTE: inja NABAYAD <table> tudartu bezanim — vagarna selector-e
    // '#dev-list tbody tr' radif-haye dakheli ra ham migirad va shomaresh/
    // check-ha kharab mishavad. Pas grid-e CSS.
    return '<tr><td class="c-num">'+toFa(idx+1)+'</td>'+
      '<td>'+nm+sn+'</td>'+
      '<td><div class="stgrid">'+
          '<span class="slab">همتا</span>'+hb+shotBtn('hamta')+'<span class="when">'+esc(ht)+'</span>'+
          '<span class="slab">گمرک</span>'+gb+shotBtn('gomrok')+'<span class="when">'+esc(gt)+'</span>'+
          '</div></td>'+
      '<td class="res">'+res+'</td>'+
      '<td><button class="ghost" onclick="startOne(\''+esc(d.id)+'\')">'+
      esc('استعلام '+(SVC_FA[SVC]||''))+'</button> '+
      '<button class="danger" onclick="delDevice(\''+esc(d.id)+'\')">حذف</button></td></tr>';
  }).join('');
  el.innerHTML='<table>'+
    '<colgroup><col class="c-idx"><col class="c-sn"><col class="c-st"><col><col class="c-act"></colgroup>'+
    '<thead><tr><th>#</th><th>نام / سریال‌ها</th>'+
    '<th>وضعیت و زمان استعلام</th>'+
    '<th>نتیجه</th><th></th></tr></thead><tbody>'+rows+'</tbody></table>';
}

/* zaman-e estelam: tarikh-e shamsi ba saat (faDateTime); khali/na-mo'tabar '—'. */
function fmtWhen(ts){
  return faDateTime(ts);
}

function refresh(){
  return fetch('/estelam-state',{cache:'no-store'}).then(function(r){return r.json();})
    .then(function(s){STATE=s;renderDevices();renderRuntime(s.runtime||{});return s;});
}

/* --- sotoon-e natije: kholase-ye 80-character +modal-e motn-e kamel ------- */
var RES_LIMIT=80;
function resText(d,svc){return (svc==='hamta'?d.hamta_result:d.result)||'';}
function resCell(d,svc,prefix){
  prefix=prefix||'';
  var full=resText(d,svc);
  if(!full) return esc(prefix)+'—';
  // faghat khat-e aval-e ma'nadar +kutah-shode be 80 character
  var flat=full.replace(/\s+/g,' ').trim();
  if(flat.length<=RES_LIMIT) return '<span class="res-short">'+esc(prefix+flat)+'</span>';
  var head=esc(prefix+flat.slice(0,RES_LIMIT))+'…';
  return '<div class="res-short">'+head+'</div>'+
    '<button class="res-more" onclick="showResModal(\''+esc(d.id)+'\',\''+svc+'\')">'+IC.eye+' مشاهده کامل</button>';
}
function showResModal(id,svc){
  var d=(STATE.devices||[]).filter(function(x){return String(x.id)===String(id);})[0];
  if(!d)return;
  var full=resText(d,svc);
  document.getElementById('res-modal-title').textContent=
    'متن کامل نتیجه — '+(svc==='hamta'?'همتا':'گمرک');
  document.getElementById('res-modal-sn').textContent=
    (d.serial1||'')+(d.serial2?(' / '+d.serial2):'');
  document.getElementById('res-modal-body').textContent=full||'—';
  document.getElementById('res-modal').classList.add('show');
}
function closeResModal(){document.getElementById('res-modal').classList.remove('show');}
function copyResModal(){
  var t=document.getElementById('res-modal-body').textContent||'';
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(function(){showToast(true,'متن کپی شد');},
      function(){showToast(false,'کپی نشد');});
  }
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeResModal();});

/* --- v1.9.1: inquiry-result picture modal (same shape as res-modal) ------- */
var SHOT_URL='';
var SHOT_NAME='';
function showShotModal(id,svc){
  var d=(STATE.devices||[]).filter(function(x){return String(x.id)===String(id);})[0];
  if(!d)return;
  var field=svc==='hamta'?'hamta_screenshot':'gomrok_screenshot';
  if(!d[field]){showToast(false,'عکس نتیجهٔ این استعلام موجود نیست');return;}
  // Every capture overwrites the same path, so the URL never changes and the
  // browser served the previous verdict's picture from cache. `cb` busts it;
  // the route ignores parameters it does not know.
  SHOT_URL='/estelam-shot?id='+encodeURIComponent(id)+'&svc='+svc
    +'&cb='+Date.now();
  document.getElementById('shot-modal-title').textContent=
    'عکس نتیجهٔ استعلام — '+(svc==='hamta'?'همتا':'گمرک');
  document.getElementById('shot-modal-sn').textContent=
    (d.serial1||'')+(d.serial2?(' / '+d.serial2):'');
  SHOT_NAME='estelam-'+svc+'-'+String(id).replace(/[^0-9A-Za-z_-]+/g,'_')+'.png';
  var img=document.getElementById('shot-modal-img');
  var body=document.getElementById('shot-modal-body');
  var dl=document.getElementById('shot-modal-dl');
  // onerror puts Persian text where the picture was and takes the img out of
  // the body; re-opening the modal must put it back -- otherwise the previous
  // src sits on top of the error text and loading again errors again.
  if(!img){
    /* v1.9.1: clear the body BEFORE appendChild -- an innerHTML='' after it
       would wipe the very img just created, and the modal would have to be
       rebuilt on every open. */
    body.innerHTML='';
    img=document.createElement('img');
    img.id='shot-modal-img';
    img.style.maxWidth='100%';
    img.style.height='auto';
    img.style.borderRadius='10px';
    img.style.border='1px solid var(--line)';
    body.appendChild(img);
  }else{
    // v1.9.1: drop the previous visit's error text, but not the img itself.
    // body.textContent='' removes every child including the img meant for
    // reuse; a src set on a detached img never loaded, so the modal had to be
    // rebuilt on each open.
    for(var k=body.childNodes.length-1;k>=0;k--){
      var nd=body.childNodes[k];
      if(nd!==img)body.removeChild(nd);
    }
  }
  // v1.9.1: one alt for every open -- the static markup, a reused img and a
  // rebuilt one must all read the same Persian string.
  img.alt='عکس نتیجهٔ استعلام';
  img.style.display='';
  dl.style.display='';
  document.getElementById('shot-modal-dl-ic').innerHTML=IC.download;
  img.onerror=function(){
    /* The recorded path is gone (data cleared, or the robot failed) -- show
       Persian text instead of a broken image. */
    document.getElementById('shot-modal-body').textContent=
      'عکس بارگذاری نشد — فایل پیدا نیست';
    dl.style.display='none';
    img.onerror=null;
  };
  img.src=SHOT_URL;
  document.getElementById('shot-modal').classList.add('show');
}
function closeShotModal(){document.getElementById('shot-modal').classList.remove('show');}
function shotDownload(){
  if(!SHOT_URL)return;
  /* The route answers image/png with no Content-Disposition, so window.open
     would just render the picture in a new tab. A temporary anchor carrying
     `download` is what actually saves a file, and it keeps the same-origin
     session cookie that a fetch-and-revoke dance would have to re-create. */
  var a=document.createElement('a');
  a.href=SHOT_URL;
  a.download=SHOT_NAME||'estelam.png';
  a.style.display='none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeShotModal();});

/* chips-e gomrok hamun vajegan-e badge ra estefade mikonad (yek-dast ba hamta) */
var RUN_STATE_FA=BADGE_FA;

function renderRuntime(rt){
  var dot=document.getElementById('run-dot');
  var st=document.getElementById('run-state');
  var meta=document.getElementById('run-meta');
  var chips=document.getElementById('run-chips');
  var running=!!rt.running;
  dot.className='dot'+(running?' on':'');
  st.textContent=running?('در حال اجرا'+(rt.service_fa?(' — '+rt.service_fa):'')):'متوقف';
  st.style.color=running?'var(--busy)':'var(--muted)';
  meta.textContent=running?('pid '+rt.pid+(rt.started?(' · '+faDateTime(rt.started)):'')):
    (rt.started?('آخرین اجرا: '+faDateTime(rt.started)):'');
  // chips ba servis-e entekhab-shode hamahang mishavad
  var c,fa;
  if(SVC==='hamta'){c=rt.hamta_counts||{};fa=HAMTA_FA;}
  else{c=rt.counts||{};fa=RUN_STATE_FA;}
  chips.innerHTML=Object.keys(c).map(function(k){
    return '<span class="chip '+esc(k)+'">'+esc(fa[k]||k)+': '+toFa(c[k])+'</span>';
  }).join('');
  // topbar live pill mirrors the run state
  var tp=document.getElementById('top-run-pill');
  if(tp){tp.classList.toggle('on',running);
    var tpt=tp.querySelector('.rp-t');
    if(tpt)tpt.textContent=running?'در حال اجرا':'متوقف';}
}

function toFa(n){var FA='۰۱۲۳۴۵۶۷۸۹';return String(n).replace(/[0-9]/g,function(d){return FA[d];});}

function refreshAll(){refresh();renderLogs();}

function stopRun(){
  fetch('/estelam-stop',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(r){return r.json();}).then(function(j){
      showToast(true,j.stopped?'استعلام متوقف و مرورگر بسته شد':'اجرای فعالی برای توقف نبود');
      refreshAll();
    });
}

function closeWholeSystem(){
  if(!confirm('کل سامانه بسته شود؟ همهٔ ربات‌ها و استعلام‌های در حال اجرا متوقف می‌شوند و پنل خاموش می‌شود.'))return;
  fetch('/shutdown',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .catch(function(){});
  var banner=document.createElement('div');
  banner.style.cssText='position:fixed;top:0;left:0;right:0;z-index:9999;background:#b91c1c;color:#fff;'+
    'padding:14px;text-align:center;font-family:Tahoma,sans-serif;font-size:14px;font-weight:bold';
  banner.textContent='در حال بستن سامانه… همهٔ ربات‌ها متوقف شدند؛ این صفحه تا چند ثانیه دیگر در دسترس نخواهد بود.';
  document.body.appendChild(banner);
  setTimeout(function(){
    banner.textContent='سامانه بسته شد. برای اجرای مجدد، میان‌بر IRICA را باز کنید.';
    setTimeout(function(){location.reload();},4000);
  },1500);
}
 
function restartRun(){
  fetch('/estelam-restart',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){
      if(!res.ok||!res.j.ok){showErrors('run-err',res.j.errors||['راه‌اندازی مجدد نشد']);
        showToast(false,'راه‌اندازی مجدد نشد',(res.j.errors||[]).join(' · '));return;}
      showErrors('run-err',[]);
      showToast(true,'راه‌اندازی مجدد شد ('+res.j.count+' دستگاه)','pid '+res.j.pid);
      refreshAll();
    });
}

function retryFailed(){startAll();}

function savePerson(){
  var body={national:digits(document.getElementById('p-national').value),
            birth:document.getElementById('p-birth').value.trim(),
            mobile:digits(document.getElementById('p-mobile').value)};
  fetch('/estelam-person',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)}).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){
      if(!res.ok||!res.j.ok){showErrors('p-err',res.j.errors||['ذخیره نشد']);
        showToast(false,'اطلاعات شخص ذخیره نشد');return;}
      showErrors('p-err',[]);STATE.person=res.j.state.person;
      showToast(true,'اطلاعات شخص ذخیره شد');
    });
}

function devFormActions(html){document.getElementById('dev-form-actions').innerHTML=html;}

function startSingle(){
  MODE='single';
  document.getElementById('dev-form').classList.add('show');
  document.getElementById('dev-form-note').textContent='افزودن یک دستگاه';
  clearDevForm();
  showErrors('d-err',[]);
  devFormActions('<button onclick="saveDevice(false)">'+IC.save+'<span>ذخیره</span></button>'+
    '<button class="ok" onclick="saveDevice(true)">'+IC.save+'<span>ذخیره و استعلام</span></button>'+
    '<button class="ghost" onclick="closeDevForm()">انصراف</button>');
  document.getElementById('d-name').focus();
}

function startBulk(){
  MODE='bulk';
  document.getElementById('dev-form').classList.add('show');
  clearDevForm();
  showErrors('d-err',[]);
  bulkNote();
  devFormActions('<button onclick="bulkNext()">'+IC.save+'<span>ذخیره و بعدی</span></button>'+
    '<button class="ok" onclick="bulkFinish()">'+IC.check+'<span>پایان و برو به استعلام</span></button>'+
    '<button class="ghost" onclick="closeDevForm()">انصراف</button>');
  document.getElementById('d-name').focus();
}

function bulkNote(){
  document.getElementById('dev-form-note').textContent=
    'حالت عمده — تا حالا '+((STATE.devices||[]).length)+' دستگاه ذخیره شده. سریال دستگاه بعدی را وارد کنید.';
}

function closeDevForm(){MODE='';document.getElementById('dev-form').classList.remove('show');}

function clearDevForm(){
  ['d-name','d-s1','d-s2'].forEach(function(id){document.getElementById(id).value='';});
}

function postDevice(){
  var body={name:(document.getElementById('d-name').value||'').trim(),
            serial1:digits(document.getElementById('d-s1').value),
            serial2:digits(document.getElementById('d-s2').value)};
  return fetch('/estelam-device',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)}).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});});
}

function saveDevice(thenRun){
  postDevice().then(function(res){
    if(!res.ok||!res.j.ok){showErrors('d-err',res.j.errors||['ذخیره نشد']);
      showToast(false,'دستگاه ذخیره نشد');return;}
    showErrors('d-err',[]);STATE=res.j.state;renderDevices();
    showToast(true,'دستگاه ذخیره شد');
    var id=res.j.device.id;
    closeDevForm();
    if(thenRun) startOne(id);
  });
}

function bulkNext(){
  postDevice().then(function(res){
    if(!res.ok||!res.j.ok){showErrors('d-err',res.j.errors||['ذخیره نشد']);return;}
    showErrors('d-err',[]);STATE=res.j.state;renderDevices();
    clearDevForm();
    document.getElementById('d-name').focus();
    bulkNote();showToast(true,'ذخیره شد — سریال دستگاه بعدی');
  });
}

function bulkFinish(){
  var s1=digits(document.getElementById('d-s1').value);
  var nm=(document.getElementById('d-name').value||'').trim();
  var done=function(){closeDevForm();startAll();};
  if(!s1&&!nm){done();return;}
  postDevice().then(function(res){
    if(!res.ok||!res.j.ok){showErrors('d-err',res.j.errors||['ذخیره نشد']);return;}
    STATE=res.j.state;renderDevices();done();
  });
}

function delDevice(id){
  fetch('/estelam-device-delete',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id:id})}).then(function(r){return r.json();})
    .then(function(j){STATE=j.state;renderDevices();if(MODE==='bulk')bulkNote();});
}

function runEstelam(id){
  return fetch('/estelam-start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(Object.assign({service:SVC},id?{id:id}:{}))}).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
    .then(function(res){
      if(!res.ok||!res.j.ok){showErrors('run-err',res.j.errors||['اجرا نشد']);
        showToast(false,'استعلام شروع نشد',(res.j.errors||[]).join(' · '));return;}
      showErrors('run-err',[]);
      showToast(true,'استعلام '+(SVC_FA[res.j.service||SVC]||'')+' شروع شد ('+res.j.count+' دستگاه)','pid '+res.j.pid);
      refresh();
    });
}
function startOne(id){runEstelam(id);}
function startAll(){runEstelam(null);}

/* --- entekhab-e no'-e estelam --- */
var SVC='hamta';
/* SVC_FA dar dokme-ye radif ('استعلام '+…) va toast estefade mishavad. baraye
   'all' motn-e sarih-e «از گمرک و همتا» (na «همه استعلام‌ها») khaste shode. */
var SVC_FA={hamta:'همتا',gomrok:'گمرک',all:'از گمرک و همتا'};
function pickSvc(s){
  SVC=s;
  document.querySelectorAll('#svc-btns .svc').forEach(function(b){
    b.classList.toggle('on', b.getAttribute('data-svc')===s);
  });
  // dokme-ye shoro' dar tab-e «همه» sarih migoyad az kodam do samane estelam migirad
  var sb=document.getElementById('btn-start-all');
  if(sb) sb.innerHTML=IC.play+'<span>'+((s==='all')
    ? 'استعلام از گمرک و همتا (در انتظارها)'
    : 'شروع استعلام '+(SVC_FA[s]||'')+' (در انتظارها)')+'</span>';
  renderDevices();
  renderRuntime((STATE.runtime)||{});
}

/* --- arz-e INTERACTIVE-e kadr-e asli (drag +preset +localStorage) --------
   Chera: natije-ye HAMTA chand-khati va tolani ast; kadr-e 1080px faza-ye khali-ye
   ziad dar chap/rast migozasht. Pishfarz 1620px (50% bishtar). */
var WMIN=900, WMAX=3000, WKEY='estelam_wrap_w';
var TKEY='estelam_theme';

/* --- theme: pishfarz ROSHAN (light); entekhab dar localStorage mimanad ----- */
function applyTheme(t){
  var dark=(t==='dark');
  document.documentElement.setAttribute('data-theme', dark?'dark':'light');
  var b=document.getElementById('theme-btn');
  if(b) b.innerHTML=(dark?IC.sun:IC.moon)+'<span>'+(dark?'حالت روشن':'حالت تاریک')+'</span>';
}
function setTheme(t){applyTheme(t);try{localStorage.setItem(TKEY,t);}catch(e){}}
function toggleTheme(){
  setTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');
}
function initTheme(){
  var t=null;try{t=localStorage.getItem(TKEY);}catch(e){}
  applyTheme(t==='dark'?'dark':'light');
}

function applyWrapW(v){
  var px = (v==='max') ? Math.max(WMIN, Math.round(window.innerWidth*0.98))
                       : Math.max(WMIN, Math.min(WMAX, Number(v)||1620));
  document.documentElement.style.setProperty('--wrapw', px+'px');
  document.querySelectorAll('.wbar .wbtn').forEach(function(b){
    b.classList.toggle('on', String(b.getAttribute('data-w'))===String(v));
  });
}
function setWrapW(v){
  applyWrapW(v);
  try{localStorage.setItem(WKEY,String(v));}catch(e){}
}
function initWrapW(){
  var v=null;
  try{v=localStorage.getItem(WKEY);}catch(e){}
  applyWrapW(v||1620);
  ['wgrip-r','wgrip-l'].forEach(function(id){
    var g=document.getElementById(id);
    if(!g)return;
    g.addEventListener('mousedown',function(ev){
      ev.preventDefault();
      var wrap=document.querySelector('.wrap');
      var startX=ev.clientX, startW=wrap.getBoundingClientRect().width;
      // dastgire-ye rast: keshidan be rast arz ra kam mikonad (RTL-agnostic:
      // az fasele-ye markaz hesab mishavad ta har do dastgire tabi'i bashand)
      var dir=(id==='wgrip-r')?-2:2;
      g.classList.add('drag');document.body.classList.add('wresize');
      function mv(e){
        var w=Math.round(startW+(e.clientX-startX)*dir);
        w=Math.max(WMIN,Math.min(WMAX,w));
        document.documentElement.style.setProperty('--wrapw',w+'px');
      }
      function up(){
        document.removeEventListener('mousemove',mv);
        document.removeEventListener('mouseup',up);
        g.classList.remove('drag');document.body.classList.remove('wresize');
        var w=Math.round(document.querySelector('.wrap').getBoundingClientRect().width);
        setWrapW(w);
      }
      document.addEventListener('mousemove',mv);
      document.addEventListener('mouseup',up);
    });
    // dobar-click roo-ye dastgire = bazgasht be pishfarz-e arizh
    g.addEventListener('dblclick',function(){setWrapW(1620);});
  });
  window.addEventListener('resize',function(){
    var v=null;try{v=localStorage.getItem(WKEY);}catch(e){}
    if(v==='max')applyWrapW('max');
  });
}

function checkApiHealth(){
  fetch('/telegram-health',{cache:'no-store'}).then(function(r){return r.json();}).then(function(h){
    if(!h||!h.ts)return;
    showToast(!!h.ok,h.ok?'ارتباط API تلگرام سالم است':'ارتباط API تلگرام برقرار نشد',
      (h.message||'')+(h.api_base?(' · '+h.api_base):''));
  }).catch(function(){});
}

/* ---------------- log-e interactive (kadr-e sabet +scroll) ---------------- */
var LOGS=[];
var LOG_FILTER='all';
var LOG_OPEN={};
var LOG_ICON={healthy:IC.okc,problem:IC.oct,advanced:IC.tri,retry:IC.rot,running:IC.play,
              error:IC.xc,warn:IC.tri,info:IC.info,shot:IC.camera};
var LOG_FA={healthy:'سالم',problem:'اشکال',advanced:'هشدار مهم',retry:'تلاش مجدد',
            running:'در حال اجرا',error:'خطا',warn:'هشدار',info:'اطلاع',shot:'عکس'};
var LOG_TABS=[['all','همه'],['healthy','سالم'],['problem','اشکال'],
              ['retry','تلاش مجدد'],['advanced','هشدار'],['error','خطا'],['shot','عکس']];

function renderLogFilters(){
  document.getElementById('log-filters').innerHTML=LOG_TABS.map(function(t){
    return '<button class="f'+(LOG_FILTER===t[0]?' on':'')+'" onclick="setLogFilter(\''+t[0]+'\')">'+
      esc(t[1])+'</button>';
  }).join('');
}
function setLogFilter(f){LOG_FILTER=f;renderLogFilters();paintLogs();}

function renderLogs(){
  return fetch('/estelam-logs',{cache:'no-store'}).then(function(r){return r.json();})
    .then(function(j){LOGS=j.logs||[];notifyNewLogs(LOGS);paintLogs();});
}

function paintLogs(){
  var box=document.getElementById('log-box');
  var q=(document.getElementById('log-q').value||'').trim();
  var list=LOGS.filter(function(l){
    if(LOG_FILTER!=='all'&&(l.status||'')!==LOG_FILTER)return false;
    if(!q)return true;
    return ((l.message||'')+' '+(l.serial||'')+' '+(l.step||'')).indexOf(q)>=0;
  });
  if(!list.length){box.innerHTML='<div class="logempty">لاگی برای نمایش نیست</div>';return;}
  var top=box.scrollTop;
  box.innerHTML=list.map(function(l,i){
    var st=l.status||'info';
    var key=(l.ts||'')+'|'+i;
    var open=LOG_OPEN[key]?' open':'';
    return '<div class="li s-'+esc(st)+open+'" onclick="toggleLog(\''+esc(key)+'\')">'+
      '<div class="h"><b>'+(LOG_ICON[st]||'•')+' '+esc(LOG_FA[st]||st)+
      (l.step?(' · '+esc(l.step)):'')+'</b><span class="ts">'+esc(faDateTime(l.ts))+'</span></div>'+
      (l.serial?('<div class="sn">سریال: '+esc(l.serial)+'</div>'):'')+
      '<div class="msg">'+esc(l.message||'')+'</div>'+
      (LOG_OPEN[key]?'':'<div class="more">برای جزئیات کلیک کنید</div>')+
      '</div>';
  }).join('');
  box.scrollTop=top;
}

function toggleLog(key){LOG_OPEN[key]=!LOG_OPEN[key];paintLogs();}

function clearLogs(){
  fetch('/estelam-clear-logs',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(){LOG_OPEN={};renderLogs();showToast(true,'لاگ‌ها پاک شد');});
}

/* ---- notification-e OPTIONAL-e log-e jadid (bala-chap) ---- */
var NOTIF_ON=localStorage.getItem('estelam-lognotif')!=='0';
var NOTIF_SEEN={};
var NOTIF_READY=false;

function logKey(l){return (l.ts||'')+'|'+(l.status||'')+'|'+(l.message||'').slice(0,60);}

function updateNotifToggle(){
  var b=document.getElementById('notif-toggle'); if(!b)return;
  b.innerHTML=(NOTIF_ON?IC.bell:IC.bellOff)+'<span>اعلان لاگ: '+(NOTIF_ON?'روشن':'خاموش')+'</span>';
}
function toggleLogNotif(){
  NOTIF_ON=!NOTIF_ON;
  localStorage.setItem('estelam-lognotif',NOTIF_ON?'1':'0');
  if(!NOTIF_ON) document.getElementById('lognotif-wrap').innerHTML='';
  updateNotifToggle();
}

function notifyNewLogs(logs){
  var fresh=[];
  (logs||[]).forEach(function(l){
    var k=logKey(l);
    if(!NOTIF_SEEN[k]){NOTIF_SEEN[k]=1;fresh.push(l);}
  });
  if(!NOTIF_READY){NOTIF_READY=true;return;}
  if(!NOTIF_ON)return;
  fresh.slice(0,4).forEach(function(l,i){setTimeout(function(){pushLogNotif(l);},i*220);});
}

function pushLogNotif(l){
  var wrap=document.getElementById('lognotif-wrap'); if(!wrap)return;
  var st=l.status||'info';
  var d=document.createElement('div');
  d.className='lognotif s-'+st;
  d.innerHTML='<button class="x" aria-label="بستن" onclick="this.parentNode.remove()">×</button>'+
    '<div class="t">'+(LOG_ICON[st]||'•')+' <span>'+esc(LOG_FA[st]||st)+'</span>'+
    '<span style="margin-inline-start:auto;font-size:10.5px;color:var(--muted)">'+
    esc(faDateTime(l.ts))+'</span></div>'+
    (l.serial?('<div class="sn">سریال: '+esc(l.serial)+'</div>'):'')+
    '<div class="m">'+esc(l.message||'')+'</div>';
  wrap.appendChild(d);
  requestAnimationFrame(function(){d.classList.add('show');});
  while(wrap.children.length>4) wrap.removeChild(wrap.firstChild);
  setTimeout(function(){
    d.classList.remove('show');
    setTimeout(function(){if(d.parentNode)d.remove();},300);
  },9000);
}

STATE=__ESTELAM_JSON__;
initTheme();
initWrapW();
fillPerson();renderDevices();renderRuntime(STATE.runtime||{});
renderLogFilters();updateNotifToggle();renderLogs();
setInterval(refresh,4000);
setInterval(renderLogs,5000);
checkApiHealth();
</script>
</body>
</html>
"""


CRM_PAGE = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>مدیریت مشتریان و پرونده‌ها (CRM)</title>
<link rel="icon" href="data:,">
<style>
  /* Bundled Vazirmatn — offline, no external fetch (frontend-design skill:
     typography carries the identity; here a Persian-first humanist face). */
  @font-face{
    font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-var.woff2') format('woff2-variations');
    font-weight:100 900;font-style:normal;font-display:swap;
  }
  @font-face{
    font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-Bold.woff2') format('woff2');
    font-weight:700;font-style:normal;font-display:swap;
  }

  :root{
    --bg:#f4f6fb;--card:#ffffff;--card2:#f7f8fd;--line:rgba(27,32,54,.10);
    --line-strong:rgba(27,32,54,.16);--txt:#1b2036;--muted:#5c6484;--faint:#687291;
    --brand:#4460e3;--brand-hover:#3757cf;--brand-soft:rgba(68,96,227,.10);
    --on-brand:#ffffff;
    --ok:#0c7d4f;--ok-soft:rgba(15,157,99,.12);
    --danger:#d93752;--danger-soft:rgba(217,55,82,.10);
    --warn:#b9770e;--warn-soft:rgba(185,119,14,.13);
    --pill-neutral-bg:rgba(27,32,54,.06);--pill-neutral-fg:#5c6484;
    --pill-ok-bg:rgba(15,157,99,.13);--pill-ok-fg:#0b7a4d;
    --pill-danger-bg:rgba(217,55,82,.12);--pill-danger-fg:#b72740;
    --pill-warn-bg:rgba(185,119,14,.14);--pill-warn-fg:#92590a;
    --shadow-1:0 1px 2px rgba(16,20,40,.05),0 1px 6px rgba(16,20,40,.04);
    --shadow-2:0 4px 14px rgba(16,20,40,.10),0 1px 3px rgba(16,20,40,.06);
    --ring:0 0 0 3px rgba(68,96,227,.30);
  }
  html[data-theme="dark"]{
    --bg:#101322;--card:#181c2e;--card2:#1f2438;--line:rgba(255,255,255,.08);
    --line-strong:rgba(255,255,255,.14);--txt:#eef1fb;--muted:#aeb6d0;--faint:#848cad;
    --brand:#7d95ff;--brand-hover:#93a7ff;--brand-soft:rgba(125,149,255,.12);
    --on-brand:#0e1330;
    --ok:#3ad28b;--ok-soft:rgba(58,210,139,.13);
    --danger:#ff6678;--danger-soft:rgba(255,102,120,.13);
    --warn:#f6b94b;--warn-soft:rgba(246,185,75,.13);
    --pill-neutral-bg:rgba(255,255,255,.07);--pill-neutral-fg:#a9b7e0;
    --pill-ok-bg:rgba(58,210,139,.14);--pill-ok-fg:#3ad28b;
    --pill-danger-bg:rgba(255,102,120,.14);--pill-danger-fg:#ff6678;
    --pill-warn-bg:rgba(246,185,75,.14);--pill-warn-fg:#f6b94b;
    --shadow-1:0 1px 2px rgba(0,0,0,.35),0 1px 6px rgba(0,0,0,.25);
    --shadow-2:0 6px 18px rgba(0,0,0,.45),0 2px 5px rgba(0,0,0,.3);
    --ring:0 0 0 3px rgba(125,149,255,.30);
  }
  *{box-sizing:border-box}
  html{color-scheme:light}
  html[data-theme="dark"]{color-scheme:dark}
  body{margin:0;background:var(--bg);color:var(--txt);
    font-family:Vazirmatn,"Segoe UI",Tahoma,sans-serif;
    font-size:14px;line-height:1.6;padding:24px 18px 70px;
    -webkit-font-smoothing:antialiased}
  /* v1.4.1: page width is operator-controlled (--crm-w, set from the
     header «عرض» popover) and capped by the viewport so it can never
     overflow. */
  .wrap{width:min(var(--crm-w,1240px),98vw);margin:0 auto}
  /* v1.3.7 header nav: the two panel links are real navigation buttons,
     not bare text; account actions sit behind a hairline divider. */
  .headnav{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .navlink{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;
    border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--txt);
    text-decoration:none;font-size:13px;font-weight:500;box-shadow:var(--shadow-1);
    transition:border-color .15s,color .15s,background .15s}
  .navlink .ic{color:var(--muted);flex:none}
  .navlink:hover{border-color:var(--brand);color:var(--brand);background:var(--brand-soft)}
  .navlink:hover .ic{color:var(--brand)}
  .navlink:focus-visible{box-shadow:var(--ring)}
  .headacts{display:flex;gap:8px;align-items:center;padding-inline-start:14px;
    border-inline-start:1px solid var(--line);margin-inline-start:2px}
  /* v1.4.1 page-width popover: presets + fine slider, persisted. */
  .wwrap{position:relative}
  .wpop{position:absolute;top:calc(100% + 8px);inset-inline-end:0;width:236px;
    background:var(--card);border:1px solid var(--line);border-radius:12px;
    box-shadow:var(--shadow-2);padding:12px 14px;display:none;z-index:40}
  .wpop.open{display:block}
  .wpop-lbl{font-size:11px;font-weight:600;color:var(--muted);margin:0 0 8px}
  .wpop input[type=range]{width:100%;margin:12px 0 2px;accent-color:var(--brand);min-height:0;padding:0;border:0;background:transparent}
  :is(a,button,input,select,textarea,summary):focus-visible{outline:none;box-shadow:var(--ring)}
  /* inline icons sit on the text baseline (flex boxes ignore this) */
  svg.ic{vertical-align:-.18em}
  /* header */
  .head{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:18px}
  .head h1{font-size:20px;font-weight:750;margin:0;flex:1;letter-spacing:-.3px;
    display:flex;align-items:center;gap:11px}
  .head h1 .mono{width:38px;height:38px;border-radius:11px;flex:none;
    background:var(--brand);color:var(--on-brand);display:grid;place-items:center;
    font-size:16px;font-weight:800;letter-spacing:0}
  .head h1 .sub{font-size:12px;color:var(--muted);margin-top:2px;font-weight:400;
    letter-spacing:0}
  .iconbtn{border:1px solid var(--line);background:var(--card);color:var(--txt);
    border-radius:9px;padding:7px 12px;cursor:pointer;font-family:inherit;font-size:13px;
    transition:background .15s,border-color .15s}
  .iconbtn:hover{border-color:var(--line-strong);background:var(--card2)}
  /* buttons */
  .btn{border:1px solid var(--line);background:var(--card);color:var(--txt);border-radius:9px;
    padding:8px 16px;cursor:pointer;font-family:inherit;font-size:13px;font-weight:500;
    transition:background .15s,border-color .15s,color .15s;min-height:32px}
  .btn:hover{border-color:var(--line-strong);background:var(--card2)}
  .btn.primary{background:var(--brand);border-color:transparent;color:var(--on-brand)}
  .btn.primary:hover{background:var(--brand-hover);border-color:transparent}
  .btn.danger{color:var(--danger);border-color:var(--danger-soft);background:var(--danger-soft)}
  .btn.danger:hover{border-color:var(--danger)}
  .btn.ghost{background:var(--card);border-color:var(--line-strong);color:var(--txt)}
  .btn.ghost:hover{background:var(--brand-soft);border-color:var(--brand);color:var(--brand)}
  .btn.warn{color:var(--pill-warn-fg);border-color:var(--pill-warn-fg);background:var(--pill-warn-bg)}
  .btn.warn:hover{border-color:var(--pill-warn-fg);filter:brightness(.97)}
  /* success buttons («ثبت دریافتی», «استعلام مجدد») previously fell back to
     the neutral .btn — mirror .btn.warn so the tone family is complete */
  .btn.ok{color:var(--pill-ok-fg);border-color:var(--pill-ok-fg);background:var(--pill-ok-bg)}
  .btn.ok:hover{border-color:var(--pill-ok-fg);filter:brightness(.97)}
  .btn.mini{padding:4px 11px;font-size:12px;border-radius:8px;min-height:28px}
  .btn:disabled{opacity:.5;cursor:not-allowed}
  /* v1.8.1: the period gate marks its button aria-disabled instead of disabled
     so it stays focusable — that is the only way a keyboard user can read the
     reason (the tooltip chip shows on focus and the click answers with a
     toast). It must still look and feel inert, so it shares the disabled skin
     and its own hover delta is switched off. */
  .btn[aria-disabled="true"]{opacity:.5;cursor:not-allowed}
  .btn[aria-disabled="true"]:hover{filter:none;transform:none}
  .btn.primary[aria-disabled="true"]:hover{background:var(--brand);border-color:transparent}
  /* ===== v1.8 icon action buttons =====
     The icon-only sibling of .btn.mini for row toolbars. Quiet at rest and
     brand-tinted under the pointer, because a dense row has to say which
     button is hot. Motion stays on transform only (1px travel, .16s hover,
     .09s press) so the row never reflows; an action in flight swaps the
     glyph for an absolutely-positioned spinner, which also can never move
     the layout. Icon-only controls carry aria-label + data-tip at every call
     site: the tooltip is supplementary, never the only disclosure. */
  .ibtn{position:relative;display:inline-flex;align-items:center;justify-content:center;
    width:34px;height:34px;min-width:34px;padding:0;flex:none;cursor:pointer;
    border:1px solid var(--line);border-radius:9px;background:var(--card);color:var(--muted);
    font-family:inherit;
    transition:background .16s,border-color .16s,color .16s,transform .16s}
  .ibtn .ic{width:14px;height:14px}
  .ibtn:hover{border-color:var(--brand);background:var(--brand-soft);color:var(--brand);
    transform:translateY(-1px)}
  .ibtn:active{transform:translateY(0) scale(.96);transition-duration:.09s}
  .ibtn:focus-visible{border-color:var(--brand);box-shadow:var(--ring)}
  .ibtn.primary{background:var(--brand);border-color:transparent;color:var(--on-brand)}
  .ibtn.primary:hover{background:var(--brand-hover);border-color:transparent;color:var(--on-brand)}
  .ibtn.ok{color:var(--pill-ok-fg);border-color:var(--pill-ok-fg);background:var(--pill-ok-bg)}
  .ibtn.warn{color:var(--pill-warn-fg);border-color:var(--pill-warn-fg);background:var(--pill-warn-bg)}
  /* .ibtn.ok/.ibtn.warn set their own background, so the shared :hover tint
     never reached them. currentColor/soft-token swaps are invisible here (the
     border already IS the ink colour and the soft tints differ by 0.01 alpha),
     so the hover lights a halo of the same tint instead — and never on a
     disabled button, where the whole point is that it does not react. */
  .ibtn.ok:hover:not(:disabled),.ibtn.warn:hover:not(:disabled){
    filter:brightness(.94);transform:translateY(-1px);
    box-shadow:0 0 0 3px var(--pill-ok-bg)}
  .ibtn.warn:hover:not(:disabled){box-shadow:0 0 0 3px var(--pill-warn-bg)}
  .ibtn.danger{color:var(--danger);border-color:var(--danger-soft);background:var(--danger-soft)}
  .ibtn.danger:hover{border-color:var(--danger)}
  .ibtn.ghost{background:var(--card);border-color:var(--line-strong);color:var(--txt)}
  .ibtn.ghost:hover{background:var(--brand-soft);border-color:var(--brand);color:var(--brand)}
  .ibtn:disabled,.ibtn[disabled]{opacity:.5;cursor:not-allowed;transform:none}
  .ibtn.busy{cursor:progress;pointer-events:none}
  .ibtn.busy .ic{opacity:0}
  .ibtn.busy::before{content:'';position:absolute;width:15px;height:15px;border-radius:50%;
    border:2px solid currentColor;border-top-color:transparent;animation:ibspin .7s linear infinite}
  @keyframes ibspin{to{transform:rotate(1turn)}}
  /* touch targets grow to 44px while pointer devices keep the dense 34px that
     matches the .btn.mini row rhythm */
  @media (pointer:coarse){.ibtn{width:44px;height:44px;min-width:44px}}
  @media (prefers-reduced-motion:reduce){
    .ibtn{transition:none}
    .ibtn:hover,.ibtn:active,
    .ibtn.ok:hover:not(:disabled),.ibtn.warn:hover:not(:disabled){
      transform:none;filter:none;box-shadow:none}
    /* no spinner: the glyph stays, dimmed, so "in flight" is still visible */
    .ibtn.busy::before{animation:none;border-top-color:var(--muted)}
    .ibtn.busy .ic{opacity:.35}}
  .ibacts{display:flex;gap:6px;align-items:center;justify-content:flex-end;white-space:nowrap}
  /* tooltip chip (its behaviour lives in the TIP layer further down the
     script): fixed and re-parented, because a tip inside a scrolling table
     would be eaten by .tbl-wrap/.tblcard overflow, and a tip inside an open
     dialog would be painted under it (the dialog sits in the browser top
     layer). The geometry is read from getBoundingClientRect in physical
     pixels, so nothing here needs RTL mirroring; --txt on --bg inverts with
     the theme, which keeps the contrast ratio identical in both modes. */
  #tip{position:fixed;z-index:120;max-width:min(280px,calc(100vw - 16px));
    padding:6px 10px;border-radius:8px;background:var(--txt);color:var(--bg);
    font-size:11.5px;font-weight:500;line-height:1.7;box-shadow:var(--shadow-2);
    text-align:start;white-space:normal;unicode-bidi:plaintext;
    pointer-events:none;animation:tipin .12s ease-out}
  #tip[hidden]{display:none}
  @keyframes tipin{from{opacity:0}}
  @media (prefers-reduced-motion:reduce){#tip{animation:none}}
  /* ===== v1.8 periods tab =====
     A period card answers one question at a glance — how big was this batch
     and how much money moved through it — and the whole card is the way into
     the case-by-case detail. */
  dialog:has(.perdlg){width:min(1040px,96vw)}
  .pcards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
  .pcard{position:relative;background:var(--card);border:1px solid var(--line);
    border-radius:14px;padding:13px 15px;box-shadow:var(--shadow-1);
    transition:border-color .15s,transform .15s,box-shadow .15s}
  .pcard:hover{border-color:var(--brand);transform:translateY(-2px);box-shadow:var(--shadow-2)}
  /* The stretched target sits ABOVE the card's text (so a click anywhere on
     the card opens the period) and BELOW the card's own action row (so those
     buttons stay clickable). The focus ring is drawn on the target itself —
     an outline works on every engine, the :has() ring would not. */
  .pcard-hit{position:absolute;inset:0;z-index:1;padding:0;border:0;background:transparent;
    border-radius:inherit;cursor:pointer}
  .pcard-hit:focus-visible{outline:2px solid var(--brand);outline-offset:-3px}
  /* the row itself is transparent to the pointer — only its buttons are
     clickable, so the empty part still falls through to the card target */
  .pcard .pacts{position:relative;z-index:2;display:flex;gap:6px;align-items:center;
    justify-content:flex-end;margin-top:10px;pointer-events:none}
  .pcard .pacts>*{pointer-events:auto}
  .pcard .ph{display:flex;align-items:center;justify-content:space-between;gap:8px}
  .pcard .pn{font-size:14.5px;font-weight:700}
  .pcard .pd{font-size:11.5px;color:var(--muted);margin-top:5px;font-variant-numeric:tabular-nums}
  .pcard .pc{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
  .pcard .pm{display:flex;flex-wrap:wrap;gap:16px;margin-top:11px;padding-top:10px;
    border-top:1px solid var(--line);font-size:12px;font-variant-numeric:tabular-nums}
  .pcard .pm span{white-space:nowrap}
  .pcard .pm b{font-weight:700}
  .pcard .pm .d{color:var(--danger)}
  .pcard .pm .c{color:var(--ok)}
  .per-kpis{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line);
    border-radius:12px;background:var(--card);overflow:hidden;margin:2px 0 12px}
  .per-kpi{padding:10px 13px;border-inline-start:1px solid var(--line);min-width:0}
  .per-kpi:first-child{border-inline-start:none}
  .per-kpi .l{display:block;font-size:11px;color:var(--muted);font-weight:600;margin-bottom:3px}
  .per-kpi .v{display:block;font-size:15.5px;font-weight:750;font-variant-numeric:tabular-nums;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .per-kpi.ok .v{color:var(--ok)}
  .per-kpi.bad .v{color:var(--danger)}
  .pmoney{font-variant-numeric:tabular-nums;white-space:nowrap;font-size:12.5px}
  .pmoney.d{color:var(--danger)}
  .pmoney.c{color:var(--ok)}
  @media (max-width:900px){.per-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}

  /* KPI — "دفتر ثبت" ledger strip: one surface, hairline dividers, not 4
     clone cards (frontend-design: structure carries the information). */
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);background:var(--card);
    border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow-1);
    margin-bottom:0;overflow:hidden}
  .kpi{position:relative;background:transparent;border:none;border-inline-start:1px solid var(--line);
    padding:14px 18px;cursor:pointer;text-align:right;font-family:inherit;transition:background .15s}
  .kpi:first-child{border-inline-start:none}
  .kpi:hover{background:var(--brand-soft)}
  .kpi:focus-visible{box-shadow:inset var(--ring)}
  .kpi::after{content:'';position:absolute;inset-inline:0;bottom:0;height:2px;
    background:transparent;transition:background .15s}
  .kpi:hover::after{background:var(--brand)}
  .kpi .n{display:block;font-size:27px;font-weight:800;line-height:1.25;
    font-variant-numeric:tabular-nums;letter-spacing:-.3px;transition:transform .15s}
  .kpi:active .n{transform:scale(.97)}
  .kpi .l{font-size:12px;color:var(--muted);font-weight:500}
  .kpi.attention .n{color:var(--warn)}
  .kpi.k-problem .n{color:var(--danger)}
  .kpi.k-ok .n{color:var(--ok)}
  /* v1.5 finance dialog: segmented mode switch, summary cards, weekly day
     strip, two-segment activity bar and the collapsible transactions — one
     token set serves light and dark, logical properties only. The report
     body is wide (5-column money table), so its marker class widens the
     shared dialog; without :has support it simply stays 600px. */
  dialog:has(.findlg){width:min(760px,94vw)}
  .seg{display:inline-flex;gap:2px;border:1px solid var(--line-strong);
    border-radius:10px;background:var(--card2);padding:3px}
  .seg button{border:0;background:transparent;color:var(--muted);border-radius:8px;
    padding:4px 14px;font-family:inherit;font-size:12.5px;font-weight:600;cursor:pointer;
    min-height:0;transition:background .15s,color .15s}
  .seg button:hover{color:var(--txt)}
  .seg button.on{background:var(--card);color:var(--brand);box-shadow:var(--shadow-1)}
  .seg button:focus-visible{box-shadow:var(--ring)}
  .chev-r{transform:rotate(-90deg)}
  .chev-l{transform:rotate(90deg)}
  .finkpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border:1px solid var(--line);
    border-radius:12px;background:var(--card);overflow:hidden;margin:2px 0 12px}
  .finkpi{padding:10px 14px;border-inline-start:1px solid var(--line);min-width:0}
  .finkpi:first-child{border-inline-start:none}
  .finkpi .l{display:block;font-size:11px;color:var(--muted);font-weight:600;margin-bottom:3px}
  .finkpi .v{display:block;font-size:16.5px;font-weight:750;font-variant-numeric:tabular-nums;
    letter-spacing:-.2px}
  .finkpi.ok .v{color:var(--ok)}
  .finkpi.bad .v{color:var(--danger)}
  .finkpi .split{display:flex;gap:5px;flex-wrap:wrap;align-items:center;margin-top:6px}
  .findays{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:6px;margin:0 0 12px}
  .finday{border:1px solid var(--line);border-radius:10px;background:var(--card2);
    padding:8px 10px;display:flex;flex-direction:column;gap:3px;min-width:0}
  .finday .d{font-size:11.5px;font-weight:650}
  .finday .dt{font-size:10.5px;color:var(--muted)}
  .finday .r,.finday .b{font-size:11px;font-weight:650;font-variant-numeric:tabular-nums}
  .finday .r{color:var(--ok)}
  .finday .b{color:var(--danger)}
  .finday .r.zero,.finday .b.zero{color:var(--faint);font-weight:500}
  .finnum{font-variant-numeric:tabular-nums}
  .fin-ok{color:var(--ok)}
  .fin-bad{color:var(--danger)}
  .fin-zero{color:var(--muted)}
  .finbar{display:flex;height:4px;border-radius:2px;overflow:hidden;margin-top:6px;
    background:var(--pill-neutral-bg);min-width:52px;max-width:120px}
  .finbar span{display:block;height:100%}
  .finbar .g{background:var(--ok)}
  .finbar .b{background:var(--danger);flex:1}
  .finsec{border:1px solid var(--line);border-radius:10px;margin:12px 0 0;background:var(--card2)}
  .finsec summary{display:flex;align-items:center;gap:8px;cursor:pointer;padding:9px 12px;
    font-size:12.5px;font-weight:650;list-style:none;user-select:none}
  .finsec summary::-webkit-details-marker{display:none}
  .finsec summary:focus-visible{box-shadow:inset var(--ring)}
  .finsec .chev{display:inline-flex;color:var(--muted);transition:transform .15s}
  .finsec[open] .chev{transform:rotate(180deg)}
  .finsec .finsec-body{padding:2px 12px 10px}
  .fintx{display:flex;gap:8px;flex-wrap:wrap;align-items:baseline;font-size:12px;padding:6px 0}
  .fintx+.fintx{border-top:1px solid var(--line)}
  /* v1.6 accounting round: the voided-transaction strike (ledger + statement
     rows, one token set for both themes), the statement identity row and its
     compact 4-cell totals strip — the finance KPI grid re-tokened smaller. */
  .voidedtx td{color:var(--muted);text-decoration:line-through}
  .stmthead{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 10px}
  .stmthead b{font-size:14px}
  .stmt-kpis{grid-template-columns:repeat(4,minmax(0,1fr))}
  .stmt-kpis .finkpi .v{font-size:14px}
  /* tabs — active pill: soft brand fill + underline that covers the rail;
     flex-end + the -1px margin make the 2px tab border overlap the 1px
     container rule (the classic connected-underline tab bar) */
  .tabs{display:flex;gap:4px;flex-wrap:wrap;align-items:flex-end;margin-bottom:16px;
    border-bottom:1px solid var(--line)}
  .tab{background:transparent;border:none;border-bottom:2px solid transparent;border-radius:9px 9px 0 0;
    padding:10px 15px 8px;margin-bottom:-1px;cursor:pointer;font-family:inherit;
    font-size:var(--crm-fs,13.5px);color:var(--muted);font-weight:500;min-height:40px;
    transition:color .15s,background .15s,border-color .15s}
  .tab:hover{color:var(--txt);background:var(--pill-neutral-bg)}
  .tab.active{color:var(--brand);border-bottom-color:var(--brand);background:var(--brand-soft)}
  .tab .cnt{font-size:11px;font-weight:600;background:var(--pill-neutral-bg);color:var(--pill-neutral-fg);
    border-radius:999px;padding:1px 7px;margin-inline-start:6px;font-variant-numeric:tabular-nums;
    display:inline-block;min-width:20px;text-align:center}
  .tab.active .cnt{background:var(--card);color:var(--brand)}
  /* two-column content + history aside */
  .crm-cols{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:14px;align-items:start}
  .crm-aside{display:flex;flex-direction:column;gap:12px;min-width:0}
  .crm-aside .history{max-height:420px;overflow:auto;position:sticky;top:12px}
  /* one header scale for the whole page: main cards use .card h3, the
     compact aside captions (history + summary rail) share one smaller cut */
  .crm-aside .history h3,.devrail h4{margin:0 0 8px;font-size:12.5px;font-weight:600;color:var(--muted)}
  .crm-aside .history .kbd{margin-bottom:4px;line-height:1.7}
  @media (max-width:1100px){.crm-cols{grid-template-columns:1fr}.crm-aside .history{position:static;max-height:260px}}
  /* v1.3.4 (operator request): the KPI strip and the devices summary rail
     render in the aside above the history card, so the case table owns the
     full main column. On the narrow desktop aside the four KPIs become a
     2x2 grid; below the 1100px breakpoint the aside is full-width and the
     base 4-column strip returns. */
  @media (min-width:1101px){.crm-aside .kpis{grid-template-columns:repeat(2,1fr)}
    .crm-aside .kpi:nth-child(3){border-inline-start:none}}
  /* payment robot row on device cards */
  .payrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:var(--card2);
    border:1px solid var(--line);border-radius:10px;padding:8px 10px}
  .payrow a.btn{text-decoration:none;display:inline-flex;align-items:center}
  /* continue button states */
  .btn-continue:disabled{opacity:.45;cursor:not-allowed}
  /* quick links box (bottom corner). v1.9: moved to the bottom-LEFT corner —
     in RTL, inset-inline-start is the physical right, where the toasts also
     live, so the two stacked. inset-inline-end is the physical left and is
     clear. The box also takes a close button now (qb-x). */
  .quickbox-wrap{position:fixed;bottom:14px;inset-inline-end:14px;z-index:60}
  .quickbox{position:relative;background:var(--card);border:1px solid var(--line);border-radius:12px;
    box-shadow:var(--shadow-2);padding:8px;display:flex;flex-direction:column;gap:5px;max-width:220px}
  .qb-title{font-size:11px;color:var(--muted);font-weight:600;margin:0 2px 2px}
  .qb-x{position:absolute;top:6px;inset-inline-end:6px;background:transparent;border:0;
    color:var(--muted);font-size:15px;line-height:1;cursor:pointer;padding:2px 5px;border-radius:6px}
  .qb-x:hover{color:var(--txt);background:var(--card2)}
  .qb-btn{display:block;background:var(--card2);border:1px solid var(--line);border-radius:8px;
    padding:6px 10px;font-size:12px;color:var(--txt);text-decoration:none;text-align:center;
    transition:background .15s,color .15s,border-color .15s}
  .qb-btn:hover{background:var(--brand-soft);color:var(--brand)}
  #quickWrap .muted{font-size:11px}
  /* v1.9: the header speaker toggle rides the existing iconbtn chrome. */
  #soundBtn.on{color:var(--txt)}
  #soundBtn.off{color:var(--muted);text-decoration:line-through}
  /* cards & tables */
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;
    margin-bottom:14px;box-shadow:var(--shadow-1)}
  .card .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  /* v1.3.7: a base .row — toolbars outside .card (devices tab) rendered
     as an unstyled block with the hint text glued to the button. */
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .card h3{margin:0 0 10px;font-size:14px;font-weight:650}
  table{width:100%;border-collapse:collapse;font-size:13px}
  /* ledger table: soft header band + hairline row rules; the row hover is
     the same brand tint the KPI strip and summary rail use */
  th,td{border-bottom:1px solid var(--line);padding:10px 12px;text-align:right;vertical-align:top}
  th{color:var(--muted);font-weight:650;font-size:11px;white-space:nowrap;background:var(--card2);
    border-bottom:1px solid var(--line-strong)}
  tbody td{transition:background .15s}
  tbody tr:hover td{background:var(--brand-soft)}
  tr:last-child td{border-bottom:none}
  .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11.5px;white-space:nowrap;font-weight:500}
  .pill.n{background:var(--pill-neutral-bg);color:var(--pill-neutral-fg)}
  .pill.ok{background:var(--pill-ok-bg);color:var(--pill-ok-fg)}
  .pill.bad{background:var(--pill-danger-bg);color:var(--pill-danger-fg)}
  .pill.warn{background:var(--pill-warn-bg);color:var(--pill-warn-fg)}
  .muted{color:var(--muted);font-size:12.5px}
  .kbd{font-size:11px;color:var(--faint);font-variant-numeric:tabular-nums}
  .chip{display:inline-block;background:var(--pill-neutral-bg);color:var(--pill-neutral-fg);
    border-radius:7px;padding:2px 9px;font-size:11.5px}
  .chip .ic{margin-inline-end:3px}
  /* device cards */
  .devgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:12px}
  .devrail{display:flex;flex-direction:column;gap:12px;min-width:0}
  .devrail .card{padding:10px 12px;margin-bottom:0}
  .sumrow{display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:8px;
    border-top:1px solid var(--line);cursor:pointer;transition:background .15s}
  .sumrow:first-of-type{border-top:0}
  .sumrow:hover{background:var(--brand-soft)}
  .sumrow .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
  .sumrow .dot{width:8px;height:8px;border-radius:50%;flex:none}
  .sumbox{max-height:230px;overflow:auto;padding-bottom:4px}
  .dev.flash{animation:devflash 1.6s ease-out 1}
  @keyframes devflash{0%{box-shadow:0 0 0 3px var(--brand-soft)}70%{box-shadow:0 0 0 3px var(--brand-soft)}100%{box-shadow:none}}
  @media (prefers-reduced-motion:reduce){.dev.flash{animation:none}}
  .closedreason{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;unicode-bidi:plaintext}
  @media (max-width:900px){.closedreason{max-width:60vw}}
  .dev{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 15px 12px;
    box-shadow:var(--shadow-1);display:flex;flex-direction:column;gap:10px;
    border-inline-start:3px solid transparent}
  .dev.needs-action{border-inline-start-color:var(--warn)}
  .dev .devhead{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
  .dev .devhead b{font-size:15px;letter-spacing:-.2px}
  .dev .devhead .ic{color:var(--faint);align-self:center;flex:none}
  .dev .ser{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;color:var(--faint);direction:ltr;unicode-bidi:embed;
    letter-spacing:.4px}
  .dev .meta{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  /* 9-step stage rail — the page's signature: numbered nodes, current node
     enlarged (frontend-design: one bold element, not decoration). */
  .rail{display:flex;gap:0;align-items:center;margin:4px 0 2px}
  .rail .step{flex:1;height:4px;border-radius:2px;background:var(--pill-neutral-bg);position:relative}
  .rail .step::before{counter-increment:stage;content:counter(stage);
    position:absolute;top:-13px;inset-inline-start:calc(100% - 7px);
    width:14px;height:14px;border-radius:50%;background:var(--pill-neutral-bg);
    color:var(--faint);font-size:8.5px;font-weight:700;display:grid;place-items:center;
    font-variant-numeric:tabular-nums}
  .rail{counter-reset:stage}
  .rail .step{border:0;padding:0;cursor:pointer;font:inherit}
  .rail .step:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
  .rail .step.done{background:var(--ok)}
  .rail .step.done::before{background:var(--ok-soft);color:var(--ok)}
  .rail .step.cur{background:var(--brand);box-shadow:0 0 0 3px var(--brand-soft)}
  .rail .step.cur::before{background:var(--brand);color:var(--on-brand);
    width:17px;height:17px;top:-15px;font-size:9.5px}
  .rail .step.bad{background:var(--danger)}
  .rail .step.bad::before{background:var(--danger-soft);color:var(--danger)}
  .rail .step.warn{background:var(--warn)}
  .rail .step.warn::before{background:var(--warn-soft);color:var(--warn)}
  .stagebar{display:flex;justify-content:space-between;align-items:center;gap:8px}
  .stagebar .st{font-size:12.5px;font-weight:600}
  .dev .acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:auto;padding-top:2px}
  .dev .subrow{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px}
  .dev .subrow .cell b{font-size:11px;color:var(--muted);font-weight:600;display:block}
  /* v1.5 B7: cases table + case-detail modal — per-case actions moved off
     the list into the modal; table rows keep the devcard-<id> anchor the
     summary rail flashes (tr cells pulse the background, devRow cards keep
     the old box-shadow pulse). */
  .tbl-wrap{overflow-x:auto}
  /* full-bleed case-table card: no card padding, clipped corners, and a
     soft inline-start edge fade that appears only while the table is
     scrolled (toggled by the capture-phase scroll listener in the JS) */
  .card.tblcard{position:relative;padding:0;overflow:hidden}
  .card.tblcard::after{content:'';position:absolute;inset-block:0;inset-inline-start:0;width:26px;
    background:linear-gradient(to left,var(--card),transparent);pointer-events:none;opacity:0;
    transition:opacity .15s;z-index:1}
  .card.tblcard.scrl::after{opacity:1}
  .casetbl td{white-space:nowrap}
  tr.flash>td{animation:rowflash 1.6s ease-out 1}
  @keyframes rowflash{0%,70%{background:var(--brand-soft)}100%{background:transparent}}
  .card.flash{animation:devflash 1.6s ease-out 1}
  .dlg-lbl{font-size:11px;color:var(--muted);font-weight:600;margin:12px 0 5px}
  .dlg-sec{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  /* v1.5.x case detail: full-width next-step card + tool/quiet action groups */
  .nextcard{margin:12px 0 4px;padding:12px 14px;border:1px solid var(--line);border-inline-start:4px solid var(--brand);border-radius:10px;background:var(--card2);display:flex;flex-wrap:wrap;align-items:center;gap:10px}
  .nextcard .btn{flex:1 1 auto;min-height:44px;font-size:15px}
  .nextcard .need{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
  /* v1.3.5 (operator request): every action cluster sits in its own framed
     group — tools of the step, payment controls, low-frequency actions. */
  .grp{border:1px solid var(--line);border-radius:12px;background:var(--card2);
    padding:10px 12px;margin:12px 0 0}
  .grp .grp-lbl{font-size:11px;font-weight:600;color:var(--muted);margin:0 0 8px}
  .grp-quiet{background:transparent;border-style:dashed}
  .grp .payrow{background:transparent;border:0;padding:0}
  .tools{display:flex;flex-wrap:wrap;gap:8px}
  .quiet{display:flex;flex-wrap:wrap;gap:6px;opacity:.92}
  /* v1.3.5 step-guide dialog: numbered header + mini progress dots */
  .guide .ghead{display:flex;align-items:center;gap:12px;margin-bottom:12px;padding-inline-end:34px}
  .guide .gnum{width:44px;height:44px;border-radius:12px;flex:none;display:grid;place-items:center;
    background:var(--brand);color:var(--on-brand);font-size:19px;font-weight:800}
  .guide .gnum.bad{background:var(--danger)}
  .guide .glbl{font-size:11px;color:var(--muted);font-weight:600;margin-bottom:2px}
  .guide .ghead h3{margin:0;padding:0;font-size:15.5px}
  .guide .grail{display:flex;gap:5px;margin:0 0 14px}
  .guide .gdot{flex:1;height:4px;border-radius:2px;background:var(--pill-neutral-bg)}
  .guide .gdot.done{background:var(--ok)}
  .guide .gdot.cur{background:var(--brand);box-shadow:0 0 0 3px var(--brand-soft)}
  .guide .gdot.bad{background:var(--danger);box-shadow:0 0 0 3px var(--danger-soft)}
  .guide .gdesc{margin:0;color:var(--txt);font-size:13.5px;line-height:2.05}
  @media (prefers-reduced-motion:reduce){tr.flash>td,.card.flash{animation:none}}
  /* forms & dialog */
  input,select,textarea{font-family:inherit;font-size:13.5px;border:1px solid var(--line-strong);
    border-radius:9px;padding:8px 11px;background:var(--card);color:var(--txt);min-height:34px}
  select{cursor:pointer}
  input:disabled,select:disabled{background:var(--card2);color:var(--muted)}
  label.f{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted);font-weight:500}
  label.f input,label.f select,label.f textarea{color:var(--txt)}
  label.f .ferr{color:var(--danger);font-size:11.5px;min-height:0}
  input[aria-invalid="true"],select[aria-invalid="true"],textarea[aria-invalid="true"]{border-color:var(--danger)}
  /* checkbox control — custom, aligned, keyboard-visible (ux-guidelines) */
  label.f.check{flex-direction:row;align-items:center;gap:9px;cursor:pointer;
    padding:7px 11px;border:1px solid var(--line-strong);border-radius:9px;background:var(--card);
    min-height:34px;user-select:none}
  label.f.check input{position:absolute;opacity:0;width:0;height:0}
  label.f.check .box{flex:none;width:17px;height:17px;border:1.5px solid var(--line-strong);
    border-radius:5px;background:var(--card2);position:relative;transition:background .12s,border-color .12s}
  label.f.check .box::after{content:'';position:absolute;inset:2px 3px 4px;
    border-inline-start:2px solid var(--on-brand);border-bottom:2px solid var(--on-brand);
    transform:rotate(-45deg) scale(0);transform-origin:center;transition:transform .12s}
  label.f.check input:checked+.box{background:var(--brand);border-color:var(--brand)}
  label.f.check input:checked+.box::after{transform:rotate(-45deg) scale(1)}
  label.f.check input:focus-visible+.box{box-shadow:var(--ring)}
  label.f.check .ft{font-size:12.5px;color:var(--txt);font-weight:500}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}
  dialog{position:relative;border:1px solid var(--line);border-radius:16px;background:var(--card);color:var(--txt);
    padding:20px;width:min(600px,94vw);box-shadow:var(--shadow-2)}
  dialog::backdrop{background:rgba(8,10,25,.55)}
  dialog h3{margin:0 0 12px;font-size:16px;font-weight:650;padding-inline-end:34px}
  /* long bodies (case detail) scroll inside #dlgBody so the dialog title and
     the chrome x stay put; short dialogs are unaffected */
  #dlgBody{max-height:calc(100dvh - 140px);overflow:auto}
  /* shared dialog chrome: one x-close outside #dlgBody (bodies keep their
     own dismiss buttons; native ESC/cancel path untouched) */
  .dlg-x{position:absolute;top:10px;inset-inline-end:10px;background:transparent;border:0;
    color:var(--muted);font-size:20px;line-height:1;cursor:pointer;padding:2px 6px;border-radius:8px}
  .dlg-x:hover{color:var(--txt);background:var(--card2)}
  /* v1.9.1: the inquiry-result picture dialog. The capture is whatever the
     remote site rendered, so its height is unbounded -- the frame caps it and
     scrolls instead of pushing the download button off the viewport, and the
     width cap keeps a wide full-page fallback from stretching the dialog. */
  .case-shot-dialog{min-width:min(560px,86vw);max-width:min(860px,92vw)}
  .case-shot-frame{max-height:min(62dvh,620px);overflow:auto;
    border-radius:10px;background:var(--card2);padding:6px;
    display:flex;justify-content:center}
  /* `download` only works on an anchor, and .btn is written for <button>:
     without this the control renders as an underlined inline link. */
  a.btn{text-decoration:none;display:inline-flex;align-items:center;
    justify-content:center}
  .err{color:var(--danger);font-size:12.5px;white-space:pre-line}
  /* states */
  /* one empty-state pattern everywhere: icon tile + bold title + muted
     description (+ optional action), rendered by emptyInnerHtml */
  .empty{padding:34px 16px;text-align:center;color:var(--muted)}
  .empty .eic{display:inline-grid;place-items:center;width:46px;height:46px;border-radius:13px;
    background:var(--pill-neutral-bg);color:var(--faint);margin-bottom:12px}
  .empty .eic .ic{width:22px;height:22px}
  .empty b{display:block;font-size:15px;color:var(--txt);margin-bottom:5px;font-weight:650}
  .empty .esub{display:block;font-size:12.5px;line-height:1.9}
  .skel{height:84px;border-radius:14px;border:1px solid var(--line);
    background:linear-gradient(100deg,var(--card) 40%,var(--card2) 50%,var(--card) 60%);
    background-size:200% 100%;animation:sh 1.1s infinite linear;margin-bottom:10px}
  @keyframes sh{to{background-position:-200% 0}}
  @media (prefers-reduced-motion:reduce){.skel{animation:none}}
  /* toast */
  #toasts{position:fixed;bottom:18px;inset-inline-start:18px;display:flex;flex-direction:column;gap:8px;z-index:99}
  .toast{background:var(--ok);color:#fff;padding:10px 18px;border-radius:10px;font-size:13px;
    box-shadow:var(--shadow-2);animation:tin .18s ease-out}
  .toast.bad{background:var(--danger)}
  /* v1.7: the period-close notice is a warning, not a success. Solid amber
     with ink text keeps >=4.5:1 on --warn in both themes (white text would
     be 3.7:1 in light and 1.8:1 in dark). */
  .toast.warn{background:var(--warn);color:#0c1226}
  /* dark theme brightens --ok/--danger, so white toast text loses contrast
     (1.9:1 / 2.8:1) — flip to ink text there */
  html[data-theme="dark"] .toast{color:#0c1226}
  @keyframes tin{from{opacity:0;transform:translateY(6px)}}
  @media (prefers-reduced-motion:reduce){.toast{animation:none}}
  /* log console */
  /* .logbox: the periodic-tab log card uses the same console chrome as the
     reports #logBox (it previously had no matching rule at all) */
  #logBox,.logbox{max-height:320px;overflow:auto;border:1px solid var(--line);border-radius:10px;
    background:var(--card2);padding:10px;font-size:11.5px;display:flex;flex-direction:column;gap:3px}
  /* v1.4.0 tab toolbar: search box + result pill + (devices only) stage
     chips. Sticky over long lists; lives OUTSIDE the re-rendered #tabBody
     so typing never loses focus. */
  .tabbar{position:sticky;top:8px;z-index:5;background:var(--bg);padding:8px 0;
    display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .tabbar .srch{position:relative;flex:1 1 260px;max-width:420px;min-width:200px}
  .tabbar .srch .ic{position:absolute;inset-inline-start:11px;top:50%;
    transform:translateY(-50%);color:var(--faint);pointer-events:none}
  .tabbar .srch input{width:100%;padding-inline-start:32px;padding-inline-end:30px}
  .tabbar .srch .clr{position:absolute;inset-inline-end:5px;top:50%;transform:translateY(-50%);
    border:0;background:transparent;color:var(--muted);font-size:15px;line-height:1;
    cursor:pointer;padding:4px 7px;border-radius:7px;display:none}
  .tabbar .srch .clr:hover{color:var(--txt);background:var(--card2)}
  .tabbar .srch.hasq .clr{display:block}
  .tabbar .cntpill{font-variant-numeric:tabular-nums}
  /* .pill sets display:inline-block, which would beat the UA's [hidden]
     rule — keep the count pill actually hideable. */
  .tabbar .cntpill[hidden]{display:none}
  .tabchips{display:flex;gap:6px;flex-wrap:wrap;width:100%}
  .chipbtn{border:1px solid var(--line);background:var(--card);color:var(--muted);
    border-radius:999px;padding:3px 12px;font-family:inherit;font-size:12px;font-weight:500;
    cursor:pointer;min-height:26px;transition:background .15s,border-color .15s,color .15s}
  .chipbtn:hover{border-color:var(--brand);color:var(--brand);background:var(--brand-soft)}
  .chipbtn.active{background:var(--brand);border-color:transparent;color:var(--on-brand)}
  /* one soft scrollbar for every scroll region on the page */
  .sumbox,.crm-aside .history,#logBox,.logbox,.card.tblcard .tbl-wrap,#dlgBody{
    scrollbar-width:thin;scrollbar-color:var(--line-strong) transparent}
  @media (max-width:640px){body{padding:14px 10px 70px}
    .devgrid{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}.kpi:nth-child(3){border-inline-start:none}}

  /* --- CRM Cloud Sync Surface (v1.12.1) --- */
  .cloud-card { display:grid; gap:14px; }
  .cloud-banner { display:none; gap:11px; align-items:flex-start; padding:13px 15px;
    border:1px solid color-mix(in srgb,var(--warn) 45%,var(--line));
    border-inline-start:5px solid var(--warn); border-radius:12px;
    background:var(--warn-soft); color:var(--txt); }
  .cloud-banner.on { display:flex; }
  .cloud-banner .cloud-banner-b { font-size:13.5px; font-weight:750; color:var(--warn); }
  .cloud-banner .cloud-banner-p { margin:6px 0 0; font-size:12px; line-height:1.85; }
  .cloud-state-row { display:flex; align-items:center; gap:10px; flex-wrap:wrap; min-height:32px; }
  .cloud-pill { display:inline-flex; align-items:center; gap:7px; min-inline-size:140px;
    justify-content:flex-start; padding:6px 13px; border-radius:999px; border:1px solid transparent;
    font-size:12px; font-weight:700; cursor:pointer; font-family:inherit; }
  .cloud-pill.ok { color:var(--ok); background:var(--ok-soft); border-color:color-mix(in srgb,var(--ok) 30%,var(--line)); }
  .cloud-pill.warn { color:var(--warn); background:var(--warn-soft); border-color:color-mix(in srgb,var(--warn) 30%,var(--line)); }
  .cloud-pill.bad { color:var(--danger); background:var(--danger-soft); border-color:color-mix(in srgb,var(--danger) 30%,var(--line)); }
  .cloud-pill.mute { color:var(--muted); background:var(--card); border-color:var(--line); }
  .cloud-actor { display:none; align-items:center; gap:7px; font-size:12px; color:var(--muted); }
  .cloud-actor.on { display:inline-flex; }
  .cloud-actor b { color:var(--txt); font-weight:700; }
  .cloud-facts { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; }
  .cloud-fact { display:flex; flex-direction:column; justify-content:space-between; gap:6px;
    min-height:64px; padding:11px 12px; border:1px solid var(--line); border-radius:11px;
    background:var(--card); }
  .cloud-fact-l { font-size:11px; color:var(--muted); line-height:1.6; }
  .cloud-fact-v { font-size:15px; font-weight:750; color:var(--txt); word-break:break-word; }
  .cloud-fact-v.cloud-code { direction:ltr; text-align:right; font-family:var(--mono, monospace);
    font-size:12.5px; letter-spacing:.4px; color:var(--warn); overflow-wrap:anywhere; }
  .cloud-error { display:none; gap:8px; align-items:flex-start; padding:10px 13px; border-radius:10px;
    border:1px solid color-mix(in srgb,var(--danger) 35%,var(--line));
    background:var(--danger-soft); color:var(--danger); font-size:12.5px; line-height:1.8; }
  .cloud-error.on { display:flex; }
  .cloud-status { min-height:18px; font-size:12px; color:var(--muted); line-height:1.7; }
  .cloud-status.ok { color:var(--ok); }
  .cloud-status.bad { color:var(--danger); }
  .cloud-actions { display:flex; gap:9px; flex-wrap:wrap; align-items:center; }
  .cloud-btn { width:auto; min-width:160px; padding:10px 16px; border:0;
    border-radius:10px; background:var(--brand); color:var(--on-brand); font-family:inherit;
    font-size:12.5px; font-weight:650; cursor:pointer; display:inline-flex; align-items:center;
    justify-content:center; gap:7px; transition:background .15s,opacity .15s; box-shadow:var(--shadow-1); }
  .cloud-btn:hover { background:var(--brand-hover); }
  .cloud-btn[disabled] { opacity:.55; cursor:progress; }
  .cloud-btn.ghost { background:transparent; color:var(--txt); border:1px solid var(--line); box-shadow:none; }
  .cloud-btn.ghost:hover { border-color:var(--brand); color:var(--brand); background:var(--brand-soft); }
  .cloud-btn.ghost-danger { background:transparent; color:var(--danger);
    border:1px solid color-mix(in srgb,var(--danger) 40%,var(--line)); box-shadow:none; }
  .cloud-btn.ghost-danger:hover { background:var(--danger-soft); }
  .cloud-btn.mini { min-width:auto; padding:6px 12px; font-size:11.5px; }
  .cloud-block { display:grid; gap:10px; padding:16px; border:1px solid var(--line); border-radius:12px; background:var(--card); }
  .cloud-block > strong { font-size:13.5px; font-weight:750; }
  .cloud-fields { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
  .cloud-field { display:grid; gap:6px; min-width:0; }
  .cloud-field label { font-size:11.5px; color:var(--muted); }
  .cloud-field input { min-height:40px; }
  .cloud-notice { display:none; gap:8px; align-items:flex-start; padding:10px 13px; border-radius:10px;
    border:1px solid color-mix(in srgb,var(--warn) 40%,var(--line));
    background:var(--warn-soft); color:var(--warn); font-size:12.5px; line-height:1.8; }
  .cloud-notice.on { display:flex; }
  .cloud-conflicts { display:none; gap:9px; padding-top:13px; border-top:1px dashed var(--line); }
  .cloud-conflicts.on { display:grid; }
  .cloud-conflict-count { font-size:12.5px; color:var(--muted); margin-bottom:4px; }
  .cloud-conflict-card { display:grid; gap:9px; padding:12px; border:1px solid var(--line); border-radius:10px; background:var(--card2); }
  .cloud-conflict-head { display:flex; justify-content:space-between; align-items:center; font-size:12.5px; }
  .cloud-conflict-table { width:100%; border-collapse:collapse; font-size:11.5px; margin:4px 0; }
  .cloud-conflict-table th, .cloud-conflict-table td { padding:5px 8px; border:1px solid var(--line); text-align:start; }
  .cloud-conflict-table th { background:var(--card); color:var(--muted); font-weight:600; }
  .cloud-conflict-table td.diff-loc { color:var(--brand); }
  .cloud-conflict-table td.diff-srv { color:var(--ok); }
  .cloud-conflict-actions { display:flex; gap:8px; flex-wrap:wrap; }
  .cloud-tutorial { display:grid; gap:12px; padding:16px; border:1px solid var(--line); border-radius:12px; background:var(--card2); }
  .cloud-tutorial h4 { margin:0; font-size:14px; font-weight:750; color:var(--brand); display:flex; align-items:center; gap:8px; }
  .cloud-tutorial-step { display:grid; gap:4px; font-size:12.5px; line-height:1.75; }
  .cloud-tutorial-code { direction:ltr; text-align:left; background:var(--bg); border:1px solid var(--line);
    border-radius:8px; padding:8px 12px; font-family:monospace; font-size:12px; overflow-x:auto; }
  @media (max-width:900px){
    .cloud-facts { grid-template-columns:repeat(2,minmax(0,1fr)); }
    .cloud-fields { grid-template-columns:minmax(0,1fr); }
  }

</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <h1><span class="mono">R</span><span>مدیریت مشتریان و پرونده‌ها<div class="sub">چرخهٔ کامل دستگاه: استعلام ← مسافر ← تحویل ← پرداخت ← کد فعال‌سازی</div></span></h1>
    <nav class="headnav" aria-label="سایر بخش‌های پنل">
      <a class="navlink" href="/site-2"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg>پنل استعلام‌ها</a>
      <a class="navlink" href="/site-1"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.7 2.6 4 5.7 4 9s-1.3 6.4-4 9c-2.7-2.6-4-5.7-4-9s1.3-6.4 4-9z"/></svg>سامانه مدیریت گمرک</a>
    </nav>
    <div class="headacts">
      <button class="iconbtn cloud-pill mute" id="crmCloudPill" onclick="setTab('cloud')" title="وضعیت سرور ابری" style="margin-inline-end:4px"><span id="crmCloudPillIcon"><svg class="ic" width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="8"/></svg></span><span id="crmCloudPillText">سرور ابری</span></button>
      <div class="wwrap">
        <button class="iconbtn" id="widthBtn" aria-expanded="false" aria-haspopup="true" title="عرض صفحه"><svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12h18"/><path d="m7 8-4 4 4 4"/><path d="m17 8 4 4-4 4"/></svg> عرض</button>
        <div class="wpop" id="wPop">
          <div class="wpop-lbl">عرض صفحه</div>
          <div class="row" style="gap:6px">
            <button type="button" class="btn mini ghost wpreset" data-w="1080">باریک</button>
            <button type="button" class="btn mini ghost wpreset" data-w="1240">عادی</button>
            <button type="button" class="btn mini ghost wpreset" data-w="1920">عریض</button>
          </div>
          <input type="range" id="wRange" min="900" max="1920" step="20" aria-label="عرض دقیق صفحه">
          <div class="row" style="justify-content:space-between;margin-top:4px">
            <span class="kbd" id="wVal"></span>
            <button type="button" class="btn mini ghost" id="wReset">بازنشانی</button>
          </div>
        </div>
      </div>
      <button class="iconbtn" id="themeBtn">پوسته</button>
      <button class="iconbtn" id="soundBtn" title="صدای رویدادها" aria-pressed="false"></button>
      <button class="iconbtn" id="logoutBtn" title="خروج از حساب">خروج (__ACTOR__)</button>
    </div>
  </div>
  <div class="tabs" id="tabs"></div>
  <div id="view"></div>
</div>

<dialog id="dlg"><button type="button" class="dlg-x" onclick="closeDlg()" aria-label="بستن">×</button><div id="dlgBody"></div></dialog>
<div id="toasts"></div>
<div class="quickbox-wrap" id="quickWrap"></div>

<script>
"use strict";
/* ================= state ================= */
var STATE = null, TAB = (new URLSearchParams(location.search).get('tab')||'devices'), LOGS = [], LOADFAIL = false;
var STAGE_ORDER = ['new','inquiry','problem','ready_owner','handed','to_payment','payment','payment_done','done'];
// Numbered rail steps (8) — 'problem' is a parking state, not a step;
// a problem device shows step 2 (its inquiry) as failed/red.
var RAIL_STEPS = ['new','inquiry','ready_owner','handed','to_payment','payment','payment_done','done'];
var STAGE_FA = {
  'new':'ثبت پرونده','inquiry':'استعلام ثبت‌نبودن','problem':'دارای اشکال',
  'ready_owner':'اتصال مسافر','handed':'تحویل به مسئول ثبت',
  'to_payment':'استعلام ثبت‌بودن — پرداخت','payment':'در حال پرداخت',
  'payment_done':'پرداخت تأییدشده','done':'تکمیل‌شده','closed':'مختومه'
};
var STAGE_TONE = {'new':'n','inquiry':'n','problem':'bad','ready_owner':'warn','handed':'n',
  'to_payment':'ok','payment':'warn','payment_done':'ok','done':'ok','closed':'n'};
/* v1.9: UI notification sounds. One short cue per event family, served from
   /sfx/. The browser's autoplay policy allows Audio elements that are
   created after the first user gesture — every cue below follows a click or
   a submit, so nothing is blocked. A failure to play is swallowed on
   purpose: a missing cue must never stop the action it announces. */
var SOUND = {
  enabled: true,                 /* mirrored from settings; login page honours it too */
  els: {},                       /* name -> HTMLAudioElement, created once and reused */
  last: {},                      /* name -> ms of the last play, for rate limiting */
};
function sfx(name){
  if(!SOUND.enabled)return;
  if(document.hidden)return;      /* do not beep into a tab the operator left */
  var now=Date.now();
  /* A repeated cue (a flapping connection re-toasting every 5s, or a fast
     double-click) would stack into a buzz. 350 ms per family is enough for
     the cues to be distinct and short enough to feel instant. */
  var last=SOUND.last[name]||0;
  if(now-last<350)return;
  SOUND.last[name]=now;
  try{
    var el=SOUND.els[name];
    if(!el){
      el=new Audio('/sfx/'+name);
      el.preload='auto';
      SOUND.els[name]=el;
    }
    el.currentTime=0;
    var pr=el.play();
    if(pr&&pr.catch)pr.catch(function(){/* gesture/policy: ignore */});
  }catch(e){/* a cue is decoration, never the signal */}
}
function paintSoundBtn(){
  var b=document.getElementById('soundBtn');
  if(!b)return;
  var on=!!SOUND.enabled;
  b.className='iconbtn '+(on?'on':'off');
  b.setAttribute('aria-pressed',String(on));
  b.textContent=on?'صدای':'بی‌صدا';
  b.title=on?'صدای رویدادها روشن است (کلیک: خاموش)':'صدای رویدادها خاموش است (کلیک: روشن)';
}
function toggleSound(){
  api('/crm-settings',{sound_enabled:!SOUND.enabled})
    .then(function(r){
      SOUND.enabled=r.settings.sound_enabled!==false;
      paintSoundBtn();
      toast(SOUND.enabled?'صدای رویدادها روشن شد.':'صدای رویدادها خاموش شد.');
    })
    .catch(function(e){toast(e,false);});
}
/* No 'payment_done' entry (v1.5 B8): completion is never gate-free -- the
   continue button at payment_done is the only path that can land on 'done'. */
var STAGE_SKIP_NEXT = {
  'new':'inquiry','inquiry':'ready_owner','ready_owner':'handed','handed':'to_payment',
  'to_payment':'payment','payment':'payment_done','problem':'inquiry'
};
var EST_FA = {'pending':'در انتظار','running':'در حال استعلام','healthy':'سالم',
  'advanced':'ثبت‌شده در گمرک','problem':'دارای اشکال','error':'بدون پاسخ','':'—'};
var EST_PILL = {'pending':'n','running':'warn','healthy':'ok','advanced':'ok','problem':'bad','error':'bad','':'n'};
var HAMTA_FA_CARD = {'pending':'در انتظار','running':'در حال استعلام','good':'مجاز (قابل ثبت)',
  'registered':'ثبت‌شده (قانونی)','blocked':'مسدود/خطر','success':'موفق','unknown':'نامشخص','error':'خطای ربات','':'—'};
var HAMTA_PILL = {'pending':'n','running':'warn','good':'ok','registered':'ok','success':'ok',
  'blocked':'bad','unknown':'warn','error':'bad','':'n'};
var TABS = [
  ['devices','دستگاه‌ها'],['periods','دوره‌ها'],['customers','مشتریان'],['owners','اطلاعات مسافر'],
  ['owner_archive','بایگانی مسافر‌ها'],
  ['identities','استخر هویت'],['periodic','استعلام دوره‌ای گمرک'],['ledger','تراکنش‌ها'],['reports','گزارش‌ها'],
  ['done_tab','تکمیل شده‌ها'],['problem_tab','دارای اشکال'],['closed_tab','مختومه‌ها'],
  ['settings','تنظیمات'],['cloud','سرور ابری']
];
/* v1.4.0 per-tab search/filter state (session memory only — never sent to
   the server): TAB_Q keeps the query per tab, TAB_STAGE_FILTER is the
   devices stage filter, TAB_PERIOD_FILTER is the period filter every case
   list shares (v1.10), TAB_COUNT is the filtered row count the body
   renderers report back for the result pill. */
var TAB_Q={};
var TAB_STAGE_FILTER='all';
var TAB_PERIOD_FILTER='all';
var TAB_COUNT=0;
/* List tabs that get the search toolbar (settings/reports have no list). */
var TAB_SEARCH={
  devices:{ph:'جستجو در پرونده‌ها…',unit:'پرونده'},
  customers:{ph:'جستجو در مشتری‌ها…',unit:'مشتری'},
  owners:{ph:'جستجو در مسافر‌ها…',unit:'مسافر'},
  owner_archive:{ph:'جستجو در بایگانی مسافر‌ها…',unit:'مسافر'},
  identities:{ph:'جستجو در استخر هویت…',unit:'مشخصات'},
  periodic:{ph:'جستجو در استعلام دوره‌ای…',unit:'دستگاه'},
  ledger:{ph:'جستجو در تراکنش‌ها…',unit:'تراکنش'},
  done_tab:{ph:'جستجو در تکمیل شده‌ها…',unit:'پرونده'},
  problem_tab:{ph:'جستجو در دارای اشکال…',unit:'پرونده'},
  closed_tab:{ph:'جستجو در مختومه‌ها…',unit:'پرونده'}
};

/* Jalali display helpers (v1.4.2): stored timestamps stay ISO Gregorian;
   conversion happens only at render time. faDate for plain dates,
   faDateTime when the clock matters (logs, last change, last inquiry).
   Empty or unparsable values render as «—». */
function faDate(iso){
  var d=new Date(String(iso||'').replace(' ','T'));
  if(isNaN(d))return String(iso||'—');
  try{return d.toLocaleDateString('fa-IR-u-ca-persian',{day:'numeric',month:'long',year:'numeric'});}catch(e){return String(iso||'—');}
}
function faDateTime(iso){
  var d=new Date(String(iso||'').replace(' ','T'));
  if(isNaN(d))return String(iso||'—');
  try{return d.toLocaleDateString('fa-IR-u-ca-persian',{day:'numeric',month:'long',year:'numeric'})+'، '+d.toLocaleTimeString('fa-IR',{hour:'2-digit',minute:'2-digit'});}catch(e){return String(iso||'—');}
}

/* ================= plumbing ================= */
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function money(n){n=Number(n||0);return n.toLocaleString('fa-IR')+' تومان';}
function fa(n){return Number(n||0).toLocaleString('fa-IR');}
async function api(path,payload){
  var opt = payload ? {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)} : {};
  var res = await fetch(path,opt);
  var body = null; try{ body = await res.json(); }catch(e){}
  if(!res.ok){ throw ((body&&body.errors)||['خطای '+res.status]).join('\n'); }
  return body;
}
function toast(msg, ok){
  /* v1.9: the toast IS the action's settle signal (success/warn/fail all
     funnel through here), so the cue belongs here too. The 5s background
     refresh also toasts on a connection loss — rate limiting below keeps a
     flapping connection from beeping once a second. */
  sfx(ok===false?'ui-error':(ok==='warn'?'ui-warn':'ui-ok'));
  ibtnClearBusy();
  var el=document.createElement('div');
  el.className='toast'+(ok==='warn'?' warn':(ok===false?' bad':''));
  el.textContent=msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(()=>el.remove(), 3800);
}
/* v1.3.1: contextual toast — every entity action names its row so the
   operator always knows WHICH case/customer/passenger the message is about. */
function toastCtx(name, msg, ok){
  toast(name?('«'+name+'» '+msg):msg, ok);
}
/* v1.3.1: the case-detail modal keeps itself in sync. CASE_MODAL.id is the
   case whose detail SHOULD be showing; .live means the dialog currently on
   screen IS that detail (any other openDlg clears .live, so attach/edit/
   confirm dialogs are never overwritten by the sync loop). refresh() calls
   dlgCaseSync() which re-renders when the case's signature changes and
   closes the modal if the case was deleted. */
var CASE_MODAL={id:'',sig:'',live:false,origin:''};
var CLOUD_PRESENCE={entity:'',id:'',leaseId:'',timer:null,peers:[]};
function presencePaint(peers){
  CLOUD_PRESENCE.peers=Array.isArray(peers)?peers:[];
  var el=document.getElementById('case-presence');
  if(!el)return;
  if(!CLOUD_PRESENCE.peers.length){el.hidden=true;el.innerHTML='';return;}
  var names=CLOUD_PRESENCE.peers.slice(0,3).map(function(p){
    return esc(p.display_name||'همکار دیگر');
  }).join('، ');
  var extra=CLOUD_PRESENCE.peers.length>3?' و '+fa(CLOUD_PRESENCE.peers.length-3)+' نفر دیگر':'';
  el.hidden=false;
  el.innerHTML=ICONS.info+'<div><b>'+names+extra+' هم‌زمان این پرونده را باز کرده‌اند.</b>'
    +'<div class="cloud-banner-p">این فقط هشدار حضور است؛ ویرایش قفل نمی‌شود. اگر دو نفر هم‌زمان ذخیره کنند، کنترل نسخه و حل تداخل سرور تعیین‌کننده است.</div></div>';
}
function presenceBeat(){
  if(!CASE_MODAL.live||CASE_MODAL.id!==CLOUD_PRESENCE.id)return;
  api('/cloud-presence',{entity:CLOUD_PRESENCE.entity,entity_id:CLOUD_PRESENCE.id,
      lease_id:CLOUD_PRESENCE.leaseId||''}).then(function(r){
    if(!CASE_MODAL.live||CASE_MODAL.id!==CLOUD_PRESENCE.id)return;
    CLOUD_PRESENCE.leaseId=String(r.lease_id||'');
    presencePaint(r.peers||[]);
  }).catch(function(){presencePaint([]);});
}
function presenceStart(entity,id){
  entity=String(entity||'');id=String(id||'');
  if(CLOUD_PRESENCE.entity!==entity||CLOUD_PRESENCE.id!==id){
    presenceStop(true);
    CLOUD_PRESENCE.entity=entity;CLOUD_PRESENCE.id=id;
  }
  presenceBeat();
  if(!CLOUD_PRESENCE.timer)
    CLOUD_PRESENCE.timer=setInterval(presenceBeat,15000);
}
function presenceStop(closeRemote){
  var lease=CLOUD_PRESENCE.leaseId;
  if(CLOUD_PRESENCE.timer){clearInterval(CLOUD_PRESENCE.timer);CLOUD_PRESENCE.timer=null;}
  CLOUD_PRESENCE.entity='';CLOUD_PRESENCE.id='';CLOUD_PRESENCE.leaseId='';CLOUD_PRESENCE.peers=[];
  if(closeRemote&&lease)
    api('/cloud-presence-close',{lease_id:lease}).catch(function(){});
}
function dlgCaseSig(d){
  var e=d.estelam||{},p=d.pay||{};
  var o=(STATE.owners||[]).find(x=>x.id===d.owner_id)||{};
  var c=(STATE.customers||[]).find(x=>x.id===d.customer_id)||{};
  return [d.stage,d.updated,d.name,d.notes,d.customer_id,c.name,d.owner_id,o.name,o.passport,o.national,
          d.profile_id,d.periodic_opt_out?1:0,
          e.status,e.hamta_status,p.run_status,p.browser_visible?1:0,
          (p.payment_link?'l':''),(STATE.identities||[]).length].join('|');
}
function dlgCaseSync(){
  if(!CASE_MODAL.live||!CASE_MODAL.id)return;
  var d=(STATE.devices||[]).find(x=>x.id===CASE_MODAL.id);
  if(!d){var nm=CASE_MODAL.name||'';closeDlg();toastCtx(nm,'حذف شد — پنجرهٔ جزئیات بسته شد');return;}
  var sig=dlgCaseSig(d);
  if(sig!==CASE_MODAL.sig){caseDetail(CASE_MODAL.id,true);}
}
/* Restore the case detail after a child dialog (attach/edit) or a confirm
   flow replaced it — used by the action callbacks that know the case id. */
function dlgCaseRestore(id){
  if(CASE_MODAL.id===id&&!CASE_MODAL.live)caseDetail(id);
}
function openDlg(html, silent){
  /* v1.3.5: any dialog opened over a LIVE case modal arms the return —
     dismissing it (انصراف, ×, Esc) comes back to that case. Action
     confirms disarm via confirmYes; success callbacks restore (or close)
     themselves. Replacing content re-arms, so a stale return cannot
     survive an in-flight callback. v1.8.1: the live period dialog arms the
     same return, tagged «per:» so closeDlg knows which dialog to rebuild —
     a case opened from the period view now has a way back. */
  DLG_BACK=CASE_MODAL.live?CASE_MODAL.id:(PER.live?'per:'+PER.pid:'');
  CASE_MODAL.live=false;
  PER.live=false;
  document.getElementById('dlgBody').innerHTML=html;
  var dlg=document.getElementById('dlg');dlg.showModal();
  /* The modal dialog renders in the browser top layer, above every
     z-index — a toast left in the body shows dimmed underneath it. Pull
     the toast container inside the dialog while it is open; closeDlg
     moves it back. Fixed positioning is unaffected (the dialog has no
     transform/filter). */
  dlg.appendChild(document.getElementById('toasts'));
  /* v1.9: a dialog opening is a boundary the operator crossed deliberately,
     so it gets the softest cue of the set. confirmDlg() also lands here, so
     a destructive confirm does not need a separate sound. `silent` is for
     the 5s rebuild path: dlgCaseSync/dlgPeriodSync replace an already-open
     modal from the background refresh, and that is not a boundary anyone
     crossed — without it, an open modal would chirp every time the server
     state moved. */
  if(!silent)sfx('ui-open');
}
function closeDlg(){
  /* v1.3.5: everything a close needs happens HERE, synchronously — the
     dialog 'close' event only arrives asynchronously in Chromium (often
     long after the close), so it is a safety net, not the driver. This
     also consumes DLG_BACK so dismissed child dialogs return to their
     case or period — unless the dialog being closed IS that own modal. */
  ibtnClearBusy();
  var closingLiveCase=CASE_MODAL.live;
  var back=DLG_BACK;DLG_BACK='';
  if(closingLiveCase)presenceStop(true);
  var self=(CASE_MODAL.live&&CASE_MODAL.id===back)
        ||(PER.live&&('per:'+PER.pid)===back);
  /* v1.8.1: a case modal is about to be restored, so its origin has to survive
     the gap — anywhere else the case session is over and the origin is spent
     (a stale one would make the NEXT case reopen the wrong dialog). */
  var keepOrigin=Boolean(back)&&back.indexOf('per:')!==0&&!self;
  document.getElementById('dlg').close();
  CASE_MODAL.id='';CASE_MODAL.sig='';CASE_MODAL.live=false;
  if(!keepOrigin)CASE_MODAL.origin='';
  PER.live=false;
  document.body.appendChild(document.getElementById('toasts'));
  if(back&&!self){
    if(back.indexOf('per:')===0)dlgPeriod(back.slice(4));else caseDetail(back);
  }
}
/* Esc path: the native cancel never passes through closeDlg — take the
   close over and run the same synchronous bookkeeping. */
document.getElementById('dlg').addEventListener('cancel',function(e){
  e.preventDefault();
  closeDlg();
});
/* Safety net only, for any close that did not go through closeDlg (the
   event can also arrive stale after a reopen — then a newer dialog is
   already open and must be left alone). */
document.getElementById('dlg').addEventListener('close',function(){
  if(this.open)return;
  if(CASE_MODAL.live)presenceStop(true);
  CASE_MODAL.id='';CASE_MODAL.sig='';CASE_MODAL.live=false;CASE_MODAL.origin='';
  PER.live=false;
  document.body.appendChild(document.getElementById('toasts'));
});
/* Confirm dialog (native confirm() is blocking & unstyled): a small dialog
   reusing #dlg with a confirm/cancel pair — used by stage rollback. */
var _confirmCb=null;
function confirmDlg(title,text,okLabel,cb){
  _confirmCb=cb;
  openDlg('<h3>'+esc(title)+'</h3><p style="margin:0 0 14px;color:var(--muted);font-size:13.5px;line-height:1.9">'
    +esc(text)+'</p>'
    +'<div class="row" style="margin-top:10px"><button class="btn danger" onclick="confirmYes()">'+esc(okLabel||'تأیید')+'</button>'
    +'<button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function confirmYes(){var cb=_confirmCb;_confirmCb=null;DLG_BACK='';closeDlg();if(cb)cb();}
var urlTheme=new URLSearchParams(location.search).get('theme');
var savedTheme=urlTheme||localStorage.getItem('irica-theme')||'light';
document.documentElement.setAttribute('data-theme',savedTheme);
var savedFs=Number(localStorage.getItem('irica-crm-fs')||'0');
if(savedFs)document.documentElement.style.setProperty('--crm-fs',(13.5+savedFs*1.5)+'px');
document.getElementById('themeBtn').onclick=function(){
  var dark=document.documentElement.getAttribute('data-theme')==='dark';
  var next=dark?'light':'dark';
  document.documentElement.setAttribute('data-theme',next);
  localStorage.setItem('irica-theme',next);
};
/* v1.9: the header mirror of the settings checkbox. One click toggles and
   saves; no confirm needed, and the cue for the toggle itself is the only
   proof the speaker is alive. */
document.getElementById('soundBtn').onclick=function(){
  toggleSound();
  if(SOUND.enabled)sfx('ui-ok');   /* the button's own announcement */
};
document.getElementById('logoutBtn').onclick=function(){
  fetch('/logout',{method:'POST'}).then(function(){
    window.location.replace('/login');
  }).catch(function(){ toast('خروج ناموفق بود',false); });
};
/* ================= v1.4.1 page width =================
   Operator-controlled page width: presets + a fine slider, persisted in
   localStorage, clamped to [900,1920] and always capped by 98vw in CSS
   so it can never overflow. The control lives in the header (outside
   #view), so the 5-second refresh never touches it. */
var CRMW={key:'irica-crm-w',min:900,max:1920,def:1240,cur:1240};
function crmWApply(v){
  v=Math.max(CRMW.min,Math.min(CRMW.max,Math.round(Number(v)||CRMW.def)));
  CRMW.cur=v;
  document.documentElement.style.setProperty('--crm-w',v+'px');
  return v;
}
function crmWSet(v){
  v=crmWApply(v);
  try{localStorage.setItem(CRMW.key,String(v));}catch(e){}
  crmWSync();
  return v;
}
function crmWSync(){
  var r=document.getElementById('wRange');
  if(r)r.value=String(CRMW.cur);
  var lbl=document.getElementById('wVal');
  if(lbl)lbl.textContent=fa(CRMW.cur)+'px';
  var btns=document.querySelectorAll('.wpreset');
  for(var i=0;i<btns.length;i++){
    btns[i].classList.toggle('primary',Number(btns[i].getAttribute('data-w'))===CRMW.cur);
    btns[i].classList.toggle('ghost',Number(btns[i].getAttribute('data-w'))!==CRMW.cur);
  }
}
(function(){
  var stored=Number(localStorage.getItem(CRMW.key)||'0');
  crmWApply(stored||CRMW.def);
  crmWSync();
  var pop=document.getElementById('wPop');
  var btn=document.getElementById('widthBtn');
  btn.onclick=function(e){
    e.stopPropagation();
    var open=pop.classList.toggle('open');
    btn.setAttribute('aria-expanded',open?'true':'false');
  };
  pop.onclick=function(e){e.stopPropagation();};
  document.addEventListener('click',function(){
    if(pop.classList.contains('open')){pop.classList.remove('open');btn.setAttribute('aria-expanded','false');}
  });
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape'&&pop.classList.contains('open')&&!document.getElementById('dlg').open){
      pop.classList.remove('open');btn.setAttribute('aria-expanded','false');
    }
  });
  var presets=document.querySelectorAll('.wpreset');
  for(var i=0;i<presets.length;i++){
    presets[i].onclick=function(){crmWSet(this.getAttribute('data-w'));};
  }
  var range=document.getElementById('wRange');
  range.addEventListener('input',function(){crmWApply(this.value);crmWSync();});
  range.addEventListener('change',function(){crmWSet(this.value);});
  document.getElementById('wReset').onclick=function(){crmWSet(CRMW.def);};
})();

/* ================= lookups ================= */
function findCustomer(id){return (STATE&&STATE.customers||[]).find(c=>c.id===id)||null;}
function findOwner(id){return (STATE&&STATE.owners||[]).find(o=>o.id===id)||null;}
function custName(id){var c=findCustomer(id);return c?c.full_name:'—';}
function ownerName(id){var o=findOwner(id);return o?(o.first_name+' '+o.last_name):'—';}
/* v1.6: voided transactions and their 'void' reversal rows never count
   toward any balance — the same skip predicate the server applies to its
   aggregates; every balance surface (table pills, KPIs, debtor rail) flows
   through here, so one predicate covers all of them. */
function bal(id){var c=findCustomer(id);if(!c)return 0;return (c.transactions||[]).reduce((s,t)=>(t.voided_at||t.kind==='void'||!/^\d{4}-\d{2}-\d{2}/.test(String(t.at||'')))?s:s+Number(t.amount||0),0);}
function v(id){return document.getElementById(id).value.trim();}

/* ================= stage actions (server contract) ================= */
/* ================= inline SVG icons (no emoji per ux-guidelines) ================= */
var ICONS = {
  user:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5"/></svg>',
  warn:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l10 17H2L12 3z"/><path d="M12 9v5"/><path d="M12 17.4v.2"/></svg>',
  id:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="2" y="5" width="20" height="14" rx="2.5"/><circle cx="8.5" cy="11" r="2"/><path d="M5.5 16c.6-1.6 1.7-2.3 3-2.3s2.4.7 3 2.3M14.5 9.5H19M14.5 13H19"/></svg>',
  dev:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M10.5 18.5h3"/></svg>',
  search:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/></svg>',
  swap:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M7 16V4m0 0L3.5 7.5M7 4l3.5 3.5M17 8v12m0 0 3.5-3.5M17 20l-3.5-3.5"/></svg>',
  stop:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="1.5"/></svg>',
  info:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11.2 12h.8v4h.8"/><path d="M11.2 12h1.6v4h1"/></svg>',
  /* v1.3.5 button icons — one stroke language for every action button
     (replaces the old emoji links in the payment row). */
  link:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M10 14a5 5 0 0 0 7.1.4l2.1-2.1a5 5 0 0 0-7.1-7.1l-1.2 1.2"/><path d="M14 10a5 5 0 0 0-7.1-.4l-2.1 2.1a5 5 0 0 0 7.1 7.1l1.2-1.2"/></svg>',
  receipt:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 3h14v18l-2.3-1.6-2.3 1.6-2.4-1.6-2.3 1.6L5 21V3z"/><path d="M9 8h6M9 12h6M9 16h4"/></svg>',
  card:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="2" y="5" width="20" height="14" rx="2.5"/><path d="M2 10h20"/></svg>',
  eye:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeOff:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7c1.8 0 3.4.5 4.7 1.3M22 12s-3.6 7-10 7c-1.8 0-3.4-.5-4.7-1.3"/><path d="m3 3 18 18"/></svg>',
  send:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/></svg>',
  alert:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2 20h20L12 3z"/><path d="M12 10v4"/><path d="M12 17.2h.01"/></svg>',
  userplus:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3.6-6.5 8-6.5"/><path d="M19 8v6M16 11h6"/></svg>',
  wallet:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12V7H5a2 2 0 0 1 0-4h14v4"/><path d="M3 5v14a2 2 0 0 0 2 2h16v-5"/><path d="M18 12a2 2 0 0 0 0 4h4v-4Z"/></svg>',
  /* v1.5 finance dialog: the library chevron-down reused for the RTL
     period-nav pair and the collapsible section — chev-r/chev-l only add
     the CSS rotation (previous points right, next left; same direction
     language as arrow-back), the path stays byte-identical. */
  chev:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>',
  chevR:'<svg class="ic chev-r" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>',
  chevL:'<svg class="ic chev-l" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>',
  /* empty-state tiles (irica-icons language, 24-grid / stroke 2): the inbox
     tray marks a genuinely empty list, search-x an active search/filter with
     no hit; CSS scales them up inside the .eic tile */
  inbox:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>',
  searchx:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.8-3.8"/><path d="M8.5 8.5l5 5M13.5 8.5l-5 5"/></svg>',
  /* v1.6 accounting round: printable document (page + text lines) for the
     invoice action — same 24-grid stroke-2 rounded language as the rest. */
  doc:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h4"/></svg>',
  plus:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>',
  edit:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11.5 20H20"/><path d="M17 4.4a1.8 1.8 0 0 1 2.55 2.55L7.55 18.95 3.8 20.1l1.2-3.7z"/><path d="M14.6 6.8 17.2 9.4"/></svg>',
  trash:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3.5 6.5h17"/><path d="M9 6.5V4h6v2.5"/><path d="M18.5 6.5 17.7 20a1.8 1.8 0 0 1-1.8 1.7H8.1A1.8 1.8 0 0 1 6.3 20L5.5 6.5"/><path d="M10 11v6M14 11v6"/></svg>',
  unlink:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.6 5.4l1.8-1.8a4 4 0 0 1 5.6 5.6l-1.8 1.8"/><path d="M9.4 18.6l-1.8 1.8a4 4 0 0 1-5.6-5.6l1.8-1.8"/><path d="M7.4 7.4 5.2 5.2M16.6 16.6l2.2 2.2"/></svg>',
  undo:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>',
  rotate:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>',
  refresh:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/></svg>',
  ban:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M5.99 5.99l12.02 12.02"/></svg>',
  play:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.5 4.8v14.4L19.5 12z"/></svg>',
  lock:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8.5 10.5V7.8a3.5 3.5 0 0 1 7 0v2.7"/></svg>',
  list:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6.5h16M4 12h16M4 17.5h10"/></svg>',
  users:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="9.5" cy="7.5" r="3.5"/><path d="M15.5 20.5c0-3.4-2.6-5.5-6-5.5s-6 2.1-6 5.5"/><path d="M16.5 4.5a3.5 3.5 0 0 1 0 6.4"/><path d="M18.5 20.5c0-2.4-.9-4.1-2.4-5.2"/></svg>',
  check:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="m8.2 12.4 2.6 2.6 5-5.4"/></svg>',
  clock:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 6.8V12l3.8 2.4"/></svg>',
  globe:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.7 2.6 4 5.7 4 9s-1.3 6.4-4 9c-2.7-2.6-4-5.7-4-9s1.3-6.4 4-9z"/></svg>',
  fileText:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="3.5" width="15" height="17" rx="2"/><path d="M8.5 8.5h7M8.5 12.5h7M8.5 16.5h4"/></svg>',
  download:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.5v11M7.5 10 12 14.5 16.5 10"/><path d="M4.5 16.5v2a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-2"/></svg>',
  camera:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>',
  x:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6 18 18M18 6 6 18"/></svg>',
  money:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2.5" y="6" width="19" height="12" rx="2"/><circle cx="12" cy="12" r="2.6"/><path d="M6.5 12h.01M17.5 12h.01"/></svg>',
  rewind:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7.5V12l3.5 2"/></svg>',
  printer:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6.5 9.5V3.5h11v6"/><path d="M6.5 18H5a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-1.5"/><path d="M6.5 14.5h11v6h-11z"/></svg>',
  ticket:'<svg class="ic" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 9.5V7a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v2.5a2.5 2.5 0 0 0 0 5V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-2.5a2.5 2.5 0 0 0 0-5z"/><path d="M14.5 5v14"/></svg>',
};
/* ===== v1.8 shared tooltip layer =====
   One layer, delegated listeners, fixed positioning: a short hover dwell (so
   sweeping a row of buttons does not flash labels), a small hide tolerance,
   and an immediate show on keyboard focus. The chip is flipped below its
   trigger when there is no room above, then clamped to the viewport. Any
   scroll, resize, press, blur or Escape dismisses it. `data-tip` is the
   trigger; the accessible name always lives in `aria-label` on the control,
   so nothing here is hover-only. */
var TIP=(function(){
  var el=null,t=null,showTimer=0,hideTimer=0;
  function layer(){
    if(!el){
      el=document.createElement('div');
      el.id='tip';
      el.setAttribute('role','tooltip');
      el.hidden=true;
      document.body.appendChild(el);
    }
    return el;
  }
  function place(){
    if(!t||!t.isConnected)return hide();
    var r=t.getBoundingClientRect(),b=el.getBoundingClientRect();
    var vw=document.documentElement.clientWidth;
    var top=r.top-b.height-10;
    if(top<8)top=r.bottom+10;
    var left=r.left+r.width/2-b.width/2;
    var max=Math.max(8,vw-b.width-8);
    el.style.top=Math.max(8,Math.round(top))+'px';
    el.style.left=Math.min(Math.max(8,Math.round(left)),max)+'px';
  }
  function show(trig){
    clearTimeout(showTimer);clearTimeout(hideTimer);
    /* jumping straight from one trigger to the next must not leave the first
       one pointing at the chip with aria-describedby */
    if(t&&t!==trig)t.removeAttribute('aria-describedby');
    t=trig;
    layer();
    el.textContent=trig.getAttribute('data-tip');
    /* an open dialog paints above every z-index on the page, so the chip has
       to live inside it while it is up */
    (trig.closest('dialog[open]')||document.body).appendChild(el);
    el.hidden=false;
    place();
    trig.setAttribute('aria-describedby','tip');
  }
  function hide(){
    clearTimeout(showTimer);clearTimeout(hideTimer);
    if(t)t.removeAttribute('aria-describedby');
    t=null;
    if(el){el.hidden=true;el.textContent='';}
  }
  /* Named tip* handlers: the dismissal paths are part of the layer's
     surface, so they read as such (and stay greppable) instead of hiding
     inside anonymous callbacks. */
  function tipFocusIn(e){
    var n=e.target&&e.target.closest?e.target.closest('[data-tip]'):null;
    if(n&&n.matches&&n.matches(':focus-visible'))show(n);
  }
  function tipDismiss(){hide();}
  /* Leaving a trigger (or the window) must take the chip down: pointerover
     alone only notices the NEXT element under the pointer. */
  function tipPointerOut(e){
    var to=e.relatedTarget;
    if(to&&to.closest&&to.closest('[data-tip]'))return;
    clearTimeout(showTimer);
    hideTimer=setTimeout(hide,90);
  }
  document.addEventListener('pointerover',function(e){
    var n=e.target&&e.target.closest?e.target.closest('[data-tip]'):null;
    if(n===t)return;
    if(!n){clearTimeout(showTimer);hideTimer=setTimeout(hide,90);return;}
    clearTimeout(hideTimer);
    clearTimeout(showTimer);
    var d=n.getAttribute('data-tip-delay')==='0'?0:220;
    showTimer=setTimeout(function(){show(n);},d);
  });
  document.addEventListener('pointerout',tipPointerOut,true);
  document.addEventListener('pointerdown',tipDismiss,true);
  document.addEventListener('click',tipDismiss,true);
  document.addEventListener('focusin',tipFocusIn);
  document.addEventListener('focusout',tipDismiss,true);
  document.addEventListener('scroll',tipDismiss,true);
  window.addEventListener('resize',tipDismiss);
  /* Escape only takes the chip down; it never swallows the key, so a dialog's
     own Escape-to-close still works on the same press. */
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape')hide();
  });
  return {show:show,hide:hide};
})();
function tipShow(el){TIP.show(el);}
function tipHide(){TIP.hide();}
/* An icon-only button has no label to grey out, so an action in flight shows a
   spinner instead. Every settled action on this page ends in a toast, which is
   therefore the signal that clears the busy buttons; the timeout is the net for
   the few paths that never toast. Buttons that only open something carry
   data-static="1" and never flip.
   v1.8.1: the busy state is kept per ACTION, not per element. The 5s list
   re-render replaces every button node, and the spinner used to be destroyed
   with the old node — leaving an in-flight action looking idle. ibtnRepaintBusy
   re-marks the freshly rendered nodes, so the spinner means "still running". */
var _busyKeys={},_busyTimer=0;
/* Action identity, stable across re-renders: the same generated button carries
   the same accessible name and the same handler. Two buttons sharing both are
   the same action on the same entity and light up together — which is the
   truth (no false "this one is idle"). */
function ibtnKey(el){
  return (el.getAttribute('aria-label')||'')+'|'+String(el.getAttribute('onclick')||'');
}
function ibtnRepaintBusy(){
  [].forEach.call(document.querySelectorAll('.ibtn'),function(el){
    /* an open-only button never flips, so it can never inherit a key either */
    if(el.getAttribute('data-static')==='1')return;
    var on=Boolean(_busyKeys[ibtnKey(el)]);
    el.classList.toggle('busy',on);
    if(on)el.setAttribute('aria-busy','true');else el.removeAttribute('aria-busy');
  });
}
function ibtnClearBusy(){
  clearTimeout(_busyTimer);
  _busyKeys={};
  ibtnRepaintBusy();
}
document.addEventListener('click',function(e){
  var el=e.target&&e.target.closest?e.target.closest('.ibtn'):null;
  if(!el||el.disabled||el.getAttribute('data-static')==='1')return;
  var key=ibtnKey(el);
  if(_busyKeys[key])return;
  _busyKeys[key]=true;
  clearTimeout(_busyTimer);
  /* A press indicator, not a progress bar: the toast that ends the action
     clears it and this net only covers a handler that never toasts. Long robot
     runs show their state in the «ربات استعلام در حال اجراست» banner, not
     here. */
  _busyTimer=setTimeout(ibtnClearBusy,6000);
  ibtnRepaintBusy();
});
/* v1.3.1 round 3 (operator request): the manual inquiry / telegram re-send
   / periodic-toggle tools are step-scoped inside caseDetail (steps 2/4/5)
   instead of the old broad intake/handoff stage lists — see the toolsHtml
   block there. */
var STAGE_CONTINUE_FA = {
  'new':'شروع استعلام ثبت‌نبودن','inquiry':'ادامه ← اتصال مسافر','ready_owner':'تحویل به مسئول ثبت',
  'handed':'ادامه ← انتظار پرداخت','to_payment':'شروع ربات پرداخت','payment':'تأیید پرداخت',
  'payment_done':'تحویل کد و تکمیل'};
var STAGE_READY = {
  'new':true,
  'inquiry':d=>((d.estelam||{}).status==='healthy')&&['good','registered','success'].includes((d.estelam||{}).hamta_status),
  'problem':false,
  'ready_owner':d=>Boolean(d.owner_id),
  'handed':d=>((d.estelam||{}).status==='advanced')||Boolean(d.auto_advance),
  'to_payment':true,
  'payment':true,
  'payment_done':true,
  'done':false};
var STAGE_NEEDS = {
  'inquiry':()=>['ثبت‌نبودن در گمرک','ثبت‌نبودن در همتا'],
  'ready_owner':()=>['مسافر',''],
  'handed':()=>['ثبت‌بودن در گمرک','']};
var STAGE_SKIP_WARN = {
  'new':'مرحلهٔ ثبت پرونده نادیده گرفته می‌شود؛ استعلام ثبت‌نبودن همچنان برای این دستگاه لازم است.',
  'inquiry':'نتایج استعلام ثبت‌نبودن نادیده گرفته می‌شوند و پرونده مستقیم «خام» فرض می‌شود.',
  'ready_owner':'نیاز به مسافر نادیده گرفته می‌شود؛ مشخصات مسافر برای ثبت پرونده و تحویل لازم است، نه برای هویت استعلام.',
  'handed':'استعلام ثبت‌بودن دستگاه در گمرک نادیده گرفته می‌شود و پرونده مستقیم به گام پرداخت می‌رود.',
  'to_payment':'ربات پرداخت خودکار اجرا نمی‌شود؛ لینک پرداخت گرفته نمی‌شود.',
  'payment':'تأیید پرداخت بدون بررسی انجام می‌شود و مبلغ پرداختی در دفتر ثبت نمی‌شود.',
  'problem':'پرونده بدون تکرار استعلام به گام استعلام برمی‌گردد.'};
function stageReady(d){
  var fn=STAGE_READY[d.stage];
  return fn===true?true:(typeof fn==='function'?Boolean(fn(d)):false);
}
function stageContinue(d){
  var label=STAGE_CONTINUE_FA[d.stage];
  if(!label)return null;
  var ready=stageReady(d);
  return {action:d.stage==='new'?'queue_inquiry':
             d.stage==='inquiry'?'mark_ready':
             d.stage==='ready_owner'?'handover':
             d.stage==='handed'?'to_payment':
             d.stage==='to_payment'?(d.auto_advance?'__noop':'__start_payment'):
             d.stage==='payment'?'confirm_payment':'deliver_code',
          label:label, ready:ready,
          need:(STAGE_NEEDS[d.stage]||function(){return[];})().join(' + ')};
}
/* v1.5.x: step tools only — the continue button moved to the caseDetail
   «قدم بعدی» card (auto-advance «خودکار» display included) and skip/back to
   its «سایر اقدامات» quiet row; attach stays here and now renders primary
   (same class as the old passenger-block button). v1.3.1 round 3: problem's
   «بازگشت به صف» also moved to the «قدم بعدی» card. */
function stageActions(d){
  var a=[];
  var st=d.stage;
  if(st==='inquiry') a.push(['mark_problem','ثبت اشکال','danger','alert']);
  if(st==='ready_owner') a.push(['__attach','اتصال مسافر','primary','userplus']);
  return a;
}
var STAGE_BACK_FA = {
  'inquiry':'ثبت پرونده','ready_owner':'استعلام ثبت‌نبودن','handed':'اتصال مسافر',
  'to_payment':'تحویل به مسئول ثبت','payment':'استعلام ثبت‌بودن — پرداخت',
  'payment_done':'در حال پرداخت'
};
function devTick(id, action){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  if(action==='__attach'){dlgAttach(id);return;}
  if(action==='__skip'){
    var d=nm;
    var next=STAGE_SKIP_NEXT[d?d.stage:'']||'';
    if(!next){toast('رد کردن مرحله در این وضعیت ممکن نیست',false);return;}
    var msg=STAGE_SKIP_WARN[d.stage]||'';
    msg+=' پرونده مستقیم به «'+(STAGE_FA[next]||next)+'» می‌رود و این ردشدن در پرونده ثبت می‌شود. مطمئنی؟';
    confirmDlg('رد کردن این مرحله',msg,'رد کردن مرحله',function(){
        api('/crm-tick',{device_id:id,action:'stage_skip'}).then(async r=>{
          toastCtx(cn,'به «'+(STAGE_FA[r.device.stage]||r.device.stage)+'» رفت (مرحله رد شد)');await refresh();caseDetail(id);})
          .catch(e=>{toastCtx(cn,String(e),false);caseDetail(id);});
      });
    return;
  }
  if(action==='__stage_back'){
    api('/crm-state').then(function(state){
      var d=(state.devices||[]).find(x=>x.id===id);
      if(!d){toast('پرونده پیدا نشد',false);return;}
      var target=STAGE_BACK_FA[d.stage]||'مرحلهٔ قبل';
      confirmDlg('برگشت به مرحلهٔ قبل','مطمئنی می‌خوای به گام «'+target+'» برگردی؟',
        'برگشت',function(){
          api('/crm-tick',{device_id:id,action:'stage_back'}).then(async r=>{
            toastCtx(cn,'به «'+(STAGE_FA[r.device.stage]||r.device.stage)+'» برگشت');await refresh();caseDetail(id);})
            .catch(e=>{toastCtx(cn,String(e),false);caseDetail(id);});
        });
    }).catch(e=>toastCtx(cn,String(e),false));
    return;
  }
  if(action==='__start_payment'){
    api('/crm-start-payment',{device_id:id}).then(async r=>{toastCtx(cn, r.ok?'ربات پرداخت شروع شد':'شروع ربات پرداخت انجام نشد', r.ok);await refresh();dlgCaseRestore(id);})
      .catch(e=>toastCtx(cn,String(e),false));
    return;
  }
  if(action==='__close_case'){closeCaseDialog(id);return;}
  if(action==='__noop'){return;}
  api('/crm-tick',{device_id:id,action:action}).then(async r=>{
      toastCtx(cn, action==='requeue_inquiry'
        ? 'به «'+(STAGE_FA[r.device.stage]||r.device.stage)+'» برگشت'
        : 'گام '+(STAGE_FA[r.device.stage]||r.device.stage));
      if(r.handoff_notice){toast(r.handoff_notice,false);}
      await refresh();dlgCaseRestore(id);})
    .catch(e=>toastCtx(cn,String(e),false));
}
/* ================= completed / problem / closed tabs (v1.1.5) ================= */
function devRow(d, extra){
  var st=d.stage;
  var cust=esc(custName(d.customer_id));
  var row='<div class="card" id="devrow-'+d.id+'" style="margin-bottom:8px"><div class="row" style="margin-bottom:6px;flex-wrap:wrap;gap:6px">'
    +'<b>'+esc(d.name)+'</b>'
    +'<span class="pill '+(STAGE_TONE[st]||'n')+'">'+(STAGE_FA[st]||esc(st))+'</span>'
    +'<span class="chip">'+ICONS.dev+esc(d.serial1)+(d.serial2?' / '+esc(d.serial2):'')+'</span>'
    +(cust?'<span class="chip">'+ICONS.user+cust+'</span>':'')
    +'<span class="kbd">ایجاد: '+esc(faDate(d.created))+' · آخرین تغییر: '+esc(faDateTime(d.updated))+'</span>'
    +(extra||'')+'</div>';
  if(extra===undefined||extra==='')row+='';
  return row+'</div>';
}
function doneTabHtml(){
  var ds=(STATE.devices||[]).filter(d=>d.stage==='done')
    .sort((a,b)=>String(b.updated||'').localeCompare(String(a.updated||'')));
  ds=filterDevRows(ds);
  TAB_COUNT=ds.length;
  var note='<div class="row" style="margin-bottom:10px"><span class="muted">'
    +'پرونده‌های تکمیل‌شده — از جریان اصلی خارج شده‌اند؛ در صورت نیاز مشخصات را ویرایش کنید یا با احتیاط پرونده را به مرحلهٔ قبل برگردانید.</span></div>';
  if(!ds.length){
    if(searchActive())return note+searchEmptyCard();
    return note+emptyHtml('پروندهٔ تکمیل‌شده‌ای نیست','پرونده‌ها پس از تحویل کد فعال‌سازی به این‌جا می‌آیند.');
  }
  return note+ds.map(d=>devRow(d,
    '<span class="kbd">تاریخ تکمیل: '+esc(faDate(d.done_at))+'</span>'
    +'<div class="ibacts">'
    +'<button type="button" class="ibtn" data-static="1" aria-label="مشاهده پرونده" data-tip="مشاهده پرونده" onclick="caseDetail(\''+d.id+'\')">'+ICONS.eye+'</button>'
    +'<button type="button" class="ibtn" data-static="1" aria-label="ویرایش پرونده" data-tip="ویرایش پرونده" onclick="dlgDeviceEdit(\''+d.id+'\')">'+ICONS.edit+'</button>'
    +'<button type="button" class="ibtn danger" aria-label="بازگشت به مرحلهٔ قبل" data-tip="بازگشت به مرحلهٔ قبل" onclick="doneRollback(\''+d.id+'\')">'+ICONS.undo+'</button>'
    +'</div>')).join('');
}
/* Done-tab rollback (v1.5 B3): undoing a completion is bookkeeping-sensitive,
   so it lives here with its own strong confirmation instead of riding the
   active-case __stage_back flow. STAGE_BACK_FA deliberately has no 'done'
   entry — the completed tab is the only surface offering this rollback. */
function doneRollback(id){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  confirmDlg('بازگشت به مرحلهٔ قبل',
    'پروندهٔ تکمیل‌شده به گام «پرداخت تأییدشده» برمی‌گردد و تاریخ تکمیل آن پاک می‌شود. این کار نادرست می‌تواند حساب‌ها را به‌هم بریزد؛ مطمئنی؟',
    'بازگشت به مرحلهٔ قبل',function(){
      api('/crm-tick',{device_id:id,action:'stage_back'}).then(async r=>{
        toastCtx(cn,'به «'+(STAGE_FA[r.device.stage]||r.device.stage)+'» برگشت');await refresh();})
        .catch(e=>toastCtx(cn,String(e),false));
    });
}
function problemTabHtml(){
  var ds=(STATE.devices||[]).filter(d=>d.stage==='problem')
    .sort((a,b)=>String(b.updated||'').localeCompare(String(a.updated||'')));
  ds=filterDevRows(ds);
  TAB_COUNT=ds.length;
  var note='<div class="row" style="margin-bottom:10px"><span class="muted">'
    +'پرونده‌های دارای اشکال — با «بازگشت به صف» دوباره وارد جریان می‌شوند یا مختومه می‌گردند.</span></div>';
  if(!ds.length){
    if(searchActive())return note+searchEmptyCard();
    return note+emptyHtml('پروندهٔ دارای اشکالی نیست','اگر استعلامی اشکال پیدا کند پروندهٔ آن این‌جا می‌آید.');
  }
  return note+ds.map(d=>devRow(d,
    '<div class="ibacts">'
    +'<button type="button" class="ibtn" data-static="1" aria-label="مشاهده پرونده" data-tip="مشاهده پرونده" onclick="caseDetail(\''+d.id+'\')">'+ICONS.eye+'</button>'
    +'<button type="button" class="ibtn primary" aria-label="بازگشت به صف" data-tip="بازگشت به صف" onclick="devRequeue(\''+d.id+'\')">'+ICONS.undo+'</button>'
    +'<button type="button" class="ibtn danger" aria-label="مختومه کردن پرونده" data-tip="مختومه کردن پرونده" onclick="devTick(\''+d.id+'\',\'__close_case\')">'+ICONS.ban+'</button>'
    +'</div>')).join('');
}
function closedTabHtml(){
  var ds=(STATE.devices||[]).filter(d=>d.stage==='closed')
    .sort((a,b)=>String(b.closed_at||'').localeCompare(String(a.closed_at||'')));
  ds=filterDevRows(ds,function(d){return d.closed_reason||'';});
  TAB_COUNT=ds.length;
  var note='<div class="row" style="margin-bottom:10px"><span class="muted">'
    +'پرونده‌های مختومه — بسته‌شده و غیرقابل ادامه.</span></div>';
  if(!ds.length){
    if(searchActive())return note+searchEmptyCard();
    return note+emptyHtml('پروندهٔ مختومه‌ای نیست','پرونده‌هایی که قابل ادامه نباشند پس از مختومه‌کردن این‌جا می‌آیند.');
  }
  return note+ds.map(d=>'<div class="card" id="devrow-'+d.id+'" style="margin-bottom:8px"><div class="row" style="margin-bottom:6px;flex-wrap:wrap;gap:6px">'
    +'<b>'+esc(d.name)+'</b>'
    +'<span class="pill n">'+(STAGE_FA[d.stage]||esc(d.stage))+'</span>'
    +'<span class="chip">'+ICONS.dev+esc(d.serial1)+(d.serial2?' / '+esc(d.serial2):'')+'</span>'
    +'<span class="chip">'+ICONS.user+esc(custName(d.customer_id))+'</span>'
    +'<span class="chip closedreason">دلیل: '+esc(d.closed_reason||'—')+'</span>'
    +'<span class="chip">'+esc(faDate(d.closed_at))+'</span>'
    +'<span class="kbd">ایجاد: '+esc(faDate(d.created))+' · آخرین تغییر: '+esc(faDateTime(d.updated))+'</span>'
    +'<div class="ibacts">'
    +'<button type="button" class="ibtn" data-static="1" aria-label="مشاهده پرونده" data-tip="مشاهده پرونده" onclick="caseDetail(\''+d.id+'\')">'+ICONS.eye+'</button>'
    +'</div>'
    +'</div></div>').join('');
}
function devRequeue(id){
  var wasModal=CASE_MODAL.live&&CASE_MODAL.id===id;
  confirmDlg('بازگشت به صف','پرونده به مرحلهٔ «'+(STAGE_FA['inquiry']||'استعلام')+'» برمی‌گردد و استعلام از نو اجرا می‌شود. مطمئنی؟',
    'بازگشت به صف',function(){
      devTick(id,'requeue_inquiry');
      if(wasModal)caseDetail(id);
    });
}
function closeCaseDialog(id){
  openDlg('<h3>مختومه کردن پرونده</h3>'
    +'<p style="margin:0 0 10px;color:var(--muted);font-size:13px;line-height:1.8">پرونده برای همیشه بسته می‌شود و دیگر قابل ادامه نیست. دلیل آن ثبت می‌شود.</p>'
    +'<input id="closeReason" placeholder="دلیل مختومه‌کردن پرونده…" class="inp" style="width:100%">'
    +'<div class="row" style="margin-top:12px"><button class="btn danger" onclick="closeCaseYes(\''+id+'\')">مختومه کردن پرونده</button>'
    +'<button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function closeCaseYes(id){
  var reason=(document.getElementById('closeReason')||{}).value||'';
  reason=reason.trim();
  if(!reason){toast('ثبت دلیل الزامی است',false);return;}
  var cn=((STATE.devices||[]).find(x=>x.id===id)||{}).name||'';
  closeDlg();
  api('/crm-tick',{device_id:id,action:'close_case',reason:reason}).then(async r=>{
    toastCtx(cn,'مختومه شد');await refresh();})
    .catch(e=>toastCtx(cn,String(e),false));
}
/* v1.5 B4: the main grid lists active cases only; done/problem/closed
   devices appear exclusively in their own tabs (no case in two sections). */
function isActiveCase(d){return !['done','problem','closed'].includes(d.stage);}
function needsAction(d){
  return ['problem','ready_owner','to_payment','payment'].includes(d.stage);
}
var STAGE_GUIDE = {
  'new': {n:1, name:'ثبت اطلاعات پرونده دستگاه', desc:'سریال دستگاه ثبت و پرونده به مشتری وصل می‌شود. این گام فقط ورود اطلاعات است؛ هنوز هیچ استعلامی اجرا نشده است.'},
  'inquiry': {n:2, name:'استعلام ثبت‌نبودن دستگاه در همتا و گمرک', desc:'در این مرحله از سامانه‌های همتا و رجیستری گمرک باید استعلام بگیریم که دستگاه خام باشد و قبلاً در این سامانه‌ها ثبت نشده باشد. هر پیامی مبنی بر سابقهٔ ثبت‌بودن دستگاه مساوی است با خطا و نباید باقی مراحل برای این دستگاه پیش برود. پس پیام «ثبت‌نبودن در گمرک» پیام مثبت (سبز) این گام است و پیام «ثبت‌بودن دستگاه» پیام خطر قرمز و عدم امکان ادامه به گام بعد است.'},
  'ready_owner': {n:3, name:'اتصال مسافر به دستگاه', desc:'دستگاه خام تأیید شد؛ حالا پرونده به اطلاعات مسافر (نام، کد ملی، تاریخ تولد) نیاز دارد. مسافر را با دکمهٔ «اتصال مسافر» به دستگاه وصل کنید.'},
  'handed': {n:4, name:'تحویل پرونده به مسئول ثبت', desc:'پرونده به مسئول ثبت‌کنندهٔ سایت تحویل شده و در لیست استعلام دوره‌ای گمرک قرار می‌گیرد تا ثبت‌شدن دستگاه در سامانهٔ گمرک مرتب چک شود.'},
  'to_payment': {n:5, name:'استعلام ثبت‌بودن دستگاه در گمرک', desc:'در این گام دستگاه باید در سامانهٔ گمرک استعلام گرفته شود. اگر دستگاه ثبت شده باشد این گام تأیید است و می‌توان به گام بعد رفت؛ اگر ثبت نشده باشد گام هنوز تکمیل نشده است. این گام به استعلام دوره‌ای نیاز دارد؛ پیام موفق پرونده‌هایی که به استعلام دوره‌ای فرستاده می‌شوند «ثبت‌بودن دستگاه» است و با آن امکان رفتن به گام بعد باز می‌شود.'},
  'payment': {n:6, name:'رسیدن به مرحلهٔ پرداخت', desc:'پرونده با مشخصات مسافری که به آن وصل شده برای دریافت لینک پرداخت با ربات گمرک می‌رود. در صورت دریافت لینک پرداخت، اسکرین‌شات‌های موردنیاز و فایل لینک پرداخت برای این دستگاه در پنل CRM قابل مشاهده و استفاده است و برای گام بعد آزاد می‌شود.'},
  'payment_done': {n:7, name:'تأیید دستی انجام‌شدن پرداخت', desc:'پرداخت پرونده به‌صورت دستی بررسی و تأیید می‌شود. رسید و اسکرین‌شات‌ها در کارت پرونده قابل مشاهده است.'},
  'done': {n:8, name:'تأیید تحویل کد فعال‌سازی', desc:'تحویل کد فعال‌سازی به مشتری تأیید می‌شود و پرونده تکمیل می‌شود.'}
};
var STAGE_GUIDE_PROBLEM = 'این دستگاه در گام ۲ (استعلام ثبت‌نبودن) دارای اشکال شد — معمولاً به این معناست که دستگاه قبلاً در یکی از سامانه‌ها ثبت بوده یا سایت پاسخ رد داده است. با «بازگشت به صف» دوباره استعلام بگیرد یا پرونده بسته شود.';
/* v1.3.5: the step guide opens OVER the case modal and returns to it on
   every close path (button, x, Esc) — DLG_BACK holds the case to restore
   and closeDlg consumes it. */
var DLG_BACK='';
function stageGuideModal(stage){
  var isProblem=stage==='problem';
  var g=STAGE_GUIDE[isProblem?'inquiry':stage];
  if(!g)return;
  var back=CASE_MODAL.live?CASE_MODAL.id:'';
  /* a parked-problem case keeps its step-2 dot red even when the guide of
     another step is open (H1 review) */
  var dev=back?(STATE.devices||[]).find(x=>x.id===back):null;
  var failed=!!(dev&&dev.stage==='problem');
  var title=isProblem?'دارای اشکال در گام ۲ — استعلام ثبت‌نبودن':g.name;
  var desc=isProblem?STAGE_GUIDE_PROBLEM:g.desc;
  var focus=STAGE_ORDER.indexOf(isProblem?'inquiry':stage);
  var dots=RAIL_STEPS.map(function(s){
    var i=STAGE_ORDER.indexOf(s);
    var cls='gdot'+(i<focus?' done':'')+(((failed||isProblem)&&s==='inquiry')?' bad':(i===focus?' cur':''));
    return '<span class="'+cls+'"></span>';
  }).join('');
  openDlg('<div class="guide">'
    +'<div class="ghead"><span class="gnum'+(isProblem?' bad':'')+'">'+(isProblem?'!':fa(g.n))+'</span>'
    +'<div><div class="glbl">گام '+fa(g.n)+' از '+fa(RAIL_STEPS.length)+'</div>'
    +'<h3>'+esc(title)+'</h3></div></div>'
    +'<div class="grail">'+dots+'</div>'
    +'<p class="gdesc">'+esc(desc)+'</p>'
    +'<div class="row" style="margin-top:14px"><button class="btn primary" onclick="closeDlg()">'
    +(back?'بازگشت به پرونده':'بستن')+'</button></div>'
    +'</div>');
  DLG_BACK=back;
}
function railHtml(d){
  // 8 numbered steps; 'problem' is a parking state shown as a RED step-2 dot.
  var failed = d.stage==='problem';
  var cur = STAGE_ORDER.indexOf(d.stage);
  var steps = RAIL_STEPS.map(function(st){
    var i = STAGE_ORDER.indexOf(st);
    var cls='step';
    if(failed && st==='inquiry') cls+=' bad';
    else if(i<cur) cls+=' done';
    else if(i===cur) cls+= (STAGE_TONE[st]==='ok'?' done':' cur');
    var g=STAGE_GUIDE[st]||{};
    var label='گام '+(g.n||'')+' — '+(STAGE_FA[st]||st);
    if(failed && st==='inquiry') label+=' — این دستگاه در همین گام دارای اشکال شد';
    return '<button type="button" class="'+cls+'" title="'+esc(label)+'" '
      +'onclick="stageGuideModal(\''+(failed&&st==='inquiry'?'problem':st)+'\')" '
      +'aria-label="'+esc(label)+'"></button>';
  }).join('');
  return '<div class="rail" role="group" aria-label="مراحل پرونده">'+steps+'</div>';
}

/* ================= per-tab search & filter (v1.4.0) ================= */
/* Normalize one side of a search: lowercase, Persian/Arabic digits to
   Latin, ZWNJ removed — so «۰۹۱۲» finds "0912" and «می‌شود» matches
   «میشود». */
function normSearch(s){
  return String(s==null?'':s).toLowerCase()
    .replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d))
    .replace(/[٠-٩]/g,d=>'٠١٢٣٤٥٦٧٨٩'.indexOf(d))
    .replace(/\u200c/g,'');
}
function tabSearchMatches(text,q){
  q=String(q||'').trim();
  if(!q)return true;
  return normSearch(text).indexOf(normSearch(q))>=0;
}
function tabQ(){return String(TAB_Q[TAB]||'').trim();}
/* v1.10 period filter (operator request): «لیست پرونده‌ها بر اساس دوره‌ها».
   It is a SECOND dimension over the case lists, not a replacement for the
   stage chips: 'all' is the tab's own set (the devices tab keeps showing the
   in-flight cases it has always shown), 'cur' is what is live right now, and a
   period id is that period at every stage, finished cases included. */
var PERIOD_FILTER_TABS=['devices','done_tab','problem_tab','closed_tab'];
function periodFilterTab(){return PERIOD_FILTER_TABS.indexOf(TAB)>=0;}
/* The one resolver every reader asks, so the chips, the lists and the result
   pill can never disagree. Two values degrade to 'all' instead of showing an
   empty list with no way back: a period the store no longer has (the operator
   closed/deleted it in another browser between two 5s refreshes), and 'cur'
   while no period is open (nothing is "current" then, and a stale 'cur' would
   silently hide every finished case of every tab).
   Off the case-list tabs the filter reads as 'all' — the shared toolbar state
   is not a lie on tables that do not filter by period. */
function periodFilterResolved(){
  if(!periodFilterTab())return 'all';
  if(TAB_PERIOD_FILTER==='cur')return activePeriod()?'cur':'all';
  if(TAB_PERIOD_FILTER==='all')return 'all';
  return periodById(TAB_PERIOD_FILTER)?TAB_PERIOD_FILTER:'all';
}
function periodPass(d){
  var f=periodFilterResolved();
  if(f==='all')return true;
  if(f==='cur'){
    /* the operator's rule: a case that is in flight is never hidden by the
       period view, so the live set is the in-flight cases PLUS everything
       registered in the open period (which is where «دورهٔ فعلی» reads as a
       case list — its finished ones included). */
    var per=activePeriod();
    return isActiveCase(d)||(!!per&&String(d.period_id||'')===String(per.id));
  }
  return String(d.period_id||'')===String(f);
}
/* The devices list's base set: the in-flight cases (unchanged default) or,
   while a period filter is on, that period's cases at every stage. */
function periodBaseDevices(){
  var f=periodFilterResolved();
  var all=(STATE&&STATE.devices)||[];
  return f==='all'?all.filter(isActiveCase):all.filter(periodPass);
}
function searchActive(){
  return !!tabQ()||(TAB==='devices'&&TAB_STAGE_FILTER!=='all')
    ||periodFilterResolved()!=='all';
}
/* Search haystack shared by every device-based list: id, name, serials,
   passenger and customer names. */
function devHay(d){
  return [d.id,d.name,d.serial1,d.serial2,ownerName(d.owner_id),custName(d.customer_id)].join(' ');
}
/* devices tab: stage-chip filter + query over the period base set. The period
   rule is applied here too, so any caller that hands in a raw list still gets
   it — periodBaseDevices has already narrowed the set and the predicate is
   idempotent. */
function filterDevices(ds){
  var q=tabQ();
  return ds.filter(d=>
    periodPass(d)
    &&(TAB_STAGE_FILTER==='all'||(TAB_STAGE_FILTER==='need'?needsAction(d):d.stage===TAB_STAGE_FILTER))
    &&tabSearchMatches(devHay(d),q));
}
/* done/problem/closed rows: period + query (extraHay adds per-tab fields,
   e.g. the closed reason). */
function filterDevRows(ds,extraHay){
  var q=tabQ();
  var f=periodFilterResolved();
  if(!q&&f==='all')return ds;
  return ds.filter(d=>periodPass(d)
    &&tabSearchMatches(devHay(d)+' '+(extraHay?extraHay(d):''),q));
}
/* v1.9.0 (operator request): the lists read newest-first. The store is
   append-only, so its raw order IS oldest-first and a list that never sorts
   shows the oldest row on top. A COPY is sorted — reordering STATE in place
   would leak into every other render (and filterDevRows even hands the
   caller's own array back when no search is on).
   The store index breaks the tie: crm._now() has second resolution, so two
   rows really can share a stamp, and among equals the later one is the newer
   one — the same fallback the launcher page uses. That makes the order total,
   so the 5s re-render can never flip two rows. A missing/empty stamp counts
   as oldest and rides the same index fallback: legacy rows stay put and
   nothing is migrated or written back. */
function newestFirst(rows,stamp){
  return (rows||[]).map(function(r,i){return {r:r,i:i};}).sort(function(a,b){
    var sa=String(stamp(a.r)||''), sb=String(stamp(b.r)||'');
    return sa!==sb?(sb<sa?-1:1):(b.i-a.i);
  }).map(function(x){return x.r;});
}
/* Friendly "no match" state — only shown while a search/filter is ACTIVE;
   a genuinely empty list keeps its own message. */
function searchEmptyHtml(){
  var q=tabQ();
  var title=q?'چیزی برای «'+esc(q)+'» پیدا نشد':'چیزی با این فیلتر پیدا نشد';
  return '<div class="empty"><span class="eic">'+ICONS.searchx+'</span><b>'+title+'</b>'
    +'<span class="esub">فیلتر یا عبارت جستجو را تغییر دهید.</span>'
    +'<div style="margin-top:14px"><button class="btn ghost" onclick="searchResetAll()">پاک کردن جستجو</button></div></div>';
}
function searchEmptyCard(){return '<div class="card">'+searchEmptyHtml()+'</div>';}
/* Clears the query, the stage filter AND the period filter from the
   empty-state button; the input lives in the toolbar (outside #tabBody), so it
   is reset directly. The period chips are rebuilt because clearing the period
   filter changes which stages exist (see tabPeriodSet). */
function searchResetAll(){
  TAB_Q[TAB]='';
  TAB_STAGE_FILTER='all';
  TAB_PERIOD_FILTER='all';
  var inp=document.getElementById('tabQIn');
  if(inp)inp.value='';
  var box=document.getElementById('tabSrch');
  if(box)box.classList.remove('hasq');
  var stages=document.getElementById('stageChips');
  if(stages)stages.innerHTML=stageChipsHtml();
  syncPeriodChips();
  renderBody();
  updateTabCount();
}
/* ---- toolbar rendering + focus-preserving updates ---- */
function tabBarHtml(){
  var cfg=TAB_SEARCH[TAB];
  if(!cfg)return '';
  var q=String(TAB_Q[TAB]||'');
  return '<div class="tabbar" id="tabBar">'
    +'<div class="srch'+(q.trim()?' hasq':'')+'" id="tabSrch">'
    +ICONS.search
    +'<input id="tabQIn" type="text" value="'+esc(q)+'" placeholder="'+esc(cfg.ph)+'"'
    +' aria-label="'+esc(cfg.ph)+'" autocomplete="off" oninput="tabSearchInput(this.value)">'
    +'<button type="button" class="clr" onclick="tabSearchClear()" aria-label="پاک کردن جستجو" title="پاک کردن جستجو">×</button>'
    +'</div>'
    +'<span class="pill n cntpill" id="tabCount" hidden></span>'
    +(TAB==='devices'?'<div class="tabchips" id="stageChips">'+stageChipsHtml()+'</div>':'')
    +(periodFilterTab()?'<div class="tabchips" id="periodChips">'+periodChipsHtml()+'</div>':'')
    +'</div>';
}
/* Stage chips: «همه» + «نیازمند اقدام» + one per stage the current period
   filter can actually produce. With no period filter that is the in-flight
   stages (exactly what it has always been); a period filter widens the base
   set to a period's cases, so its finished stages get chips too — otherwise a
   selected period would list done cases with no way to isolate them. */
function stageChipsHtml(){
  var base=periodBaseDevices();
  var stages=[];
  ['new','inquiry','ready_owner','handed','to_payment','payment','payment_done',
   'problem','done','closed'].forEach(function(st){
    if(base.some(d=>d.stage===st))stages.push(st);
  });
  var chips=[['all','همه'],['need','نیازمند اقدام']];
  stages.forEach(function(st){chips.push([st,STAGE_FA[st]||st]);});
  return chips.map(function(c){
    return '<button type="button" class="chipbtn'+(TAB_STAGE_FILTER===c[0]?' active':'')+'" data-f="'+c[0]+'"'
      +' onclick="tabStageSet(\''+c[0]+'\')">'+esc(c[1])+'</button>';
  }).join('');
}
/* Period chips (v1.10): «همهٔ دوره‌ها» keeps the tab's own set, «دورهٔ فعلی»
   is the live set while a period is open, and the rest are one chip per
   period, newest first — the open period is represented by «دورهٔ فعلی»
   rather than by a second, near-identical chip. Only the newest few periods
   are chipped: the row lives in the toolbar, and the periods tab is the place
   to reach an old one. */
var PERIOD_CHIP_MAX=8;
function periodPidAttr(value){
  /* The id reaches an onclick string literal, so it is reduced to what an id
     can actually be (the server mints 8 hex chars). A hand-edited store that
     holds something else loses its chip instead of injecting code. */
  return String(value==null?'':value).replace(/[^A-Za-z0-9_\-]/g,'');
}
function periodChipsHtml(){
  var f=periodFilterResolved();
  var chips=[['all','همهٔ دوره‌ها']];
  if(activePeriod())chips.push(['cur','دورهٔ فعلی']);
  var hidden=0;
  periodSorted().forEach(function(p){
    if(String(p.id)===String((activePeriod()||{}).id))return;   /* = «دورهٔ فعلی» */
    if(chips.length>=PERIOD_CHIP_MAX+1){hidden++;return;}
    chips.push([periodPidAttr(p.id),periodName(p)]);
  });
  var html=chips.map(function(c){
    return '<button type="button" class="chipbtn'+(f===c[0]?' active':'')+'" data-f="'+c[0]+'"'
      +' onclick="tabPeriodSet(\''+c[0]+'\')">'+esc(c[1])+'</button>';
  }).join('');
  if(hidden)html+='<span class="kbd">و '+fa(hidden)+' دورهٔ قدیمی‌تر در سربرگ «دوره‌ها»</span>';
  return html;
}
/* Chip clicks toggle the active class in place — the toolbar itself is
   never re-rendered while the operator works in it. */
function syncStageChips(){
  var chips=document.querySelectorAll('#stageChips .chipbtn');
  for(var i=0;i<chips.length;i++)
    chips[i].classList.toggle('active',chips[i].getAttribute('data-f')===TAB_STAGE_FILTER);
}
function syncPeriodChips(){
  var chips=document.querySelectorAll('#periodChips .chipbtn');
  var f=periodFilterResolved();
  for(var i=0;i<chips.length;i++)
    chips[i].classList.toggle('active',chips[i].getAttribute('data-f')===f);
}
function tabStageSet(f){
  TAB_STAGE_FILTER=f;
  syncStageChips();
  renderBody();
  updateTabCount();
}
/* A stage filter is only meaningful while the new period set still has that
   stage (picking an old period that never saw a pass-through case would
   otherwise leave the list empty with no active chip to explain why). */
function tabStageEnsure(){
  if(TAB_STAGE_FILTER==='all'||TAB_STAGE_FILTER==='need')return;
  if(periodBaseDevices().some(d=>d.stage===TAB_STAGE_FILTER))return;
  TAB_STAGE_FILTER='all';
}
function tabPeriodSet(f){
  TAB_PERIOD_FILTER=f;
  tabStageEnsure();
  /* The base set changed, so the stage chips are rebuilt (not just
     re-highlighted): an old period adds its finished stages and may drop the
     in-flight ones. The toolbar around them is left alone. */
  var stages=document.getElementById('stageChips');
  if(stages)stages.innerHTML=stageChipsHtml();
  syncPeriodChips();
  renderBody();
  updateTabCount();
}
function tabSearchInput(val){
  TAB_Q[TAB]=String(val||'');
  var box=document.getElementById('tabSrch');
  if(box)box.classList.toggle('hasq',!!tabQ());
  renderBody();
  updateTabCount();
}
function tabSearchClear(){
  TAB_Q[TAB]='';
  var inp=document.getElementById('tabQIn');
  if(inp)inp.value='';
  var box=document.getElementById('tabSrch');
  if(box)box.classList.remove('hasq');
  renderBody();
  updateTabCount();
}
function updateTabCount(){
  var pill=document.getElementById('tabCount');
  if(!pill)return;
  if(!searchActive()){pill.hidden=true;return;}
  pill.hidden=false;
  pill.textContent=fa(TAB_COUNT)+' '+(TAB_SEARCH[TAB]||{}).unit;
}
/* Edge fade for the wide case table: while its .tbl-wrap is scrolled the
   .tblcard frame shows the soft inline-start gradient (RTL scrollLeft is 0
   at rest, negative once scrolled). One capture-phase listener covers every
   re-render; presentation only, no state. */
document.addEventListener('scroll',function(e){
  var t=e.target;
  if(!t||!t.classList||!t.classList.contains('tbl-wrap'))return;
  var frame=t.parentElement;
  if(frame&&frame.classList.contains('tblcard'))
    frame.classList.toggle('scrl',t.scrollLeft!==0);
},true);
/* Shared per-tab body dispatch (renderView and renderBody both use it). */
function bodyHtml(){
  var body;
  if(TAB==='devices')body=devicesHtml();
  else if(TAB==='periods')body=periodsHtml();
  else if(TAB==='done_tab')body=doneTabHtml();
  else if(TAB==='problem_tab')body=problemTabHtml();
  else if(TAB==='closed_tab')body=closedTabHtml();
  else if(TAB==='customers')body=customersHtml();
  else if(TAB==='owners')body=ownersHtml();
  else if(TAB==='owner_archive')body=ownerArchiveHtml();
  else if(TAB==='identities')body=identitiesHtml();
  else if(TAB==='periodic')body=periodicHtml();
  else if(TAB==='ledger')body=ledgerHtml();
  else if(TAB==='settings')body=settingsHtml();
  else if(TAB==='cloud')body=cloudTabHtml();
  else body=reportsHtml();
  return body;
}
function renderBody(){
  var el=document.getElementById('tabBody');
  if(!el)return;
  if(TAB==='cloud'&&document.getElementById('cloud-sync-section')){
    paintCloud();
    return;
  }
  if(TAB==='settings'&&document.getElementById('stFee')){
    var ae=document.activeElement;
    if(ae&&el.contains(ae))return;
  }
  el.innerHTML=bodyHtml();
  if(TAB==='settings'&&typeof settingsLoadTelegram==='function')settingsLoadTelegram();
}

/* ================= KPI strip ================= */
function kpisHtml(){
  var ds=(STATE.devices||[]);
  var c={all:ds.length,need:0,ok:0,debt:0};
  ds.forEach(d=>{ if(needsAction(d))c.need++; if(d.stage==='done')c.ok++; });
  (STATE.customers||[]).forEach(x=>{ if(bal(x.id)<0)c.debt++; });
  function k(cls,label,n,tab){
    return '<button type="button" class="kpi '+cls+'" onclick="setTab(\''+tab+'\')">'
      +'<span class="n">'+fa(n)+'</span><span class="l">'+label+'</span></button>';
  }
  return '<div class="kpis">'
    +k('','همهٔ پرونده‌ها',c.all,'devices')
    +k('attention','نیازمند اقدام',c.need,'devices')
    +k('k-ok','تکمیل شده‌ها',c.ok,'done_tab')
    +k('k-problem','مشتری بدهکار',c.debt,'customers')
    +'</div>';
}

/* ================= devices (case table + detail modal) ================= */
/* Serials are long IMEIs; the table shows a masked form (the full value
   lives in the case detail modal). Short values pass through untouched. */
function maskSerial(s){s=String(s||'');return s.length<=8?s:s.slice(0,4)+'…'+s.slice(-3);}
/* v1.7: the active reporting period bar. Devices registered while a
   period is open carry its id; the operator closes the period to lock the
   books before printing the period finance report. Computed from STATE
   (server is the source of truth) so a refresh always shows the truth. */
/* v1.8.1 (operator rule: a case may not exist outside a period): the one
   resolver every caller asks. The stored pointer can outlive the period it
   names, so a period counts as open only while the server agrees — the server
   answers a second close with a 400. */
function activePeriod(){
  var pid=(STATE.settings||{}).current_period_id;
  if(!pid)return null;
  return (STATE.periods||[]).find(p=>String(p.id)===String(pid)&&!p.closed_at)||null;
}
var NO_PERIOD_TIP='دورهٔ باز وجود ندارد. برای ساخت اولین پرونده، از دکمهٔ «شروع دورهٔ جدید» بالای همین صفحه یک دوره باز کنید.';
/* Carries the blocked state AND the reason. aria-disabled rather than disabled
   on purpose: a disabled control cannot take focus, so a keyboard user could
   never reach the reason — and the reason IS the whole point of this gate. The
   click answers with the same sentence as a toast (dlgDevice guards), the
   tooltip chip shows on hover and on focus, and .btn[aria-disabled] keeps the
   look inert. */
function periodGateAttrs(){
  return activePeriod()?'':' aria-disabled="true" data-tip="'+NO_PERIOD_TIP+'"';
}
function periodBarHtml(){
  var per=activePeriod();
  if(!per) return '<div class="row" style="margin:0 0 12px;align-items:center">'
    +'<span class="pill n">دورهٔ بسته</span>'
    +'<span class="muted">تا دورهٔ باز شروع نشود، پروندهٔ جدیدی ساخته نمی‌شود.</span>'
    +'<button class="btn primary" onclick="periodOpen()">شروع دورهٔ جدید</button></div>';
  var inPeriod=(STATE.devices||[]).filter(d=>d.period_id===per.id).length;
  return '<div class="row" style="margin:0 0 12px;align-items:center">'
    +'<span class="pill ok">'+esc(per.label||('دورهٔ '+fa(per.number||0)))+'</span>'
    +'<span class="muted">'+fa(inPeriod)+' پرونده در این دوره</span>'
    +'<button class="btn warn" onclick="periodClose(\''+per.id+'\')">بستن دوره</button></div>';
}
function periodOpen(){
  api('/crm-period-open',{label:''}).then(async r=>{
    toast('دورهٔ جدید شروع شد: '+esc(r.period.label));await refresh();})
    .catch(e=>toast(e,false));
}
function periodClose(id){
  /* v1.8.1: the confirm replaces the dialog, and confirmYes disarms the
     return, so a close confirmed from the period's own dialog comes back to
     it (rebuilt on the fresh state) instead of dropping the operator on the
     tab. */
  var fromDlg=PER.live&&String(PER.pid)===String(id);
  confirmDlg('بستن دوره','با بستن این دوره، پرونده‌های جدید به آن اضافه نمی‌شوند و گزارش مالی این دوره نهایی می‌شود. ادامه می‌دهید؟','بستن دوره',function(){
    api('/crm-period-close',{period_id:id}).then(async r=>{
      var s=r.summary;
      var msg='دوره بسته شد: '+fa(s.devices)+' پرونده';
      if(s.open_cases>0) msg+='؛ '+fa(s.open_cases)+' پرونده هنوز باز است';
      toast(msg, s.open_cases>0?'warn':true);await refresh();
      /* Only if the operator has not opened something meanwhile: the confirm
         already closed this dialog, so the tab is interactive while the close
         is in flight, and rebuilding over their work would be a hijack. */
      if(fromDlg&&periodById(id)&&!document.getElementById('dlg').open)dlgPeriod(id);})
      .catch(e=>toast(e,false));
  });
}
/* ================= periods tab (v1.8) ================= */
/* One card per reporting period, plus a detail dialog that answers — for every
   case of that period — which customer owns it, which passenger is attached,
   whether the case is finished, and its debit/credit/remaining. Everything is
   derived from the STATE the page already holds: no extra route, so the tab
   can never disagree with the case list it links to, and it opens instantly. */
var PER={pid:'',seg:'cases',live:false,sig:''};
function periodById(pid){
  return ((STATE&&STATE.periods)||[]).find(p=>String(p.id)===String(pid))||null;
}
function periodCases(pid){
  return ((STATE&&STATE.devices)||[]).filter(d=>String(d.period_id||'')===String(pid));
}
/* Mirrors crm._tx_countable: a voided row (and the reversal that voids it) and
   a row whose date cannot be parsed never count, and the sign picks the
   column. Kept on this side on purpose — every ledger row is already in STATE,
   so one round-trip per case would make the dialog crawl on a long period and
   could disagree with the balances the same page shows. */
function caseMoney(deviceId){
  var debit=0,credit=0;
  ((STATE&&STATE.customers)||[]).forEach(function(c){
    (c.transactions||[]).forEach(function(t){
      /* one row counts for this case when it is linked to this device, it is
         not voided (and is not the reversal that voids one), and its stamp is
         a real date — the same three tests crm._tx_countable applies. */
      if(String(t.device_id||'')===deviceId&&!t.voided_at&&t.kind!=='void'
         &&/^\d{4}-\d{2}-\d{2}/.test(String(t.at||''))){
        var amount=Number(t.amount||0);
        if(!isFinite(amount))return;      /* a hand-edited store must not NaN */
        if(amount<0)debit+=-amount;else credit+=amount;
      }
    });
  });
  return {debit:debit,credit:credit,net:credit-debit};
}
function periodMoney(pid){
  var m={debit:0,credit:0,net:0};
  periodCases(pid).forEach(function(d){
    var cm=caseMoney(d.id);
    m.debit+=cm.debit;m.credit+=cm.credit;m.net+=cm.net;
  });
  return m;
}
function periodOwners(pid){
  return periodCases(pid).map(function(d){
    var o=((STATE&&STATE.owners)||[]).find(x=>String(x.id)===String(d.owner_id||''));
    return o?{owner:o,device:d}:null;
  }).filter(Boolean);
}
function periodCustomers(pid){
  var seen={},out=[];
  periodCases(pid).forEach(function(d){
    var cid=String(d.customer_id||'');
    if(!cid||seen[cid])return;
    seen[cid]=true;
    var c=((STATE&&STATE.customers)||[]).find(x=>String(x.id)===cid);
    if(c)out.push(c);
  });
  return out;
}
function periodCustomerMoney(pid,cid){
  var m={debit:0,credit:0,net:0,cases:0};
  periodCases(pid).forEach(function(d){
    if(String(d.customer_id||'')!==String(cid))return;
    var cm=caseMoney(d.id);
    m.debit+=cm.debit;m.credit+=cm.credit;m.net+=cm.net;m.cases++;
  });
  return m;
}
function balancePill(net){
  if(net>0)return '<span class="pill ok">بستانکار</span>';
  if(net<0)return '<span class="pill bad">بدهکار</span>';
  return '<span class="pill n">تسویه</span>';
}
function stagePill(st){
  return '<span class="pill '+(STAGE_TONE[st]||'n')+'">'+(STAGE_FA[st]||esc(st))+'</span>';
}
function periodPill(p){
  return p.closed_at?'<span class="pill n">بسته</span>':'<span class="pill ok">باز</span>';
}
function periodName(p){return p.label||("دورهٔ "+fa(p.number||0));}
function periodRange(p){
  return faDateTime(p.opened_at)+(p.closed_at?' — '+faDateTime(p.closed_at):' — تا کنون');
}
function periodSorted(){
  /* the open period first — asked through the one resolver, so the tab can
     never disagree with the bar about which period is open */
  var cur=activePeriod();
  var cid=cur?String(cur.id):'';
  return ((STATE&&STATE.periods)||[]).slice().sort(function(a,b){
    var ao=String(a.id)===cid?0:1, bo=String(b.id)===cid?0:1;
    return ao-bo||String(b.opened_at||'').localeCompare(String(a.opened_at||''));
  });
}
function periodCardsHtml(){
  var ps=periodSorted();
  if(!ps.length)
    return emptyHtml('دوره‌ای ثبت نشده است',
      'با «شروع دورهٔ جدید» پرونده‌های بعدی در یک دورهٔ قابل‌گزارش جمع می‌شوند.');
  return '<div class="pcards">'+ps.map(function(p){
    var ds=periodCases(p.id);
    var done=ds.filter(d=>d.stage==='done').length;
    var closed=ds.filter(d=>d.stage==='closed').length;
    var run=ds.length-done-closed;
    var m=periodMoney(p.id);
    /* The whole card is the way in, and the click lives on a real button
       stretched over it rather than on the card div: the button carries the
       accessible name and the focus state for free. It is layered above the
       card's text and below the action row (see .pcard-hit / .pacts). */
    return '<div class="pcard">'
      +'<button type="button" class="pcard-hit" aria-label="جزئیات '+esc(periodName(p))+'"'
      +' onclick="dlgPeriod(\''+p.id+'\')"></button>'
      +'<div class="ph"><span class="pn">'+esc(periodName(p))+'</span>'+periodPill(p)+'</div>'
      +'<div class="pd">'+esc(periodRange(p))+'</div>'
      +'<div class="pc"><span class="chip">'+fa(ds.length)+' پرونده</span>'
      +'<span class="chip">'+fa(done)+' تکمیل‌شده</span>'
      +(run>0?'<span class="chip">'+fa(run)+' در جریان</span>':'')
      +(closed>0?'<span class="chip">'+fa(closed)+' مختومه</span>':'')
      +'<span class="chip">'+fa(ds.filter(d=>d.owner_id).length)+' مسافر متصل</span>'
      +'<span class="chip">'+fa(periodCustomers(p.id).length)+' مشتری</span></div>'
      +'<div class="pm"><span>بدهکاری پرونده‌ها <b class="d">'+money(m.debit)+'</b></span>'
      +'<span>بستانکاری پرونده‌ها <b class="c">'+money(m.credit)+'</b></span>'
      +'<span>مانده '+balancePill(m.net)+'</span></div>'
      +'<div class="pacts">'
      +'<button type="button" class="ibtn" data-static="1" aria-label="گزارش مالی این دوره"'
      +' data-tip="گزارش مالی این دوره" onclick="window.open(\'/crm-finance-report?mode=period&ref='
      +p.id+'&fmt=html\',\'_blank\')">'+ICONS.wallet+'</button>'
      +(p.closed_at?'':'<button type="button" class="ibtn warn" aria-label="بستن دوره"'
        +' data-tip="بستن دوره" onclick="periodClose(\''+p.id+'\')">'+ICONS.lock+'</button>')
      +'</div>'
      +'</div>';
  }).join('')+'</div>';
}
function periodsHtml(){
  /* No search toolbar on this tab (TAB_SEARCH has no entry), so there is no
     count pill to feed either. The «شروع دورهٔ جدید» offer asks the same
     resolver the gate does: while a period IS open there is nothing to start. */
  var open=activePeriod();
  return '<div class="card"><div class="row" style="margin-bottom:10px">'
    +(open?'':'<button class="btn primary" onclick="periodOpen()">شروع دورهٔ جدید</button>')
    +'<span class="muted">هر پرونده‌ای که در دورهٔ باز ثبت شود عضو آن می‌شود؛ تا دوره بسته نشود ارقام نهایی نیستند.</span>'
    +'</div>'+periodCardsHtml()+'</div>';
}
function perKpisHtml(p){
  var ds=periodCases(p.id);
  var done=ds.filter(d=>d.stage==='done').length;
  var m=periodMoney(p.id);
  return '<div class="per-kpis">'
    +'<div class="per-kpi"><span class="l">پرونده</span><span class="v">'+fa(ds.length)+'</span></div>'
    +'<div class="per-kpi ok"><span class="l">تکمیل‌شده</span><span class="v">'+fa(done)+'</span></div>'
    +'<div class="per-kpi"><span class="l">مسافر متصل</span><span class="v">'+fa(ds.filter(d=>d.owner_id).length)+'</span></div>'
    +'<div class="per-kpi'+(m.debit?' bad':'')+'"><span class="l">بدهکاری پرونده‌ها</span><span class="v">'+money(m.debit)+'</span></div>'
    +'<div class="per-kpi'+(m.credit?' ok':'')+'"><span class="l">بستانکاری پرونده‌ها</span><span class="v">'+money(m.credit)+'</span></div>'
    +'</div>';
}
function perDetailBtn(did,label){
  label=esc(label);
  return '<button type="button" class="ibtn ghost" data-static="1" aria-label="'+label+'" data-tip="'+label+'"'
    +' onclick="caseDetail(\''+did+'\')">'+ICONS.eye+'</button>';
}
function perCasesHtml(p){
  var ds=periodCases(p.id).slice().sort(function(a,b){
    return String(b.updated||'').localeCompare(String(a.updated||''));});
  if(!ds.length)
    return emptyHtml('پرونده‌ای در این دوره نیست','هنوز هیچ پرونده‌ای عضو این دوره نشده است.');
  var rows=ds.map(function(d){
    var cm=caseMoney(d.id);
    var o=((STATE&&STATE.owners)||[]).find(x=>String(x.id)===String(d.owner_id||''));
    return '<tr><td><b>'+esc(d.name)+'</b>'
      +'<div class="kbd" dir="ltr">'+esc(d.serial1)+(d.serial2?' / '+esc(d.serial2):'')+'</div></td>'
      +'<td>'+esc(custName(d.customer_id)||'—')+'</td>'
      +'<td>'+(o?'<b>'+esc(o.first_name+' '+o.last_name)+'</b> <span class="pill ok">متصل</span>'
              :'<span class="pill n">بدون مسافر</span>')+'</td>'
      +'<td>'+stagePill(d.stage)+'</td>'
      +'<td class="pmoney d">'+(cm.debit?money(cm.debit):'—')+'</td>'
      +'<td class="pmoney c">'+(cm.credit?money(cm.credit):'—')+'</td>'
      +'<td>'+balancePill(cm.net)+'</td>'
      +'<td>'+perDetailBtn(d.id,'جزئیات پرونده')+'</td></tr>';
  }).join('');
  return '<div class="card tblcard"><div class="tbl-wrap"><table><thead><tr>'
    +'<th>پرونده</th><th>مشتری</th><th>مسافر</th><th>وضعیت</th>'
    +'<th>بدهکاری</th><th>بستانکاری</th><th>مانده</th><th></th>'
    +'</tr></thead><tbody>'+rows+'</tbody></table></div></div>';
}
function perOwnersHtml(p){
  /* v1.9.0: newest case first, so the stamp is the CASE's created. The
     derived index breaks a tie deterministically — the list must not jump
     between two orders on the period dialog's own 5s refresh. */
  var ps=newestFirst(periodOwners(p.id),r=>(r.device||{}).created);
  var bound={};
  ((STATE&&STATE.devices)||[]).forEach(function(d){
    if(d.owner_id)bound[String(d.owner_id)]=true;
  });
  var free=newestFirst(((STATE&&STATE.owners)||[]).filter(o=>!bound[String(o.id)]),
    o=>o.created);
  /* Reviewing a period is also when the operator wants to see who is still
     unassigned, so the free passengers ride along — clearly marked, because
     they belong to no case at all. */
  var freeHtml=free.length
    ?'<div class="row" style="margin-top:10px;flex-wrap:wrap;gap:6px">'
      +'<span class="muted">مسافران بدون پرونده:</span>'
      +free.map(o=>'<span class="chip">'+esc(o.first_name+' '+o.last_name)
        +' <span class="pill n">بدون پرونده</span></span>').join('')+'</div>'
    :'';
  if(!ps.length)
    return emptyHtml('مسافری به پرونده‌های این دوره وصل نشده است',
      'با اتصال مسافر به هر پرونده، این‌جا با وضعیت همان پرونده نمایش داده می‌شود.')+freeHtml;
  var rows=ps.map(function(r){
    var d=r.device,o=r.owner,cm=caseMoney(d.id);
    return '<tr><td><b>'+esc(o.first_name+' '+o.last_name)+'</b> <span class="pill ok">متصل</span></td>'
      +'<td class="kbd">'+esc(o.national)+'</td><td class="kbd">'+esc(o.mobile)+'</td>'
      +'<td>'+esc(d.name)+'<div class="kbd" dir="ltr">'+esc(d.serial1)+'</div></td>'
      +'<td>'+stagePill(d.stage)+'</td>'
      +'<td>'+balancePill(cm.net)+'</td>'
      +'<td>'+perDetailBtn(d.id,'جزئیات پرونده')+'</td></tr>';
  }).join('');
  return '<div class="card tblcard"><div class="tbl-wrap"><table><thead><tr>'
    +'<th>مسافر</th><th>کد ملی</th><th>موبایل</th><th>پرونده</th><th>وضعیت پرونده</th>'
    +'<th>ماندهٔ پرونده</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div></div>'
    +freeHtml;
}
function perCustomersHtml(p){
  /* v1.9.0: newest customer first — the segment lists the customers of the
     period's cases, latest first, like every other list. */
  var cs=newestFirst(periodCustomers(p.id),c=>c.created);
  if(!cs.length)
    return emptyHtml('مشتری‌ای به پرونده‌های این دوره وصل نیست',
      'پرونده‌های بدون مشتری هم در بخش «پرونده‌ها» فهرست شده‌اند.');
  var rows=cs.map(function(c){
    var m=periodCustomerMoney(p.id,c.id);
    return '<tr><td><b>'+esc(c.full_name)+'</b></td><td class="kbd">'+esc(c.mobile)+'</td>'
      +'<td class="kbd">'+fa(m.cases)+'</td>'
      +'<td class="pmoney d">'+(m.debit?money(m.debit):'—')+'</td>'
      +'<td class="pmoney c">'+(m.credit?money(m.credit):'—')+'</td>'
      +'<td>'+balancePill(m.net)+'</td>'
      +'<td><button type="button" class="ibtn" data-static="1" aria-label="صورت‌حساب مشتری"'
      +' data-tip="صورت‌حساب مشتری" onclick="window.open(\'/crm-statement?customer_id='+c.id
      +'&fmt=html\',\'_blank\')">'+ICONS.list+'</button></td></tr>';
  }).join('');
  return '<div class="card tblcard"><div class="tbl-wrap"><table><thead><tr>'
    +'<th>مشتری</th><th>موبایل</th><th>پرونده</th><th>بدهکاری</th><th>بستانکاری</th>'
    +'<th>مانده</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div></div>';
}
function perBodyHtml(p){
  if(PER.seg==='owners')return perOwnersHtml(p);
  if(PER.seg==='customers')return perCustomersHtml(p);
  return perCasesHtml(p);
}
function perSeg(seg){PER.seg=seg;perPaint();}
function perPaint(){
  var p=periodById(PER.pid);
  if(!p)return;
  var segs=document.getElementById('perSeg');
  if(segs)
    [].forEach.call(segs.querySelectorAll('button'),function(b){
      var on=b.getAttribute('data-pseg')===PER.seg;
      b.classList.toggle('on',on);
      b.setAttribute('aria-pressed',on?'true':'false');
    });
  var body=document.getElementById('perBody');
  if(body)body.innerHTML=perKpisHtml(p)+perBodyHtml(p);
  var head=document.getElementById('perHead');
  if(head)head.innerHTML='<h3>'+esc(periodName(p))+' '+periodPill(p)+'</h3>'
    +'<div class="kbd">'+esc(periodRange(p))+'</div>';
}
function dlgPeriod(pid, silent){
  var p=periodById(pid);
  if(!p){toast('دورهٔ انتخاب‌شده پیدا نشد',false);return;}
  /* v1.8.1: coming back from a case (or a live refresh) rebuilds the SAME
     period — the segment the operator was reading is kept, so the return
     lands where they left. A different period starts on its cases. */
  PER.seg=(String(PER.pid)===String(pid)&&PER.seg)?PER.seg:'cases';
  PER.pid=String(pid);
  openDlg('<div class="perdlg">'
    +'<div id="perHead"></div>'
    +'<div class="row" style="margin:8px 0 12px">'
    +'<div class="seg" id="perSeg">'
    +'<button type="button" data-pseg="cases" onclick="perSeg(\'cases\')">پرونده‌ها</button>'
    +'<button type="button" data-pseg="owners" onclick="perSeg(\'owners\')">مسافر‌ها</button>'
    +'<button type="button" data-pseg="customers" onclick="perSeg(\'customers\')">مشتری‌ها</button>'
    +'</div></div>'
    +'<div id="perBody"></div>'
    +'<div class="row" style="margin-top:12px">'
    +'<button type="button" class="btn" onclick="window.open(\'/crm-finance-report?mode=period&ref='
    +pid+'&fmt=html\',\'_blank\')">'+ICONS.wallet+' گزارش مالی این دوره</button>'
    +(p.closed_at?'':'<button type="button" class="btn warn" onclick="periodClose(\''+pid+'\')">'
      +ICONS.lock+' بستن دوره</button>')
    +'<button type="button" class="btn" onclick="closeDlg()">بستن</button>'
    +'</div>'
    +'<p class="muted" style="margin:10px 0 0">ارقام این پنجره تراکنش‌های '
    +'وصل‌شده به پرونده‌های همین دوره را می‌شمارد؛ گزارش مالی این دوره ممکن است '
    +'ردیف‌های دستی (بدون پرونده) را هم داشته باشد، و برای پرونده‌ای که مشتری‌اش '
    +'بعداً عوض شده، ماندهٔ این‌جا با فاکتور همان پرونده یکی نیست.</p>'
    +'</div>', silent);
  perPaint();
  /* openDlg cleared PER.live above; re-arm only here (same contract as
     CASE_MODAL at the end of caseDetail). */
  PER.live=true;PER.sig=perSig(PER.pid);
}
/* v1.8.1: the period dialog keeps itself in sync exactly like the case modal —
   a signature over what it renders, recomputed on every 5s refresh, so an
   action taken anywhere else (a case attached to a passenger, a receipt booked
   on the customer tab, the period closed from the card) shows up in an open
   dialog instead of leaving stale numbers on screen. */
function perSig(pid){
  var p=periodById(pid);
  if(!p)return '';
  var s=[String(p.closed_at||''),String(p.label||'')];
  periodCases(pid).slice().sort(function(a,b){
    return String(a.id).localeCompare(String(b.id));}).forEach(function(d){
      /* the fields the case table PRINTS — deliberately not d.updated, which
         every robot tick stamps: that would rebuild the table every 5 seconds
         and throw away the operator's scroll position */
      s.push([d.id,d.name,d.stage,d.owner_id||'',d.customer_id||'',
              d.serial1||'',d.serial2||''].join(','));
    });
  /* it also prints identities, not only ids, and the passenger table lists the
     FREE passengers too — so an owner or customer renamed from another tab, or
     an owner freed by a case in another period, must repaint this dialog. The
     per-owner bound flag carries the whole binding state. */
  var bound={};
  ((STATE.devices||[])).forEach(function(d){
    if(d.owner_id)bound[String(d.owner_id)]=true;});
  ((STATE.owners||[])).forEach(function(o){
    s.push(['o',o.id,o.first_name,o.last_name,o.national,o.mobile,
            bound[String(o.id)]?'b':''].join(','));});
  periodCustomers(pid).forEach(function(c){
    s.push(['c',c.id,c.full_name,c.mobile].join(','));});
  var m=periodMoney(pid);
  s.push('m'+m.debit+'/'+m.credit);
  return s.join('|');
}
function dlgPeriodSync(){
  if(!PER.live||!PER.pid)return;
  var p=periodById(PER.pid);
  if(!p){closeDlg();toast('این دوره پیدا نشد؛ پنجرهٔ آن بسته شد',false);return;}
  var sig=perSig(PER.pid);
  if(sig===PER.sig)return;
  /* A full rebuild (not just perPaint) so the footer follows too: the
     «بستن دوره» button has to disappear when the period closes. The dialog
     body is the scroller, so put the operator back where they were reading. */
  var scroller=document.getElementById('dlgBody');
  var keep=scroller?scroller.scrollTop:0;
  dlgPeriod(PER.pid,true);
  var fresh=document.getElementById('dlgBody');
  if(fresh)fresh.scrollTop=keep;
}

function devicesHtml(){
  /* v1.10: the base set is the in-flight cases (unchanged) unless a period
     filter is on, in which case it is that period's cases at every stage —
     that is what makes a closed period's cases reachable as a list here. */
  var ds=periodBaseDevices().sort((a,b)=>
    (needsAction(b)-needsAction(a)) || String(b.updated||'').localeCompare(String(a.updated||'')));
  ds=filterDevices(ds);
  TAB_COUNT=ds.length;
  var periodBar=periodBarHtml();
  var runCount=(STATE.estelam_runs||[]).length;
  var runningBanner=(STATE.estelam_running)
    ?'<div class="row" style="margin:0 0 12px;align-items:center">'
      +'<span class="pill warn">ربات استعلام در حال اجراست'+(runCount>1?' — '+fa(runCount)+' اجرای همزمان':'')+'</span>'
      +'<button type="button" class="ibtn danger" aria-label="توقف ربات استعلام" data-tip="توقف ربات استعلام" onclick="crmStopRun()">'+ICONS.stop+'</button></div>'
    :'';
  // B4: an empty active grid must not claim the workspace has no cases at
  // all when only done/problem/closed ones exist — point at their tabs.
  var others=(STATE.devices||[]).length>0;
  if(!ds.length){
    // v1.4.0: an active search/stage filter with no hit shows its own
    // card; the genuine empty states below stay untouched.
    if(searchActive())return periodBar+runningBanner+searchEmptyCard();
    return periodBar+runningBanner+'<div class="row" style="margin-bottom:12px">'
      +'<button class="btn primary"'+periodGateAttrs()+' onclick="dlgDevice()">+ پروندهٔ جدید</button>'
      +'<span class="muted">'+(activePeriod()
        ?(others
          ?'پروندهٔ در جریانی نیست؛ پرونده‌های تکمیل‌شده، دارای اشکال و مختومه در سربرگ خودشان هستند.'
          :'اولین پرونده را بسازید: سریال دستگاه، مشتری و در ادامه مسافر.')
        :NO_PERIOD_TIP)+'</span></div>'
      +emptyHtml(others?'پروندهٔ در جریانی نیست':'پرونده‌ای ثبت نشده',
        others?'این‌جا فقط پرونده‌های فعال را نشان می‌دهد؛ بقیهٔ پرونده‌ها در سربرگ‌های «تکمیل شده‌ها»، «دارای اشکال» و «مختومه‌ها» هستند.'
          :(activePeriod()?'هنوز پرونده‌ای نیست؛ با دکمهٔ «+ پروندهٔ جدید» بالا شروع کنید.'
            :NO_PERIOD_TIP));
  }
  var ORDINAL_FA = {
    1:'اول', 2:'دوم', 3:'سوم', 4:'چهارم', 5:'پنجم',
    6:'ششم', 7:'هفتم', 8:'هشتم', 9:'نهم', 10:'دهم',
    11:'یازدهم', 12:'دوازدهم', 13:'سیزدهم', 14:'چهاردهم', 15:'پانزدهم',
    16:'شانزدهم', 17:'هفدهم', 18:'هجدهم', 19:'نوزدهم', 20:'بیستم'
  };
  var PERIOD_PALETTE = [
    { border: '#3b82f6', bg: 'rgba(59,130,246,0.06)', badge: '#2563eb' },
    { border: '#10b981', bg: 'rgba(16,185,129,0.06)', badge: '#059669' },
    { border: '#8b5cf6', bg: 'rgba(139,92,246,0.06)', badge: '#7c3aed' },
    { border: '#f59e0b', bg: 'rgba(245,158,11,0.06)', badge: '#d97706' },
    { border: '#ec4899', bg: 'rgba(236,72,153,0.06)', badge: '#db2777' },
    { border: '#06b6d4', bg: 'rgba(6,182,212,0.06)', badge: '#0891b2' },
    { border: '#f97316', bg: 'rgba(249,115,22,0.06)', badge: '#ea580c' },
    { border: '#6366f1', bg: 'rgba(99,102,241,0.06)', badge: '#4f46e5' }
  ];
  function periodCardPalette(index){
    return PERIOD_PALETTE[Math.abs(index) % PERIOD_PALETTE.length];
  }
  function periodCardTitle(p){
    if(!p) return 'پرونده‌های بدون دوره';
    if(p.label && p.label.trim()) return p.label.trim();
    var num = Number(p.number || 0);
    if(num && ORDINAL_FA[num]) return 'دورهٔ ' + ORDINAL_FA[num];
    if(num) return 'دورهٔ ' + fa(num);
    return 'دوره';
  }
  function deviceRowHtml(d, i){
    var est=d.estelam||{};
    var cust=custName(d.customer_id);
    var owner=ownerName(d.owner_id);
    return '<tr id="devcard-'+d.id+'" style="cursor:pointer" onclick="caseDetail(\''+d.id+'\')">'
      +'<td class="kbd">'+fa(i+1)+'</td>'
      +'<td><b>'+esc(d.name)+'</b></td>'
      +'<td>'+(cust&&cust!=='—'?esc(cust):'<span class="muted">—</span>')+'</td>'
      +'<td>'+(owner&&owner!=='—'?esc(owner):'<span class="muted">—</span>')+'</td>'
      +'<td class="kbd" dir="ltr">'+esc(maskSerial(d.serial1))+'</td>'
      +'<td><span class="pill '+(STAGE_TONE[d.stage]||'n')+'">'+(STAGE_FA[d.stage]||esc(d.stage))+'</span></td>'
      +'<td><span class="pill '+((d.stage==='inquiry'&&est.status==='advanced')?'bad':(EST_PILL[est.status]||'n'))+'">'
        +((d.stage==='inquiry'&&est.status==='advanced')?'ثبت‌شده در گمرک — خطر!':(EST_FA[est.status]||esc(est.status||'—')))+'</span>'
        +(est.hamta_status?'<span class="pill '+(HAMTA_PILL[est.hamta_status]||'n')+'">همتا: '+(HAMTA_FA_CARD[est.hamta_status]||esc(est.hamta_status))+'</span>':'')+'</td>'
      +'<td class="kbd" dir="ltr">'+esc(d.id)+'</td>'
      +'<td class="kbd">'+esc(faDate(d.created))+'</td>'
      +'<td><div class="ibacts">'+caseShotBtn(d,'hamta')+caseShotBtn(d,'gomrok')+
        '<button type="button" class="ibtn" data-static="1" aria-label="جزئیات پرونده" data-tip="جزئیات پرونده" onclick="event.stopPropagation();caseDetail(\''+d.id+'\')">'+ICONS.eye+'</button></div></td></tr>';
  }
  function periodGroupCardHtml(p, rowsHtml, count, colorIndex){
    var col = p ? periodCardPalette(colorIndex != null ? colorIndex : ((p.number || 1) - 1))
                : { border: 'var(--line-strong)', bg: 'rgba(128,128,128,0.03)', badge: 'var(--muted)' };
    var title = periodCardTitle(p);
    var badgePill = p ? periodPill(p) : '<span class="pill n">بدون دوره</span>';
    var dateRange = p ? periodRange(p) : '';

    return '<div class="card tblcard pergroup-card" style="margin-bottom:18px;border:1.5px solid '+col.border+';border-right:6px solid '+col.border+';border-radius:12px;overflow:hidden">'
      +'<div class="pergroup-head" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;padding:10px 16px;background:'+col.bg+';border-bottom:1px solid var(--line)">'
      +'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
      +'<span style="background:'+col.badge+';color:#fff;padding:3px 12px;border-radius:6px;font-weight:700;font-size:13px">'+esc(title)+'</span>'
      +badgePill
      +(dateRange ? '<span class="muted kbd" style="font-size:12px">'+esc(dateRange)+'</span>' : '')
      +'</div>'
      +'<div style="display:flex;align-items:center;gap:8px">'
      +'<span class="chip" style="font-weight:600">'+fa(count)+' پرونده</span>'
      +(p ? '<button type="button" class="btn mini ghost" onclick="dlgPeriod(\''+p.id+'\')">'+ICONS.eye+' جزئیات دوره</button>' : '')
      +'</div></div>'
      +'<div class="tbl-wrap"><table class="casetbl">'
      +'<thead><tr><th>ردیف</th><th>دستگاه</th><th>مشتری</th><th>مسافر</th><th>سریال</th><th>گام فعلی</th><th>وضعیت</th><th>شناسه پرونده</th><th>تاریخ ایجاد</th><th></th></tr></thead><tbody>'
      +rowsHtml+'</tbody></table></div></div>';
  }

  var toolbarHtml = periodBar+runningBanner+'<div class="row" style="margin-bottom:12px;gap:12px">'
    +'<button class="btn primary"'+periodGateAttrs()+' onclick="dlgDevice()">+ پروندهٔ جدید</button>'
    +'<span class="muted">مرتب‌سازی: نیازمند اقدام در بالا · استعلام‌ها خودکار و بدون تکرار اجرا می‌شوند</span></div>';

  var f = periodFilterResolved();
  if (f === 'all') {
    var pers = periodSorted();
    var groups = [];
    var seenPeriods = {};
    pers.forEach(function(p, idx){
      seenPeriods[String(p.id)] = { period: p, devices: [], colorIndex: idx };
      groups.push(seenPeriods[String(p.id)]);
    });
    var noPeriod = { period: null, devices: [], colorIndex: groups.length };

    ds.forEach(function(d){
      var pid = String(d.period_id || '');
      if(pid && seenPeriods[pid]){
        seenPeriods[pid].devices.push(d);
      } else {
        noPeriod.devices.push(d);
      }
    });

    var cardsHtml = '';
    var activeGroupIndex = 0;
    groups.forEach(function(g){
      if(!g.devices.length) return;
      var rHtml = g.devices.map(function(d, i){ return deviceRowHtml(d, i); }).join('');
      cardsHtml += periodGroupCardHtml(g.period, rHtml, g.devices.length, g.colorIndex);
      activeGroupIndex++;
    });

    if(noPeriod.devices.length){
      var rHtml = noPeriod.devices.map(function(d, i){ return deviceRowHtml(d, i); }).join('');
      cardsHtml += periodGroupCardHtml(null, rHtml, noPeriod.devices.length, activeGroupIndex);
    }

    if(!cardsHtml){
      return toolbarHtml + searchEmptyCard();
    }
    return toolbarHtml + cardsHtml;
  } else {
    var targetPeriod = f === 'cur' ? activePeriod() : periodById(f);
    var rows = ds.map(function(d, i){ return deviceRowHtml(d, i); }).join('');
    if(targetPeriod){
      var colorIdx = (targetPeriod.number || 1) - 1;
      return toolbarHtml + periodGroupCardHtml(targetPeriod, rows, ds.length, colorIdx);
    }
    return toolbarHtml + '<div class="card tblcard"><div class="tbl-wrap"><table class="casetbl">'
      +'<thead><tr><th>ردیف</th><th>دستگاه</th><th>مشتری</th><th>مسافر</th><th>سریال</th><th>گام فعلی</th><th>وضعیت</th><th>شناسه پرونده</th><th>تاریخ ایجاد</th><th></th></tr></thead><tbody>'
      +rows+'</tbody></table></div></div>';
  }
}
function caseShotBtn(d,svc){
  var e=d.estelam||{}, has=svc==='hamta'?e.has_hamta_screenshot:e.has_gomrok_screenshot;
  if(!has)return '';
  var fa=svc==='hamta'?'همتا':'گمرک';
  return '<button type="button" class="ibtn" data-static="1" aria-label="مشاهدهٔ عکس نتیجهٔ '+fa+'"'
    +' data-tip="مشاهدهٔ عکس نتیجهٔ '+fa+'" onclick="event.stopPropagation();showCaseShot(\''+d.id+'\',\''+svc+'\')">'+ICONS.camera+'</button>';
}
function showCaseShot(id,svc){
  var d=(STATE.devices||[]).find(function(x){return String(x.id)===String(id);});
  var e=d&&d.estelam||{};
  var has=svc==='hamta'?e.has_hamta_screenshot:e.has_gomrok_screenshot;
  if(!d||!has){toast('عکس نتیجهٔ این استعلام موجود نیست',false);return;}
  var fa=svc==='hamta'?'همتا':'گمرک';
  /* Every capture overwrites the same file, so the URL never changes and the
     browser would serve the previous verdict's picture from cache. `cb` busts
     it; the route ignores parameters it does not know. */
  var src='/estelam-shot?id='+encodeURIComponent(id)+'&svc='+svc+'&cb='+Date.now();
  openDlg('<div class="case-shot-dialog">'
    +'<h3 style="margin:0 0 12px">عکس نتیجهٔ استعلام — '+fa+'</h3>'
    +'<div class="muted kbd" style="margin-bottom:12px">'+esc(d.serial1||'')+
      (d.serial2?' / '+esc(d.serial2):'')+'</div>'
    /* The error text lives inside the frame so a missing file replaces the
       picture in place, rather than leaving an empty frame above it. */
    +'<div class="case-shot-frame"><img id="case-shot-img" alt="عکس نتیجهٔ استعلام"'
      +' style="max-width:100%;height:auto;border-radius:10px;border:1px solid var(--line)">'
      +'<div id="case-shot-error" class="muted" hidden>عکس بارگذاری نشد — فایل پیدا نیست</div></div>'
    +'<div class="row" style="margin-top:12px"><a id="case-shot-download" class="btn mini ghost"'
      +' download="estelam-'+svc+'-'+esc(id)+'.png" href="'+src+'">دانلود عکس</a></div>'
    +'</div>');
  var img=document.getElementById('case-shot-img');
  var download=document.getElementById('case-shot-download');
  var err=document.getElementById('case-shot-error');
  img.onerror=function(){img.hidden=true;download.hidden=true;err.hidden=false;};
  img.src=src;
}
/* Case detail modal (v1.5 B7): every per-case action that used to sit on
   the card opens here — next-step continue card, step tools, quiet row
   (edit/back/skip/close/delete), inquiries, periodic opt-in/out, pay
   controls. Handlers are the existing card functions verbatim. After an
   action refresh() runs dlgCaseSync() which re-renders this modal on state
   change, and action callbacks restore it via dlgCaseRestore(id) after a
   child dialog replaced it. */
function caseDetail(id, silent){
  var d=(STATE.devices||[]).find(x=>x.id===id);
  if(!d){toast('پرونده پیدا نشد',false);return;}
  /* v1.8.1: where a close should return to. Entering from the period dialog
     arms «per:<pid>»; a REBUILD of the same case (the 5s sync, or a restore
     after a child dialog) keeps the origin it already had, so the way back
     survives an action taken inside the modal. closeDlg keeps the field alive
     for exactly as long as a case modal is being restored, and the tail of
     this function owns DLG_BACK — openDlg cannot tell a rebuild from a fresh
     open and would overwrite the origin with the case's own id. */
  var origin=CASE_MODAL.origin||(PER.live&&PER.pid?'per:'+PER.pid:'');
  var est=d.estelam||{};
  var pay=d.pay||{};
  var st=d.stage;
  var o=findOwner(d.owner_id)||{};
  var cont=stageContinue(d);
  var acts=stageActions(d).map(a=>a[0]?
    '<button class="btn mini '+(a[2]==='danger'?'danger':(a[2]==='primary'?'primary':(a[2]==='skip'?'warn':'ghost')))+'" onclick="devTick(\''+d.id+'\',\''+a[0]+'\')">'+(ICONS[a[3]]||'')+' '+a[1]+'</button>':'').join('');
  /* v1.5.x «قدم بعدی» card: the ONE primary action of the current step,
     full-width directly under the rail; unmet requirements render as warn
     chips next to the disabled button. Terminal states explain themselves;
     auto-advance cases show the non-action «خودکار» display instead. */
  var nextHtml='';
  if(st==='done'){
    nextHtml='<span class="muted" style="font-size:11px;font-weight:600">قدم بعدی</span>'
      +'<div class="muted">پرونده تکمیل شده — تاریخ تکمیل: '+esc(faDate(d.done_at))+'</div>';
  }else if(st==='closed'){
    nextHtml='<span class="muted" style="font-size:11px;font-weight:600">قدم بعدی</span>'
      +'<div class="muted">پرونده مختومه — قابل ادامه نیست</div>';
  }else if(st==='problem'){
    nextHtml='<span class="muted" style="font-size:11px;font-weight:600">قدم بعدی</span>'
      +'<div class="muted need">برای ادامه، اشکال این مرحله را رفع کنید و پرونده را به صف استعلام برگردانید.</div>'
      +'<button class="btn primary btn-continue" onclick="devRequeue(\''+d.id+'\')">بازگشت به صف</button>';
  }else if(cont){
    nextHtml='<span class="muted" style="font-size:11px;font-weight:600">قدم بعدی</span>';
    if((st==='handed'||st==='to_payment')&&d.auto_advance){
      nextHtml+='<span class="chip">خودکار</span>'
        +'<span class="muted">'+(st==='to_payment'
          ?'روبات پرداخت خودکار در جریان است — پس از گرفتن لینک، کنترل‌ها همین‌جا فعال می‌شوند'
          :'پس از ثبت دستگاه در گمرک، پرداخت خودکار آغاز می‌شود')+'</span>'
        +'<button class="btn primary btn-continue" disabled>خودکار در جریان است</button>';
    }else if(cont.ready){
      nextHtml+='<button class="btn primary btn-continue" onclick="stageContinueClick(\''+d.id+'\',this)">'+cont.label+'</button>';
    }else{
      var needs=cont.need?cont.need.split(' + ').filter(Boolean):[];
      var needChips=needs.length
        ?needs.map(function(x){return '<span class="pill warn">'+esc(x)+'</span>';}).join('')
        :'<span class="pill warn">هنوز آماده نیست</span>';
      nextHtml+='<div class="muted need">منتظر: '+needChips+'</div>'
        +'<button class="btn primary btn-continue" disabled title="'+esc(cont.need?'نیازمند: '+cont.need:'هنوز آماده نیست')+'">'+cont.label+' ⌛</button>';
    }
  }
  var payRow='';
  if(st==='payment'||st==='payment_done'||(st==='to_payment'&&d.profile_id)){
    var busy=pay.run_status==='busy';
    var autoChip=d.auto_advance?'<span class="chip">پرداخت خودکار</span>':'';
    if(st==='to_payment'&&!busy&&!d.auto_advance)
      payRow='<div class="payrow">'+autoChip+'<span class="muted">پرداخت دستی: با «شروع ربات پرداخت» لینک پرداخت گرفته می‌شود.</span></div>';
    else
      payRow='<div class="payrow">'+autoChip
        +(busy?'<span class="pill warn">ربات پرداخت در حال اجرا</span>':'')
        +(busy?'<button class="btn mini danger" onclick="payStop(\''+d.id+'\')">'+ICONS.stop+' توقف ربات پرداخت</button>':'')
        +(busy?'<button class="btn mini ghost" onclick="payBrowser(\''+d.id+'\','+(!pay.browser_visible)+')">'+(pay.browser_visible?ICONS.eyeOff+' مخفی کردن مرورگر':ICONS.eye+' نمایش مرورگر')+'</button>':'')
        +(pay.payment_link?'<a class="btn mini primary" target="_blank" href="'+esc(pay.payment_link)+'">'+ICONS.link+' لینک پرداخت</a>':'')
        +(pay.receipt_screenshot?'<a class="btn mini ghost" target="_blank" href="/artifact?id='+encodeURIComponent(d.profile_id)+'&kind=receipt">'+ICONS.receipt+' رسید</a>':'')
        +(pay.payment_screenshot?'<a class="btn mini ghost" target="_blank" href="/artifact?id='+encodeURIComponent(d.profile_id)+'&kind=payment">'+ICONS.card+' اسکرین پرداخت</a>':'')
        +'</div>';
  }
  /* v1.5.x: step tools in one group; v1.3.1 round 3 (operator request):
     every tool appears only on its own step — manual gomrok/hamta inquiries
     on step 2 (inquiry), telegram re-send on step 4 (handed), periodic watch
     toggle on step 5 (to_payment). The periodic tab still offers the watch
     toggle for every watched stage; the group hides when a step has none. */
  var toolsHtml=''
    +(d.stage==='inquiry'
      ?'<button class="btn mini ghost"'+gomrokGateAttrs()+' onclick="devInquire(\''+d.id+'\',\'gomrok\')">'+ICONS.search+' استعلام گمرک</button>'
       +'<button class="btn mini ghost" onclick="devInquire(\''+d.id+'\',\'hamta\')">'+ICONS.swap+' استعلام همتا</button>':'')
    +(d.stage==='to_payment'
      ?(d.periodic_opt_out
        ?'<button class="btn mini ghost" onclick="periodicReAdd(\''+d.id+'\')">'+ICONS.search+' افزودن به استعلام دوره‌ای</button>'
        :'<button class="btn mini ghost" onclick="periodicRemove(\''+d.id+'\')">'+ICONS.stop+' حذف از استعلام دوره‌ای</button>'):'')
    +(d.stage==='handed'
      ?'<button class="btn mini ghost" onclick="crmHandoffResend(\''+d.id+'\')">'+ICONS.send+' ارسال مجدد به تلگرام</button>':'')
    +(acts||'');
  /* v1.9.1: `silent` must be the SECOND argument, not a term in the string
     concatenation. Placed here it was added to the boolean and the whole
     modal body never reached dlgBody — the dialog opened as an empty 54px
     box with only the close button. */
  openDlg('<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 12px;padding-inline-end:34px">'
    +'<h3 style="margin:0;padding:0">'+esc(d.name)+'</h3>'
    +'<span class="pill '+(STAGE_TONE[st]||'n')+'">'+(STAGE_FA[st]||esc(st))+'</span>'
    +'<span class="chip kbd">'+esc(d.id)+'</span></div>'
    +'<div id="case-presence" class="cloud-notice" role="status" hidden></div>'
    +'<div style="margin:14px 0 6px">'+railHtml(d)+'</div>'
    +(nextHtml?'<div class="nextcard">'+nextHtml+'</div>':'')
    +'<div class="dlg-lbl">مسافر</div>'
    +'<div class="dlg-sec">'
    +ICONS.user+'<span class="chip">'+esc(ownerName(d.owner_id))+'</span>'
    +'<span class="chip">کد ملی: '+esc(o.national||'—')+'</span>'
    +'<span class="chip">تولد: '+esc(o.birth||'—')+'</span>'
    +'<span class="chip">موبایل: '+esc(o.mobile||'—')+'</span>'
    +'<span class="chip">کارت: '+esc(o.card_no||'—')+'</span>'
    +'<span class="chip">گذرنامه: '+esc(o.passport||'—')+'</span>'
    +'</div>'
    +'<div class="dlg-lbl">دستگاه</div>'
    +'<div class="dlg-sec">'
    +ICONS.dev+'<b>'+esc(d.name)+'</b>'
    +'<span class="chip" dir="ltr">'+esc(d.serial1)+(d.serial2?' / '+esc(d.serial2):'')+'</span>'
    +'<span class="chip">'+ICONS.user+esc(custName(d.customer_id))+'</span>'
    +(d.auto_advance?'<span class="chip">پرداخت خودکار</span>':'')
    +'</div>'
    +'<div class="kbd">ایجاد: '+esc(faDate(d.created))+' · آخرین تغییر: '+esc(faDateTime(d.updated))+(d.done_at?' · تکمیل: '+esc(faDate(d.done_at)):'')+'</div>'
    +(d.notes?'<div class="kbd">یادداشت: '+esc(d.notes)+'</div>':'')
    +'<div class="dlg-lbl">استعلام</div>'
    +'<div class="dlg-sec">'
    +'<span class="pill '+((d.stage==='inquiry'&&est.status==='advanced')?'bad':(EST_PILL[est.status]||'n'))+'">استعلام: '
    +((d.stage==='inquiry'&&est.status==='advanced')?'ثبت‌شده در گمرک — خطر!':(EST_FA[est.status]||esc(est.status||'—')))+'</span>'
    +(est.hamta_status?'<span class="pill '+(HAMTA_PILL[est.hamta_status]||'n')+'">همتا: '+(HAMTA_FA_CARD[est.hamta_status]||esc(est.hamta_status))+'</span>':'')
    +'</div>'
    +(est.result?'<div class="kbd">نتیجه: '+esc(est.result)+'</div>':'')
    +'<div class="kbd">آخرین استعلام: '+esc(faDateTime(d.last_inquiry_at))+'</div>'
    +(toolsHtml?'<div class="grp"><div class="grp-lbl">ابزار این گام</div>'
      +'<div class="tools">'+toolsHtml+'</div></div>':'')
    +(payRow?'<div class="grp"><div class="grp-lbl">پرداخت</div>'+payRow+'</div>':'')
    +'<div class="grp grp-quiet"><div class="grp-lbl">سایر اقدامات</div>'
    +'<div class="quiet">'
    +'<button class="btn mini ghost" onclick="dlgDeviceEdit(\''+d.id+'\')">ویرایش پرونده</button>'
    +'<button class="btn mini ghost" onclick="window.open(\'/crm-invoice?device_id='+d.id+'&fmt=html\',\'_blank\')">'+ICONS.doc+' فاکتور</button>'
    +(STAGE_BACK_FA[st]?'<button class="btn mini ghost" onclick="devTick(\''+d.id+'\',\'__stage_back\')">↩ برگشت به «'+STAGE_BACK_FA[st]+'»</button>':'')
    +(STAGE_SKIP_WARN[st]?'<button class="btn mini ghost" onclick="devTick(\''+d.id+'\',\'__skip\')">رد کردن این مرحله</button>':'')
    +((st==='inquiry'||st==='problem')?'<button class="btn mini danger" onclick="devTick(\''+d.id+'\',\'__close_case\')">مختومه کردن</button>':'')
    +'<button class="btn mini danger" onclick="devDelete(\''+d.id+'\')">حذف پرونده</button>'
    +'</div></div>', silent);
  /* openDlg clears CASE_MODAL.live, so (re)arm the sync state only here. */
  CASE_MODAL.id=id;CASE_MODAL.name=d.name;CASE_MODAL.live=true;CASE_MODAL.sig=dlgCaseSig(d);
  /* v1.8.1: and re-arm the return to where this case was opened from — a
     rebuild that dropped it would strand the operator (openDlg armed the
     self-return only, so this must come after it). */
  CASE_MODAL.origin=origin;DLG_BACK=origin;
  presenceStart('crm_devices',id);
}
/* v1.5 B10: manual re-send of the registration handoff (case detail modal).
   The route re-checks stage/destination/passport server-side; a failed send
   keeps the case untouched and surfaces the Persian notice in red. */
function crmHandoffResend(id){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  api('/crm-handoff-resend',{device_id:id}).then(async r=>{
    if(r.ok){toastCtx(cn,'اطلاعات ثبت به تلگرام ارسال شد');}
    else{toastCtx(cn,r.notice||'ارسال مجدد به تلگرام انجام نشد',false);}
    await refresh();
  }).catch(e=>toastCtx(cn,String(e),false));
}
/* ================= left summary rail (v1.1.5) ================= */
function sumBalPill(id){
  var b=bal(id);
  if(bal(id)<0)return '<span class="pill bad">بدهکار '+money(b)+'</span>';
  if(b>0)return '<span class="pill ok">'+money(b)+'</span>';
  return '<span class="pill n">تسویه</span>';
}
function sumCustomersHtml(){
  var cs=(STATE.customers||[]).slice()
    .sort((a,b)=>String(b.created||'').localeCompare(String(a.created||'')));
  if(!cs.length)return '<div class="muted">هنوز مشتری‌ای ثبت نشده است.</div>';
  return '<div class="sumbox">'+cs.slice(0,5).map(c=>
    '<div class="sumrow" onclick="dlgCustomer(\'edit\',\''+c.id+'\')">'
    +'<span class="nm">'+esc(c.full_name)+'</span>'
    +'<span class="kbd">'+esc(c.mobile||'—')+'</span>'
    +sumBalPill(c.id)+'</div>').join('')+'</div>';
}
function sumCasesHtml(){
  var ds=(STATE.devices||[]).slice()
    .sort((a,b)=>String(b.updated||'').localeCompare(String(a.updated||'')));
  if(!ds.length)return '<div class="muted">هنوز پرونده‌ای ثبت نشده است.</div>';
  return '<div class="sumbox">'+ds.slice(0,5).map(d=>
    '<div class="sumrow" onclick="sumFocusDevice(\''+d.id+'\')">'
    +'<span class="dot" style="background:var(--'+(STAGE_TONE[d.stage]==='bad'?'danger':(STAGE_TONE[d.stage]==='ok'?'ok':(STAGE_TONE[d.stage]==='warn'?'warn':'muted')))+')"></span>'
    +'<span class="nm">'+esc(d.name||d.serial1||'')+'</span>'
    +'<span class="kbd">'+esc(d.serial1||'')+'</span>'
    +'<span class="pill '+(STAGE_TONE[d.stage]||'n')+'">'+(STAGE_FA[d.stage]||esc(d.stage))+'</span>'
    +'</div>').join('')+'</div>';
}
function sumFocusDevice(id){
  /* v1.5 B7: route to the tab owning this case before focusing — done/
     problem/closed rows live in their own tabs now, so the old
     devices-only retry loop would spin forever. One delayed retry covers
     the post-setTab render; devRow ids are tried too (done/problem tabs). */
  var d=(STATE.devices||[]).find(x=>x.id===id);
  var st=d?d.stage:'';
  if(st==='done')setTab('done_tab');
  else if(st==='problem')setTab('problem_tab');
  else if(st==='closed')setTab('closed_tab');
  else setTab('devices');
  function flashRow(){
    var el=document.getElementById('devcard-'+id)||document.getElementById('devrow-'+id);
    if(!el)return false;
    el.scrollIntoView({behavior:'smooth',block:'center'});
    el.classList.add('flash');
    setTimeout(function(){el.classList.remove('flash');},1700);
    return true;
  }
  if(!flashRow())setTimeout(flashRow,250);
}
function sumDebtorsHtml(){
  var ds=(STATE.customers||[]).filter(c=>bal(c.id)<0)
    .sort((a,b)=>bal(a.id)-bal(b.id));
  if(!ds.length)return '<div class="muted">مشتری بدهکاری نیست.</div>';
  var rows=ds.slice(0,5).map(c=>
    '<div class="sumrow" onclick="dlgCustomer(\'edit\',\''+c.id+'\')">'
    +'<span class="nm">'+esc(c.full_name)+'</span>'
    +'<span class="pill bad">'+money(bal(c.id))+'</span></div>').join('');
  if(ds.length>5)rows+='<div class="muted" style="margin-top:6px">… و '+fa(ds.length-5)+' مورد دیگر</div>';
  return '<div class="sumbox">'+rows+'</div>';
}
function devicesRailHtml(){
  return '<div class="card"><h4>جدیدترین مشتری‌ها</h4>'+sumCustomersHtml()+'</div>'
    +'<div class="card"><h4>پرونده‌های اخیر</h4>'+sumCasesHtml()+'</div>'
    +'<div class="card"><h4>بیشترین بدهکاری</h4>'+sumDebtorsHtml()+'</div>';
}
function emptyInnerHtml(title,sub){
  return '<div class="empty"><span class="eic">'+ICONS.inbox+'</span><b>'+esc(title)+'</b>'
    +'<span class="esub">'+esc(sub)+'</span></div>';
}
function emptyHtml(title,sub){
  return '<div class="card">'+emptyInnerHtml(title,sub)+'</div>';
}

/* ================= customers ================= */
function customersHtml(){
  var q=tabQ();
  var cs=(STATE.customers||[]).filter(c=>tabSearchMatches(
    [c.full_name,c.mobile,c.telegram_id,c.instagram_id,c.address,c.notes].join(' '),q));
  /* v1.9.0: newest customer on top. The filter has already run, so TAB_COUNT
     and the rows stay in step. */
  cs=newestFirst(cs,c=>c.created);
  TAB_COUNT=cs.length;
  var rows=cs.map(c=>
    '<tr><td><b>'+esc(c.full_name)+'</b></td><td class="kbd">'+esc(c.mobile||'—')+'</td>'
    +'<td class="kbd">'+esc(c.telegram_id||'—')+' / '+esc(c.instagram_id||'—')+'</td>'
    +'<td class="kbd">'+esc(c.address||'—')+'</td>'
    +'<td>'+(bal(c.id)<0?'<span class="pill bad">بدهکار '+money(bal(c.id))+'</span>'
             :(bal(c.id)>0?'<span class="pill ok">'+money(bal(c.id))+'</span>':'<span class="pill n">تسویه</span>'))+'</td>'
    +'<td><div class="ibacts">'
    +'<button type="button" class="ibtn" data-static="1" aria-label="ویرایش مشتری" data-tip="ویرایش مشتری" onclick="dlgCustomer(\'edit\',\''+c.id+'\')">'+ICONS.edit+'</button>'
    +'<button type="button" class="ibtn" data-static="1" aria-label="صورت‌حساب مشتری" data-tip="صورت‌حساب مشتری" onclick="dlgStatement(\''+c.id+'\')">'+ICONS.list+'</button>'
    +'<button type="button" class="ibtn ok" data-static="1" aria-label="ثبت دریافتی" data-tip="ثبت دریافتی" onclick="dlgReceipt(\''+c.id+'\')">'+ICONS.receipt+'</button>'
    +'<button type="button" class="ibtn warn" data-static="1" aria-label="ثبت بدهی" data-tip="ثبت بدهی" onclick="dlgDebt(\''+c.id+'\')">'+ICONS.money+'</button>'
    +'<button type="button" class="ibtn danger" aria-label="حذف مشتری" data-tip="حذف مشتری" onclick="custDelete(\''+c.id+'\')">'+ICONS.trash+'</button>'
    +'</div></td></tr>').join('');
  return '<div class="card"><div class="row" style="margin-bottom:10px">'
    +'<button class="btn" onclick="dlgFinance()">'+ICONS.wallet+' گزارش مالی</button>'
    +'<button class="btn primary" onclick="dlgCustomer(\'add\')">+ مشتری جدید</button></div>'
    +'<table><thead><tr><th>نام</th><th>موبایل</th><th>تلگرام / اینستا</th><th>آدرس</th><th>مانده</th><th></th></tr></thead>'
    +'<tbody>'+(rows||'<tr><td colspan="6">'+(searchActive()?searchEmptyHtml():emptyInnerHtml('مشتری ثبت نشده است','مشتری‌ها را از تلگرام، اینستاگرام یا تماس تلفنی اضافه کنید.'))+'</td></tr>')+'</tbody></table></div>';
}

/* ================= owners ================= */
function archivedIds(){
  // v1.7: passengers whose case is delivered (done) move to the archive tab.
  return (STATE.archived_owners||[]).map(r=>r.owner.id);
}
function ownersHtml(){
  var q=tabQ();
  var arch=archivedIds();
  var os=(STATE.owners||[]).filter(o=>!arch.includes(o.id)).filter(o=>{
    var dev=(STATE.devices||[]).find(d=>d.owner_id===o.id);
    return tabSearchMatches([o.first_name,o.last_name,o.national,o.birth,o.mobile,o.card_no,o.passport,dev?dev.name:''].join(' '),q);
  });
  var archCount=arch.length;
  /* v1.9.0 (operator request): newest passenger on top, numbered like the
     case table — fa(i+1) over the FILTERED, SORTED list, so the numbers start
     at ۱ and hold still across the 5s re-render. */
  os=newestFirst(os,o=>o.created);
  TAB_COUNT=os.length;
  var rows=os.map((o,i)=>{
    var dev=(STATE.devices||[]).find(d=>d.owner_id===o.id);
    return '<tr><td class="kbd">'+fa(i+1)+'</td>'
    +'<td><b>'+esc(o.first_name+' '+o.last_name)+'</b></td>'
    +'<td class="kbd">'+esc(o.national)+'</td><td class="kbd">'+esc(o.birth)+'</td>'
    +'<td class="kbd">'+esc(o.mobile)+'</td><td class="kbd">'+esc(o.card_no)+'</td>'
    +'<td>'+(dev?'<span class="pill n">'+esc(dev.name)+'</span> <span class="pill ok">متصل</span>':'<span class="pill warn">آزاد</span>')+'</td>'
    +'<td><div class="ibacts">'
    +'<button type="button" class="ibtn" data-static="1" aria-label="ویرایش مسافر" data-tip="ویرایش مسافر" onclick="dlgOwner(\'edit\',\''+o.id+'\')">'+ICONS.edit+'</button>'
    +(dev&&dev.stage!=='done'?'<button type="button" class="ibtn warn" data-static="1" aria-label="قطع اتصال" data-tip="قطع اتصال" onclick="dlgDetach(\''+o.id+'\')">'+ICONS.unlink+'</button>':'')
    +(dev?'':'<button type="button" class="ibtn danger" aria-label="حذف مسافر" data-tip="حذف مسافر" onclick="ownerDelete(\''+o.id+'\')">'+ICONS.trash+'</button>')+'</div></td></tr>';
  }).join('');
  return '<div class="card"><div class="row" style="margin-bottom:10px">'
    +'<button class="btn primary" onclick="dlgOwner(\'add\')">+ مسافر جدید</button>'
    +(archCount?'<button class="btn" onclick="setTab(\'owner_archive\')">بایگانی: '+fa(archCount)+' مسافر</button>':'')
    +'<span class="muted">کد ملی با رقم کنترلی بررسی می‌شود؛ سن ۱۵ تا ۹۹ سال مجاز است.</span></div>'
    +'<table><thead><tr><th>ردیف</th><th>نام</th><th>کد ملی</th><th>تولد</th><th>موبایل</th><th>کارت</th><th>دستگاه</th><th></th></tr></thead>'
    +'<tbody>'+(rows||'<tr><td colspan="8">'+(searchActive()?searchEmptyHtml():(archCount?emptyInnerHtml('مسافر فعالی نیست','همهٔ مسافر‌ها در بایگانی هستند؛ به تب «بایگانی مسافر‌ها» بروید.'):emptyInnerHtml('مسافری ثبت نشده است','مشخصات مسافر برای ثبت پرونده، تحویل و ثبت‌نام لازم است.')))+'</td></tr>')+'</tbody></table></div>';
}

/* ================= owner archive (v1.7) ================= */
/* Passengers whose case reached completion leave the active owners tab
   and land here with their delivered case, serials and completion dates.
   The list is computed server-side; a stage rollback from done returns
   the passenger to the active list automatically. */
function ownerArchiveHtml(){
  var q=tabQ();
  var rows=(STATE.archived_owners||[]).filter(r=>
    tabSearchMatches([r.owner.first_name,r.owner.last_name,r.owner.national,
      r.owner.birth,r.owner.mobile,r.owner.passport,r.device?r.device.name:'',
      r.customer_name].join(' '),q));
  TAB_COUNT=rows.length;
  /* v1.9.0 (operator request): the same numbering as the active passenger
     list. The ORDER is the server's — crm.archived_owners sorts by done_at
     DESC — so numbering the filtered list is all this surface needs. */
  var tr=rows.map((r,i)=>{
    var o=r.owner, d=r.device||{};
    var serials=[d.serial1,d.serial2].filter(Boolean).join(' / ');
    return '<tr><td class="kbd">'+fa(i+1)+'</td>'
    +'<td><b>'+esc(o.first_name+' '+o.last_name)+'</b></td>'
    +'<td class="kbd">'+esc(o.national)+'</td>'
    +'<td class="kbd">'+esc(o.birth)+'</td>'
    +'<td class="kbd">'+esc(o.mobile||'—')+'</td>'
    +'<td><b>'+esc(d.name||'—')+'</b>'
    +(serials?'<div class="kbd" dir="ltr">'+esc(serials)+'</div>':'')+'</td>'
    +'<td>'+esc(r.customer_name||'—')+'</td>'
    +'<td class="kbd">'+esc(faDateTime(r.code_delivered_at||r.done_at||''))+'</td>'
    +'<td><div class="ibacts">'
    +'<button type="button" class="ibtn" data-static="1" aria-label="ویرایش مسافر" data-tip="ویرایش مسافر" onclick="dlgOwner(\'edit\',\''+o.id+'\')">'+ICONS.edit+'</button>'
    +'<button type="button" class="ibtn" data-static="1" aria-label="جزئیات پرونده" data-tip="جزئیات پرونده" onclick="caseDetail(\''+d.id+'\')">'+ICONS.eye+'</button>'
    +'</div></td></tr>';
  }).join('');
  return '<div class="card"><div class="row" style="margin-bottom:10px">'
    +'<span class="pill ok">'+fa(rows.length)+' مسافر تکمیل‌شده</span>'
    +'<span class="muted">مسافرانی که کد فعال‌سازی تحویل شده و پروندهٔ آن‌ها تکمیل شده است. با بازگرداندن پرونده به گام قبل، مسافر به‌صورت خودکار به لیست فعال برمی‌گردد.</span></div>'
    +'<table><thead><tr><th>ردیف</th><th>نام</th><th>کد ملی</th><th>تولد</th><th>موبایل</th><th>دستگاه</th><th>مشتری</th><th>تاریخ تحویل کد</th><th></th></tr></thead>'
    +'<tbody>'+(tr||'<tr><td colspan="9">'+(searchActive()?searchEmptyHtml():emptyInnerHtml('هنوز مسافری بایگانی نشده است','با تکمیل پروندهٔ یک مسافر، او به‌صورت خودکار اینجا ظاهر می‌شود.'))+'</td></tr>')+'</tbody></table></div>';
}

/* ================= periodic gomrok inquiry tab ================= */
var PERIODIC_STAGES = {'handed':1,'to_payment':1,'payment':1,'payment_done':1};
function periodicDevices(){
  return (STATE.devices||[]).filter(d=>PERIODIC_STAGES[d.stage]);
}
function periodicSaveInterval(){
  var raw=document.getElementById('periodicInterval').value;
  api('/crm-settings',{watch_interval_hours:raw}).then(async r=>{
    toast('بازهٔ استعلام ذخیره شد: هر '+fa(r.settings.watch_interval_hours)+' ساعت');await refresh();})
    .catch(e=>toast(e,false));
}
function periodicToggle(){
  /* v1.6.1: the tab-level kill-switch for the periodic scheduler. The
     server beat (crm_periodic_scan) already no-ops while
     settings.scheduler_enabled is false; manual runs stay available. */
  api('/crm-settings',{scheduler_enabled:!(STATE.settings||{}).scheduler_enabled}).then(async r=>{
    toast(r.settings.scheduler_enabled?'استعلام دوره‌ای فعال شد.':'استعلام دوره‌ای غیرفعال شد.');await refresh();})
    .catch(e=>toast(e,false));
}
function periodicSelIds(){
  return (STATE.devices||[]).filter(d=>d.id &&
    document.getElementById('periodicSel'+d.id) &&
    document.getElementById('periodicSel'+d.id).checked).map(d=>d.id);
}
function periodicSelAll(master){
  (periodicDevices()||[]).forEach(d=>{
    var box=document.getElementById('periodicSel'+d.id);
    if(box)box.checked=!!master.checked;
  });
}
/* Bulk /crm-inquiry answers 200 with per-device results; surface the first
   backend error instead of a bare «شروع نشد» so a fail-closed start (e.g.
   empty identity pool) tells the operator why. */
function inquiryBulkToast(r){
  if(r.ok){toast('استعلام برای '+fa(r.queued)+' دستگاه شروع شد');return;}
  var firstErr='';
  (r.results||[]).forEach(function(x){
    if(!firstErr&&x&&x.errors&&x.errors.length)firstErr=String(x.errors[0]);
  });
  toast(firstErr||'استعلام شروع نشد',false);
}
function periodicRunSelected(){
  var ids=periodicSelIds();
  if(!ids.length){toast('دستگاهی انتخاب نشده است',false);return;}
  confirmDlg('استعلام گروهی','استعلام گمرک برای '+fa(ids.length)+' دستگاه انتخاب‌شده اجرا شود؟',
    'شروع',function(){
      api('/crm-inquiry',{service:'gomrok',device_ids:ids}).then(async r=>{
        inquiryBulkToast(r);await refresh();})
        .catch(e=>toast(e,false));
    });
}
function periodicResetSelected(){
  var ids=periodicSelIds();
  if(!ids.length){toast('دستگاهی انتخاب نشده است',false);return;}
  confirmDlg('ریست تاریخچهٔ گروهی','تاریخچهٔ استعلام '+fa(ids.length)+' دستگاه پاک شود؟ نتیجهٔ فعلی و زمان آخرین استعلام حذف می‌شود.',
    'ریست',function(){
      api('/crm-inquiry-reset',{device_ids:ids}).then(async r=>{
        toast(r.ok?'تاریخچهٔ استعلام ریست شد':'انجام نشد',r.ok);await refresh();})
        .catch(e=>toast(e,false));
    });
}
/* ---- periodic add-devices modal (search + pagesize + pagination) ---- */
var PA_PAGE=1, PA_SIZE=10, PA_Q='';
function periodicAddModal(){
  PA_PAGE=1;PA_Q='';
  openDlg('<h3>افزودن پرونده به استعلام دوره‌ای</h3>'
    +'<div class="row" style="margin:0 0 10px">'
    +'<input id="paQ" placeholder="جستجو: نام یا سریال…" style="flex:1" oninput="paSearch(this.value)">'
    +'<select id="paSize" onchange="paSize(this.value)"><option value="10">۱۰ تایی</option>'
    +'<option value="20">۲۰ تایی</option><option value="30">۳۰ تایی</option></select></div>'
    +'<div id="paBody"></div><div id="paNav" class="row" style="margin-top:8px"></div>'
    +'<div class="row" style="margin-top:10px">'
    +'<button class="btn primary" onclick="paAddSelected()">افزودن به استعلام دوره‌ای</button>'
    +'<button class="btn" onclick="closeDlg()">انصراف</button></div>');
  paRender();
}
function paSearch(q){PA_Q=String(q||'').trim();PA_PAGE=1;paRender();}
function paSize(v){PA_SIZE=Math.max(1,Number(v)||10);PA_PAGE=1;paRender();}
function paDevices(){
  return (STATE.devices||[]).filter(d=>{
    if(!PERIODIC_STAGES[d.stage])return false;
    if(!PA_Q)return true;
    var hay=(String(d.name||'')+' '+String(d.serial1||'')+' '+String(d.serial2||''));
    return hay.indexOf(PA_Q)>=0;
  });
}
function paRender(){
  var body=document.getElementById('paBody'),nav=document.getElementById('paNav');
  if(!body)return;
  /* v1.9.0: newest case first, so page ۱ is the NEWEST page. The pager itself
     is untouched — same PA_SIZE, same page numbers, same clamp below. */
  var all=newestFirst(paDevices(),d=>d.created);
  var pages=Math.max(1,Math.ceil(all.length/PA_SIZE));
  if(PA_PAGE>pages)PA_PAGE=pages;
  var slice=all.slice((PA_PAGE-1)*PA_SIZE,PA_PAGE*PA_SIZE);
  var rows=slice.map(d=>{
    var on=!d.periodic_opt_out;
    return '<label class="row" style="margin:0 0 6px;align-items:center;gap:8px">'
      +'<input type="checkbox" class="paSel" value="'+esc(d.id)+'" '+(on?'checked':'')+'>'
      +'<b>'+esc(d.name)+'</b><span class="kbd">'+esc(d.serial1)+(d.serial2?' / '+esc(d.serial2):'')+'</span>'
      +(on?'<span class="pill ok">در لیست</span>':'<span class="pill n">خارج از لیست</span>')
      +'</label>';
  }).join('');
  body.innerHTML=rows||('<div class="empty"><span class="eic">'+ICONS.inbox+'</span><span class="esub">پرونده‌ای برای افزودن نیست — فقط پرونده‌های «تحویل به مسئول سایت» و بعدی به استعلام دوره‌ای می‌روند.</span></div>');
  var navHtml='';
  if(pages>1){
    for(var p=1;p<=pages;p++)
      navHtml+='<button class="btn mini '+(p===PA_PAGE?'primary':'ghost')+'" onclick="paGo('+p+')">'+fa(p)+'</button>';
  }
  nav.innerHTML=navHtml+'<span class="muted">'+fa(all.length)+' پرونده</span>';
}
function paGo(p){PA_PAGE=p;paRender();}
function paAddSelected(){
  var boxes=[].slice.call(document.querySelectorAll('#paBody .paSel:checked'));
  if(!boxes.length){toast('پرونده‌ای انتخاب نشده است',false);return;}
  var jobs=boxes.map(b=>api('/crm-periodic',{device_id:b.value,remove:false}));
  Promise.all(jobs).then(async()=>{
    closeDlg();toast('به استعلام دوره‌ای اضافه شد');await refresh();
  }).catch(e=>toast(e,false));
}

function periodicResetOne(id){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  confirmDlg('ریست تاریخچهٔ استعلام','تاریخچهٔ استعلام این دستگاه پاک شود؟ نتیجهٔ فعلی و زمان آخرین استعلام حذف می‌شود.',
    'ریست',function(){
      api('/crm-inquiry-reset',{device_ids:[id]}).then(async r=>{
        toastCtx(cn,r.ok?'تاریخچه ریست شد':'ریست انجام نشد',r.ok);await refresh();})
        .catch(e=>toastCtx(cn,String(e),false));
    });
}
function periodicReInquire(id){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  confirmDlg('استعلام مجدد','ابتدا تاریخچهٔ استعلام ریست و سپس استعلام گمرک بلافاصله اجرا شود؟',
    'اجرا',function(){
      api('/crm-inquiry-reset',{device_ids:[id],restart:true}).then(async r=>{
        toastCtx(cn,r.ok?'استعلام مجدد شروع شد':'انجام نشد',r.ok);await refresh();})
        .catch(e=>toastCtx(cn,String(e),false));
    });
}
function periodicRunAll(){
  var ids=periodicDevices().filter(d=>!d.periodic_opt_out).map(d=>d.id);
  if(!ids.length){toast('دستگاهی در لیست نیست',false);return;}
  confirmDlg('شروع فوری استعلام','استعلام گمرک برای '+fa(ids.length)+' دستگاه همین حالا اجرا شود؟',
    'شروع',function(){
      api('/crm-inquiry',{service:'gomrok',device_ids:ids}).then(async r=>{
        inquiryBulkToast(r);await refresh();})
        .catch(e=>toast(e,false));
    });
}
function periodicRunOne(id){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  confirmDlg('اجرای فوری','استعلام گمرک همین حالا برای این دستگاه اجرا شود؟','اجرا',function(){
    api('/crm-inquire',{device_id:id,service:'gomrok'}).then(async r=>{
      toastCtx(cn,'استعلام شروع شد');await refresh();}).catch(e=>toastCtx(cn,String(e),false));
  });
}
function periodicRemove(id){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  var wasModal=CASE_MODAL.live&&CASE_MODAL.id===id;
  confirmDlg('حذف از استعلام دوره‌ای','دستگاه از استعلام دوره‌ای حذف شود؟ استعلام خودکار دیگر برایش اجرا نمی‌شود.',
    'حذف',function(){
      api('/crm-periodic',{device_id:id,remove:true}).then(async()=>{
        toastCtx(cn,'از استعلام دوره‌ای حذف شد');await refresh();if(wasModal)caseDetail(id);})
        .catch(e=>{toastCtx(cn,String(e),false);if(wasModal)caseDetail(id);});
    });
}
function periodicReAdd(id){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  api('/crm-periodic',{device_id:id,remove:false}).then(async()=>{
    toastCtx(cn,'دوباره به استعلام دوره‌ای اضافه شد');await refresh();}).catch(e=>toastCtx(cn,String(e),false));
}
function periodicHistory(id){
  var d=(STATE.devices||[]).find(x=>x.id===id);
  var logs=(STATE.periodic_logs||[]).filter(l=>String(l.device_id||'')===String(id));
  var rows=logs.map(l=>'<tr><td class="kbd">'+esc(faDateTime(l.ts))+'</td><td><span class="pill '+
    (EST_PILL[l.status]||'n')+'">'+(EST_FA[l.status]||esc(l.status||''))+'</span></td>'+
    '<td class="muted">'+esc(l.message||'')+'</td></tr>').join('');
  openDlg('<h3>تاریخچهٔ استعلام — '+esc((d||{}).name||id)+'</h3>'
    +(d&&d.last_inquiry_at?'<p class="muted">آخرین استعلام: '+esc(faDateTime(d.last_inquiry_at))+' · نتیجهٔ فعلی: '+
      (EST_FA[(d.estelam||{}).status]||'—')+'</p>':'')
    +'<table><thead><tr><th>زمان</th><th>وضعیت</th><th>پیام</th></tr></thead><tbody>'+
    (rows||'<tr><td colspan="3">'+emptyInnerHtml('تاریخچه‌ای ثبت نشده است','هنوز استعلامی برای این دستگاه اجرا نشده.')+'</td></tr>')+
    '</tbody></table>');
}
function periodicHtml(){
  var settings=(STATE.settings||{});
  var schedOn=!!settings.scheduler_enabled;
  var hours=settings.watch_interval_hours||2;
  var full=periodicDevices();
  /* v1.9.0: newest case first, but only for the ROWS — `full` keeps its store
     order for the active/total counts printed in the toolbar. */
  var all=newestFirst(filterDevRows(full),d=>d.created);
  TAB_COUNT=all.length;
  var rows=all.map(d=>{
    var est=d.estelam||{};
    var opt=d.periodic_opt_out;
    var statusPill='<span class="pill '+(opt?'n':(EST_PILL[est.status]||'n'))+'">'+
      (opt?'خارج از لیست':(EST_FA[est.status]||'—'))+'</span>';
    // payment/payment_done are NEVER auto-inquired (the scheduler watch set is
    // handed/to_payment only): show a manual-only badge instead of a due
    // countdown that would imply a scheduled run (v1.5 review item 3).
    var due=!schedOn
      ?'<span class="pill n">زمان‌بند خاموش</span>'
      :(d.stage==='payment'||d.stage==='payment_done')
      ?'<span class="pill n">فقط دستی</span>':dueIn(d,hours);
    return '<tr'+(opt?' style="opacity:.55"':'')+'><td><input type="checkbox" id="periodicSel'+d.id+'" class="periodicSel"></td>'+
      '<td><b>'+esc(d.name)+'</b>'+
      '<div class="kbd">'+esc(d.serial1)+'</div></td>'+
      '<td><span class="pill '+(STAGE_TONE[d.stage]||'n')+'">'+(STAGE_FA[d.stage]||esc(d.stage))+'</span></td>'+
      '<td>'+statusPill+'</td>'+
      '<td><span class="pill '+(HAMTA_PILL[est.hamta_status]||'n')+'">'+(HAMTA_FA_CARD[est.hamta_status]||'—')+'</span></td>'+
      '<td class="kbd">'+esc(faDateTime(d.last_inquiry_at))+'</td>'+
      '<td class="kbd">'+due+'</td>'+
      '<td><div class="ibacts">'+
      '<button type="button" class="ibtn ghost" data-static="1" aria-label="تاریخچه" data-tip="تاریخچه" onclick="periodicHistory(\''+d.id+'\')">'+ICONS.clock+'</button>'+
      '<button type="button" class="ibtn warn" aria-label="اجرای فوری" data-tip="اجرای فوری"'+gomrokGateAttrs()+' onclick="periodicRunOne(\''+d.id+'\')" '+(STATE.estelam_running?'disabled':'')+'>'+ICONS.play+'</button>'+
      '<button type="button" class="ibtn danger" aria-label="ریست تاریخچه" data-tip="ریست تاریخچه" onclick="periodicResetOne(\''+d.id+'\')" '+(STATE.estelam_running?'disabled':'')+'>'+ICONS.rewind+'</button>'+
      '<button type="button" class="ibtn ok" aria-label="استعلام مجدد" data-tip="استعلام مجدد"'+gomrokGateAttrs()+' onclick="periodicReInquire(\''+d.id+'\')" '+(STATE.estelam_running?'disabled':'')+'>'+ICONS.refresh+'</button>'+
      (opt?'<button type="button" class="ibtn primary" aria-label="افزودن به استعلام دوره‌ای" data-tip="افزودن به استعلام دوره‌ای" onclick="periodicReAdd(\''+d.id+'\')">'+ICONS.plus+'</button>'
          :'<button type="button" class="ibtn danger" aria-label="حذف از لیست" data-tip="حذف از لیست" onclick="periodicRemove(\''+d.id+'\')">'+ICONS.trash+'</button>')+'</div></td></tr>';
  }).join('');
  var logs=(STATE.periodic_logs||[]).slice(0,60).map(l=>'<tr><td class="kbd">'+esc(faDateTime(l.ts))+'</td>'+
    '<td><b>'+esc((STATE.devices||[]).find(d=>String(d.id)===String(l.device_id))?.name||l.device_id||'—')+'</b></td>'+
    '<td><span class="pill '+(EST_PILL[l.status]||'n')+'">'+(EST_FA[l.status]||esc(l.status||''))+'</span></td>'+
    '<td class="muted">'+esc(l.message||'')+'</td></tr>').join('');
  var activeCount=full.filter(d=>!d.periodic_opt_out).length;
  return '<div class="card"><div class="row" style="margin-bottom:10px;flex-wrap:wrap;gap:8px">'+
    '<span class="pill '+(schedOn?'ok':'bad')+'">استعلام دوره‌ای: '+(schedOn?'فعال':'غیرفعال')+'</span>'+
    (schedOn?'<button class="btn warn" onclick="periodicToggle()">غیرفعال کردن</button>'
            :'<button class="btn primary" onclick="periodicToggle()">فعال کردن</button>')+
    '<label class="f" style="flex-direction:row;align-items:center;gap:6px">بازهٔ استعلام دوره‌ای (ساعت): '+
    '<input id="periodicInterval" class="ltr" style="width:64px" type="number" min="1" max="72" value="'+hours+'" inputmode="numeric">'+
    '</label><button class="btn" onclick="periodicSaveInterval()">ذخیره بازه</button>'+
    '<button class="btn primary"'+gomrokGateAttrs()+' onclick="periodicRunAll()" '+(STATE.estelam_running?'disabled':'')+'>شروع فوری استعلام</button>'+
    '<button class="btn"'+gomrokGateAttrs()+' onclick="periodicRunSelected()" '+(STATE.estelam_running?'disabled':'')+'>استعلام انتخاب‌شده‌ها</button>'+
    '<button class="btn warn" onclick="periodicResetSelected()">ریست تاریخچهٔ انتخاب‌شده‌ها</button>'+
    '<button class="btn" onclick="periodicAddModal()">+ افزودن پرونده</button>'+
    '<span class="muted">'+fa(activeCount)+' دستگاه فعال از '+fa(full.length)+' دستگاه در این مرحله'+(STATE.estelam_running?' — <b>'+fa(STATE.estelam_runs?STATE.estelam_runs.length:1)+' اجرا در جریان است</b>':'')+'</span>'+
    '<span class="muted">استعلام خودکار فقط برای مراحل «تحویل به مسئول ثبت» و «استعلام ثبت‌بودن» اجرا می‌شود؛ مراحل پرداخت فقط دستی‌اند.</span></div>'+
    (schedOn?'':'<p class="muted" style="margin:0 0 10px">استعلام دوره‌ای غیرفعال است؛ زمان‌بند به‌صورت خودکار استعلام نمی‌گیرد. اجرای فوری و استعلام‌های دستی همچنان کار می‌کنند.</p>')+
    '<table><thead><tr><th><input type="checkbox" id="periodicSelAll" onchange="periodicSelAll(this)"></th><th>دستگاه</th><th>مرحله</th><th>وضعیت استعلام</th><th>همتا</th><th>آخرین استعلام</th><th>استعلام بعدی</th><th></th></tr></thead>'+
    '<tbody>'+(rows||'<tr><td colspan="8">'+(searchActive()?searchEmptyHtml():emptyInnerHtml('دستگاهی در لیست نیست','با رسیدن پرونده به «تحویل به مسئول سایت» به‌صورت خودکار در استعلام دوره‌ای گمرک قرار می‌گیرد.'))+'</td></tr>')+'</tbody></table></div>'+
    '<div class="card"><h3>لاگ استعلام‌های قبلی (کلی)</h3><div id="periodicLog" class="logbox">'+
    '<table><thead><tr><th>زمان</th><th>دستگاه</th><th>وضعیت</th><th>پیام</th></tr></thead>'+
    '<tbody>'+(logs||'<tr><td colspan="4"><div class="empty"><span class="eic">'+ICONS.inbox+'</span><span class="esub">هنوز لاگی ثبت نشده است.</span></div></td></tr>')+'</tbody></table></div></div>';
}
/* ================= settings tab ================= */
/* v1.9: the related-site buttons moved out of localStorage into settings, so
   every browser sees the same list. The tab edits a local draft and saves it
   in one go; the read side is STATE.settings.links. */
function loadLinks(){
  var arr=(STATE&&STATE.settings&&STATE.settings.links)||[];
  return arr.map(function(l){return {name:String(l.name||''),url:String(l.url||'')};})
    .filter(function(l){return !!l.url;});
}
function draftLinks(){
  /* The tab's inputs are the draft of a not-yet-saved list. Reading them back
     is what add/remove and save have in common. */
  var out=[];
  var i=0;
  for(;;i++){
    var n=document.getElementById('lnName'+i), u=document.getElementById('lnUrl'+i);
    if(!n&&!u)break;
    out.push({name:(n?n.value:'').trim(),url:(u?u.value:'').trim()});
  }
  return out;
}
function settingsLinkAdd(){
  var arr=draftLinks();arr.push({name:'',url:''});settingsLinksPaint(arr);
}
function settingsLinkRemove(i){
  var arr=draftLinks();arr.splice(i,1);settingsLinksPaint(arr);
}
function settingsLinksPaint(links){
  /* Re-render just the link rows, not the whole tab: the operator's unsaved
     edits in the other cards would otherwise be lost. */
  var box=document.getElementById('linkRows');
  if(!box)return;
  box.innerHTML=(links||draftLinks()).map(function(l,i){
    return '<div class="row" style="gap:6px;margin-bottom:6px">'
    +'<input id="lnName'+i+'" value="'+esc(l.name)+'" style="width:150px" placeholder="نام">'
    +'<input id="lnUrl'+i+'" value="'+esc(l.url)+'" dir="ltr" style="flex:1" placeholder="https://...">'
    +'<button class="btn mini danger" onclick="settingsLinkRemove('+i+')">حذف</button></div>';
  }).join('')||'<div class="muted">لینکی ثبت نشده است.</div>';
}
function settingsHtml(){
  var settings=(STATE&&STATE.settings)||{};
  return '<div class="card"><h3>نمایش</h3>'
  +'<div class="row" style="margin-bottom:8px">'
  +'<label class="f">پوسته<select id="stTheme" onchange="settingsApply()">'
  +'<option value="light">روشن</option><option value="dark">تاریک</option></select></label>'
  +'<label class="f">اندازهٔ متن<select id="stFs" onchange="settingsApply()">'
  +'<option value="0">معمولی</option><option value="1">بزرگ</option><option value="2">بزرگ‌تر</option></select></label>'
  +'</div>'
  /* v1.9: a saved cue plays for save/error/warning/open/tab events. OFF is
     not a silent error — the header speaker mirrors it, and the login page
     honours it too, so the panel never beeps after you asked it not to. */
  +'<div class="row"><label class="f check"><input type="checkbox" id="stSound" '+(settings.sound_enabled!==false?'checked':'')+'><span class="box" aria-hidden="true"></span><span class="ft">افکت صدا روشن باشد</span></label>'
  +'<button class="btn primary" onclick="settingsSaveSound()">ذخیره</button></div>'
  +'<p class="muted">صداهای کوتاه برای ذخیرهٔ موفق، خطا، هشدار و باز شدن پنجره‌ها. با دکمهٔ بلندگو بالای صفحه هم می‌توانید سریع قطع و وصل کنید.</p></div>'
  +'<div class="card"><h3>مالی</h3>'
  +'<div class="row"><label class="f">هزینه ثبت رجیستری (تومان)'
  +'<input id="stFee" class="ltr" inputmode="numeric" style="width:150px" value="'+fa(settings.registry_fee_amount||0)+'"></label>'
  +'<button class="btn primary" onclick="settingsSaveFee()">ذخیره مبلغ</button></div>'
  +'<p class="muted">این مبلغ هنگام ثبت هر دستگاه برای مشتریِ آن دستگاه به‌صورت خودکار بدهکار می‌شود.</p></div>'
  +'<div class="card"><h3>کسب‌وکار</h3>'
  +'<div class="row"><label class="f">نام کسب‌وکار'
  +'<input id="stBizName" style="flex:1" value="'+esc(settings.business_name||'')+'"></label>'
  +'<label class="f">شمارهٔ تماس کسب‌وکار'
  +'<input id="stBizPhone" dir="ltr" inputmode="tel" style="width:170px" value="'+esc(settings.business_phone||'')+'"></label>'
  +'<button class="btn primary" onclick="settingsSaveBiz()">ذخیره</button></div>'
  +'<p class="muted">نام و شمارهٔ تماس کسب‌وکار در سربرگ صورت‌حساب مشتری و فاکتور چاپی درج می‌شود.</p></div>'
  +'<div class="card"><h3>اتصال و ربات تلگرام</h3>'
  +'<div class="row" style="margin-bottom:8px">'
  +'<label class="f" style="flex:1">توکن ربات تلگرام (Bot Token)'
  +'<input id="stTgToken" class="ltr" type="password" autocomplete="off" placeholder="توکن ربات...">'
  +'</label><div id="stTgTokenBadge" style="align-self:flex-end;margin-bottom:8px"></div></div>'
  +'<div class="row" style="margin-bottom:8px">'
  +'<label class="f" style="flex:1">روش اتصال به تلگرام'
  +'<select id="stTgMode" onchange="settingsTgModeChange()">'
  +'<option value="host">سرویس هاست ابری (بدون نیاز به پروکسی)</option>'
  +'<option value="proxy">پروکسی اختصاصی (SOCKS5 / HTTP)</option>'
  +'<option value="direct">مستقیم / ورکر کلودفلر</option>'
  +'</select></label></div>'
  +'<div id="stTgHostFields" class="row" style="margin-bottom:8px;gap:8px">'
  +'<label class="f" style="flex:2">آدرس سرویس فایل هاست (Relay URL)'
  +'<input id="stTgRelayUrl" class="ltr" placeholder="https://api.oneserver.in/telegram.php"></label>'
  +'<label class="f" style="flex:1">کلید امنیتی رله (اختیاری)'
  +'<input id="stTgRelaySecret" class="ltr" type="password" placeholder="در صورت تنظیم روی هاست"></label>'
  +'</div>'
  +'<div id="stTgProxyFields" class="row" style="margin-bottom:8px;display:none">'
  +'<label class="f" style="flex:1">آدرس پروکسی (Proxy URL)'
  +'<input id="stTgProxyUrl" class="ltr" placeholder="socks5h://127.0.0.1:10808 یا http://127.0.0.1:7890"></label>'
  +'</div>'
  +'<div id="stTgDirectFields" class="row" style="margin-bottom:8px;display:none">'
  +'<label class="f" style="flex:1">آدرس پایه API تلگرام (API Base)'
  +'<input id="stTgApiBase" class="ltr" placeholder="https://api.telegram.org یا آدرس ورکر"></label>'
  +'</div>'
  +'<div class="row" style="margin-bottom:8px">'
  +'<label class="f" style="flex:1">شناسه‌های چت پیش‌فرض (با کاما جدا کنید)'
  +'<input id="stTgChats" class="ltr" placeholder="123456789, -100123456789"></label>'
  +'</div>'
  +'<div class="row" style="gap:8px;margin-top:10px;align-items:center">'
  +'<button class="btn primary" id="stTgSaveBtn" onclick="settingsSaveTelegram()">ذخیره تنظیمات تلگرام</button>'
  +'<button class="btn" id="stTgTestBtn" onclick="settingsTestTelegram()">ارسال پیام آزمایشی (تست اتصال)</button>'
  +'<span id="stTgStatusText" class="muted" style="font-size:12px"></span>'
  +'</div>'
  +'<p class="muted" style="margin-top:8px">در حالت «سرویس هاست ابری»، ارسال پیام‌ها و عکس‌ها بدون فیلترشکن از طریق فایل telegram.php روی هاست انجام می‌شود.</p></div>'
  +'<div class="card"><h3>تحویل اطلاعات ثبت به تلگرام</h3>'
  +'<div class="row" style="margin-bottom:8px">'
  +'<label class="f">شناسهٔ عددی کانال/گروه ثبت مسافری'
  +'<input id="stRegChat" dir="ltr" inputmode="numeric" style="width:200px" value="'+esc(settings.registration_chat_id||'')+'"></label>'
  +'<button class="btn primary" onclick="settingsSaveRegChat()">ذخیره</button></div>'
  +'<p class="muted">اطلاعات دستگاه و مسافر که برای فرآیند ثبت لازم است، برای تحویل به مسئول ثبت به این کانال/گروه تلگرام ارسال می‌شود.</p></div>'
  +'<div class="card"><h3>کانال تلگرام گزارش‌ها</h3>'
  +'<div class="row" style="margin-bottom:8px">'
  +'<label class="f">شناسهٔ عددی کانال گزارش‌ها'
  +'<input id="stReportChat" dir="ltr" inputmode="numeric" style="width:200px" value="'+esc(settings.report_chat_id||'')+'"></label>'
  +'<button class="btn primary" onclick="settingsSaveReportChat()">ذخیره</button></div>'
  +'<p class="muted">گزارش پرونده‌ها، گزارش مالی، صورت‌حساب و نتیجهٔ استعلام‌های گمرک و همتا، علاوه بر چت‌های فعلی، یک نسخه هم به این کانال می‌رود. برای اینکه ارسال انجام شود، ربات باید در آن کانال عضو و مدیر باشد. خالی بگذارید تا نسخه‌ای به کانال نرود.</p></div>'
  +'<div class="card"><h3>زمان‌بند و روال خودکار</h3>'
    +'<div class="row"><label class="f check"><input type="checkbox" id="stSched" '+(settings.scheduler_enabled?'checked':'')+'><span class="box" aria-hidden="true"></span><span class="ft">زمان‌بند استعلام دوره‌ای فعال باشد</span></label>'
    +'<button class="btn primary" onclick="settingsSave()">ذخیره</button></div>'
    +'<div class="row" style="margin-top:8px"><label class="f check"><input type="checkbox" id="stAutoAdv" '+(settings.auto_advance_default?'checked':'')+'><span class="box" aria-hidden="true"></span><span class="ft">پرداخت خودکار پیش‌فرض برای پرونده‌های جدید</span></label>'
    +'<button class="btn primary" onclick="settingsSaveAutoAdv()">ذخیره</button></div>'
    +'<p class="muted">زمان‌بند، استعلام گمرکِ پرونده‌های تحویل‌شده را هر بازهٔ تنظیم‌شده اجرا می‌کند. پرداخت خودکار پرونده را پس از ثبت بلافاصله به گام پرداخت می‌برد.</p></div>'
    +'<div class="card"><h3>دکمه‌های سایت‌های مرتبط (گوشهٔ پایین صفحه)</h3>'
    +'<div id="linkRows">'+(loadLinks().map(function(l,i){
      return '<div class="row" style="gap:6px;margin-bottom:6px">'
      +'<input id="lnName'+i+'" value="'+esc(l.name)+'" style="width:150px" placeholder="نام">'
      +'<input id="lnUrl'+i+'" value="'+esc(l.url)+'" dir="ltr" style="flex:1" placeholder="https://...">'
      +'<button class="btn mini danger" onclick="settingsLinkRemove('+i+')">حذف</button></div>';
    }).join('')||'<div class="muted">لینکی ثبت نشده است.</div>')+'</div>'
    +'<div class="row" style="margin-top:8px"><button class="btn" onclick="settingsLinkAdd()">+ افزودن لینک</button>'
    +'<button class="btn primary" onclick="settingsLinksSave()">ذخیره لینک‌ها</button></div>'
    +'<p class="muted">این دکمه‌ها گوشهٔ پایین چپ صفحه هستند و در همهٔ مرورگرها یکسان نشان داده می‌شوند. برای بستن کادر، دکمهٔ × بالای خودش را بزنید؛ از همین جا دوباره فعال می‌شود.</p></div>';
}
function settingsApply(){
  var theme=document.getElementById('stTheme').value;
  var fs=Number(document.getElementById('stFs').value);
  document.documentElement.setAttribute('data-theme',theme);
  document.documentElement.style.setProperty('--crm-fs',(13.5+fs*1.5)+'px');
  try{localStorage.setItem('irica-theme',theme);localStorage.setItem('irica-crm-fs',String(fs));}catch(e){}
}
function settingsSaveFee(){
  var raw=document.getElementById('stFee').value;
  api('/crm-settings',{registry_fee_amount:raw}).then(async r=>{
    toast('هزینه ثبت رجیستری ذخیره شد: '+money(r.settings.registry_fee_amount));await refresh();})
    .catch(e=>toast(e,false));
}
/* v1.6: optional business identity for the statement/invoice headers —
   same per-card save shape as the fee field above. */
function settingsSaveBiz(){
  api('/crm-settings',{business_name:v('stBizName'),business_phone:v('stBizPhone')})
    .then(async r=>{toast('تنظیمات ذخیره شد');await refresh();})
    .catch(e=>toast(e,false));
}
function settingsSaveRegChat(){
  api('/crm-settings',{registration_chat_id:v('stRegChat')})
    .then(async r=>{toast('شناسهٔ تلگرام ثبت مسافری ذخیره شد');await refresh();})
    .catch(e=>toast(e,false));
}
/* v1.10: the report channel is read by telegram_notify (and through it by the
   robot processes) on every report/inquiry send, so nothing else has to know
   it changed — the next send picks up the new value. */
function settingsSaveReportChat(){
  api('/crm-settings',{report_chat_id:v('stReportChat')})
    .then(async r=>{toast('شناسهٔ کانال گزارش‌ها ذخیره شد');await refresh();})
    .catch(e=>toast(e,false));
}
function settingsSave(){
  api('/crm-settings',{scheduler_enabled:document.getElementById('stSched').checked})
    .then(async r=>{toast('تنظیمات ذخیره شد');await refresh();})
    .catch(e=>toast(e,false));
}
function settingsSaveAutoAdv(){
  api('/crm-settings',{auto_advance_default:document.getElementById('stAutoAdv').checked})
    .then(async r=>{toast('تنظیم پرداخت خودکار ذخیره شد');await refresh();})
    .catch(e=>toast(e,false));
}
function settingsLoadTelegram(){
  fetch('/telegram-config',{cache:'no-store'})
    .then(r=>r.json())
    .then(d=>{
      if(!d||typeof d!=='object')return;
      var modeEl=document.getElementById('stTgMode');
      if(modeEl)modeEl.value=d.mode||'host';
      var rUrl=document.getElementById('stTgRelayUrl');
      if(rUrl)rUrl.value=d.relay_url||'https://api.oneserver.in/telegram.php';
      var pUrl=document.getElementById('stTgProxyUrl');
      if(pUrl)pUrl.value=d.proxy_url||'';
      var aBase=document.getElementById('stTgApiBase');
      if(aBase)aBase.value=d.api_base||'https://api.telegram.org';
      var chats=document.getElementById('stTgChats');
      if(chats)chats.value=(d.chat_ids||[]).join(', ');
      var badge=document.getElementById('stTgTokenBadge');
      var tokenInp=document.getElementById('stTgToken');
      if(badge){
        if(d.token_set){
          badge.innerHTML='<span class="pill ok">✓ توکن ذخیره است</span>';
          if(tokenInp)tokenInp.placeholder='(توکن قبلی ذخیره است؛ برای تغییر مقدار جدید بنویسید)';
        }else{
          badge.innerHTML='<span class="pill warn">توکن تنظیم نشده</span>';
          if(tokenInp)tokenInp.placeholder='123456:ABC-DEF...';
        }
      }
      settingsTgModeChange();
    }).catch(function(){});
}
function settingsTgModeChange(){
  var mode=(document.getElementById('stTgMode')||{}).value||'host';
  var hf=document.getElementById('stTgHostFields');
  var pf=document.getElementById('stTgProxyFields');
  var df=document.getElementById('stTgDirectFields');
  if(hf)hf.style.display=(mode==='host')?'flex':'none';
  if(pf)pf.style.display=(mode==='proxy')?'flex':'none';
  if(df)df.style.display=(mode==='direct')?'flex':'none';
}
function settingsSaveTelegram(){
  var btn=document.getElementById('stTgSaveBtn');
  if(btn)btn.disabled=true;
  var payload={
    mode:(document.getElementById('stTgMode')||{}).value||'host',
    bot_token:(document.getElementById('stTgToken')||{}).value||'',
    relay_url:(document.getElementById('stTgRelayUrl')||{}).value||'',
    relay_secret:(document.getElementById('stTgRelaySecret')||{}).value||'',
    proxy_url:(document.getElementById('stTgProxyUrl')||{}).value||'',
    api_base:(document.getElementById('stTgApiBase')||{}).value||'',
    chat_ids:(document.getElementById('stTgChats')||{}).value||''
  };
  fetch('/telegram-config',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload)
  })
    .then(r=>r.json())
    .then(d=>{
      if(btn)btn.disabled=false;
      toast('تنظیمات تلگرام ذخیره شد');
      var tokenInp=document.getElementById('stTgToken');
      if(tokenInp)tokenInp.value='';
      var secInp=document.getElementById('stTgRelaySecret');
      if(secInp)secInp.value='';
      settingsLoadTelegram();
    })
    .catch(e=>{
      if(btn)btn.disabled=false;
      toast('خطا در ذخیره تنظیمات: '+e,false);
    });
}
function settingsTestTelegram(){
  var btn=document.getElementById('stTgTestBtn');
  var st=document.getElementById('stTgStatusText');
  if(btn)btn.disabled=true;
  if(st)st.textContent='در حال آزمون ارتباط...';
  fetch('/telegram-test',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({send_message:true})
  })
    .then(r=>r.json())
    .then(d=>{
      if(btn)btn.disabled=false;
      if(st)st.textContent=d.ok?'ارتباط موفق بود':'خطا در اتصال';
      toast(d.message||(d.ok?'ارتباط با تلگرام برقرار است':'خطا در اتصال'),d.ok);
    })
    .catch(e=>{
      if(btn)btn.disabled=false;
      if(st)st.textContent='خطا در ارسال درخواست';
      toast('خطا: '+e,false);
    });
}
function settingsSaveSound(){
  api('/crm-settings',{sound_enabled:document.getElementById('stSound').checked})
    .then(async r=>{
      SOUND.enabled=r.settings.sound_enabled!==false;
      paintSoundBtn();
      toast(SOUND.enabled?'صدای رویدادها روشن شد.':'صدای رویدادها خاموش شد.');
      await refresh();
    })
    .catch(e=>toast(e,false));
}
function settingsLinksSave(){
  var arr=draftLinks().filter(function(l){return !!l.url;});
  api('/crm-settings',{links:arr})
    .then(async r=>{
      if(STATE&&STATE.settings)STATE.settings.links=r.settings.links||[];
      toast('لینک‌ها ذخیره شد');await refresh();renderQuickBox();
    })
    .catch(e=>toast(e,false));
}
function renderQuickBox(){
  var wrap=document.getElementById('quickWrap');
  if(!wrap)return;
  var links=loadLinks();
  /* v1.9: the box can be dismissed. The state is local because hiding the
     buttons is a per-operator comfort, not a shared setting — the buttons
     themselves are the shared part and stay configured in this tab. */
  var hidden=false;
  try{hidden=localStorage.getItem('irica-quickbox')==='0';}catch(e){}
  if(hidden){wrap.innerHTML='';return;}
  wrap.innerHTML='<div class="quickbox" id="quickBox">'
    +'<button type="button" class="qb-x" onclick="quickBoxHide()" aria-label="بستن کادر سایت‌های مرتبط" title="بستن (از تب تنظیمات دوباره فعال می‌شود)">×</button>'
    +'<div class="qb-title">سایت‌های مرتبط</div>'
    +(links.map(function(l){return l.url?'<a class="qb-btn" target="_blank" href="'+esc(l.url)+'">'+esc(l.name||l.url)+'</a>':'';}).join('')
      ||'<span class="muted">لینکی ثبت نشده</span>')+'</div>';
}
function quickBoxHide(){
  try{localStorage.setItem('irica-quickbox','0');}catch(e){}
  renderQuickBox();
  toast('کادر سایت‌های مرتبط بسته شد؛ از تب تنظیمات دوباره فعال می‌شود.');
}
function quickBoxShow(){
  try{localStorage.removeItem('irica-quickbox');}catch(e){}
  renderQuickBox();
}

/* ================= CRM Cloud Sync Surface (v1.12.1) ================= */
var CLOUD={last:null,timer:null,burst:null,busy:false};
var CLOUD_UNKNOWN_MESSAGE='خطای همگام‌سازی؛ کد آن را به پشتیبانی اعلام کنید.';
var CLOUD_ICONS={
  dot:'<svg class="ic" width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="8"/></svg>',
  checkCircle:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>',
  xCircle:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/></svg>',
  alert:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  lock:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="4.5" y="10" width="15" height="10.5" rx="2.5"/><path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"/></svg>',
  info:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>',
  minusCircle:'<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg>'
};
var CLOUD_LINK={
  unconfigured:{cls:'mute',icon:'dot',label:'پیکربندی‌نشده'},
  connected:{cls:'ok',icon:'checkCircle',label:'متصل'},
  syncing:{cls:'ok',icon:'dot',label:'در حال همگام‌سازی'},
  offline:{cls:'bad',icon:'xCircle',label:'آفلاین'},
  read_only:{cls:'warn',icon:'alert',label:'فقط‌خواندنی'},
  auth_required:{cls:'warn',icon:'lock',label:'نیازمند ورود'},
  not_enrolled:{cls:'warn',icon:'info',label:'ثبت‌نشده'},
  conflict:{cls:'warn',icon:'alert',label:'نیازمند بررسی تداخل'},
  disabled:{cls:'mute',icon:'minusCircle',label:'غیرفعال'},
  error:{cls:'bad',icon:'xCircle',label:'خطا'}
};
var CLOUD_CONFLICTS_CACHE=null;
var CLOUD_CONFLICTS_FETCHING=false;
var CLOUD_ENTITY_NAMES={
  'customers':'مشتری',
  'customer_transactions':'تراکنش مشتری',
  'owners':'مسافر / مالک',
  'identities':'استخر هویتی',
  'devices':'دستگاه / پرونده',
  'crm_devices':'دستگاه / پرونده',
  'periods':'دوره مالی',
  'settings':'تنظیمات'
};

function cloudTabHtml(){
  return '<div class="cloud-card" id="cloud-sync-section">'+
    '<div class="card" style="display:grid;gap:12px">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">'+
        '<div><h3 style="margin:0;font-size:16px;font-weight:750">سرور ابری و پایگاه داده مشترک</h3>'+
        '<p class="hint" style="margin:4px 0 0">داده‌های CRM (پرونده‌ها، مشتریان، مسافران، دوره‌ها و تراکنش‌ها) روی سرور ابری ذخیره می‌شوند و بین همهٔ سیستم‌های همکاران همگام‌سازی می‌گردند.</p></div>'+
        '<div class="cloud-state-row">'+
          '<span class="cloud-pill mute" id="cloud-pill"><span id="cloud-pill-icon">'+CLOUD_ICONS.dot+'</span><span id="cloud-pill-text">در حال بررسی…</span></span>'+
          '<span class="cloud-actor" id="cloud-actor"><svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><span>کاربر فعال:</span><b id="cloud-actor-name"></b></span>'+
        '</div>'+
      '</div>'+
      '<div class="cloud-banner" id="cloud-readonly-banner" role="alert">'+CLOUD_ICONS.alert+
        '<div><span class="cloud-banner-b">دستگاه در حالت فقط‌خواندنی است</span>'+
        '<p class="cloud-banner-p">مهلت کارکرد آفلاین هفت‌روزه به پایان رسیده است. تا زمانی که دوباره وارد نشوید، ویرایش‌های محلی پذیرفته نمی‌شوند؛ خواندن داده‌ها ادامه دارد.</p></div></div>'+
      '<div class="cloud-notice" id="cloud-must-change" role="alert">'+CLOUD_ICONS.alert+
        '<div><span class="cloud-banner-b">رمز عبور باید تغییر کند</span>'+
        '<p class="cloud-banner-p">برای ادامه، رمز عبور حساب خود در سرور را تغییر دهید.</p></div></div>'+
      '<div class="cloud-facts">'+
        '<div class="cloud-fact"><span class="cloud-fact-l">این دستگاه</span><span class="cloud-fact-v cloud-code" id="cloud-device">ثبت‌نشده</span></div>'+
      '<div class="cloud-fact"><span class="cloud-fact-l">آخرین همگام‌سازی موفق</span><span class="cloud-fact-v" id="cloud-last-sync">—</span></div>'+
        '<div class="cloud-fact"><span class="cloud-fact-l">تغییرات در صف ارسال</span><span class="cloud-fact-v" id="cloud-pending">۰</span></div>'+
        '<div class="cloud-fact"><span class="cloud-fact-l">تداخل‌های نیازمند بررسی</span><span class="cloud-fact-v" id="cloud-conflicts">۰</span></div>'+
        '<div class="cloud-fact"><span class="cloud-fact-l">کد آخرین خطا</span><span class="cloud-fact-v cloud-code" id="cloud-error-code">—</span></div>'+
      '</div>'+
      '<div class="cloud-error" id="cloud-error-line" role="alert">'+CLOUD_ICONS.alert+'<span id="cloud-error-text"></span></div>'+
      '<div class="cloud-notice" id="cloud-reconnect" role="status">'+CLOUD_ICONS.info+
        '<div><span class="cloud-banner-b">اتصال این دستگاه نیاز به بازسازی دارد</span>'+
        '<p class="cloud-banner-p" id="cloud-reconnect-text"></p></div></div>'+
      '<div class="cloud-status" id="cloud-beat-line" role="status"></div>'+
      '<div class="cloud-status" id="cloud-action-status" role="status" aria-live="polite"></div>'+
      '<div class="cloud-actions">'+
        '<button type="button" class="cloud-btn" id="cloud-sync-btn" onclick="cloudSyncNow()" disabled><span class="cloud-lbl">همگام‌سازی اکنون</span></button>'+
        '<button type="button" class="cloud-btn ghost hidden" id="cloud-import-btn" onclick="cloudImportPrompt()"><span class="cloud-lbl">انتقال و ادغام پرونده‌های محلی با سرور</span></button>'+
        '<button type="button" class="cloud-btn ghost" id="cloud-backup-btn" onclick="cloudBackupNow()"><span class="cloud-lbl">پشتیبان‌گیری فوری ابری به تلگرام</span></button>'+
        '<button type="button" class="cloud-btn ghost-danger hidden" id="cloud-logout-btn" onclick="cloudLogout()"><span class="cloud-lbl">خروج از حساب سرور</span></button>'+
      '</div>'+
    '</div>'+
    '<div class="cloud-block">'+
      '<strong>حالت کارکرد پایگاه داده (همکاری آنلاین همکاران)</strong>'+
      '<p class="hint">در حالت ابری (آنلاین)، تغییرات پرونده‌ها با سرعت لحظه‌ای (۲ ثانیه) بین سیستم شما و همکاران همگام می‌شود و ربات‌های استعلام و ثبت به کار خود ادامه می‌دهند.</p>'+
      '<div class="cloud-fields" style="margin-top:8px">'+
        '<div class="cloud-field"><label for="cloud-db-mode">حالت پایگاه داده</label>'+
          '<select id="cloud-db-mode" onchange="cloudSetDbMode(this.value)">'+
            '<option value="online">ابری (آنلاین - همکاران همزمان، همگام‌سازی لحظه‌ای ۲ ثانیه)</option>'+
            '<option value="local">محلی (آفلاین با همگام‌سازی دوره‌ای)</option>'+
          '</select>'+
        '</div>'+
      '</div>'+
    '</div>'+
    '<div class="cloud-block">'+
      '<strong>تنظیمات اتصال به سرور ابری</strong>'+
      '<p class="hint">آدرس سرور و شناسه‌ی سازمان باید روی همهٔ سیستم‌های همکاران یکسان تنظیم شود.</p>'+
      '<div class="cloud-fields">'+
        '<div class="cloud-field"><label for="cloud-api">آدرس وب‌سرویس سرور (API Base)</label>'+
          '<input id="cloud-api" type="text" class="ltr" autocomplete="off" spellcheck="false" placeholder="https://api.example.com"></div>'+
        '<div class="cloud-field"><label for="cloud-tenant">شناسه‌ی سازمان (Tenant ID)</label>'+
          '<input id="cloud-tenant" type="text" class="ltr" autocomplete="off" spellcheck="false"></div>'+
      '</div>'+
      '<div style="display:flex;gap:8px">'+
        '<button type="button" class="cloud-btn mini" id="cloud-save-btn" onclick="cloudSaveConfig()"><span class="cloud-lbl">ذخیره تنظیمات اتصال</span></button>'+
      '</div>'+
    '</div>'+
    '<div class="cloud-block hidden" id="cloud-login-block">'+
      '<strong>ورود و اتصال دستگاه به سرور</strong>'+
      '<p class="hint">با نام کاربری و رمز عبوری که در سرور ساخته شده است وارد شوید تا این دستگاه ثبت و متصل گردد.</p>'+
      '<div class="cloud-fields">'+
        '<div class="cloud-field"><label for="cloud-user">نام کاربری در سرور</label>'+
          '<input id="cloud-user" type="text" class="ltr" autocomplete="username" spellcheck="false"></div>'+
        '<div class="cloud-field"><label for="cloud-pass">رمز عبور در سرور</label>'+
          '<input id="cloud-pass" type="password" class="ltr" autocomplete="current-password"></div>'+
      '</div>'+
      '<div style="display:flex;gap:8px">'+
        '<button type="button" class="cloud-btn mini" id="cloud-login-btn" onclick="cloudLogin()"><span class="cloud-lbl">ورود و ثبت دستگاه</span></button>'+
      '</div>'+
    '</div>'+
    '<div class="cloud-conflicts" id="cloud-conflicts-view"></div>'+
    '<div class="cloud-tutorial">'+
      '<h4><svg class="ic" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg> راهنمای افزودن کاربر (همکار جدید) در سرور ابری</h4>'+
      '<div class="cloud-tutorial-step">'+
        '<b>۱. ایجاد حساب کاربری برای همکار روی سرور:</b>'+
        '<span>از طریق ترمینال SSH یا سرور cPanel وارد پوشهٔ پکیج سرور شوید و دستور زیر را اجرا کنید:</span>'+
        '<div class="cloud-tutorial-code">php bin/create-user.php --username=colleague1 --password=StrongPassword123 --role=operator</div>'+
        '<span class="hint">نکته: نقش operator برای ثبت و ویرایش پرونده‌ها توسط همکار مناسب است. نقش admin برای مدیریت سازمان و کاربران است.</span>'+
      '</div>'+
      '<div class="cloud-tutorial-step">'+
        '<b>۲. ارائه اطلاعات اتصال به همکار:</b>'+
        '<span>سه مورد را در اختیار همکار قرار دهید: ۱. آدرس وب‌سرویس سرور (API Base)، ۲. شناسه‌ی سازمان (Tenant ID)، ۳. نام کاربری و رمز عبوری که ساختید.</span>'+
      '</div>'+
      '<div class="cloud-tutorial-step">'+
        '<b>۳. اتصال در سیستم همکار:</b>'+
        '<span>همکار کافیست در پنل سیستم خود به همین تب «سرور ابری» بیاید، آدرس و شناسه سازمان را ذخیره کند و سپس با نام کاربری خود وارد شود.</span>'+
      '</div>'+
      '<div class="cloud-tutorial-step">'+
        '<b>۴. همگام‌سازی خودکار:</b>'+
        '<span>به محض ورود همکار، تمام پرونده‌ها و اطلاعات CRM به صورت خودکار از سرور دریافت و همگام می‌شوند. روی سیستم همکار <b>نیازی به زدن دکمهٔ انتقال پرونده‌ها (Import) نیست</b> (انتقال پرونده‌ها فقط یکبار در سیستم اصلی که داده‌های اولیه را داشت زده می‌شود).</span>'+
      '</div>'+
    '</div>'+
  '</div>';
}

function paintCloud(){
  var s=CLOUD.last;
  var link=s&&s.link?s.link:'unconfigured';
  if(link==='connected'&&s&&s.state==='syncing')link='syncing';
  var meta=CLOUD_LINK[link]||CLOUD_LINK.error;

  var hpill=document.getElementById('crmCloudPill');
  if(hpill){
    var dbMode=(STATE&&STATE.settings&&STATE.settings.database_mode)?STATE.settings.database_mode:'online';
    var isOnline=link==='connected'&&dbMode==='online';
    hpill.className='iconbtn cloud-pill '+(isOnline?'ok':meta.cls);
    var hicon=document.getElementById('crmCloudPillIcon');
    if(hicon)hicon.innerHTML=isOnline?CLOUD_ICONS.checkCircle:(CLOUD_ICONS[meta.icon]||CLOUD_ICONS.dot);
    var htext=document.getElementById('crmCloudPillText');
    if(htext)htext.textContent=isOnline?'ابری (آنلاین)':meta.label;
  }

  if(!document.getElementById('cloud-sync-section'))return;
  var pill=document.getElementById('cloud-pill');
  if(pill){
    pill.className='cloud-pill '+meta.cls;
    var picon=document.getElementById('cloud-pill-icon');
    if(picon)picon.innerHTML=CLOUD_ICONS[meta.icon]||CLOUD_ICONS.dot;
    var ptext=document.getElementById('cloud-pill-text');
    if(ptext)ptext.textContent=meta.label;
  }
  var rBanner=document.getElementById('cloud-readonly-banner');
  if(rBanner)rBanner.classList.toggle('on',Boolean(s&&s.read_only));
  var mChange=document.getElementById('cloud-must-change');
  if(mChange)mChange.classList.toggle('on',Boolean(s&&s.must_change_password));
  var name=s&&s.actor?String(s.actor):'';
  var actorEl=document.getElementById('cloud-actor');
  if(actorEl)actorEl.classList.toggle('on',Boolean(name));
  var actorName=document.getElementById('cloud-actor-name');
  if(actorName)actorName.textContent=name;
  var deviceId=s&&s.device_id?String(s.device_id):'';
  var deviceText=deviceId?(deviceId.length>12?deviceId.slice(0,8)+'…'+deviceId.slice(-4):deviceId):'ثبت‌نشده';
  var deviceEl=document.getElementById('cloud-device');
  if(deviceEl){deviceEl.textContent=deviceText;deviceEl.title=deviceId;}
  var lastSync=document.getElementById('cloud-last-sync');
  if(lastSync)lastSync.textContent=(s&&s.last_sync)?faDateTime(s.last_sync):'—';
  var pending=document.getElementById('cloud-pending');
  if(pending)pending.textContent=fa(s?Number(s.pending||0):0);
  var conflicts=document.getElementById('cloud-conflicts');
  if(conflicts)conflicts.textContent=fa(s?Number(s.conflicts||0):0);
  var errCode=document.getElementById('cloud-error-code');
  if(errCode)errCode.textContent=(s&&s.error_code)?s.error_code:'—';
  var msg=(s&&s.error_message)?String(s.error_message):'';
  var errLine=document.getElementById('cloud-error-line');
  if(errLine)errLine.classList.toggle('on',Boolean(msg));
  var errText=document.getElementById('cloud-error-text');
  if(errText)errText.textContent=msg;
  var reconnect=document.getElementById('cloud-reconnect');
  var reconnectText=document.getElementById('cloud-reconnect-text');
  var needsReconnect=Boolean(s&&['not_enrolled','auth_required','read_only'].indexOf(s.link)>=0);
  if(reconnect)reconnect.classList.toggle('on',needsReconnect);
  if(reconnectText){
    if(needsReconnect){
      reconnectText.textContent=s.link==='not_enrolled'
        ?'با نام کاربری و رمز عبور میزبان وارد شوید؛ این رایانه با شناسه‌ی مستقل ثبت می‌شود.'
        :(s.link==='read_only'
          ?'مهلت آفلاین تمام شده است؛ برای تازه‌سازی مجوز این رایانه دوباره وارد میزبان شوید.'
          :'نشست ابری قابل استفاده نیست؛ دوباره وارد میزبان شوید. اگر اعتبار دستگاه لغو شده یا از دست رفته باشد، ورود موفق یک شناسه‌ی دستگاه تازه ثبت می‌کند.');
    }else{reconnectText.textContent='';}
  }
  var beatLine=document.getElementById('cloud-beat-line');
  if(beatLine)beatLine.textContent=cloudBeatLine(s);
  var loginBlock=document.getElementById('cloud-login-block');
  if(loginBlock)loginBlock.classList.toggle('hidden',Boolean(name));
  var logoutBtn=document.getElementById('cloud-logout-btn');
  if(logoutBtn)logoutBtn.classList.toggle('hidden',!Boolean(name));
  var syncBtn=document.getElementById('cloud-sync-btn');
  if(syncBtn)syncBtn.disabled=Boolean(CLOUD.busy)||!(s&&s.configured);
  var importBtn=document.getElementById('cloud-import-btn');
  if(importBtn)importBtn.classList.toggle('hidden',!(s&&s.can_import));
  var apiInput=document.getElementById('cloud-api');
  if(apiInput&&!apiInput.value&&s&&s.api_base)apiInput.value=s.api_base;
  var tenantInput=document.getElementById('cloud-tenant');
  if(tenantInput&&!tenantInput.value&&s&&s.tenant_id)tenantInput.value=s.tenant_id;
  var dbModeEl=document.getElementById('cloud-db-mode');
  if(dbModeEl&&STATE&&STATE.settings&&STATE.settings.database_mode){
    dbModeEl.value=STATE.settings.database_mode;
  }
  renderCloudConflicts(document.getElementById('cloud-conflicts-view'),s);
}

function cloudBeatLine(s){
  if(!s)return '';
  var line=s.worker==='running'?'سرویس همگام‌سازی در حال اجراست.':'سرویس همگام‌سازی متوقف است.';
  var b=s.worker_last;
  if(!b)return line;
  if(b.message)return line+' '+b.message;
  if(b.attempted)return line+' ارسال گروهی انجام شد.';
  return line+' تغییری برای ارسال نبود.';
}

function loadCloudStatus(){
  return fetch('/cloud-status',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      CLOUD.last=(d&&typeof d==='object')?d:null;
      paintCloud();
      renderTabs();
      return d;
    })
    .catch(function(){
      paintCloud();
      return null;
    });
}

function cloudSetBusy(on,label){
  CLOUD.busy=on;
  ['cloud-sync-btn','cloud-login-btn','cloud-save-btn','cloud-logout-btn','cloud-import-btn','cloud-backup-btn'].forEach(function(id){
    var b=document.getElementById(id);if(b)b.disabled=on;
  });
  var st=document.getElementById('cloud-action-status');
  if(!st)return;
  st.className='cloud-status';
  st.textContent=label||'';
}

function cloudResult(ok,text,code){
  var st=document.getElementById('cloud-action-status');
  if(st){
    st.className='cloud-status'+(ok?' ok':' bad');
    st.textContent=text+(code?' ['+code+']':'');
  }
  paintCloud();
}

function cloudPost(path,body,onOk){
  cloudSetBusy(true,'در حال انجام…');
  return fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body||{})})
    .then(function(r){return r.json();})
    .then(function(d){
      cloudSetBusy(false,'');
      if(d&&d.ok){cloudResult(true,'انجام شد.');if(onOk)onOk(d);}
      else{cloudResult(false,(d&&d.errors&&d.errors[0])?d.errors[0]:CLOUD_UNKNOWN_MESSAGE,d&&d.code);}
      loadCloudStatus();
    })
    .catch(function(){
      cloudSetBusy(false,'');
      cloudResult(false,'ارتباط با پنل برقرار نشد؛ دوباره تلاش کنید.');
      loadCloudStatus();
    });
}

function cloudSyncNow(){
  cloudPost('/cloud-sync',{},function(){toast('همگام‌سازی با موفقیت انجام شد.',true);});
}

function cloudSetDbMode(mode){
  api('/crm-settings',{database_mode:mode})
    .then(async function(r){
      if(STATE&&STATE.settings)STATE.settings.database_mode=mode;
      toast(mode==='online'?'حالت دیتابیس آنلاین (همگام‌سازی لحظه‌ای) فعال شد.':'حالت دیتابیس محلی (آفلاین) فعال شد.',true);
      paintCloud();
      await refresh();
    })
    .catch(function(e){toast(e,false);});
}

function cloudBackupNow(){
  var btn=document.getElementById('cloud-backup-btn');
  if(btn)btn.disabled=true;
  toast('در حال تهیه نسخه پشتیبان از پایگاه داده ابری و ارسال به تلگرام…',true);
  cloudPost('/cloud-backup-now',{},function(d){
    if(btn)btn.disabled=false;
    var msg=d&&d.message?d.message:'پشتیبان پایگاه داده ابری با موفقیت به تلگرام ارسال شد.';
    toast(msg,true);
  });
}

function cloudSaveConfig(){
  cloudPost('/cloud-config',{api_base:document.getElementById('cloud-api').value,
    tenant_id:document.getElementById('cloud-tenant').value},function(d){
      CLOUD.last=d;paintCloud();toast('تنظیمات اتصال به سرور ذخیره شد.',true);
    });
}

function cloudLogin(){
  var u=document.getElementById('cloud-user'),p=document.getElementById('cloud-pass');
  var username=u.value,password=p.value;
  p.value='';
  cloudPost('/cloud-login',{username:username,password:password},function(){
    u.value='';toast('دستگاه با موفقیت در سرور ثبت شد.',true);
  });
}

function cloudLogout(){
  if(!confirm('آیا از خروج از حساب سرور اطمینان دارید؟'))return;
  cloudPost('/cloud-logout',{},function(){toast('از حساب سرور خارج شدید.',true);});
}

function cloudImportPrompt(){
  if(confirm('آیا از انتقال و ادغام پرونده‌های محلی با سرور اطمینان دارید؟ اطلاعات محلی با سرور هوشمندانه ادغام خواهند شد.')){
    cloudPost('/cloud-import',{},function(d){
      var n=d&&d.rows!=null?d.rows:(d&&d.count!=null?d.count:0);
      var msg=d&&d.message?d.message:'انتقال و ادغام پرونده‌ها با موفقیت انجام شد ('+fa(n)+' رکورد).';
      toast(msg,true);
      loadCloudStatus();
      if(typeof refresh==='function')refresh();
    });
  }
}

function renderCloudConflicts(container,s){
  if(!container)return;
  if(s&&Number(s.conflicts||0)>0){
    container.classList.add('on');
    var count=fa(s.conflicts);
    var head='<div class="cloud-conflict-count"><strong>تداخل‌ها:</strong> '+count+' مورد در انتظار تصمیم شماست.</div>';
    if(typeof CLOUD_CONFLICTS_CACHE!=='undefined'&&CLOUD_CONFLICTS_CACHE&&CLOUD_CONFLICTS_CACHE.length>0){
      var cards='';
      for(var i=0;i<CLOUD_CONFLICTS_CACHE.length;i++){
        var c=CLOUD_CONFLICTS_CACHE[i];
        var ent=(typeof CLOUD_ENTITY_NAMES!=='undefined'&&CLOUD_ENTITY_NAMES[c.entity])?CLOUD_ENTITY_NAMES[c.entity]:(c.entity||'مورد');
        cards+='<div class="cloud-conflict-card">'+
          '<div class="cloud-conflict-head"><strong>'+esc(ent)+'</strong> <span class="kbd ltr">'+esc(c.id||'')+'</span></div>'+
          diffHtml(c.local_record,c.server_record)+
          '<div class="cloud-conflict-actions">'+
            '<button type="button" class="cloud-btn mini" onclick="resolveCloudConflict(\''+c.operation_id+'\',\'keep_local\',this)"><span class="cloud-lbl">نگه‌داشتن تغییرات من (روی سرور ذخیره شود)</span></button>'+
            '<button type="button" class="cloud-btn mini ghost" onclick="resolveCloudConflict(\''+c.operation_id+'\',\'accept_server\',this)"><span class="cloud-lbl">پذیرش نسخه سرور (تغییرات محلی لغو شود)</span></button>'+
          '</div>'+
        '</div>';
      }
      container.innerHTML=head+cards;
    }else{
      container.innerHTML=head+'<div class="hint">در حال دریافت اطلاعات تداخل‌ها…</div>';
      if(typeof fetch==='function'&&!CLOUD_CONFLICTS_FETCHING){
        fetchCloudConflicts();
      }
    }
  }else{
    container.classList.remove('on');
    container.innerHTML='';
    if(typeof CLOUD_CONFLICTS_CACHE!=='undefined')CLOUD_CONFLICTS_CACHE=null;
  }

  function diffHtml(loc,srv){
    loc=loc||{}; srv=srv||{};
    var keys={};
    for(var k in loc)keys[k]=true;
    for(var k in srv)keys[k]=true;
    var rows='';
    for(var key in keys){
      var lv=loc[key], sv=srv[key];
      var ls=(lv===undefined||lv===null)?'—':(typeof lv==='object'?JSON.stringify(lv):String(lv));
      var ss=(sv===undefined||sv===null)?'—':(typeof sv==='object'?JSON.stringify(sv):String(sv));
      if(ls!==ss){
        rows+='<tr><th>'+esc(key)+'</th><td class="diff-loc">'+esc(ls)+'</td><td class="diff-srv">'+esc(ss)+'</td></tr>';
      }
    }
    if(!rows)return '<div class="hint">تغییر فیلد مشخصی ثبت نشده است.</div>';
    return '<table class="cloud-conflict-table"><thead><tr><th>فیلد</th><th>نسخه محلی (من)</th><th>نسخه سرور</th></tr></thead><tbody>'+rows+'</tbody></table>';
  }
}

function fetchCloudConflicts(){
  CLOUD_CONFLICTS_FETCHING=true;
  fetch('/cloud-conflicts',{cache:'no-store'})
    .then(function(r){return r.json();})
    .then(function(d){
      CLOUD_CONFLICTS_FETCHING=false;
      if(d&&d.ok&&Array.isArray(d.conflicts)){
        CLOUD_CONFLICTS_CACHE=d.conflicts;
        var el=document.getElementById('cloud-conflicts-view');
        if(el)renderCloudConflicts(el,CLOUD.last);
      }
    })
    .catch(function(){
      CLOUD_CONFLICTS_FETCHING=false;
    });
}

function resolveCloudConflict(opId,resolution,btn){
  if(btn)btn.disabled=true;
  cloudPost('/cloud-resolve-conflict',{operation_id:opId,resolution:resolution},function(){
    CLOUD_CONFLICTS_CACHE=null;
    loadCloudStatus();
  });
}
function dueIn(d,hours){
  if(d.periodic_opt_out)return '—';
  var last=String(d.last_inquiry_at||'');
  if(!last)return 'همین حالا (صف)';
  var p=last.split(/[- :]/).map(Number);
  if(p.length<6||p.some(isNaN))return 'همین حالا (صف)';
  var lastTs=new Date(p[0],p[1]-1,p[2],p[3],p[4],p[5]).getTime();
  if(isNaN(lastTs))return 'همین حالا (صف)';
  var nextMs=lastTs+hours*3600000-Date.now();
  if(nextMs<=0)return 'همین حالا (صف)';
  var mins=Math.ceil(nextMs/60000);
  return mins>=60?(Math.floor(mins/60)+' ساعت و '+(mins%60)+' دقیقه'):mins+' دقیقه';
}

/* ================= identity pool ================= */
function identitiesHtml(){
  var q=tabQ();
  var ids=(STATE.identities||[]).filter(i=>tabSearchMatches(
    [i.label,i.national,i.birth,i.mobile].join(' '),q));
  /* v1.9.0: newest identity first (the pool grows at the end of the store). */
  ids=newestFirst(ids,i=>i.created);
  TAB_COUNT=ids.length;
  var rows=ids.map(i=>
    '<tr><td><b>'+esc(i.label)+'</b></td><td class="kbd">'+esc(i.national)+'</td>'
    +'<td class="kbd">'+esc(i.birth)+'</td><td class="kbd">'+esc(i.mobile)+'</td>'
    +'<td><div class="ibacts">'
    +'<button type="button" class="ibtn" data-static="1" aria-label="ویرایش مشخصات" data-tip="ویرایش مشخصات" onclick="dlgIdent(\'edit\',\''+i.id+'\')">'+ICONS.edit+'</button>'
    +'<button type="button" class="ibtn danger" aria-label="حذف مشخصات" data-tip="حذف مشخصات" onclick="identDelete(\''+i.id+'\')">'+ICONS.trash+'</button>'
    +'</div></td></tr>').join('');
  return '<div class="card"><div class="row" style="margin-bottom:10px">'
    +'<button class="btn primary" onclick="dlgIdent(\'add\')">+ مشخصات جدید</button>'
    +'<span class="muted">برای هر استعلام — ورودی و نظارتی — یک مشخصات تصادفی معتبر از همین استخر انتخاب می‌شود.</span></div>'
    +'<table><thead><tr><th>عنوان</th><th>کد ملی</th><th>تولد</th><th>موبایل</th><th></th></tr></thead>'
    +'<tbody>'+(rows||'<tr><td colspan="5">'+(searchActive()?searchEmptyHtml():emptyInnerHtml('استخر هویت خالی است','بدون حداقل یک مشخصات معتبر، هیچ استعلامی — ورودی و نظارتی — اجرا نمی‌شود.'))+'</td></tr>')+'</tbody></table></div>';
}

/* ================= ledger ================= */
function ledgerHtml(){
  var q=tabQ();
  var rows='';
  var count=0;
  /* v1.9.0: the newest customer's rows come first. ONLY this outer order
     changes — the inner loop still walks each transaction array backwards,
     because the row button hands txDetailModal the TRUE array index (idx). */
  newestFirst((STATE.customers||[]),c=>c.created).forEach(c=>{
    var txs=c.transactions||[];
    for(var idx=txs.length-1; idx>=0; idx--){            // newest first (as before)
      var t=txs[idx];
      // v1.4.0: search covers the customer name, the note and the amount
      // as a plain Latin-digit string (Persian digits normalize on both
      // sides of the match). idx stays the true transaction index.
      if(!tabSearchMatches([c.full_name,t.note,String(t.amount==null?'':t.amount)].join(' '),q))continue;
      count++;
      /* v1.6: voided transactions and their reversal rows stay visible for
         the audit trail but render struck-through and muted. */
      var dead=t.voided_at||t.kind==='void';
      rows+='<tr'+(dead?' class="voidedtx"':'')+'><td><b>'+esc(c.full_name)+'</b></td><td class="kbd">'+esc(faDateTime(t.at))+'</td>'
      +'<td>'+(t.amount<0?'<span class="pill bad">'+money(t.amount)+'</span>':'<span class="pill ok">'+money(t.amount)+'</span>')+'</td>'
      +'<td class="kbd">'+esc(t.note||'—')+'</td>'
      +'<td><button type="button" class="ibtn ghost" data-static="1" aria-label="جزئیات تراکنش" data-tip="جزئیات تراکنش" onclick="txDetailModal(\''+c.id+'\','+idx+')">'+ICONS.info+'</button></td></tr>';
    }
  });
  TAB_COUNT=count;
  return '<div class="card"><table><thead><tr><th>مشتری</th><th>زمان</th><th>مبلغ</th><th>شرح</th><th></th></tr></thead>'
    +'<tbody>'+(rows||'<tr><td colspan="5">'+(searchActive()?searchEmptyHtml():emptyInnerHtml('تراکنشی ثبت نشده است','از تب مشتریان روی «تراکنش» بزنید.'))+'</td></tr>')+'</tbody></table></div>';
}
var TX_KIND_FA={'base_fee':'هزینه ثبت رجیستری','base_fee_refund':'بازگشت هزینه ثبت رجیستری','receipt':'دریافتی','debt':'بدهی','tx':'تراکنش','void':'ابطال','':'—'};
function txDetailModal(cid, idx){
  var c=(STATE.customers||[]).find(x=>x.id===cid);
  if(!c)return;
  var t=(c.transactions||[])[idx];
  if(!t)return;
  var d=(STATE.devices||[]).find(x=>x.id===t.device_id);
  var serials=[d&&d.serial1,d&&d.serial2].filter(Boolean).join(' / ');
  var rows=[
    ['مشتری', esc(c.full_name||'—')],
    ['زمان', '<span class="kbd">'+esc(faDateTime(t.at))+'</span>'],
    ['مبلغ', t.amount<0?'<span class="pill bad">'+money(t.amount)+'</span>'
                       :'<span class="pill ok">'+money(t.amount)+'</span>'],
    ['نوع', esc(TX_KIND_FA[t.kind]||t.kind||'—')],
    ['شرح', esc(t.note||'—')],
    ['پرونده', d?esc(d.name):'<span class="muted">—</span>'],
    ['سریال دستگاه', serials?'<span class="kbd">'+esc(serials)+'</span>':'<span class="muted">—</span>'],
    ['پیوست', t.image?'<a target="_blank" href="/tx-artifact?name='+encodeURIComponent(t.image)+'">مشاهده تصویر</a>':'<span class="muted">—</span>']
  ];
  /* v1.6: a voided transaction shows when and why it was voided instead of
     the void action; a 'void' reversal row never offers the button (an
     already-voided reversal must not be voided again). */
  if(t.voided_at){
    rows.push(['تاریخ ابطال','<span class="kbd">'+esc(faDateTime(t.voided_at))+'</span>']);
    rows.push(['دلیل ابطال',esc(t.void_reason||'—')]);
  }
  var rowsHtml=rows.map(r=>'<tr><td class="muted" style="white-space:nowrap">'+r[0]+'</td><td>'+r[1]+'</td></tr>').join('');
  var voidBtn=(!t.voided_at&&t.kind!=='void')
    ?'<button class="btn danger" onclick="dlgVoidTx(\''+cid+'\','+idx+')">ابطال</button>':'';
  openDlg('<h3>جزئیات تراکنش</h3><table style="width:100%;font-size:13.5px">'+rowsHtml+'</table>'
    +'<div class="row" style="margin-top:10px">'+voidBtn
    +'<button class="btn" onclick="closeDlg()">بستن</button></div>');
}

/* ================= reports ================= */
function reportsHtml(){
  return '<div class="card">'
    +'<div class="row">'
    +'<button type="button" class="ibtn" data-static="1" aria-label="دانلود گزارش متنی" data-tip="دانلود گزارش متنی" onclick="location.href=\'/crm-report?fmt=txt\'">'+ICONS.fileText+'</button>'
    +'<button type="button" class="ibtn" data-static="1" aria-label="گزارش چاپی" data-tip="گزارش چاپی" onclick="window.open(\'/crm-report?fmt=html\',\'_blank\')">'+ICONS.printer+'</button>'
    +'<button type="button" class="ibtn" data-static="1" aria-label="دانلود PDF" data-tip="دانلود PDF" onclick="location.href=\'/crm-report?fmt=pdf\'">'+ICONS.download+'</button>'
    +'<button type="button" class="ibtn primary" aria-label="ارسال گزارش به تلگرام" data-tip="ارسال گزارش به تلگرام" onclick="sendTelegram()">'+ICONS.send+'</button></div>'
    +'<p class="muted">گزارش شامل وضعیت تمام پرونده‌هاست؛ در تلگرام کد ملی‌ها ماسک می‌شوند و شمارهٔ کارت هرگز ارسال نمی‌شود.</p>'
    +'<h3>لاگ رویدادها</h3>'
    +'<div id="logBox"></div>'
    +'</div>';
}

/* ================= dialogs ================= */
function showFieldErrors(errText){
  /* ux-guidelines (Forms/Error Placement): identify each invalid field under
     the input, not only a top-level blob; server sends "field: message" lines
     where it can (English field names from crm.py validation). */
  var box=document.querySelector('.err:not([hidden])');
  if(!box)return;
  box.textContent=errText;
  var lines=String(errText).split('\n');
  lines.forEach(function(line){
    var m=line.match(/^\s*([a-z_]+)\s*[:：]\s*(.+)$/i);
    if(!m)return;
    var input=document.querySelector('#dlgBody [id], #dlgBody input, #dlgBody select');
    var el=null;
    try{el=document.getElementById('dlgBody').querySelector('[id^="'+m[1].slice(0,4)+'"], [id$="'+m[1].slice(-4)+'"]');}catch(e){}
    if(el){el.setAttribute('aria-invalid','true');}
  });
}
function dlgDevice(){
  /* v1.8.1 (operator rule): no case outside a reporting period. The button in
     the case toolbar is already inert in that state — this is the guard for
     every other way in (a keyboard path, a page whose STATE went stale while a
     period was closed elsewhere). The server re-checks; this only saves a
     round-trip. */
  if(!activePeriod()){toast(NO_PERIOD_TIP,false);return;}
  var custOpts='<option value="">مشتری جدید</option>'+newestFirst(STATE.customers||[],c=>c.created).map(c=>'<option value="'+c.id+'">'+esc(c.full_name)+'</option>').join('');
  openDlg('<h3>پروندهٔ دستگاه جدید</h3>'
    +'<p class="muted">با ثبت دستگاه، «هزینه ثبت رجیستری» به حساب مشتری بدهکار می‌شود؛ مبلغ پیش‌فرض از تب تنظیمات خوانده می‌شود و قابل تغییر است. مبلغ دریافتی نیز به‌صورت «دریافتی» در حساب همان مشتری ثبت می‌شود.</p>'
    +'<div class="grid" style="margin-bottom:8px">'
    +'<label class="f">نام دستگاه *<input id="dvName" placeholder="iPhone 13"></label>'
    +'<label class="f">سریال اول * (IMEI ۱۵ رقمی)<input id="dvS1" inputmode="numeric" maxlength="15" placeholder="356938035643809"></label>'
    +'<label class="f">سریال دوم (اختیاری)<input id="dvS2" inputmode="numeric" maxlength="15" placeholder=""></label>'
    +'<label class="f">مبلغ دریافتی (تومان)<input id="dvRecv" class="ltr" inputmode="numeric" value="0"></label>'
    +'<label class="f">هزینه ثبت رجیستری (تومان)<input id="dvFee" class="ltr" inputmode="numeric" placeholder="پیش‌فرض تنظیمات" value="'+fa((STATE.settings||{}).registry_fee_amount||0)+'"></label>'
    +'</div>'
    +'<div class="row"><label class="f">مشتری *<select id="dvCust" onchange="document.getElementById(\'dvNewCustRow\').style.display=this.value?\'none\':\'block\'">'+custOpts+'</select></label>'
    +'<label class="f check"><input type="checkbox" id="dvAuto"><span class="box" aria-hidden="true"></span><span class="ft">پرداخت خودکار پس از ثبت در گمرک</span></label></div>'
    +'<div id="dvNewCustRow" style="display:block;margin-top:8px"><div class="grid">'
    +'<label class="f">نام مشتری *<input id="dvCn"></label>'
    +'<label class="f">موبایل (۰۹… ۱۱ رقمی)<input id="dvCm" inputmode="tel" maxlength="11" placeholder="09121234567"></label>'
    +'<label class="f">تلگرام (اختیاری)<input id="dvTg" dir="ltr" placeholder="@username"></label>'
    +'<label class="f">اینستاگرام (اختیاری)<input id="dvIg" dir="ltr" placeholder="@username"></label>'
    +'<label class="f">آدرس (اختیاری)<input id="dvCa"></label>'
    +'<label class="f">یادداشت دستگاه (اختیاری)<input id="dvNotes"></label>'
    +'</div></div>'
    +'<div class="err" id="dvErr"></div>'
    +'<div class="row" style="margin-top:10px"><button class="btn primary" onclick="doAddDevice()">ثبت پرونده</button><button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function doAddDevice(){
  var mobile=digitsFa(v('dvCm'));
  if(mobile && !/^09\d{9}$/.test(mobile)){
    document.getElementById('dvErr').textContent='موبایل باید ۱۱ رقم و با ۰۹ شروع شود';
    var el=document.getElementById('dvCm');if(el)el.setAttribute('aria-invalid','true');
    return;
  }
  var el=document.getElementById('dvCm');if(el)el.removeAttribute('aria-invalid');
  /* v1.6: amount paid up front — books as «دریافتی» on the customer's
     account (server stays the authority; 0 means no transaction). The RAW
     input is validated first: digitsFa strips '-' and '.', so a typed
     "-500" or "1.5" would otherwise silently book 500/15 (H1 review).
     The class also allows the Persian thousands separator U+066C «٬» that
     fa()-formatted amounts carry (same reason as the fee field below). */
  /* One input class for both amount fields, matching what the server's own
     parser (crm._amount_digits) strips: ASCII/Persian digits plus every
     group separator the panel's fa() formatter (toLocaleString('fa-IR')
     emits U+066C) or a paste can carry — ASCII comma, U+060C, space, NBSP,
     thin space, narrow NBSP. A sign or a dot must stay OUT of this class:
     digitsFa() drops them, so a typed "-500" would silently book +500. */
  var AMOUNT_RAW_RE=/^[\d\u06F0-\u06F9\u066C,\u060C\u00A0\u2009\u202F ]*$/;
  var recvRaw=v('dvRecv');
  if(!AMOUNT_RAW_RE.test(recvRaw)){
    document.getElementById('dvErr').textContent='مبلغ دریافتی باید عدد نامنفی باشد (تومان)';
    var rEl=document.getElementById('dvRecv');if(rEl)rEl.setAttribute('aria-invalid','true');
    return;
  }
  var recv=parseInt(digitsFa(recvRaw)||'0',10);
  if(isNaN(recv)||recv<0){
    document.getElementById('dvErr').textContent='مبلغ دریافتی باید عدد نامنفی باشد (تومان)';
    var rEl0=document.getElementById('dvRecv');if(rEl0)rEl0.setAttribute('aria-invalid','true');
    return;
  }
  var rEl=document.getElementById('dvRecv');if(rEl)rEl.removeAttribute('aria-invalid');
  /* v1.7: per-case registry fee — defaults to the configured amount; the
     operator may lower or raise it for this case only. Raw input first:
     digitsFa strips '-'/'.' so a typed "-500" must be rejected as text.
     The class must ALSO allow the Persian thousands separator U+066C «٬»:
     fa() renders the pre-filled default through toLocaleString('fa-IR'),
     so the field the operator sees already carries it and a guard that
     rejected it refused every submit. digitsFa drops it afterwards. */
  var feeRaw=v('dvFee');
  if(!AMOUNT_RAW_RE.test(feeRaw)){
    document.getElementById('dvErr').textContent='هزینه ثبت رجیستری باید عدد نامنفی باشد (تومان)';
    var fEl=document.getElementById('dvFee');if(fEl)fEl.setAttribute('aria-invalid','true');
    return;
  }
  /* An EMPTY field means "no override, charge the configured amount", which
     is exactly what the placeholder promises; only an explicit 0 means
     "charge nothing". Mapping blank to 0 (the v1.7 behaviour) booked no fee
     at all and said nothing, silently losing the configured amount. */
  /* A field holding nothing but separators (the operator cleared the digits
     of the pre-filled «۲۴٬۰۰۰٬۰۰۰» and left «٬» behind) means "no
     override" as well: reading it as 0 would silently book no fee at all. */
  var fee=null;
  var feeDigits=digitsFa(feeRaw);
  if(feeRaw!==''&&feeDigits!==''){fee=parseInt(feeDigits,10);}
  if(fee!==null&&(isNaN(fee)||fee<0)){
    document.getElementById('dvErr').textContent='هزینه ثبت رجیستری باید عدد نامنفی باشد (تومان)';
    var fEl0=document.getElementById('dvFee');if(fEl0)fEl0.setAttribute('aria-invalid','true');
    return;
  }
  var fEl2=document.getElementById('dvFee');if(fEl2)fEl2.removeAttribute('aria-invalid');
  var addBtn=document.querySelector('#dlg button[onclick="doAddDevice()"]');
  if(addBtn){if(addBtn.disabled)return;addBtn.disabled=true;
    setTimeout(function(){addBtn.disabled=false;},1500);}
  var payload={action:'add',name:v('dvName'),serial1:v('dvS1'),serial2:v('dvS2'),
    notes:v('dvNotes'),auto_advance:document.getElementById('dvAuto').checked,
    received_amount:recv};
  if(fee!==null)payload.registry_fee_override=fee;
  var custSel=v('dvCust');
  if(custSel){payload.customer_id=custSel;}
  else payload.customer={full_name:v('dvCn'),mobile:mobile,telegram_id:v('dvTg'),
    instagram_id:v('dvIg'),address:v('dvCa')};
  api('/crm-device',payload).then(async r=>{
    closeDlg();
    await refresh();
    toastCtx(r.record.name,'ثبت شد — گام ۱');
    if(r.record&&r.record.id)caseDetail(r.record.id);
  })
    .catch(e=>{showFieldErrors(String(e));});
}
/* Device EDIT modal (v1.5 B2): serial1 is the immutable case identity — the
   backend (crm.update_device) rejects serial1 changes — so the field is
   locked here and the update payload in doSaveDeviceEdit never carries a
   serial1 key. The ADD modal dlgDevice above keeps an editable serial1. */
function dlgDeviceEdit(id){
  var d=(STATE.devices||[]).find(x=>x.id===id);
  if(!d){toast('پرونده پیدا نشد',false);return;}
  var custOpts='<option value="">بدون مشتری</option>'+newestFirst(STATE.customers||[],c=>c.created).map(c=>'<option value="'+c.id+'"'+(c.id===d.customer_id?' selected':'')+'>'+esc(c.full_name)+'</option>').join('');
  openDlg('<h3>ویرایش پروندهٔ دستگاه</h3>'
    +'<div class="grid" style="margin-bottom:8px">'
    +'<label class="f">نام دستگاه *<input id="dvEName" value="'+esc(d.name||'')+'"></label>'
    +'<label class="f">سریال اول<input id="dvES1" value="'+esc(d.serial1||'')+'" inputmode="numeric" maxlength="15" disabled title="سریال اول قابل ویرایش نیست — برای تغییر، پرونده را حذف و دوباره بسازید"></label>'
    +'<label class="f">سریال دوم (اختیاری)<input id="dvES2" value="'+esc(d.serial2||'')+'" inputmode="numeric" maxlength="15"></label>'
    +'</div>'
    +'<div class="row"><label class="f">مشتری<select id="dvECust">'+custOpts+'</select></label>'
    +'<label class="f check"><input type="checkbox" id="dvEAuto"'+(d.auto_advance?' checked':'')+'><span class="box" aria-hidden="true"></span><span class="ft">پرداخت خودکار پس از ثبت در گمرک</span></label></div>'
    +'<label class="f" style="margin-top:8px">یادداشت دستگاه (اختیاری)<input id="dvENotes" value="'+esc(d.notes||'')+'"></label>'
    +'<div class="err" id="dvEErr"></div>'
    +'<div class="row" style="margin-top:10px"><button class="btn primary" onclick="doSaveDeviceEdit(\''+id+'\')">ذخیره</button><button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function doSaveDeviceEdit(id){
  var nm=v('dvEName');
  var payload={action:'update',id:id,name:nm,serial2:v('dvES2'),
    customer_id:v('dvECust'),notes:v('dvENotes'),
    auto_advance:document.getElementById('dvEAuto').checked};
  /* No closeDlg() here: when the edit was opened from the case detail the
     dialog returns to it via dlgCaseRestore; otherwise it just closes. */
  api('/crm-device',payload).then(async()=>{toastCtx(nm,'ذخیره شد');await refresh();dlgCaseRestore(id);if(!CASE_MODAL.live)closeDlg();})
    .catch(e=>{document.getElementById('dvEErr').textContent=e;showFieldErrors(String(e));});
}
function digitsFa(s){return String(s||'').replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[^0-9]/g,'');}
/* Gomrok inquiries need a usable identity. Approximate client-side mirror
   of the backend pool validation (crm.pick_pool_identity ->
   panel.validate_estelam_person): an entry roughly validates when national
   is 10 digits and mobile is 09xxxxxxxxx (both after digitsFa), and birth
   looks like YYYY/MM/DD. digitsFa strips separators, so birth is checked on
   a Persian-digit-normalized copy that keeps the slashes; the year test
   /\d{4} is deliberately looser than the backend's 1[34]\d{2} — the backend
   stays the authority, this gate only disables the obvious no-valid-entry
   case and devInquire still surfaces the exact backend error. */
function identityPoolReady(){
  return (STATE.identities||[]).some(function(i){
    var birth=String((i&&i.birth)||'').replace(/[۰-۹]/g,d=>'۰۱۲۳۴۵۶۷۸۹'.indexOf(d));
    return /^\d{10}$/.test(digitsFa(i.national))
      && /^09\d{9}$/.test(digitsFa(i.mobile))
      && /\d{4}\/\d{2}\/\d{2}/.test(birth);
  });
}
var IDENTITY_POOL_HINT='ابتدا در بخش استخر هویت حداقل یک مشخصات معتبر اضافه کنید';
function gomrokGateAttrs(){
  return identityPoolReady()?'':' disabled title="'+IDENTITY_POOL_HINT+'"';
}
function dlgAttach(id){
  /* v1.5: only FREE owners are pickable — the bound map stays purely as
     the filter (the server remains the enforcer of the 1:1). With no free
     owner the dialog says so and the attach button stays disabled. */
  var bound={};(STATE.devices||[]).forEach(d=>{if(d.owner_id)bound[d.owner_id]=true;});
  /* v1.9.0: newest passenger first in the picker, like the passenger tab. */
  var free=newestFirst((STATE.owners||[]).filter(o=>!bound[o.id]),o=>o.created);
  var opts=free.map(o=>{
    var label=esc(o.first_name+' '+o.last_name)+' — '+esc(o.national);
    return '<option value="'+o.id+'">'+label+'</option>';
  }).join('');
  openDlg('<h3>اتصال مسافر به دستگاه</h3>'
    +(free.length
      ?'<div class="row"><select id="attOwner">'+opts+'</select>'
       +'<button class="btn primary" onclick="doAttach(\''+id+'\')">اتصال</button></div>'
      :'<p class="muted">مسافر آزادی برای اتصال وجود ندارد.</p>'
       +'<div class="row" style="margin-top:10px"><button class="btn primary" disabled>اتصال</button>'
       +'<button class="btn" onclick="closeDlg()">انصراف</button></div>')
    +'<p class="muted">هر مسافر فقط به یک دستگاه متصل می‌شود (نسبت یک‌به‌یک).</p>');
}
function doAttach(id){
  var o=findOwner(document.getElementById('attOwner').value);
  var oname=o?(o.first_name+' '+o.last_name):'';
  api('/crm-tick',{device_id:id,action:'attach_owner',owner_id:document.getElementById('attOwner').value})
    .then(async r=>{toastCtx(oname,'متصل شد');if(r.profile_notice){toastCtx(oname,r.profile_notice,false);}await refresh();dlgCaseRestore(id);if(!CASE_MODAL.live)closeDlg();})
    .catch(e=>toastCtx(oname,String(e),false));
}
function devInquire(id, service){
  if(service!=='hamta'&&!identityPoolReady()){toast(IDENTITY_POOL_HINT,false);return;}
  var nm=(STATE.devices||[]).find(x=>x.id===id); var cn=(nm?nm.name:'')||'';
  var wasModal=CASE_MODAL.live&&CASE_MODAL.id===id;
  var labels={gomrok:'گمرک',hamta:'همتا',all:'همهٔ استعلام‌ها'};
  confirmDlg('اجرای استعلام','استعلام «'+(labels[service]||service)+'» برای این دستگاه اجرا شود؟',
    'اجرا',function(){
      api('/crm-inquire',{device_id:id,service:service}).then(async r=>{
        toastCtx(cn,'استعلام شروع شد'+(r.pid?' (pid '+r.pid+')':''));await refresh();if(wasModal)caseDetail(id);})
        .catch(e=>{toastCtx(cn,String(e),false);if(wasModal)caseDetail(id);});
    });
}
function stageContinueClick(id, btn){
  var d=(STATE.devices||[]).find(x=>x.id===id);
  if(!d)return;
  var cont=stageContinue(d);
  if(!cont){return;}
  if(!cont.ready){toast('نیازمند: '+(cont.need||'تکمیل این مرحله'),false);return;}
  /* Double-click guard: a second POST before the first one lands is what
     produced the old «این کنش در مرحلهٔ فعلی مجاز نیست» errors. Re-enable
     after a beat — a successful action re-renders the card anyway and a
     failed one must not leave the button stuck. */
  if(btn){if(btn.disabled)return;btn.disabled=true;
    setTimeout(function(){btn.disabled=false;},1500);}
  devTick(id,cont.action);
}
function payStop(id){
  var d=(STATE.devices||[]).find(x=>x.id===id);
  var pid=(d&&d.pay&&d.pay.runner_pid)||0;
  var cn=(d&&d.name)||'';
  var wasModal=CASE_MODAL.live&&CASE_MODAL.id===id;
  confirmDlg('توقف ربات پرداخت','ربات پرداخت این پرونده متوقف شود؟ مرورگرِ در حال اجرا بسته می‌شود و می‌توانید دوباره شروع کنید.',
    'توقف ربات',function(){
      api('/crm-pay-stop',{device_id:id,pid:pid}).then(async r=>{
        toastCtx(cn,r.ok?'ربات پرداخت متوقف شد':'توقف انجام نشد',r.ok);await refresh();if(wasModal)caseDetail(id);})
        .catch(e=>{toastCtx(cn,String(e),false);if(wasModal)caseDetail(id);});
    });
}
function payBrowser(id,visible){
  var d=(STATE.devices||[]).find(x=>x.id===id);
  var pid=(d&&d.profile_id)||'';
  var cn=(d&&d.name)||'';
  if(!pid){toast('پروفایل پرداخت این پرونده هنوز ساخته نشده',false);return;}
  api('/browser-visibility',{id:pid,visible:visible}).then(async r=>{
    toastCtx(cn,visible?'مرورگر ربات پرداخت نمایش داده شد':'مرورگر ربات پرداخت مخفی شد');await refresh();}).catch(e=>toastCtx(cn,String(e),false));
}
function crmStopRun(){
  confirmDlg('توقف ربات استعلام','ربات استعلام متوقف شود؟ مرورگرِ در حال اجرا بسته می‌شود و ردیف‌های در جریان به «در صف» برمی‌گردند.',
    'توقف',function(){
      api('/crm-stop',{}).then(async r=>{
        toast(r.stopped?'استعلام متوقف و مرورگر بسته شد':'اجرای فعالی برای توقف نبود');await refresh();})
        .catch(e=>toast(e,false));
    });
}
function devDelete(id){
  var nm=(STATE.devices||[]).find(x=>x.id===id); var dn=(nm?nm.name:'')||'';
  confirmDlg('حذف پرونده','این پرونده حذف شود؟ ردیف استعلام آن نیز حذف می‌شود و برگشت‌پذیر نیست.',
    'حذف پرونده',function(){
      api('/crm-device',{action:'delete',id:id}).then(async()=>{closeDlg();toastCtx(dn,'حذف شد');await refresh();}).catch(e=>toastCtx(dn,String(e),false));
    });
}
function dlgCustomer(mode,id){
  var c = id?findCustomer(id):{};
  openDlg('<h3>'+(id?'ویرایش مشتری':'مشتری جدید')+'</h3>'
    +'<div class="grid">'
    +'<label class="f">نام و نام خانوادگی *<input id="cName" value="'+esc(c.full_name||'')+'"></label>'
    +'<label class="f">موبایل<input id="cMobile" value="'+esc(c.mobile||'')+'" inputmode="tel"></label>'
    +'<label class="f">تلگرام<input id="cTg" value="'+esc(c.telegram_id||'')+'"></label>'
    +'<label class="f">اینستاگرام<input id="cIg" value="'+esc(c.instagram_id||'')+'"></label>'
    +'</div>'
    +'<label class="f" style="margin-top:8px">آدرس<textarea id="cAddr" style="width:100%">'+esc(c.address||'')+'</textarea></label>'
    +'<label class="f" style="margin-top:8px">یادداشت<textarea id="cNotes" style="width:100%">'+esc(c.notes||'')+'</textarea></label>'
    +'<div class="err" id="cErr"></div>'
    +'<div class="row" style="margin-top:10px"><button class="btn primary" onclick="doSaveCustomer(\''+(id||'')+'\')">ذخیره</button><button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function doSaveCustomer(id){
  var cnm=v('cName');
  var payload={action:id?'update':'add',full_name:cnm,mobile:v('cMobile'),
    telegram_id:v('cTg'),instagram_id:v('cIg'),address:v('cAddr'),notes:v('cNotes')};
  if(id)payload.id=id;
  api('/crm-customer',payload).then(async()=>{closeDlg();toastCtx(cnm,'ذخیره شد');await refresh();})
    .catch(e=>{document.getElementById('cErr').textContent=e;showFieldErrors(String(e));});
}
function custDelete(id){
  /* v1.8: the styled confirm replaces the blocking native one, so a cancelled
     delete can never leave the row's icon spinning (and the page keeps one
     confirmation language). */
  var hasDevices=(STATE.devices||[]).some(d=>d.customer_id===id);
  var msg=hasDevices?'این مشتری دستگاه دارد؛ دستگاه‌ها فقط از اتصال مشتری آزاد می‌شوند. حذف شود؟'
                    :'مشتری حذف شود؟';
  confirmDlg('حذف مشتری',msg,'حذف مشتری',function(){
    api('/crm-customer',{action:'delete',id:id,force:true}).then(async()=>{toastCtx(custName(id),'حذف شد');await refresh();}).catch(e=>toast(e,false));
  });
}
function dlgTx(cid){
  openDlg('<h3>تراکنش جدید — '+esc(custName(cid))+'</h3>'
    +'<div class="row"><label class="f">مبلغ (تومان؛ بدهی منفی)<input id="txAmt" inputmode="numeric" style="width:170px"></label>'
    +'<label class="f">شرح<input id="txNote" style="flex:1"></label></div>'
    +'<div class="err" id="txErr"></div>'
    +'<div class="row" style="margin-top:10px"><button class="btn primary" onclick="doTx(\''+cid+'\')">ثبت</button><button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function dlgReceipt(cid){
  openDlg('<h3>ثبت دریافتی — '+esc(custName(cid))+'</h3>'
    +'<div class="row"><label class="f">مبلغ (تومان)<input id="txAmt" inputmode="numeric" class="ltr" style="width:170px"></label>'
    +'<label class="f">شرح<input id="txNote" style="flex:1" placeholder="مثلاً واریز کارت به کارت"></label></div>'
    +'<label class="f" style="margin-top:8px">عکس رسید (اختیاری — PNG/JPG تا ۴ مگابایت)'
    +'<input id="txImage" type="file" accept="image/png,image/jpeg,image/webp" onchange="readTxImage(this)"></label>'
    +'<div class="kbd" id="txImageName" style="margin-top:4px;display:none"></div>'
    +'<div class="err" id="txErr"></div>'
    +'<div class="row" style="margin-top:10px"><button class="btn primary" onclick="doTx(\''+cid+'\',\'receipt\')">ثبت دریافتی</button><button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function dlgDebt(cid){
  openDlg('<h3>ثبت بدهی جدید — '+esc(custName(cid))+'</h3>'
    +'<div class="row"><label class="f">مبلغ (تومان)<input id="txAmt" inputmode="numeric" class="ltr" style="width:170px"></label>'
    +'<label class="f">شرح<input id="txNote" style="flex:1" placeholder="مثلاً هزینه قطعه"></label></div>'
    +'<label class="f" style="margin-top:8px">عکس مدرک بدهی (اختیاری — مثل عکس سریال دستگاه)'
    +'<input id="txImage" type="file" accept="image/png,image/jpeg,image/webp" onchange="readTxImage(this)"></label>'
    +'<div class="kbd" id="txImageName" style="margin-top:4px;display:none"></div>'
    +'<div class="err" id="txErr"></div>'
    +'<div class="row" style="margin-top:10px"><button class="btn primary" onclick="doTx(\''+cid+'\',\'debt\')">ثبت بدهی</button><button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
var TX_IMAGE_B64='', TX_IMAGE_MIME='';
function readTxImage(input){
  TX_IMAGE_B64='';TX_IMAGE_MIME='';
  var label=document.getElementById('txImageName');
  var file=input.files&&input.files[0];
  if(!file){if(label)label.style.display='none';return;}
  if(file.size>4*1024*1024){
    document.getElementById('txErr').textContent='حجم تصویر بیشتر از ۴ مگابایت است';
    input.value='';if(label)label.style.display='none';return;
  }
  TX_IMAGE_MIME=file.type||'image/png';
  var reader=new FileReader();
  reader.onload=function(){TX_IMAGE_B64=String(reader.result||'');
    if(label){label.textContent='پیوست: '+file.name;label.style.display='';}};
  reader.readAsDataURL(file);
}
function doTx(cid,kind){
  var amount=Number(String(v('txAmt')||'').replace(/[,\s،]/g,''))||0;
  if(!amount){document.getElementById('txErr').textContent='مبلغ باید عدد باشد';return;}
  var isDebt=(kind==='debt');
  var payload={action:'tx',id:cid,amount:isDebt?-amount:amount,note:v('txNote'),
               kind:kind||'tx'};
  if(TX_IMAGE_B64){payload.image_b64=TX_IMAGE_B64;payload.image_mime=TX_IMAGE_MIME;}
  api('/crm-customer',payload)
    .then(async()=>{TX_IMAGE_B64='';TX_IMAGE_MIME='';closeDlg();toast('ثبت شد');await refresh();})
    .catch(e=>{document.getElementById('txErr').textContent=e;showFieldErrors(String(e));});
}
/* ================= void transaction (v1.6) ================= */
/* Voiding is bookkeeping-sensitive: the original row stays (history is
   never rewritten), a mirrored reversal row is appended, and both drop out
   of every balance. The reason is captured first, then the styled confirm —
   the same two-step shape as closeCaseDialog. */
function dlgVoidTx(cid, idx){
  var c=(STATE.customers||[]).find(x=>x.id===cid);
  if(!c){toast('مشتری پیدا نشد',false);return;}
  var t=(c.transactions||[])[idx];
  if(!t){toast('تراکنش پیدا نشد',false);return;}
  var info=[
    ['نوع', esc(TX_KIND_FA[t.kind]||t.kind||'—')],
    ['مبلغ', t.amount<0?'<span class="pill bad">'+money(t.amount)+'</span>'
                       :'<span class="pill ok">'+money(t.amount)+'</span>'],
    ['شرح', esc(t.note||'—')],
    ['زمان', '<span class="kbd">'+esc(faDateTime(t.at))+'</span>']
  ].map(r=>'<tr><td class="muted" style="white-space:nowrap">'+r[0]+'</td><td>'+r[1]+'</td></tr>').join('');
  openDlg('<h3>ابطال تراکنش</h3>'
    +'<table style="width:100%;font-size:13.5px">'+info+'</table>'
    +'<p style="margin:12px 0 0;color:var(--txt);font-size:13px;line-height:1.9">هشدار: ابطال، تراکنش را از محاسبه‌ها خارج می‌کند و یک ردیف اصلاحیهٔ قرینه ثبت می‌شود؛ تاریخچه پاک نمی‌شود.</p>'
    +'<label class="f" style="margin-top:8px">دلیل ابطال *<textarea id="vtReason" rows="3" style="width:100%"></textarea></label>'
    +'<div class="row" style="margin-top:10px"><button class="btn danger" onclick="doVoidTx(\''+cid+'\','+idx+',this)">ابطال</button>'
    +'<button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function doVoidTx(cid, idx, btn){
  /* The reason must exist before the confirm replaces this dialog; the
     message is the canonical one the server also answers with. */
  var reason=v('vtReason');
  if(!reason){toast('ثبت دلیل برای ابطال الزامی است',false);return;}
  /* Double-click guard (same shape as doDetach/stageContinueClick). */
  if(btn){if(btn.disabled)return;btn.disabled=true;
    setTimeout(function(){btn.disabled=false;},1500);}
  var cn=custName(cid);
  confirmDlg('تأیید ابطال','این تراکنش ابطال شود؟ این کار قابل بازگشت نیست.','بله، ابطال کن',function(){
    api('/crm-customer',{action:'void_tx',id:cid,tx_index:idx,reason:reason}).then(async()=>{
      toastCtx(cn,'تراکنش ابطال شد.');
      await refresh();
      renderView();
      closeDlg();
    }).catch(e=>toast(e,false));
  });
}
function dlgOwner(mode,id){
  var o = id?findOwner(id):{};
  /* Passport is required for the registration submission (v1.5); owners
     created before the field existed get a hint under the empty input. */
  var passHint=(id&&!String(o.passport||'').trim())
    ?'<span class="muted" style="display:block;margin-top:2px;font-size:12px">برای ارسال اطلاعات ثبت، شمارهٔ گذرنامه لازم است</span>'
    :'';
  openDlg('<h3>'+(id?'ویرایش مسافر':'مسافر جدید')+'</h3><div class="grid">'
    +'<label class="f">نام *<input id="oFn" value="'+esc(o.first_name||'')+'"></label>'
    +'<label class="f">نام خانوادگی *<input id="oLn" value="'+esc(o.last_name||'')+'"></label>'
    +'<label class="f">کد ملی *<input id="oNat" value="'+esc(o.national||'')+'" inputmode="numeric"></label>'
    +'<label class="f">تاریخ تولد * (۱۳۷۵/۰۴/۲۹)<input id="oBirth" value="'+esc(o.birth||'')+'"></label>'
    +'<label class="f">موبایل *<input id="oMob" value="'+esc(o.mobile||'')+'" inputmode="tel"></label>'
    +'<label class="f">گذرنامه<input id="oPassport" value="'+esc(o.passport||'')+'" dir="ltr">'+passHint+'</label>'
    +'<label class="f">شماره کارت ۱۶ رقمی<input id="oCard" value="'+esc(o.card_no||'')+'" inputmode="numeric"></label>'
    +'</div><div class="err" id="oErr"></div>'
    +'<div class="row" style="margin-top:10px"><button class="btn primary" onclick="doSaveOwner(\''+(id||'')+'\')">ذخیره</button><button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function doSaveOwner(id){
  var onm=v('oFn')+' '+v('oLn');
  var payload={action:id?'update':'add',first_name:v('oFn'),last_name:v('oLn'),
    national:v('oNat'),birth:v('oBirth'),mobile:v('oMob'),passport:v('oPassport'),card_no:v('oCard')};
  if(id)payload.id=id;
  api('/crm-owner',payload).then(async()=>{closeDlg();toastCtx(onm,'ذخیره شد');await refresh();})
    .catch(e=>{document.getElementById('oErr').textContent=e;showFieldErrors(String(e));});
}
function ownerDelete(id){
  /* v1.5: destructive actions use the styled confirmDlg (never the native
     blocking confirm) — same shape as devDelete. */
  var onm=ownerName(id);
  confirmDlg('حذف مسافر','این مسافر حذف شود؟','حذف مسافر',function(){
    api('/crm-owner',{action:'delete',id:id}).then(async()=>{closeDlg();toastCtx(onm,'حذف شد');await refresh();}).catch(e=>toastCtx(onm,String(e),false));
    });
}
/* v1.5: detaching a passenger (owners tab). The server allows the tick
   only from اتصال مسافر / دارای اشکال / مختومه; past the handover the
   modal guides instead of confirming (the tick would be rejected). */
function dlgDetach(ownerId){
  var dev=(STATE.devices||[]).find(d=>d.owner_id===ownerId);
  if(!dev){toast('پرونده پیدا نشد',false);return;}
  var owner=findOwner(ownerId)||{};
  var serials=[dev.serial1,dev.serial2].filter(Boolean).join(' / ');
  var info=[
    ['مسافر', esc(ownerName(ownerId))],
    ['کد ملی', '<span class="kbd">'+esc(owner.national||'—')+'</span>'],
    ['دستگاه', esc(dev.name)+(serials?' <span class="kbd" dir="ltr">'+esc(serials)+'</span>':'')],
    ['مشتری', esc(custName(dev.customer_id))],
    ['گام فعلی', '<span class="pill '+(STAGE_TONE[dev.stage]||'n')+'">'+(STAGE_FA[dev.stage]||esc(dev.stage))+'</span>']
  ].map(r=>'<tr><td class="muted" style="white-space:nowrap">'+r[0]+'</td><td>'+r[1]+'</td></tr>').join('');
  var actions;
  if(['ready_owner','problem','closed'].includes(dev.stage)){
    actions='<p style="margin:12px 0 0;color:var(--txt);font-size:13px;line-height:1.9">هشدار: هر مسافر فقط به یک پرونده متصل می‌ماند. با قطع اتصال، مسافر برای اتصال به پروندهٔ دیگری آزاد می‌شود و پروفایل ثبت‌نام او از این پرونده جدا می‌شود.</p>'
      +'<div class="row" style="margin-top:12px"><button class="btn danger" onclick="doDetach(\''+dev.id+'\',this)">قطع اتصال</button>'
      +'<button class="btn" onclick="closeDlg()">انصراف</button></div>';
  }else{
    /* handed..payment_done, or a case rolled back before step 3 (the owner
       link survives stage_back): same remedy sentence, minus the claim
       about the handover which only holds for the blocked stages. */
    var guide=['handed','to_payment','payment','payment_done'].includes(dev.stage)
      ?'این پرونده به مسئول ثبت تحویل شده است. برای قطع اتصال، ابتدا پرونده را به گام ۳ (اتصال مسافر) برگردانید یا آن را مختومه کنید.'
      :'برای قطع اتصال، ابتدا پرونده را به گام ۳ (اتصال مسافر) برگردانید یا آن را مختومه کنید.';
    actions='<p style="margin:12px 0 0;color:var(--muted);font-size:13px;line-height:1.9">'+guide+'</p>'
      +'<div class="row" style="margin-top:12px"><button class="btn" onclick="closeDlg()">بستن</button></div>';
  }
  openDlg('<h3>قطع اتصال مسافر</h3>'
    +'<table style="width:100%;font-size:13.5px">'+info+'</table>'+actions);
}
function doDetach(id,btn){
  /* Double-click guard (same shape as stageContinueClick): a second click
     before the POST lands produced the old stage-mismatch errors. */
  if(btn){if(btn.disabled)return;btn.disabled=true;
    setTimeout(function(){btn.disabled=false;},1500);}
  var dev=(STATE.devices||[]).find(x=>x.id===id);
  var onm=dev?ownerName(dev.owner_id):'—';
  var dnm=(dev&&dev.name)||'';
  confirmDlg('تأیید قطع اتصال','مسافر '+onm+' از پروندهٔ '+dnm+' قطع شود؟ مرحلهٔ پرونده تغییری نمی‌کند.','بله، قطع اتصال کن',function(){
    api('/crm-tick',{device_id:id,action:'detach_owner'}).then(async()=>{
      toastCtx(onm,'اتصال مسافر قطع شد.');
      await refresh();
      renderView();
      closeDlg();
    }).catch(e=>toastCtx(onm,String(e),false));
  });
}
function dlgIdent(mode,id){
  var i = id?(STATE.identities||[]).find(x=>x.id===id)||{}:{};
  openDlg('<h3>'+(id?'ویرایش مشخصات':'مشخصات استعلام جدید')+'</h3><div class="grid">'
    +'<label class="f">عنوان<input id="iLabel" value="'+esc(i.label||'')+'"></label>'
    +'<label class="f">کد ملی *<input id="iNat" value="'+esc(i.national||'')+'" inputmode="numeric"></label>'
    +'<label class="f">تاریخ تولد * (۱۳۷۵/۰۴/۲۹)<input id="iBirth" value="'+esc(i.birth||'')+'"></label>'
    +'<label class="f">موبایل *<input id="iMob" value="'+esc(i.mobile||'')+'" inputmode="tel"></label>'
    +'</div><div class="err" id="iErr"></div>'
    +'<div class="row" style="margin-top:10px"><button class="btn primary" onclick="doSaveIdent(\''+(id||'')+'\')">ذخیره</button><button class="btn" onclick="closeDlg()">انصراف</button></div>');
}
function doSaveIdent(id){
  var inm=v('iLabel');
  var payload={action:id?'update':'add',label:inm,national:v('iNat'),
    birth:v('iBirth'),mobile:v('iMob')};
  if(id)payload.id=id;
  api('/crm-identity',payload).then(async()=>{closeDlg();toastCtx(inm,'ذخیره شد');await refresh();})
    .catch(e=>{document.getElementById('iErr').textContent=e;showFieldErrors(String(e));});
}
function identDelete(id){
  var i=(STATE.identities||[]).find(x=>x.id===id);
  confirmDlg('حذف مشخصات','مشخصات از استخر حذف شود؟ این مشخصات از پرونده‌های متصل هم جدا می‌شود.','حذف از استخر',function(){
    api('/crm-identity',{action:'delete',id:id}).then(async()=>{toastCtx((i&&i.label)||'','حذف شد');await refresh();}).catch(e=>toast(e,false));
  });
}
function sendTelegram(){
  api('/crm-report-telegram',{full_data:document.documentElement.dataset.full==='1'})
    .then(r=>toast('ارسال شد ('+fa(r.chunks)+' بخش)')).catch(e=>toast(e,false));
}

/* ================= finance report dialog (v1.5) ================= */
/* Period state is session-scoped: FIN_MODE persists across opens; FIN_REF
   resets to "today" on EVERY open — implemented by fetching without ref and
   adopting the server-returned from. No date beyond ±day/±week arithmetic
   on that anchor is ever computed here; all labels (from_fa/to_fa/day_fa)
   come from the response. FIN_SEQ drops stale responses that race a newer
   fetch (fast period navigation). */
var FIN_MODE='daily',FIN_REF='',FIN_PERIOD='',FIN_DATA=null,FIN_ERR='',FIN_SEQ=0;
function finIso(d){
  var p=function(n){return (n<10?'0':'')+n;};
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate());
}
function finPeriodPick(){
  var sel=document.getElementById('finPeriodSel');
  if(!sel)return;
  FIN_PERIOD=sel.value;FIN_REF='';FIN_DATA=null;FIN_ERR='';FIN_SEQ++;
  finLoad();
}
function finUrl(){
  if(FIN_MODE==='period')
    return '/crm-finance-report?mode=period'+(FIN_PERIOD?'&ref='+FIN_PERIOD:'')+'&fmt=json';
  return '/crm-finance-report?mode='+FIN_MODE+(FIN_REF?'&ref='+FIN_REF:'')+'&fmt=json';
}
/* v1.7: the report toolbar. Built separately from the dialog shell because
   finMode() rebuilds it in place — the period selector only exists in
   period mode, so switching modes must re-render the bar or the operator
   never sees a period to pick. */
function finBarHtml(){
  var periodMode=(FIN_MODE==='period');
  var sel=periodMode
    ?'<select id="finPeriodSel" onchange="finPeriodPick()" style="max-width:180px">'
      +((STATE.periods||[]).slice().reverse().map(p=>
        '<option value="'+p.id+'"'+(FIN_PERIOD===p.id?' selected':'')+'>'+esc(p.label||('دورهٔ '+fa(p.number||0)))+(p.closed_at?' (بسته)':' (باز)')+'</option>'
      ).join('')||'<option value="">دوره‌ای نیست</option>')+'</select>'
    :'';
  return '<div class="row" style="margin-bottom:10px"><div class="seg" id="finSeg">'
    +'<button type="button" class="'+(FIN_MODE==='daily'?'on':'')+'" data-m="daily" aria-pressed="'+(FIN_MODE==='daily'?'true':'false')+'" onclick="finMode(\'daily\')">روزانه</button>'
    +'<button type="button" class="'+(FIN_MODE==='weekly'?'on':'')+'" data-m="weekly" aria-pressed="'+(FIN_MODE==='weekly'?'true':'false')+'" onclick="finMode(\'weekly\')">هفتگی</button>'
    +'<button type="button" class="'+(periodMode?'on':'')+'" data-m="period" aria-pressed="'+(periodMode?'true':'false')+'" onclick="finMode(\'period\')">دوره</button></div>'
    +sel
    /* The date nav (previous/next/today) is meaningless over a period: a
       period is picked by name, not by shifting a day. */
    +(periodMode?''
      :'<button type="button" class="btn mini" title="بازهٔ قبلی" aria-label="بازهٔ قبلی" onclick="finShift(-1)">'+ICONS.chevR+'</button>'
       +'<button type="button" class="btn mini" title="بازهٔ بعدی" aria-label="بازهٔ بعدی" onclick="finShift(1)">'+ICONS.chevL+'</button>'
       +'<button type="button" class="btn mini" id="finReset" onclick="finReset()">'+(FIN_MODE==='daily'?'امروز':'این هفته')+'</button>')
    +'<span class="chip" id="finLabel">…</span></div>';
}
function dlgFinance(){
  FIN_REF='';FIN_DATA=null;FIN_ERR='';FIN_SEQ++;
  openDlg('<div class="findlg"><h3>گزارش مالی مشتریان</h3>'
    +'<div id="finBar">'+finBarHtml()+'</div>'
    +'<div id="finBody"><div class="muted">در حال دریافت گزارش…</div></div>'
    +'<div class="row" style="margin-top:12px">'
    +'<button type="button" class="btn" id="finPrint" disabled onclick="finOpen(\'html\')">چاپ</button>'
    +'<button type="button" class="btn" id="finPdf" disabled onclick="finOpen(\'pdf\')">PDF</button>'
    +'<button type="button" class="btn primary" id="finTg" disabled onclick="finTelegram()">ارسال به تلگرام</button>'
    +'<button type="button" class="btn" onclick="closeDlg()">بستن</button></div></div>');
  finLoad();
}
function finMode(m){
  if(FIN_MODE===m)return;
  FIN_MODE=m;
  /* v1.7: entering period mode selects the newest period by default.
     Either way the date anchor resets, so leaving period mode lands on
     today rather than on the period's open date. FIN_PERIOD is kept so
     returning to period mode re-selects the same period. */
  if(m==='period'){
    var pers=(STATE.periods||[]);
    if(pers.length&&!FIN_PERIOD)FIN_PERIOD=pers[pers.length-1].id;
  }
  FIN_REF='';
  var bar=document.getElementById('finBar');
  if(bar)bar.innerHTML=finBarHtml();
  finLoad();
}
function finShift(dir){
  var d=new Date(String(FIN_REF||'')+'T00:00:00');
  if(!FIN_REF||isNaN(d)){finReset();return;}
  d.setDate(d.getDate()+(FIN_MODE==='weekly'?7:1)*dir);
  FIN_REF=finIso(d);
  finLoad();
}
function finReset(){
  FIN_REF='';FIN_DATA=null;FIN_ERR='';finLoad();
}
function finLoad(){
  var seq=++FIN_SEQ;
  FIN_ERR='';FIN_DATA=null;
  finPaint();
  api(finUrl()).then(function(r){
    if(seq!==FIN_SEQ)return;
    FIN_DATA=r;
    if(r&&r.from)FIN_REF=String(r.from);
    finPaint();
  }).catch(function(e){
    if(seq!==FIN_SEQ)return;
    FIN_ERR=String(e);
    finPaint();
  });
}
function finPaint(){
  var body=document.getElementById('finBody');
  if(body)body.innerHTML=finBodyHtml();
  var lbl=document.getElementById('finLabel');
  if(lbl)lbl.innerHTML=finLabelHtml();
  var has=!!FIN_DATA;
  ['finPrint','finPdf','finTg'].forEach(function(bid){
    var b=document.getElementById(bid);
    if(b)b.disabled=!has;
  });
}
function finLabelHtml(){
  if(!FIN_DATA)return '…';
  if(FIN_MODE==='period'){
    var p=FIN_DATA.period||{};
    return esc(p.label||('دورهٔ '+fa(p.number||0)))
      +(p.closed_at? '، بسته در '+faDateTime(p.closed_at):'، باز');
  }
  return FIN_MODE==='daily'?esc(FIN_DATA.from_fa||'')
    :'از '+esc(FIN_DATA.from_fa||'')+' تا '+esc(FIN_DATA.to_fa||'');
}
/* v1.7: a period that is still open warns the operator right inside the
   report that the figures are not final. */
function finOpenWarningHtml(){
  if(!FIN_DATA||!FIN_DATA.open_warning)return '';
  return '<div class="row" style="margin:0 0 10px"><span class="pill warn">'
    +ICONS.warn+' '+esc(FIN_DATA.open_warning)+'</span></div>';
}
function finBal(n){
  n=Number(n||0);
  if(n<0)return '<span class="fin-bad">'+money(n)+'</span>';
  if(n>0)return '<span class="fin-ok">'+money(n)+'</span>';
  return '<span class="fin-zero">تسویه</span>';
}
function finBodyHtml(){
  if(FIN_ERR)return '<div class="err">'+esc(FIN_ERR)+'</div>';
  if(!FIN_DATA)return '<div class="muted">در حال دریافت گزارش…</div>';
  var r=FIN_DATA,t=r.totals||{};
  var split=(Number(t.closing)||0)===0
    ?'<span class="pill n">تسویه</span>'
    :'<span class="pill bad">بدهکار '+money(t.debtors_total)+'</span> / <span class="pill ok">بستانکار '+money(t.creditors_total)+'</span>';
  var warn=finOpenWarningHtml();
  var html=warn+'<div class="finkpis">'
    +'<div class="finkpi ok"><span class="l">دریافتی‌های نقدی (واریزی)</span><span class="v">'+money(t.receipts)+'</span></div>'
    +'<div class="finkpi bad"><span class="l">بدهکاری‌های جدید</span><span class="v">'+money(t.debits)+'</span></div>'
    +'<div class="finkpi '+(t.closing>0?'ok':(t.closing<0?'bad':''))+'"><span class="l">ماندهٔ کل مشتریان</span><span class="v">'+money(t.closing)+'</span>'
    +'<span class="split">'+split+'</span></div></div>';
  if(FIN_MODE==='weekly'&&(r.days||[]).length){
    html+='<div class="findays">'+r.days.map(function(day){
      var rc=Number(day.receipts||0),db=Number(day.debits||0);
      return '<div class="finday"><span class="d">'+esc(day.day_fa)+'</span>'
        +'<span class="dt">'+esc(day.date_fa)+'</span>'
        +'<span class="r'+(rc?'':' zero')+'" title="دریافتی">'+money(rc)+'</span>'
        +'<span class="b'+(db?'':' zero')+'" title="بدهکاری">'+money(db)+'</span></div>';
    }).join('')+'</div>';
  }
  var rows=(r.customers||[]).map(function(c){
    var cr=Number(c.credits||0),db=Math.abs(Number(c.debits||0));
    var bar=(cr+db)>0?'<div class="finbar"><span class="g" style="width:'+Math.round(cr*100/(cr+db))+'%"></span><span class="b"></span></div>':'';
    return '<tr><td><b>'+esc(c.name)+'</b>'+bar+'</td>'
      +'<td class="finnum">'+finBal(c.opening)+'</td>'
      +'<td class="finnum fin-bad">'+money(c.debits)+'</td>'
      +'<td class="finnum fin-ok">'+money(c.credits)+'</td>'
      +'<td class="finnum">'+finBal(c.closing)+'</td></tr>';
  }).join('');
  html+='<table><thead><tr><th>مشتری</th><th>ماندهٔ اول</th><th>بدهکاری</th><th>بستانکاری</th><th>ماندهٔ پایان</th></tr></thead>'
    +'<tbody>'+(rows||'<tr><td colspan="5" class="muted" style="padding:16px 8px">در این بازه تراکنشی ثبت نشده است.</td></tr>')+'</tbody></table>';
  var txs=r.transactions||[];
  var txRows=txs.map(function(x){
    return '<div class="fintx"><span class="kbd">'+esc(faDateTime(x.at))+'</span>'
      +'<b>'+esc(x.customer)+'</b><span>'+esc(x.label)+'</span>'
      +(Number(x.amount)<0?'<span class="pill bad">'+money(x.amount)+'</span>':'<span class="pill ok">'+money(x.amount)+'</span>')
      +(x.note?'<span class="muted">'+esc(x.note)+'</span>':'')+'</div>';
  }).join('');
  html+='<details class="finsec"><summary><span class="chev">'+ICONS.chev+'</span> تراکنش‌های این بازه '
    +'<span class="chip">'+fa(txs.length)+'</span></summary>'
    +'<div class="finsec-body">'+(txRows||'<div class="muted">در این بازه تراکنشی ثبت نشده است.</div>')+'</div></details>';
  html+='<div class="muted" style="font-size:11.5px;margin-top:8px">مانده‌ها بر اساس مشتری‌های فعلی است.</div>';
  if(Number(r.anomalies||0)>0)html+='<div class="muted" style="font-size:11.5px;margin-top:4px">'+fa(r.anomalies)+' تراکنش با تاریخ نامعتبر نادیده‌گرفته شد.</div>';
  return html;
}
function finOpen(fmt){
  if(!FIN_REF)return;
  window.open('/crm-finance-report?mode='+FIN_MODE+'&ref='+(FIN_MODE==='period'?FIN_PERIOD:FIN_REF)+'&fmt='+fmt,'_blank');
}
function finTelegram(){
  if(FIN_MODE==='period'){
    if(!FIN_PERIOD)return;
    api('/crm-finance-report-telegram',{mode:'period',ref:FIN_PERIOD})
      .then(r=>toast('ارسال شد ('+fa(r.sent)+' بخش)')).catch(e=>toast(String(e),false));
    return;
  }
  if(!FIN_REF)return;
  api('/crm-finance-report-telegram',{mode:FIN_MODE,ref:FIN_REF})
    .then(r=>toast('ارسال شد ('+fa(r.sent)+' بخش)')).catch(e=>toast(String(e),false));
}

/* ================= customer statement dialog (v1.6) ================= */
/* Per-customer ledger statement with a selectable date range. STMT resets
   on every open (unlike FIN_* nothing persists): cid pins the customer,
   from/to the inclusive ISO bounds (empty = unbounded «همه»), range the
   active chip. The 30/90-day chips anchor on local midnight — new
   Date(iso+'T00:00:00'), the same arithmetic finShift uses. The server
   alone computes rows, running balances and totals; STMT_SEQ drops
   responses that race a newer fetch. */
var STMT={cid:'',from:'',to:'',range:'all'};
var STMT_DATA=null,STMT_ERR='',STMT_SEQ=0;
function stmtQuery(){
  return 'customer_id='+STMT.cid+(STMT.from?'&from='+STMT.from:'')+(STMT.to?'&to='+STMT.to:'');
}
function stmtUrl(){
  return '/crm-statement?'+stmtQuery()+'&fmt=json';
}
function dlgStatement(cid){
  var c=findCustomer(cid);
  if(!c){toast('مشتری پیدا نشد',false);return;}
  STMT={cid:cid,from:'',to:'',range:'all'};STMT_DATA=null;STMT_ERR='';STMT_SEQ++;
  openDlg('<div class="findlg"><h3>صورت‌حساب مشتری</h3>'
    +'<div class="row" style="margin-bottom:10px">'
    +'<div class="seg" id="stmtSeg">'
    +'<button type="button" class="on" data-r="all" aria-pressed="true" onclick="stmtRange(\'all\')">همه</button>'
    +'<button type="button" data-r="30" aria-pressed="false" onclick="stmtRange(30)">۳۰ روز اخیر</button>'
    +'<button type="button" data-r="90" aria-pressed="false" onclick="stmtRange(90)">۹۰ روز اخیر</button></div></div>'
    +'<div id="stmtBody"><div class="muted">در حال دریافت صورت‌حساب…</div></div>'
    +'<div class="row" style="margin-top:12px">'
    +'<button type="button" class="btn" id="stmtPrint" disabled onclick="stmtOpen(\'html\')">چاپ</button>'
    +'<button type="button" class="btn" id="stmtPdf" disabled onclick="stmtOpen(\'pdf\')">PDF</button>'
    +'<button type="button" class="btn primary" id="stmtTg" disabled onclick="stmtTelegram()">ارسال به تلگرام</button>'
    +'<button type="button" class="btn" onclick="closeDlg()">بستن</button></div></div>');
  stmtLoad();
}
function stmtRange(r){
  r=String(r);
  if(r==='all'){STMT.from='';STMT.to='';}
  else{
    /* local-midnight anchor: today minus 29/89 days = the chip's window */
    var to=new Date();
    var from=new Date(finIso(to)+'T00:00:00');
    from.setDate(from.getDate()-(Number(r)-1));
    STMT.from=finIso(from);STMT.to=finIso(to);
  }
  STMT.range=r;
  var seg=document.querySelectorAll('#stmtSeg button');
  for(var i=0;i<seg.length;i++){
    var on=seg[i].getAttribute('data-r')===r;
    seg[i].classList.toggle('on',on);
    seg[i].setAttribute('aria-pressed',on?'true':'false');
  }
  stmtLoad();
}
function stmtLoad(){
  var seq=++STMT_SEQ;
  STMT_ERR='';STMT_DATA=null;
  stmtPaint();
  api(stmtUrl()).then(function(r){
    if(seq!==STMT_SEQ)return;
    STMT_DATA=r;
    stmtPaint();
  }).catch(function(e){
    if(seq!==STMT_SEQ)return;
    STMT_ERR=String(e);
    stmtPaint();
  });
}
function stmtPaint(){
  var body=document.getElementById('stmtBody');
  if(body)body.innerHTML=stmtBodyHtml();
  var has=!!STMT_DATA;
  ['stmtPrint','stmtPdf','stmtTg'].forEach(function(bid){
    var b=document.getElementById(bid);
    if(b)b.disabled=!has;
  });
}
function stmtBodyHtml(){
  if(STMT_ERR)return '<div class="err">'+esc(STMT_ERR)+'</div>';
  if(!STMT_DATA)return '<div class="muted">در حال دریافت صورت‌حساب…</div>';
  var r=STMT_DATA,t=r.totals||{};
  /* identity row: the live client-side balance (bal() skips voided rows),
     so the pill is the customer's true current balance on every range */
  var b=bal(STMT.cid);
  var balPill=b<0?'<span class="pill bad">بدهکار '+money(b)+'</span>'
    :(b>0?'<span class="pill ok">بستانکار '+money(b)+'</span>':'<span class="pill n">تسویه</span>');
  var cu=r.customer||{};
  var head='<div class="stmthead"><b>'+esc(cu.name||custName(STMT.cid))+'</b>'
    +(cu.mobile?'<span class="kbd">'+esc(cu.mobile)+'</span>':'')+balPill+'</div>';
  var kpis='<div class="finkpis stmt-kpis">'
    +'<div class="finkpi"><span class="l">ماندهٔ اول</span><span class="v">'+finBal(t.opening)+'</span></div>'
    +'<div class="finkpi bad"><span class="l">بدهکاری</span><span class="v">'+money(t.debits)+'</span></div>'
    +'<div class="finkpi ok"><span class="l">بستانکاری</span><span class="v">'+money(t.credits)+'</span></div>'
    +'<div class="finkpi '+(Number(t.closing)>0?'ok':(Number(t.closing)<0?'bad':''))+'"><span class="l">ماندهٔ پایان</span><span class="v">'+finBal(t.closing)+'</span></div>'
    +'</div>';
  var rows=(r.rows||[]).map(function(x,i){
    /* voided rows and 'void' reversal rows: struck through and out of the
       running balances (balances[i] is null for exactly those rows) */
    var dead=!!x.voided||x.kind==='void';
    var rb=(r.balances||[])[i];
    return '<tr'+(dead?' class="voidedtx"':'')+'>'
      +'<td class="kbd">'+esc(x.at_fa||'—')+'</td>'
      +'<td>'+esc(x.label||'—')+(x.note?' <span class="muted">'+esc(x.note)+'</span>':'')+'</td>'
      +(Number(x.debit)?'<td class="finnum fin-bad">'+money(x.debit)+'</td>':'<td class="muted">—</td>')
      +(Number(x.credit)?'<td class="finnum fin-ok">'+money(x.credit)+'</td>':'<td class="muted">—</td>')
      +'<td class="finnum">'+(dead||rb==null?'—':finBal(rb))+'</td></tr>';
  }).join('');
  var html=head+kpis
    +'<table><thead><tr><th>تاریخ</th><th>شرح</th><th>بدهکار</th><th>بستانکار</th><th>مانده</th></tr></thead>'
    +'<tbody>'+(rows||'<tr><td colspan="5" class="muted" style="padding:16px 8px">در این بازه تراکنشی ثبت نشده است.</td></tr>')+'</tbody></table>';
  if(Number(r.voided_count||0)>0)
    html+='<div class="muted" style="font-size:11.5px;margin-top:8px">'+fa(r.voided_count)+' ردیف ابطال‌شده در محاسبه‌ها لحاظ نشده است.</div>';
  if(Number(r.anomalies||0)>0)
    html+='<div class="muted" style="font-size:11.5px;margin-top:4px">'+fa(r.anomalies)+' تراکنش با تاریخ نامعتبر نادیده‌گرفته شد.</div>';
  return html;
}
function stmtOpen(fmt){
  if(!STMT.cid)return;
  window.open('/crm-statement?'+stmtQuery()+'&fmt='+fmt,'_blank');
}
function stmtTelegram(){
  if(!STMT.cid)return;
  api('/crm-statement-telegram',{customer_id:STMT.cid,from:STMT.from,to:STMT.to})
    .then(r=>toast('ارسال شد ('+fa(r.sent)+' بخش)')).catch(e=>toast(String(e),false));
}

/* ================= render ================= */
var HISTORY_EVENT_KEYS = {
  devices:['device_id','entity_id'],
  customers:['customer_id','entity_id'],
  owners:['owner_id','entity_id'],
  identities:['identity_id','entity_id'],
  periodic:['device_id','entity_id'],
  ledger:['customer_id','entity_id'],
  reports:[],settings:['settings','entity_id'],cloud:['cloud_sync','cloud','entity_id']};
function historyHtml(){
  var keys=HISTORY_EVENT_KEYS[TAB]||[];
  var rows=(LOGS||[]).filter(l=>{
    if(TAB==='settings')return l.event==='settings';
    if(TAB==='reports')return String(l.event||'').startsWith('report');
    if(TAB==='periodic')return String(l.event||'').startsWith('scheduler')||String(l.event||'').startsWith('periodic')||String(l.event||'').startsWith('inquiry');
    if(!keys.length)return true;
    return keys.some(k=>l[k]!==undefined&&l[k]!=='');
  }).slice(-40).reverse();
  var items=rows.map(l=>'<div class="kbd">'+esc(faDateTime(l.at))+' — <b>'+esc(l.event)+'</b> '
    +esc(Object.entries(l).filter(([k])=>!['at','event','level'].includes(k)).map(([k,v])=>k+'='+v).join(' '))+'</div>').join('');
  return '<div class="card history"><h3>تاریخچه</h3>'
    +(items||'<div class="muted">رویدادی برای این بخش ثبت نشده است.</div>')+'</div>';
}
function renderTabs(){
  var devs=(STATE&&STATE.devices||[]);
  /* v1.7: archived passengers left the owners tab, so its badge counts only
     the ones that tab actually lists and the archive gets its own badge. */
  var arch=((STATE&&STATE.archived_owners)||[]).length;
  var allOwners=((STATE&&STATE.owners)||[]).length;
  var counts={devices:devs.length,periods:((STATE&&STATE.periods)||[]).length,customers:(STATE&&STATE.customers||[]).length,
    owners:Math.max(0,allOwners-arch),owner_archive:arch,
    identities:(STATE&&STATE.identities||[]).length,
    periodic:devs.filter(d=>(d.stage==='handed'||d.stage==='to_payment'||d.stage==='payment'||d.stage==='payment_done')&&!d.periodic_opt_out).length,
    ledger:null,reports:null,
    cloud:(typeof CLOUD!=='undefined'&&CLOUD.last&&Number(CLOUD.last.conflicts||0)>0?CLOUD.last.conflicts:null),
    done_tab:devs.filter(d=>d.stage==='done').length,
    problem_tab:devs.filter(d=>d.stage==='problem').length,
    closed_tab:devs.filter(d=>d.stage==='closed').length};
  document.getElementById('tabs').innerHTML = TABS.map(t=>
    '<button class="tab'+(TAB===t[0]?' active':'')+'" onclick="setTab(\''+t[0]+'\')">'+t[1]
    +(counts[t[0]]!=null?'<span class="cnt">'+fa(counts[t[0]])+'</span>':'')+'</button>').join('');
}
function setTab(t){
  ibtnClearBusy();TAB=t;renderTabs();renderView();
  if(t==='cloud'&&typeof loadCloudStatus==='function')loadCloudStatus();
  if(t==='settings'&&typeof settingsLoadTelegram==='function')settingsLoadTelegram();
  /* v1.9: the quietest cue, because tab switching is frequent. The initial
     render reads TAB from the URL and does not come through here, so loading
     the panel does not beep. */
  sfx('ui-tab');
}
function renderLogs(){
  var box=document.getElementById('logBox');
  if(!box)return;
  box.innerHTML=(LOGS||[]).slice().reverse().map(l=>
    '<div class="kbd">'+esc(faDateTime(l.at))+' — <b>'+esc(l.event)+'</b> '+esc(Object.entries(l).filter(([k])=>!['at','event','level'].includes(k)).map(([k,v])=>k+'='+v).join(' '))+'</div>').join('');
}
function renderView(){
  TIP.hide();
  var el=document.getElementById('view');
  if(!STATE){ el.innerHTML='<div class="skel"></div><div class="skel"></div><div class="skel"></div>';return; }
  /* v1.3.4 (operator request): the KPI strip and the devices summary rail
     render in the aside, above the «تاریخچه» card, so the case list owns
     the full main column — the old top strip and in-table side rail are
     gone. The rail stays devices-tab-only, as before. */
  var aside='<div class="crm-aside" id="crmAside">'+kpisHtml()
    +(TAB==='devices'?'<div class="devrail">'+devicesRailHtml()+'</div>':'')
    +historyHtml()+'</div>';
  /* v1.4.0: the tab toolbar (search box, result pill, stage chips) is built
     with the shell and then left alone — refreshes and typing re-render
     only #tabBody and the aside, so the input never loses focus. A tab
     switch (or a missing shell) rebuilds everything. #tabShell wraps BOTH
     the toolbar and #tabBody so it is the sticky containing block of the
     toolbar (a wrapper around the bar alone would give it zero travel). */
  var shell=document.getElementById('tabShell');
  if(!(shell&&shell.getAttribute('data-tab')===TAB&&document.getElementById('tabBody')&&document.getElementById('crmAside'))){
    el.innerHTML='<div class="crm-cols"><div class="crm-main">'
      +'<div id="tabShell" data-tab="'+esc(TAB)+'">'+tabBarHtml()
      +'<div id="tabBody">'+bodyHtml()+'</div></div></div>'+aside+'</div>';
    if(TAB==='cloud')paintCloud();
    if(TAB==='settings'&&typeof settingsLoadTelegram==='function')settingsLoadTelegram();
  }else{
    renderBody();
    /* outerHTML, not innerHTML: the aside string carries its own
       .crm-aside wrapper — innerHTML would nest a duplicate-id copy
       inside itself on every refresh (H review). */
    document.getElementById('crmAside').outerHTML=aside;
  }
  renderLogs();
  updateTabCount();
  /* v1.8.1: the render above replaced every button node in the tab body —
     re-mark the ones whose action is still in flight. */
  ibtnRepaintBusy();
}
async function refresh(){
  try{
    var r=await Promise.all([fetch('/crm-state'),fetch('/crm-logs'),fetch('/crm-periodic-logs')]);
    if(!r[0].ok||!r[1].ok)throw 0;
    STATE=await r[0].json();
    LOGS=(await r[1].json()).logs||[];
    STATE.periodic_logs=((await r[2].json()).logs||[]).reverse();
    LOADFAIL=false;
    /* v1.9: the sound switch is a server setting, so every browser agrees.
      Re-checked on every refresh — another operator turning it off here
      silences this panel too, and vice versa. The local key is only the
      mirror the login page reads before it has a session. */
    var snd=(STATE.settings||{}).sound_enabled;
    var on=snd!==false;
    if(SOUND.enabled!==on){
      SOUND.enabled=on;
      paintSoundBtn();
    }
    try{ if(on)localStorage.removeItem('irica-sound');else localStorage.setItem('irica-sound','0'); }catch(e){}
    /* v1.9: the box is painted after STATE lands (the links are a server
       setting, so there is nothing to show before the first fetch). */
    renderQuickBox();
  }catch(e){ LOADFAIL=true; }
  renderTabs();
  renderView();
  dlgCaseSync();
  dlgPeriodSync();
  if(LOADFAIL)toast('ارتباط با پنل برقرار نشد — تلاش مجدد…',false);
}
renderTabs();
paintSoundBtn();   /* the button is in the header, so the 5s refresh never touches it */
/* v1.9: the box reads STATE.settings.links, which is empty until the first
   fetch lands. Painting it here would show «لینکی ثبت نشده» for the whole
   first 5s; refresh() repaints it once STATE is loaded. */
var _REFRESH_TIMER=null;
function scheduleNextRefresh(){
  var isOnline=!(STATE&&STATE.settings&&STATE.settings.database_mode==='local');
  var ms=isOnline?2500:5000;
  if(_REFRESH_TIMER)clearTimeout(_REFRESH_TIMER);
  _REFRESH_TIMER=setTimeout(async function(){
    await refresh();
    scheduleNextRefresh();
  }, ms);
}
refresh().then(scheduleNextRefresh).catch(scheduleNextRefresh);
loadCloudStatus();
setInterval(loadCloudStatus, 4000);
</script>

</body>
</html>"""



def render_crm_page(actor="system"):
    """CRM page; __ACTOR__ becomes the logged-in user chip in the header."""
    return with_csrf_bootstrap(
        CRM_PAGE.replace("__ACTOR__", str(actor or "system")))


def render_estelam_page():
    state = estelam_load()
    state["runtime"] = estelam_runtime()
    html = ESTELAM_PAGE
    html = html.replace("__ESTELAM_JSON__", json.dumps(state, ensure_ascii=False))
    html = html.replace("__STATUS_JSON__",
                        json.dumps(ESTELAM_STATUS_FA, ensure_ascii=False))
    html = html.replace("__BADGE_JSON__",
                        json.dumps(ESTELAM_BADGE_FA, ensure_ascii=False))
    html = html.replace("__VERSION__", app_version_text() or "—")
    return with_csrf_bootstrap(html).encode("utf-8")


TX_ARTIFACT_SUBDIR = "tx_artifacts"
_TX_IMAGE_MAX_BYTES = 4 * 1024 * 1024
_TX_IMAGE_TYPES = {"image/png": ".png", "image/jpeg": ".jpg",
                   "image/webp": ".webp"}


def _save_tx_image(image_b64, mime):
    """Decode a base64 data-URL attachment for a finance transaction.

    Returns (filename, "") on success or ("", Persian error). Files land in
    DATA_DIR/tx_artifacts with a random hex name; the extension is derived
    from the declared mime type only.
    """
    import base64 as _b64
    raw = str(image_b64 or "").strip()
    if not raw:
        return "", ""
    if raw.startswith("data:"):
        head, _, raw = raw.partition(",")
        mime = head[5:].partition(";")[0] or mime
    try:
        blob = _b64.b64decode(raw, validate=True)
    except Exception:
        return "", "تصویر پیوست قابل خواندن نیست"
    if not blob:
        return "", ""
    if len(blob) > _TX_IMAGE_MAX_BYTES:
        return "", "حجم تصویر بیشتر از ۴ مگابایت است"
    ext = _TX_IMAGE_TYPES.get(str(mime or "").lower())
    if not ext:
        return "", "فرمت تصویر باید PNG یا JPG یا WebP باشد"
    directory = app_paths.data_subdir(TX_ARTIFACT_SUBDIR)
    name = uuid.uuid4().hex + ext
    try:
        with open(os.path.join(directory, name), "wb") as fh:
            fh.write(blob)
    except OSError:
        return "", "ذخیرهٔ تصویر ناموفق بود"
    return name, ""


def _tx_artifact(self, query):
    """Serve a finance attachment from tx_artifacts by exact file name
    (uuid hex + known extension); anything else is a 404."""
    name = (query.get("name") or [""])[0]
    safe = os.path.basename(str(name))
    if (not safe or safe != str(name) or not re.fullmatch(
            r"[0-9a-f]{32}\.(?:png|jpg|webp)", safe)):
        self._send(404, b"not found", "text/plain")
        return
    path = os.path.join(app_paths.data_subdir(TX_ARTIFACT_SUBDIR), safe)
    ctype = {"png": "image/png", "jpg": "image/jpeg",
             "webp": "image/webp"}.get(safe.rsplit(".", 1)[1], "application/octet-stream")
    try:
        with open(path, "rb") as fh:
            self._send(200, fh.read(), ctype)
    except OSError:
        self._send(404, b"not found", "text/plain")



def crm_finance_report_params(mode, ref, fmt):
    """Validate /crm-finance-report query values (v1.5).

    Returns (mode, ref_date, fmt, errors); errors is a Persian list (empty =
    valid). `ref` must be a non-empty YYYY-MM-DD string — callers substitute
    today before calling. Calendar-invalid dates (e.g. 2026-02-30) are
    rejected too.
    """
    import datetime
    errors = []
    mode = str(mode or "").strip()
    if mode not in ("daily", "weekly", "period"):
        errors.append("مقدار mode نامعتبر است")
    ref_text = str(ref or "").strip()
    ref_date = None
    # v1.7: period mode takes a period id, not a date — the range comes from
    # the period's own open/close times.
    if mode == "period":
        if not ref_text:
            errors.append("شناسهٔ دوره مشخص نشده است")
        ref_date = ref_text or None
    elif not ref_text or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", ref_text):
        errors.append("تاریخ ref نامعتبر است؛ قالب درست: YYYY-MM-DD")
    else:
        try:
            parts = [int(p) for p in ref_text.split("-")]
            ref_date = datetime.date(*parts)
        except ValueError:
            errors.append("تاریخ ref نامعتبر است؛ قالب درست: YYYY-MM-DD")
    fmt = str(fmt or "").strip()
    if fmt not in ("json", "html", "pdf", "txt"):
        errors.append("مقدار fmt نامعتبر است")
    return mode, ref_date, fmt, errors


def _crm_optional_date(text, label, errors):
    """Parse an optional YYYY-MM-DD bound (v1.6); None when absent/blank.
    Mirrors crm_finance_report_params' ref parsing, including the calendar
    check (2026-02-30 is rejected)."""
    import datetime
    text = str(text or "").strip()
    if not text:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        errors.append(f"تاریخ {label} نامعتبر است؛ قالب درست: YYYY-MM-DD")
        return None
    try:
        parts = [int(p) for p in text.split("-")]
        return datetime.date(*parts)
    except ValueError:
        errors.append(f"تاریخ {label} نامعتبر است؛ قالب درست: YYYY-MM-DD")
        return None


def crm_statement_params(customer_id, from_text, to_text, fmt):
    """Validate /crm-statement query/body values (v1.6).

    Returns (customer_id, from_date, to_date, fmt, errors); errors is a
    Persian list (empty = valid). customer_id is required; from/to are
    optional YYYY-MM-DD bounds (each unbounded when blank).
    """
    errors = []
    customer_id = str(customer_id or "").strip()
    if not customer_id:
        errors.append("مشتری پیدا نشد")
    from_date = _crm_optional_date(from_text, "from", errors)
    to_date = _crm_optional_date(to_text, "to", errors)
    fmt = str(fmt or "").strip() or "json"
    if fmt not in ("json", "html", "pdf", "txt"):
        errors.append("مقدار fmt نامعتبر است")
    return customer_id, from_date, to_date, fmt, errors


class RequestBodyRejected(Exception):
    """The POST body could not be read within the panel's resource limits.

    Carries the status the client should get: a body the panel will not accept
    and a body that never finishes arriving are different answers, and neither
    is the server error that a bare failure here would otherwise become.
    """

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class Handler(BaseHTTPRequestHandler):
    actor = "system"  # set by the login gate for authenticated requests
    # The POST body this request arrived with, read once by _consume_body().
    _request_body = None

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # v1.9.1: never let a browser second-guess the declared type. The
        # inquiry-result images are bytes the robots captured from a remote
        # site, and /estelam-shot serves them to a logged-in operator, so a
        # sniffed content type is the one way those bytes could be treated as
        # anything but an image.
        self.send_header("X-Content-Type-Options", "nosniff")
        # v1.3.6: pages must never come from browser cache — after a panel
        # update the operator kept seeing the previous version otherwise.
        # Static assets (fonts) keep their normal caching.
        if ctype.startswith("text/html"):
            self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def _read_json(self):
        raw = self._consume_body()
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return {}

    def _consume_body(self):
        """Read this request's body exactly once; every route shares the copy.

        Windows closes a socket that still holds unread receive bytes with RST
        instead of FIN, and the client's in-flight read then dies with
        WSAECONNABORTED -- so a browser got a raw network error where the route
        had sent a real status. Three exits used to leave those bytes behind:
        the login gate's 401, the /driver-update reply (which never looks at
        its body), and do_POST's own exception handler. Reading here, before
        any route runs, drains the socket for every POST whatever route it
        takes; the copy is what keeps the routes that DO need the body working.
        Caching is per handler instance, and the panel never sets
        protocol_version, so HTTP/1.0 gives one request per instance.

        Draining centrally is what makes the limits in _read_body possible at
        all. A declared Content-Length is the client's claim, not a fact, so it
        is checked against MAX_POST_BODY_BYTES before a single byte is read and
        refused past it rather than truncated -- a truncated body would reach
        the route as valid JSON that had silently lost fields. Raises
        RequestBodyRejected, which do_POST answers before the gate: no route can
        do anything with a request whose body is missing, and whether the
        caller is logged in does not change that.
        """
        if self._request_body is None:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                length = 0
            if length > MAX_POST_BODY_BYTES:
                raise RequestBodyRejected(
                    413, "بدنه‌ی درخواست بیش از حد بزرگ است")
            self._request_body = self._read_body(length)
        return self._request_body

    def _read_body(self, length):
        """Read `length` bytes, giving up if the client stops sending.

        Without a deadline here one request whose body never finishes arriving
        holds a worker thread for as long as the client cares to keep the socket
        open. A short socket timeout is deliberately local: it is set for this
        read and restored afterwards, so no other part of the panel inherits it.
        """
        if length <= 0:
            return b""
        connection = self.connection
        previous = connection.gettimeout()
        connection.settimeout(POST_BODY_READ_TIMEOUT)
        try:
            return self.rfile.read(length)
        except TimeoutError as exc:
            raise RequestBodyRejected(
                408, "خواندن بدنه‌ی درخواست ناتمام ماند") from exc
        except OSError:
            # The client can close before we drain what it sent. Nothing to
            # read then, and the route still has to answer it.
            return b""
        finally:
            connection.settimeout(previous)

    def _tx_artifact(self, query):
        """Serve a finance attachment from tx_artifacts by exact file name
        (uuid hex + known extension); anything else is a 404."""
        name = (query.get("name") or [""])[0]
        safe = os.path.basename(str(name))
        if (not safe or safe != str(name) or not re.fullmatch(
                r"[0-9a-f]{32}\.(?:png|jpg|webp)", safe)):
            self._send(404, b"not found", "text/plain")
            return
        path = os.path.join(app_paths.data_subdir(TX_ARTIFACT_SUBDIR), safe)
        ctype = {"png": "image/png", "jpg": "image/jpeg",
                 "webp": "image/webp"}.get(safe.rsplit(".", 1)[1], "application/octet-stream")
        try:
            with open(path, "rb") as fh:
                self._send(200, fh.read(), ctype)
        except OSError:
            self._send(404, b"not found", "text/plain")

    def _crm_inquiry_reset(self, data):
        """Reset inquiry history for devices (periodic-panel group tool).
        restart=True additionally queues each device for an immediate run."""
        import crm as crm_mod
        ids = data.get("device_ids") or []
        restart = bool(data.get("restart"))
        if not isinstance(ids, list) or not ids:
            self._json({"ok": False, "queued": 0,
                        "errors": ["دستگاهی انتخاب نشده است"]}, 400)
            return
        results, queued, restart_ids = [], 0, []
        for device_id in ids:
            device_id = str(device_id)
            data_crm = crm_mod.store_read()
            device = next((d for d in data_crm.get("devices", [])
                           if str(d.get("id")) == device_id), None)
            if not device:
                results.append({"device_id": device_id, "ok": False,
                                "errors": ["دستگاه پیدا نشد"]})
                continue
            est = estelam_load()
            row = next((d for d in est.get("devices", [])
                        if str(d.get("id")) == device_id), None)
            if row:
                row["status"] = "pending"
                row["result"] = ""
                row["error"] = ""
                row["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                estelam_save(est)
            # Locked read-modify-write: store_write serialises the WHOLE
            # document, so a read taken outside the lock can hand back a
            # snapshot another mutator (scheduler, auto-advance, a second
            # handler thread) has already changed — and this write would then
            # silently drop that change. Same crm.STORE_LOCK as everywhere
            # else; RLock, so the nested store_read/store_write are fine.
            with crm_mod.STORE_LOCK:
                data_crm = crm_mod.store_read()
                device = next((d for d in data_crm.get("devices", [])
                               if str(d.get("id")) == device_id), None)
                if device is not None:
                    device["last_inquiry_at"] = ""
                    crm_mod.store_write(data_crm)
            crm_mod.crm_log("info", "inquiry_history_reset", device_id=device_id)
            results.append({"device_id": device_id, "ok": True})
            if restart:
                restart_ids.append(device_id)
        if restart and restart_ids and not estelam_is_running():
            first = restart_ids.pop(0)
            result = crm_start_inquiry(first, service="gomrok",
                                       origin="reinquiry", actor=self.actor)
            if result.get("ok"):
                queued += 1
            else:
                results.append({"device_id": first, "ok": False,
                                "errors": result.get("errors")})
            for extra in restart_ids:
                sync_errors = crm_sync_queue(extra, service="gomrok")
                results.append({"device_id": extra,
                                "ok": not sync_errors,
                                "errors": sync_errors})
                if not sync_errors:
                    queued += 1
        ok = all(r.get("ok") for r in results)
        self._json({"ok": ok, "queued": queued, "results": results},
                   200 if ok else 400)

    def _crm_entity(self, route, data):
        """Dispatch add/update/delete for the four CRM entity routes."""
        import crm as crm_mod
        action = str(data.get("action") or "").strip().lower()
        record_id = str(data.get("id") or "").strip()
        entity = route.rsplit("-", 1)[1]          # customer|owner|identity|device
        record, errors, extra = None, [], {}
        if entity == "customer":
            if action == "add":
                record, errors = crm_mod.add_customer(data)
            elif action == "update":
                record, errors = crm_mod.update_customer(record_id, data)
            elif action == "tx":
                image_name, image_error = _save_tx_image(
                    data.get("image_b64"),
                    data.get("image_mime") or "image/png")
                if image_error:
                    record, errors = None, [image_error]
                else:
                    kind = str(data.get("kind") or "").strip()
                    try:
                        tx_amount = int(crm_mod.normalize_digits(
                            data.get("amount")))
                    except (TypeError, ValueError):
                        return self._json(
                            {"ok": False,
                             "errors": ["مبلغ باید عدد باشد"]}, 400)
                    # «ثبت دریافتی» books positive, «ثبت بدهی جدید» books
                    # negative — the operator enters a magnitude only.
                    if kind == "debt" and tx_amount > 0:
                        tx_amount = -tx_amount
                    elif kind == "receipt" and tx_amount < 0:
                        tx_amount = -tx_amount
                    record, errors = crm_mod.add_transaction(
                        record_id, tx_amount, data.get("note") or "",
                        kind=kind, image=image_name)
            elif action == "void_tx":
                # v1.6: void one ledger row. The index resolves inside
                # crm.void_transaction under STORE_LOCK (re-checked there —
                # the append-only list keeps a caller-resolved index valid,
                # but a concurrent void of the same row must still fail).
                # str() before normalize_digits: index 0 is falsy, and
                # normalize_digits turns falsy input into "" — without the
                # str() the FIRST transaction of every customer could never
                # be voided (regression-tested).
                reason = str(data.get("reason") or "").strip()
                raw_index = data.get("tx_index")
                try:
                    tx_index = int(crm_mod.normalize_digits(
                        "" if raw_index is None else str(raw_index)))
                except (TypeError, ValueError):
                    tx_index = -1        # resolves to «تراکنش پیدا نشد»
                record, errors = crm_mod.void_transaction(
                    record_id, tx_index, reason)
            elif action == "delete":
                ok, errors = crm_mod.delete_customer(record_id, force=bool(data.get("force")))
                record = {"ok": ok} if ok else None
            else:
                errors = ["کنش نامعتبر است"]
        elif entity == "owner":
            if action == "add":
                record, errors = crm_mod.add_owner(data)
            elif action == "update":
                record, errors = crm_mod.update_owner(record_id, data)
            elif action == "delete":
                ok, errors = crm_mod.delete_owner(record_id)
                record = {"ok": ok} if ok else None
            else:
                errors = ["کنش نامعتبر است"]
        elif entity == "identity":
            if action == "add":
                record, errors = crm_mod.add_identity(data)
            elif action == "update":
                record, errors = crm_mod.update_identity(record_id, data)
            elif action == "delete":
                ok, errors = crm_mod.delete_identity(record_id)
                record = {"ok": ok} if ok else None
            else:
                errors = ["کنش نامعتبر است"]
        else:  # device
            if action == "add":
                # v1.8.1: every case belongs to a reporting period, so this is
                # the one door the operator's intake goes through and it asks
                # crm.add_device for the guarantee. require_period checks
                # inside the store lock, before the inline customer is
                # created: a period closing concurrently cannot slip a
                # period-less case through, and a rejected intake leaves no
                # orphan customer behind. (A stale tab and a direct API call
                # both land here; the page itself disables the button.)
                inline = data.get("customer") if isinstance(data.get("customer"), dict) else None
                record, errors = crm_mod.add_device(data, customer=inline,
                                                    require_period=True)
            elif action == "update":
                record, errors = crm_mod.update_device(record_id, data)
            elif action == "delete":
                ok, errors = crm_mod.delete_device(record_id)
                record = {"ok": ok} if ok else None
            else:
                errors = ["کنش نامعتبر است"]
        if errors:
            crm_mod.crm_log("warn", f"{entity}_{action}_rejected",
                            entity_id=record_id, errors="; ".join(errors))
            self._json({"ok": False, "errors": errors}, 400)
            return
        crm_mod.crm_log("info", f"{entity}_{action}",
                        entity_id=str((record or {}).get("id") or record_id))
        # Enqueue local mutation into outbox for cloud sync (spec §9)
        try:
            if entity == "customer":
                if action in ("add", "update") and isinstance(record, dict):
                    _cloud_enqueue_mutation("customers", record.get("id"), record)
                elif action == "delete":
                    _cloud_enqueue_mutation("customers", record_id, kind="delete")
                elif action == "tx" and isinstance(record, dict):
                    txs = record.get("transactions", [])
                    if txs:
                        seq = len(txs) - 1
                        tx_rec = {**txs[-1], "seq": seq, "customer_id": record.get("id")}
                        _cloud_enqueue_mutation(
                            "customer_transactions",
                            f"{record.get('id')}/{seq}", tx_rec,
                            transport="finance_append")
                elif action == "void_tx" and isinstance(record, dict):
                    txs = record.get("transactions", [])
                    if 0 <= tx_index < len(txs):
                        tx_rec = {**txs[tx_index], "seq": tx_index, "customer_id": record.get("id")}
                        _cloud_enqueue_mutation(
                            "customer_transactions",
                            f"{record.get('id')}/{tx_index}", tx_rec,
                            transport="finance_void")
            elif entity == "owner":
                if action in ("add", "update") and isinstance(record, dict):
                    _cloud_enqueue_mutation("owners", record.get("id"), record)
                elif action == "delete":
                    _cloud_enqueue_mutation("owners", record_id, kind="delete")
                elif action == "detach" and isinstance(record, dict):
                    _cloud_enqueue_mutation("crm_devices", record.get("id"), record)
            elif entity == "identity":
                if action in ("add", "update") and isinstance(record, dict):
                    _cloud_enqueue_mutation("identities", record.get("id"), record)
                elif action == "delete":
                    _cloud_enqueue_mutation("identities", record_id, kind="delete")
            elif entity == "device":
                if action in ("add", "update") and isinstance(record, dict):
                    _cloud_enqueue_mutation("crm_devices", record.get("id"), record)
                elif action == "delete":
                    _cloud_enqueue_mutation("crm_devices", record_id, kind="delete")
        except Exception:
            pass
        payload = {"ok": True, "record": record}
        if entity == "device" and action == "add":
            payload["device"] = record
        payload.update(extra)
        self._json(payload)

    def _crm_start_payment(self, device_id):
        """Advance to payment. Explicit linked profile_id ONLY (review F18/F9):
        start_profile() with no id pool-claims ANY free profile."""
        import crm as crm_mod
        data = crm_mod.store_read()
        device = next((d for d in data.get("devices", [])
                       if d.get("id") == device_id), None)
        if not device:
            self._json({"ok": False, "errors": ["دستگاه پیدا نشد"]}, 404)
            return
        profile_id = str(device.get("profile_id") or "").strip()
        if profile_id:
            # Stale link (v1.5 review item 11): a profile_id pointing at a
            # profile that no longer exists in the store must self-heal the
            # same way as a missing one — otherwise start_profile answers an
            # English 404 "profile not found" instead of the actionable
            # Persian path below.
            store = load_store()
            if not next((p for p in store.get("profiles", [])
                         if p.get("id") == profile_id), None):
                profile_id = ""
        if not profile_id:
            # Self-heal (v1.5 item 11): cases that skipped past handover
            # (stage_skip) or lost their linked profile reach payment without
            # a registration profile. Bounded retries + a surfaced reason
            # (production fix 2026-09-15): the old code swallowed the
            # exception, so a persistent cause (e.g. profiles.json held open
            # by another process) was indistinguishable from a missing
            # passenger. Only with a passenger attached: without an owner the
            # ensure could mint nothing but a national-less profile the robot
            # rejects anyway, so the actionable 400 below names the real
            # recovery. F5 stays intact: the heal produces an EXPLICIT device
            # link; there is still no pool claim and no auto-advance
            # semantics change.
            healed = ""
            ensure_exc = None
            if str(device.get("owner_id") or "").strip():
                for attempt in range(3):
                    try:
                        healed = str(
                            crm_ensure_registration_profile(device_id)
                            or "").strip()
                        ensure_exc = None
                        break
                    except Exception as exc:
                        ensure_exc = exc
                    if attempt < 2:
                        time.sleep(0.5 * (attempt + 1))
            if not healed:
                if ensure_exc is not None:
                    crm_mod.crm_log("error", "profile_ensure_failed",
                                    device_id=device_id, phase="payment",
                                    detail=repr(ensure_exc)[:300])
                reason = ""
                if ensure_exc is not None:
                    reason = " — علت: " + str(ensure_exc)[:160]
                self._json({"ok": False,
                            "errors": ["پروفایل ثبت‌نام برای این دستگاه ساخته نشده است — "
                                       "ابتدا مسافر را به پرونده متصل کنید "
                                       "(در صورت نیاز پرونده را به گام «اتصال مسافر» برگردانید)"
                                       + reason]}, 400)
                return
            profile_id = healed
        status, payload = start_profile(profile_id, actor=self.actor)
        if status != 200:
            crm_mod.crm_log("error", "payment_start_failed", device_id=device_id,
                            profile_id=profile_id, detail=str(payload))
            message = "شروع ربات انجام نشد"
            if isinstance(payload, dict):
                message = str(payload.get("error") or message)
            self._json({"ok": False, "errors": [message]}, status)
            return
        device, errors = crm_mod.advance(device_id, "start_payment")
        crm_mod.crm_log("info", "payment_started", device_id=device_id,
                        profile_id=profile_id)
        self._json({"ok": True, "device": device, "pid": payload.get("pid")})

    def _crm_report_telegram(self, full_data):
        import crm as crm_mod
        state = crm_state_payload()
        allow_full = bool((state.get("settings") or {})
                          .get("telegram_report_full_data", True)) \
            and bool(full_data)
        text = crm_mod.build_report(state, fmt="txt",
                                    full_data=allow_full, plain=True)
        chunks = [text[i:i + 3900] for i in range(0, len(text), 3900)] or [""]
        sent = 0
        try:
            import telegram_notify as tg
            # v1.10: additive — the configured chats keep receiving every
            # chunk and a configured report channel gets a copy of each.
            extras = tg.report_extra_chat_ids()
            for chunk in chunks:
                if tg.send_message(chunk, timeout=20, actor=self.actor,
                                   extra_chat_ids=extras):
                    sent += 1
        except Exception as exc:
            crm_mod.crm_log("error", "report_telegram_failed", detail=str(exc))
            self._json({"ok": False, "errors": ["ارسال تلگرام ناموفق بود"]}, 502)
            return
        crm_mod.crm_log("info", "report_telegram_sent", chunks=sent)
        self._json({"ok": True, "chunks": sent})

    def _crm_report(self, query):
        """Devices report; fmt=txt (download) | html (printable) | pdf
        (headless Edge --print-to-pdf; HTML fallback with a print note)."""
        import crm as crm_mod
        fmt = (query.get("fmt") or ["txt"])[0]
        stages = (query.get("stage") or [""])[0]
        stage_filter = [s for s in stages.split(",") if s] or None
        state = crm_state_payload()
        report = crm_mod.build_report(state, stage_filter=stage_filter,
                                      fmt="html" if fmt in ("html", "pdf") else "txt")
        if fmt == "txt":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="crm-report.txt"')
            self.end_headers()
            self.wfile.write(report.encode("utf-8"))
            return
        if fmt == "pdf":
            pdf_bytes = crm_html_to_pdf(report)
            if pdf_bytes:
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition",
                                 'inline; filename="crm-report.pdf"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
                return
            report = report.replace(
                "</body>",
                "<script>window.onload=()=>setTimeout(()=>window.print(),300)"
                "</script></body>")
            self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")

    def _finance_aggregate(self, mode, ref):
        """Aggregate the finance report, or None after answering with a 400.

        v1.7: in period mode `ref` is a period id that is never validated
        against the store, so a stale id (a period dropped by a store
        restore) made the aggregate raise ValueError and abort the socket.
        Answer in Persian instead of leaving the operator with a dropped
        connection. Only a bad *reference* is a 400 (ReportRefError); any
        other ValueError is an unreadable store record and is answered as a
        500, so the operator is not told to re-read a list that is itself
        broken.
        """
        import crm as crm_mod
        try:
            return crm_mod.finance_report_aggregate(
                crm_mod.store_read(), mode, ref)
        except crm_mod.ReportRefError as exc:
            crm_mod.crm_log("warn", "report_finance_bad_ref",
                            detail="%s: %s" % (mode, exc))
            self._json({"ok": False, "errors": [
                "دورهٔ انتخاب‌شده پیدا نشد؛ فهرست دوره‌ها را دوباره بخوانید"]},
                400)
            return None
        except ValueError as exc:
            # Any other ValueError is a server-side data problem (a period
            # record whose fields cannot be read, say), not a stale client
            # list: answer 500 and keep the traceback in the log instead of
            # telling the operator to re-read a list that is itself broken.
            crm_mod.crm_log("error", "report_finance_failed",
                            detail="%s: %s" % (mode, exc))
            import traceback
            try:
                traceback.print_exc()
            except Exception:
                pass
            self._json({"ok": False,
                        "errors": ["خطای سرور؛ دوباره تلاش کنید"]}, 500)
            return None

    def _crm_finance_report(self, query):
        """Finance report (v1.5+); mode=daily|weekly|period (v1.7),
        ref=YYYY-MM-DD or, in period mode, the period id,
        fmt=json (aggregate) | html (printable) | pdf (Edge, HTML fallback) |
        txt (attachment download). Mirrors _crm_report's serving patterns."""
        import crm as crm_mod
        mode = (query.get("mode") or ["daily"])[0]
        # v1.7: period mode takes the period id as `ref`, so the today-fallback
        # (a date) must not be substituted for it.
        ref = (query.get("ref") or [""])[0]
        if mode != "period" and not ref:
            ref = time.strftime("%Y-%m-%d")
        fmt = (query.get("fmt") or ["json"])[0]
        mode, ref, fmt, errors = crm_finance_report_params(mode, ref, fmt)
        if errors:
            self._json({"ok": False, "errors": errors}, 400)
            return
        agg = self._finance_aggregate(mode, ref)
        if agg is None:
            return
        if fmt == "json":
            payload = {"ok": True}
            payload.update(agg)
            self._json(payload)
            return
        if fmt == "txt":
            report = crm_mod.finance_report_txt(agg)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="crm-finance-report.txt"')
            self.end_headers()
            self.wfile.write(report.encode("utf-8"))
            return
        report = crm_mod.finance_report_html(agg)
        if fmt == "pdf":
            pdf_bytes = crm_html_to_pdf(report)
            if pdf_bytes:
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition",
                                 'inline; filename="crm-finance-report.pdf"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
                return
            report = report.replace(
                "</body>",
                "<script>window.onload=()=>setTimeout(()=>window.print(),300)"
                "</script></body>")
            self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")

    def _crm_finance_report_telegram(self, data):
        """Finance report to Telegram (v1.5): plain text, chunks of <=3900
        chars; every chunk must land or the route 502s (a partial financial
        digest must never report success)."""
        import crm as crm_mod
        mode = str(data.get("mode") or "daily")
        # v1.7: period mode passes the period id through `ref`; the
        # today-fallback is a date and must not replace it.
        ref = str(data.get("ref") or "")
        if mode != "period" and not ref:
            ref = time.strftime("%Y-%m-%d")
        mode, ref, _fmt, errors = crm_finance_report_params(mode, ref, "json")
        if errors:
            self._json({"ok": False, "errors": errors}, 400)
            return
        agg = self._finance_aggregate(mode, ref)
        if agg is None:
            return
        text = crm_mod.finance_report_txt(agg)
        chunks = [text[i:i + 3900] for i in range(0, len(text), 3900)] or [""]
        sent = 0
        try:
            import telegram_notify as tg
            # v1.10: additive report channel (see _crm_report_telegram).
            extras = tg.report_extra_chat_ids()
            for chunk in chunks:
                if tg.send_message(chunk, timeout=20, actor=self.actor,
                                   extra_chat_ids=extras):
                    sent += 1
        except Exception as exc:
            crm_mod.crm_log("error", "report_finance_failed", detail=str(exc))
            self._json({"ok": False, "errors": ["ارسال تلگرام ناموفق بود"]}, 502)
            return
        if sent < len(chunks):
            crm_mod.crm_log("error", "report_finance_failed",
                            detail="%d/%d" % (sent, len(chunks)))
            import jalali
            self._json({"ok": False, "errors": [
                "ارسال تلگرام کامل نشد: " + jalali.fa_digits(sent) + " از "
                + jalali.fa_digits(len(chunks)) + " بخش ارسال شد"]}, 502)
            return
        crm_mod.crm_log("info", "report_finance_sent",
                        mode=mode, chunks=sent)
        self._json({"ok": True, "sent": sent})

    def _crm_statement(self, query):
        """Customer statement (v1.6); customer_id required, from/to optional
        YYYY-MM-DD bounds, fmt=json (default) | html (printable) | pdf (Edge,
        HTML fallback) | txt (attachment download). Mirrors the finance
        report's serving patterns."""
        import crm as crm_mod
        customer_id = (query.get("customer_id") or [""])[0]
        from_text = (query.get("from") or [""])[0]
        to_text = (query.get("to") or [""])[0]
        fmt = (query.get("fmt") or ["json"])[0]
        customer_id, from_date, to_date, fmt, errors = crm_statement_params(
            customer_id, from_text, to_text, fmt)
        if errors:
            self._json({"ok": False, "errors": errors}, 400)
            return
        stmt, errors = crm_mod.customer_statement(
            crm_mod.store_read(), customer_id, from_date, to_date)
        if errors:
            self._json({"ok": False, "errors": errors}, 400)
            return
        if fmt == "json":
            payload = {"ok": True}
            payload.update(stmt)
            self._json(payload)
            return
        if fmt == "txt":
            text = crm_mod.customer_statement_txt(stmt)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="crm-statement.txt"')
            self.end_headers()
            self.wfile.write(text.encode("utf-8"))
            return
        report = crm_mod.customer_statement_html(stmt)
        if fmt == "pdf":
            pdf_bytes = crm_html_to_pdf(report)
            if pdf_bytes:
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition",
                                 'inline; filename="crm-statement.pdf"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
                return
            report = report.replace(
                "</body>",
                "<script>window.onload=()=>setTimeout(()=>window.print(),300)"
                "</script></body>")
            self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")

    def _crm_statement_telegram(self, data):
        """Customer statement to Telegram (v1.6): plain text, chunks of
        <=3900 chars; every chunk must land or the route 502s (mirrors
        _crm_finance_report_telegram exactly, error strings included)."""
        import crm as crm_mod
        customer_id, from_date, to_date, _fmt, errors = crm_statement_params(
            data.get("customer_id"), data.get("from"), data.get("to"), "json")
        if errors:
            self._json({"ok": False, "errors": errors}, 400)
            return
        stmt, errors = crm_mod.customer_statement(
            crm_mod.store_read(), customer_id, from_date, to_date)
        if errors:
            self._json({"ok": False, "errors": errors}, 400)
            return
        text = crm_mod.customer_statement_txt(stmt)
        chunks = [text[i:i + 3900] for i in range(0, len(text), 3900)] or [""]
        sent = 0
        try:
            import telegram_notify as tg
            # v1.10: additive report channel (see _crm_report_telegram).
            extras = tg.report_extra_chat_ids()
            for chunk in chunks:
                if tg.send_message(chunk, timeout=20, actor=self.actor,
                                   extra_chat_ids=extras):
                    sent += 1
        except Exception as exc:
            crm_mod.crm_log("error", "report_statement_failed",
                            detail=str(exc))
            self._json({"ok": False, "errors": ["ارسال تلگرام ناموفق بود"]}, 502)
            return
        if sent < len(chunks):
            crm_mod.crm_log("error", "report_statement_failed",
                            detail="%d/%d" % (sent, len(chunks)))
            import jalali
            self._json({"ok": False, "errors": [
                "ارسال تلگرام کامل نشد: " + jalali.fa_digits(sent) + " از "
                + jalali.fa_digits(len(chunks)) + " بخش ارسال شد"]}, 502)
            return
        crm_mod.crm_log("info", "report_statement_sent",
                        customer_id=customer_id, chunks=sent)
        self._json({"ok": True, "sent": sent})

    def _crm_invoice(self, query):
        """Per-case invoice (v1.6); device_id required, fmt=html (default) |
        pdf (Edge, HTML fallback). Mirrors the finance report's serving
        patterns."""
        import crm as crm_mod
        device_id = str((query.get("device_id") or [""])[0]).strip()
        fmt = str((query.get("fmt") or ["html"])[0]).strip() or "html"
        errors = []
        if not device_id:
            errors.append("دستگاه پیدا نشد")
        if fmt not in ("html", "pdf"):
            errors.append("مقدار fmt نامعتبر است")
        if errors:
            self._json({"ok": False, "errors": errors}, 400)
            return
        invoice, errors = crm_mod.device_invoice(crm_mod.store_read(),
                                                 device_id)
        if errors:
            self._json({"ok": False, "errors": errors}, 400)
            return
        report = crm_mod.device_invoice_html(invoice)
        if fmt == "pdf":
            pdf_bytes = crm_html_to_pdf(report)
            if pdf_bytes:
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition",
                                 'inline; filename="crm-invoice.pdf"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
                return
            report = report.replace(
                "</body>",
                "<script>window.onload=()=>setTimeout(()=>window.print(),300)"
                "</script></body>")
            self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")

    def _state_json(self, code=200):
        """load_store-e amn baraye route-haye read: agar file lahze-i kharab bood,
        be jaye 500/khali, akharin store-e salem barmigardanad (UI khali nashavad)."""
        try:
            self._json(load_store(), code)
        except StoreUnreadableError:
            cached = _LAST_GOOD_STORE.get(PROFILES_PATH)
            if cached is not None:
                self._json(cached, code)
            else:
                # hich manba'-e salemi nist: 503 ba flag ta JS store-e fe'li ra negah darad.
                self._json({"error": "store temporarily unreadable", "retry": True}, 503)

    # ------------------------------------------------------------- gate
    # v1.9: /sfx/* is public on purpose — the login page plays the login cues
    # before there is a session. Only the seven generated files are ever
    # served (SFX_FILES), and the route itself re-checks the name, so nothing
    # else in that folder is reachable.
    PUBLIC_GET_PATHS = ("/login", "/favicon.ico", "/fonts/Vazirmatn-var.woff2",
                       "/fonts/Vazirmatn-Bold.woff2", "/sfx/")

    def _is_browser_navigation(self):
        """True for real browser navigations (typed URL, link, refresh).

        Browsers send Accept: text/html,... on navigations; fetch()/XHR from
        the page JS sends Accept: */* (api() sets no Accept header). Sec-Fetch-
        Mode: navigate is the modern explicit signal — used when present.
        """
        fetch_mode = (self.headers.get("Sec-Fetch-Mode") or "").strip().lower()
        if fetch_mode:
            return fetch_mode == "navigate"
        accept = self.headers.get("Accept")
        if accept is None:
            # No Accept header at all: page JS fetch always sends one (default
            # "*/*"), so this is a plain client (curl, scripts) — redirect it.
            return True
        return "text/html" in accept.lower()

    def _own_origin(self, value):
        """True when `value` (an Origin or a Referer) names this panel.

        Scheme must be http/https, the host must be a loopback literal, and the
        port must be the port this server is actually listening on — an
        ephemeral port in the tests, PORT in production. Anything else,
        including `Origin: null`, is foreign.
        """
        from urllib.parse import urlsplit
        try:
            parts = urlsplit(str(value or "").strip())
            port = parts.port
        except ValueError:
            return False
        if parts.scheme not in ("http", "https") or port is None:
            return False
        if not _is_loopback_label(parts.hostname):
            return False
        try:
            listening = self.server.server_address[1]
        except (AttributeError, IndexError, TypeError):
            listening = PORT
        return int(port) == int(listening)

    def _foreign_source(self):
        """The Persian rejection reason when this request did not come from
        the panel itself, else None.

        Checked on EVERY state-changing request, including /login, before any
        route runs. Host first (DNS rebinding), then Origin and, when a client
        sends no Origin, Referer. A client with neither — curl, the robots, the
        test harness — is judged on Host alone, which is the rebinding rule.
        """
        if not _is_loopback_label(_host_label(self.headers.get("Host"))):
            return _SOURCE_HOST_REJECT
        origin = str(self.headers.get("Origin") or "").strip()
        if not origin:
            referer = str(self.headers.get("Referer") or "").strip()
            if not referer:
                return None
            # Referer may be a full page URL; only its origin is comparable.
            try:
                from urllib.parse import urlsplit
                parts = urlsplit(referer)
                origin = "%s://%s" % (parts.scheme, parts.netloc)
            except ValueError:
                return _SOURCE_ORIGIN_REJECT
        if not self._own_origin(origin):
            return _SOURCE_ORIGIN_REJECT
        return None

    def _csrf_rejected(self, token):
        """True when a POST carries a LIVE session cookie without the CSRF
        token issued for that session.

        Deliberately scoped to live sessions: an absent or forged cookie has
        no token to present, and the session check below already answers it
        with 401. This gate exists for the one case that matters — a real
        session riding on someone else's request.
        """
        if not token or panel_auth.session_user(token) is None:
            return False
        return not panel_auth.csrf_matches(token,
                                           self.headers.get(CSRF_HEADER))

    def _gate(self, route):
        """Returns True when the request may proceed. Handles the login page,
        login POST and logout POST itself; everything else requires a valid
        session cookie."""
        from urllib.parse import urlsplit
        method = self.command
        if method == "POST":
            # Both checks run before ANY route, so a rejected request never
            # touches the store and never reaches a 500 path.
            foreign = self._foreign_source()
            if foreign is not None:
                self._json({"ok": False, "errors": [foreign]}, 403)
                return False
            if self._csrf_rejected(_cookie_token(self.headers)):
                self._json({"ok": False, "errors": [_CSRF_REJECT]}, 403)
                return False
        if method == "GET":
            if route == "/login":
                self._send(200, render_login_page())
                return False
            if any(route == p or route.startswith(p)
                   for p in self.PUBLIC_GET_PATHS if p != "/login"):
                return True
        if method == "POST":
            if route == "/login":
                self._handle_login()
                return False
            if route == "/logout":
                self._handle_logout()
                return False
        token = _cookie_token(self.headers)
        username = panel_auth.session_user(token)
        if username is None:
            if method == "GET" and self._is_browser_navigation():
                # Typed URLs / link clicks / refreshes land on the login page;
                # fetch()/XHR (Accept: */* or cors mode) still get JSON 401 so
                # page scripts can show their own "برای ادامه وارد شوید".
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._json({"ok": False, "errors": ["برای ادامه وارد شوید"]},
                           401)
            return False
        self.actor = username
        return True

    def _handle_login(self):
        try:
            payload = self._read_json()
        except Exception:
            payload = {}
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        if panel_auth.is_locked_out(username):
            self._json({"ok": False,
                        "errors": ["تلاش‌های ناموفق زیاد؛ چند دقیقه بعد دوباره امتحان کنید"]},
                       429)
            return
        if panel_auth.verify_password(panel_auth.USERS_PATH, username, password):
            panel_auth.register_success(username)
            token = panel_auth.create_session(username)
            # Session: HttpOnly + Strict, so neither script nor a cross-site
            # request can touch it. Companion: the same CSRF token in a
            # readable Strict cookie, which is the only way the page's JS can
            # put it in the X-CSRF-Token header (the session cookie itself is
            # invisible to script on purpose).
            cookie = ("irica_session=" + token +
                      "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" +
                      str(panel_auth.SESSION_TTL_SECONDS))
            csrf = panel_auth.session_csrf(token) or ""
            csrf_cookie = (CSRF_COOKIE + "=" + csrf +
                           "; Path=/; SameSite=Strict; Max-Age=" +
                           str(panel_auth.SESSION_TTL_SECONDS))
            self.send_response(200)
            self.send_header("Set-Cookie", cookie)
            self.send_header("Set-Cookie", csrf_cookie)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            body = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            try:
                import crm as crm_mod
                crm_mod.crm_log("info", "login_ok", user=username)
            except Exception:
                pass
            return
        if panel_auth.valid_username(username):
            panel_auth.register_failed_login(username)
        self._json({"ok": False,
                    "errors": ["نام کاربری یا رمز عبور اشتباه است"]}, 401)

    def _handle_logout(self):
        token = _cookie_token(self.headers)
        if token:
            panel_auth.destroy_session(token)
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie",
                         "irica_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        self.send_header("Set-Cookie",
                         CSRF_COOKIE + "=; Path=/; SameSite=Strict; Max-Age=0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        try:
            self._do_get_body()
        except Exception as exc:
            # v1.7: mirrors do_POST's safety net. A GET route that raised used
            # to abort the socket mid-response, so the browser reported a raw
            # "TypeError: Failed to fetch" (e.g. a period report whose id no
            # longer resolves against the store). Answer in Persian instead,
            # and log the traceback so the cause stays discoverable.
            import traceback
            try:
                traceback.print_exc()
            except Exception:
                pass
            try:
                self._json({"ok": False,
                            "errors": ["خطای سرور؛ دوباره تلاش کنید"]}, 500)
            except Exception:
                pass

    def _do_get_body(self):
        from urllib.parse import urlsplit
        route = urlsplit(self.path).path
        if not self._gate(route):
            return
        if route in ("/", "/index.html"):
            self._send(200, render_home_page())
        elif route == "/launch":
            self._send(200, render_launch_page())
        elif route in ("/fonts/Vazirmatn-var.woff2",
                       "/fonts/Vazirmatn-Bold.woff2"):
            path = os.path.join(HERE, route.lstrip("/").replace("/", os.sep))
            try:
                with open(path, "rb") as fh:
                    self._send(200, fh.read(), "font/woff2")
            except OSError:
                self._send(404, b"not found", "text/plain")
        elif route.startswith("/sfx/"):
            # v1.9: UI notification cues. The whitelist is the seven generated
            # files only; a name is never joined into a path unchecked, so the
            # folder holds nothing else that is reachable. WAV is cached here
            # once per process instead of re-reading ~150 KB on every click.
            name = os.path.basename(route)
            if name not in SFX_FILES:
                self._send(404, b"not found", "text/plain")
                return
            data = _sfx_cache(name)
            if data is None:
                self._send(404, b"not found", "text/plain")
                return
            self._send(200, data, "audio/wav")
        elif route == "/favicon.ico":
            # v1.4.0: the IRICA brand mark (path-drawn R, from
            # lab/design/irica-brand.md) — font-independent and legible at
            # 16px, in the unified brand color.
            svg = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'>"
                   "<rect width='24' height='24' rx='5.5' fill='#4460e3'/>"
                   "<g fill='none' stroke='#fff' stroke-width='3.4' "
                   "stroke-linecap='round' stroke-linejoin='round'>"
                   "<path d='M7 18.5v-13'/>"
                   "<path d='M7 5.5h4.6c2.9 0 4.8 1.7 4.8 4.3s-1.9 4.3-4.8 4.3H7'/>"
                   "<path d='M11.4 14.1l5.6 4.4'/></g></svg>")
            self._send(200, svg.encode("utf-8"), "image/svg+xml")
        elif route == "/site-1":
            self._send(200, render_page())
        elif route == "/site-2":
            self._send(200, render_estelam_page())
        elif route == "/estelam-state":
            estelam_reset_pending_stale()
            state = estelam_load()
            state["runtime"] = estelam_runtime()
            self._json(state)
        elif route == "/estelam-logs":
            self._json({"logs": load_estelam_logs()})
        elif route == "/state":
            clear_stale_busy_profiles()
            self._state_json()
        elif route == "/logs":
            self._json(load_logs())
        elif route == "/site2-notif":
            self._json(load_site2_notif())
        elif route == "/telegram-health":
            from urllib.parse import parse_qs
            query = parse_qs(urlsplit(self.path).query)
            if query.get("run") == ["1"]:
                self._json(test_telegram_api(attempts=2))
            else:
                self._json(load_telegram_health())
        elif route == "/cloud-status":
            # Read-only snapshot of the sync surface (spec §11): counts,
            # stable codes and the non-secret transport config. No network,
            # no state-machine event.
            self._json(cloud_status_payload())
        elif route == "/cloud-conflicts":
            self._json(cloud_conflicts_payload())
        elif route == "/system-debug-config":
            self._json(load_system_debug_config())
        elif route == "/system-logs":
            self._json({"logs": list_system_logs()})
        elif route == "/system-log":
            from urllib.parse import parse_qs
            query = parse_qs(urlsplit(self.path).query)
            name = (query.get("name") or [""])[0]
            try:
                self._json({"name": name, "content": read_system_log(name)})
            except ValueError:
                self._json({"error": "نام فایل لاگ نامعتبر است"}, 400)
            except FileNotFoundError:
                self._json({"error": "فایل لاگ پیدا نشد"}, 404)
        elif route == "/artifact":
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(self.path).query)
            pid, kind = (q.get("id") or [""])[0], (q.get("kind") or [""])[0]
            key = "receipt_screenshot" if kind == "receipt" else "payment_screenshot"
            try:
                profiles = load_store().get("profiles", [])
            except StoreUnreadableError:
                profiles = (_LAST_GOOD_STORE.get(PROFILES_PATH) or {}).get("profiles", [])
            profile = next((p for p in profiles if p.get("id") == pid), None)
            path = os.path.realpath((profile or {}).get(key) or "")
            # Screenshots now live in the data directory. Paths recorded by an
            # older release point inside that release folder, so both roots are
            # accepted -- containment is still enforced against each of them.
            roots = [os.path.realpath(app_paths.data_subdir("screenshots")),
                     os.path.realpath(os.path.join(HERE, "screenshots"))]
            allowed = False
            for root in roots:
                try:
                    if os.path.commonpath([root, path]) == root:
                        allowed = True
                        break
                except ValueError:
                    continue
            if profile and allowed and os.path.isfile(path):
                with open(path, "rb") as f:
                    self._send(200, f.read(), "image/png")
            else:
                self._send(404, b"not found", "text/plain")
        elif route == "/estelam-shot":
            # v1.9.1: inquiry result image. The recorded path is never trusted
            # directly; it must resolve inside the screenshots data subdir.
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(self.path).query)
            did = (q.get("id") or [""])[0]
            svc = (q.get("svc") or [""])[0]
            # Both values come from the query string and both end up in records
            # in a log the panel renders and that keeps only its newest entries.
            # `did` is used in full for the store lookup below, but every record
            # written about it is bounded too: one request carrying a huge id
            # would otherwise evict the real robot diagnostics.
            did_log = did[:64]
            key = _SHOT_FIELD.get(svc)
            path = ""
            if not key:
                # Bounded for the same reason as did_log above.
                estelam_log("shot", f"unknown service {svc[:32]!r}",
                            device_id=did_log)
            else:
                try:
                    device = next((d for d in estelam_load().get("devices", [])
                                   if str(d.get("id")) == str(did)), None)
                except Exception:
                    device = None
                raw = str((device or {}).get(key) or "")
                # A device without a capture is a normal state, not a
                # diagnostic: shot_resolve returns "" for both an empty field
                # and an escaping one, so the two are told apart here. Without
                # that distinction every request for a capture-less device
                # would write a security-flavoured record into
                # estelam_logs.jsonl, which keeps only the newest 400 entries
                # -- a browser retrying a missing image could evict every real
                # robot diagnostic.
                path = shot_resolve(raw)
                if not device:
                    estelam_log("shot", f"unknown device {did_log!r} ({svc})")
                elif raw and not path:
                    # A store field pointing outside both roots is a
                    # misconfiguration, not a missing capture — log it
                    # distinctly. Only the file name goes into the record: the
                    # operator can read the full value in the store, and the
                    # panel renders this log, so there is no reason to copy
                    # install paths into it.
                    estelam_log("shot", f"{key} for {did_log!r} is outside the "
                                        f"screenshots roots: "
                                        f"{os.path.basename(raw)!r}")
            if path and os.path.isfile(path):
                try:
                    with open(path, "rb") as f:
                        self._send(200, f.read(), "image/png")
                except OSError as exc:
                    # Basename only, for the same reason as the containment
                    # record above: this log is rendered in the panel.
                    estelam_log("shot", f"unreadable "
                                        f"{os.path.basename(path)!r}: {exc}")
                    self._send(404, b"not found", "text/plain")
            else:
                self._send(404, b"not found", "text/plain")
        elif route == "/crm":
            self._send(200, render_crm_page(self.actor).encode("utf-8"))
        elif route == "/crm-state":
            self._json(crm_state_payload())
        elif route == "/telegram-config":
            self._json(public_telegram_config())
        elif route == "/crm-periodic-logs":
            self._json({"logs": [l for l in load_estelam_logs()
                                 if l.get("device_id")]})
        elif route == "/crm-logs":
            self._json({"logs": load_crm_logs()})
        elif route == "/crm-report":
            from urllib.parse import parse_qs
            query = parse_qs(urlsplit(self.path).query)
            self._crm_report(query)
        elif route == "/crm-finance-report":
            from urllib.parse import parse_qs
            query = parse_qs(urlsplit(self.path).query)
            self._crm_finance_report(query)
        elif route == "/crm-statement":
            from urllib.parse import parse_qs
            query = parse_qs(urlsplit(self.path).query)
            self._crm_statement(query)
        elif route == "/crm-invoice":
            from urllib.parse import parse_qs
            query = parse_qs(urlsplit(self.path).query)
            self._crm_invoice(query)
        elif route == "/tx-artifact":
            from urllib.parse import parse_qs
            query = parse_qs(urlsplit(self.path).query)
            self._tx_artifact(query)
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        from urllib.parse import urlsplit
        try:
            self._consume_body()
        except RequestBodyRejected as rejected:
            # The one case answered before the gate: a body that is over the cap
            # or that stopped arriving cannot be routed, and the caller's
            # session would not change that. Answering without reading the rest
            # leaves those bytes in the socket, so the close is an RST rather
            # than a FIN -- deliberately, since waiting out a body the panel has
            # already refused is what the cap exists to prevent.
            self._json({"ok": False, "errors": [rejected.message]},
                       rejected.status)
            return
        if not self._gate(urlsplit(self.path).path):
            return
        try:
            self._do_post_body()
        except Exception as exc:
            # v1.7: a route exception used to abort the socket mid-response,
            # so the browser reported a raw "TypeError: Failed to fetch" while
            # the store write had already succeeded (the operator saw "saved
            # but errored"). Surface a Persian error instead, and log the
            # traceback server-side so the cause is discoverable.
            import traceback
            try:
                traceback.print_exc()
            except Exception:
                pass
            try:
                self._json({"ok": False,
                            "errors": ["خطای سرور؛ دوباره تلاش کنید"]}, 500)
            except Exception:
                pass

    def _do_post_body(self):
        if self.path == "/driver-update":
            # Operator-triggered repair of the ChromeDriver the robots launch.
            # Deliberately bypasses the auto-update latch and cooldown: a person
            # clicked the button and is waiting for the verdict. captcha_collector
            # owns driver resolution, so it is imported here rather than
            # duplicating those rules in the panel.
            #
            # Handled before load_store(): repairing the driver has nothing to
            # do with the profile store, and were profiles.json momentarily
            # unreadable the route would answer 500 and the page would report a
            # proxy problem. Every outcome here leaves as JSON -- the page reads
            # the verdict to say what happened, so a raised exception must
            # arrive as a status it understands, never as an HTML error body.
            try:
                import captcha_collector
                result = captcha_collector.update_chromedriver_now()
            except Exception as exc:
                result = {"status": "failed", "detail": str(exc),
                          "target": "", "version": ""}
            self._json(result)
            return
        try:
            store = load_store()
        except StoreUnreadableError:
            # profiles.json lahze-i ghabel-e khandan nist. Az cache estefade mikonim
            # ta write-e badi rooye dade-ye salem anjam shavad (na baznevisi-ye khali).
            cached = _LAST_GOOD_STORE.get(PROFILES_PATH)
            if cached is None:
                self._json({"error": "store temporarily unreadable", "retry": True}, 503)
                return
            store = {"profiles": [dict(p) for p in cached["profiles"]],
                     "active_id": cached["active_id"]}
        if self.path == "/save":
            data = self._read_json()
            pid = (data.get("id") or "").strip()
            found = False
            for i, p in enumerate(store["profiles"]):
                if p["id"] == pid:
                    data["id"] = pid
                    data = sync_shared_identity(merge_profile_update(p, data))
                    store["profiles"][i] = data
                    found = True
                    break
            if not found:
                data["id"] = pid or None
                store["profiles"].append(data)
            # Route-level passport validation (v1.5 item 11): the field is
            # OPTIONAL — empty always passes; a non-empty value must be 5-20
            # latin letters/digits (after strip+upper). Deliberately NOT in
            # _clean_profile/save_store so legacy stores keep loading/saving
            # unchanged; only operator edits through this route are checked.
            candidate_passport = str(data.get("passport") or "").strip().upper()
            if candidate_passport and \
                    not re.fullmatch(r"[A-Z0-9]{5,20}", candidate_passport):
                self._json({"error": "شمارهٔ گذرنامه باید ۵ تا ۲۰ کاراکتر حرف یا رقم لاتین باشد"}, 400)
                return
            # profile-i ke zakhire shod ra ACTIVE mikonim
            store["active_id"] = pid or store["profiles"][-1].get("id") or ""
            clean = save_store(store)
            # active_id-e vaghe'i ba'd az tamiz-shodan
            # The title is operator data and can be Persian: on a cp1252
            # console this print raises UnicodeEncodeError inside the handler
            # thread and the client would get a connection drop instead of
            # the saved store. Diagnostics must never break the response
            # (v1.5 review item 10).
            try:
                print(f">>> Zakhire shod: profile={data.get('title')!r} "
                      f"active={clean['active_id']}")
            except UnicodeEncodeError:
                pass
            self._json(clean)

        elif self.path == "/activate":
            data = self._read_json()
            store["active_id"] = (data.get("id") or "").strip()
            clean = save_store(store)
            # active_id comes from the operator's payload: on a cp1252
            # console an unencodable id would raise UnicodeEncodeError inside
            # the handler thread and drop the response. Diagnostics must
            # never break the route (same guard as /save, v1.5 item 10/12).
            try:
                print(f">>> Faal shod: {clean['active_id']}")
            except UnicodeEncodeError:
                pass
            self._json(clean)

        elif self.path == "/toggle":
            data = self._read_json()
            for p in store["profiles"]:
                if p["id"] == str(data.get("id") or "") and p.get("run_status") != "busy":
                    p["enabled"] = bool(data.get("enabled"))
            self._json(save_store(store))

        elif self.path == "/start":
            data = self._read_json()
            status, payload = start_profile(str(data.get("id") or ""),
                                            actor=self.actor)
            self._json(payload if status != 200 else load_store(), status)

        elif self.path == "/start2":
            data = self._read_json()
            status, payload = start_profile2(str(data.get("id") or ""),
                                             actor=self.actor)
            self._json(payload if status != 200 else load_store(), status)

        elif self.path == "/start2-manual":
            try:
                runtime = start_site2_manual_process(actor=self.actor)
            except (OSError, ValueError):
                self._json({"error": "شروع ربات سایت دوم انجام نشد"}, 500)
            else:
                self._json({"ok": True, "pid": runtime["pid"]})

        elif self.path == "/profile-device-inquiry":
            data = self._read_json()
            status, payload = start_profile_device_inquiry(
                str(data.get("id") or ""), str(data.get("service") or ""),
                actor=self.actor)
            self._json(payload, status)

        elif self.path == "/profile-device-stop":
            data = self._read_json()
            ok, message = stop_profile_inquiry(str(data.get("id") or ""))
            payload = {"ok": ok, "message": message}
            if ok:
                payload["store"] = load_store()
            self._json(payload, 200 if ok else 404)

        elif self.path == "/shutdown":
            self._json(shutdown_everything())

        elif self.path == "/exitban-inquiry":
            data = self._read_json()
            profile_id = str(data.get("id") or "").strip()
            try:
                import exitban
                identity = exitban.load_identity(profile_id)
                missing = exitban.missing_identity_fields(identity)
            except ValueError as exc:
                self._json({"error": str(exc)}, 404)
                return
            if missing:
                self._json({"error": "اطلاعات هویتی ناقص است", "missing": missing}, 422)
                return
            runtime = start_exitban_process(profile_id, actor=self.actor)
            self._json({"ok": True, "profile_id": profile_id, "pid": runtime["pid"], "submitted": False})

        elif self.path == "/exitban-result":
            data = self._read_json()
            profile_id = str(data.get("id") or data.get("profile_id") or "").strip()
            text = str(data.get("text") or data.get("result") or "").strip()
            status = str(data.get("status") or "").strip()
            if not profile_id or not text:
                self._json({"error": "profile id and result text are required"}, 422)
            elif record_exitban_result(profile_id, text, status):
                profile = next(p for p in load_store()["profiles"] if p["id"] == profile_id)
                self._json({"ok": True, "profile_id": profile_id,
                            "status": profile["exitban_status"],
                            "checked_at": profile["exitban_checked_at"]})
            else:
                self._json({"error": "profile not found"}, 404)

        elif self.path == "/stop":
            data = self._read_json()
            profile_id = str(data.get("id") or "").strip()
            if profile_id:
                status, payload = stop_profile(profile_id)
                self._json(payload if status != 200 else load_store(), status)
            else:
                pid = int(data.get("pid") or 0)
                stop_profile_process(pid)
                clear_stale_busy_profiles()
                self._json(load_store())

        elif self.path == "/new":
            store["profiles"].append(_clean_profile({}))
            store["active_id"] = store["profiles"][-1]["id"]
            clean = save_store(store)
            self._json(clean)

        elif self.path == "/clone":
            data = self._read_json()
            cloned = clone_profile(str(data.get("id") or ""))
            self._json(load_store() if cloned else {"error": "profile not found"}, 200 if cloned else 404)

        elif self.path == "/release-blocked":
            data = self._read_json()
            ok, message = release_blocked_profile_with_reason(str(data.get("id") or ""))
            payload = {"ok": ok, "message": message}
            if ok:
                payload["store"] = load_store()
            self._json(payload, 200 if ok else 409)

        elif self.path == "/delete":
            data = self._read_json()
            pid = (data.get("id") or "").strip()
            store["profiles"] = [p for p in store["profiles"] if p["id"] != pid]
            if not store["profiles"]:
                store["profiles"] = [_clean_profile({})]
            if store.get("active_id") == pid:
                store["active_id"] = store["profiles"][0]["id"]
            clean = save_store(store)
            self._json(clean)

        elif self.path == "/browser-visibility":
            data = self._read_json()
            status, payload = set_browser_visibility(
                str(data.get("id") or ""), bool(data.get("visible")))
            self._json(payload, status)

        elif self.path == "/clear-logs":
            clear_logs()
            self._json({"ok": True})

        elif self.path == "/system-debug-config":
            self._json(save_system_debug_config(self._read_json()))

        elif self.path == "/telegram-config":
            self._json(save_telegram_config(self._read_json()))

        elif self.path == "/telegram-test":
            self._json(run_telegram_test(self._read_json()))

        # Cloud sync (spec §11). Origin / Host / CSRF were already checked by
        # _gate before any route ran; _cloud_route_guard is where the two
        # state-machine faults are caught BY NAME (spec §15.12).
        elif self.path == "/cloud-config":
            self._json(*_cloud_route_guard(cloud_save_config,
                                           self._read_json()))
        elif self.path == "/cloud-login":
            data = self._read_json()
            if not isinstance(data, dict):
                data = {}
            self._json(*_cloud_route_guard(
                cloud_login, str(data.get("username") or ""),
                str(data.get("password") or "")))
        elif self.path == "/cloud-logout":
            self._json(*_cloud_route_guard(cloud_logout))
        elif self.path in ("/cloud-sync", "/cloud-sync-now"):  # self.path == "/cloud-sync"
            self._json(*_cloud_route_guard(cloud_sync_now))
        elif self.path == "/cloud-presence":
            resp, status = _cloud_route_guard(cloud_presence_heartbeat,
                                                self._read_json())
            self._json(resp, status)
        elif self.path == "/cloud-presence-close":
            resp, status = _cloud_route_guard(cloud_presence_close,
                                                self._read_json())
            self._json(resp, status)
        elif self.path == "/cloud-resolve-conflict":
            resp, status = _cloud_route_guard(cloud_resolve_conflict,
                                              self._read_json())
            self._json(resp, status)
        elif self.path == "/cloud-import":
            resp, status = _cloud_route_guard(cloud_run_import)
            self._json(resp, status)
        elif self.path in ("/cloud-backup-now", "/cloud-backup"):
            resp, status = _cloud_route_guard(cloud_run_backup_now)
            self._json(resp, status)

        elif self.path == "/estelam-person":
            data = self._read_json()
            errors = validate_estelam_person(data)
            if errors:
                self._json({"ok": False, "errors": errors}, 400)
            else:
                self._json({"ok": True, "state": estelam_save_person(data)})

        elif self.path == "/estelam-device":
            data = self._read_json()
            errors = validate_estelam_device(data)
            if errors:
                self._json({"ok": False, "errors": errors}, 400)
            else:
                record = estelam_add_device(data)
                self._json({"ok": True, "device": record, "state": estelam_load()})

        elif self.path == "/estelam-device-delete":
            data = self._read_json()
            self._json({"ok": True,
                        "state": estelam_delete_device(str(data.get("id") or ""))})

        elif self.path == "/estelam-start":
            data = self._read_json()
            result = estelam_start(str(data.get("id") or "") or None,
                                   service=str(data.get("service") or "gomrok"),
                                   actor=self.actor)
            self._json(result, 200 if result.get("ok") else 400)

        elif self.path == "/estelam-stop":
            self._json(estelam_stop())

        elif self.path == "/estelam-restart":
            result = estelam_restart(actor=self.actor)
            self._json(result, 200 if result.get("ok") else 400)

        elif self.path == "/estelam-clear-logs":
            self._json(clear_estelam_logs())

        elif self.path in ("/crm-customer", "/crm-owner", "/crm-identity",
                           "/crm-device"):
            self._crm_entity(self.path, self._read_json())

        elif self.path == "/crm-inquire":
            data = self._read_json()
            service = str(data.get("service") or "")
            if service not in ESTELAM_SERVICES:
                self._json({"ok": False,
                            "errors": ["نوع استعلام نامعتبر است"]}, 400)
                return
            result = crm_start_inquiry(str(data.get("device_id") or ""),
                                       service=service, origin="manual",
                                       actor=self.actor)
            self._json(result, 200 if result.get("ok") else 400)

        elif self.path == "/crm-stop":
            self._json(estelam_stop())

        elif self.path == "/crm-period-open":
            import crm as crm_mod
            payload = self._read_json()
            period, errors = crm_mod.open_period(
                str(payload.get("label") or ""), actor=self.actor)
            if errors:
                self._json({"ok": False, "errors": errors}, 400)
            else:
                _cloud_enqueue_mutation("periods", period.get("id"), period)
                self._json({"ok": True, "period": period})

        elif self.path == "/crm-period-close":
            import crm as crm_mod
            payload = self._read_json()
            summary, errors = crm_mod.close_period(
                str(payload.get("period_id") or ""),
                actor=self.actor,
                reason=str(payload.get("reason") or ""))
            if errors:
                self._json({"ok": False, "errors": errors}, 400)
            else:
                period_data = summary.get("period") or {}
                _cloud_enqueue_mutation("periods", period_data.get("id") or str(payload.get("period_id") or ""), period_data)
                self._json({"ok": True, "summary": summary})

        elif self.path == "/crm-periodic":
            data = self._read_json()
            result = crm_periodic_toggle(str(data.get("device_id") or ""),
                                         remove=bool(data.get("remove")))
            self._json(result, 200 if result.get("ok") else 404)

        elif self.path == "/crm-pay-stop":
            data = self._read_json()
            device_id = str(data.get("device_id") or "")
            import crm as crm_mod
            store = load_store()
            device = next((d for d in crm_mod.store_read().get("devices", [])
                           if str(d.get("id")) == device_id), None)
            profile = next((p for p in store.get("profiles", [])
                            if p.get("id") == (device or {}).get("profile_id")),
                           None) if device else None
            if not profile:
                self._json({"ok": False,
                            "errors": ["پروفایل پرداخت پیدا نشد"]}, 404)
                return
            status, payload = stop_profile(profile["id"])
            if status == 200:
                crm_mod.crm_log("info", "payment_stopped",
                                device_id=device_id,
                                profile_id=profile["id"])
            self._json(payload, status)

        elif self.path == "/crm-tick":
            data = self._read_json()
            tick_device_id = str(data.get("device_id") or "")
            tick_action = str(data.get("action") or "")
            device, errors = crm_advance_logged(tick_device_id, tick_action,
                                                owner_id=data.get("owner_id") or "",
                                                reason=str(data.get("reason") or ""))
            if errors:
                self._json({"ok": False, "errors": errors}, 400)
            else:
                _cloud_enqueue_mutation("crm_devices", tick_device_id, device)
                payload = {"ok": True, "device": device}
                if tick_action == "attach_owner":
                    # TWO-LAYER invariant (v1.5 item 11): the registration
                    # profile is created/linked at passenger-connect time
                    # (THIS hook — the primary layer), while the existing
                    # handover-time ensure inside crm_auto_advance_scan stays
                    # as the backstop for shapes that skipped the attach
                    # (stage_skip, legacy stores, a failed ensure here).
                    # Nothing may 500 the route: on failure/empty return the
                    # owner binding is KEPT, the operator gets profile_notice
                    # (with the surfaced reason — production fix 2026-09-15),
                    # and the backstop retries at handover/auto-advance time.
                    try:
                        profile_id = crm_ensure_registration_profile(tick_device_id)
                    except Exception as exc:
                        profile_id = ""
                        import crm as crm_mod
                        # device_id + phase + error text only — never
                        # personal data (plan §12).
                        crm_mod.crm_log("error", "profile_ensure_failed",
                                        device_id=tick_device_id,
                                        phase="attach",
                                        detail=repr(exc)[:300])
                        payload["profile_notice"] = (
                            "مسافر متصل شد اما ساخت پروفایل ثبت‌نام ناموفق بود "
                            "(علت: " + str(exc)[:120] + ") — "
                            "هنگام تحویل دوباره تلاش می‌شود")
                    if not profile_id and "profile_notice" not in payload:
                        import crm as crm_mod
                        # device_id only — never personal data (plan §12).
                        crm_mod.crm_log("warn", "profile_ensure_failed",
                                        device_id=tick_device_id,
                                        phase="attach")
                        payload["profile_notice"] = (
                            "مسافر متصل شد اما ساخت پروفایل ثبت‌نام ناموفق بود — "
                            "هنگام تحویل دوباره تلاش می‌شود")
                if tick_action == "handover":
                    # v1.5 B10: after a COMMITTED handover, try to hand the
                    # registration data to the registration Telegram
                    # destination. Fail-closed on every error shape (no
                    # destination, missing passport, send failure): the
                    # handover itself is already saved and stays; the
                    # operator gets handoff_notice. Nothing here may 500
                    # the route.
                    try:
                        _sent, handoff_notice = \
                            crm_send_registration_handoff(
                                tick_device_id, self.actor)
                    except Exception:
                        handoff_notice = "ارسال اطلاعات ثبت به تلگرام ناموفق بود"
                    payload["handoff_notice"] = handoff_notice
                self._json(payload)

        elif self.path == "/crm-start-payment":
            self._crm_start_payment(str(self._read_json().get("device_id") or ""))

        elif self.path == "/crm-inquiry":
            data = self._read_json()
            service = str(data.get("service") or "gomrok")
            ids = data.get("device_ids") or []
            if not isinstance(ids, list) or not ids:
                self._json({"ok": False, "errors": ["دستگاهی انتخاب نشده است"]}, 400)
                return
            results = []
            queued = 0
            for entry_id in ids:
                result = crm_start_inquiry(str(entry_id), service=service,
                                           origin="manual", actor=self.actor)
                errors = result.get("errors") or []
                results.append({"device_id": str(entry_id), "ok": result.get("ok"),
                                "errors": errors})
                if result.get("ok"):
                    queued += 1
                elif any("سقف" in str(e) for e in errors):
                    # Cap reached: stop here; the operator can re-run the rest
                    # when a browser frees up. Keep the failure visible.
                    break
            self._json({"ok": queued > 0, "queued": queued, "results": results})

        elif self.path == "/crm-inquiry-reset":
            self._crm_inquiry_reset(self._read_json())

        elif self.path == "/crm-settings":
            data = self._read_json()
            settings, errors = crm_update_settings(data)
            if errors:
                self._json({"ok": False, "errors": errors}, 400)
            else:
                self._json({"ok": True, "settings": settings})

        elif self.path == "/crm-handoff-resend":
            # v1.5 B10: manual re-send of the registration handoff from the
            # case detail modal. Valid only once the case has been handed
            # over (HANDOFF_STAGES); the destination/passport/send gates and
            # the log hygiene all live in the shared helper.
            import crm as crm_mod
            resend_id = str(self._read_json().get("device_id") or "")
            device = next((d for d in crm_mod.store_read().get("devices", [])
                           if d.get("id") == resend_id), None)
            if not device:
                self._json({"ok": False, "errors": ["دستگاه پیدا نشد"]}, 400)
            elif device.get("stage") not in HANDOFF_STAGES:
                self._json({"ok": False, "errors": [
                    "ارسال مجدد اطلاعات ثبت فقط برای مراحل پس از تحویل ممکن است"]},
                    400)
            else:
                try:
                    sent, notice = crm_send_registration_handoff(
                        resend_id, self.actor)
                except Exception:
                    # Mirror the /crm-tick handover hook: a helper crash must
                    # never abort the connection — surface the failure notice.
                    crm_mod.crm_log("warn", "registration_handoff_failed",
                                    device_id=resend_id)
                    sent, notice = False, "ارسال اطلاعات ثبت به تلگرام ناموفق بود"
                self._json({"ok": sent, "notice": notice})

        elif self.path == "/crm-report-telegram":
            self._crm_report_telegram(bool(self._read_json().get("full_data")))

        elif self.path == "/crm-finance-report-telegram":
            self._crm_finance_report_telegram(self._read_json())

        elif self.path == "/crm-statement-telegram":
            self._crm_statement_telegram(self._read_json())

        else:
            self._send(404, b"not found", "text/plain")

    def log_message(self, *args):
        pass


def clean_project_root():
    """Harf-e mohandesi: az root-e proje fayl-ha-ye test/dbg/movaqat-ra
    (ke asl-e kar nistand) pak kon — har bar ke panel run mishavad."""
    patterns = (
        "_after_*.png", "_after_*.html", "_after_*.json",
        "_dbg_last.*", "_dbg_patched.*", "_dbg_step_*.html",
        "_last_captcha_*.png", "_scs_fast.js", "_tmp_*",
        "hermes-verify-*.py", "_verify_*.py", "verify_tmp_*.py",
    )
    import glob
    for pattern in patterns:
        for path in glob.glob(os.path.join(HERE, pattern)):
            try:
                if os.path.isfile(path):
                    os.remove(path)
                    print(f">>> Cleanup: {os.path.basename(path)}")
            except OSError:
                pass
    dbg_site2 = os.path.join(HERE, "_dbg_site2")
    if os.path.isdir(dbg_site2):
        import shutil
        try:
            shutil.rmtree(dbg_site2)
            print(">>> Cleanup: _dbg_site2/")
        except OSError:
            pass


def start_gate_decision(probe_ok, probe_version):
    """Pure decision for the single-instance gate.

    (probe_ok, probe_version) is what the port probe observed. Returns
    ("already-running", version) when another panel of this project answers
    on the port, ("proceed", "") otherwise. Kept pure so tests cover the
    logic without sockets."""
    if probe_ok:
        return ("already-running", str(probe_version or ""))
    return ("proceed", "")


def _panel_already_running(timeout=1.5):
    """True when a panel of THIS project already answers on HOST:PORT.

    v1.2.0 note: / redirects to /login for fresh visitors, so the probe targets
    /login — public, always 200, and (since v1.2.0) carries the same
    'irica-version' chip the old home page had. Panels from releases older than
    1.0.11 are still recognized via their Persian site-picker markers, so
    upgrading over a running old install still refuses instead of crashing on
    bind. An unrelated service on the port (different markup) does not block us.
    """
    for probe_path in ("/login", "/"):
        probe_url = f"http://{HOST}:{PORT}{probe_path}"
        try:
            import urllib.request
            with urllib.request.urlopen(probe_url, timeout=timeout) as resp:
                body = resp.read(65536).decode("utf-8", "replace")
        except Exception:
            continue
        if "irica-version" in body or app_version_text() in body:
            return True
        # Pre-1.0.11 marker: the site picker's title + a site-1 link together
        # are specific enough to be this project and nothing else.
        if "سامانه مدیریت گمرک" in body and "/site-1" in body:
            return True
    return False
    if "irica-version" in body or app_version_text() in body:
        return True
    # Pre-1.0.11 marker: the site picker's title + a site-1 link together
    # are specific enough to be this project and nothing else.
    return "سامانه مدیریت گمرک" in body and "/site-1" in body


class PanelHTTPServer(ThreadingHTTPServer):
    # Windows SO_REUSEADDR (the socketserver default) silently allows a second
    # bind of the same listening port -> two panels racing on one socket.
    # Refuse reuse so a second bind fails loudly instead.
    allow_reuse_address = False


def _announce_seeded_accounts(seeded):
    """First boot only: show the generated passwords once, on stdout.

    `seeded` is what panel_auth.seed_default_users returned. The plaintext
    exists nowhere else — not in the file, not in a config, not in a log — so
    this is the operator's one and only sight of it. Written straight to
    stdout (never through the logging helpers) and guarded, because
    sys.stdout is None whenever the process has no writable standard stream
    (pythonw, a closed handle) and an unguarded write would abort startup.
    """
    if not seeded:
        return
    out = getattr(sys, "stdout", None)
    if out is None:
        return
    width = max(len(name) for name, _pw in seeded)
    lines = [
        ">>> First boot: no users file yet, so one password per account was",
        ">>> generated for this install. It is shown ONCE and stored nowhere:",
        ">>> sign in and change it from the panel as soon as possible.",
    ]
    lines.extend(">>>   %s%s = %s" % (name, " " * (width - len(name)), password)
                 for name, password in seeded)
    lines.append(">>> Lost them? Delete panel_users.json in")
    lines.append(">>>   " + DATA_DIR)
    lines.append(">>> and start the panel again to generate a fresh set.")
    try:
        out.write("\n".join(lines) + "\n")
        out.flush()
    except Exception:
        pass


def main():
    if _panel_already_running():
        url = f"http://{HOST}:{PORT}"
        print(f">>> Panel-e digari hamin port ast: {url}")
        print(">>> Baraye start-e nuskhe-ye jadid, aval panel-e fe'li ra beband.")
        try:
            import webbrowser
            webbrowser.open(url + "/site-1")
        except Exception:
            pass
        return
    # First boot of this install: create the three accounts with a random
    # password and show it once. Existing users files are left untouched.
    _announce_seeded_accounts(panel_auth.seed_default_users())
    url = f"http://{HOST}:{PORT}"

    try:
        srv = PanelHTTPServer((HOST, PORT), Handler)
    except OSError:
        # Probe failed but the port is taken: a running panel is the only
        # legitimate holder (robots bind other ports). Treat as already-running.
        if _panel_already_running():
            print(f">>> Panel-e digari hamin port ast: {url}")
            try:
                import webbrowser
                webbrowser.open(url + "/site-1")
            except Exception:
                pass
            return
        raise
    load_store()  # motmaen sho profiles.json +inputs.json sakhte/sync shode-and
    clear_stale_busy_profiles()
    clean_project_root()
    crm_scheduler_start()
    # Cloud sync (spec §9): a daemon beat with a bounded interval. It
    # returns None until a base URL is configured, so a fresh install starts
    # no network worker at all.
    cloud_worker_start()
    threading.Thread(target=_startup_telegram_bootstrap, daemon=True,
                     name="telegram-api-health").start()
    print(f">>> Panel bala amad: {url}")
    print(f">>> Tanzimat va dade-ha: {DATA_DIR}")
    if _MIGRATED_FILES:
        source = app_paths.imported_from()
        print(f">>> Az nasKHe-ye ghabli montaghel shod ({source}): "
              f"{', '.join(_MIGRATED_FILES)}")
    print(f">>> Profile-ha: {PROFILES_PATH}")
    print(f">>> Profile-e active -> {INPUTS_PATH} (gomrok.py az inja mikhanad)")
    print(f">>> Log-ha: {LOGS_PATH}")
    print(">>> Baraye khamoosh kardan: Ctrl+C")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        # serve_forever runs on a helper thread; the main thread polls the
        # /shutdown flag so "بستن سامانه" can stop the panel cleanly
        # (robots already killed by shutdown_everything()).
        serve_thread = threading.Thread(target=srv.serve_forever,
                                        name="panel-serve", daemon=True)
        serve_thread.start()
        while not _SHUTDOWN_REQUESTED.is_set():
            _SHUTDOWN_REQUESTED.wait(timeout=0.5)
        print(">>> Panel ba dastoor-e karbar (بستن سامانه) khamoosh shod.")
        srv.shutdown()
        serve_thread.join(timeout=5)
    except KeyboardInterrupt:
        print("\n>>> Panel baste shod.")
        srv.shutdown()


if __name__ == "__main__":
    main()


# --------------------------------------------------------------- login gate
def render_login_page():
    # Wrapped too: a live session cookie may accompany this POST (a signed-in
    # operator typing /login), and that POST must carry the token as well.
    return with_csrf_bootstrap(
        LOGIN_PAGE.replace("__VERSION__", app_version_text() or "—")).encode("utf-8")


LOGIN_PAGE = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ورود — ایریکا</title>
<link rel="icon" href="/favicon.ico">
<style>
/* IRICA design system — light entry skin (login, no theme toggle).
   Keep the 'irica-version' chip: _panel_already_running and the tray probe
   identify this panel through that marker on the public /login page. */
@font-face{
  font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-var.woff2') format('woff2-variations');
  font-weight:100 900;font-style:normal;font-display:swap;
}
@font-face{
  font-family:'Vazirmatn';src:url('/fonts/Vazirmatn-Bold.woff2') format('woff2');
  font-weight:700;font-style:normal;font-display:swap;
}
:root{
  --bg:#f4f6fb;--card:#ffffff;--card2:#f7f8fd;--line:rgba(27,32,54,.10);
  --line-strong:rgba(27,32,54,.16);--txt:#1b2036;--muted:#5c6484;
  --brand:#4460e3;--brand-hover:#3757cf;--brand-soft:rgba(68,96,227,.10);
  --on-brand:#ffffff;--ok:#0c7d4f;--ok-soft:rgba(15,157,99,.12);
  --danger:#d93752;--danger-soft:rgba(217,55,82,.10);
  --shadow-1:0 1px 2px rgba(16,20,40,.05),0 1px 6px rgba(16,20,40,.04);
  --shadow-2:0 4px 14px rgba(16,20,40,.10),0 1px 3px rgba(16,20,40,.06);
  --ring:0 0 0 3px rgba(68,96,227,.30);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { color-scheme: light; }
body {
  font-family: Vazirmatn, "Segoe UI", Tahoma, sans-serif;
  background:
    radial-gradient(900px 480px at 85% -10%, rgba(79,107,239,.13), transparent 60%),
    radial-gradient(720px 420px at 6% 8%, rgba(124,92,245,.09), transparent 55%),
    var(--bg);
  color: var(--txt); min-height: 100vh; font-size: 14px; line-height: 1.7;
  display: flex; align-items: center; justify-content: center; padding: 24px;
  -webkit-font-smoothing: antialiased;
}
.card {
  width: 100%; max-width: 392px; background: var(--card);
  border: 1px solid var(--line); border-radius: 18px;
  padding: 34px 30px 26px; box-shadow: var(--shadow-2);
}
.mono {
  width: 56px; height: 56px; border-radius: 14px; margin: 0 auto 16px;
  background: linear-gradient(135deg, var(--brand), #7c5cf5); color: var(--on-brand);
  display: grid; place-items: center; font-size: 24px; font-weight: 800;
  box-shadow: var(--shadow-1);
}
h1 { font-size: 19px; font-weight: 750; text-align: center; margin-bottom: 4px; }
.sub { font-size: 12.5px; color: var(--muted); text-align: center; margin-bottom: 22px; }
label { display: block; font-size: 12.5px; color: var(--muted); margin: 14px 0 6px; }
input {
  width: 100%; padding: 11px 13px; border-radius: 10px; font-size: 14px;
  border: 1px solid var(--line-strong); background: var(--card2); color: var(--txt);
  font-family: inherit; transition: border-color .15s, box-shadow .15s, background .15s;
}
input:hover { border-color: rgba(27,32,54,.30); }
input:focus { outline: none; border-color: var(--brand); background: var(--card); box-shadow: var(--ring); }
button {
  width: 100%; margin-top: 22px; padding: 12px; border: 0; border-radius: 10px;
  background: var(--brand); color: var(--on-brand); font-size: 14.5px; font-weight: 700;
  font-family: inherit; cursor: pointer; transition: background .15s, transform .15s;
}
button:hover { background: var(--brand-hover); }
button:active { transform: translateY(1px); }
button:disabled { opacity: .6; cursor: default; transform: none; }
button:focus-visible { outline: none; box-shadow: var(--ring); }
.err {
  display: none; margin-top: 14px; padding: 10px 12px; border-radius: 10px;
  background: var(--danger-soft); border: 1px solid rgba(217,55,82,.28);
  color: #b72740; font-size: 12.5px; line-height: 1.8;
}
.foot { margin-top: 18px; font-size: 11.5px; color: var(--muted); text-align: center; }
.foot.irica-version {
  display: block; width: max-content; margin: 8px auto 0; padding: 3px 12px;
  border-radius: 999px; border: 1px solid var(--line); background: var(--card2);
  font-size: 11px;
}
</style>
</head>
<body>
<form class="card" id="f" autocomplete="off">
  <div class="mono">R</div>
  <h1>ورود به پنل</h1>
  <div class="sub">برای ادامه، نام کاربری و رمز عبور خود را وارد کنید</div>
  <label for="u">نام کاربری</label>
  <input id="u" name="username" autofocus autocomplete="username" required>
  <label for="p">رمز عبور</label>
  <input id="p" name="password" type="password"
         autocomplete="current-password" required>
  <button type="submit" id="btn">ورود</button>
  <div class="err" id="err"></div>
  <div class="foot">ایریکا · سامانهٔ استعلام و ثبت سفارش</div>
  <div class="foot irica-version">نسخه __VERSION__</div>
</form>
<script>
"use strict";
var f = document.getElementById("f");
var btn = document.getElementById("btn");
var err = document.getElementById("err");
/* v1.9: the login page has no shared shell, so it carries its own cue code.
   The switch is the server setting; before login there is no session to
   read it from, so the last known choice is remembered locally and the
   default is ON. The cue follows the submit click, so the browser's
   autoplay policy allows it. */
function sfxOn(){
  try{ return localStorage.getItem("irica-sound") !== "0"; }catch(e){ return true; }
}
function sfx(name){
  if(!sfxOn())return;
  try{
    var el = new Audio("/sfx/" + name);
    el.preload = "auto";
    var pr = el.play();
    if(pr && pr.catch) pr.catch(function(){});
  }catch(e){}
}
function fail(msg) {
  err.textContent = msg;
  err.style.display = "block";
  btn.disabled = false;
  sfx("ui-login-error");
}
f.addEventListener("submit", function (ev) {
  ev.preventDefault();
  btn.disabled = true;
  err.style.display = "none";
  var payload = {
    username: document.getElementById("u").value.trim(),
    password: document.getElementById("p").value
  };
  fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }).then(function (r) {
    if (r.status === 429) { fail("تلاش‌های ناموفق زیاد؛ چند دقیقه بعد دوباره امتحان کنید"); return null; }
    if (r.ok) { sfx("ui-login"); window.location.replace("/"); return null; }
    return r.json().then(function (j) {
      fail((j.errors && j.errors[0]) || "ورود ناموفق بود");
    }, function () { fail("ورود ناموفق بود"); });
  }).catch(function () { fail("ارتباط با سرور برقرار نشد"); });
});
</script>
</body>
</html>
"""


def _cookie_token(headers_get):
    """Extract the irica_session token from a Cookie header, if any."""
    raw = headers_get.get("Cookie") or ""
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith("irica_session="):
            return part.split("=", 1)[1]
    return None


def _actor_env(username):
    """Child-process env carrying the acting user for Telegram attribution."""
    env = os.environ.copy()
    env["IRICA_ACTOR"] = username
    return env





