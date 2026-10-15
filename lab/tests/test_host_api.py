# -*- coding: utf-8 -*-
"""Host API contract (workstream C-host) — the real PHP server, end to end.

Unlike every other cloud-sync test, this module does NOT use the loopback
fake: it starts the actual front controller

    php -S 127.0.0.1:<port> -t host/public host/public/index.php

against the local MariaDB of spec §13.1, on a dedicated database with a
dedicated least-privilege account, and drives every endpoint of spec §6 over
HTTP. What it proves:

  * login success and failure, and that a failed login is rate limited into a
    temporary lock that then RELEASES (never a permanent lockout, §10.5);
  * refresh rotation, and that replaying a consumed refresh token revokes the
    whole family (§5);
  * enrolment needs a live *user* access token with `device:enroll` (§5/§7);
  * bootstrap returns its snapshot and its cursor from one transaction (§6.2);
  * changes pages with `has_more`, filters on `seq > cursor` only, and reports
    a delete as `record: null` (§6.2, §4);
  * mutations apply, replay idempotently by `operation_id`, report conflicts
    as data WITHOUT aborting the rest of the batch, and answer a stale
    `base_version` on an unknown row as `server_version: 0` (§6.1);
  * an id owned by another tenant answers 404, never 403 (§7);
  * the role matrix: a non-admin may not write settings or a period (§7);
  * `bin/create-user.php` mints a `user`-role account that then obeys that
    whole matrix over HTTP, refuses a duplicate username with exit 1 and no
    row, and prints a generated password exactly once and never a hash
    (§15 ruling 17, §10.1);
  * import is idempotent for one `import_id` and refuses the second one with
    `409 DATASET_NOT_EMPTY` (§8);
  * the app account cannot run DDL, no `Access-Control-Allow-Origin` is ever
    sent, an oversized body is refused, a non-JSON body is refused (§10);
  * no password, token, national id, phone number or name appears in any log
    line this test can observe (§5, §10.9);
  * `Ids::uuid5` agrees byte for byte with Python's `uuid.uuid5`, and every
    error code this package can emit satisfies §15.8's grammar.

Run:
  "C:/Program Files/Python310/python.exe" lab/scripts/run_panel_tests.py test_host_api

Mock/sample rows only — no real customer PII and no real credential: the
database password, the app password, the admin password and the second user's
password are all generated for this run, kept in memory plus one temporary
config file outside the repository, and redacted from every assertion message.
Nothing is written to %LOCALAPPDATA%\\irica\\.
"""
import atexit
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

HOST_DIR = os.path.join(ROOT, "host")
PUBLIC_DIR = os.path.join(HOST_DIR, "public")
INDEX_PHP = os.path.join(PUBLIC_DIR, "index.php")
HTACCESS = os.path.join(PUBLIC_DIR, ".htaccess")
SCHEMA_SQL = os.path.join(HOST_DIR, "migrations", "001_initial.sql")
CONFIG_EXAMPLE = os.path.join(HOST_DIR, "config", "config.example.php")

# Spec §13.1 — the provisioned local environment.
PHP_CANDIDATES = (
    r"C:\Users\Saeed\AppData\Local\Microsoft\WinGet\Packages"
    r"\PHP.PHP.8.1_Microsoft.Winget.Source_8wekyb3d8bbwe\php.exe",
)
MARIADB_RELATIVE = os.path.join(
    ".tools", "mysql", "mariadb-11.4.4-winx64", "bin", "mariadb.exe")
DB_HOST = "127.0.0.1"
DB_PORT = 3307
API_DB = "irica_test_api"          # created and dropped by this module
API_USER = "irica_api_host"        # DML only, exactly like production
SCRATCH_DB = "irica_test_api_mig"  # exercises bin/migrate.php

ENTITIES = ("customers", "customer_transactions", "owners", "identities",
            "crm_devices", "periods", "settings")
# Spec §15.8 / the client's ERROR_CODE_RE.
ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
MAX_CODE_LENGTH = 40
NAMESPACE_URL = uuid.NAMESPACE_URL

_environment_cache = {}
_passwords = set()
_state = {}


# ---------------------------------------------------------------------------
# Environment discovery (never prints a credential)
# ---------------------------------------------------------------------------

def _find_php():
    override = os.environ.get("IRICA_PHP")
    if override and os.path.isfile(override):
        return override
    for candidate in PHP_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return shutil.which("php")


def _find_mariadb():
    override = os.environ.get("IRICA_MARIADB")
    if override and os.path.isfile(override):
        return override
    local = os.path.join(ROOT, MARIADB_RELATIVE)
    if os.path.isfile(local):
        return local
    for name in ("mariadb.exe", "mariadb", "mysql"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _credentials():
    path = os.environ.get("IRICA_TEST_DB_JSON") or os.path.join(
        os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir(),
        "irica_test_db.json")
    root = os.environ.get("IRICA_DB_ROOT_PASSWORD")
    port = DB_PORT
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            return None, DB_PORT, "credential file is unreadable: %s" % exc
        root = root or data.get("root_password")
        port = int(data.get("port") or DB_PORT)
    if not root:
        return None, port, ("no root password: set IRICA_DB_ROOT_PASSWORD or "
                            "provide %s" % path)
    return root, port, None


def _environment():
    if "reason" in _environment_cache:
        return _environment_cache["reason"]
    reason = None
    php = _find_php()
    if not php:
        reason = ("PHP CLI not found (looked at IRICA_PHP, %s, and PATH)"
                  % ", ".join(PHP_CANDIDATES))
    mariadb = _find_mariadb()
    if not reason and not mariadb:
        reason = "mariadb client not found (expected %s under the repository)" \
                 % MARIADB_RELATIVE
    root, port, cred_error = _credentials()
    if not reason and cred_error:
        reason = cred_error
    if not reason and not os.path.isfile(INDEX_PHP):
        reason = "host/public/index.php is missing"
    _environment_cache.update({
        "reason": reason, "php": php, "mariadb": mariadb,
        "root": root, "port": port,
    })
    return reason


def _redact(text):
    if not text:
        return text
    for secret in _passwords:
        if secret:
            text = text.replace(secret, "***")
    return text


# ---------------------------------------------------------------------------
# SQL over the mariadb CLI (no Python MySQL driver — spec §1)
# ---------------------------------------------------------------------------

def _run_sql(sql, database=None, user="root", password=None, expect_ok=True):
    """Run SQL through the mariadb CLI. The password travels in MYSQL_PWD."""
    if password is None:
        password = _environment_cache["root"]
    command = [
        _environment_cache["mariadb"], "-h", DB_HOST,
        "-P", str(_environment_cache["port"]), "-u", user,
        "--protocol=TCP", "--ssl=FALSE", "--default-character-set=utf8mb4",
        "--batch", "--skip-column-names",
    ]
    if database:
        command.append(database)
    env = dict(os.environ)
    env["MYSQL_PWD"] = password
    process = subprocess.run(
        command, input=sql or "", capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env, timeout=180)
    stdout = _redact(process.stdout or "")
    stderr = _redact(process.stderr or "")
    if expect_ok and process.returncode != 0:
        raise AssertionError("SQL failed (exit %d):\n%s\n%s" % (
            process.returncode, stderr.strip(), stdout.strip()))
    return stdout, stderr, process.returncode


def _sql_value(sql, database=API_DB, user="root", password=None):
    stdout, _err, code = _run_sql(sql, database=database, user=user,
                                  password=password, expect_ok=False)
    if code != 0:
        raise AssertionError("query failed: %s" % _redact(_err.strip()))
    return stdout.strip().splitlines()[-1] if stdout.strip() else ""


# ---------------------------------------------------------------------------
# PHP invocation
# ---------------------------------------------------------------------------

def _php(script, env=None, expect_ok=True):
    """Run a PHP snippet with the host classes loaded; return stdout text."""
    directory = tempfile.mkdtemp(prefix="irica_php_")
    _state.setdefault("scratch", []).append(directory)
    path = os.path.join(directory, "probe.php")
    body = ("<?php\ndeclare(strict_types=1);\n"
            "require_once '%s';\n"
            "require_once '%s';\n"
            "require_once '%s';\n"
            "require_once '%s';\n"
            "require_once '%s';\n"
            "require_once '%s';\n"
            "require_once '%s';\n"
            % (os.path.join(HOST_DIR, "src", "Schema.php").replace("\\", "/"),
               os.path.join(HOST_DIR, "src", "Database.php").replace("\\", "/"),
               os.path.join(HOST_DIR, "src", "Http.php").replace("\\", "/"),
               os.path.join(HOST_DIR, "src", "Ids.php").replace("\\", "/"),
               os.path.join(HOST_DIR, "src", "Config.php").replace("\\", "/"),
               os.path.join(HOST_DIR, "src", "Log.php").replace("\\", "/"),
               os.path.join(HOST_DIR, "src", "Auth.php").replace("\\", "/"))
            + script)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    run_env = dict(os.environ)
    run_env["IRICA_HOST_CONFIG"] = _state["config_path"]
    if env:
        run_env.update(env)
    process = subprocess.run(
        [_environment_cache["php"], path], capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=run_env, timeout=120)
    if expect_ok and process.returncode != 0:
        raise AssertionError("php failed (exit %d):\n%s" % (
            process.returncode, _redact((process.stderr or "").strip())))
    return _redact(process.stdout or ""), _redact(process.stderr or "")


def _php_json(script, env=None):
    stdout, stderr = _php(script, env=env)
    try:
        return json.loads(stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise AssertionError("php did not output JSON: %r / %r"
                             % (stdout[:400], stderr[:400]))


# ---------------------------------------------------------------------------
# HTTP against the running server
# ---------------------------------------------------------------------------

def _call(method, path, body=None, *, token=None, acting=None, raw=None,
          content_type="application/json", timeout=30, base=None):
    url = (base + path) if base else (_state["base_url"] + path)
    data = raw
    if raw is None and body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None or method == "POST":
        request.add_header("Content-Type", content_type)
    if token:
        request.add_header("Authorization", "Bearer " + token)
    if acting:
        request.add_header("X-Acting-User", "Bearer " + acting)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            headers = dict(response.headers.items())
            payload = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        headers = dict(error.headers.items()) if error.headers else {}
        payload = error.read()
    except (urllib.error.URLError, OSError) as error:
        raise AssertionError("request to %s failed: %s"
                             % (path, _redact(str(error))))
    text = payload.decode("utf-8", "replace") if payload else ""
    parsed = None
    if text.strip():
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    return status, parsed, headers, text


def _ok(method, path, body=None, **kwargs):
    status, payload, headers, text = _call(method, path, body, **kwargs)
    if status != 200 or not isinstance(payload, dict) \
            or payload.get("ok") is not True:
        raise AssertionError("%s %s expected 200 {ok:true}, got %d %s"
                             % (method, path, status, _redact(text[:400])))
    return payload, headers


def _fail(method, path, body=None, **kwargs):
    status, payload, headers, text = _call(method, path, body, **kwargs)
    if status < 400 or not isinstance(payload, dict) or payload.get("ok") is not False:
        raise AssertionError("%s %s expected an error envelope, got %d %s"
                             % (method, path, status, _redact(text[:400])))
    error = payload.get("error")
    if not isinstance(error, dict):
        raise AssertionError("error envelope has no error object")
    return status, error, headers, payload


def _login(username, password):
    payload, _headers = _ok("POST", "/auth/login", {
        "username": username, "password": password})
    return payload


def _device_token():
    """An enrolled device's access token (login + enroll + refresh)."""
    cached = _state.get("device_token")
    if cached:
        return cached
    user = _login(_state["admin_user"], _state["admin_password"])
    enrolled, _headers = _ok("POST", "/sync-devices/enroll", {},
                             token=user["access_token"])
    _state["device_id"] = enrolled["sync_device_id"]
    _state["device_refresh"] = enrolled["device_refresh_token"]
    refreshed, _headers = _ok("POST", "/auth/refresh", {
        "refresh_token": _state["device_refresh"], "kind": "device"})
    _state["device_token"] = refreshed["access_token"]
    _state["device_refresh"] = refreshed["refresh_token"]
    return _state["device_token"]


def _enroll(role="admin"):
    """A FRESH device (new family), so revocation tests stay independent."""
    user = _login(_state["admin_user"] if role == "admin"
                  else _state["user_user"], _state["admin_password"]
                  if role == "admin" else _state["user_password"])
    enrolled, _headers = _ok("POST", "/sync-devices/enroll", {},
                             token=user["access_token"])
    refreshed, _headers = _ok("POST", "/auth/refresh", {
        "refresh_token": enrolled["device_refresh_token"], "kind": "device"})
    return refreshed["access_token"], enrolled["sync_device_id"]


def _user_token():
    return _login(_state["user_user"], _state["user_password"])["access_token"]


def _uuid5(entity, legacy):
    return str(uuid.uuid5(NAMESPACE_URL, "%s/%s/%s"
                          % (_state["installation"], entity, legacy)))


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

def _write_config(directory, app_password, admin_password):
    path = os.path.join(directory, "config.php")
    log_path = os.path.join(directory, "api.log")
    body = """<?php
return [
    'env' => 'test',
    'base_path' => '/v1',
    'tenant_slug' => 'default',
    'db' => [
        'host' => '127.0.0.1',
        'port' => %d,
        'dbname' => '%s',
        'user' => '%s',
        'password' => %s,
    ],
    'db_migrate' => [
        'host' => '127.0.0.1',
        'port' => %d,
        'dbname' => '%s',
        'user' => 'root',
        'password' => %s,
    ],
    'jwt_secret' => '%s',
    'jwt_ttl_seconds' => 900,
    'refresh' => [
        'user_idle_seconds' => 28800,
        'user_absolute_seconds' => 86400,
        'device_idle_seconds' => 7776000,
        'device_absolute_seconds' => 31536000,
    ],
    'idempotency_retention_days' => 30,
    'legacy_import_enabled' => false,
    'rate_limit' => [
        'window_seconds' => 60,
        'delay_after' => 100,
        'base_delay_seconds' => 1,
        'max_delay_seconds' => 60,
        'lock_after' => 3,
        'lock_seconds' => 2,
    ],
    'limits' => [
        'max_body_bytes' => 1048576,
        'max_import_body_bytes' => 16777216,
        'max_operations' => 500,
        'max_import_rows' => 100000,
        'default_changes_limit' => 500,
        'max_changes_limit' => 5000,
    ],
    'log_path' => %s,
    'smoke_probe_url' => null,
];
""" % (
        _environment_cache["port"], API_DB, API_USER, json.dumps(app_password),
        _environment_cache["port"], API_DB,
        json.dumps(_environment_cache["root"]),
        secrets.token_hex(32), json.dumps(log_path),
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    return path, log_path


def _provision():
    """Database, least-privilege account, migration, admin, second user."""
    root = _environment_cache["root"]
    app_password = secrets.token_urlsafe(18)
    admin_password = "Admin-" + secrets.token_urlsafe(14)
    user_password = "Member-" + secrets.token_urlsafe(14)
    _passwords.update({root, app_password, admin_password, user_password})

    # A clean slate every run: the module owns both objects. The default
    # account host is production-like localhost. Container CI may opt into '%'
    # because a service container sees the runner through its bridge address.
    account_host = os.environ.get("IRICA_TEST_DB_ACCOUNT_HOST", "127.0.0.1")
    if account_host not in ("127.0.0.1", "%"):
        raise AssertionError("IRICA_TEST_DB_ACCOUNT_HOST has an unsupported value")
    _run_sql("DROP DATABASE IF EXISTS `%s`;" % API_DB, expect_ok=False)
    _run_sql("DROP USER IF EXISTS '%s'@'%s';" % (API_USER, account_host),
             expect_ok=False)
    _run_sql("CREATE DATABASE `%s` DEFAULT CHARACTER SET utf8mb4"
             " COLLATE utf8mb4_unicode_ci;" % API_DB)
    _run_sql("CREATE USER '%s'@'%s' IDENTIFIED BY '%s';"
             % (API_USER, account_host, app_password))
    # Exactly the production grant set of spec §2: DML only, no CREATE.
    _run_sql("GRANT SELECT, INSERT, UPDATE, DELETE ON `%s`.* TO"
             " '%s'@'%s';" % (API_DB, API_USER, account_host))
    _run_sql("FLUSH PRIVILEGES;")
    # Registered the moment they exist: a failure later in provisioning must
    # still be able to drop them (tearDownClass will not run).
    _state["drop_sql"] = (
        "DROP DATABASE IF EXISTS `%s`;"
        " DROP USER IF EXISTS '%s'@'%s';"
        % (API_DB, API_USER, account_host))

    directory = tempfile.mkdtemp(prefix="irica_host_api_")
    config_path, log_path = _write_config(directory, app_password,
                                          admin_password)
    _state.update({
        "config_dir": directory, "config_path": config_path,
        "log_path": log_path, "app_password": app_password,
        "admin_password": admin_password, "user_password": user_password,
        "installation": str(uuid.uuid4()),
        "scratch": [],
    })

    # 1. migrate (privileged account — the app account has no DDL).
    _run_bin("migrate.php")

    # 2. the first administrator, password from the environment only.
    out, err, code = _run_bin("create-admin.php", env={
        "IRICA_ADMIN_PASSWORD": admin_password,
    }, args=["--username=admin"], expect_ok=False)
    if code != 0:
        raise AssertionError("create-admin failed: %s" % _redact(err or out))

    # 3. a second account with the `user` role — spec §6 has no API endpoint
    #    for creating users, so the fixture uses the package's own CLI
    #    (§15 ruling 17), which is the supported path for every account
    #    after the first administrator. The password arrives through the
    #    environment, never on the command line.
    out, err, code = _run_bin("create-user.php", args=[
        "--username=member", "--display-name=Sample Member", "--role=user",
    ], env={"IRICA_USER_PASSWORD": user_password}, expect_ok=False)
    if code != 0:
        raise AssertionError("create-user failed: %s" % _redact(err or out))
    if "PASSWORD (shown once" in out:
        raise AssertionError("create-user re-printed a supplied password")

    _state["tenant_id"] = _sql_value(
        "SELECT id FROM tenants WHERE slug = 'default';")
    _state["admin_user"] = "admin"
    _state["user_user"] = "member"
    _state["device_token"] = None
    _state["device_refresh"] = None
    _state["device_id"] = None


def _run_bin(name, args=None, env=None, expect_ok=True, config=None):
    command = [_environment_cache["php"],
               os.path.join(HOST_DIR, "bin", name)] + list(args or [])
    run_env = dict(os.environ)
    run_env["IRICA_HOST_CONFIG"] = config or _state["config_path"]
    if env:
        run_env.update(env)
    process = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=run_env, cwd=ROOT, timeout=300)
    out = _redact(process.stdout or "")
    err = _redact(process.stderr or "")
    if expect_ok and process.returncode != 0:
        raise AssertionError("%s failed (exit %d):\n%s\n%s"
                             % (name, process.returncode, out, err))
    return out, err, process.returncode


def _free_port():
    for _ in range(8):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((DB_HOST, 0))
            return probe.getsockname()[1]
    raise AssertionError("no free loopback port could be bound")


def _start_server():
    server_log = os.path.join(_state["config_dir"], "server.log")
    for _attempt in range(5):
        port = _free_port()
        base = "http://%s:%d/v1" % (DB_HOST, port)
        handle = open(server_log, "ab")
        process = subprocess.Popen(
            [_environment_cache["php"], "-d", "display_errors=0",
             "-d", "log_errors=1", "-d", "post_max_size=64M",
             "-S", "%s:%d" % (DB_HOST, port), "-t", PUBLIC_DIR, INDEX_PHP],
            stdout=handle, stderr=subprocess.STDOUT, cwd=ROOT,
            env=dict(os.environ,
                     IRICA_HOST_CONFIG=_state["config_path"]))
        ready = False
        try:
            deadline = time.time() + 20
            while time.time() < deadline and not ready:
                if process.poll() is not None:
                    break
                try:
                    status, payload, _headers, _text = _call(
                        "GET", "/health/live", timeout=2, base=base)
                except AssertionError:
                    # Not listening yet (connection refused) — try again.
                    time.sleep(0.15)
                    continue
                ready = status == 200 and isinstance(payload, dict)
                if not ready:
                    time.sleep(0.15)
        finally:
            # Whatever happens here — a port in use, an unexpected exception
            # from the probe, a timeout — this attempt's process must not
            # outlive the attempt. setUpClass failures never reach
            # tearDownClass, so the guarantee has to live here.
            if not ready and process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
            if not ready:
                handle.close()
        if ready:
            _state.update({"server": process, "server_log": server_log,
                           "server_handle": handle, "base_url": base,
                           "port": port})
            return
    raise AssertionError("the PHP development server did not become healthy")


def _stop_server():
    process = _state.get("server")
    if process is not None and process.poll() is None:
        process.kill()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass
    handle = _state.get("server_handle")
    if handle is not None and not handle.closed:
        handle.close()


def _teardown():
    if _state.get("torn_down"):
        return
    _state["torn_down"] = True
    _stop_server()
    for key in ("drop_sql",):
        try:
            _run_sql(_state[key], expect_ok=False)
        except Exception:  # noqa: BLE001 - teardown must not mask a failure
            pass
    directory = _state.get("config_dir")
    if directory:
        shutil.rmtree(directory, ignore_errors=True)
    for scratch in _state.get("scratch", []):
        shutil.rmtree(scratch, ignore_errors=True)


# unittest only calls tearDownClass when setUpClass succeeded, and a failure
# between "database created" and "server healthy" would otherwise strand a
# scratch database and a listening PHP process on this machine.
atexit.register(_teardown)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class HostApiTest(unittest.TestCase):
    """Every test here needs PHP, MariaDB and a running front controller."""

    @classmethod
    def setUpClass(cls):
        reason = _environment()
        if reason:
            print("\nHOST API SUITE SKIPPED: %s" % reason)
            raise unittest.SkipTest(
                "host API verification unavailable — %s" % reason)
        _provision()
        _start_server()

    @classmethod
    def tearDownClass(cls):
        _teardown()

    # -- plumbing -------------------------------------------------------

    def _import_document(self, suffix="a"):
        installation = _state["installation"]
        legacy_customer = "c%s" % suffix
        legacy_owner = "o%s" % suffix
        legacy_identity = "i%s" % suffix
        legacy_device = "d%s" % suffix
        legacy_period = "p%s" % suffix
        customer_id = _uuid5("customers", legacy_customer)
        owner_id = _uuid5("owners", legacy_owner)
        device_id = _uuid5("crm_devices", legacy_device)
        period_id = _uuid5("periods", legacy_period)
        tx_id = _uuid5("customer_transactions", "%s/0" % legacy_customer)
        settings_id = _uuid5("settings", "settings/settings")
        stamp = "2026-01-05T10:00:00+00:00"
        return {
            "import_id": str(uuid.uuid4()),
            "source_installation_id": installation,
            "collections": {
                "periods": [{
                    "id": legacy_period, "number": 1, "label": "Sample period",
                    "opened_at": stamp, "opened_by": "admin",
                    "closed_at": None, "closed_by": "", "closed_reason": "",
                }],
                "customers": [{
                    "id": legacy_customer, "full_name": "Sample Customer",
                    "address": "Sample Street 1", "mobile": "09120000001",
                    "telegram_id": "", "instagram_id": "", "notes": "",
                    "created": None, "updated": None,
                }],
                "owners": [{
                    "id": legacy_owner, "first_name": "Sample",
                    "last_name": "Owner", "national": "0012345678",
                    "birth": "1360/01/01", "mobile": "09120000002",
                    "card_no": "", "passport": "", "created": None,
                    "updated": None,
                }],
                "identities": [{
                    "id": legacy_identity, "label": "pool", "national": "0087654321",
                    "birth": "1361/02/02", "mobile": "09120000003",
                    "created": None, "updated": None,
                }],
                "crm_devices": [{
                    "id": legacy_device, "name": "CASE-1", "serial1": "SER1",
                    "serial2": "", "customer_id": customer_id,
                    "owner_id": owner_id, "stage": "new", "auto_advance": False,
                    "profile_id": "", "handed_at": None, "registered_at": None,
                    "payment_confirmed_at": None, "code_delivered_at": None,
                    "done_at": None, "last_inquiry_at": None, "notes": "",
                    "advance_attempts": 0, "period_id": period_id,
                    "created": None, "updated": None, "skipped_stages": [],
                    "closed_at": None, "closed_reason": "",
                    "periodic_opt_out": False, "payment_started_at": None,
                }],
                "customer_transactions": [{
                    "id": tx_id, "seq": 0, "customer_id": customer_id,
                    "at": stamp, "amount": 1500000, "note": "down payment",
                    "kind": "payment", "image": "", "device_id": device_id,
                    "voided_at": None, "void_reason": "",
                }],
                "settings": [{
                    "id": settings_id, "business_name": "Sample Business",
                    "business_phone": "02100000000",
                    "watch_interval_hours": 3, "scheduler_enabled": True,
                    "auto_advance_default": False,
                    "telegram_report_full_data": True,
                    "registry_fee_amount": 1000, "registration_chat_id": "",
                    "report_chat_id": "", "sound_enabled": True,
                    "current_period_id": period_id, "links": [],
                }],
            },
        }

    def _push(self, operations, token=None, acting=None, expect=200):
        status, payload, _headers, text = _call(
            "POST", "/sync/mutations", {"operations": operations},
            token=token or _device_token(), acting=acting)
        self.assertEqual(status, expect,
                         "mutations answered %d: %s" % (status, text[:400]))
        return payload

    def setUp(self):
        # Every case starts from an empty, never-imported tenant, so the
        # suite has no hidden ordering dependency: spec §8 only allows an
        # import while the dataset is empty, and later cases must not be
        # surprised by rows an earlier case pushed.
        self._clean_dataset()

    def _clean_dataset(self):
        """Put the shared tenant back to an empty, never-imported state.

        Spec §8 makes `/bootstrap/import` legal only while the tenant holds
        no business rows, so the import cases need a fixture-level reset of
        the rows the earlier mutation cases created. Only business rows,
        the change stream and the import markers are touched: tenants,
        users, devices and sessions survive untouched.
        """
        tenant = _state["tenant_id"]
        tables = ("legacy_import_decisions", "legacy_import_records",
                  "legacy_import_jobs", "crm_devices", "customer_transactions",
                  "identities", "owners", "customers", "periods", "settings",
                  "change_log", "idempotency_keys")
        statements = ["SET FOREIGN_KEY_CHECKS = 0;"]
        statements += ["DELETE FROM `%s`.`%s` WHERE tenant_id = '%s';"
                       % (API_DB, table, tenant) for table in tables]
        statements.append(
            "UPDATE `%s`.tenant_state SET bootstrap_status = 'pending',"
            " dataset_epoch = 0, last_import_id = NULL,"
            " last_import_hash = NULL, source_installation_id = NULL,"
            " updated_at = UTC_TIMESTAMP() WHERE tenant_id = '%s';"
            % (API_DB, tenant))
        statements.append("SET FOREIGN_KEY_CHECKS = 1;")
        _run_sql("\n".join(statements))

    def _new_customer(self, legacy, name="Sample Customer", base=0,
                      record_id=None, token=None):
        return {
            "operation_id": str(uuid.uuid4()),
            "kind": "upsert",
            "entity": "customers",
            "id": record_id or str(uuid.uuid4()),
            "base_version": base,
            "record": {
                "id": legacy, "full_name": name, "address": "",
                "mobile": "09120000010", "telegram_id": "", "instagram_id": "",
                "notes": "", "created": None, "updated": None,
            },
        }

    # -- §6: envelope, health, errors -----------------------------------

    def test_health_live_is_liveness_only(self):
        status, payload, headers, text = _call("GET", "/health/live")
        self.assertEqual(status, 200)
        self.assertIs(payload.get("ok"), True)
        self.assertEqual(set(payload), {"ok", "time"},
                         "the health probe must return nothing else (§6)")
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertNotIn("access-control-allow-origin",
                         {k.lower() for k in headers})

    def test_error_envelope_and_code_grammar(self):
        status, error, _headers, _payload = _fail("POST", "/auth/login", {})
        self.assertEqual(status, 400)
        self.assertTrue(ERROR_CODE_RE.match(error["code"]),
                        "code %r breaks the §15.8 grammar" % error["code"])
        self.assertLessEqual(len(error["code"]), MAX_CODE_LENGTH)
        self.assertTrue(re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            error["request_id"]), "request_id must be a UUID")

        status, error, _h, _p = _fail("GET", "/no/such/route")
        self.assertEqual(status, 404)
        self.assertTrue(ERROR_CODE_RE.match(error["code"]))

        status, _payload, headers, _text = _call("POST", "/health/live", {})
        self.assertEqual(status, 405)
        self.assertNotIn("access-control-allow-origin",
                         {k.lower() for k in headers})

    def test_every_emitted_code_satisfies_the_grammar(self):
        result = _php_json(
            "echo json_encode(array_map(function ($c) {"
            " return array('code' => $c, 'ok' => Codes::isValid($c)); },"
            " Codes::ALL));")
        self.assertTrue(result)
        for entry in result:
            self.assertTrue(entry["ok"],
                            "code %r does not match the §15.8 grammar"
                            % entry["code"])
            self.assertLessEqual(len(entry["code"]), MAX_CODE_LENGTH)

    def test_uuid5_agrees_with_the_python_mapper(self):
        triples = [
            ("customers", "ab12cd34"),
            ("periods", "p-legacy"),
            ("settings", "settings/settings"),
            ("customer_transactions", "ab12cd34/7"),
        ]
        script = ("echo json_encode(array_map(function ($t) {"
                  " return Ids::uuid5(%s, $t[0], $t[1]); }, %s));"
                  % (json.dumps(_state["installation"]),
                     json.dumps([list(t) for t in triples])))
        produced = _php_json(script)
        for (entity, legacy), value in zip(triples, produced):
            self.assertEqual(value, _uuid5(entity, legacy),
                             "php and python disagree on uuid5 for %s" % entity)

    def test_https_gate_is_a_pure_function_of_header_and_address(self):
        cases = [
            (["https", "203.0.113.9", ""], True),
            (["", "203.0.113.9", ""], False),
            (["http", "203.0.113.9", ""], False),
            (["HTTPS", "203.0.113.9", ""], True),
            (["", "127.0.0.1", ""], True),
            (["", "127.4.5.6", ""], True),
            (["", "::1", ""], True),
            (["", "203.0.113.9", "on"], True),
            (["", "10.1.2.3", ""], False),
        ]
        script = ("echo json_encode(array_map(function ($c) {"
                  " return Request::isSecureTransport($c[0], $c[1], $c[2]); },"
                  " %s));" % json.dumps([list(c) for c, _ in cases]))
        produced = _php_json(script)
        for (args, expected), actual in zip(cases, produced):
            self.assertEqual(actual, expected,
                             "isSecureTransport%s should be %s"
                             % (tuple(args), expected))

    def test_legacy_migration_routes_are_default_off_admin_only_and_atomic(self):
        store = {
            "customers": [{
                "id": "legacy01", "full_name": "Legacy HTTP Customer",
                "address": "Old address", "mobile": "09121111111",
                "notes": "", "created": "2026-01-01 12:00:00",
                "transactions": [],
            }],
            "owners": [], "identities": [], "devices": [], "periods": [],
        }
        body = {
            "source_text": json.dumps(store, ensure_ascii=False,
                                      separators=(",", ":")),
            "filename": "crm_store.json", "source_version": "1.13.1",
        }
        admin = _login(_state["admin_user"], _state["admin_password"])

        # The endpoint exists but the migration window is closed by default.
        status, error, _h, _p = _fail(
            "POST", "/legacy-import/analyze", body,
            token=admin["access_token"])
        self.assertEqual((status, error["code"]), (403, "PERMISSION_DENIED"))

        path = _state["config_path"]
        with open(path, "r", encoding="utf-8") as handle:
            original = handle.read()
        enabled = original.replace(
            "'legacy_import_enabled' => false,",
            "'legacy_import_enabled' => true,", 1)
        self.assertNotEqual(original, enabled, "fixture did not expose the migration switch")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(enabled)
        try:
            member = _login(_state["user_user"], _state["user_password"])
            status, error, _h, _p = _fail(
                "POST", "/legacy-import/analyze", body,
                token=member["access_token"])
            # Roles::requireImport uses the host's established role-matrix code.
            self.assertEqual((status, error["code"]),
                             (403, "ROLE_FORBIDDEN"))

            analyzed, _h = _ok(
                "POST", "/legacy-import/analyze", body,
                token=admin["access_token"])
            self.assertEqual(analyzed["job"]["status"], "ready")
            job_id = analyzed["job"]["id"]

            reviewed, _h = _ok(
                "GET", "/legacy-import/review?job_id=" + job_id,
                token=admin["access_token"])
            self.assertEqual(reviewed["unresolved"], 0)
            self.assertEqual(reviewed["counts"]["create"], 1)

            applied, _h = _ok(
                "POST", "/legacy-import/apply", {"job_id": job_id},
                token=admin["access_token"])
            self.assertEqual(applied["status"], "applied")
            self.assertEqual(applied["counts"]["created"], 1)
            self.assertEqual(_sql_value(
                "SELECT COUNT(*) FROM customers WHERE tenant_id='%s';"
                % _state["tenant_id"]), "1")

            # Replay is a no-op and the staged source was never stored raw.
            replay, _h = _ok(
                "POST", "/legacy-import/apply", {"job_id": job_id},
                token=admin["access_token"])
            self.assertTrue(replay["replayed"])
            self.assertEqual(_sql_value(
                "SELECT COUNT(*) FROM customers WHERE tenant_id='%s';"
                % _state["tenant_id"]), "1")
        finally:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(original)

    # -- §5: login, rate limiting, refresh, enrolment --------------------

    def test_login_success_and_failure(self):
        payload = _login(_state["admin_user"], _state["admin_password"])
        for field in ("access_token", "refresh_token", "expires_in"):
            self.assertIn(field, payload)
        self.assertIsInstance(payload["expires_in"], int)
        self.assertIn("must_change_password", payload)
        self.assertIn("role", payload["user"])
        self.assertEqual(payload["user"]["role"], "admin")

        status, error, _h, _p = _fail("POST", "/auth/login", {
            "username": _state["admin_user"], "password": "wrong-password"})
        self.assertEqual(status, 401)
        self.assertEqual(error["code"], "AUTH_REQUIRED")

        status, error, _h, _p = _fail("POST", "/auth/login", {
            "username": "no-such-account", "password": "whatever"})
        self.assertEqual(status, 401)
        # An unknown account and a wrong password must be indistinguishable.
        self.assertEqual(error["code"], "AUTH_REQUIRED")

    def test_rate_limit_locks_then_releases(self):
        probe = "ratelimit-probe"
        for _ in range(3):
            status, _error, _h, _p = _fail("POST", "/auth/login", {
                "username": probe, "password": "nope"})
            self.assertEqual(status, 401)
        status, error, headers, _p = _fail("POST", "/auth/login", {
            "username": probe, "password": "nope"})
        self.assertEqual(status, 429, "the limiter did not lock")
        self.assertEqual(error["code"], "RATE_LIMITED")
        self.assertIn("Retry-After", headers)
        self.assertTrue(int(headers["Retry-After"]) >= 1)

        # Temporarily locked, then RELEASED — and never permanently: after the
        # window the real account still logs in (spec §10.5: no permanent
        # lockout, that would be a DoS weapon).
        time.sleep(3.0)
        status, _error, _h, _p = _fail("POST", "/auth/login", {
            "username": probe, "password": "nope"})
        self.assertEqual(status, 401, "the temporary lock did not expire")

        payload = _login(_state["admin_user"], _state["admin_password"])
        self.assertIn("access_token", payload)

    def test_refresh_rotates_and_reuse_kills_the_family(self):
        first = _login(_state["admin_user"], _state["admin_password"])
        rotated, _h = _ok("POST", "/auth/refresh", {
            "refresh_token": first["refresh_token"], "kind": "user"})
        self.assertNotEqual(rotated["refresh_token"], first["refresh_token"],
                            "the refresh token must rotate (§5)")
        self.assertIn("access_token", rotated)

        # Replay of the consumed token: the whole family dies.
        status, error, _h, _p = _fail("POST", "/auth/refresh", {
            "refresh_token": first["refresh_token"], "kind": "user"})
        self.assertEqual(status, 401)
        self.assertEqual(error["code"], "AUTH_REVOKED")

        # The rotated token is in the same family, so it is dead too.
        status, error, _h, _p = _fail("POST", "/auth/refresh", {
            "refresh_token": rotated["refresh_token"], "kind": "user"})
        self.assertEqual(status, 401)
        self.assertEqual(error["code"], "AUTH_REVOKED")

        # …and the access tokens of that family stop working immediately.
        status, _payload, _headers, _text = _call(
            "POST", "/auth/logout", {}, token=rotated["access_token"])
        self.assertEqual(status, 401)

    def test_logout_revokes_the_family(self):
        login = _login(_state["admin_user"], _state["admin_password"])
        _ok("POST", "/auth/logout", {}, token=login["access_token"])
        status, _payload, _h, _t = _call(
            "POST", "/sync-devices/enroll", {}, token=login["access_token"])
        self.assertEqual(status, 401, "logout must revoke the family (§5)")

    def test_refresh_rejects_a_wrong_kind(self):
        login = _login(_state["admin_user"], _state["admin_password"])
        status, error, _h, _p = _fail("POST", "/auth/refresh", {
            "refresh_token": login["refresh_token"], "kind": "device"})
        self.assertEqual(status, 401)

    def test_enrolment_needs_the_device_enroll_permission(self):
        # A non-admin user token may not enrol (§7).
        member = _user_token()
        status, error, _h, _p = _fail("POST", "/sync-devices/enroll", {},
                                      token=member)
        self.assertEqual(status, 403)
        self.assertEqual(error["code"], "ROLE_FORBIDDEN")

        # No token at all.
        status, _payload, _h, _t = _call("POST", "/sync-devices/enroll", {})
        self.assertEqual(status, 401)

        # A device token is the wrong credential family.
        status, _payload, _h, _t = _call("POST", "/sync-devices/enroll", {},
                                         token=_device_token())
        self.assertEqual(status, 401)

        # An admin user token does enrol.
        admin = _login(_state["admin_user"], _state["admin_password"])
        payload, _h = _ok("POST", "/sync-devices/enroll", {"name": "laptop"},
                          token=admin["access_token"])
        for field in ("sync_device_id", "device_refresh_token"):
            self.assertIn(field, payload)
        self.assertTrue(re.match(
            r"^[0-9a-f-]{36}$", payload["sync_device_id"]))

    def test_revoking_a_device_stops_its_in_flight_token(self):
        token, device_id = _enroll()
        _ok("GET", "/sync/bootstrap", token=token)
        _run_sql("UPDATE `%s`.sync_devices SET status = 'revoked'"
                 " WHERE id = '%s';" % (API_DB, device_id))
        status, payload, _h, _t = _call("GET", "/sync/bootstrap", token=token)
        self.assertEqual(status, 401)
        self.assertIn(payload["error"]["code"], ("AUTH_REVOKED", "AUTH_REQUIRED"))
        _run_sql("UPDATE `%s`.sync_devices SET status = 'active'"
                 " WHERE id = '%s';" % (API_DB, device_id))

    def test_bumping_token_version_stops_the_token(self):
        token, device_id = _enroll()
        _ok("GET", "/sync/bootstrap", token=token)
        _run_sql("UPDATE `%s`.sync_devices SET token_version = token_version + 1"
                 " WHERE id = '%s';" % (API_DB, device_id))
        status, payload, _h, _t = _call("GET", "/sync/bootstrap", token=token)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "AUTH_REVOKED")

    # -- §6.2: bootstrap and changes -------------------------------------

    def test_bootstrap_returns_snapshot_and_cursor_from_one_transaction(self):
        payload, _h = _ok("GET", "/sync/bootstrap", token=_device_token())
        self.assertIsInstance(payload["collections"], dict)
        for entity in ENTITIES:
            self.assertIn(entity, payload["collections"])
        self.assertIsInstance(payload["cursor"], int)
        self.assertGreaterEqual(payload["cursor"], 0)
        self.assertIsInstance(payload["dataset_epoch"], int)
        self.assertEqual(payload["tenant_id"], _state["tenant_id"])
        for entity, rows in payload["collections"].items():
            for row in rows:
                self.assertEqual(
                    set(row), {"id", "tenant_id", "row_version", "record"})
                self.assertEqual(row["tenant_id"], _state["tenant_id"])
                self.assertIsInstance(row["row_version"], int)
                self.assertIsInstance(row["record"], dict)

    def test_bootstrap_cursor_then_changes_is_consistent(self):
        device = _device_token()
        bootstrap, _h = _ok("GET", "/sync/bootstrap", token=device)
        cursor = bootstrap["cursor"]

        page, _h = _ok("GET", "/sync/changes?cursor=%d&limit=50" % cursor,
                       token=device)
        self.assertEqual(page["changes"], [])
        self.assertFalse(page["has_more"])
        self.assertEqual(page["cursor"], cursor)

        operation = self._new_customer("cursorprobe")
        result = self._push([operation])
        self.assertEqual(result["applied"], [operation["operation_id"]])

        page, _h = _ok("GET", "/sync/changes?cursor=%d&limit=50" % cursor,
                       token=device)
        self.assertEqual(len(page["changes"]), 1)
        change = page["changes"][0]
        self.assertEqual(change["entity"], "customers")
        self.assertEqual(change["id"], operation["id"])
        self.assertGreater(change["seq"], cursor)
        self.assertEqual(change["record"]["id"], "cursorprobe")
        self.assertFalse(page["has_more"])

        # Re-pulling from the new cursor yields nothing twice (no double read).
        after, _h = _ok("GET", "/sync/changes?cursor=%d&limit=50"
                        % page["cursor"], token=device)
        self.assertEqual(after["changes"], [])

    def test_changes_pages_with_has_more_and_reports_tombstones(self):
        device = _device_token()
        start, _h = _ok("GET", "/sync/bootstrap", token=device)
        cursor = start["cursor"]

        operations = [self._new_customer("page%02d" % index, base=0)
                      for index in range(3)]
        result = self._push(operations)
        self.assertEqual(len(result["applied"]), 3)
        self.assertGreater(result["cursor"], cursor)

        first, _h = _ok("GET", "/sync/changes?cursor=%d&limit=2" % cursor,
                        token=device)
        self.assertEqual(len(first["changes"]), 2)
        self.assertTrue(first["has_more"], "limit must be honoured (§6.2)")
        self.assertEqual(first["cursor"], first["changes"][1]["seq"])

        rest, _h = _ok("GET", "/sync/changes?cursor=%d&limit=2"
                       % first["cursor"], token=device)
        self.assertEqual(len(rest["changes"]), 1)
        self.assertFalse(rest["has_more"])

        # Tombstone: a delete propagates as record: null (§6.1).
        before = rest["cursor"]
        delete = {
            "operation_id": str(uuid.uuid4()), "kind": "delete",
            "entity": "customers", "id": operations[2]["id"], "base_version": 1,
        }
        deleted = self._push([delete])
        self.assertEqual(deleted["applied"], [delete["operation_id"]])
        page, _h = _ok("GET", "/sync/changes?cursor=%d&limit=10" % before,
                       token=device)
        self.assertEqual(len(page["changes"]), 1)
        self.assertIsNone(page["changes"][0]["record"],
                          "a delete must arrive as record: null")

        # …and the snapshot no longer carries it either.
        after, _h = _ok("GET", "/sync/bootstrap", token=device)
        ids = [row["id"] for row in after["collections"]["customers"]]
        self.assertNotIn(operations[2]["id"], ids)

    def test_changes_rejects_a_malformed_cursor(self):
        for query in ("cursor=-1", "cursor=abc", "limit=0", "limit=99999"):
            status, error, _h, _p = _fail(
                "GET", "/sync/changes?%s" % query, token=_device_token())
            self.assertEqual(status, 400, query)
            self.assertTrue(ERROR_CODE_RE.match(error["code"]))

    # -- §6.1: mutations -------------------------------------------------

    def test_mutations_apply_then_replay_idempotently(self):
        operation = self._new_customer("idemprobe")
        first = self._push([operation])
        self.assertEqual(first["applied"], [operation["operation_id"]])
        self.assertEqual(first["conflicts"], [])
        self.assertIsInstance(first["cursor"], int)

        second = self._push([operation])
        self.assertEqual(second["applied"], [operation["operation_id"]],
                         "the same operation_id must return its first result")
        self.assertEqual(second["conflicts"], [])

        # Proof it was written once: the row is still at version 1 and appears
        # exactly once in the snapshot.
        bootstrap, _h = _ok("GET", "/sync/bootstrap", token=_device_token())
        matches = [row for row in bootstrap["collections"]["customers"]
                   if row["id"] == operation["id"]]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["row_version"], 1)
        self.assertEqual(matches[0]["record"]["id"], "idemprobe")

    def test_conflicts_are_data_and_do_not_abort_the_batch(self):
        created = self._new_customer("conflictprobe")
        self.assertEqual(self._push([created])["applied"],
                         [created["operation_id"]])

        stale = self._new_customer("conflictprobe", base=0,
                                   record_id=created["id"])
        fresh = self._new_customer("conflictprobe-late")
        result = self._push([stale, fresh])

        self.assertIn(fresh["operation_id"], result["applied"],
                      "an untouched operation must still apply (§6.1)")
        self.assertEqual(len(result["conflicts"]), 1)
        conflict = result["conflicts"][0]
        self.assertEqual(conflict["operation_id"], stale["operation_id"])
        self.assertEqual(conflict["entity"], "customers")
        self.assertEqual(conflict["id"], created["id"])
        self.assertEqual(conflict["server_version"], 1)
        self.assertIsInstance(conflict["server_record"], dict)
        self.assertEqual(conflict["server_record"]["id"], "conflictprobe")

    def test_stale_base_version_and_unknown_rows_are_conflicts(self):
        # A row this tenant has never seen with base_version >= 1 answers
        # server_version 0 / server_record null — a conflict, not a 4xx.
        unknown = self._new_customer("neverseen", base=4)
        result = self._push([unknown])
        self.assertEqual(result["applied"], [])
        self.assertEqual(result["conflicts"][0]["server_version"], 0)
        self.assertIsNone(result["conflicts"][0]["server_record"])

        # A genuinely stale base version on a live row reports the server copy.
        created = self._new_customer("staleprobe")
        self._push([created])
        stale = self._new_customer("staleprobe", base=0, record_id=created["id"])
        result = self._push([stale])
        self.assertEqual(result["applied"], [])
        self.assertEqual(result["conflicts"][0]["server_version"], 1)
        self.assertEqual(result["conflicts"][0]["server_record"]["id"],
                         "staleprobe")

        # A correctly versioned update does apply and bumps the version.
        update = self._new_customer("staleprobe", name="Renamed",
                                    base=1, record_id=created["id"])
        result = self._push([update])
        self.assertEqual(result["applied"], [update["operation_id"]])
        bootstrap, _h = _ok("GET", "/sync/bootstrap", token=_device_token())
        row = [r for r in bootstrap["collections"]["customers"]
               if r["id"] == created["id"]][0]
        self.assertEqual(row["row_version"], 2)
        self.assertEqual(row["record"]["full_name"], "Renamed")

    def test_cross_tenant_id_answers_404_never_403(self):
        other_tenant = str(uuid.uuid4())
        foreign = str(uuid.uuid4())
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        _run_sql(
            "INSERT INTO `%s`.tenants (id, slug, name, status, created_at,"
            " updated_at) VALUES ('%s', 'other-tenant', 'Other', 'active',"
            " '%s', '%s');" % (API_DB, other_tenant, now, now))
        _run_sql(
            "INSERT INTO `%s`.customers (id, tenant_id, legacy_id,"
            " row_version, created_at, updated_at, full_name)"
            " VALUES ('%s', '%s', 'foreign01', 1, '%s', '%s',"
            " 'Foreign Customer');" % (API_DB, foreign, other_tenant, now, now))

        operation = {
            "operation_id": str(uuid.uuid4()), "kind": "upsert",
            "entity": "customers", "id": foreign, "base_version": 0,
            "record": {"id": "foreign01", "full_name": "Attempted Takeover",
                       "address": "", "mobile": "09120000099",
                       "telegram_id": "", "instagram_id": "", "notes": "",
                       "created": None, "updated": None},
        }
        status, payload, _headers, text = _call(
            "POST", "/sync/mutations", {"operations": [operation]},
            token=_device_token())
        self.assertEqual(status, 404,
                         "a foreign id must answer 404, not 403: %s"
                         % text[:300])
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")

        # The foreign row is untouched.
        owner = _sql_value("SELECT tenant_id FROM `%s`.customers"
                           " WHERE id = '%s';" % (API_DB, foreign))
        self.assertEqual(owner, other_tenant)

    def test_mutations_require_a_device_token(self):
        operation = self._new_customer("unauthorized")
        status, _payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [operation]})
        self.assertEqual(status, 401)
        status, _payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [operation]},
            token=_login(_state["admin_user"], _state["admin_password"])
            ["access_token"])
        self.assertEqual(status, 401, "a user token is not a device token")

    def test_mutations_reject_a_malformed_batch(self):
        cases = [
            {},
            {"operations": []},
            {"operations": ["not-an-object"]},
            {"operations": [{"operation_id": "nope", "kind": "upsert",
                             "entity": "customers",
                             "id": str(uuid.uuid4()), "base_version": 0,
                             "record": {}}]},
            {"operations": [{"operation_id": str(uuid.uuid4()),
                             "kind": "explode",
                             "entity": "customers",
                             "id": str(uuid.uuid4()), "base_version": 0,
                             "record": {}}]},
            {"operations": [{"operation_id": str(uuid.uuid4()),
                             "kind": "upsert", "entity": "not_an_entity",
                             "id": str(uuid.uuid4()), "base_version": 0,
                             "record": {}}]},
            {"operations": [{"operation_id": str(uuid.uuid4()),
                             "kind": "upsert", "entity": "customers",
                             "id": str(uuid.uuid4()), "base_version": -1,
                             "record": {}}]},
            {"operations": [{"operation_id": str(uuid.uuid4()),
                             "kind": "upsert", "entity": "customers",
                             "id": str(uuid.uuid4()), "base_version": 0}]},
        ]
        for case in cases:
            status, payload, _h, _t = _call(
                "POST", "/sync/mutations", case, token=_device_token())
            self.assertEqual(status, 400, "case %r was accepted" % case)
            self.assertTrue(ERROR_CODE_RE.match(payload["error"]["code"]))

    # -- §7: the role matrix --------------------------------------------

    def test_role_matrix_gates_settings_and_periods(self):
        device = _device_token()
        member = _user_token()
        admin = _login(_state["admin_user"], _state["admin_password"])[
            "access_token"]

        settings_op = {
            "operation_id": str(uuid.uuid4()), "kind": "upsert",
            "entity": "settings",
            "id": _uuid5("settings", "settings/settings"), "base_version": 0,
            "record": {"id": _uuid5("settings", "settings/settings"),
                       "business_name": "Role Probe", "business_phone": "",
                       "watch_interval_hours": 2, "scheduler_enabled": True,
                       "auto_advance_default": False,
                       "telegram_report_full_data": True,
                       "registry_fee_amount": 1, "registration_chat_id": "",
                       "report_chat_id": "", "sound_enabled": True,
                       "current_period_id": None, "links": []},
        }
        period_op = {
            "operation_id": str(uuid.uuid4()), "kind": "upsert",
            "entity": "periods", "id": str(uuid.uuid4()), "base_version": 0,
            "record": {"id": "roleprb1", "number": 99,
                       "label": "Role Probe", "opened_at":
                       "2026-02-01T00:00:00+00:00", "opened_by": "admin",
                       "closed_at": None, "closed_by": "",
                       "closed_reason": ""},
        }
        plain = self._new_customer("roleprobe")

        # A non-admin acting user may not write settings or open a period.
        status, payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [settings_op]},
            token=device, acting=member)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "ROLE_FORBIDDEN")

        status, payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [period_op]},
            token=device, acting=member)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "ROLE_FORBIDDEN")

        # …but may write an ordinary case record.
        result = self._push([plain], acting=member)
        self.assertEqual(result["applied"], [plain["operation_id"]])

        # A non-admin may not delete either (§7: "delete records" is admin).
        delete = {"operation_id": str(uuid.uuid4()), "kind": "delete",
                  "entity": "customers", "id": plain["id"], "base_version": 1}
        status, payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [delete]},
            token=device, acting=member)
        self.assertEqual(status, 403)

        # An admin acting user may.
        result = self._push([settings_op], acting=admin)
        self.assertEqual(result["applied"], [settings_op["operation_id"]],
                         "an admin must be able to write settings")
        result = self._push([period_op], acting=admin)
        self.assertEqual(result["applied"], [period_op["operation_id"]])

        # A user access token alone is never a device credential.
        status, _payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [plain]}, token=member)
        self.assertEqual(status, 401)

    # -- §15.17: create-user.php (no HTTP user management) ---------------

    def _cli_user(self, prefix, role="user", password=None):
        """Create an account with the package's CLI; return (name, secret)."""
        username = "%s-%s" % (prefix, uuid.uuid4().hex[:10])
        password = password or (prefix.capitalize() + "-"
                                + secrets.token_urlsafe(14))
        # Registered before the run so no assertion message can echo it.
        _passwords.add(password)
        args = ["--username=" + username, "--role=" + role]
        out, err, code = _run_bin("create-user.php", args=args,
                                  env={"IRICA_USER_PASSWORD": password},
                                  expect_ok=False)
        self.assertEqual(code, 0, _redact(out + err))
        # A password handed in on the command line is never printed back,
        # and no hash ever leaves the process (§10.1, §15.17).
        self.assertNotIn("PASSWORD (shown once", out)
        for marker in ("$argon2", "$2y$", "$pbkdf2", "password_hash"):
            self.assertNotIn(marker, out + err)
        return username, password

    def test_create_user_cli_account_obeys_the_role_matrix(self):
        """§7 for an account only the CLI could create (§15.17)."""
        username, password = self._cli_user("cli")
        device = _device_token()

        # The account exists and its role comes from the membership row.
        login = _login(username, password)
        self.assertEqual(login["user"]["username"], username)
        self.assertEqual(login["user"]["role"], "user")
        self.assertIs(login["must_change_password"], True)
        member = login["access_token"]

        # §7 rows 1 and 4 — read all synced data, read `settings`. Sync
        # reads are device-credential routes (§6), so a user token alone
        # is refused as a missing credential (401), never as a role
        # refusal: no read in this package is gated on the role.
        status, payload, _h, _t = _call("GET", "/sync/bootstrap", token=member)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "AUTH_REQUIRED")

        # §7 row 2 — the colleague may create a case record …
        record = self._new_customer("clirole")
        result = self._push([record], acting=member)
        self.assertEqual(result["applied"], [record["operation_id"]])

        # … and the admin may write the settings row (row 5, admin column).
        admin = _login(_state["admin_user"], _state["admin_password"])[
            "access_token"]
        settings_op = {
            "operation_id": str(uuid.uuid4()), "kind": "upsert",
            "entity": "settings", "id": _uuid5("settings", "settings/settings"),
            "base_version": 0,
            "record": {"id": _uuid5("settings", "settings/settings"),
                       "business_name": "CLI Role Probe", "business_phone": "",
                       "watch_interval_hours": 2, "scheduler_enabled": True,
                       "auto_advance_default": False,
                       "telegram_report_full_data": True,
                       "registry_fee_amount": 1, "registration_chat_id": "",
                       "report_chat_id": "", "sound_enabled": True,
                       "current_period_id": None, "links": []},
        }
        result = self._push([settings_op], acting=admin)
        self.assertEqual(result["applied"], [settings_op["operation_id"]])

        # Both reads answer on this machine while this user acts.
        snapshot, _h = _ok("GET", "/sync/bootstrap", token=device,
                           acting=member)
        self.assertEqual(len(snapshot["collections"]["customers"]), 1)
        self.assertEqual(
            snapshot["collections"]["customers"][0]["record"]["id"], "clirole")
        self.assertEqual(len(snapshot["collections"]["settings"]), 1)
        page, _h = _ok("GET", "/sync/changes?cursor=0&limit=50", token=device,
                       acting=member)
        self.assertIn("changes", page)

        # §7 row 5 — the same colleague may not write settings.
        deny = dict(settings_op, operation_id=str(uuid.uuid4()))
        status, payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [deny]},
            token=device, acting=member)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "ROLE_FORBIDDEN")

        # §7 row 3 — no opening a period, no deleting a record.
        period_op = {
            "operation_id": str(uuid.uuid4()), "kind": "upsert",
            "entity": "periods", "id": str(uuid.uuid4()), "base_version": 0,
            "record": {"id": "cliusrpr1", "number": 98,
                       "label": "CLI Role Probe", "opened_at":
                       "2026-02-01T00:00:00+00:00", "opened_by": "admin",
                       "closed_at": None, "closed_by": "",
                       "closed_reason": ""},
        }
        status, payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [period_op]},
            token=device, acting=member)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "ROLE_FORBIDDEN")

        delete = {"operation_id": str(uuid.uuid4()), "kind": "delete",
                  "entity": "customers", "id": record["id"], "base_version": 1}
        status, payload, _h, _t = _call(
            "POST", "/sync/mutations", {"operations": [delete]},
            token=device, acting=member)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "ROLE_FORBIDDEN")

        # §7 row 6 — enrolling a machine and running the import are admin.
        status, payload, _h, _t = _call("POST", "/sync-devices/enroll", {},
                                        token=member)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "ROLE_FORBIDDEN")

        status, payload, _h, _t = _call("POST", "/bootstrap/import",
                                        self._import_document("clirole"),
                                        token=device, acting=member)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "ROLE_FORBIDDEN")

    def test_create_user_cli_refuses_a_duplicate_username(self):
        """§15.17 — a duplicate is a refusal (exit 1) that writes nothing."""
        username, password = self._cli_user("dup")
        before = int(_sql_value("SELECT COUNT(*) FROM users;"))

        out, err, code = _run_bin("create-user.php",
                                  args=["--username=" + username],
                                  env={"IRICA_USER_PASSWORD": password},
                                  expect_ok=False)
        self.assertEqual(code, 1, _redact(out + err))
        self.assertIn("already exists", (out + err).lower())
        self.assertEqual(int(_sql_value("SELECT COUNT(*) FROM users;")), before,
                         "a refused duplicate must not create an account")

        # The first administrator is a duplicate too: create-user never
        # replaces or re-runs create-admin (§15.17, §8.1).
        out, err, code = _run_bin(
            "create-user.php", args=["--username=" + _state["admin_user"]],
            env={"IRICA_USER_PASSWORD": password}, expect_ok=False)
        self.assertEqual(code, 1, _redact(out + err))
        self.assertIn("already exists", (out + err).lower())
        self.assertEqual(int(_sql_value("SELECT COUNT(*) FROM users;")), before,
                         "an admin username must not be taken over")

    def test_create_user_cli_generates_and_prints_the_password_once(self):
        """§15.17 / §10.1 — no seed, no hash, one printing, then it works."""
        username = "gen-%s" % uuid.uuid4().hex[:10]
        # Pinned so a stray IRICA_USER_PASSWORD cannot turn this run into a
        # supplied-password run; an empty value is "absent" to the script.
        out, err, code = _run_bin("create-user.php",
                                  args=["--username=" + username, "--quiet"],
                                  env={"IRICA_USER_PASSWORD": ""},
                                  expect_ok=False)
        match = re.search(r"PASSWORD \(shown once[^)]*\):\n  (\S+)\n", out)
        password = match.group(1) if match else ""
        if password:
            # From here on every assertion message is redacted.
            _passwords.add(password)
        self.assertEqual(code, 0, _redact(out + err))
        self.assertIsNotNone(match, _redact(out + err))

        self.assertEqual(out.count("PASSWORD (shown once"), 1)
        self.assertEqual(out.count(password), 1,
                         "the generated password must be printed exactly once")
        self.assertNotIn(password, err)
        # Nothing that could be used to recover the stored credential.
        for marker in ("$argon2", "$2y$", "$pbkdf2", "password_hash"):
            self.assertNotIn(marker, out + err)
        # --quiet prints only the outcome, never the account's metadata.
        self.assertTrue(out.startswith("OK    user created"))
        self.assertNotIn("user id:", out)
        self.assertGreaterEqual(len(password), 12)
        self.assertRegex(password, r"^[A-Za-z0-9_-]+$")

        # The printed value really is the credential of that account.
        login = _login(username, password)
        self.assertEqual(login["user"]["username"], username)
        self.assertEqual(login["user"]["role"], "user")

    # -- §8: bootstrap / import ------------------------------------------

    def test_import_is_idempotent_then_refuses_a_second_one(self):
        device = _device_token()
        admin = _login(_state["admin_user"], _state["admin_password"])[
            "access_token"]
        document = self._import_document("a")

        first, _h = _ok("POST", "/bootstrap/import", document,
                        token=device, acting=admin)
        self.assertEqual(first["dataset_epoch"], 1)
        self.assertGreater(first["rows"], 0)
        self.assertEqual(first["source_installation_id"],
                         _state["installation"])
        for entity in ("periods", "customers", "owners", "identities",
                       "crm_devices", "customer_transactions", "settings"):
            self.assertEqual(first["counts"][entity], 1, entity)

        # The same import_id with the same payload replays the same result.
        replay, _h = _ok("POST", "/bootstrap/import", document,
                         token=device, acting=admin)
        self.assertEqual(replay, first, "an import must replay byte for byte")

        # The same import_id with a different payload is a 409, not a merge.
        altered = json.loads(json.dumps(document))
        altered["collections"]["customers"][0]["full_name"] = "Different"
        status, payload, _h, _t = _call("POST", "/bootstrap/import", altered,
                                        token=device, acting=admin)
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "IMPORT_CONFLICT")

        # Any further import is refused: the tenant already holds data.
        second = self._import_document("b")
        status, payload, _h, _t = _call("POST", "/bootstrap/import", second,
                                        token=device, acting=admin)
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "DATASET_NOT_EMPTY")

        # provenance is recorded (spec §8.3)
        stored = _sql_value("SELECT source_installation_id FROM `%s`"
                            ".tenant_state WHERE tenant_id = '%s';"
                            % (API_DB, _state["tenant_id"]))
        self.assertEqual(stored, _state["installation"])
        status = _sql_value("SELECT bootstrap_status FROM `%s`.tenant_state"
                            " WHERE tenant_id = '%s';"
                            % (API_DB, _state["tenant_id"]))
        self.assertEqual(status, "done")

    def test_import_needs_an_admin_user_and_a_device(self):
        device = _device_token()
        member = _user_token()
        admin = _login(_state["admin_user"], _state["admin_password"])[
            "access_token"]
        document = self._import_document("auth")

        # No acting user at all.
        status, payload, _h, _t = _call("POST", "/bootstrap/import", document,
                                        token=device)
        self.assertEqual(status, 401)

        # A non-admin acting user.
        status, payload, _h, _t = _call("POST", "/bootstrap/import", document,
                                        token=device, acting=member)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "ROLE_FORBIDDEN")

        # No device.
        status, _payload, _h, _t = _call("POST", "/bootstrap/import", document,
                                         acting=admin)
        self.assertEqual(status, 401)

    def test_import_reference_columns_arrive_as_uuids(self):
        """The mapper emits UUID foreign keys; the host never resolves them."""
        device = _device_token()
        admin = _login(_state["admin_user"], _state["admin_password"])[
            "access_token"]
        document = self._import_document("uuidrefs")
        # An 8-hex legacy id in a reference column must be refused: the host
        # only ever stores what the client's mapper produced (§15.1).
        document["collections"]["crm_devices"][0]["customer_id"] = "ab12cd34"
        status, payload, _h, _t = _call("POST", "/bootstrap/import", document,
                                        token=device, acting=admin)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "VALIDATION_FAILED")

    # -- §10: security posture --------------------------------------------

    def test_app_account_cannot_create(self):
        stdout, stderr = _php(
            "$db = Database::fromConfig(Config::db());\n"
            "$denied = false;\n"
            "try { $db->execute('CREATE TABLE zz_api_probe (id INT)'); }\n"
            "catch (Throwable $e) { $denied = true; }\n"
            "if (!$denied) {\n"
            "  try { $db->execute('DROP TABLE zz_api_probe'); }\n"
            "  catch (Throwable $e) {}\n"
            "}\n"
            "echo json_encode(['denied' => $denied,\n"
            "  'version' => $db->serverVersion() !== '',\n"
            "  'tz' => $db->sessionTimeZone()]);")
        result = json.loads(stdout.strip())
        self.assertTrue(result["denied"],
                        "the application account was allowed to run DDL (§2)")
        self.assertTrue(result["version"])
        self.assertEqual(result["tz"], "+00:00")
        self.assertNotIn(_state["app_password"], stdout + stderr)
        self.assertNotIn(_environment_cache["root"], stdout + stderr)

    def test_no_access_control_allow_origin_anywhere(self):
        probes = [
            ("GET", "/health/live", None, None),
            ("POST", "/auth/login", {"username": "x", "password": "y"}, None),
            ("GET", "/sync/bootstrap", None, _device_token()),
            ("GET", "/nope", None, None),
        ]
        for method, path, body, token in probes:
            _status, _payload, headers, _text = _call(method, path, body,
                                                      token=token)
            lowered = {key.lower() for key in headers}
            self.assertNotIn("access-control-allow-origin", lowered,
                             "%s %s leaked a CORS header" % (method, path))
            self.assertNotIn("access-control-allow-credentials", lowered)

        source = open(INDEX_PHP, encoding="utf-8").read()
        self.assertNotIn("Access-Control-Allow-Origin", source)
        self.assertIn("Access-Control-Allow-Origin", open(
            HTACCESS, encoding="utf-8").read(),
            ".htaccess must actively strip any CORS header (§10.7)")

    def test_oversized_body_is_refused(self):
        blob = b'{"pad":"' + (b"x" * (1048576 + 512)) + b'"}'
        status, payload, _h, _text = _call(
            "POST", "/sync/mutations", raw=blob, token=_device_token())
        self.assertEqual(status, 413)
        self.assertTrue(ERROR_CODE_RE.match(payload["error"]["code"]))
        self.assertEqual(payload["error"]["code"], "PAYLOAD_TOO_LARGE")

    def test_non_json_body_is_refused(self):
        status, payload, _h, _text = _call(
            "POST", "/auth/login", raw=b"username=admin&password=x",
            content_type="application/x-www-form-urlencoded")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "UNSUPPORTED_MEDIA_TYPE")

        status, payload, _h, _text = _call(
            "POST", "/auth/login", raw=b"{not json",
            content_type="application/json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "BAD_PAYLOAD")

        status, payload, _h, _text = _call(
            "POST", "/auth/login", raw=b"[1,2,3]",
            content_type="application/json")
        self.assertEqual(status, 400)

    def test_no_pii_or_token_reaches_an_observable_log(self):
        canary_password = "Canary-" + secrets.token_urlsafe(16)
        canary_name = "Canary Customer " + secrets.token_hex(6)
        canary_national = "9" + secrets.token_hex(4)
        canary_phone = "0912000" + secrets.token_hex(2)  # exactly 11 digits
        _passwords.add(canary_password)

        status, payload, _h, _t = _call("POST", "/auth/login", {
            "username": _state["admin_user"], "password": canary_password})
        self.assertEqual(status, 401)

        token = _device_token()
        operation = self._new_customer("logprobe", name=canary_name)
        operation["record"]["mobile"] = canary_phone
        operation["record"]["notes"] = canary_national
        self._push([operation], token=token)
        _ok("GET", "/sync/bootstrap", token=token)
        _ok("POST", "/auth/refresh",
            {"refresh_token": _state["device_refresh"], "kind": "device"})
        login = _login(_state["admin_user"], _state["admin_password"])
        _ok("POST", "/sync-devices/enroll", {"name": "log-probe-device"},
            token=login["access_token"])

        observed = []
        for path in (_state["log_path"], _state["server_log"]):
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8", errors="replace") as handle:
                observed.append(handle.read())
        self.assertTrue(observed, "no log file was produced to inspect")

        # Force the access/refresh tokens and the record contents into the
        # requests above, then prove none of it was written anywhere.
        needles = [
            canary_password, canary_name, canary_national, canary_phone,
            login["access_token"], login["refresh_token"],
            _state["device_refresh"], _state["admin_password"],
            _state["user_password"], _state["app_password"],
            _environment_cache["root"],
        ]
        blob = "\n".join(observed)
        for needle in needles:
            if not needle:
                continue
            self.assertNotIn(needle, blob,
                             "a secret or PII value reached a log line")

        # audit_events stores metadata only — no record contents, no names.
        rows = _run_sql(
            "SELECT action, metadata FROM `%s`.audit_events;" % API_DB)[0]
        for needle in (canary_name, canary_national, canary_phone,
                       canary_password):
            self.assertNotIn(needle, rows,
                             "audit_events stored a PII value (§10.9)")

    # -- installables ------------------------------------------------------

    def test_smoke_test_passes_and_prints_no_credential(self):
        # Point the probe at the running server so the header checks run too.
        _run_sql("SELECT 1")  # keep the CLI warm; nothing else
        config = open(_state["config_path"], encoding="utf-8").read()
        probe = _state["base_url"] + "/health/live"
        patched = config.replace("'smoke_probe_url' => null,",
                                 "'smoke_probe_url' => %s," % json.dumps(probe))
        probe_path = os.path.join(_state["config_dir"], "probe_config.php")
        with open(probe_path, "w", encoding="utf-8") as handle:
            handle.write(patched)

        out, err, code = _run_bin("smoke-test.php", config=probe_path,
                                  expect_ok=False)
        text = out + err
        print("\n--- host/bin/smoke-test.php (against the running API) ---\n"
              "%s" % text)
        self.assertEqual(code, 0, "smoke-test reported failures:\n%s" % text)
        self.assertIn("Result: PASS", text)
        self.assertIn("refused DDL", text)
        for secret in (_state["app_password"], _environment_cache["root"],
                       _state["admin_password"], _state["user_password"]):
            self.assertNotIn(secret, text)

    def test_smoke_test_fails_without_a_configuration(self):
        missing = os.path.join(tempfile.gettempdir(),
                               "irica_no_such_config.php")
        out, _err, code = _run_bin("smoke-test.php", config=missing,
                                   expect_ok=False)
        self.assertNotEqual(code, 0)
        self.assertIn("Result: FAIL", out)

    def test_migrate_applies_once_then_skips_and_refuses_drift(self):
        scratch_config = os.path.join(_state["config_dir"], "migrate.php")
        with open(scratch_config, "w", encoding="utf-8") as handle:
            handle.write("""<?php
return [
    'env' => 'test', 'base_path' => '/v1', 'tenant_slug' => 'default',
    'db' => ['host' => '127.0.0.1', 'port' => %d, 'dbname' => '%s',
             'user' => 'root', 'password' => %s],
    'db_migrate' => ['host' => '127.0.0.1', 'port' => %d, 'dbname' => '%s',
             'user' => 'root', 'password' => %s],
    'jwt_secret' => '%s',
    'log_path' => null,
];
""" % (_environment_cache["port"], SCRATCH_DB,
       json.dumps(_environment_cache["root"]),
       _environment_cache["port"], SCRATCH_DB,
       json.dumps(_environment_cache["root"]), secrets.token_hex(32)))

        _run_sql("DROP DATABASE IF EXISTS `%s`;" % SCRATCH_DB,
                 expect_ok=False)
        _run_sql("CREATE DATABASE `%s` DEFAULT CHARACTER SET utf8mb4"
                 " COLLATE utf8mb4_unicode_ci;" % SCRATCH_DB)

        try:
            first, _err, code = _run_bin("migrate.php", config=scratch_config,
                                         expect_ok=False)
            self.assertEqual(code, 0, first)
            self.assertIn("APPLY 001_initial", first)
            migration_files = sorted(
                name for name in os.listdir(os.path.join(HOST_DIR, "migrations"))
                if name.endswith(".sql"))
            self.assertEqual(
                _sql_value("SELECT COUNT(*) FROM `%s`.schema_migrations;"
                           % SCRATCH_DB), str(len(migration_files)))
            for filename in migration_files:
                self.assertIn("APPLY " + os.path.splitext(filename)[0], first)

            # The recorded checksum for 001 must match that exact file.
            checksum = _sql_value(
                "SELECT checksum FROM `%s`.schema_migrations "
                "WHERE version='001_initial';" % SCRATCH_DB)
            with open(SCHEMA_SQL, "rb") as handle:
                import hashlib
                actual = hashlib.sha256(handle.read()).hexdigest()
            self.assertEqual(checksum, actual)

            # A second run is a no-op.
            second, _err, code = _run_bin("migrate.php",
                                          config=scratch_config,
                                          expect_ok=False)
            self.assertEqual(code, 0, second)
            # migrate.php column-aligns its labels: "APPLY " and "SKIP  ".
            self.assertIn("SKIP  001_initial", second)
            self.assertNotIn("APPLY", second)

            # A changed checksum is a hard refusal (forward-only, §10.10).
            _run_sql("UPDATE `%s`.schema_migrations SET checksum = '%s';"
                     % (SCRATCH_DB, "0" * 64))
            third, _err, code = _run_bin("migrate.php", config=scratch_config,
                                         expect_ok=False)
            self.assertNotEqual(code, 0,
                                "a drifted checksum must be refused")
            self.assertIn("checksum", (third + _err).lower())

            # Restoring the checksum still refuses: the tables are there and
            # the tracker row is not, which is the "not pristine" guard.
            _run_sql("UPDATE `%s`.schema_migrations SET checksum = '%s';"
                     % (SCRATCH_DB, actual))
            _run_sql("DELETE FROM `%s`.schema_migrations;" % SCRATCH_DB)
            fourth, _err, code = _run_bin("migrate.php",
                                          config=scratch_config,
                                          expect_ok=False)
            self.assertNotEqual(code, 0,
                                "a populated database without a tracker row "
                                "must be refused, never written into")
            self.assertIn("non-empty", (fourth + _err).lower())
        finally:
            _run_sql("DROP DATABASE IF EXISTS `%s`;" % SCRATCH_DB,
                     expect_ok=False)


if __name__ == "__main__":
    unittest.main()
