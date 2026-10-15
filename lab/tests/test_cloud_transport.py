# -*- coding: utf-8 -*-
"""Cloud sync transport, outbox, auth and config (workstream C-client).

Contract: `lab/docs/CLOUD_SYNC_SPEC.md` — §5 (auth protocol and storage),
§6 (HTTP contract and error envelope), §9 (outbox, retries, conflicts),
§11 (errors reach the UI as codes), §12 (offline tests only), §13.1 (local
verification environment), §15 rulings 7, 8, 9, 10 and 12.

Everything here runs offline against the loopback fake in
`lab/tests/_cloud_api_fake.py`, which is the executable copy of §6. The fake
is swappable in exactly one place: when `IRICA_TEST_API_BASE` is set the same
tests talk to that real base URL instead, and the scenarios that script faults
skip themselves.

What is pinned:

* bootstrap -> cursor resume across `has_more` pages, and across a restart;
* push applies, returns `conflicts[]` as **data**, and never raises for one;
* the same `operation_id` retried is never applied twice;
* retry only on 429/5xx/timeout/connection error — never on 400/403/409;
* backoff is bounded by the five-minute cap and honours `Retry-After`;
* 401 refreshes exactly once, retries once, then surfaces `AUTH_REQUIRED`;
* the outbox survives a simulated restart and raises `QUEUE_FULL` instead of
  ever truncating;
* every error code matches manager ruling 8's grammar;
* no token, no server message and no `Authorization` header reaches a log
  line, an exception message or a file in the data dir;
* an expired lease blocks the push before it reaches the socket;
* the state machine receives exactly one outcome or fault per attempt.

Run:
    "C:/Program Files/Python310/python.exe" lab/scripts/run_panel_tests.py test_cloud_transport
"""
import json
import logging
import os
import re
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _path in (_ROOT, _HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import requests  # noqa: E402

import _cloud_api_fake as fake_api  # noqa: E402
from cloud_sync.auth import (  # noqa: E402
    ACCESS_TTL_SECONDS, AUTH_FILE_NAME, DpapiSecretStore, MemorySecretStore,
    TokenVault, current_user_sid_string, read_acl_sids,
)
from cloud_sync.client import SyncClient, push_order  # noqa: E402
from cloud_sync.mapper import (  # noqa: E402 - read-only, workstream B
    REFERENCE_FIELDS, UnresolvedReferenceError,
)
from cloud_sync.outbox import _wrap_unexpected  # noqa: E402
from cloud_sync.config import (  # noqa: E402
    CloudConfig, CONFIG_FILE_NAME, LOOPBACK_HOSTS, load_config,
    normalize_api_base,
)
from cloud_sync.errors import (  # noqa: E402
    AuthRequiredError, AuthRevokedError, BadResponseError, CloudSyncError,
    ConfigError, HttpError, QueueFullError, RequestTimeoutError,
    SecretStoreError, UnreachableError, UnresolvedReferenceCloudError,
    CLIENT_ERROR_CODES,
    ERROR_CODE_RE, MAX_CODE_LENGTH, SERVER_ERROR, code_for_status,
    envelope_code, is_retryable, is_valid_code, parse_retry_after,
    AUTH_REQUIRED, AUTH_REVOKED, BAD_PAYLOAD, CONFIG_INVALID,
    HTTP_400, HTTP_403, HTTP_409, HTTP_429, HTTP_500, NET_TIMEOUT,
    NET_UNREACHABLE, QUEUE_FULL, SECRET_UNAVAILABLE, VERSION_CONFLICT,
    TRANSITION_NOT_LEGAL, UNRESOLVED_REFERENCE,
)
from cloud_sync.lease import LEASE_EXPIRED, LeaseExpiredError, OfflineLease  # noqa: E402
from cloud_sync.outbox import (  # noqa: E402
    OUTBOX_FILE_NAME, Outbox, OutboxWorker, RetryPolicy,
)
from cloud_sync.state import (  # noqa: E402
    ERROR_CODE_RE as STATE_CODE_RE, KNOWN_ERROR_CODES, MAX_CODE_LENGTH as
    STATE_MAX_CODE, IllegalTransitionError, SyncEvent, SyncState,
    SyncStateMachine,
)

import app_paths  # noqa: E402

#: Fixed clock: nothing here sleeps, and every boundary is exact.
CLOCK = 1_800_000_000

#: Every server error message carries this marker (the fake builds it in).
CANARY = fake_api.SERVER_MESSAGE_CANARY

#: Realistic-shaped but fake values that must never appear anywhere.
TOKEN_SAMPLES = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPxx",
    "fake-device-refresh-token-that-must-not-leak-0123456789abcdef",
    "Bearer fake-device-access-0123456789abcdef0123456789abcdef",
    "09123456789",
    "operator@example.com",
)
TOKEN_PATTERNS = (
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}"),            # a JWT segment
    re.compile(r"Bearer\s+\S+"),                    # an Authorization header
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+"),  # an e-mail
    re.compile(r"\b09\d{9}\b"),                     # an Iranian mobile
    re.compile(r"fake-[a-z]+-(access|refresh)-[0-9a-f]+"),  # our own tokens
)


def assert_no_secret(testcase, text, where):
    """`text` must contain none of the token/PII shapes, nor the canary."""
    testcase.assertNotIn(CANARY, text, "%s leaked the server message" % where)
    for sample in TOKEN_SAMPLES:
        testcase.assertNotIn(sample, text, "%s leaked a known secret" % where)
    for pattern in TOKEN_PATTERNS:
        testcase.assertIsNone(pattern.search(text),
                              "%s matched %s" % (where, pattern.pattern))


class _CaptureHandler(logging.Handler):
    """Keeps every record the transport logger produces, in memory."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    @property
    def texts(self):
        return [self.format(record) if self.formatter else record.getMessage()
                for record in self.records]


class DataDirCase(unittest.TestCase):
    """Base case: a throwaway data directory, never the operator's."""

    def setUp(self):
        super().setUp()
        self._dir = tempfile.TemporaryDirectory(prefix="irica_cloud_")
        self.addCleanup(self._dir.cleanup)
        self.data_dir = self._dir.name
        self._env = patch.dict(os.environ, {"IRICA_DATA_DIR": self.data_dir})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(app_paths.reset_cache)
        app_paths.reset_cache()

    def data_files(self):
        found = []
        for base, _dirs, names in os.walk(self.data_dir):
            found += [os.path.join(base, name) for name in names]
        return found

    def read_data_files(self):
        blobs = []
        for path in self.data_files():
            with open(path, "rb") as handle:
                blobs.append(handle.read())
        return blobs


class ApiCase(DataDirCase):
    """Base case for anything that talks to the fake API.

    Also traps the transport logger for the whole test: nothing reaches the
    console, and every line produced is available for the leak assertions.
    """

    def setUp(self):
        super().setUp()
        self.logger = logging.getLogger("irica.cloud_sync")
        self._old_level = self.logger.level
        self._old_propagate = self.logger.propagate
        self.capture = _CaptureHandler()
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.logger.addHandler(self.capture)
        self.addCleanup(self.logger.removeHandler, self.capture)
        self.addCleanup(self._restore_logger)

        self.handle = fake_api.start_api(self, needs_fake=True)
        self.api = self.handle.fake
        self.config = CloudConfig(
            api_base=self.handle.base_url, tenant_id=self.api.tenant_id,
            path=os.path.join(self.data_dir, CONFIG_FILE_NAME))
        self.clock = [float(CLOCK)]
        self.vault = TokenVault(store=MemorySecretStore(),
                                path=os.path.join(self.data_dir,
                                                  AUTH_FILE_NAME),
                                clock=lambda: self.clock[0])
        self.client = SyncClient(self.config, self.vault,
                                 clock=lambda: self.clock[0])

    def _restore_logger(self):
        self.logger.setLevel(self._old_level)
        self.logger.propagate = self._old_propagate

    # -- helpers --------------------------------------------------------
    def enrol(self):
        """Log in, enrol, then commit the initial authoritative snapshot."""
        self.client.login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        self.client.enroll()
        snapshot = self.client.bootstrap()
        self.client.commit_bootstrap(snapshot)
        self.user_token = self.vault.user_access_token
        return self.config.sync_device_id

    def warm(self):
        """Populate the device access token so the next 401 is a real one."""
        if not self.config.sync_device_id:
            self.enrol()
        snapshot = self.client.bootstrap()
        self.client.commit_bootstrap(snapshot)
        self.api.requests.clear()
        self.api.clear_faults()
        self.vault.clear_user()

    def new_machine(self):
        """A second client on the same files: what a restart looks like."""
        return SyncClient(
            load_config(path=self.config.path),
            TokenVault(store=self.vault.store, path=self.vault.path,
                       clock=lambda: self.clock[0]),
            clock=lambda: self.clock[0])

    def new_worker(self, *, policy=None, machine=None, lease=None):
        if machine is None:
            machine = SyncStateMachine()
            machine.apply(SyncEvent.ENROL)
        if lease is None:
            lease = OfflineLease(path=os.path.join(self.data_dir,
                                                    "lease.json"),
                                 clock=lambda: self.clock[0])
            lease.grant()
        outbox = Outbox(path=os.path.join(self.data_dir, OUTBOX_FILE_NAME),
                        clock=lambda: self.clock[0])
        worker = OutboxWorker(outbox, self.client, machine, lease,
                              policy=policy or RetryPolicy(
                                  base_delay=1.0, rng=lambda: 1.0),
                              clock=lambda: self.clock[0])
        worker.bind_auth()
        self.addCleanup(worker.unbind_auth, (None, None))
        return worker

    def all_log_text(self):
        return "\n".join(self.capture.texts)

    def known_tokens(self):
        """Every token this test has seen, for the leak assertions."""
        found = [self.user_token] if getattr(self, "user_token", None) else []
        found.append(self.api.device_access_token())
        found.append(self.api.device_refresh_token())
        return [token for token in found if token]


# =====================================================================
# Error codes (manager ruling 8)
# =====================================================================
class TestErrorCodes(unittest.TestCase):

    def test_grammar_is_exactly_the_ruling(self):
        self.assertEqual(ERROR_CODE_RE.pattern,
                         r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
        self.assertEqual(ERROR_CODE_RE, STATE_CODE_RE)
        self.assertEqual(MAX_CODE_LENGTH, 40)
        self.assertEqual(MAX_CODE_LENGTH, STATE_MAX_CODE)

    def test_every_client_code_matches_the_grammar(self):
        for code in sorted(CLIENT_ERROR_CODES):
            self.assertRegex(code, ERROR_CODE_RE, code)
            self.assertLessEqual(len(code), MAX_CODE_LENGTH, code)
            self.assertTrue(is_valid_code(code), code)

    def test_no_code_is_duplicated_by_accident(self):
        self.assertEqual(len(CLIENT_ERROR_CODES), len(set(CLIENT_ERROR_CODES)))

    def test_the_two_new_codes_are_valid_and_exported(self):
        for code in (UNRESOLVED_REFERENCE, TRANSITION_NOT_LEGAL):
            self.assertTrue(is_valid_code(code), code)
            self.assertLessEqual(len(code), MAX_CODE_LENGTH)
            self.assertIn(code, CLIENT_ERROR_CODES)

    def test_every_documented_client_code_exists_here(self):
        # workstream A documented which codes it expects the client to emit;
        # dropping one would leave the panel with nothing to translate (§11).
        self.assertEqual(set(), set(KNOWN_ERROR_CODES) - CLIENT_ERROR_CODES)

    def test_grammar_rejects_a_token_shaped_value(self):
        for bad in ("bad", "Lower_Case", "HTTP 500", "user@example.com",
                    "AUTH_REQUIRED; DROP", "A" * 41, "ECONNREFUSED", ""):
            self.assertFalse(is_valid_code(bad), bad)

    def test_status_mapping_never_invents_a_code(self):
        self.assertEqual(code_for_status(429), HTTP_429)
        self.assertEqual(code_for_status(503), HTTP_500)
        self.assertEqual(code_for_status(400), HTTP_400)
        self.assertEqual(code_for_status(403), HTTP_403)
        self.assertEqual(code_for_status(409), HTTP_409)
        self.assertEqual(code_for_status(418), "HTTP_ERROR")
        self.assertEqual(code_for_status(None), SERVER_ERROR)
        for status in (200, 301, 400, 403, 404, 409, 429, 500, 503, 599, 999):
            self.assertTrue(is_valid_code(code_for_status(status)))

    def test_envelope_code_drops_a_hostile_server_code(self):
        hostile = {"ok": False, "error": {"code": "user@example.com",
                                          "message": "leaked"}}
        self.assertEqual(envelope_code(hostile, 500), HTTP_500)
        unknown_but_legal = {"ok": False,
                             "error": {"code": "HOST_SAYS_WHAT",
                                       "message": "x"}}
        self.assertEqual(envelope_code(unknown_but_legal, 500),
                         "HOST_SAYS_WHAT")
        self.assertEqual(envelope_code({}, 404), "HTTP_404")


# =====================================================================
# Retry policy (spec §9)
# =====================================================================
class TestRetryPolicy(unittest.TestCase):

    def setUp(self):
        self.policy = RetryPolicy(base_delay=1.0, cap=300.0, jitter=0.5,
                                  rng=lambda: 1.0)

    @staticmethod
    def http(status, code):
        return HttpError(code=code, status=status, route="/sync/mutations")

    def test_only_timeout_connection_429_and_5xx_are_retryable(self):
        for error in (RequestTimeoutError(), UnreachableError(),
                      self.http(429, HTTP_429), self.http(500, HTTP_500),
                      self.http(503, HTTP_500), requests.Timeout(),
                      requests.ConnectionError()):
            self.assertTrue(is_retryable(error), repr(error))
            self.assertTrue(self.policy.should_retry(error, 1), repr(error))

    def test_400_403_and_409_are_never_retried(self):
        for error in (self.http(400, BAD_PAYLOAD),
                      self.http(403, HTTP_403),
                      self.http(409, HTTP_409),
                      self.http(404, "HTTP_404"),
                      requests.HTTPError(), ValueError("nope")):
            self.assertFalse(is_retryable(error), repr(error))
            self.assertFalse(self.policy.should_retry(error, 1), repr(error))

    def test_attempts_are_bounded(self):
        error = self.http(500, HTTP_500)
        for failures in range(1, self.policy.max_attempts):
            self.assertTrue(self.policy.should_retry(error, failures))
        self.assertFalse(self.policy.should_retry(error, self.policy.max_attempts))
        self.assertFalse(self.policy.should_retry(error, 10_000))

    def test_backoff_is_bounded_by_the_five_minute_cap(self):
        for failures in range(1, 60):
            delay = self.policy.delay(failures)
            self.assertGreaterEqual(delay, 0.0)
            self.assertLessEqual(delay, 300.0, failures)

    def test_backoff_grows_monotonically_before_the_cap(self):
        delays = [self.policy.delay(n) for n in range(1, 10)]
        self.assertEqual(delays, sorted(delays))
        self.assertEqual(delays[0], 1.0)
        self.assertEqual(delays[-1], 256.0)

    def test_jitter_stays_inside_the_bound(self):
        fast = RetryPolicy(base_delay=8.0, jitter=0.5, rng=lambda: 0.0)
        slow = RetryPolicy(base_delay=8.0, jitter=0.5, rng=lambda: 1.0)
        self.assertEqual(fast.delay(1), 4.0)
        self.assertEqual(slow.delay(1), 8.0)

    def test_retry_after_is_honoured_when_it_fits_the_cap(self):
        self.assertEqual(self.policy.delay(1, retry_after=42), 42.0)
        self.assertEqual(self.policy.delay(1, retry_after=120), 120.0)

    def test_retry_after_longer_than_the_cap_is_clamped(self):
        # Spec §9 caps this queue at five minutes; a longer server hint must
        # not strand every later change behind one 429.
        self.assertEqual(self.policy.delay(1, retry_after=3600), 300.0)

    def test_retry_after_never_returns_a_negative_or_nan_delay(self):
        self.assertEqual(self.policy.delay(1, retry_after=-5), 1.0)
        self.assertTrue(0 <= self.policy.delay(1, retry_after="nonsense") <= 300)

    def test_parse_retry_after_accepts_both_rfc_forms(self):
        self.assertEqual(parse_retry_after("42"), 42.0)
        self.assertEqual(parse_retry_after(7), 7.0)
        self.assertEqual(parse_retry_after("0"), 0.0)
        import email.utils
        import time as _time
        moment = email.utils.formatdate(_time.time() + 90, usegmt=True)
        parsed = parse_retry_after(moment)
        self.assertIsNotNone(parsed)
        self.assertAlmostEqual(parsed, 90.0, delta=3.0)

    def test_parse_retry_after_rejects_nonsense(self):
        for bad in (None, "", "   ", "-1", "nan", "inf", "yesterday",
                    "Wed, 99 Oct 209999:99:99 GMT", ["", "1"]):
            self.assertIsNone(parse_retry_after(bad), repr(bad))

    def test_invalid_policy_arguments_are_refused(self):
        for kwargs in ({"max_attempts": 0}, {"max_attempts": True},
                       {"base_delay": 0}, {"cap": 0.1},
                       {"jitter": 1.5}, {"jitter": -1}):
            with self.assertRaises(ValueError):
                RetryPolicy(**kwargs)
        with self.assertRaises(ValueError):
            self.policy.delay(0)
        with self.assertRaises(ValueError):
            self.policy.should_retry(self.http(500, HTTP_500), 0)


# =====================================================================
# Configuration (spec §4, §5)
# =====================================================================
class TestCloudConfig(DataDirCase):

    def test_https_is_accepted_and_normalised(self):
        self.assertEqual(normalize_api_base("https://api.example.com/v1/"),
                         "https://api.example.com/v1")
        self.assertEqual(normalize_api_base("https://API.Example.com"),
                         "https://API.Example.com")

    def test_plain_http_is_refused_off_loopback(self):
        for bad in ("http://api.example.com/v1", "ftp://api.example.com",
                    "javascript:alert(1)", "https://user:pass@example.com/x",
                    "https://example.com/v1?token=abc",
                    "https://example.com/v1#frag", "", "not-a-url", None, 5):
            with self.assertRaises(ConfigError, msg=repr(bad)):
                normalize_api_base(bad)

    def test_plain_http_is_allowed_on_loopback_only(self):
        for host in ("127.0.0.1", "localhost", "[::1]"):
            base = normalize_api_base("http://%s:12345/v1" % host)
            self.assertEqual(base, "http://%s:12345/v1" % host)
        self.assertIn("::1", LOOPBACK_HOSTS)

    def test_config_round_trips_the_cursor_and_epoch(self):
        path = os.path.join(self.data_dir, CONFIG_FILE_NAME)
        config = CloudConfig(api_base="https://api.example.com/v1",
                             tenant_id="tenant-abc", path=path)
        config.set_cursor(4242, "epoch-xyz")
        config.save()
        again = load_config(path=path)
        self.assertEqual(again.cursor, 4242)
        self.assertEqual(again.dataset_epoch, "epoch-xyz")
        self.assertEqual(again.tenant_id, "tenant-abc")
        self.assertEqual(again.source_installation_id,
                         config.source_installation_id)

    def test_installation_id_is_minted_once_and_then_stable(self):
        path = os.path.join(self.data_dir, CONFIG_FILE_NAME)
        first = load_config(path=path)
        second = load_config(path=path)
        self.assertEqual(first.source_installation_id,
                         second.source_installation_id)
        self.assertNotEqual(first.source_installation_id,
                            CloudConfig().source_installation_id)
        self.assertFalse(second.minted)

    def test_unknown_keys_are_dropped_on_write(self):
        path = os.path.join(self.data_dir, CONFIG_FILE_NAME)
        CloudConfig(api_base="https://api.example.com/v1", path=path).save()
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        payload["api_token"] = "should-not-survive"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        loaded = load_config(path=path)
        loaded.save()
        with open(path, "r", encoding="utf-8") as handle:
            self.assertNotIn("api_token", json.load(handle))

    def test_a_malformed_config_fails_closed(self):
        path = os.path.join(self.data_dir, CONFIG_FILE_NAME)
        for raw in ("", "[]", "not json", '{"version": 2}', "{}"):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(raw)
            with self.assertRaises(ConfigError, msg=repr(raw)) as caught:
                load_config(path=path)
            self.assertEqual(caught.exception.code, CONFIG_INVALID)

    def test_a_bad_cursor_is_refused(self):
        config = CloudConfig(api_base="https://api.example.com/v1")
        for bad in (-1, 1.5, "3", True, None):
            with self.assertRaises(ConfigError, msg=repr(bad)):
                config.set_cursor(bad)

    def test_url_building_rejects_an_injection(self):
        config = CloudConfig(api_base="https://api.example.com/v1")
        self.assertEqual(config.url("/sync/bootstrap"),
                         "https://api.example.com/v1/sync/bootstrap")
        for bad in ("", "sync/bootstrap", "//evil.example.com/x",
                    "https://evil.example.com"):
            with self.assertRaises(ConfigError, msg=repr(bad)):
                config.url(bad)


# =====================================================================
# Transport: headers, envelopes, health
# =====================================================================
class TestTransport(ApiCase):

    def test_health_needs_no_token(self):
        payload = self.client.health()
        self.assertTrue(payload["ok"])
        self.assertIn("time", payload)
        self.assertEqual(self.api.calls("GET /health/live")[0]["authorization"],
                         "")

    def test_every_authenticated_call_carries_the_bearer_header(self):
        self.enrol()
        self.client.bootstrap()
        # §6: /auth/refresh authenticates with a token in its *body*, and
        # /health/live and /auth/login carry no Authorization header at all.
        skip = ("/health/live", "/auth/login", "/auth/refresh")
        calls = [c for c in self.api.requests if c["route"] not in skip]
        self.assertTrue(calls)
        for call in calls:
            self.assertTrue(call["authorization"].startswith("Bearer "),
                            call["route"])
        self.assertEqual(
            self.api.calls("GET /sync/bootstrap")[0]["authorization"],
            "Bearer " + self.vault.access_token)

    def test_failure_envelope_becomes_a_typed_error(self):
        self.enrol()
        self.api.fail_next("GET /sync/bootstrap", 500, HTTP_500, count=1)
        with self.assertRaises(HttpError) as caught:
            self.client.bootstrap()
        error = caught.exception
        self.assertIsInstance(error, CloudSyncError)
        self.assertEqual(error.code, HTTP_500)
        self.assertEqual(error.status, 500)
        self.assertEqual(error.route, "/sync/bootstrap")
        self.assertTrue(error.request_id)
        self.assertTrue(error.retryable)
        self.assertTrue(is_valid_code(error.code))

    def test_the_server_message_never_reaches_the_exception(self):
        self.enrol()
        self.api.fail_next("GET /sync/bootstrap", 500, HTTP_500, count=1)
        with self.assertRaises(HttpError) as caught:
            self.client.bootstrap()
        assert_no_secret(self, str(caught.exception), "exception text")
        assert_no_secret(self, repr(caught.exception), "exception repr")

    def test_a_2xx_that_is_not_the_envelope_is_a_protocol_fault(self):
        self.enrol()
        self.api.fail_next("GET /sync/bootstrap", 200, HTTP_500, count=1,
                           body={"something": "else"})
        with self.assertRaises(BadResponseError):
            self.client.bootstrap()

    def test_an_unparseable_body_is_bad_payload(self):
        self.enrol()
        self.api.fail_next("GET /sync/bootstrap", 200, HTTP_500, count=1,
                           body="<html>not json</html>")
        with self.assertRaises(BadResponseError) as caught:
            self.client.bootstrap()
        self.assertEqual(caught.exception.code, BAD_PAYLOAD)

    def test_an_unknown_route_is_reported_as_404(self):
        self.enrol()
        with self.assertRaises(HttpError) as caught:
            self.client._request("GET", "/does/not/exist")
        self.assertEqual(caught.exception.status, 404)

    def test_a_403_is_a_permission_answer_not_a_dead_session(self):
        self.warm()
        self.api.fail_next("GET /sync/bootstrap", 403, HTTP_403, count=1)
        with self.assertRaises(HttpError) as caught:
            self.client.bootstrap()
        self.assertEqual(caught.exception.code, HTTP_403)
        self.assertIsInstance(caught.exception, HttpError)
        self.assertNotIsInstance(caught.exception, AuthRequiredError)
        self.assertEqual(self.api.calls("/auth/refresh"), [])


# =====================================================================
# Bootstrap and incremental pull (spec §6.2)
# =====================================================================
class TestBootstrapAndPull(ApiCase):

    def test_bootstrap_returns_collections_cursor_and_epoch(self):
        self.enrol()
        self.api.seed("customers", "cust-1", {"name": "customer one"})
        payload = self.client.bootstrap()
        self.assertIn("collections", payload)
        self.assertIn("customers", payload["collections"])
        self.assertEqual(payload["cursor"], self.api.seq)
        self.assertEqual(payload["dataset_epoch"], self.api.dataset_epoch)
        # Fetching a snapshot alone must not advance durable state. The fixture
        # already committed an empty bootstrap, so its cursor remains zero
        # until this newer snapshot is explicitly materialized/committed.
        self.assertEqual(self.config.cursor, 0)
        self.client.commit_bootstrap(payload)
        self.assertEqual(self.config.cursor, self.api.seq)

    def test_pull_resumes_across_has_more_pages(self):
        self.enrol()
        for index in range(7):
            self.api.seed("customers", "cust%02d" % index,
                          {"name": "customer %d" % index})
        self.config.set_cursor(0)
        self.config.save()
        sizes = []

        def handler(page):
            self.assertTrue(page["has_more"] or page["changes"])
            sizes.append(len(page["changes"]))

        pages = self.client.pull_all(handler, limit=3)
        self.assertEqual(pages, 3)
        self.assertEqual(sizes, [3, 3, 1])
        self.assertEqual(self.config.cursor, self.api.seq)

        # Nothing new: one more drain reads zero pages worth of changes.
        after = self.client.pull_all(lambda page: self.fail("no changes"),
                                     limit=3)
        self.assertEqual(after, 1)

    def test_cursor_survives_a_restart(self):
        self.enrol()
        for index in range(5):
            self.api.seed("owners", "own%02d" % index,
                          {"name": "owner %d" % index})
        self.config.set_cursor(0)
        self.config.save()
        for _ in range(2):                 # a caller applies, then records
            page = self.client.pull(self.config.cursor, 2)
            self.config.set_cursor(page["cursor"])
            self.config.save()
        half = self.config.cursor
        self.assertEqual(half, 4)
        self.assertLess(half, self.api.seq)

        # A brand new process reads the same config and continues from there.
        restarted = self.new_machine()
        self.assertEqual(restarted.config.cursor, half)
        seen = []
        restarted.pull_all(lambda page: seen.append(len(page["changes"])),
                           limit=2)
        self.assertEqual(sum(seen), self.api.seq - half)

    def test_cursor_only_advances_after_the_page_was_handled(self):
        self.enrol()
        for index in range(4):
            self.api.seed("periods", "per%02d" % index,
                          {"label": "period %d" % index})
        self.config.set_cursor(0)
        self.config.save()
        before = self.config.cursor

        class Boom(Exception):
            pass

        def handler(page):
            raise Boom()

        with self.assertRaises(Boom):
            self.client.pull_all(handler, limit=2)
        self.assertEqual(self.config.cursor, before,
                         "a failed page must not be skipped")

    def test_pull_rejects_a_malformed_page(self):
        self.enrol()
        self.api.fail_next("GET /sync/changes", 200, HTTP_500, count=1,
                           body={"ok": True, "changes": "not-a-list",
                                 "cursor": 1, "has_more": False})
        with self.assertRaises(BadResponseError):
            self.client.pull(0, 10)

    def test_pull_validates_its_own_arguments(self):
        self.enrol()
        for cursor, limit in ((-1, 10), (1.5, 10), ("1", 10), (0, 0),
                              (0, True)):
            with self.assertRaises(BadResponseError, msg=repr((cursor, limit))):
                self.client.pull(cursor, limit)

    def test_import_document_requires_live_user_token_and_sends_it_in_header(self):
        self.enrol()
        # Enrol leaves user token in vault
        fake_body = {
            "import_id": str(uuid.uuid4()),
            "source_installation_id": str(uuid.uuid4()),
            "collections": {
                "customers": [], "customer_transactions": [],
                "owners": [], "identities": [], "crm_devices": [],
                "periods": [], "settings": [],
            },
        }
        res = self.client.import_document(fake_body)
        self.assertTrue(res.get("ok"))
        self.assertEqual(len(self.api.calls("POST /bootstrap/import")), 1)

        # Clear user token: must fail immediately without sending network request
        self.vault.clear_user()
        with self.assertRaises(AuthRequiredError):
            self.client.import_document(fake_body)


# =====================================================================
# Push: apply, conflict-as-data, idempotency (spec §6.1)
# =====================================================================
class TestPush(ApiCase):

    def operation(self, **overrides):
        operation = {"kind": "upsert", "entity": "crm_devices",
                     "id": "dev-uuid-1", "base_version": 0,
                     "record": {"label": "device A"}}
        operation.update(overrides)
        return operation

    def test_push_applies_and_bumps_the_row_version(self):
        self.enrol()
        operation = self.operation()
        result = self.client.push([operation])
        self.assertEqual(result.applied, (operation["operation_id"],))
        self.assertEqual(result.conflicts, ())
        self.assertEqual(self.api.row("crm_devices", "dev-uuid-1")
                         ["row_version"], 1)

    def test_push_never_advances_the_durable_pull_cursor(self):
        self.enrol()
        before = self.config.cursor
        result = self.client.push([self.operation()])
        self.assertGreater(result.cursor, before)
        self.assertEqual(self.config.cursor, before)

    def test_operation_id_is_minted_once_into_the_caller_dict(self):
        self.enrol()
        operation = self.operation()
        self.assertNotIn("operation_id", operation)
        first = self.client.push([operation])
        minted = operation["operation_id"]
        self.assertTrue(minted)
        second = self.client.push([operation])
        self.assertEqual(second.applied, (minted,))
        self.assertEqual(first.applied, (minted,))

    def test_the_same_operation_id_is_never_applied_twice(self):
        self.enrol()
        operation = self.operation()
        self.client.push([operation])
        self.client.push([operation])
        self.client.push([operation])
        self.assertEqual(self.api.apply_count[operation["operation_id"]], 1)
        self.assertEqual(self.api.row("crm_devices", "dev-uuid-1")
                         ["row_version"], 1)

    def test_a_conflict_is_data_and_does_not_raise(self):
        self.enrol()
        operation = self.operation()
        self.client.push([operation])          # row_version becomes 1
        stale = self.operation(operation_id="op-stale-1", base_version=0,
                               record={"label": "stale edit"})
        result = self.client.push([stale])     # must not raise
        self.assertEqual(result.applied, ())
        self.assertEqual(len(result.conflicts), 1)
        conflict = result.conflicts[0]
        self.assertEqual(conflict.operation_id, "op-stale-1")
        self.assertEqual(conflict.entity, "crm_devices")
        self.assertEqual(conflict.server_version, 1)
        self.assertEqual(conflict.server_record, {"label": "device A"})
        self.assertEqual(self.api.row("crm_devices", "dev-uuid-1")["record"],
                         {"label": "device A"})

    def test_a_conflict_carries_a_valid_code_for_the_ui(self):
        self.enrol()
        self.client.push([self.operation()])
        result = self.client.push([self.operation(operation_id="op-2",
                                                  base_version=0)])
        self.assertEqual(result.conflicts[0].server_version, 1)
        self.assertTrue(is_valid_code(VERSION_CONFLICT))

    def test_untouched_operations_still_apply_when_one_conflicts(self):
        self.enrol()
        self.client.push([self.operation()])
        stale = self.operation(operation_id="op-stale", base_version=0)
        fresh = self.operation(operation_id="op-fresh", id="dev-uuid-2",
                               base_version=0, record={"label": "device B"})
        result = self.client.push([stale, fresh])
        self.assertEqual(result.applied, ("op-fresh",))
        self.assertEqual([c.operation_id for c in result.conflicts],
                         ["op-stale"])
        self.assertIsNotNone(self.api.row("crm_devices", "dev-uuid-2"))

    def test_a_delete_propagates_as_a_tombstone(self):
        self.enrol()
        self.client.push([self.operation()])
        row = self.api.row("crm_devices", "dev-uuid-1")
        delete = {"operation_id": "op-del", "kind": "delete",
                  "entity": "crm_devices", "id": "dev-uuid-1",
                  "base_version": row["row_version"]}
        result = self.client.push([delete])
        self.assertEqual(result.applied, ("op-del",))
        self.api.requests.clear()
        self.config.set_cursor(0)
        page = self.client.pull(0, 50)
        tombstones = [c for c in page["changes"]
                      if c["id"] == "dev-uuid-1" and c["record"] is None]
        self.assertTrue(tombstones, page)

    def test_push_validates_operations_before_sending(self):
        self.enrol()
        for bad in ([], [None], [{"kind": "nope"}],
                    [{"kind": "upsert", "entity": "profiles", "id": "x",
                      "base_version": 0, "record": {}}],
                    [{"kind": "upsert", "entity": "owners"}]):
            with self.assertRaises(BadResponseError, msg=repr(bad)):
                self.client.push(bad)
        self.assertEqual(self.api.calls("POST /sync/mutations"), [])


# =====================================================================
# Retry behaviour driven by the outbox (spec §9)
# =====================================================================
class TestRetries(ApiCase):

    def setUp(self):
        super().setUp()
        self.enrol()
        self.client.bootstrap()
        self.api.requests.clear()
        self.api.clear_faults()
        self.vault.clear_user()
        self.worker = self.new_worker()
        self.outbox = self.worker.outbox

    def queue_one(self, identifier="own-1"):
        return self.outbox.enqueue({
            "kind": "upsert", "entity": "owners", "id": identifier,
            "base_version": 0, "record": {"name": "owner " + identifier}})

    def advance(self, seconds):
        self.clock[0] += seconds

    def test_a_500_is_retried_and_then_applies(self):
        self.queue_one()
        self.api.fail_next("POST /sync/mutations", 500, HTTP_500, count=2)
        first = self.worker.run_once()
        self.assertTrue(first.attempted)
        self.assertEqual(first.code, HTTP_500)
        self.assertEqual(first.terminal, SyncEvent.SYNC_FAILED.value)
        self.advance(60)
        second = self.worker.run_once()
        self.assertEqual(second.code, HTTP_500)
        self.advance(60)
        third = self.worker.run_once()
        self.assertEqual(third.terminal, SyncEvent.SYNC_OK.value)
        self.assertEqual(third.applied, 1)
        self.assertEqual(len(self.api.calls("POST /sync/mutations")), 3)

    def test_a_400_is_not_retried(self):
        self.queue_one()
        self.api.fail_next("POST /sync/mutations", 400, BAD_PAYLOAD, count=5)
        outcome = self.worker.run_once()
        self.assertEqual(outcome.code, BAD_PAYLOAD)
        self.assertIsNone(outcome.retry_at)
        self.advance(600)
        self.assertFalse(self.worker.run_once().attempted)
        self.assertEqual(len(self.api.calls("POST /sync/mutations")), 1)
        self.assertEqual(self.outbox.parked_count, 1)

    def test_a_403_is_not_retried(self):
        self.queue_one()
        self.api.fail_next("POST /sync/mutations", 403, HTTP_403, count=5)
        outcome = self.worker.run_once()
        self.assertEqual(outcome.code, HTTP_403)
        self.assertIsNone(outcome.retry_at)
        self.advance(600)
        self.assertFalse(self.worker.run_once().attempted)
        self.assertEqual(len(self.api.calls("POST /sync/mutations")), 1)

    def test_a_409_is_not_retried(self):
        self.queue_one()
        self.api.fail_next("POST /sync/mutations", 409, HTTP_409, count=5)
        outcome = self.worker.run_once()
        self.assertEqual(outcome.code, HTTP_409)
        self.assertIsNone(outcome.retry_at)
        self.advance(600)
        self.assertFalse(self.worker.run_once().attempted)
        self.assertEqual(len(self.api.calls("POST /sync/mutations")), 1)
        self.assertEqual(self.outbox.parked_count, 1)
        self.assertEqual(self.outbox.pending_count, 0)

    def test_a_429_honours_retry_after(self):
        self.queue_one()
        self.api.fail_next("POST /sync/mutations", 429, HTTP_429, count=1,
                           headers={"Retry-After": "42"})
        outcome = self.worker.run_once()
        self.assertEqual(outcome.code, HTTP_429)
        self.assertIsNotNone(outcome.retry_at)
        self.assertEqual(outcome.retry_at, self.clock[0] + 42.0)
        self.assertFalse(self.worker.run_once().attempted)
        self.advance(43)
        self.assertTrue(self.worker.run_once().attempted)

    def test_retry_after_is_clamped_to_the_five_minute_cap(self):
        self.queue_one()
        self.api.fail_next("POST /sync/mutations", 429, HTTP_429, count=1,
                           headers={"Retry-After": "7200"})
        outcome = self.worker.run_once()
        self.assertEqual(outcome.retry_at, self.clock[0] + 300.0)

    def test_backoff_stays_bounded_across_many_failures(self):
        self.queue_one()
        self.api.fail_next("POST /sync/mutations", 500, HTTP_500, count=8)
        waits = []
        for _ in range(8):
            outcome = self.worker.run_once()
            if outcome.retry_at is None:
                break
            waits.append(outcome.retry_at - self.clock[0])
            self.assertLessEqual(outcome.retry_at - self.clock[0], 300.0)
            self.advance(301)
        self.assertEqual(len(waits), 7)   # the 8th attempt exhausts the budget
        self.assertEqual(self.outbox.parked_count, 1)
        self.assertEqual(self.outbox.pending_count, 0)
        self.assertEqual(waits, [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0])

    def test_a_timeout_is_retried(self):
        self.queue_one()
        calls = {"n": 0}

        def flaky(method, url, headers, body, timeout):
            calls["n"] += 1
            if calls["n"] == 1:
                raise requests.Timeout("read timed out")
            return _RealSend(self)(method, url, headers, body, timeout)

        self.client._send = flaky
        outcome = self.worker.run_once()
        self.assertEqual(outcome.code, NET_TIMEOUT)
        self.assertEqual(outcome.terminal, SyncEvent.SYNC_FAILED.value)
        self.assertIsNotNone(outcome.retry_at)

    def test_a_connection_error_is_retried(self):
        self.queue_one()

        def refused(method, url, headers, body, timeout):
            raise requests.ConnectionError("connection refused")

        self.client._send = refused
        outcome = self.worker.run_once()
        self.assertEqual(outcome.code, NET_UNREACHABLE)
        self.assertIsNotNone(outcome.retry_at)

    def test_a_transport_failure_before_push_still_fires_one_outcome(self):
        self.queue_one()
        self.client._send = lambda *a, **k: (_ for _ in ()).throw(
            requests.Timeout("slow"))
        outcome = self.worker.run_once()
        self.assertEqual(outcome.terminal_count, 1)
        self.assertEqual(outcome.events,
                         (SyncEvent.START_SYNC.value,
                          SyncEvent.SYNC_FAILED.value))

    def test_nothing_due_means_no_attempt_and_no_event(self):
        outcome = self.worker.run_once()
        self.assertFalse(outcome.attempted)
        self.assertEqual(outcome.events, ())
        self.assertEqual(self.api.calls("POST /sync/mutations"), [])


class _RealSend(object):
    """Rebuilds the default requests session so a stub can fall back to it."""

    def __init__(self, case):
        self.case = case

    def __call__(self, method, url, headers, body, timeout):
        session = self.case.client._session
        return session.request(method, url, data=body, headers=headers,
                               timeout=timeout, allow_redirects=False)


# =====================================================================
# Authentication (spec §5, manager ruling 7)
# =====================================================================
class TestAuth(ApiCase):

    def test_login_returns_tokens_and_keeps_them_in_ram_only(self):
        payload = self.client.login(fake_api.FAKE_USERNAME,
                                    fake_api.FAKE_PASSWORD)
        self.assertTrue(payload["must_change_password"] is False)
        self.assertTrue(self.vault.user_access_token)
        self.assertIsNone(self.vault.device_refresh_token)
        self.assertFalse(os.path.exists(self.vault.path))
        for blob in self.read_data_files():
            assert_no_secret(self, blob.decode("utf-8", "replace"),
                             "a data-dir file")

    def test_a_wrong_password_is_a_typed_auth_error(self):
        with self.assertRaises(AuthRequiredError) as caught:
            self.client.login(fake_api.FAKE_USERNAME, "FAKE-wrong-password")
        self.assertEqual(caught.exception.code, AUTH_REQUIRED)
        self.assertIsNone(self.vault.user_access_token)

    def test_enrolment_persists_the_device_id_and_a_protected_token(self):
        device_id = self.enrol()
        self.assertTrue(device_id)
        self.assertEqual(self.config.sync_device_id, device_id)
        self.assertTrue(os.path.exists(self.vault.path))
        with open(self.vault.path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertEqual(document["store"], "dpapi")
        self.assertNotIn(fake_api.FAKE_PASSWORD, json.dumps(document))
        self.assertTrue(self.vault.device_refresh_token)

    def test_a_401_refreshes_exactly_once_then_retries(self):
        self.warm()
        self.api.fail_next("GET /sync/bootstrap", 401, AUTH_REQUIRED, count=1)
        payload = self.client.bootstrap()      # succeeds on the retry
        self.assertTrue(payload["ok"])
        refreshes = self.api.calls("POST /auth/refresh")
        self.assertEqual(len(refreshes), 1)
        bootstraps = self.api.calls("GET /sync/bootstrap")
        self.assertEqual(len(bootstraps), 2)

    def test_a_second_401_surfaces_auth_required_and_stops(self):
        self.warm()
        self.api.fail_next("GET /sync/bootstrap", 401, AUTH_REQUIRED, count=2)
        with self.assertRaises(AuthRequiredError) as caught:
            self.client.bootstrap()
        self.assertEqual(caught.exception.code, AUTH_REQUIRED)
        self.assertEqual(len(self.api.calls("POST /auth/refresh")), 1,
                         "spec §9 allows exactly one refresh")

    def test_a_failed_refresh_revokes_the_local_credentials(self):
        self.warm()
        self.api.revoke_device_family()
        with self.assertRaises(AuthRequiredError) as caught:
            self.client.bootstrap()
        self.assertIsInstance(caught.exception, AuthRevokedError)
        self.assertEqual(caught.exception.code, AUTH_REVOKED)
        self.assertFalse(os.path.exists(self.vault.path),
                         "a refused refresh token must not stay on disk")
        self.assertIsNone(self.vault.access_token)

    def test_refresh_reuse_detection_revokes_local_state(self):
        self.warm()
        self.api.reuse_next_refresh()
        self.vault.clear_access()          # force the refresh path
        with self.assertRaises(AuthRequiredError):
            self.client.pull(self.config.cursor, 10)
        self.assertFalse(os.path.exists(self.vault.path))

    def test_no_device_credentials_is_enrol_required(self):
        config = CloudConfig(api_base=self.handle.base_url,
                             tenant_id=self.api.tenant_id,
                             path=os.path.join(self.data_dir,
                                               CONFIG_FILE_NAME))
        client = SyncClient(config, self.vault, clock=lambda: self.clock[0])
        with self.assertRaises(AuthRequiredError) as caught:
            client.bootstrap()
        self.assertEqual(caught.exception.code, "ENROL_REQUIRED")

    def test_user_tokens_are_never_used_as_device_tokens(self):
        # A regression here used to present the user JWT on /sync/* and was
        # answered with a 401 that looked like a dead device session.
        self.enrol()
        self.assertNotEqual(self.vault.access_token,
                            self.vault.user_access_token)
        self.client.bootstrap()
        self.assertEqual(self.api.calls("GET /sync/bootstrap")[0]["status"],
                         200)

    def test_access_tokens_never_reach_the_disk(self):
        self.enrol()
        self.client.bootstrap()
        self.assertTrue(self.vault.access_token)
        self.assertTrue(self.vault.user_access_token)
        for blob in self.read_data_files():
            text = blob.decode("utf-8", "replace")
            self.assertNotIn(self.vault.access_token, text)
            self.assertNotIn(self.vault.user_access_token, text)
            for pattern in TOKEN_PATTERNS:
                self.assertIsNone(pattern.search(text),
                                  "a data-dir file matched %s"
                                  % pattern.pattern)

    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-only")
    def test_dpapi_protects_the_refresh_token_on_disk(self):
        vault = TokenVault(store=DpapiSecretStore(),
                           path=os.path.join(self.data_dir, AUTH_FILE_NAME))
        token = "FAKE-device-refresh-" + "a" * 40
        vault.save_device_refresh(token)
        self.assertEqual(vault.device_refresh_token, token)
        for blob in self.read_data_files():
            self.assertNotIn(token, blob.decode("utf-8", "replace"),
                             "the refresh token was stored in the clear")

    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-only")
    def test_auth_file_dacl_is_current_user_and_system_only(self):
        vault = TokenVault(store=DpapiSecretStore(),
                           path=os.path.join(self.data_dir, AUTH_FILE_NAME))
        vault.save_device_refresh("FAKE-device-refresh-" + "b" * 40)
        trustees = read_acl_sids(vault.path)
        self.assertEqual(set(trustees),
                         {current_user_sid_string(), "S-1-5-18"})
        self.assertNotIn("S-1-5-32-544", trustees,
                         "Administrators must not inherit this file")

    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-only")
    def test_a_plaintext_auth_file_is_refused(self):
        path = os.path.join(self.data_dir, AUTH_FILE_NAME)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "store": "plaintext",
                       "data": "FAKE-device-refresh-in-the-clear"},
                      handle)
        vault = TokenVault(store=DpapiSecretStore(), path=path)
        with self.assertRaises(SecretStoreError) as caught:
            _ = vault.device_refresh_token
        self.assertEqual(caught.exception.code, SECRET_UNAVAILABLE)
        self.assertEqual(vault.restore_reason, "AUTH_FILE_NOT_PROTECTED")

    def test_a_secret_store_that_fails_never_writes_the_token(self):
        class Broken(MemorySecretStore):
            def protect(self, data):
                raise SecretStoreError(code=SECRET_UNAVAILABLE)

        path = os.path.join(self.data_dir, AUTH_FILE_NAME)
        vault = TokenVault(store=Broken(), path=path)
        with self.assertRaises(SecretStoreError):
            vault.save_device_refresh("FAKE-device-refresh-never-on-disk")
        self.assertFalse(os.path.exists(path))

    def test_dpapi_is_refused_on_a_platform_that_lacks_it(self):
        with patch.object(__import__("cloud_sync.auth", fromlist=["x"]),
                          "os") as fake_os:
            fake_os.name = "posix"
            fake_os.fspath = os.fspath
            fake_os.path = os.path
            fake_os.makedirs = os.makedirs
            fake_os.fdopen = os.fdopen
            fake_os.unlink = os.unlink
            fake_os.replace = os.replace
            with self.assertRaises(SecretStoreError):
                DpapiSecretStore()

    def test_login_with_a_blank_password_is_refused_locally(self):
        for username, password in (("", "x"), (fake_api.FAKE_USERNAME, ""),
                                   (None, "x"), (fake_api.FAKE_USERNAME, None)):
            with self.assertRaises(BadResponseError):
                self.client.login(username, password)

    def test_access_tokens_expire_after_fifteen_minutes(self):
        self.enrol()
        self.client.bootstrap()
        self.assertIsNotNone(self.vault.access_token)
        self.clock[0] += ACCESS_TTL_SECONDS
        self.assertIsNone(self.vault.access_token,
                          "a 15-minute JWT must not be reused past its TTL")

    def test_logout_forgets_the_user_session(self):
        self.enrol()
        self.assertIsNotNone(self.vault.user_access_token)
        self.client.logout()
        self.assertIsNone(self.vault.user_access_token)
        self.assertIsNone(self.vault.user_refresh_token)


# =====================================================================
# Logging (spec §5)
# =====================================================================
class TestLogging(ApiCase):

    def test_every_log_line_is_the_documented_six_fields(self):
        self.enrol()
        self.client.bootstrap()
        self.assertTrue(self.capture.records)
        allowed = {"route", "method", "status", "duration_ms",
                   "request_id", "code"}
        for record in self.capture.records:
            payload = json.loads(record.getMessage())
            self.assertEqual(set(payload), allowed, payload)
            self.assertTrue(is_valid_code(payload["code"])
                            or payload["code"] == "", payload["code"])
            self.assertTrue(payload["request_id"] == ""
                            or re.fullmatch(
                                r"[0-9a-f-]{36}", payload["request_id"]),
                            payload["request_id"])

    def test_no_token_reaches_any_log_line(self):
        self.enrol()
        self.client.bootstrap()
        for index in range(3):
            self.api.seed("owners", "own%d" % index, {"name": "owner"})
        self.client.pull_all(lambda page: None, limit=2)
        self.client.push([{"kind": "upsert", "entity": "owners",
                           "id": "own-x", "base_version": 0,
                           "record": {"name": "pushed"}}])
        self.api.fail_next("GET /sync/bootstrap", 500, HTTP_500, count=1)
        try:
            self.client.bootstrap()
        except HttpError:
            pass
        text = self.all_log_text()
        self.assertTrue(text.strip())
        for token in self.known_tokens():
            self.assertNotIn(token, text)
        assert_no_secret(self, text, "the transport log")

    def test_a_non_uuid_request_id_is_dropped_from_the_log(self):
        self.enrol()
        self.api.fail_next("GET /sync/bootstrap", 500, HTTP_500, count=1,
                           message="token-shaped request id",
                           body={"ok": False, "error": {
                               "code": HTTP_500, "message": "x",
                               "request_id": "tok-abcdef0123456789"}})
        with self.assertRaises(HttpError) as caught:
            self.client.bootstrap()
        self.assertEqual(caught.exception.request_id, "")
        for line in self.capture.texts:
            self.assertNotIn("tok-abcdef0123456789", line)

    def test_server_message_never_reaches_a_log_line(self):
        self.enrol()
        self.api.fail_next("GET /sync/bootstrap", 500, HTTP_500, count=1)
        try:
            self.client.bootstrap()
        except HttpError as error:
            assert_no_secret(self, str(error), "exception")
        assert_no_secret(self, self.all_log_text(), "the transport log")

    def test_the_canary_survives_a_full_authenticated_flow(self):
        self.enrol()
        self.api.fail_next("POST /sync/mutations", 500, HTTP_500, count=1)
        self.client.bootstrap()
        try:
            self.client.push([{"kind": "upsert", "entity": "owners",
                               "id": "own-y", "base_version": 0,
                               "record": {"name": "y"}}])
        except CloudSyncError as error:
            assert_no_secret(self, str(error), "exception")
        assert_no_secret(self, self.all_log_text(), "the transport log")
        for blob in self.read_data_files():
            assert_no_secret(self, blob.decode("utf-8", "replace"),
                             "a data-dir file")


# =====================================================================
# Outbox durability (spec §9, manager ruling 10)
# =====================================================================
class TestOutbox(DataDirCase):

    def path(self):
        return os.path.join(self.data_dir, OUTBOX_FILE_NAME)

    def operation(self, identifier):
        return {"kind": "upsert", "entity": "owners", "id": identifier,
                "base_version": 0, "record": {"name": identifier}}

    def test_a_default_outbox_lives_in_the_data_directory(self):
        # OUTBOX_FILE_NAME is a path *relative to* the data directory, but
        # app_paths.data_path() refuses any separator. Resolving the default
        # through it therefore raised ValueError, so an Outbox built without
        # an explicit path could never load or push. The default must land on
        # exactly the same file the callers join by hand.
        default = Outbox()
        self.assertEqual(os.path.abspath(default.path),
                         os.path.abspath(self.path()))
        default.enqueue(self.operation("d"), operation_id="op-d")
        self.assertEqual(len(Outbox().load()), 1)

    def test_enqueue_writes_a_line_and_reloads(self):
        outbox = Outbox(path=self.path())
        outbox.enqueue(self.operation("a"), operation_id="op-a")
        outbox.enqueue(self.operation("b"), operation_id="op-b")
        self.assertTrue(os.path.exists(self.path()))
        with open(self.path(), "r", encoding="utf-8") as handle:
            lines = [line for line in handle.read().splitlines() if line]
        self.assertEqual(len(lines), 2)
        for line in lines:
            json.loads(line)

        reloaded = Outbox(path=self.path()).load()
        self.assertEqual(len(reloaded), 2)
        self.assertEqual(reloaded.corrupt_lines, 0)
        self.assertEqual([e.operation_id for e in reloaded.entries()],
                         ["op-a", "op-b"])

    def test_the_queue_survives_a_simulated_restart(self):
        outbox = Outbox(path=self.path())
        for index in range(5):
            outbox.enqueue(self.operation("row%d" % index),
                           operation_id="op-%d" % index)
        outbox.record_attempt("op-0", code=HTTP_500, due_at=CLOCK + 30)
        outbox.park("op-1", "attempts", code=HTTP_400)
        outbox.mark_done("op-2", "applied")

        # A fresh process, no shared state: only what is on disk.
        restored = Outbox(path=self.path()).load()
        self.assertEqual(len(restored), 4)
        self.assertEqual(restored.pending_count, 3)
        self.assertEqual(restored.parked_count, 1)
        self.assertIsNone(restored.get("op-2"))
        entry = restored.get("op-0")
        self.assertEqual(entry.attempts, 1)
        self.assertEqual(entry.due_at, CLOCK + 30)
        self.assertEqual(entry.operation["id"], "row0")

    def test_queue_full_raises_and_never_truncates(self):
        outbox = Outbox(path=self.path(), max_pending=3)
        for index in range(3):
            outbox.enqueue(self.operation("row%d" % index),
                           operation_id="op-%d" % index)
        with self.assertRaises(QueueFullError) as caught:
            outbox.enqueue(self.operation("overflow"), operation_id="op-x")
        self.assertEqual(caught.exception.code, QUEUE_FULL)
        self.assertTrue(is_valid_code(caught.exception.code))

        # Nothing was dropped: the three originals are still there, on disk.
        self.assertEqual(len(outbox), 3)
        restored = Outbox(path=self.path(), max_pending=3).load()
        self.assertEqual(len(restored), 3)
        self.assertIsNone(restored.get("op-x"))
        self.assertEqual([e.operation_id for e in restored.entries()],
                         ["op-0", "op-1", "op-2"])
        with self.assertRaises(QueueFullError):
            restored.enqueue(self.operation("again"), operation_id="op-y")

    def test_a_full_queue_frees_room_only_when_a_row_finishes(self):
        outbox = Outbox(path=self.path(), max_pending=2)
        outbox.enqueue(self.operation("a"), operation_id="op-a")
        outbox.enqueue(self.operation("b"), operation_id="op-b")
        with self.assertRaises(QueueFullError):
            outbox.enqueue(self.operation("c"), operation_id="op-c")
        outbox.mark_done("op-a", "applied")
        outbox.enqueue(self.operation("c"), operation_id="op-c")
        self.assertEqual(len(outbox), 2)
        self.assertIsNotNone(outbox.get("op-c"))

    def test_a_truncated_last_line_is_counted_not_fatal(self):
        outbox = Outbox(path=self.path())
        outbox.enqueue(self.operation("a"), operation_id="op-a")
        outbox.enqueue(self.operation("b"), operation_id="op-b")
        with open(self.path(), "a", encoding="utf-8") as handle:
            handle.write('{"v":1,"kind":"enqueue","id":"op-c","trunc')
        restored = Outbox(path=self.path()).load()
        self.assertEqual(restored.corrupt_lines, 1)
        self.assertEqual([e.operation_id for e in restored.entries()],
                         ["op-a", "op-b"])

    def test_compaction_keeps_every_live_row(self):
        outbox = Outbox(path=self.path())
        outbox.enqueue(self.operation("a"), operation_id="op-a")
        for index in range(600):
            outbox.record_attempt("op-a", code=HTTP_500, due_at=CLOCK + index)
        with open(self.path(), "r", encoding="utf-8") as handle:
            self.assertLess(len(handle.read().splitlines()), 600)
        restored = Outbox(path=self.path()).load()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored.get("op-a").operation["id"], "a")

    def test_conflicts_are_listed_separately_from_pending(self):
        outbox = Outbox(path=self.path())
        outbox.enqueue(self.operation("a"), operation_id="op-a")
        outbox.enqueue(self.operation("b"), operation_id="op-b")
        outbox.park("op-a", "conflict", code=VERSION_CONFLICT,
                    conflict={"server_version": 3})
        self.assertEqual(outbox.conflict_count, 1)
        self.assertEqual(outbox.pending_count, 1)
        self.assertEqual(outbox.parked_count, 0)
        self.assertEqual([e.operation_id for e in outbox.conflicts()],
                         ["op-a"])
        outbox.release("op-a")
        self.assertEqual(outbox.conflict_count, 0)
        self.assertEqual(outbox.pending_count, 2)

    def test_a_bad_park_reason_is_refused(self):
        outbox = Outbox(path=self.path())
        outbox.enqueue(self.operation("a"), operation_id="op-a")
        with self.assertRaises(ValueError):
            outbox.park("op-a", "whatever")
        with self.assertRaises(ValueError):
            Outbox(path=self.path(), max_pending=0)

    def test_an_enqueue_without_an_operation_is_refused(self):
        outbox = Outbox(path=self.path())
        for bad in (None, {}, [], "x", 5):
            with self.assertRaises(QueueFullError, msg=repr(bad)):
                outbox.enqueue(bad)


# =====================================================================
# The worker: exactly one outcome per attempt (manager ruling 12)
# =====================================================================
class TestWorker(ApiCase):

    def setUp(self):
        super().setUp()
        self.enrol()
        self.client.bootstrap()
        self.api.requests.clear()
        self.api.clear_faults()
        self.vault.clear_user()
        self.machine = SyncStateMachine()
        self.machine.apply(SyncEvent.ENROL)
        self.lease = OfflineLease(path=os.path.join(self.data_dir,
                                                    "lease.json"),
                                  clock=lambda: self.clock[0])
        self.lease.grant()
        self.worker = self.new_worker(machine=self.machine, lease=self.lease)
        self.outbox = self.worker.outbox

    def queue(self, identifier="own-1", **overrides):
        operation = {"kind": "upsert", "entity": "owners", "id": identifier,
                     "base_version": 0, "record": {"name": identifier}}
        operation.update(overrides)
        return self.outbox.enqueue(operation)

    def advance(self, seconds):
        self.clock[0] += seconds

    def test_a_successful_attempt_fires_exactly_one_outcome(self):
        self.queue()
        outcome = self.worker.run_once()
        self.assertTrue(outcome.attempted)
        self.assertEqual(outcome.terminal, SyncEvent.SYNC_OK.value)
        self.assertEqual(outcome.terminal_count, 1)
        self.assertEqual(outcome.events,
                         (SyncEvent.START_SYNC.value, SyncEvent.SYNC_OK.value))
        self.assertIsNone(outcome.code)
        self.assertEqual(self.machine.state, SyncState.IDLE)
        self.assertEqual(self.machine.pending_changes, 0)
        self.assertIsNotNone(self.machine.last_successful_sync)

    def test_a_failed_attempt_fires_exactly_one_outcome(self):
        self.queue()
        self.api.fail_next("POST /sync/mutations", 500, HTTP_500, count=1)
        outcome = self.worker.run_once()
        self.assertEqual(outcome.terminal_count, 1)
        self.assertEqual(outcome.terminal, SyncEvent.SYNC_FAILED.value)
        self.assertEqual(outcome.code, HTTP_500)
        self.assertEqual(self.machine.last_error_code, HTTP_500)
        self.assertEqual(self.machine.state, SyncState.IDLE)

    def test_a_conflict_fires_the_finding_then_one_outcome(self):
        self.queue("own-1")
        self.worker.run_once()                     # creates the row
        self.queue("own-1", operation_id="op-stale", base_version=0)
        outcome = self.worker.run_once()
        self.assertEqual(outcome.conflicts, 1)
        self.assertEqual(outcome.terminal, SyncEvent.SYNC_OK.value)
        self.assertEqual(outcome.terminal_count, 1)
        self.assertIn(SyncEvent.CONFLICT_FOUND.value, outcome.events)
        self.assertEqual(self.machine.conflict_count, 1)
        self.assertEqual(self.machine.state, SyncState.CONFLICT)
        self.assertEqual(self.outbox.conflict_count, 1)
        self.assertEqual(self.outbox.pending_count, 0)
        self.assertEqual(self.machine.pending_changes, 0)

    def test_an_expired_lease_blocks_the_push_before_the_socket(self):
        self.queue()
        expired = OfflineLease(path=self.lease.path,
                               clock=lambda: self.clock[0] + 8 * 24 * 3600)
        expired.grant(at=CLOCK)
        worker = self.new_worker(machine=self.machine, lease=expired)
        outcome = worker.run_once()
        self.assertFalse(outcome.attempted)
        self.assertEqual(outcome.terminal, SyncEvent.LEASE_EXPIRED.value)
        self.assertEqual(outcome.terminal_count, 1)
        self.assertEqual(outcome.code, LEASE_EXPIRED)
        self.assertEqual(self.machine.state, SyncState.READ_ONLY)
        self.assertEqual(self.machine.last_error_code, LEASE_EXPIRED)
        self.assertEqual(self.api.calls("POST /sync/mutations"), [])
        self.assertEqual(len(worker.outbox), 1, "the row must not be lost")

    def test_a_lease_that_was_never_granted_also_blocks(self):
        self.queue()
        # The exact type the worker catches at its boundary (ruling 12): the
        # push must never reach the socket because of it.
        with self.assertRaises(LeaseExpiredError):
            OfflineLease(path=os.path.join(self.data_dir, "never.json"),
                         clock=lambda: self.clock[0]).assert_writable()
        fresh = OfflineLease(path=os.path.join(self.data_dir, "no-lease.json"),
                             clock=lambda: self.clock[0])
        worker = self.new_worker(machine=self.machine, lease=fresh)
        outcome = worker.run_once()
        self.assertEqual(self.machine.state, SyncState.READ_ONLY)
        self.assertEqual(self.api.calls("POST /sync/mutations"), [])

    def test_auth_failure_fires_exactly_one_terminal_event(self):
        self.queue()
        self.api.revoke_device_family()
        outcome = self.worker.run_once()
        self.assertEqual(outcome.terminal, SyncEvent.AUTH_FAILED.value)
        self.assertEqual(outcome.terminal_count, 1)
        self.assertEqual(outcome.code, AUTH_REVOKED)
        self.assertEqual(self.machine.state, SyncState.AUTH_REQUIRED)
        self.assertEqual(len(self.api.calls("POST /auth/refresh")), 1)

    def test_an_illegal_transition_is_recorded_and_never_swallowed(self):
        self.queue()
        real_apply = self.machine.apply

        def refuse_outcome(event, **kwargs):
            if event is SyncEvent.SYNC_OK:
                raise IllegalTransitionError(SyncState.SYNCING,
                                             SyncEvent.SYNC_OK)
            return real_apply(event, **kwargs)

        self.machine.apply = refuse_outcome
        try:
            outcome = self.worker.run_once()
        finally:
            self.machine.apply = real_apply
        self.assertIn("!%s" % SyncEvent.SYNC_OK.value, outcome.events)
        self.assertTrue(outcome.attempted)
        self.assertEqual(self.machine.state, SyncState.SYNCING)
        self.assertNotIn(SyncEvent.SYNC_OK.value, outcome.events)

    def test_a_state_that_cannot_start_reports_a_refusal_not_a_crash(self):
        self.queue()
        self.machine.apply(SyncEvent.DISABLE)
        outcome = self.worker.run_once()
        self.assertFalse(outcome.attempted)
        self.assertEqual(outcome.refused, "START_SYNC")
        self.assertEqual(outcome.events, ())
        self.assertEqual(self.api.calls("POST /sync/mutations"), [])
        self.assertEqual(len(self.outbox), 1, "nothing may be dropped")

    def test_a_disabled_machine_keeps_its_row(self):
        self.queue()
        self.machine.apply(SyncEvent.DISABLE)
        self.worker.run_once()
        self.machine.apply(SyncEvent.ENABLE)
        outcome = self.worker.run_once()
        self.assertEqual(outcome.terminal, SyncEvent.SYNC_OK.value)
        self.assertEqual(outcome.applied, 1)

    def test_the_pending_gauge_follows_the_queue(self):
        for index in range(4):
            self.queue("own%d" % index)
        self.assertEqual(self.machine.pending_changes, 0)
        outcome = self.worker.run_once(max_batch=2)
        self.assertEqual(outcome.applied, 2)
        self.assertEqual(self.machine.pending_changes, 2)
        self.assertEqual(self.outbox.pending_count, 2)
        self.worker.run_once()
        self.assertEqual(self.machine.pending_changes, 0)

    def test_a_refresh_renews_the_lease_and_fires_auth_ok(self):
        before = self.lease.granted_at
        self.advance(60)
        self.vault.clear_access()
        self.client.bootstrap()
        self.assertGreater(self.lease.granted_at, before)

    def test_bind_and_unbind_restore_the_client_hooks(self):
        removed = self.worker.unbind_auth((None, None))
        self.assertTrue(all(callable(hook) for hook in removed),
                        "bind_auth must hand back what it replaced")
        self.assertIsNone(self.client.on_auth_ok)
        self.assertIsNone(self.client.on_auth_failed)
        previous = self.worker.bind_auth()
        self.assertEqual(previous, (None, None))
        self.assertTrue(callable(self.client.on_auth_ok))
        self.assertTrue(callable(self.client.on_auth_failed))

    def test_a_bug_in_the_batch_is_settled_then_propagated(self):
        self.queue()

        class Exploding(object):
            def push(self, operations):
                raise RuntimeError("unexpected client bug")

        worker = self.new_worker(machine=self.machine, lease=self.lease)
        real_client = worker.client
        worker.client = Exploding()
        try:
            with self.assertRaises(RuntimeError):
                worker.run_once()
        finally:
            worker.client = real_client
        self.assertEqual(self.machine.state, SyncState.IDLE,
                         "the machine must not be stranded in syncing")
        self.assertEqual(worker.outbox.parked_count, 1)
        self.assertEqual(worker.outbox.pending_count, 0)


# =====================================================================
# Batch ordering and unresolved references (workstream B integration)
# =====================================================================
class TestBatchOrder(ApiCase):
    """A batch must arrive parent-first, or the host rejects the transaction."""

    def operation(self, entity, identifier, **overrides):
        operation = {"kind": "upsert", "entity": entity, "id": identifier,
                     "base_version": 0, "record": {"name": identifier}}
        operation.update(overrides)
        return operation

    def test_the_dependency_graph_is_read_from_the_mapper(self):
        self.assertEqual(set(REFERENCE_FIELDS),
                         {"crm_devices", "customer_transactions", "settings"})
        self.assertEqual(REFERENCE_FIELDS["crm_devices"],
                         {"customer_id": "customers", "owner_id": "owners",
                          "period_id": "periods"})

    def test_push_order_puts_every_parent_before_its_child(self):
        child_first = [
            self.operation("customer_transactions", "tx-1"),
            self.operation("settings", "settings/settings"),
            self.operation("crm_devices", "dev-1"),
            self.operation("owners", "own-1"),
            self.operation("customers", "cus-1"),
            self.operation("periods", "per-1"),
            self.operation("identities", "ide-1"),
        ]
        ordered = [item["entity"] for item in push_order(child_first)]
        for entity, targets in REFERENCE_FIELDS.items():
            if entity not in ordered:
                continue
            for target in targets.values():
                if target in ordered:
                    self.assertLess(ordered.index(target),
                                    ordered.index(entity),
                                    "%s must precede %s" % (target, entity))
        self.assertIn("customers", ordered)
        self.assertIn("identities", ordered)

    def test_push_order_keeps_rows_of_one_entity_in_caller_order(self):
        operations = [self.operation("customers", "cus-2"),
                      self.operation("customers", "cus-1"),
                      self.operation("crm_devices", "dev-1"),
                      self.operation("customers", "cus-3")]
        ordered = [item["id"] for item in push_order(operations)]
        self.assertEqual(ordered, ["cus-2", "cus-1", "cus-3", "dev-1"])

    def test_the_batch_that_reaches_the_host_is_ordered(self):
        self.enrol()
        self.client.bootstrap()
        self.api.requests.clear()
        self.client.push([
            self.operation("customer_transactions", "tx-1"),
            self.operation("crm_devices", "dev-1"),
            self.operation("owners", "own-1"),
            self.operation("customers", "cus-1"),
        ])
        call = self.api.calls("POST /sync/mutations")[0]
        self.assertEqual(call["entities"], ["owners", "customers", "crm_devices",
                                            "customer_transactions"])

    def test_the_outbox_drives_the_same_ordered_batch(self):
        self.enrol()
        self.client.bootstrap()
        self.api.requests.clear()
        worker = self.new_worker()
        for entity, identifier in (("customer_transactions", "tx-1"),
                                   ("crm_devices", "dev-1"),
                                   ("customers", "cus-1"),
                                   ("owners", "own-1")):
            worker.outbox.enqueue(self.operation(entity, identifier))
        worker.run_once()
        call = self.api.calls("POST /sync/mutations")[0]
        seen = call["entities"]
        self.assertEqual(sorted(seen), sorted(["customers", "owners",
                                               "crm_devices",
                                               "customer_transactions"]))
        self.assertLess(seen.index("customers"), seen.index("crm_devices"))
        self.assertLess(seen.index("owners"), seen.index("crm_devices"))
        self.assertLess(seen.index("crm_devices"),
                        seen.index("customer_transactions"))

    def test_pull_changes_arrive_in_ascending_seq_order(self):
        self.enrol()
        for index in range(5):
            self.api.seed("customers", "cus%d" % index, {"name": "c"})
        self.config.set_cursor(0)
        self.config.save()
        seen = []
        self.client.pull_all(
            lambda page: seen.extend(change["seq"]
                                     for change in page["changes"]), limit=2)
        self.assertEqual(seen, sorted(seen))
        self.assertEqual(len(seen), 5)

    def test_a_page_that_goes_backwards_is_refused(self):
        self.enrol()
        self.api.fail_next("GET /sync/changes", 200, HTTP_500, count=1,
                           body={"ok": True, "cursor": 9, "has_more": False,
                                 "changes": [
                                     {"entity": "customers", "id": "c1",
                                      "seq": 9, "record": {}},
                                     {"entity": "owners", "id": "o1",
                                      "seq": 4, "record": {}}]})
        with self.assertRaises(BadResponseError):
            self.client.pull(0, 10)

    def test_an_unresolved_reference_stops_the_page_and_keeps_the_cursor(self):
        self.enrol()
        for index in range(3):
            self.api.seed("customers", "cus%d" % index, {"name": "c"})
        self.config.set_cursor(0)
        self.config.save()

        def handler(page):
            raise UnresolvedReferenceError("wire foreign key unresolvable")

        with self.assertRaises(UnresolvedReferenceCloudError) as caught:
            self.client.pull_all(handler, limit=2)
        self.assertEqual(caught.exception.code, UNRESOLVED_REFERENCE)
        self.assertIsInstance(caught.exception.__cause__,
                              UnresolvedReferenceError)
        self.assertEqual(self.config.cursor, 0,
                         "the cursor must not move past a failed page")

    def test_an_unresolved_reference_is_wrapped_with_a_stable_code(self):
        wrapped = _wrap_unexpected(
            UnresolvedReferenceError("wire foreign key unresolvable"))
        self.assertIsInstance(wrapped, UnresolvedReferenceCloudError)
        self.assertEqual(wrapped.code, UNRESOLVED_REFERENCE)
        assert_no_secret(self, str(wrapped), "exception text")


# =====================================================================
# The fake itself: swapability and loopback-only binding
# =====================================================================
class TestFakeApi(unittest.TestCase):

    def test_the_fake_binds_loopback_only(self):
        api = fake_api.FakeApi().start()
        self.addCleanup(api.stop)
        host, port = api.base_url.split("//")[1].split(":")[0], api.port
        self.assertEqual(host, "127.0.0.1")
        self.assertGreater(port, 0)
        self.assertNotEqual(port, 443)

    def test_irica_test_api_base_is_honoured_in_one_place(self):
        with fake_api.with_local_api():
            handle = fake_api.acquire()
            try:
                self.assertFalse(handle.external)
                self.assertIsNotNone(handle.fake)
            finally:
                handle.close()
        with patch.dict(os.environ,
                        {fake_api.EXTERNAL_ENV: "https://api.example.test/v1"}):
            handle = fake_api.acquire()
            try:
                self.assertTrue(handle.external)
                self.assertIsNone(handle.fake)
                self.assertEqual(handle.base_url,
                                 "https://api.example.test/v1")
            finally:
                handle.close()

    def test_a_scripted_scenario_skips_against_a_real_server(self):
        holder = unittest.TestCase()
        with patch.dict(os.environ,
                        {fake_api.EXTERNAL_ENV: "https://api.example.test/v1"}):
            with self.assertRaises(unittest.SkipTest):
                fake_api.start_api(holder, needs_fake=True)
        # …but a scenario that only needs a reachable base URL still runs.
        with patch.dict(os.environ,
                        {fake_api.EXTERNAL_ENV: "https://api.example.test/v1"}):
            handle = fake_api.start_api(unittest.TestCase(), needs_fake=False)
            handle.close()
            self.assertTrue(handle.external)

    def test_the_fake_only_speaks_fake_credentials(self):
        self.assertEqual(fake_api.FAKE_PASSWORD, "FAKE-admin-password-not-real")
        self.assertTrue(fake_api.FAKE_PASSWORD.startswith("FAKE-"))
        api = fake_api.FakeApi().start()
        self.addCleanup(api.stop)
        self.assertIn(fake_api.FAKE_USERNAME, api.users)
        self.assertNotIn("password", api.base_url)

    def test_the_envelope_always_carries_the_canary_in_a_message(self):
        api = fake_api.FakeApi().start()
        self.addCleanup(api.stop)
        status, payload = fake_api.error_envelope(500, HTTP_500)
        self.assertEqual(status, 500)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], HTTP_500)
        self.assertIn(CANARY, payload["error"]["message"])
        self.assertTrue(re.fullmatch(
            r"[0-9a-f-]{36}", payload["error"]["request_id"]))


if __name__ == "__main__":
    unittest.main()
