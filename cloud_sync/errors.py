# -*- coding: utf-8 -*-
"""Typed errors and the stable error-code set of the sync client (spec §6, §9, §11).

Two hard rules shape everything in this module:

* **A code, never a sentence.** The panel maps ``error.code`` to its Persian
  wording (spec §11), so the UI never shows a server string. Every code here
  therefore passes the grammar of manager ruling 8 --
  ``^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$``, at most 40 characters -- which makes a
  phone number, an e-mail or a token structurally impossible to emit.
* **Nothing sensitive in the text.** ``str()`` and ``repr()`` of every error
  are built only from the code, the route, the HTTP status, the attempt count
  and the server's ``request_id``. The server's ``error.message`` is parsed
  only far enough to decide whether it carried a *valid code*; it is then
  discarded. Nothing here ever carries an ``Authorization`` header, a token, a
  password, a request body or PII (spec §5).

The grammar itself is imported from :mod:`cloud_sync.state` rather than
re-declared: workstream A owns that definition and one pattern that two modules
disagree about is exactly the drift this project is trying to remove.
"""
import datetime
import math
import re
import time

from email.utils import parsedate_to_datetime

import requests

from cloud_sync.state import ERROR_CODE_RE, KNOWN_ERROR_CODES, MAX_CODE_LENGTH

__all__ = [
    # grammar
    "ERROR_CODE_RE", "MAX_CODE_LENGTH", "is_valid_code", "client_error_codes",
    # codes
    "AUTH_REQUIRED", "AUTH_EXPIRED", "AUTH_REVOKED", "ENROL_REQUIRED",
    "BAD_PAYLOAD", "VERSION_CONFLICT", "HTTP_400", "HTTP_403", "HTTP_404",
    "HTTP_409", "HTTP_429", "HTTP_500", "HTTP_ERROR", "SERVER_ERROR",
    "NET_TIMEOUT", "NET_UNREACHABLE", "QUEUE_FULL", "LEASE_EXPIRED",
    "IMPORT_REJECTED", "CONFIG_INVALID", "SECRET_UNAVAILABLE",
    "TRANSITION_NOT_LEGAL", "REMOTE_NOT_READY", "BOOTSTRAP_REQUIRED",
    "DATASET_EPOCH_MISMATCH",
    # helpers
    "code_for_status", "is_retryable", "parse_retry_after",
    "envelope_code", "safe_request_id", "safe_code",
    # errors
    "CloudSyncError", "TransportError", "RequestTimeoutError",
    "UnreachableError", "HttpError", "AuthError", "AuthRequiredError",
    "AuthExpiredError", "AuthRevokedError", "BadResponseError",
    "RequestValidationError", "ConfigError", "SecretStoreError",
    "QueueFullError", "UnresolvedReferenceCloudError", "RemoteNotReadyError",
    "BootstrapRequiredError", "DatasetEpochMismatchError",
]

# =====================================================================
# The code set (manager ruling 8: allowlist-shaped grammar)
# =====================================================================

#: The access token is missing, expired after a refresh attempt, or the whole
#: token family was revoked. Spec §9: surface this and stop.
AUTH_REQUIRED = "AUTH_REQUIRED"
#: Refresh was refused (expired / rotated away) — a refresh may still help.
AUTH_EXPIRED = "AUTH_EXPIRED"
#: Reuse detection fired: a previously used refresh token was replayed and the
#: server invalidated the family (spec §5).
AUTH_REVOKED = "AUTH_REVOKED"
#: No device enrolment on record; ``POST /sync-devices/enroll`` is required.
ENROL_REQUIRED = "ENROL_REQUIRED"

#: A request or response body did not parse, or the server rejected it as
#: malformed (HTTP 400).
BAD_PAYLOAD = "BAD_PAYLOAD"
#: A whole-request 409 that is not a per-row version conflict (e.g. import).
VERSION_CONFLICT = "VERSION_CONFLICT"
HTTP_400 = "HTTP_400"
HTTP_403 = "HTTP_403"
HTTP_404 = "HTTP_404"
HTTP_409 = "HTTP_409"
HTTP_429 = "HTTP_429"
HTTP_500 = "HTTP_500"
#: Any other 4xx the server did not label itself.
HTTP_ERROR = "HTTP_ERROR"
#: A 5xx (or a success body that was not an envelope) with no usable code.
SERVER_ERROR = "SERVER_ERROR"

#: The request never completed inside its deadline.
NET_TIMEOUT = "NET_TIMEOUT"
#: DNS, TCP or TLS could not be established.
NET_UNREACHABLE = "NET_UNREACHABLE"

#: The durable queue refused another operation (spec §9, ruling 10): a code,
#: never a ninth state and never a silent truncation.
QUEUE_FULL = "QUEUE_FULL"
#: The 7-day offline lease ran out (spec §5).
LEASE_EXPIRED = "LEASE_EXPIRED"
#: The one-shot import was rejected by the host (spec §8).
IMPORT_REJECTED = "IMPORT_REJECTED"

#: The transport configuration on disk is unusable.
CONFIG_INVALID = "CONFIG_INVALID"
#: The OS secret store refused to protect or read the device refresh token.
#: There is deliberately no plaintext fallback (spec §5).
SECRET_UNAVAILABLE = "SECRET_UNAVAILABLE"
#: A state-machine event was refused in the current state and was recorded
#: instead of being swallowed (manager ruling 12).
TRANSITION_NOT_LEGAL = "TRANSITION_NOT_LEGAL"
#: A wire foreign key cannot be turned back into a local legacy id: the
#: parent does not exist on this machine (spec §4, workstream B's
#: ``UnresolvedReferenceError``). Fail closed — the unresolved UUID is never
#: written to ``crm_store.json``, which the robots read.
UNRESOLVED_REFERENCE = "UNRESOLVED_REFERENCE"
#: The server dataset is not seeded or bootstrap is not marked done.
#: The local non-empty store must not be wiped by an empty server snapshot.
REMOTE_NOT_READY = "REMOTE_NOT_READY"
#: This device has not durably applied a bootstrap snapshot yet.
BOOTSTRAP_REQUIRED = "BOOTSTRAP_REQUIRED"
#: The server identifies a different dataset generation than the one
#: this local cache was materialized from. Never auto-adopt it.
DATASET_EPOCH_MISMATCH = "DATASET_EPOCH_MISMATCH"

#: Everything this client may emit. Includes every code workstream A documented
#: as client-produced, plus the ones this transport needs on its own.
CLIENT_ERROR_CODES = frozenset({
    AUTH_REQUIRED, AUTH_EXPIRED, AUTH_REVOKED, ENROL_REQUIRED,
    BAD_PAYLOAD, VERSION_CONFLICT,
    HTTP_400, HTTP_403, HTTP_404, HTTP_409, HTTP_429, HTTP_500, HTTP_ERROR,
    SERVER_ERROR, NET_TIMEOUT, NET_UNREACHABLE,
    QUEUE_FULL, LEASE_EXPIRED, IMPORT_REJECTED,
    CONFIG_INVALID, SECRET_UNAVAILABLE, TRANSITION_NOT_LEGAL,
    UNRESOLVED_REFERENCE, REMOTE_NOT_READY, BOOTSTRAP_REQUIRED,
    DATASET_EPOCH_MISMATCH,
})


#: A ``request_id`` comes off the wire, so it is kept only when it is the
#: UUID §6 says it is. Anything else is dropped rather than stored: a server
#: that puts a token in the field must not get it into a log or an exception.
_REQUEST_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def is_valid_code(value):
    """Whether `value` is a string that fits manager ruling 8's grammar."""
    return (isinstance(value, str) and len(value) <= MAX_CODE_LENGTH
            and ERROR_CODE_RE.match(value) is not None)


def safe_request_id(value):
    """A UUID `value`, or "" — never an arbitrary server string."""
    if isinstance(value, str) and _REQUEST_ID_RE.match(value):
        return value
    return ""


def client_error_codes():
    """A frozen view of the codes this module defines (sorted for messages)."""
    return tuple(sorted(CLIENT_ERROR_CODES))


# Fail at import time rather than at 3 a.m. with a code the UI cannot map.
for _code in CLIENT_ERROR_CODES:              # noqa: N806
    if not is_valid_code(_code):              # pragma: no cover - import guard
        raise ValueError("error code %r does not match the client grammar"
                         % (_code,))
# Workstream A documented which codes it expects the client to produce; if a
# future edit drops one, the panel would map it to nothing (spec §11).
_MISSING_FROM_CLIENT = KNOWN_ERROR_CODES - CLIENT_ERROR_CODES
if _MISSING_FROM_CLIENT:                      # pragma: no cover - import guard
    raise ValueError("client code set is missing documented codes: %s"
                     % ", ".join(sorted(_MISSING_FROM_CLIENT)))


# =====================================================================
# Classification helpers
# =====================================================================
_STATUS_CODES = {
    400: HTTP_400,
    403: HTTP_403,
    404: HTTP_404,
    409: HTTP_409,
    429: HTTP_429,
}


def code_for_status(status):
    """The stable code for an HTTP status the server did not label itself."""
    if status in _STATUS_CODES:
        return _STATUS_CODES[status]
    if status is None:
        return SERVER_ERROR
    try:
        numeric = int(status)
    except (TypeError, ValueError):
        return SERVER_ERROR
    if 500 <= numeric <= 599:
        return HTTP_500
    if 400 <= numeric <= 499:
        return HTTP_ERROR
    return SERVER_ERROR


def safe_code(value):
    """A stable code `value`, or "" — never an arbitrary server string."""
    if is_valid_code(value):
        return value
    return ""


def envelope_code(payload, status):
    """Pull a *usable* code out of a failure envelope, else synthesize one.

    The server's ``message`` is never returned: only the code is examined, and
    anything that does not pass the grammar is ignored in favour of the status
    mapping. A hostile or careless server therefore cannot smuggle text into
    the panel through this path.
    """
    error = payload.get("error") if isinstance(payload, dict) else None
    candidate = error.get("code") if isinstance(error, dict) else None
    if is_valid_code(candidate) and candidate in CLIENT_ERROR_CODES:
        return candidate
    if is_valid_code(candidate):
        # A server code we have never seen but which fits the grammar: accept
        # it, because the whole point of the grammar is that it is safe to
        # forward (spec §6: the client maps `code`, never `message`).
        return candidate
    return code_for_status(status)


def is_retryable(error):
    """Whether a failed call may be attempted again (spec §9).

    Only timeouts, connection failures, ``429`` and ``500-599`` qualify.
    ``400``, ``403`` and ``409`` never do: repeating them changes nothing and
    hides the real fault.
    """
    if isinstance(error, CloudSyncError):
        return bool(error.retryable)
    if isinstance(error, requests.Timeout):          # Connect/Read timeout
        return True
    if isinstance(error, requests.ConnectionError):
        return True
    if isinstance(error, requests.RequestException):
        return False
    return False


def parse_retry_after(value, now=None):
    """Seconds to wait from a ``Retry-After`` header, or None.

    Accepts both forms RFC 9110 allows -- delta-seconds and an HTTP-date --
    and rejects anything negative or non-finite. The returned value is a plain
    number of seconds so the backoff arithmetic never has to parse a header
    again.
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except ValueError:
        try:
            moment = parsedate_to_datetime(text)
        except (TypeError, ValueError, OverflowError):
            return None
        if moment is None:
            return None
        if moment.tzinfo is None:
            # HTTP-date is GMT; a naive date means the sender omitted it.
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        base = datetime.datetime.fromtimestamp(
            time.time() if now is None else now, datetime.timezone.utc)
        seconds = (moment - base).total_seconds()
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return seconds


# =====================================================================
# The error hierarchy
# =====================================================================
class CloudSyncError(Exception):
    """Base for everything this transport raises.

    Never constructed with free text: the text is derived from the code and
    the safe request metadata, so an accidental ``str(err)`` in a log cannot
    leak a token or a server message.
    """

    #: The stable code the panel maps (spec §11). Subclasses override it.
    code = SERVER_ERROR
    #: Overridden by subclasses whose retryability depends on the status.
    retryable = False

    def __init__(self, *, code=None, route=None, status=None,
                 request_id=None, retry_after=None, attempts=None):
        if code is not None:
            if not is_valid_code(code):
                # Deliberately does not echo `code`: a rejected code may be a
                # token that reached this constructor by mistake.
                raise ValueError("error code must match %s and be <= %d chars"
                                 % (ERROR_CODE_RE.pattern, MAX_CODE_LENGTH))
            self.code = code
        else:
            self.code = type(self).code
        self.route = route
        self.status = status
        self.request_id = safe_request_id(request_id)
        self.retry_after = retry_after
        self.attempts = attempts
        super().__init__(self._describe())

    def _describe(self):
        parts = [self.code]
        if self.route:
            parts.append("route=%s" % self.route)
        if self.status is not None:
            parts.append("status=%s" % self.status)
        if self.attempts is not None:
            parts.append("attempts=%s" % self.attempts)
        if self.request_id:
            parts.append("request_id=%s" % self.request_id)
        return " ".join(parts)


class TransportError(CloudSyncError):
    """The request never reached the server (timeout / connection)."""

    retryable = True


class RequestTimeoutError(TransportError):
    """The server did not answer inside the deadline."""

    code = NET_TIMEOUT


class UnreachableError(TransportError):
    """DNS, TCP or TLS failed before any response existed."""

    code = NET_UNREACHABLE


class HttpError(CloudSyncError):
    """The server answered, and the answer was not a success.

    ``retryable`` is derived from the status so ``400``/``403``/``409`` are
    never retried blindly while ``429`` and ``5xx`` are (spec §9).
    """

    def __init__(self, *, code=None, route=None, status=None,
                 request_id=None, retry_after=None, attempts=None,
                 code_source="status"):
        super().__init__(code=code, route=route, status=status,
                         request_id=request_id, retry_after=retry_after,
                         attempts=attempts)
        #: "envelope" when the server named the code, "status" when we mapped it.
        self.code_source = code_source

    @property
    def retryable(self):
        if self.status == 429:
            return True
        return self.status is not None and 500 <= self.status <= 599


class AuthError(CloudSyncError):
    """Authentication could not be established or was rejected."""

    code = AUTH_REQUIRED


class AuthRequiredError(AuthError):
    """Spec §9: one refresh, one retry, then this — and stop.

    ``event_fired`` is set by :class:`cloud_sync.auth.TokenVault`'s caller when
    a wired ``on_auth_failed`` callback already reported the fault to the state
    machine, so a batch attempt still fires **exactly one** outcome (manager
    ruling 12).
    """

    code = AUTH_REQUIRED

    def __init__(self, *, code=AUTH_REQUIRED, fired=False, **kwargs):
        self.event_fired = fired
        super().__init__(code=code, **kwargs)


class AuthExpiredError(AuthRequiredError):
    code = AUTH_EXPIRED


class AuthRevokedError(AuthRequiredError):
    code = AUTH_REVOKED


class BadResponseError(CloudSyncError):
    """A 2xx body that is not the documented envelope (spec §6)."""

    code = BAD_PAYLOAD


class RequestValidationError(CloudSyncError):
    """The caller built a request the contract does not allow."""

    code = BAD_PAYLOAD


class ConfigError(CloudSyncError):
    """``cloud_config.json`` is missing, unreadable or unsafe."""

    code = CONFIG_INVALID


class SecretStoreError(CloudSyncError):
    """The OS secret store could not protect or read the refresh token.

    There is no plaintext fallback: a failure here stops the call rather than
    writing the token to disk in the clear (spec §5).
    """

    code = SECRET_UNAVAILABLE


class UnresolvedReferenceCloudError(CloudSyncError):
    """A row references a parent this machine cannot resolve (spec §4).

    Raised at the pull boundary so the page is not applied and the cursor is
    not advanced; the underlying mapping error stays available as ``__cause__``
    for diagnostics, but the panel only ever sees this stable code (§11).
    """

    code = UNRESOLVED_REFERENCE


class QueueFullError(CloudSyncError):
    """The durable outbox refused another entry (spec §9, ruling 10)."""

    code = QUEUE_FULL


class RemoteNotReadyError(CloudSyncError):
    """The server dataset is empty or unseeded while local store has records.

    Raised at the snapshot apply boundary to prevent destroying local CRM data.
    """

    code = REMOTE_NOT_READY


class BootstrapRequiredError(CloudSyncError):
    """A device must materialize the authoritative snapshot before push/pull."""

    code = BOOTSTRAP_REQUIRED


class DatasetEpochMismatchError(CloudSyncError):
    """The remote dataset generation differs from the local cache authority."""

    code = DATASET_EPOCH_MISMATCH
