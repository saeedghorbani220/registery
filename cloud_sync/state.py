# -*- coding: utf-8 -*-
"""The explicit sync state machine the panel runs in (workstream A).

Contract: `lab/docs/CLOUD_SYNC_SPEC.md` — §5 (auth + offline lease), §9
(client behaviour and the observable sync state), §11 (status surface), §13
(file ownership).

Before cloud sync nothing in the project had a notion of sync state, so any
code that "kept going" could leave the status surface describing something
that was not true: syncing with no worker, writable with an expired lease,
enrolled with no device. This module makes every situation an explicit
``SyncState`` and every change an explicit ``SyncEvent``:

* the legal pairs are data, not control flow — ``TRANSITIONS``. Anything not
  listed raises :class:`IllegalTransitionError`; there is no default branch,
  so an impossible situation fails loudly instead of being absorbed.
* the observables §9 asks for live here: last successful sync, pending change
  count, conflict count, last error code.
* the machine serialises to a plain JSON-safe dict and restores from one, so
  a panel restart resumes in a known state; anything unknown or malformed on
  disk fails **closed** to ``DISABLED`` or ``NOT_ENROLLED`` — never to
  ``SYNCING``, which would describe a worker that does not exist.
* the clock and the counters are owned here: no ``time.monotonic()`` and no
  sleep anywhere, so the boundaries are exact under an injected clock.

Kinds of event
--------------
``NETWORK_LOST``, ``AUTH_FAILED``, ``LEASE_EXPIRED`` and ``CONFLICT_FOUND``
are **faults**: each moves the machine into its own fault state and is
idempotent when that fault already governs (an expired lease does not become
"offline" just because the socket dropped, and a dropped socket does not
clear an expired lease).

``NETWORK_RESTORED``, ``AUTH_OK`` and ``CONFLICTS_RESOLVED`` are
**recoveries**: each clears exactly one fault and is a harmless no-op when
that fault is not held, so a monitor may report a condition the machine never
recorded without being able to clear a *different* fault.

``SYNC_OK`` / ``SYNC_FAILED`` are **progress** events of one in-flight batch.
They are legal from ``SYNCING`` (the normal case) and from ``CONFLICT`` (the
batch completed and reported conflicts — firing either order with
``CONFLICT_FOUND`` must work), and illegal from every fault state: if a
fault ended the attempt, that fault is the outcome.

Wiring
------
* Fire ``AUTH_OK`` exactly where :meth:`cloud_sync.lease.OfflineLease.grant`
  runs (spec §5: the lease counts from the last successful authentication);
  both mean "authentication succeeded, lease granted", which is why either
  one may leave ``READ_ONLY``.
* Fire ``LEASE_EXPIRED`` when ``lease.assert_writable()`` refuses an edit.
* Call :meth:`SyncStateMachine.save` after transitions that must survive a
  restart; if the file is never written the next start is a fresh, safely
  un-enrolled machine.
* Writability itself is the lease's call (§5), never this machine's: the
  panel asks ``lease.assert_writable()``, and ``READ_ONLY`` is the mirror of
  that fact for the status surface.

Error codes
-----------
``last_error_code`` holds a short uppercase identifier matching
``^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`` (at most 40 characters) and nothing else:
a message, a request id, a password, a token or any other free text is
rejected by :func:`validate_error_code`, which never echoes the value it
refused. The Persian wording for each code is the UI's job (spec §11).
"""
import json
import os
import re
import time
from datetime import datetime, timezone
from enum import Enum

import app_paths

SCHEMA_VERSION = 1

#: File the machine persists to, inside the data directory (spec §5).
STATE_FILE_NAME = "cloud_sync_state.json"

#: A restore file larger than this is treated as unreadable, not parsed.
_MAX_JSON_BYTES = 64 * 1024


# =====================================================================
# Stable codes
# =====================================================================
ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
MAX_CODE_LENGTH = 40

#: The lease's refusal code. It lives here because it is also a value of
#: `last_error_code`; cloud_sync.lease re-exports it at its raise site.
LEASE_EXPIRED_CODE = "LEASE_EXPIRED"

#: Codes the client is expected to produce. Documented, not enforced: any
#: code that fits the format is accepted so a new server code cannot wedge
#: the panel, and the UI maps what it knows.
KNOWN_ERROR_CODES = frozenset({
    "AUTH_EXPIRED", "AUTH_REVOKED", "BAD_PAYLOAD", "BOOTSTRAP_REQUIRED",
    "DATASET_EPOCH_MISMATCH", "HTTP_409", "HTTP_429",
    "HTTP_500", "IMPORT_REJECTED", LEASE_EXPIRED_CODE, "NET_TIMEOUT",
    "NET_UNREACHABLE", "QUEUE_FULL", "REMOTE_NOT_READY", "SERVER_ERROR",
    "VERSION_CONFLICT",
})

#: Why a restored machine is not what was on disk, or why a transition was
#: refused. Stable identifiers; never a sentence, never operator data.
REASON_MALFORMED = "MALFORMED_STATE"
REASON_UNKNOWN = "UNKNOWN_STATE"
REASON_UNREADABLE = "UNREADABLE_STATE"
REASON_INTERRUPTED = "INTERRUPTED_SYNC"
REASON_INCONSISTENT = "INCONSISTENT_STATE"
REASON_NOT_LEGAL = "TRANSITION_NOT_LEGAL"
REASON_NO_CONFLICT = "NO_PENDING_CONFLICT"


def validate_error_code(value, field="error_code"):
    """Return a stable code, or raise ValueError without echoing `value`.

    The refusal message names the field and the accepted shape only: the
    rejected value may be a token, a phone number or an operator identifier
    and must not reach a message, a log or a state dict.
    """
    if not isinstance(value, str) or len(value) > MAX_CODE_LENGTH \
            or not ERROR_CODE_RE.match(value):
        raise ValueError("%s must be a stable code matching %s"
                         % (field, ERROR_CODE_RE.pattern))
    return value


def _optional_code(value, field="error_code"):
    """None stays None; anything else must be a stable code."""
    if value is None:
        return None
    return validate_error_code(value, field)


# =====================================================================
# The state set and the event set
# =====================================================================
class SyncState(Enum):
    """Every situation the sync can be in. Nothing outside this set exists."""

    #: No device enrolment on record (spec §5) — the safe starting point.
    NOT_ENROLLED = "not_enrolled"
    #: Enrolled, nothing in flight, nothing wrong.
    IDLE = "idle"
    #: A batch is in flight; exactly one outcome or fault is still owed.
    SYNCING = "syncing"
    #: The network is unreachable; no batch can start or finish.
    OFFLINE = "offline"
    #: Server rows conflict with local ones and await the operator (§9/§11).
    CONFLICT = "conflict"
    #: The access token is invalid or revoked; the worker has stopped (§9).
    AUTH_REQUIRED = "auth_required"
    #: The 7-day offline lease ran out: reads work, local edits are refused.
    READ_ONLY = "read_only"
    #: Switched off by the operator (or failed closed on a bad restore).
    DISABLED = "disabled"


class SyncEvent(Enum):
    """Every change the machine accepts. Unknown names raise, never default."""

    #: Enrolment succeeded (spec §5) — the only way out of NOT_ENROLLED.
    ENROL = "enrol"
    #: The push/pull worker claimed a batch.
    START_SYNC = "start_sync"
    #: That batch finished and was applied.
    SYNC_OK = "sync_ok"
    #: That batch failed for a reason that is neither network, auth nor conflict.
    SYNC_FAILED = "sync_failed"
    NETWORK_LOST = "network_lost"
    NETWORK_RESTORED = "network_restored"
    #: A refresh attempt failed, or the device is revoked (spec §5, §9).
    AUTH_FAILED = "auth_failed"
    #: Authentication succeeded — the lease is granted here (spec §5).
    AUTH_OK = "auth_ok"
    #: The server answered 409 VERSION_CONFLICT for at least one row (§6.1).
    CONFLICT_FOUND = "conflict_found"
    #: The operator chose a side for pending conflict(s) (§11).
    CONFLICTS_RESOLVED = "conflicts_resolved"
    #: The 7-day offline lease ran out (spec §5).
    LEASE_EXPIRED = "lease_expired"
    DISABLE = "disable"
    ENABLE = "enable"


#: Transition targets that are not a state: each is resolved per call from
#: the observables, so the table stays free of conditional branches.
TARGET_RECOVER = "<recover>"    # healthy again: CONFLICT if any is pending
TARGET_RESOLVE = "<resolve>"    # last conflict gone: IDLE, else stay put
TARGET_RESUME = "<resume>"      # ENABLE: back to where DISABLE was pressed

_STATES = tuple(SyncState)
_EVENTS = tuple(SyncEvent)
_STATE_BY_VALUE = {s.value: s for s in _STATES}
_EVENT_BY_VALUE = {e.value: e for e in _EVENTS}
_RECOVERY_EVENTS = frozenset({
    SyncEvent.SYNC_OK, SyncEvent.NETWORK_RESTORED, SyncEvent.AUTH_OK,
})


class UnknownEventError(Exception):
    """The caller passed something that is not a :class:`SyncEvent`.

    Deliberately carries no echo of what was passed: a bad event name may be
    a token or an operator identifier.
    """


class IllegalTransitionError(Exception):
    """The event is real but not legal in this state — always a bug.

    Raised, never swallowed and never defaulted away: the panel must not be
    able to drift into a state its own table does not describe.
    """

    def __init__(self, state, event, reason=REASON_NOT_LEGAL):
        self.state = state
        self.event = event
        self.reason = reason
        super().__init__("illegal sync transition %s -> %s (%s)"
                         % (state.value, event.value, reason))


# =====================================================================
# The table: legal (state, event) pairs, exhaustively
# =====================================================================
# A missing pair is illegal and raises. Four rules explain every absence:
#   * a fault is cleared only by its own recovery, never by an unrelated
#     event, so an expired lease cannot be talked out of READ_ONLY by a
#     socket that came back — and a live fault is never downgraded by an
#     unrelated one (network status cannot mask authentication or the lease);
#   * a batch cannot start where it could not run: offline, auth-required,
#     read-only, already syncing, un-enrolled or disabled;
#   * an outcome belongs to an in-flight batch, so it is legal from SYNCING
#     and from CONFLICT (conflicts reported by that same batch) and nowhere
#     else;
#   * enrol, disable and enable each describe exactly one side of a switch.
TRANSITIONS = {
    SyncState.NOT_ENROLLED: {
        SyncEvent.ENROL: TARGET_RECOVER,
        SyncEvent.DISABLE: SyncState.DISABLED,
    },
    SyncState.IDLE: {
        SyncEvent.START_SYNC: SyncState.SYNCING,
        SyncEvent.NETWORK_LOST: SyncState.OFFLINE,
        SyncEvent.NETWORK_RESTORED: SyncState.IDLE,
        SyncEvent.AUTH_FAILED: SyncState.AUTH_REQUIRED,
        SyncEvent.AUTH_OK: SyncState.IDLE,
        SyncEvent.CONFLICT_FOUND: SyncState.CONFLICT,
        SyncEvent.LEASE_EXPIRED: SyncState.READ_ONLY,
        SyncEvent.DISABLE: SyncState.DISABLED,
    },
    SyncState.SYNCING: {
        SyncEvent.SYNC_OK: TARGET_RECOVER,
        SyncEvent.SYNC_FAILED: TARGET_RECOVER,
        SyncEvent.NETWORK_LOST: SyncState.OFFLINE,
        SyncEvent.NETWORK_RESTORED: SyncState.SYNCING,
        SyncEvent.AUTH_FAILED: SyncState.AUTH_REQUIRED,
        SyncEvent.AUTH_OK: SyncState.SYNCING,
        SyncEvent.CONFLICT_FOUND: SyncState.CONFLICT,
        SyncEvent.CONFLICTS_RESOLVED: TARGET_RESOLVE,
        SyncEvent.LEASE_EXPIRED: SyncState.READ_ONLY,
        SyncEvent.DISABLE: SyncState.DISABLED,
    },
    SyncState.OFFLINE: {
        SyncEvent.NETWORK_LOST: SyncState.OFFLINE,
        SyncEvent.NETWORK_RESTORED: TARGET_RECOVER,
        SyncEvent.AUTH_FAILED: SyncState.AUTH_REQUIRED,
        SyncEvent.AUTH_OK: SyncState.OFFLINE,
        SyncEvent.CONFLICTS_RESOLVED: TARGET_RESOLVE,
        SyncEvent.LEASE_EXPIRED: SyncState.READ_ONLY,
        SyncEvent.DISABLE: SyncState.DISABLED,
    },
    SyncState.CONFLICT: {
        # The batch that found the conflicts may still report its outcome,
        # in either order with CONFLICT_FOUND.
        SyncEvent.SYNC_OK: TARGET_RECOVER,
        SyncEvent.SYNC_FAILED: TARGET_RECOVER,
        SyncEvent.START_SYNC: SyncState.SYNCING,
        SyncEvent.NETWORK_LOST: SyncState.OFFLINE,
        SyncEvent.NETWORK_RESTORED: SyncState.CONFLICT,
        SyncEvent.AUTH_FAILED: SyncState.AUTH_REQUIRED,
        SyncEvent.AUTH_OK: SyncState.CONFLICT,
        SyncEvent.CONFLICT_FOUND: SyncState.CONFLICT,
        SyncEvent.CONFLICTS_RESOLVED: TARGET_RESOLVE,
        SyncEvent.LEASE_EXPIRED: SyncState.READ_ONLY,
        SyncEvent.DISABLE: SyncState.DISABLED,
    },
    SyncState.AUTH_REQUIRED: {
        # The socket coming back clears nothing: authentication is the fault.
        SyncEvent.NETWORK_LOST: SyncState.AUTH_REQUIRED,
        SyncEvent.NETWORK_RESTORED: SyncState.AUTH_REQUIRED,
        SyncEvent.AUTH_FAILED: SyncState.AUTH_REQUIRED,
        SyncEvent.AUTH_OK: TARGET_RECOVER,
        SyncEvent.CONFLICTS_RESOLVED: TARGET_RESOLVE,
        SyncEvent.LEASE_EXPIRED: SyncState.READ_ONLY,
        SyncEvent.DISABLE: SyncState.DISABLED,
    },
    SyncState.READ_ONLY: {
        # An expired lease outranks the network in both directions: the only
        # way out is a renewed lease (AUTH_OK).
        SyncEvent.NETWORK_LOST: SyncState.READ_ONLY,
        SyncEvent.NETWORK_RESTORED: SyncState.READ_ONLY,
        SyncEvent.AUTH_FAILED: SyncState.AUTH_REQUIRED,
        SyncEvent.AUTH_OK: TARGET_RECOVER,
        SyncEvent.CONFLICTS_RESOLVED: TARGET_RESOLVE,
        SyncEvent.LEASE_EXPIRED: SyncState.READ_ONLY,
        SyncEvent.DISABLE: SyncState.DISABLED,
    },
    SyncState.DISABLED: {
        SyncEvent.ENABLE: TARGET_RESUME,
    },
}


def _coerce_event(event):
    """A SyncEvent (or its wire value); anything else raises, unechoed."""
    if isinstance(event, SyncEvent):
        return event
    if isinstance(event, str):
        found = _EVENT_BY_VALUE.get(event)
        if found is not None:
            return found
    raise UnknownEventError("unknown sync event")


def _coerce_state(value):
    """A SyncState for a wire value, or None — never raises with the value."""
    if isinstance(value, SyncState):
        return value
    if isinstance(value, str):
        return _STATE_BY_VALUE.get(value)
    return None


def write_json_atomic(path, payload):
    """Write `payload` as JSON without ever leaving a half-written file.

    Both files this workstream persists (state and lease) go through it: the
    panel has to restart into a known state, so the data is written to a
    sibling temp file, flushed to disk and renamed over the target.
    `os.replace` is atomic on POSIX and on NTFS. An OSError propagates — a
    write that failed must not look like a write that succeeded.
    """
    directory = os.path.dirname(path) or "."
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _iso(epoch):
    """UTC ISO-8601 with offset (spec §4) for an epoch second."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _parse_iso(value):
    """Canonical UTC ISO-8601 for `value`, or None when it is not one."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


class SyncStateMachine:
    """The sync lifecycle: one explicit state, explicit events, no defaults."""

    def __init__(self, *, clock=None):
        self._clock = clock if clock is not None else time.time
        self._state = SyncState.NOT_ENROLLED
        self._disabled_from = None
        self._last_successful_sync = None
        self._pending_changes = 0
        self._conflict_count = 0
        self._last_error_code = None
        self._restore_reason = ""

    # -- observables (spec §9: last success, pending, conflicts, error) --
    @property
    def state(self):
        return self._state

    @property
    def disabled_from(self):
        """Where DISABLE was pressed from, so ENABLE returns there."""
        return self._disabled_from

    @property
    def last_successful_sync(self):
        """UTC ISO-8601 of the last batch that completed, or None."""
        return self._last_successful_sync

    @property
    def pending_changes(self):
        """Changes waiting in the outbox. Owned by the outbox worker."""
        return self._pending_changes

    @property
    def conflict_count(self):
        """Rows awaiting an operator choice (§9/§11). Never auto-resolved."""
        return self._conflict_count

    @property
    def last_error_code(self):
        """Most recent stable error code, or None. Never a message."""
        return self._last_error_code

    @property
    def restore_reason(self):
        """Why this machine is not exactly what was persisted (or "")."""
        return self._restore_reason

    def set_pending(self, value):
        """Set the outbox depth. Counters are validated, never trusted."""
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("pending_changes must be a non-negative integer")
        self._pending_changes = value
        return value

    def add_pending(self, delta):
        """Move the outbox depth by `delta` (negative drains it)."""
        if isinstance(delta, bool) or not isinstance(delta, int):
            raise ValueError("pending delta must be an integer")
        return self.set_pending(self._pending_changes + delta)

    # -- guards ---------------------------------------------------------
    def can(self, event):
        """Whether `event` is legal right now (UI decides what to offer)."""
        return self._guard(_coerce_event(event)) is None

    def _guard(self, event):
        """The reason `event` is refused here, or None when it is legal."""
        row = TRANSITIONS.get(self._state)
        if row is None or event not in row:
            return REASON_NOT_LEGAL
        if event is SyncEvent.CONFLICTS_RESOLVED and self._conflict_count < 1:
            return REASON_NO_CONFLICT
        return None

    # -- the transition -------------------------------------------------
    def apply(self, event, *, error_code=None, conflicts_cleared=None):
        """Apply `event`; return the resulting state.

        Raises :class:`UnknownEventError` for a name that does not exist and
        :class:`IllegalTransitionError` for a real event that is not legal
        here. There is no fall-through: an unexpected call is an error the
        caller has to see.
        """
        event = _coerce_event(event)
        refused = self._guard(event)
        if refused is not None:
            raise IllegalTransitionError(self._state, event, refused)

        if error_code is not None and event not in (
                SyncEvent.SYNC_FAILED, SyncEvent.AUTH_FAILED):
            raise ValueError("error_code is only valid for SYNC_FAILED "
                             "and AUTH_FAILED")
        cleared = conflicts_cleared
        if event is SyncEvent.CONFLICTS_RESOLVED:
            if cleared is None:
                cleared = 1
            if isinstance(cleared, bool) or not isinstance(cleared, int) \
                    or cleared < 1 or cleared > self._conflict_count:
                raise IllegalTransitionError(self._state, event,
                                             REASON_NO_CONFLICT)
        elif cleared is not None:
            raise ValueError("conflicts_cleared is only valid for "
                             "CONFLICTS_RESOLVED")

        previous = self._state
        resume_from = self._disabled_from   # captured before effects clear it

        # -- effects, in the order the caller experiences them ----------
        if event is SyncEvent.SYNC_OK:
            self._last_successful_sync = _iso(self._clock())
            self._last_error_code = None
        elif event is SyncEvent.SYNC_FAILED:
            if error_code is None:
                raise ValueError("SYNC_FAILED requires error_code=<stable code>")
            self._last_error_code = validate_error_code(error_code)
        elif event is SyncEvent.AUTH_FAILED and error_code is not None:
            self._last_error_code = validate_error_code(error_code)
        elif event is SyncEvent.LEASE_EXPIRED:
            self._last_error_code = LEASE_EXPIRED_CODE
        elif event is SyncEvent.CONFLICT_FOUND:
            self._conflict_count += 1
        elif event is SyncEvent.CONFLICTS_RESOLVED:
            self._conflict_count -= cleared
        elif event is SyncEvent.DISABLE:
            self._disabled_from = previous
        elif event is SyncEvent.ENABLE:
            self._disabled_from = None

        target = TRANSITIONS[previous][event]
        resolved = self._resolve(target, previous, resume_from)
        self._state = resolved

        # A recovery only retires the recorded error when it actually left
        # the fault it cleared; a no-op report must not hide a live error.
        if event in _RECOVERY_EVENTS and resolved is not previous:
            self._last_error_code = None
        return resolved

    def _resolve(self, target, previous, resume_from=None):
        """Turn a table entry (state or token) into the state to enter."""
        if target == TARGET_RECOVER:
            resolved = SyncState.CONFLICT if self._conflict_count else SyncState.IDLE
        elif target == TARGET_RESOLVE:
            if self._conflict_count == 0 and previous is SyncState.CONFLICT:
                resolved = SyncState.IDLE
            else:
                resolved = previous
        elif target == TARGET_RESUME:
            if resume_from is None or resume_from is SyncState.DISABLED:
                resolved = SyncState.NOT_ENROLLED
            else:
                resolved = resume_from
        else:
            resolved = target
        # Invariant, applied to every path: IDLE never carries pending
        # conflicts, whatever the table or a restored payload says.
        if resolved is SyncState.IDLE and self._conflict_count > 0:
            return SyncState.CONFLICT
        return resolved

    # -- persistence ----------------------------------------------------
    def to_dict(self):
        """Plain, JSON-safe snapshot: enum values, ints and codes only."""
        return {
            "version": SCHEMA_VERSION,
            "state": self._state.value,
            "disabled_from": (self._disabled_from.value
                              if self._disabled_from is not None else None),
            "last_successful_sync": self._last_successful_sync,
            "pending_changes": self._pending_changes,
            "conflict_count": self._conflict_count,
            "last_error_code": self._last_error_code,
            "restore_reason": self._restore_reason,
        }

    @classmethod
    def from_dict(cls, payload, *, clock=None):
        """Restore a machine; anything unknown or malformed fails closed.

        * structurally broken (wrong version, wrong types, a code that is not
          a code, a timestamp that is not one) -> ``DISABLED`` with the
          payload **discarded** — untrusted fields are never carried over;
        * well formed but naming a state this build does not know ->
          ``NOT_ENROLLED``, because the only honest reading is "we do not
          know who this machine is";
        * a persisted ``SYNCING`` -> ``IDLE``: the batch did not survive the
          restart, and leaving it would block START_SYNC forever;
        * ``IDLE`` with pending conflicts -> ``CONFLICT``.

        The reason is recorded on the machine; the offending value is not.
        """
        if not isinstance(payload, dict):
            return cls._closed(REASON_MALFORMED, clock)
        version = payload.get("version")
        if type(version) is not int or version != SCHEMA_VERSION:
            return cls._closed(REASON_MALFORMED, clock)

        for key in ("state", "disabled_from", "last_successful_sync",
                    "pending_changes", "conflict_count", "last_error_code",
                    "restore_reason"):
            if key not in payload:
                return cls._closed(REASON_MALFORMED, clock)

        if not isinstance(payload["state"], str):
            return cls._closed(REASON_MALFORMED, clock)
        state = _coerce_state(payload["state"])
        if state is None:
            return cls._unknown_state(clock)

        raw_disabled = payload["disabled_from"]
        disabled_from = None
        if raw_disabled is not None:
            if not isinstance(raw_disabled, str):
                return cls._closed(REASON_MALFORMED, clock)
            disabled_from = _coerce_state(raw_disabled)
            if disabled_from is None:
                return cls._unknown_state(clock)
            if disabled_from is SyncState.DISABLED:
                return cls._closed(REASON_MALFORMED, clock)

        pending = payload["pending_changes"]
        conflicts = payload["conflict_count"]
        for value in (pending, conflicts):
            if isinstance(value, bool) or not isinstance(value, int) \
                    or value < 0:
                return cls._closed(REASON_MALFORMED, clock)

        try:
            error_code = _optional_code(payload["last_error_code"],
                                        "last_error_code")
        except ValueError:
            return cls._closed(REASON_MALFORMED, clock)
        raw_synced = payload["last_successful_sync"]
        synced_at = _parse_iso(raw_synced)
        if raw_synced is not None and synced_at is None:
            return cls._closed(REASON_MALFORMED, clock)
        reason = payload["restore_reason"]
        if not isinstance(reason, str) \
                or (reason and not ERROR_CODE_RE.match(reason)):
            return cls._closed(REASON_MALFORMED, clock)

        machine = cls(clock=clock)
        machine._state = state
        machine._disabled_from = disabled_from if state is SyncState.DISABLED \
            else None
        machine._pending_changes = pending
        machine._conflict_count = conflicts
        machine._last_error_code = error_code
        machine._last_successful_sync = synced_at
        machine._restore_reason = reason

        if state is SyncState.SYNCING:
            machine._state = SyncState.IDLE
            machine._restore_reason = REASON_INTERRUPTED
        if machine._state is SyncState.IDLE and conflicts > 0:
            machine._state = SyncState.CONFLICT
            if not machine._restore_reason:
                machine._restore_reason = REASON_INCONSISTENT
        return machine

    @classmethod
    def _closed(cls, reason, clock=None):
        """Fail closed: disabled, carrying nothing from the untrusted input."""
        machine = cls(clock=clock)
        machine._state = SyncState.DISABLED
        machine._disabled_from = SyncState.NOT_ENROLLED
        machine._restore_reason = reason
        return machine

    @classmethod
    def _unknown_state(cls, clock=None):
        """A well-formed payload naming a state this build does not have."""
        machine = cls(clock=clock)
        machine._state = SyncState.NOT_ENROLLED
        machine._restore_reason = REASON_UNKNOWN
        return machine

    @classmethod
    def load(cls, path=None, *, clock=None):
        """Read the persisted machine.

        No file at all is a fresh install (un-enrolled, nothing to record). A
        file that cannot be read or parsed fails closed to ``DISABLED``: the
        operator has to look, and the panel certainly does not start syncing.
        """
        machine = cls(clock=clock)
        target = path or app_paths.data_path(STATE_FILE_NAME)
        try:
            if os.path.getsize(target) > _MAX_JSON_BYTES:
                return cls._closed(REASON_UNREADABLE, clock)
            with open(target, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError:
            return machine
        except (OSError, ValueError):
            return cls._closed(REASON_UNREADABLE, clock)
        return cls.from_dict(payload, clock=clock)

    def save(self, path=None):
        """Persist this machine atomically so the next start resumes."""
        write_json_atomic(path or app_paths.data_path(STATE_FILE_NAME),
                          self.to_dict())
