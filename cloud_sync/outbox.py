# -*- coding: utf-8 -*-
"""The durable outbox, its retry policy, and the batch worker (spec §9).

Three things live here, and they belong together because they share one rule:

1. **:class:`Outbox`** — an append-only JSONL queue at
   ``cloud_sync/outbox.jsonl`` in the data directory. ``enqueue()`` is a
   synchronous, ``fsync``-ed append that returns only once the record is on
   disk, so a caller can put it inside the same critical section as its local
   store write and the caller never sees success for a change that is not
   queued (spec §9). The queue is bounded: a full queue raises
   ``QUEUE_FULL`` and **nothing is ever dropped** (manager ruling 10).
2. **:class:`RetryPolicy`** — retry only on timeout, connection error,
   ``429`` and ``500-599``; honour ``Retry-After``; exponential backoff with
   jitter capped at five minutes; bounded attempts. ``400``, ``403`` and
   ``409`` are never retried blindly (spec §9).
3. **:class:`OutboxWorker`** — one batch attempt, and **exactly one terminal
   event** on the state machine for it: ``SYNC_OK``, ``SYNC_FAILED``,
   ``AUTH_FAILED`` or ``LEASE_EXPIRED``, fired only from ``syncing`` or
   ``conflict`` where the table allows it (manager ruling 12).
   ``IllegalTransitionError`` and ``LeaseExpiredError`` are caught *by name*
   at this boundary and recorded on the outcome — never swallowed by a bare
   ``except Exception``.

Terminal vs side events: ``AUTH_OK`` (a refresh succeeded) and
``CONFLICT_FOUND`` (rows the operator must look at) are **not** outcomes, so a
batch may fire them next to its single terminal event without breaking the
"one outcome per attempt" rule.
"""
import json
import os
import random
import threading
import time

import app_paths
from cloud_sync.errors import (
    AuthRequiredError, BadResponseError, CloudSyncError, QueueFullError,
    UnresolvedReferenceCloudError, is_retryable, is_valid_code, QUEUE_FULL,
    SERVER_ERROR, TRANSITION_NOT_LEGAL,
)
from cloud_sync.mapper import UnresolvedReferenceError
from cloud_sync.lease import LeaseExpiredError
from cloud_sync.state import IllegalTransitionError, SyncEvent

__all__ = [
    "OUTBOX_FILE_NAME", "DEFAULT_MAX_PENDING", "SCHEMA_VERSION",
    "Entry", "Outbox", "RetryPolicy", "BatchOutcome", "OutboxWorker",
]

#: Where the queue lives, inside the data directory (spec §9).
OUTBOX_FILE_NAME = "cloud_sync/outbox.jsonl"

SCHEMA_VERSION = 1

#: Bound on the queue. Reaching it raises ``QUEUE_FULL``; it never drops the
#: oldest row to make room (manager ruling 10 — that would be silent data
#: loss, and it would not be a *code* the panel could show).
DEFAULT_MAX_PENDING = 2000

#: Rewrite the file when it grows past this many lines, so an append-only
#: history of attempts cannot grow without bound.
_COMPACT_LINES = 500

#: A generous line size; anything larger is corrupt, not a real operation.
_MAX_LINE_BYTES = 4 * 1024 * 1024

#: Transport marker for a *new* customer ledger append. Updates/voids keep
#: using generic CAS; only creation needs server-side sequence serialization.
_FINANCE_APPEND_TRANSPORT = "finance_append"
_FINANCE_VOID_TRANSPORT = "finance_void"


# =====================================================================
# Retry policy
# =====================================================================
class RetryPolicy(object):
    """Spec §9 in code: what may be retried, and for how long.

    ``delay(failures, retry_after)`` is always in ``[0, cap]``. ``Retry-After``
    is honoured whenever it fits inside the five-minute cap; a longer server
    hint is clamped to the cap, because spec §9 states the cap as an absolute
    property of this queue and waiting an hour would strand every later
    change behind one ``429``.
    """

    def __init__(self, *, max_attempts=8, base_delay=1.0, cap=300.0,
                 jitter=0.5, rng=None):
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) \
                or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        if not isinstance(base_delay, (int, float)) or base_delay <= 0:
            raise ValueError("base_delay must be a positive number of seconds")
        if not isinstance(cap, (int, float)) or cap < base_delay:
            raise ValueError("cap must be >= base_delay")
        if not isinstance(jitter, (int, float)) or not 0 <= jitter <= 1:
            raise ValueError("jitter must be between 0 and 1")
        self.max_attempts = int(max_attempts)
        self.base_delay = float(base_delay)
        self.cap = float(cap)
        self.jitter = float(jitter)
        #: Injectable so a test never sleeps and never depends on `random`.
        self._rng = rng if rng is not None else random.random

    def should_retry(self, error, failures):
        """Whether the attempt that produced `error` may be repeated.

        `failures` is how many attempts have already failed for this entry;
        the bound is on the *total* number of attempts.
        """
        if isinstance(failures, bool) or not isinstance(failures, int) \
                or failures < 1:
            raise ValueError("failures must be a positive integer")
        if failures >= self.max_attempts:
            return False
        return is_retryable(error)

    def delay(self, failures, retry_after=None):
        """Seconds to wait after `failures` failed attempts. Always <= cap."""
        if isinstance(failures, bool) or not isinstance(failures, int) \
                or failures < 1:
            raise ValueError("failures must be a positive integer")
        exponent = min(failures - 1, 30)
        raw = min(self.cap, self.base_delay * (2.0 ** exponent))
        spread = min(1.0, max(0.0, self.jitter))
        jittered = raw * (1.0 - spread) + raw * spread * float(self._rng())
        if retry_after is not None:
            try:
                hint = float(retry_after)
            except (TypeError, ValueError):
                hint = 0.0
            if hint > 0:
                jittered = max(jittered, hint)
        return min(self.cap, max(0.0, jittered))


# =====================================================================
# The queue
# =====================================================================
class Entry(object):
    """One queued operation and everything the retry loop needs to know."""

    __slots__ = ("operation_id", "operation", "attempts", "due_at", "parked",
                 "conflict", "code", "enqueued_at")

    def __init__(self, operation_id, operation, *, attempts=0, due_at=None,
                 parked=None, conflict=None, code=None, enqueued_at=0.0):
        self.operation_id = operation_id
        self.operation = operation
        self.attempts = attempts
        self.due_at = due_at
        #: None while it is still the outbox's job; "attempts" when the retry
        #: budget ran out; "conflict" when an operator must choose (§9/§11).
        self.parked = parked
        self.conflict = conflict
        self.code = code
        self.enqueued_at = enqueued_at

    @property
    def is_due(self):
        if self.parked is not None:
            return False
        return self.due_at is None

    def due(self, now):
        if self.parked is not None:
            return False
        return self.due_at is None or self.due_at <= now

    def to_record(self, kind, at):
        return {
            "v": SCHEMA_VERSION,
            "kind": kind,
            "id": self.operation_id,
            "at": at,
            "enqueued_at": self.enqueued_at,
            "operation": self.operation,
            "attempts": self.attempts,
            "due_at": self.due_at,
            "parked": self.parked,
            "conflict": self.conflict,
            "code": self.code,
        }

    @classmethod
    def from_record(cls, record):
        operation = record.get("operation")
        if not isinstance(operation, dict):
            return None
        operation_id = record.get("id")
        if not isinstance(operation_id, str) or not operation_id:
            return None
        attempts = record.get("attempts", 0)
        if isinstance(attempts, bool) or not isinstance(attempts, int) \
                or attempts < 0:
            return None
        due_at = record.get("due_at")
        if due_at is not None and (isinstance(due_at, bool)
                                   or not isinstance(due_at, (int, float))):
            return None
        parked = record.get("parked")
        if parked not in (None, "attempts", "conflict"):
            return None
        return cls(operation_id, operation, attempts=attempts,
                   due_at=due_at, parked=parked,
                   conflict=record.get("conflict"),
                   code=record.get("code"),
                   enqueued_at=record.get("enqueued_at") or 0.0)


class Outbox(object):
    """Append-only, restart-safe, bounded. Nothing here drops a row."""

    def __init__(self, path=None, *, max_pending=DEFAULT_MAX_PENDING,
                 clock=None):
        if isinstance(max_pending, bool) or not isinstance(max_pending, int) \
                or max_pending < 1:
            raise ValueError("max_pending must be a positive integer")
        self._path = path
        self._max_pending = max_pending
        self._clock = clock if clock is not None else time.time
        self._lock = threading.RLock()
        self._entries = {}          # operation_id -> Entry, insertion-ordered
        self._lines = 0
        #: Lines on disk that could not be parsed (a crash mid-append leaves
        #: exactly one). Reported, never hidden: the caller must be able to
        #: tell "queue is empty" from "queue was damaged".
        self.corrupt_lines = 0
        self.loaded = False

    # -- where it lives -------------------------------------------------
    @property
    def path(self):
        if self._path is not None:
            return self._path
        # OUTBOX_FILE_NAME is the queue's path *relative to the data
        # directory* (callers join it to their own root that way), so the
        # default resolves it segment by segment: app_paths.data_path()
        # deliberately refuses a separator, which made the default unusable
        # -- every outbox built without an explicit path raised ValueError
        # before it could ever push.
        parts = OUTBOX_FILE_NAME.replace("\\", "/").split("/")
        directory = app_paths.data_subdir(*parts[:-1]) \
            if len(parts) > 1 else app_paths.data_dir()
        return os.path.join(directory, parts[-1])

    @property
    def max_pending(self):
        return self._max_pending

    # -- durable append -------------------------------------------------
    def _append(self, record):
        """One ``fsync``-ed append. Returns after the bytes are on disk."""
        line = json.dumps(record, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":")) + "\n"
        payload = line.encode("utf-8")
        with self._lock:
            target = self.path
            directory = os.path.dirname(target) or "."
            os.makedirs(directory, exist_ok=True)
            handle = os.open(target, os.O_CREAT | os.O_WRONLY | os.O_APPEND,
                             0o600)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(handle, view)
                    if written <= 0:            # pragma: no cover - defensive
                        raise OSError("short write to the outbox")
                    view = view[written:]
                os.fsync(handle)
            finally:
                os.close(handle)
            self._lines += 1
        return target

    # -- loading --------------------------------------------------------
    def load(self):
        """Re-read the file, rebuilding the queue. Survives restart (§9)."""
        with self._lock:
            self._entries.clear()
            self.corrupt_lines = 0
            self._lines = 0
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    raw = handle.read()
            except FileNotFoundError:
                self.loaded = True
                return self
            for line in raw.splitlines():
                if not line.strip():
                    continue
                self._lines += 1
                if len(line) > _MAX_LINE_BYTES:
                    self.corrupt_lines += 1
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    self.corrupt_lines += 1
                    continue
                self._apply(record)
            self.loaded = True
        return self

    def _apply(self, record):
        """Fold one record into the in-memory queue (last write wins)."""
        if not isinstance(record, dict) or record.get("v") != SCHEMA_VERSION:
            self.corrupt_lines += 1
            return
        kind = record.get("kind")
        if kind == "done":
            self._entries.pop(record.get("id"), None)
            return
        if kind not in ("enqueue", "attempt", "park", "release", "state"):
            self.corrupt_lines += 1
            return
        entry = Entry.from_record(record)
        if entry is None:
            self.corrupt_lines += 1
            return
        self._entries[entry.operation_id] = entry

    def ensure_loaded(self):
        if not self.loaded:
            self.load()
        return self

    # -- enqueue --------------------------------------------------------
    def enqueue(self, operation, *, operation_id=None):
        """Append one operation durably; return its ``operation_id``.

        Raises :class:`cloud_sync.errors.QueueFullError` (code
        ``QUEUE_FULL``) rather than truncating anything: the caller still has
        its local write, and the operator gets a code to act on.
        """
        if not isinstance(operation, dict) or not operation:
            raise QueueFullError(code=QUEUE_FULL)
        self.ensure_loaded()
        identifier = operation_id or operation.get("operation_id")
        if not isinstance(identifier, str) or not identifier:
            from cloud_sync.ids import new_uuid
            identifier = new_uuid()
            operation = dict(operation)
            operation["operation_id"] = identifier
        with self._lock:
            if identifier not in self._entries \
                    and len(self._entries) >= self._max_pending:
                raise QueueFullError(code=QUEUE_FULL)
            entry = Entry(identifier, operation,
                          enqueued_at=self._clock())
            # The append happens *inside* the lock and only returns after
            # fsync: this is the critical section the store write shares.
            # Memory learns about the row only once the disk has it, so an
            # OSError here surfaces as a failed enqueue, never as a row that
            # looks queued and would vanish on restart.
            self._append(entry.to_record("enqueue", self._clock()))
            self._entries[identifier] = entry
        return identifier

    # -- inspection -----------------------------------------------------
    def __len__(self):
        self.ensure_loaded()
        with self._lock:
            return len(self._entries)

    @property
    def pending_count(self):
        """Entries the worker will still send by itself."""
        self.ensure_loaded()
        with self._lock:
            return sum(1 for e in self._entries.values()
                       if e.parked is None)

    @property
    def conflict_count(self):
        """Entries parked because the server's copy differs (§9/§11)."""
        self.ensure_loaded()
        with self._lock:
            return sum(1 for e in self._entries.values()
                       if e.parked == "conflict")

    @property
    def parked_count(self):
        """Entries whose retry budget ran out; they wait for an operator."""
        self.ensure_loaded()
        with self._lock:
            return sum(1 for e in self._entries.values()
                       if e.parked == "attempts")

    def entries(self):
        """A snapshot list, oldest first."""
        self.ensure_loaded()
        with self._lock:
            return list(self._entries.values())

    def get(self, operation_id):
        self.ensure_loaded()
        with self._lock:
            return self._entries.get(operation_id)

    def conflicts(self):
        """The parked conflicts with their server copies, for the panel (§11)."""
        self.ensure_loaded()
        with self._lock:
            return [e for e in self._entries.values()
                    if e.parked == "conflict"]

    def due(self, now=None):
        """Entries ready to send now, oldest first."""
        self.ensure_loaded()
        moment = self._clock() if now is None else now
        with self._lock:
            return [e for e in self._entries.values() if e.due(moment)]

    # -- lifecycle ------------------------------------------------------
    # Retry bookkeeping (attempts, due_at, parked) is deliberately allowed to
    # lag the file by one line: if it is lost the row is simply sent again on
    # the next start, and spec §6.1 makes a replayed operation_id a no-op on
    # the server. Losing the *operation* is never acceptable; losing the
    # schedule only costs one redundant request.

    def record_attempt(self, operation_id, *, code=None, due_at=None,
                       failures=1):
        """Note one failed attempt and when the entry becomes due again."""
        self.ensure_loaded()
        with self._lock:
            entry = self._entries.get(operation_id)
            if entry is None:
                return None
            entry.attempts = max(entry.attempts, failures)
            entry.due_at = due_at
            entry.code = code
            self._append(entry.to_record("attempt", self._clock()))
            self._compact()
            return entry

    def park(self, operation_id, reason, *, code=None, conflict=None):
        """Stop an entry from being retried automatically.

        ``reason`` is ``"attempts"`` (budget exhausted) or ``"conflict"`` (an
        operator must choose, spec §9). The row stays in the file either way.
        """
        if reason not in ("attempts", "conflict"):
            raise ValueError("park reason must be 'attempts' or 'conflict'")
        self.ensure_loaded()
        with self._lock:
            entry = self._entries.get(operation_id)
            if entry is None:
                return None
            entry.parked = reason
            entry.due_at = None
            entry.code = code
            if conflict is not None:
                entry.conflict = conflict
            self._append(entry.to_record("park", self._clock()))
            self._compact()
            return entry

    def release(self, operation_id, *, code=None, new_operation_id=None):
        """Put a parked entry back in the send path (conflict resolved, …).

        If ``new_operation_id`` is supplied, the entry is re-keyed to that id
        so the next push is evaluated under a fresh operation id instead of
        replaying a cached idempotency conflict on the server (spec §6.1).
        """
        self.ensure_loaded()
        with self._lock:
            entry = self._entries.get(operation_id)
            if entry is None:
                return None
            if new_operation_id and new_operation_id != operation_id:
                del self._entries[operation_id]
                entry.operation_id = new_operation_id
                if isinstance(entry.operation, dict):
                    entry.operation["operation_id"] = new_operation_id
                self._entries[new_operation_id] = entry
            entry.parked = None
            entry.due_at = None
            entry.conflict = None
            entry.attempts = 0
            entry.code = code
            self._append(entry.to_record("release", self._clock()))
            self._compact()
            return entry

    def mark_done(self, operation_id, result="applied"):
        """Remove an entry that the server has accepted (or that was voided)."""
        self.ensure_loaded()
        with self._lock:
            entry = self._entries.get(operation_id)
            if entry is None:
                return False
            # Append first: if the disk write fails the row is still queued
            # and will simply be sent again (the server replays by
            # operation_id), which is the safe direction to fail in.
            self._append({"v": SCHEMA_VERSION, "kind": "done",
                          "id": operation_id, "at": self._clock(),
                          "result": result, "operation": None,
                          "attempts": entry.attempts, "due_at": None,
                          "parked": None, "conflict": None,
                          "code": entry.code,
                          "enqueued_at": entry.enqueued_at})
            del self._entries[operation_id]
            self._compact()
            return True

    # -- compaction -----------------------------------------------------
    def _compact(self, force=False):
        """Rewrite the file as one line per live entry.

        Only ever shrinks the *history*; the live set is written in full, so a
        crash during compaction leaves either the old file or the new one —
        never a queue with holes.
        """
        if not force and self._lines < _COMPACT_LINES:
            return
        target = self.path
        directory = os.path.dirname(target) or "."
        os.makedirs(directory, exist_ok=True)
        temp = target + ".tmp"
        with open(temp, "w", encoding="utf-8") as handle:
            for entry in self._entries.values():
                handle.write(json.dumps(entry.to_record("state", self._clock()),
                                        ensure_ascii=True, sort_keys=True,
                                        separators=(",", ":")))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
        self._lines = len(self._entries)


# =====================================================================
# One batch attempt
# =====================================================================
class BatchOutcome(object):
    """What one call to :meth:`OutboxWorker.run_once` did.

    ``events`` lists every state-machine event that was fired, in order;
    ``terminal`` is the one outcome or fault among them.
    """

    __slots__ = ("attempted", "applied", "conflicts", "events", "terminal",
                 "code", "retry_at", "refused", "batch_size")

    def __init__(self, *, attempted=False, applied=0, conflicts=0,
                 events=(), terminal=None, code=None, retry_at=None,
                 refused=None, batch_size=0):
        self.attempted = attempted
        self.applied = applied
        self.conflicts = conflicts
        self.events = tuple(events)
        self.terminal = terminal
        self.code = code
        self.retry_at = retry_at
        self.refused = refused
        self.batch_size = batch_size

    TERMINAL_EVENTS = frozenset({
        SyncEvent.SYNC_OK.value, SyncEvent.SYNC_FAILED.value,
        SyncEvent.AUTH_FAILED.value, SyncEvent.LEASE_EXPIRED.value,
    })

    @property
    def terminal_count(self):
        return sum(1 for name in self.events if name in self.TERMINAL_EVENTS)

    def __repr__(self):
        return ("<BatchOutcome attempted=%s applied=%d conflicts=%d "
                "events=%s code=%s>" % (self.attempted, self.applied,
                                        self.conflicts, list(self.events),
                                        self.code))


class OutboxWorker(object):
    """Drives the queue and the state machine for exactly one batch attempt."""

    def __init__(self, outbox, client, machine=None, lease=None, *,
                 policy=None, clock=None, max_batch=100, on_conflict=None):
        self.outbox = outbox
        self.client = client
        self.machine = machine
        self.lease = lease
        self.policy = policy if policy is not None else RetryPolicy()
        self._clock = clock if clock is not None else time.time
        self.max_batch = max_batch if isinstance(max_batch, int) \
            and max_batch > 0 else 100
        #: Called with each conflict so the panel can surface it (spec §11).
        self.on_conflict = on_conflict
        self._events = []

    # -- state-machine plumbing ----------------------------------------
    def _fire(self, event, **kwargs):
        """Apply one event, recording a refusal instead of losing it.

        Manager ruling 12: a route that drives the machine catches
        ``IllegalTransitionError`` explicitly. It never raises here (the batch
        must still finish) and it never pretends the event happened — the
        refusal is returned and reported on the outcome.
        """
        if self.machine is None:
            return None
        try:
            self.machine.apply(event, **kwargs)
        except IllegalTransitionError as exc:
            self._events.append("!%s" % exc.event.value)
            return exc
        self._events.append(event.value)
        return None

    def _sync_pending(self):
        if self.machine is None:
            return
        self.machine.set_pending(self.outbox.pending_count)

    # -- auth hooks (spec §5, manager ruling 7) -------------------------
    def bind_auth(self):
        """Wire the client's auth callbacks to the machine and the lease.

        Returns the two callables so a caller can unwind them in a test.
        """
        previous_ok = getattr(self.client, "on_auth_ok", None)
        previous_failed = getattr(self.client, "on_auth_failed", None)

        def on_auth_ok():
            if self.lease is not None:
                # A device-token refresh proves possession of a valid
                # credential: it renews the 7-day lease (manager ruling 7).
                self.lease.grant()
            self._fire(SyncEvent.AUTH_OK)

        def on_auth_failed(code):
            refusal = self._fire(SyncEvent.AUTH_FAILED, error_code=code)
            return refusal is None

        self.client.on_auth_ok = on_auth_ok
        self.client.on_auth_failed = on_auth_failed
        return previous_ok, previous_failed

    def unbind_auth(self, previous):
        """Restore the hooks :meth:`bind_auth` replaced; returns them.

        Tolerant of a client that has been swapped out from under us: the
        cleanup path must not raise a second exception over the first one.
        """
        restored = (getattr(self.client, "on_auth_ok", None),
                    getattr(self.client, "on_auth_failed", None))
        self.client.on_auth_ok, self.client.on_auth_failed = previous
        return restored

    # -- the attempt ----------------------------------------------------
    def run_once(self, *, max_batch=None):
        """Take one batch, push it, and settle the machine exactly once.

        Returns the :class:`BatchOutcome`. Exactly one terminal event is
        fired for an attempt that actually reached the push; a call that
        never started (nothing due, lease expired, state refuses to start)
        fires at most one fault and reports ``attempted=False``.

        A bug inside the batch is settled first and then re-raised: the rows
        are parked and the machine leaves ``syncing``, so a crash can never
        strand the state machine, and it is still not swallowed.
        """
        self._events = []
        now = self._clock()
        self.outbox.ensure_loaded()
        ready = self.outbox.due(now)
        if not ready:
            return BatchOutcome()

        # Lease first: an expired lease stops network sync entirely (manager
        # ruling 11) and must never reach the socket.
        if self.lease is not None:
            try:
                self.lease.assert_writable()
            except LeaseExpiredError:
                self._fire(SyncEvent.LEASE_EXPIRED)
                return self._finish(BatchOutcome(
                    terminal=SyncEvent.LEASE_EXPIRED.value,
                    code="LEASE_EXPIRED"))

        if self.machine is not None and not self.machine.can(
                SyncEvent.START_SYNC):
            # No attempt, therefore no outcome: the operator (or the health
            # prober) is the one who moves the machine out of this state.
            return self._finish(BatchOutcome(
                refused="START_SYNC", code=TRANSITION_NOT_LEGAL))

        if self._fire(SyncEvent.START_SYNC) is not None:
            return self._finish(BatchOutcome(
                refused="START_SYNC", code=TRANSITION_NOT_LEGAL))

        batch = self._transport_batch(ready, max_batch or self.max_batch)
        outcome = BatchOutcome(attempted=True, batch_size=len(batch))
        failure = None
        try:
            result = self._push_batch(batch)
        except AuthRequiredError as exc:
            outcome = self._fail_auth(outcome, exc)
        except LeaseExpiredError:
            outcome = self._fire_terminal(outcome, SyncEvent.LEASE_EXPIRED,
                                          "LEASE_EXPIRED")
        except CloudSyncError as exc:
            outcome = self._fail(outcome, batch, exc)
        except Exception as exc:                     # noqa: BLE001
            # Unknown failures are still a batch outcome: park the rows with
            # a stable code, settle the machine, then let the bug out.
            outcome = self._fail(outcome, batch, _wrap_unexpected(exc))
            failure = exc
        else:
            outcome = self._succeed(outcome, batch, result)
        outcome = self._finish(outcome)
        if failure is not None:
            raise failure
        return outcome

    # -- transport routing ----------------------------------------------
    @staticmethod
    def _finance_transport(entry):
        operation = getattr(entry, "operation", None)
        if not isinstance(operation, dict):
            return None
        marker = operation.get("transport")
        if marker in (_FINANCE_APPEND_TRANSPORT, _FINANCE_VOID_TRANSPORT):
            return marker
        return None

    @classmethod
    def _is_finance_special(cls, entry):
        return cls._finance_transport(entry) is not None

    def _transport_batch(self, ready, limit):
        """Preserve queue order while isolating serialized finance appends.

        If finance is at the head, send exactly that entry. Otherwise send the
        contiguous generic prefix and stop before the first finance append.
        This guarantees a newly-created customer reaches the host before its
        first ledger entry without degrading unrelated generic batching.
        """
        bounded = ready[:limit]
        if not bounded:
            return []
        if self._is_finance_special(bounded[0]):
            return [bounded[0]]
        prefix = []
        for entry in bounded:
            if self._is_finance_special(entry):
                break
            prefix.append(entry)
        return prefix

    def _push_batch(self, batch):
        if len(batch) == 1:
            marker = self._finance_transport(batch[0])
            if marker == _FINANCE_APPEND_TRANSPORT:
                return self._push_finance_append(batch[0])
            if marker == _FINANCE_VOID_TRANSPORT:
                return self._push_finance_void(batch[0])
        return self.client.push([entry.operation for entry in batch])

    def _push_finance_append(self, entry):
        operation = entry.operation
        if operation.get("kind") != "upsert" \
                or operation.get("entity") != "customer_transactions":
            raise BadResponseError(code=SERVER_ERROR)
        record = operation.get("record")
        if not isinstance(record, dict):
            raise BadResponseError(code=SERVER_ERROR)
        customer_id = record.get("customer_id")
        amount = record.get("amount")
        if not isinstance(customer_id, str) or not customer_id \
                or isinstance(amount, bool) or not isinstance(amount, int):
            raise BadResponseError(code=SERVER_ERROR)
        note = record.get("note", "")
        kind = record.get("kind", "")
        image = record.get("image", "")
        device_id = record.get("device_id")
        if not all(isinstance(value, str) for value in (note, kind, image)):
            raise BadResponseError(code=SERVER_ERROR)
        if device_id == "":
            device_id = None
        if device_id is not None and not isinstance(device_id, str):
            raise BadResponseError(code=SERVER_ERROR)

        payload = self.client.append_ledger_transaction(
            customer_id, amount, note=note, kind=kind, image=image,
            device_id=device_id, operation_id=entry.operation_id)
        transaction = payload.get("transaction") if isinstance(payload, dict) else None
        cursor = payload.get("cursor") if isinstance(payload, dict) else None
        if not isinstance(transaction, dict) \
                or not isinstance(transaction.get("id"), str) \
                or not transaction["id"] \
                or isinstance(cursor, bool) or not isinstance(cursor, int):
            raise BadResponseError(code=SERVER_ERROR)
        return _AppliedBatchResult(entry.operation_id, cursor)

    def _push_finance_void(self, entry):
        operation = entry.operation
        if operation.get("kind") != "upsert" \
                or operation.get("entity") != "customer_transactions":
            raise BadResponseError(code=SERVER_ERROR)
        transaction_id = operation.get("id")
        record = operation.get("record")
        if not isinstance(transaction_id, str) or not transaction_id \
                or not isinstance(record, dict):
            raise BadResponseError(code=SERVER_ERROR)
        reason = record.get("void_reason")
        if not isinstance(reason, str) or not reason.strip():
            raise BadResponseError(code=SERVER_ERROR)
        payload = self.client.void_ledger_transaction(
            transaction_id, reason, operation_id=entry.operation_id)
        original = payload.get("original") if isinstance(payload, dict) else None
        reversal = payload.get("reversal") if isinstance(payload, dict) else None
        cursor = payload.get("cursor") if isinstance(payload, dict) else None
        if not isinstance(original, dict) or original.get("id") != transaction_id \
                or not isinstance(reversal, dict) \
                or not isinstance(reversal.get("id"), str) \
                or not reversal["id"] \
                or isinstance(cursor, bool) or not isinstance(cursor, int):
            raise BadResponseError(code=SERVER_ERROR)
        return _AppliedBatchResult(entry.operation_id, cursor)

    # -- the terminal-event helpers ------------------------------------
    def _finish(self, outcome):
        """Attach the events actually fired and refresh the pending gauge."""
        outcome.events = tuple(self._events)
        outcome.terminal = next(
            (name for name in reversed(self._events)
             if name in BatchOutcome.TERMINAL_EVENTS), None)
        self._sync_pending()
        return outcome

    def _fire_terminal(self, outcome, event, code, *, error_code=None):
        """Fire exactly one outcome/fault and record the code it carries."""
        kwargs = {"error_code": error_code} if error_code is not None else {}
        self._fire(event, **kwargs)
        outcome.code = code
        outcome.terminal = event.value
        return outcome

    def _fail_auth(self, outcome, exc):
        if not getattr(exc, "event_fired", False):
            # No wired callback (or the machine refused it): this attempt
            # still owes exactly one terminal event.
            self._fire(SyncEvent.AUTH_FAILED, error_code=exc.code)
        outcome.code = exc.code
        outcome.terminal = SyncEvent.AUTH_FAILED.value
        return outcome

    def _fail(self, outcome, batch, exc):
        """Record one failed attempt for every row in the batch."""
        code = getattr(exc, "code", None)
        if not is_valid_code(code):
            # Never pass an arbitrary exception attribute to apply(): the
            # machine validates its error_code and must not see junk.
            code = SERVER_ERROR
        failures = max([e.attempts for e in batch] or [0]) + 1
        if is_retryable(exc) and self.policy.should_retry(exc, failures):
            delay = self.policy.delay(
                failures, getattr(exc, "retry_after", None))
            due_at = self._clock() + delay
            for entry in batch:
                self.outbox.record_attempt(entry.operation_id, code=code,
                                           due_at=due_at, failures=failures)
            outcome.retry_at = due_at
        else:
            # Not retried (400/403/409) or the budget ran out. The rows stay
            # in the queue, parked, carrying the code that stopped them.
            for entry in batch:
                self.outbox.park(entry.operation_id, "attempts", code=code)
            outcome.retry_at = None
        self._fire(SyncEvent.SYNC_FAILED, error_code=code)
        outcome.code = code
        outcome.terminal = SyncEvent.SYNC_FAILED.value
        return outcome

    # -- success --------------------------------------------------------
    def _succeed(self, outcome, batch, result):
        applied_ids = set(result.applied)
        conflicts_by_id = {c.operation_id: c for c in result.conflicts}
        for entry in batch:
            conflict = conflicts_by_id.get(entry.operation_id)
            if conflict is not None:
                # Data, not an error: park it for the operator with the
                # server's copy, and count it once (spec §9, §11).
                payload = conflict.to_dict()
                self.outbox.park(entry.operation_id, "conflict",
                                 code="VERSION_CONFLICT", conflict=payload)
                outcome.conflicts += 1
                self._fire(SyncEvent.CONFLICT_FOUND)
                if callable(self.on_conflict):
                    self.on_conflict(payload)
            elif entry.operation_id in applied_ids:
                self.outbox.mark_done(entry.operation_id, "applied")
                outcome.applied += 1
            else:
                # Neither applied nor conflicted: the server did not confirm
                # it. Park rather than assume success — a row the host never
                # acknowledged must be sent again, not forgotten.
                self.outbox.park(entry.operation_id, "attempts",
                                 code="SERVER_ERROR")
        self._fire(SyncEvent.SYNC_OK)
        outcome.code = None
        outcome.terminal = SyncEvent.SYNC_OK.value
        outcome.retry_at = None
        return outcome


class _AppliedBatchResult(object):
    """Minimal PushResult shape used by the finance transport path."""

    __slots__ = ("applied", "conflicts", "cursor")

    def __init__(self, operation_id, cursor):
        self.applied = (operation_id,)
        self.conflicts = ()
        self.cursor = cursor


def _wrap_unexpected(exc):
    """Give an unexpected exception a stable, grammar-safe code.

    The original exception is re-raised by ``run_once`` after the batch has
    been settled, so this wrapper only carries the code the state machine
    needs — never the exception's own text, which may contain anything.
    """
    if isinstance(exc, CloudSyncError):
        return exc
    if isinstance(exc, UnresolvedReferenceError):
        # Workstream B: uuid5 is one-way, so a row whose parent this machine
        # cannot resolve is a typed, expected failure -- surfaced with a
        # stable code and never written into crm_store.json.
        return UnresolvedReferenceCloudError()
    return BadResponseError(code=SERVER_ERROR)
