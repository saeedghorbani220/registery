# -*- coding: utf-8 -*-
"""HTTP transport for cloud sync (spec §5, §6, §9, §11).

One class, :class:`SyncClient`, speaks the whole §6 contract over ``requests``:

===========  ==========================================================
``health``   ``GET  /health/live``            (no auth)
``login``    ``POST /auth/login``             -> user tokens, RAM only
``enroll``   ``POST /sync-devices/self-enroll`` -> sync device id + refresh
             (legacy ``/sync-devices/enroll`` fallback on 404)
``bootstrap````GET  /sync/bootstrap``          -> snapshot + cursor + epoch
``pull``     ``GET  /sync/changes?cursor=&limit=``
``push``     ``POST /sync/mutations``          -> applied[] + conflicts[]
``import_document``
            ``POST /bootstrap/import``          -> one-shot seed (spec §8)
===========  ==========================================================

Design rules that are not negotiable:

* **One attempt per call.** The only automatic retry here is the single
  ``401 -> refresh -> retry original request once`` of spec §9. Every other
  retry decision belongs to the outbox (spec §9), so backoff is configured in
  exactly one place.
* **Conflicts are data.** ``POST /sync/mutations`` answers ``200`` with
  ``applied[]`` and ``conflicts[]``; a conflict returns the server copy and
  never raises. Only a transport or protocol failure raises.
* **The server's ``message`` never leaves this module.** Failures become a
  typed error carrying the stable ``code``, the status and the ``request_id``;
  the body text is parsed only far enough to extract those and is discarded.
* **One log line per HTTP attempt**, carrying exactly ``route``, ``method``,
  ``status``, ``duration_ms``, ``request_id`` and ``code`` — all of them
  validated before they are formatted, so a hostile or careless server cannot
  put a token into the log through ``request_id`` (spec §5).
"""
import json
import logging
import time

import requests

from cloud_sync import ids as _ids
from cloud_sync.config import load_config
from cloud_sync.errors import (
    AuthRequiredError, AuthRevokedError, BadResponseError, HttpError,
    RequestTimeoutError, UnreachableError, UnresolvedReferenceCloudError,
    code_for_status, envelope_code, parse_retry_after, safe_code,
    safe_request_id, AUTH_REQUIRED, AUTH_REVOKED, ENROL_REQUIRED,
)
from cloud_sync.auth import ACCESS_TTL_SECONDS, TokenVault
from cloud_sync.mapper import (  # read-only: B owns this module
    REFERENCE_FIELDS, UnresolvedReferenceError)

__all__ = [
    "SyncClient", "PushResult", "Conflict", "DEFAULT_TIMEOUT",
    "CHANGE_PAGE_LIMIT", "push_order",
]

#: (connect, read) seconds. A local panel must not hang a UI thread forever.
DEFAULT_TIMEOUT = (5.0, 30.0)

#: The §6.2 default page size.
CHANGE_PAGE_LIMIT = 500

_JSON_HEADERS = {
    "Accept": "application/json; charset=utf-8",
    "Content-Type": "application/json; charset=utf-8",
}


def push_order(operations):
    """Sort a batch so every parent row is pushed before its children.

    The host runs a batch in one transaction (spec 6.1), but its foreign keys
    are real SQL constraints: a ``crm_devices`` row created in the same batch
    as the customer it points at must not be sent first, or the whole
    transaction is rejected. The graph is read from
    ``cloud_sync.mapper.REFERENCE_FIELDS``, so a column added there is ordered
    here without editing two lists.

    The sort is stable, so rows of the same entity keep the order the caller
    queued them in (one customer's own edits stay in sequence).
    """
    if not isinstance(operations, (list, tuple)):
        raise BadResponseError(route="/sync/mutations")
    entities = []
    for operation in operations:
        entity = operation.get("entity") if isinstance(operation, dict) else None
        if entity is not None and entity not in entities:
            entities.append(entity)
    dependencies = {
        entity: {target
                 for target in REFERENCE_FIELDS.get(entity, {}).values()
                 if target in entities}
        for entity in entities
    }
    ordered = []
    placed = set()
    pending = list(entities)
    while pending:
        ready = [entity for entity in pending
                 if dependencies[entity] <= placed]
        if not ready:
            break                      # a cycle: keep the caller's order
        ordered.extend(ready)
        placed.update(ready)
        pending = [entity for entity in pending if entity not in placed]
    rank = {entity: index for index, entity in enumerate(ordered)}
    for entity in pending:             # anything left after a cycle goes last
        rank[entity] = len(rank)
    return sorted(operations,
                  key=lambda operation: rank.get(operation.get("entity"),
                                                 len(rank)))


class Conflict(object):
    """One row the server refused to overwrite (spec §6.1).

    This is **data, not an error**: it carries the server's copy so the panel
    can show local-vs-server and let an operator choose (spec §11). The
    transport never raises for it and never applies it.
    """

    __slots__ = ("operation_id", "entity", "id", "server_version",
                 "server_record")

    def __init__(self, operation_id, entity, id_, server_version,
                 server_record):
        self.operation_id = operation_id
        self.entity = entity
        self.id = id_
        self.server_version = server_version
        self.server_record = server_record

    def to_dict(self):
        return {
            "operation_id": self.operation_id,
            "entity": self.entity,
            "id": self.id,
            "server_version": self.server_version,
            "server_record": self.server_record,
        }

    def __repr__(self):
        return "<Conflict %s %s v%s>" % (self.entity, self.id,
                                         self.server_version)


class PushResult(object):
    """What one ``POST /sync/mutations`` answered."""

    __slots__ = ("applied", "conflicts", "cursor")

    def __init__(self, applied, conflicts, cursor):
        self.applied = tuple(applied)
        self.conflicts = tuple(conflicts)
        self.cursor = cursor

    @property
    def has_conflicts(self):
        return bool(self.conflicts)

    def __repr__(self):
        return "<PushResult applied=%d conflicts=%d cursor=%s>" % (
            len(self.applied), len(self.conflicts), self.cursor)


class SyncClient(object):
    """A stateful client: base URL + tenant from config, tokens from a vault."""

    def __init__(self, config=None, vault=None, *, session=None, send=None,
                 timeout=DEFAULT_TIMEOUT, clock=None, logger=None,
                 on_auth_ok=None, on_auth_failed=None):
        self.config = config if config is not None else load_config()
        self.vault = vault if vault is not None else TokenVault()
        self._session = session if session is not None else requests.Session()
        #: Injected transport for tests: (method, url, headers, body, timeout)
        #: -> an object with ``status_code``, ``headers`` and ``content``.
        self._send = send
        self._timeout = timeout
        self._clock = clock if clock is not None else time.time
        self._logger = logger if logger is not None else logging.getLogger(
            "irica.cloud_sync")
        #: Wired by the outbox worker (spec §5 / manager ruling 7).
        self.on_auth_ok = on_auth_ok
        self.on_auth_failed = on_auth_failed

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self):
        close = getattr(self._session, "close", None)
        if callable(close):
            close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ------------------------------------------------------------------
    # Logging (spec §5: request_id, route, status, duration, code — nothing else)
    # ------------------------------------------------------------------
    def _log(self, route, method, status, started, *, request_id=None,
             code=None):
        record = {
            "route": route,
            "method": method,
            "status": status,
            "duration_ms": int(max(0.0, (self._clock() - started) * 1000)),
            "request_id": safe_request_id(request_id),
            "code": safe_code(code),
        }
        level = logging.INFO if (status is not None
                                 and 200 <= status < 400) else logging.WARNING
        self._logger.log(level, json.dumps(record, sort_keys=True))

    # ------------------------------------------------------------------
    # One HTTP attempt
    # ------------------------------------------------------------------
    def _exchange(self, method, route, body, token, timeout, acting=None):
        """Send once. Returns a plain record; transport failures raise."""
        url = self.config.url(route)
        headers = dict(_JSON_HEADERS)
        if token:
            headers["Authorization"] = "Bearer " + token
        if acting:
            # Spec §8: an import carries the device credential as the
            # principal and the *user's* access token in this header — the
            # host reads `X-Acting-User` for the acting identity, so a
            # request without it can never satisfy /bootstrap/import.
            headers["X-Acting-User"] = "Bearer " + acting
        payload_bytes = None
        if body is not None:
            payload_bytes = json.dumps(body, ensure_ascii=False,
                                       separators=(",", ":")).encode("utf-8")
        started = self._clock()
        try:
            if self._send is not None:
                response = self._send(method, url, headers, payload_bytes,
                                      timeout)
            else:
                response = self._session.request(
                    method, url, data=payload_bytes, headers=headers,
                    timeout=timeout, allow_redirects=False)
        except requests.Timeout:
            self._log(route, method, 0, started, code="NET_TIMEOUT")
            raise RequestTimeoutError(route=route) from None
        except requests.RequestException:
            # Connect, DNS, TLS, protocol errors: none of them produced a
            # response, so there is no status and no request id to report.
            self._log(route, method, 0, started, code="NET_UNREACHABLE")
            raise UnreachableError(route=route) from None

        status = getattr(response, "status_code", 0)
        raw = getattr(response, "content", b"") or b""
        request_id = None
        code = None
        retry_after = None
        parsed = None
        malformed = False
        try:
            text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) \
                else str(raw)
        except UnicodeDecodeError:
            text = ""
            malformed = True
        if text.strip():
            try:
                parsed = json.loads(text)
            except ValueError:
                malformed = True
        if isinstance(parsed, dict):
            error = parsed.get("error")
            if isinstance(error, dict):
                raw_id = error.get("request_id")
                request_id = raw_id if isinstance(raw_id, str) else None
                code = envelope_code(parsed, status)
        headers = getattr(response, "headers", None) or {}
        try:
            retry_after = parse_retry_after(headers.get("Retry-After"))
        except AttributeError:
            retry_after = None
        numeric = status if isinstance(status, int) else 0
        log_code = code or ("" if 200 <= numeric < 400
                            else code_for_status(status))
        self._log(route, method, status, started, request_id=request_id,
                  code=log_code)
        return {"status": status, "payload": parsed, "request_id": request_id,
                "code": code, "retry_after": retry_after,
                "malformed": malformed}

    def _failure(self, exchange, route):
        """The typed error for a non-2xx exchange. Never keeps the body text."""
        status = exchange["status"]
        code = exchange["code"] or code_for_status(status)
        common = dict(route=route, status=status,
                      request_id=exchange["request_id"],
                      retry_after=exchange["retry_after"])
        # 401 never reaches here (it goes through _auth_failure); 403 is
        # "authenticated but not allowed" (spec §7 roles), a permission
        # answer that must not look like a dead session.
        if exchange["malformed"] and not exchange["code"]:
            return BadResponseError(route=route, status=status,
                                    request_id=exchange["request_id"])
        return HttpError(code=code, code_source=(
            "envelope" if exchange["code"] else "status"), **common)

    def _request(self, method, route, *, body=None, auth=True,
                 allow_refresh=True, user_auth=False, acting=False):
        """One logical call: send, honour a single 401 refresh, then answer."""
        token = None
        acting_token = None
        if auth:
            token = self._access_token(user=user_auth, refresh=allow_refresh)
            if acting:
                acting_token = self.vault.user_access_token
                if not acting_token:
                    # The acting identity lives in RAM only (spec §5), so an
                    # expired or absent user session is answered *before* the
                    # request is built: the host would answer 401 anyway, and
                    # sending first would log a route for a call never made.
                    raise self._auth_failure(route, code=AUTH_REQUIRED)
        exchange = self._exchange(method, route, body, token, self._timeout,
                                  acting_token)
        if exchange["status"] == 401 and auth and allow_refresh:
            # Spec §9: exactly one refresh, then retry the original request
            # once. A second 401 stops here — no loop, no second refresh.
            self._refresh_device()
            token = self.vault.access_token
            exchange = self._exchange(method, route, body, token,
                                      self._timeout, acting_token)
            if exchange["status"] == 401:
                raise self._auth_failure(route, exchange)
        if not 200 <= int(exchange["status"] or 0) < 300:
            if exchange["status"] == 401:
                # One place for "the session is dead", whether the 401 came
                # from the first attempt or from the retry after a refresh —
                # so on_auth_failed fires exactly once per request.
                raise self._auth_failure(route, exchange)
            raise self._failure(exchange, route)
        payload = exchange["payload"]
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            # A 2xx that is not the documented envelope is a protocol fault,
            # not a success: guessing would silently drop data (spec §6).
            raise BadResponseError(route=route,
                                   status=exchange["status"],
                                   request_id=exchange["request_id"])
        return payload

    # ------------------------------------------------------------------
    # Authentication (spec §5)
    # ------------------------------------------------------------------
    def _access_token(self, *, user, refresh):
        """A usable access token, refreshing the device pair when needed."""
        if user:
            token = self.vault.user_access_token
            if not token:
                raise self._auth_failure("/auth/login")
            return token
        token = self.vault.access_token
        if token:
            return token
        if not self.vault.has_device_credentials:
            if not self.config.sync_device_id:
                # Never enrolled: the remedy is self-enrolment, not a refresh
                # (spec §5), and the panel must say which.
                raise self._auth_failure("/sync/bootstrap",
                                         code=ENROL_REQUIRED)
            raise self._auth_failure("/auth/refresh")
        return self._refresh_device()

    def _auth_failure(self, route, exchange=None, code=None):
        """Build the stop signal, after telling the state machine once.

        ``fired`` records whether a wired ``on_auth_failed`` callback already
        reported the fault, so a batch attempt still produces exactly one
        terminal event (manager ruling 12). Only ``AUTH_*`` codes are
        accepted here: anything else the server sent is folded into
        ``AUTH_REQUIRED`` so the panel has one thing to translate (§11).
        """
        candidate = code or (exchange or {}).get("code")
        if candidate != AUTH_REVOKED and candidate != ENROL_REQUIRED:
            candidate = AUTH_REQUIRED
        request_id = safe_request_id((exchange or {}).get("request_id"))
        fired = False
        if callable(self.on_auth_failed):
            fired = bool(self.on_auth_failed(candidate))
        cls = AuthRevokedError if candidate == AUTH_REVOKED \
            else AuthRequiredError
        return cls(code=candidate, fired=fired, route=route, status=401,
                   request_id=request_id)

    def _refresh_device(self):
        """Rotate the device pair. Returns the new access token.

        Success is a successful authentication for the 7-day lease (manager
        ruling 7), so ``on_auth_ok`` runs here and nowhere else.
        """
        refresh_token = self.vault.device_refresh_token
        if not refresh_token:
            raise self._auth_failure("/auth/refresh")
        try:
            payload = self._request(
                "POST", "/auth/refresh", auth=False, allow_refresh=False,
                body={"refresh_token": refresh_token, "kind": "device"})
        except AuthRequiredError:
            # The refresh token itself was refused: reuse detection, expiry or
            # a revoked device. Spec §5 says the local state goes with it.
            self.vault.revoke_local()
            raise
        except HttpError as exc:
            if exc.status in (401, 403):
                self.vault.revoke_local()
                raise self._auth_failure("/auth/refresh",
                                         {"request_id": exc.request_id,
                                          "code": exc.code}) from None
            # 429 / 5xx are transient: keep the credentials and let the caller
            # decide (the outbox retries them).
            raise
        access = payload.get("access_token")
        rotated = payload.get("refresh_token")
        if not isinstance(access, str) or not access:
            raise BadResponseError(route="/auth/refresh", status=200)
        self.vault.set_access(access, self._ttl(payload))
        if isinstance(rotated, str) and rotated:
            self.vault.save_device_refresh(rotated)
        if callable(self.on_auth_ok):
            self.on_auth_ok()
        return access

    @staticmethod
    def _ttl(payload):
        """``expires_in`` from the server, bounded to something sane."""
        value = payload.get("expires_in")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return ACCESS_TTL_SECONDS
        if not 60 <= value <= ACCESS_TTL_SECONDS:
            return ACCESS_TTL_SECONDS
        return int(value)

    def login(self, username, password):
        """``POST /auth/login`` — user tokens are kept in RAM only (§5)."""
        if not isinstance(username, str) or not isinstance(password, str) \
                or not username or not password:
            raise BadResponseError(route="/auth/login")
        payload = self._request("POST", "/auth/login", auth=False,
                                allow_refresh=False,
                                body={"username": username,
                                      "password": password})
        access = payload.get("access_token")
        if not isinstance(access, str) or not access:
            raise BadResponseError(route="/auth/login", status=200)
        self.vault.set_user_tokens(access, payload.get("refresh_token"),
                                   self._ttl(payload))
        return payload

    def logout(self):
        """``POST /auth/logout`` — invalidates the family, then forgets it."""
        try:
            self._request("POST", "/auth/logout", auth=True,
                          allow_refresh=False, user_auth=True, body={})
        finally:
            self.vault.clear_user()

    def enroll(self):
        """Enrol this machine for the logged-in user.

        Server CRM v2 uses ``/sync-devices/self-enroll`` for both normal users
        and administrators. A 404 means an older v1 host, so only then do we
        fall back to the historical admin-only ``/sync-devices/enroll`` route.
        Other failures are preserved exactly; in particular a 403 is never
        converted into a legacy retry.

        Persists ``sync_device_id`` in ``cloud_config.json`` and the device
        refresh token in ``auth.dat``, both immediately (spec §5).
        """
        route = "/sync-devices/self-enroll"
        try:
            payload = self._request(
                "POST", route, auth=True, allow_refresh=False,
                user_auth=True, body={})
        except HttpError as exc:
            if exc.status != 404:
                raise
            route = "/sync-devices/enroll"
            payload = self._request(
                "POST", route, auth=True, allow_refresh=False,
                user_auth=True, body={})
        device_id = payload.get("sync_device_id")
        refresh = payload.get("device_refresh_token")
        if not isinstance(device_id, str) or not device_id \
                or not isinstance(refresh, str) or not refresh:
            raise BadResponseError(route=route, status=200)
        self.vault.save_device_refresh(refresh)
        self.config.sync_device_id = device_id
        self.config.save()
        if callable(self.on_auth_ok):
            self.on_auth_ok()
        return payload

    def revoke_device(self, sync_device_id):
        """``POST /sync-devices/revoke`` for one owned machine."""
        if not isinstance(sync_device_id, str) or not sync_device_id:
            raise BadResponseError(route="/sync-devices/revoke")
        return self._request(
            "POST", "/sync-devices/revoke", auth=True, allow_refresh=False,
            user_auth=True, body={"sync_device_id": sync_device_id})

    def revoke_all_devices(self, user_id=None):
        """Revoke own machines, or an admin-selected user's machines."""
        if user_id is not None and (not isinstance(user_id, str) or not user_id):
            raise BadResponseError(route="/sync-devices/revoke-all")
        body = {} if user_id is None else {"user_id": user_id}
        return self._request(
            "POST", "/sync-devices/revoke-all", auth=True,
            allow_refresh=False, user_auth=True, body=body)

    # ------------------------------------------------------------------
    # Endpoints (spec §6)
    # ------------------------------------------------------------------
    def health(self):
        """``GET /health/live`` — liveness only, no auth, no side effects."""
        return self._request("GET", "/health/live", auth=False,
                             allow_refresh=False)

    def bootstrap(self):
        """``GET /sync/bootstrap`` — full snapshot + cursor + dataset epoch.

        The returned cursor is persisted so the first incremental pull resumes
        exactly where the snapshot ended (spec §6.2: snapshot and cursor come
        from one transaction, so nothing committed between them is missed).
        """
        payload = self._request("GET", "/sync/bootstrap")
        self._remember_cursor(payload, "/sync/bootstrap")
        return payload

    def pull(self, cursor=None, limit=CHANGE_PAGE_LIMIT):
        """``GET /sync/changes?cursor=&limit=`` — one page, never the whole log.

        The cursor is **required state, not an optimisation**: filtering by
        ``updated_at`` would drop rows on equal timestamps and clock skew
        (spec §6.2), so only ``seq > cursor`` is ever used.
        """
        from urllib.parse import urlencode
        if cursor is None:
            cursor = self.config.cursor
        if isinstance(cursor, bool) or not isinstance(cursor, int) \
                or cursor < 0 or isinstance(limit, bool) \
                or not isinstance(limit, int) or limit < 1:
            raise BadResponseError(route="/sync/changes")
        payload = self._request(
            "GET", "/sync/changes?" + urlencode({"cursor": cursor,
                                                 "limit": limit}))
        self._validate_page(payload, cursor, "/sync/changes")
        return payload

    @staticmethod
    def _validate_page(payload, cursor, route):
        """Refuse a page that would not move the cursor strictly forward.

        Spec 6.2 filters on ``seq > cursor`` only: equal timestamps and clock
        skew silently drop rows, and a page that went backwards would re-apply
        them. Enforcing monotonic ``seq`` is also what keeps a parent row in
        front of the child that references it.
        """
        if not isinstance(payload, dict) \
                or not isinstance(payload.get("cursor"), int) \
                or not isinstance(payload.get("has_more"), bool):
            raise BadResponseError(route=route, status=200)
        changes = payload.get("changes")
        if not isinstance(changes, list):
            raise BadResponseError(route=route, status=200)
        previous = cursor
        for change in changes:
            if not isinstance(change, dict) \
                    or not isinstance(change.get("entity"), str) \
                    or not isinstance(change.get("id"), str) \
                    or isinstance(change.get("seq"), bool) \
                    or not isinstance(change.get("seq"), int):
                raise BadResponseError(route=route, status=200)
            if change["seq"] <= previous:
                raise BadResponseError(route=route, status=200)
            previous = change["seq"]
        if payload["cursor"] < previous or payload["cursor"] < cursor:
            raise BadResponseError(route=route, status=200)
        return payload

    def pull_all(self, handler, *, limit=CHANGE_PAGE_LIMIT, max_pages=10000):
        """Drain the change log, page by page, honouring ``has_more``.

        ``handler(page)`` is called for every page; the cursor is persisted
        **after** the handler returns, so a crash in the middle of a page
        replays that page instead of skipping it. Returns the number of pages.
        """
        if not callable(handler):
            raise BadResponseError(route="/sync/changes")
        cursor = self.config.cursor
        pages = 0
        while pages < max_pages:
            page = self.pull(cursor, limit)
            changes = page["changes"]
            if changes:
                try:
                    handler(page)
                except UnresolvedReferenceError as exc:
                    # Fail closed: the cursor is not advanced, so the next
                    # start re-reads exactly this page, and the caller gets a
                    # stable code instead of a mapping exception (section 11).
                    raise UnresolvedReferenceCloudError() from exc
            cursor = page["cursor"]
            self.config.set_cursor(cursor)
            self.config.save()
            pages += 1
            if not page["has_more"]:
                break
        return pages

    def import_document(self, body):
        """``POST /bootstrap/import`` — the one-shot seed of spec §8.

        The device credential is the principal (the route requires a device
        bearer) and the logged-in user's access token travels in
        ``X-Acting-User``, because the host refuses an import without an
        acting identity and import is admin-only. That token is RAM-only, so an
        absent or expired session raises here instead of sending a request the
        host can only reject.
        """
        return self._request("POST", "/bootstrap/import", body=body,
                             acting=True)

    def trigger_backup(self):
        """``POST /admin/backup`` — triggers automated DB dump to Telegram on the host."""
        return self._request("POST", "/admin/backup", body={}, acting=True)

    def push(self, operations):
        """``POST /sync/mutations`` — batched push; conflicts come back as data.

        Every operation must carry an ``operation_id``. When it does not, one
        is minted **into the caller's dict**, so a retry of the same dict reuses
        the id and the server replays its first result instead of applying the
        change twice (spec §6.1).
        """
        if not isinstance(operations, (list, tuple)) or not operations:
            raise BadResponseError(route="/sync/mutations")
        prepared = []
        for operation in operations:
            if not isinstance(operation, dict):
                raise BadResponseError(route="/sync/mutations")
            if not isinstance(operation.get("operation_id"), str) \
                    or not operation["operation_id"]:
                operation["operation_id"] = _ids.new_uuid()
            if operation.get("kind") not in ("upsert", "delete"):
                raise BadResponseError(route="/sync/mutations")
            if not isinstance(operation.get("entity"), str) \
                    or operation["entity"] not in _ids.ENTITIES:
                raise BadResponseError(route="/sync/mutations")
            if not isinstance(operation.get("id"), str) or not operation["id"]:
                raise BadResponseError(route="/sync/mutations")
            prepared.append(operation)
        prepared = push_order(prepared)
        # No in-client retry here: spec §9 gives the backoff to the outbox,
        # and re-sending a batch is the outbox's decision to make.
        payload = self._request("POST", "/sync/mutations",
                                body={"operations": prepared})
        return self._parse_push(payload)

    def _parse_push(self, payload):
        applied = payload.get("applied")
        conflicts = payload.get("conflicts")
        cursor = payload.get("cursor")
        if not isinstance(applied, list) or not all(
                isinstance(item, str) for item in applied) \
                or not isinstance(conflicts, list) \
                or not isinstance(cursor, int):
            raise BadResponseError(route="/sync/mutations", status=200)
        rows = []
        for item in conflicts:
            if not isinstance(item, dict) \
                    or not isinstance(item.get("operation_id"), str) \
                    or not isinstance(item.get("entity"), str) \
                    or not isinstance(item.get("id"), str) \
                    or not isinstance(item.get("server_version"), int):
                raise BadResponseError(route="/sync/mutations", status=200)
            rows.append(Conflict(item["operation_id"], item["entity"],
                                 item["id"], item["server_version"],
                                 item.get("server_record")))
        result = PushResult(applied, rows, cursor)
        if result.cursor >= self.config.cursor:
            # The server's cursor only ever moves forward; adopting it here is
            # what keeps a pull after a push from re-reading what we just wrote.
            self.config.set_cursor(result.cursor)
            self.config.save()
        return result

    # ------------------------------------------------------------------
    def _remember_cursor(self, payload, route):
        cursor = payload.get("cursor")
        if isinstance(cursor, bool) or not isinstance(cursor, int) \
                or cursor < 0:
            raise BadResponseError(route=route, status=200)
        if "collections" not in payload:
            raise BadResponseError(route=route, status=200)
        self.config.set_cursor(cursor, payload.get("dataset_epoch"))
        self.config.save()
        return cursor
