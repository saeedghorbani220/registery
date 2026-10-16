"""cloud_sync.apply — the pull path: a payload becomes ``crm_store.json`` (J).

Spec §6.2 hands the client pages; spec §9 says a pull must never overwrite a
locally dirty row; manager ruling 13 puts the one wire/document reconciliation
seam here. This module is that seam:

    client.bootstrap()      -> apply_snapshot(payload, ...)
    client.pull_all(handler) -> handler = apply_changes(page, ...)

It is a pure library with injected I/O: ``store`` is an object with
``read()``/``write(document)``, ``versions`` is a mapping the caller owns and
persists, ``dirty`` is a predicate the caller derives from the outbox. Nothing
imports ``crm`` or ``panel``, and nothing touches the network, the cursor or
the clock.

Wire shape (manager ruling 13)
------------------------------
Every entity in ``payload["collections"]`` is a **list of envelopes**
``{id, tenant_id, row_version, record}`` — ``settings`` included. Unwrap every
envelope, collapse ``settings`` (0 → ``{}``, 1 → that record, **>1 → fail
closed**), then hand the *document* shape to :func:`mapper.merge_store`, which
is the inverse of ``split_store`` and takes ``settings`` as one dict. The
envelope never reaches the store: spec §15.1 keeps the cloud UUID outside
``record``, where the robots must never see it.

Rules this module keeps
-----------------------
* **Local wins while it is dirty** (§9): a row the outbox still holds is never
  replaced — not by an incremental change, and not by a full snapshot. Once it
  is pushed, the host copy comes back on the next pull.
* **Versions only move forward**: a row is written only when the remote
  ``row_version`` is *greater* than the version recorded for that row (0 when
  the row is absent, i.e. every first sighting). Equal or older is a no-op,
  never a downgrade.
* **Idempotent**: the same page applied twice leaves the same bytes, and an
  apply that changes nothing does not write at all (no ``.bak`` churn, no
  mtime churn for the robots' benefit).
* **Fail closed**: an unknown entity, a malformed envelope, a record that
  does not decode or a reference this machine cannot resolve raises *before*
  a single byte is written — half a store is worse than none. Repeated row ids
  in an incremental page are collapsed to their latest occurrence while
  retaining the first occurrence's position, because one row may legitimately
  have several ordered log entries after the cursor.
  :class:`mapper.UnresolvedReferenceError` is never caught, so
  ``client.pull_all`` can turn it into the stable ``UNRESOLVED_REFERENCE``
  code and leave the cursor where it was.
* **The cursor belongs to the client**: nothing here reads or writes it.
* **One atomic write**: the finished document goes through
  :meth:`FileStore.write`, which mirrors ``crm._store_write`` (same JSON
  formatting, one generation of ``.bak``, then ``os.replace``).

Assumptions the caller must honour
----------------------------------
``source_installation_id`` must be the *tenant's* value (the one
``GET /sync/bootstrap`` returns), the same on every machine of the tenant —
uuid5 is one way, so the local index that turns a cloud UUID back into the
store's eight-hex id is only reproducible when both sides share it. ``dirty``
is keyed by the cloud UUID of spec §6.1 *or* by the local legacy id; both are
accepted so an outbox built either way is protected.

Version state is committed **after** the store write, never before: a page
that raises halfway must leave ``versions`` exactly as it was, or the rows it
never wrote would look applied and the next pull would skip them.
"""
import json
import os

from cloud_sync import mapper
from cloud_sync.errors import BadResponseError, RemoteNotReadyError
from cloud_sync.ids import ENTITIES, legacy_to_uuid
from cloud_sync.mapper import (SETTINGS_LEGACY_ID, STORE_COLLECTIONS,
                               transaction_legacy_id)

__all__ = [
    "BOOTSTRAP_ROUTE", "CHANGES_ROUTE", "SYNCED_STORE_KEYS",
    "ApplyReport", "FileStore",
    "unwrap_collections", "apply_snapshot", "apply_changes",
]

BOOTSTRAP_ROUTE = "/sync/bootstrap"
CHANGES_ROUTE = "/sync/changes"

#: The ``crm_store.json`` keys this module rewrites. Everything else in the
#: local document (``version``, and anything a future version adds) is carried
#: over untouched.
SYNCED_STORE_KEYS = tuple(key for key, _entity in STORE_COLLECTIONS) + ("settings",)

_ENTITY_SET = frozenset(ENTITIES)
_STORE_KEYS = {entity: key for key, entity in STORE_COLLECTIONS}
_ENVELOPE_FIELDS = ("id", "tenant_id", "row_version", "record")
_CHANGE_FIELDS = ("entity", "id", "seq", "row_version", "record")


def _bad(route):
    """The one rejection a malformed payload gets: stable ``BAD_PAYLOAD``."""
    return BadResponseError(route=route, status=200)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

class ApplyReport(object):
    """What one apply did — the observable part of spec §9.

    ``applied``/``removed`` count rows the remote copy won, ``stale`` rows the
    version gate refused, ``protected`` rows the outbox refused, and
    ``written`` says whether the document actually changed on disk.
    """

    __slots__ = ("applied", "removed", "stale", "protected", "written")

    def __init__(self, applied=0, removed=0, stale=0, protected=0,
                 written=False):
        self.applied = applied
        self.removed = removed
        self.stale = stale
        self.protected = protected
        self.written = written

    @property
    def changed(self):
        """Rows whose remote copy was accepted (written or already equal)."""
        return self.applied + self.removed

    def __repr__(self):
        return ("ApplyReport(applied=%d, removed=%d, stale=%d, "
                "protected=%d, written=%r)"
                % (self.applied, self.removed, self.stale, self.protected,
                   self.written))


# --------------------------------------------------------------------------
# Local store (injected I/O)
# --------------------------------------------------------------------------

class FileStore(object):
    """``crm_store.json`` as the injected read/write pair this module needs.

    The write mirrors ``crm._store_write`` so both writers produce the same
    bytes and the same recovery story: JSON with ``indent=1`` and unescaped
    non-ASCII (the document holds Persian text), one generation of ``.bak``,
    then ``os.replace`` — a crash can leave a ``.tmp`` behind but never a
    half-written store. Reads fall back to ``.bak`` exactly like
    ``crm._store_read``; when neither file parses, this raises instead of
    handing an empty document to a snapshot that would then overwrite the
    evidence.
    """

    def __init__(self, path):
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        self.path = path

    def read(self):
        found = False
        for candidate in (self.path, self.path + ".bak"):
            try:
                with open(candidate, encoding="utf-8") as handle:
                    loaded = json.load(handle)
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                continue                    # unreadable: try the backup
            if isinstance(loaded, dict):
                return loaded
            found = True                    # parses, but is not a document
        if found or os.path.exists(self.path):
            raise mapper.FieldTypeError(
                "local store is not a readable JSON object")
        return {}

    def write(self, document):
        if not isinstance(document, dict):
            raise ValueError("document must be a JSON object")
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=1)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            if os.path.exists(self.path):
                os.replace(self.path, self.path + ".bak")
            else:
                with open(self.path + ".bak", "w", encoding="utf-8") as handle:
                    json.dump(document, handle, ensure_ascii=False, indent=1)
                    handle.flush()
                    os.fsync(handle.fileno())
        except OSError:
            pass                          # crm._store_write tolerates this too
        os.replace(tmp, self.path)


def _read_document(store, route):
    read = getattr(store, "read", None)
    if not callable(read):
        raise TypeError("store must provide a callable read()")
    document = read()
    if not isinstance(document, dict):
        raise mapper.FieldTypeError(
            "local store must be a dict, got %s" % type(document).__name__)
    return document


def _require_writer(store):
    if not callable(getattr(store, "write", None)):
        raise TypeError("store must provide a callable write(document)")


def _require_versions(versions):
    if versions is None:
        raise TypeError("versions is required: a mapping this apply owns")
    if not hasattr(versions, "get") or not hasattr(versions, "__setitem__"):
        raise TypeError("versions must be a mutable mapping "
                        "{(entity, cloud_id): row_version}")


# --------------------------------------------------------------------------
# Dirty rows (spec §9)
# --------------------------------------------------------------------------

def _dirty_predicate(dirty):
    """Normalise ``dirty`` into ``predicate(entity, key) -> bool``."""
    if dirty is None:
        return lambda entity, key: False
    if callable(dirty):
        return lambda entity, key: bool(dirty(entity, key))
    keys = set()
    try:
        items = list(dirty)
    except TypeError:
        raise TypeError("dirty must be a callable or an iterable of "
                        "(entity, id) pairs") from None
    for item in items:
        # A bare id would silently protect nothing (the lookup always carries
        # the entity), so the shape is checked instead of assumed.
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError("dirty must hold (entity, id) pairs, got %r"
                            % (item,))
        keys.add((item[0], item[1]))
    keys = frozenset(keys)
    return lambda entity, key: (entity, key) in keys


def _protected(is_dirty, entity, cloud_id, local_id):
    """Whether spec §9 forbids writing this row.

    Both identities are offered: the outbox carries the cloud UUID of §6.1,
    an operator-written set is far more likely to carry the eight-hex id the
    store holds. Either one protects the row.
    """
    if cloud_id and is_dirty(entity, cloud_id):
        return True
    return bool(local_id) and is_dirty(entity, local_id)


# --------------------------------------------------------------------------
# Row helpers
# --------------------------------------------------------------------------

def _records(rows, what):
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise mapper.FieldTypeError(
            f"{what} must be a list, got {type(rows).__name__}")
    for index, record in enumerate(rows):
        if not isinstance(record, dict):
            raise mapper.FieldTypeError(
                f"{what}[{index}] must be a dict, got "
                f"{type(record).__name__}")
    return list(rows)


def _records_by_id(rows, what):
    out = {}
    for record in _records(rows, what):
        legacy = record.get("id")
        if isinstance(legacy, str) and legacy:
            out[legacy] = record
    return out


def _transactions(customer):
    return _records(customer.get("transactions"),
                    f"customers[{customer.get('id')!r}].transactions")


def _tx_cloud_id(source_installation_id, customer_legacy_id, position):
    return legacy_to_uuid(source_installation_id, "customer_transactions",
                          transaction_legacy_id(customer_legacy_id, position))


def _tx_local_id(customer_legacy_id, position):
    return transaction_legacy_id(customer_legacy_id, position)


def _local_index(document, source_installation_id):
    """``{(entity, cloud_id): local_id}`` for every row the document holds.

    ``mapper.reference_index`` already covers the five entities that carry a
    source id; the two synthetic ones (spec §15.2) have no row of their own in
    the document, so they are derived here from the constant settings key and
    from each customer's nested transactions. This is the only way a tombstone
    — ``record: null``, so it carries no id of its own — can be resolved.
    """
    index = mapper.reference_index(
        document, source_installation_id=source_installation_id)
    index[("settings", legacy_to_uuid(
        source_installation_id, "settings", SETTINGS_LEGACY_ID))] = \
        SETTINGS_LEGACY_ID
    for customer in _records(document.get("customers"), "customers"):
        legacy = customer.get("id")
        if not isinstance(legacy, str) or not legacy:
            continue
        for position in range(len(_transactions(customer))):
            index[("customer_transactions", _tx_cloud_id(
                source_installation_id, legacy, position))] = \
                _tx_local_id(legacy, position)
    return index


# --------------------------------------------------------------------------
# Ruling 13 — wire shape to document shape
# --------------------------------------------------------------------------

def unwrap_collections(collections, *, source_installation_id,
                       route=BOOTSTRAP_ROUTE):
    """Envelope lists → ``mapper.merge_store`` input, plus the row versions.

    Returns ``(rows, envelopes)``: ``rows`` is the *document* shape
    ``merge_store`` takes (``settings`` a single dict, everything else a list
    of wire records), and ``envelopes`` is a list of
    ``(entity, cloud_id, row_version, local_id)`` — the cloud id the host
    named, the version it carries, and the id the local store will hold.

    Everything structural is rejected here with ``BAD_PAYLOAD``: a collection
    that is not a list, an envelope missing a field of ruling 13, a
    ``row_version`` that is not an int >= 1, an unknown or missing entity, a
    ``settings`` list of more than one element, and duplicate cloud ids or
    duplicate local ids inside one entity. A reference that cannot be resolved
    is left to :func:`mapper.merge_store` so it surfaces as
    :class:`mapper.UnresolvedReferenceError`.
    """
    _require_installation(source_installation_id)
    if not isinstance(collections, dict):
        raise _bad(route)
    if set(collections) != _ENTITY_SET:
        # Exactly §3's seven entities: a missing key would silently wipe a
        # collection, an extra one would be data this client cannot write.
        raise _bad(route)
    rows = {entity: [] for entity in ENTITIES}
    seen_cloud = {entity: set() for entity in ENTITIES}
    raw = []
    for entity in ENTITIES:
        items = collections[entity]
        if not isinstance(items, list):
            raise _bad(route)
        for item in items:
            cloud_id, row_version, record = _envelope(item, route)
            if cloud_id in seen_cloud[entity]:
                raise _bad(route)          # duplicate id in one batch
            seen_cloud[entity].add(cloud_id)
            raw.append((entity, cloud_id, row_version, record))
            rows[entity].append(record)
    # Ruling 13: 0 -> {}, 1 -> that record, >1 -> fail closed with BAD_PAYLOAD.
    settings = rows["settings"]
    if len(settings) > 1:
        raise _bad(route)
    rows["settings"] = dict(settings[0]) if settings else {}
    # One index for the whole batch: uuid5 cannot be inverted, so a wire
    # foreign key is resolved from the rows that travel beside it.
    index = mapper.reference_index(
        rows, source_installation_id=source_installation_id)
    seen_local = {entity: set() for entity in ENTITIES}
    envelopes = []
    for entity, cloud_id, row_version, record in raw:
        local_id = _local_id(entity, record, index)
        if local_id is not None:
            if local_id in seen_local[entity]:
                raise _bad(route)          # duplicate id in one batch
            seen_local[entity].add(local_id)
        envelopes.append((entity, cloud_id, row_version, local_id))
    return rows, envelopes


def _require_installation(source_installation_id):
    if not isinstance(source_installation_id, str) \
            or not source_installation_id:
        raise mapper.FieldTypeError(
            "source_installation_id must be a non-empty string, got "
            f"{source_installation_id!r}")


def _local_id(entity, record, index):
    """The id this record will hold in ``crm_store.json`` (spec §15.1/§15.2)."""
    if entity == "settings":
        return SETTINGS_LEGACY_ID
    if entity == "customer_transactions":
        return _transaction_local_id(record, index)
    local_id = record.get("id")
    # Absent/unusable: let ``mapper.merge_store`` raise the precise error
    # rather than inventing an id here.
    return local_id if isinstance(local_id, str) and local_id else None


def _transaction_local_id(record, index):
    """``<customer legacy id>/<seq>`` for one wire transaction (spec §15.2).

    The parent UUID is resolved through the batch's own reference index; a
    parent this batch cannot resolve is an unresolved reference, which must
    propagate (§9, spec §4) rather than become a silent hole in the ledger.
    """
    if "customer_id" not in record or "seq" not in record:
        return None                        # merge_store reports it precisely
    customer_uuid = record["customer_id"]
    if not isinstance(customer_uuid, str) or not customer_uuid:
        return None
    customer_legacy = index.get(("customers", customer_uuid))
    if customer_legacy is None:
        raise mapper.UnresolvedReferenceError(
            "customer_transactions: no local customers record maps to %r"
            % (customer_uuid,))
    return transaction_legacy_id(customer_legacy, record["seq"])


def _envelope(item, route):
    if not isinstance(item, dict):
        raise _bad(route)
    for field in _ENVELOPE_FIELDS:
        if field not in item:
            raise _bad(route)
    cloud_id = item["id"]
    tenant_id = item["tenant_id"]
    row_version = item["row_version"]
    record = item["record"]
    if not isinstance(cloud_id, str) or not cloud_id:
        raise _bad(route)
    if not isinstance(tenant_id, str) or not tenant_id:
        raise _bad(route)
    if isinstance(row_version, bool) or not isinstance(row_version, int) \
            or row_version < 1:
        raise _bad(route)
    if not isinstance(record, dict):
        # A snapshot carries no tombstones (host/src/Sync.php filters
        # deleted_at); a null record here is a payload this contract forbids.
        raise _bad(route)
    return cloud_id, row_version, record


# --------------------------------------------------------------------------
# Snapshot apply
# --------------------------------------------------------------------------

def apply_snapshot(payload, *, store, source_installation_id, versions,
                   dirty=None, tz=mapper.IRAN_TZ, route=BOOTSTRAP_ROUTE):
    """Materialise the local store from a full bootstrap payload (spec §8.6).

    The payload becomes the document: every collection is replaced by the host
    copy, except a row the outbox still holds, which keeps its local record
    (including a locally dirty transaction inside an otherwise remote
    customer). Local-only settings keys and the document's non-synced top
    level keys survive, because a device must never lose what the host does
    not know about (spec §3).

    ``versions`` gains one entry per envelope whose row was actually taken, so
    a replayed snapshot is a no-op. ``cursor``/``dataset_epoch`` belong to
    ``client.bootstrap`` and are not read here.
    """
    _require_writer(store)
    _require_versions(versions)
    if not isinstance(payload, dict):
        raise _bad(route)
    rows, envelopes = unwrap_collections(
        payload.get("collections"),
        source_installation_id=source_installation_id, route=route)
    merged = mapper.merge_store(rows, tz=tz,
                                source_installation_id=source_installation_id)
    local = _read_document(store, route)
    local_count = sum(
        len(local.get(store_key) or [])
        for store_key, _entity in STORE_COLLECTIONS
        if isinstance(local.get(store_key), list)
    )
    bootstrap_status = payload.get("bootstrap_status")
    if bootstrap_status is not None and bootstrap_status != "done":
        raise RemoteNotReadyError(route=route)
    if local_count > 0 and not envelopes:
        raise RemoteNotReadyError(route=route)
    is_dirty = _dirty_predicate(dirty)
    document = dict(local)
    taken = set()
    # The host's own cloud ids, keyed by the local id each envelope resolves
    # to: a dirty check must use the id the outbox holds, not one recomputed
    # from uuid5, or a mismatched installation id would stop protecting edits.
    cloud_by_local = {(entity, local_id): cloud_id
                      for entity, cloud_id, _version, local_id in envelopes
                      if local_id is not None}

    for store_key, entity in STORE_COLLECTIONS:
        if entity == "customers":
            document[store_key], part = _snapshot_customers(
                merged.get(store_key), local.get(store_key), is_dirty,
                source_installation_id, cloud_by_local)
        else:
            document[store_key], part = _snapshot_collection(
                entity, merged.get(store_key), local.get(store_key), is_dirty,
                source_installation_id, cloud_by_local)
        taken |= part
    settings, settings_taken = _snapshot_settings(
        merged.get("settings"), local.get("settings"), is_dirty,
        source_installation_id, cloud_by_local)
    document["settings"] = settings
    if settings_taken:
        taken.add(("settings", SETTINGS_LEGACY_ID))

    pending = [(entity, cloud_id, row_version)
               for entity, cloud_id, row_version, local_id in envelopes
               if local_id is not None and (entity, local_id) in taken]
    applied = len(pending)
    report = ApplyReport(applied=applied, protected=len(envelopes) - applied)
    # Version state is committed only once the document is on disk: a write
    # that fails must not leave rows that were never written looking applied.
    if document != local:
        store.write(document)
        report.written = True
    for entity, cloud_id, row_version in pending:
        versions[(entity, cloud_id)] = row_version
    return report


def _snapshot_collection(entity, merged_rows, local_rows, is_dirty,
                         source_installation_id, cloud_by_local):
    merged_rows = _records(merged_rows, f"collections.{entity}")
    local_by_id = _records_by_id(local_rows, f"store[{_STORE_KEYS[entity]}]")
    out, taken = [], set()
    present = set()
    for record in merged_rows:
        legacy = record["id"]
        present.add(legacy)
        cloud_id = cloud_by_local.get(
            (entity, legacy)) or legacy_to_uuid(
                source_installation_id, entity, legacy)
        if legacy in local_by_id and _protected(
                is_dirty, entity, cloud_id, legacy):
            out.append(local_by_id[legacy])     # §9: local wins while dirty
            continue
        taken.add((entity, legacy))
        out.append(record)
    for legacy, record in local_by_id.items():
        if legacy in present:
            continue
        cloud_id = cloud_by_local.get(
            (entity, legacy)) or legacy_to_uuid(
                source_installation_id, entity, legacy)
        if _protected(is_dirty, entity, cloud_id, legacy):
            out.append(record)                  # a dirty row never vanishes
    return out, taken


def _snapshot_customers(merged_rows, local_rows, is_dirty,
                        source_installation_id, cloud_by_local):
    merged_rows = _records(merged_rows, "collections.customers")
    local_by_id = _records_by_id(local_rows, "store[customers]")
    out, taken = [], set()
    present = set()
    for record in merged_rows:
        legacy = record["id"]
        present.add(legacy)
        cloud_id = cloud_by_local.get(
            ("customers", legacy)) or legacy_to_uuid(
                source_installation_id, "customers", legacy)
        if legacy in local_by_id and _protected(
                is_dirty, "customers", cloud_id, legacy):
            out.append(local_by_id[legacy])
            continue
        taken.add(("customers", legacy))
        out.append(_snapshot_transactions(
            record, local_by_id.get(legacy), is_dirty, source_installation_id,
            taken, cloud_by_local))
    for legacy, record in local_by_id.items():
        if legacy in present:
            continue
        cloud_id = cloud_by_local.get(
            ("customers", legacy)) or legacy_to_uuid(
                source_installation_id, "customers", legacy)
        if _protected(is_dirty, "customers", cloud_id, legacy) or any(
                _protected(is_dirty, "customer_transactions",
                           _tx_cloud_id(source_installation_id, legacy, pos),
                           _tx_local_id(legacy, pos))
                for pos in range(len(_transactions(record)))):
            out.append(record)
    return out, taken


def _snapshot_transactions(remote_customer, local_customer, is_dirty,
                           source_installation_id, taken, cloud_by_local):
    """Keep locally dirty transactions inside an otherwise remote customer.

    ``seq`` is the index ``lift_transactions`` assigns, so a transaction's
    position in the list *is* its identity — that is what lets a dirty local
    ledger row be matched against the host's copy without an id of its own.
    """
    remote = _transactions(remote_customer)
    local = _transactions(local_customer) if local_customer else []
    merged = []
    for position in range(max(len(remote), len(local))):
        legacy = _tx_local_id(remote_customer["id"], position)
        cloud_id = cloud_by_local.get(
            ("customer_transactions", legacy)) or _tx_cloud_id(
                source_installation_id, remote_customer["id"], position)
        local_tx = local[position] if position < len(local) else None
        remote_tx = remote[position] if position < len(remote) else None
        if local_tx is not None and _protected(
                is_dirty, "customer_transactions", cloud_id, legacy):
            merged.append(local_tx)             # §9: the local edit survives
            continue
        if remote_tx is None:
            continue                            # the host has no such row
        taken.add(("customer_transactions", legacy))
        merged.append(remote_tx)
    out = dict(remote_customer)
    out["transactions"] = merged
    return out


def _snapshot_settings(merged_settings, local_settings, is_dirty,
                       source_installation_id, cloud_by_local):
    """Merge the host settings into the local dict, or keep it while dirty.

    Returns ``(document settings, taken)``: ``taken`` is false when the row is
    dirty, so a local-only key can never be displaced by a snapshot and no
    version is recorded for a copy that was not written.
    """
    if not isinstance(local_settings, dict) and local_settings is not None:
        raise mapper.FieldTypeError(
            "store[settings] must be a dict, got %s"
            % type(local_settings).__name__)
    cloud_id = cloud_by_local.get(
        ("settings", SETTINGS_LEGACY_ID)) or legacy_to_uuid(
            source_installation_id, "settings", SETTINGS_LEGACY_ID)
    if local_settings is not None and _protected(
            is_dirty, "settings", cloud_id, SETTINGS_LEGACY_ID):
        # Nothing local means nothing to protect, exactly like a collection
        # row: the host copy is taken rather than dropped.
        return dict(local_settings), False
    incoming = merged_settings or {}
    if not isinstance(incoming, dict):
        raise mapper.FieldTypeError(
            "collections.settings must decode to a dict, got %s"
            % type(incoming).__name__)
    return mapper.merge_settings(local_settings or {}, incoming), True


# --------------------------------------------------------------------------
# Incremental apply
# --------------------------------------------------------------------------

def apply_changes(page, *, store, source_installation_id, versions,
                  dirty=None, tz=mapper.IRAN_TZ, route=CHANGES_ROUTE):
    """Apply one ``{"changes": [...]}`` page to the local store (spec §6.2).

    Each change is evaluated on its own: the row is written only when its
    ``row_version`` is greater than the one recorded for it and the row is not
    dirty, a ``record: null`` tombstone removes it, and an unknown tombstone
    is a no-op. Changes inside one page see the rows the earlier changes of
    the same page wrote, so a parent can be created immediately before its
    child — while the document is only written once, at the end, so a failure
    halfway leaves the store exactly as it was.

    The cursor is **not** read or written: ``client.pull_all`` owns it and
    advances it only after this returns. ``UnresolvedReferenceError`` is never
    caught, so a page that points at a parent this machine does not have is
    turned into a stable code there and replayed on the next start.
    """
    _require_writer(store)
    _require_versions(versions)
    changes = _page_changes(page, route=route)
    is_dirty = _dirty_predicate(dirty)
    local = _read_document(store, route)
    document = dict(local)
    index = _local_index(document, source_installation_id)
    report = ApplyReport()

    pending = []
    for entity, cloud_id, row_version, record in changes:
        local_id = index.get((entity, cloud_id))
        if row_version <= versions.get((entity, cloud_id), 0):
            report.stale += 1                  # never a downgrade
            continue
        if _protected(is_dirty, entity, cloud_id, local_id):
            report.protected += 1              # §9: local wins while dirty
            continue
        if record is None:
            if _remove(document, entity, local_id):
                report.removed += 1
        else:
            applied_id = _upsert(document, entity, cloud_id, record, index,
                                 tz, local_id)
            # Remember the mapping straight away: a later tombstone in the
            # same page must find the row this page just created.
            index[(entity, cloud_id)] = applied_id
            report.applied += 1
        pending.append(((entity, cloud_id), row_version))

    # Version state is committed only once the document is on disk: a failure
    # halfway must leave `versions` untouched, or the rows it never wrote would
    # look applied and the next pull would skip them for good.
    if document != local:
        store.write(document)
        report.written = True
    for key, row_version in pending:
        versions[key] = row_version
    return report


def _page_changes(page, route):
    if not isinstance(page, dict):
        raise _bad(route)
    changes = page.get("changes")
    if not isinstance(changes, list):
        raise _bad(route)
    out = []
    seen = {}
    for change in changes:
        if not isinstance(change, dict):
            raise _bad(route)
        for field in _CHANGE_FIELDS:
            if field not in change:
                raise _bad(route)
        entity = change["entity"]
        cloud_id = change["id"]
        seq = change["seq"]
        row_version = change["row_version"]
        record = change["record"]
        if not isinstance(entity, str) or entity not in _ENTITY_SET:
            raise _bad(route)                  # unknown entity
        if not isinstance(cloud_id, str) or not cloud_id:
            raise _bad(route)
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise _bad(route)
        if isinstance(row_version, bool) or not isinstance(row_version, int) \
                or row_version < 1:
            raise _bad(route)
        if record is not None and not isinstance(record, dict):
            raise _bad(route)
        key = (entity, cloud_id)
        out_index = seen.get(key)
        if out_index is not None:
            # One row may legitimately have several change_log entries after
            # the caller's cursor. The real host returns the current live
            # snapshot for each entry while the executable fake preserves the
            # historical snapshots. In either representation the final entry
            # is the state the client must apply. Keep the first occurrence's
            # position so parent-before-child dependency order is preserved,
            # but replace its payload/version with the latest occurrence.
            out[out_index] = (entity, cloud_id, row_version, record)
            continue
        seen[key] = len(out)
        out.append((entity, cloud_id, row_version, record))
    return out


def _upsert(document, entity, cloud_id, record, index, tz, prior):
    """Write one wire record into the document; returns its local id."""
    if entity == "settings":
        return _upsert_settings(document, record, index, tz, cloud_id, prior)
    if entity == "customer_transactions":
        return _upsert_transaction(document, record, index, tz, cloud_id,
                                   prior)
    return _upsert_row(document, entity, record, index, tz, cloud_id, prior)


def _guard(prior, local_id, entity, cloud_id):
    if prior is not None and prior != local_id:
        raise mapper.MappingError(
            "%s: %s resolves to %r but the record carries %r"
            % (entity, cloud_id, prior, local_id))


def _upsert_row(document, entity, record, index, tz, cloud_id, prior):
    new = mapper.from_row(entity, record, tz=tz, reference_index=index)
    local_id = new["id"]
    _guard(prior, local_id, entity, cloud_id)
    store_key = _STORE_KEYS[entity]
    rows = _records(document.get(store_key), f"store[{store_key}]")
    out = []
    replaced = False
    for existing in rows:
        if existing.get("id") != local_id:
            out.append(existing)
            continue
        if entity == "customers":
            # A customer change carries no transactions — they have their own
            # rows — so the local ledger stays exactly where it is.
            new = dict(new, transactions=_transactions(existing))
        out.append(new)
        replaced = True
    if not replaced:
        if entity == "customers":
            new = dict(new, transactions=[])
        out.append(new)
    document[store_key] = out
    return local_id


def _upsert_transaction(document, record, index, tz, cloud_id, prior):
    if "customer_id" not in record:
        raise mapper.MissingFieldError(
            "customer_transactions: required field 'customer_id' is missing")
    customer_uuid = record["customer_id"]
    if not isinstance(customer_uuid, str) or not customer_uuid:
        raise mapper.FieldTypeError(
            "customer_transactions.customer_id must be a non-empty string, "
            "got %r" % (customer_uuid,))
    customer_legacy = index.get(("customers", customer_uuid))
    if customer_legacy is None:
        raise mapper.UnresolvedReferenceError(
            "customer_transactions: no local customers record maps to %r"
            % (customer_uuid,))
    if "seq" not in record:
        raise mapper.MissingFieldError(
            "customer_transactions: required field 'seq' is missing")
    position = record["seq"]
    local_id = transaction_legacy_id(customer_legacy, position)
    _guard(prior, local_id, "customer_transactions", cloud_id)
    source = {key: value for key, value in record.items()
              if key not in ("seq", "customer_id")}
    new = mapper.from_row("customer_transactions", source, tz=tz,
                          reference_index=index)
    rows = _records(document.get("customers"), "store[customers]")
    out = []
    replaced = False
    for existing in rows:
        if existing.get("id") != customer_legacy:
            out.append(existing)
            continue
        transactions = _transactions(existing)
        if position > len(transactions):
            # A gap in the ledger: the predecessor rows this machine never
            # received. Applying here would invent an order, so fail closed
            # with the same code a missing parent gets — the cursor stays put
            # and the page is replayed once the hole is filled.
            raise mapper.UnresolvedReferenceError(
                "customer_transactions: %s has no local row for seq %d"
                % (customer_legacy, position))
        if position == len(transactions):
            transactions.append(new)
        else:
            transactions[position] = new
        out.append(dict(existing, transactions=transactions))
        replaced = True
    if not replaced:
        raise mapper.UnresolvedReferenceError(
            "customer_transactions: no local customers record %r"
            % (customer_legacy,))
    document["customers"] = out
    return local_id


def _upsert_settings(document, record, index, tz, cloud_id, prior):
    local_id = SETTINGS_LEGACY_ID
    _guard(prior, local_id, "settings", cloud_id)
    incoming = mapper.from_row("settings", record, tz=tz,
                               reference_index=index)
    base = document.get("settings")
    if base is None:
        base = {}
    if not isinstance(base, dict):
        raise mapper.FieldTypeError(
            "store[settings] must be a dict, got %s" % type(base).__name__)
    # merge_settings keeps every device-local key (spec §3) and drops an
    # unknown incoming key with a warning instead of writing it.
    document["settings"] = mapper.merge_settings(base, incoming)
    return local_id


def _remove(document, entity, local_id):
    """Delete one row; ``True`` when the document actually changed."""
    if local_id is None:
        return False                         # never seen here: nothing to do
    if entity == "settings":
        return False                         # one row per tenant, never deleted
    if entity == "customer_transactions":
        return _remove_transaction(document, local_id)
    store_key = _STORE_KEYS[entity]
    rows = _records(document.get(store_key), f"store[{store_key}]")
    out = [row for row in rows if row.get("id") != local_id]
    if len(out) == len(rows):
        return False
    document[store_key] = out
    return True


def _remove_transaction(document, local_id):
    customer_legacy, _sep, raw_position = local_id.rpartition("/")
    if not customer_legacy or not raw_position.isdigit():
        return False
    position = int(raw_position)
    rows = _records(document.get("customers"), "store[customers]")
    out = []
    removed = False
    for existing in rows:
        if existing.get("id") != customer_legacy:
            out.append(existing)
            continue
        transactions = _transactions(existing)
        if position >= len(transactions):
            out.append(existing)
            continue
        # In CRM, transactions are an append-only accounting ledger where
        # position equals seq. Physically deleting an item shifts array indices,
        # causing sequence holes and corrupting future seq calculations.
        # Mark voided instead of deleting from the list.
        if isinstance(transactions[position], dict):
            transactions[position]["voided_at"] = (
                transactions[position].get("voided_at") or "1970-01-01 00:00:00")
            transactions[position]["void_reason"] = "tombstone"
        out.append(dict(existing, transactions=transactions))
        removed = True
    if not removed:
        return False
    document["customers"] = out
    return True
