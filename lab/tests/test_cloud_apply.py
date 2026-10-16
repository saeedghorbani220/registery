"""Cloud-sync apply/pull path (workstream J) — offline, mock data only.

Covers ``cloud_sync.apply``: the seam that turns a pulled payload back into
the ``crm_store.json`` document the robots read. Ruling 13's envelope
reconciliation, snapshot materialisation, incremental rows and tombstones,
the §9 "local wins while dirty" rule, the never-downgrade version gate,
idempotence, fail-closed rejection and the atomic ``os.replace`` write.

Run:
  "C:/Program Files/Python310/python.exe" lab/scripts/run_panel_tests.py \\
      test_cloud_apply test_cloud_mapper

No network, no real customer data, no writes to %LOCALAPPDATA%\\irica\\ —
every store lives in a throwaway ``tempfile`` directory.
"""
import copy
import inspect
import json
import os
import shutil
import sys
import tempfile
import unittest
import warnings

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cloud_sync import apply, ids, mapper
from cloud_sync.errors import BAD_PAYLOAD, BadResponseError, RemoteNotReadyError

INSTALL = "11111111-1111-4111-8111-111111111111"
TENANT = "22222222-2222-4222-8222-222222222222"
_UNSET = object()                          # sentinel: "no argument given"


# --------------------------------------------------------------------------
# Hand-built fixtures, shaped like real crm_store.json records
# --------------------------------------------------------------------------

TRANSACTIONS = [
    {"at": "2026-09-01 10:05:00", "amount": -24000000,
     "note": "registry fee, sample device", "kind": "base_fee", "image": "",
     "device_id": "d1d2d3d4", "voided_at": "", "void_reason": ""},
    {"at": "2026-09-01 10:06:00", "amount": 5000000,
     "note": "sample receipt", "kind": "receipt", "image": "sample01.png",
     "device_id": ""},
]

CUSTOMER = {
    "id": "a1b2c3d4", "full_name": "Sample Customer",
    "address": "Sample Street 1", "mobile": "09120000001",
    "telegram_id": "@sample_tg", "instagram_id": "", "notes": "sample note",
    "transactions": list(TRANSACTIONS),
    "created": "2026-09-01 10:00:00", "updated": "2026-09-05 14:00:00",
}

OWNER = {
    "id": "e5f6a7b8", "first_name": "Sample", "last_name": "Passenger",
    "national": "0012345679", "birth": "1375/04/29", "mobile": "09120000002",
    "card_no": "6037991234567890", "passport": "AB1234567",
    "created": "2026-09-01 10:10:00",
}

IDENTITY = {
    "id": "c9d0e1f2", "label": "sample pool entry", "national": "0012345679",
    "birth": "1375/04/29", "mobile": "09120000003",
    "created": "2026-09-01 10:11:00", "updated": "2026-09-04 08:00:00",
}

DEVICE = {
    "id": "d1d2d3d4", "name": "sample device",
    "serial1": "123456789012345", "serial2": "543210987654321",
    "customer_id": "a1b2c3d4", "owner_id": "e5f6a7b8", "stage": "closed",
    "auto_advance": True, "profile_id": "prof0001",
    "handed_at": "2026-09-02 09:00:00", "registered_at": "",
    "payment_confirmed_at": "", "code_delivered_at": "", "done_at": "",
    "last_inquiry_at": "", "notes": "sample case notes",
    "advance_attempts": 0, "period_id": "aa11bb22",
    "created": "2026-09-01 10:12:00", "updated": "2026-09-05 14:00:00",
    "skipped_stages": [{"stage": "inquiry", "to": "ready_owner",
                        "at": "2026-09-01 11:00:00"}],
    "closed_at": "2026-09-05 14:00:00",
    "closed_reason": "sample closed reason",
    "periodic_opt_out": True, "payment_started_at": "",
}

PERIOD_OPEN = {
    "id": "aa11bb22", "number": 1, "label": "sample period one",
    "opened_at": "2026-09-01 00:00:00", "opened_by": "operator",
    "closed_at": "", "closed_by": "", "closed_reason": "",
}

PERIOD_CLOSED = {
    "id": "bb33cc44", "number": 2, "label": "sample period two",
    "opened_at": "2026-09-01 00:00:00", "opened_by": "operator",
    "closed_at": "2026-09-06 18:00:00", "closed_by": "operator",
    "closed_reason": "sample month end",
}

SETTINGS = {
    "business_name": "Sample Trading Co", "business_phone": "02100000000",
    "watch_interval_hours": 2, "scheduler_enabled": True,
    "auto_advance_default": False, "telegram_report_full_data": True,
    "registry_fee_amount": 24000000, "registration_chat_id": "-1001234567890",
    "report_chat_id": "", "sound_enabled": True,
    "current_period_id": "aa11bb22",
    "links": [{"name": "sample link", "url": "https://example.invalid/"}],
}

# Device-local keys that must never reach the wire and must never be lost
# locally (spec §3).
LOCAL_ONLY_SETTINGS = {
    "device_token": "placeholder",
    "profile_dir": "C:/placeholder/profiles",
}


def store_fixture():
    """A complete, hand-built CRM document with every synced collection."""
    return {
        "version": 1,
        "customers": [dict(CUSTOMER, transactions=copy.deepcopy(TRANSACTIONS))],
        "owners": [dict(OWNER)],
        "identities": [dict(IDENTITY)],
        "devices": [dict(DEVICE)],
        "periods": [dict(PERIOD_OPEN), dict(PERIOD_CLOSED)],
        "settings": dict(SETTINGS),
    }


def wire(entity, record, **kwargs):
    """The host-side record for one store record (spec §6.1/§15.1)."""
    kwargs.setdefault("source_installation_id", INSTALL)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return mapper.to_row(entity, record, **kwargs)


def cloud(entity, legacy_id):
    return ids.legacy_to_uuid(INSTALL, entity, legacy_id)


def bootstrap_payload(store, *, row_version=1):
    """A §6.2 bootstrap payload built exactly like ``Sync.php`` builds one."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        rows = mapper.split_store(store, source_installation_id=INSTALL)
    index = mapper.reference_index(rows, source_installation_id=INSTALL)
    collections = {}
    for entity in ids.ENTITIES:
        value = rows[entity]
        if entity == "settings":
            items = [value]
            legacy_ids = [mapper.SETTINGS_LEGACY_ID]
        elif entity == "customer_transactions":
            items = value
            legacy_ids = [
                "%s/%s" % (index[("customers", row["customer_id"])], row["seq"])
                for row in value]
        else:
            items = value
            legacy_ids = [row["id"] for row in value]
        collections[entity] = [
            {"id": cloud(entity, legacy), "tenant_id": TENANT,
             "row_version": row_version, "record": row}
            for row, legacy in zip(items, legacy_ids)]
    return {"ok": True, "collections": collections, "cursor": 7,
            "dataset_epoch": 1, "tenant_id": TENANT}


def change(entity, legacy_id, record, *, seq, row_version=1, tombstone=False):
    """One §6.2 change-log row, keyed by the local id it was derived from."""
    return {"entity": entity, "id": cloud(entity, legacy_id), "seq": seq,
            "row_version": row_version,
            "record": None if tombstone else record}


def page(*changes, cursor=11, has_more=False):
    return {"ok": True, "changes": list(changes), "cursor": cursor,
            "has_more": has_more}


# --------------------------------------------------------------------------
# Base fixture: one temp directory, one store, one version map
# --------------------------------------------------------------------------

class ApplyCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="irica_cloud_apply_")
        self.path = os.path.join(self.tmp, "crm_store.json")
        self.store = apply.FileStore(self.path)
        self.versions = {}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- store helpers -----------------------------------------------------
    def write_store(self, document):
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=1)

    def read_store(self):
        with open(self.path, encoding="utf-8") as handle:
            return json.load(handle)

    def read_bytes(self):
        with open(self.path, "rb") as handle:
            return handle.read()

    def seed(self, document=None):
        self.write_store(store_fixture() if document is None else document)
        return self.read_bytes()

    def snapshot(self, payload=_UNSET, **kwargs):
        kwargs.setdefault("store", self.store)
        kwargs.setdefault("source_installation_id", INSTALL)
        kwargs.setdefault("versions", self.versions)
        if payload is _UNSET:
            payload = bootstrap_payload(store_fixture())
        return apply.apply_snapshot(payload, **kwargs)

    def changes(self, *rows, **kwargs):
        kwargs.setdefault("store", self.store)
        kwargs.setdefault("source_installation_id", INSTALL)
        kwargs.setdefault("versions", self.versions)
        return apply.apply_changes(page(*rows), **kwargs)

    def assertStable(self, before, message):
        """The on-disk document must not have moved."""
        self.assertEqual(self.read_bytes(), before, message)


# --------------------------------------------------------------------------
# Ruling 13 — the wire shape
# --------------------------------------------------------------------------

class UnwrapTests(ApplyCase):

    def payload(self):
        return bootstrap_payload(store_fixture())

    def test_every_entity_arrives_as_a_list_of_envelopes(self):
        rows, envelopes = apply.unwrap_collections(
            self.payload()["collections"],
            source_installation_id=INSTALL)
        self.assertEqual(set(rows), set(ids.ENTITIES))
        self.assertIsInstance(rows["settings"], dict)
        self.assertEqual(len(envelopes), sum(
            len(value) for value in self.payload()["collections"].values()))
        for entity, cloud_id, row_version, local_id in envelopes:
            self.assertIn(entity, ids.ENTITIES)
            self.assertTrue(cloud_id)
            self.assertEqual(row_version, 1)
            self.assertTrue(local_id)

    def test_settings_of_zero_elements_collapses_to_an_empty_dict(self):
        collections = self.payload()["collections"]
        collections["settings"] = []
        rows, envelopes = apply.unwrap_collections(
            collections, source_installation_id=INSTALL)
        self.assertEqual(rows["settings"], {})
        self.assertNotIn("settings", [entity for entity, _id, _v, _lid
                                      in envelopes])

    def test_settings_of_one_element_collapses_to_its_record(self):
        collections = self.payload()["collections"]
        rows, envelopes = apply.unwrap_collections(
            collections, source_installation_id=INSTALL)
        self.assertEqual(rows["settings"], collections["settings"][0]["record"])
        self.assertEqual(len(envelopes), sum(
            len(value) for value in collections.values()))

    def test_settings_of_more_than_one_element_fails_closed(self):
        collections = self.payload()["collections"]
        collections["settings"] = collections["settings"] * 2
        with self.assertRaises(BadResponseError) as caught:
            apply.unwrap_collections(collections,
                                     source_installation_id=INSTALL)
        self.assertEqual(caught.exception.code, BAD_PAYLOAD)

    def test_a_bare_settings_object_is_rejected(self):
        collections = self.payload()["collections"]
        collections["settings"] = collections["settings"][0]["record"]
        with self.assertRaises(BadResponseError) as caught:
            apply.unwrap_collections(collections,
                                     source_installation_id=INSTALL)
        self.assertEqual(caught.exception.code, BAD_PAYLOAD)

    def test_a_missing_entity_is_rejected(self):
        collections = self.payload()["collections"]
        del collections["periods"]
        with self.assertRaises(BadResponseError):
            apply.unwrap_collections(collections,
                                     source_installation_id=INSTALL)

    def test_an_unknown_entity_is_rejected(self):
        collections = self.payload()["collections"]
        collections["profiles"] = []
        with self.assertRaises(BadResponseError):
            apply.unwrap_collections(collections,
                                     source_installation_id=INSTALL)

    def test_collections_that_are_not_a_dict_are_rejected(self):
        for value in (None, [], "collections", 3):
            with self.assertRaises(BadResponseError):
                apply.unwrap_collections(value, source_installation_id=INSTALL)

    def test_an_envelope_missing_a_ruling_13_field_is_rejected(self):
        for field in ("id", "tenant_id", "row_version", "record"):
            collections = self.payload()["collections"]
            del collections["owners"][0][field]
            with self.assertRaises(BadResponseError, msg=field):
                apply.unwrap_collections(collections,
                                         source_installation_id=INSTALL)

    def test_an_envelope_field_of_the_wrong_type_is_rejected(self):
        broken = [
            ("id", ""), ("id", 7), ("tenant_id", ""), ("tenant_id", None),
            ("row_version", 0), ("row_version", True), ("row_version", "2"),
            ("record", None), ("record", [{}]),
        ]
        for field, value in broken:
            collections = self.payload()["collections"]
            collections["owners"][0][field] = value
            with self.assertRaises(BadResponseError, msg=repr((field, value))):
                apply.unwrap_collections(collections,
                                         source_installation_id=INSTALL)

    def test_duplicate_cloud_ids_in_one_entity_are_rejected(self):
        collections = self.payload()["collections"]
        collections["owners"].append(dict(collections["owners"][0]))
        with self.assertRaises(BadResponseError):
            apply.unwrap_collections(collections,
                                     source_installation_id=INSTALL)

    def test_duplicate_local_ids_in_one_entity_are_rejected(self):
        collections = self.payload()["collections"]
        twin = dict(collections["owners"][0])
        twin["id"] = "ffffffff"
        collections["owners"].append(twin)
        with self.assertRaises(BadResponseError):
            apply.unwrap_collections(collections,
                                     source_installation_id=INSTALL)

    def test_the_same_legacy_id_in_two_entities_is_not_a_duplicate(self):
        collections = self.payload()["collections"]
        twin = dict(collections["owners"][0])
        twin["id"] = cloud("owners", "a1b2c3d4")
        twin["record"] = dict(twin["record"],
                              id=collections["customers"][0]["record"]["id"])
        collections["owners"].append(twin)
        rows, _envelopes = apply.unwrap_collections(
            collections, source_installation_id=INSTALL)
        self.assertEqual(len(rows["owners"]), 2)

    def test_the_unwrapped_rows_feed_straight_into_merge_store(self):
        rows, _envelopes = apply.unwrap_collections(
            self.payload()["collections"], source_installation_id=INSTALL)
        merged = mapper.merge_store(rows, source_installation_id=INSTALL)
        self.assertEqual(merged["customers"][0]["id"], CUSTOMER["id"])
        self.assertEqual(merged["customers"][0]["transactions"],
                         CUSTOMER["transactions"])
        self.assertEqual(merged["settings"]["current_period_id"], "aa11bb22")

    def test_the_module_never_imports_crm_or_panel(self):
        source = inspect.getsource(apply)
        for needle in ("import crm", "from crm", "import panel", "from panel"):
            self.assertNotIn(needle, source)


# --------------------------------------------------------------------------
# Snapshot apply
# --------------------------------------------------------------------------

class SnapshotTests(ApplyCase):

    def test_a_snapshot_materialises_an_empty_store(self):
        self.write_store({"version": 1,
                          "settings": dict(LOCAL_ONLY_SETTINGS)})
        report = self.snapshot()
        self.assertTrue(report.written)
        expected = dict(store_fixture())
        expected["settings"] = dict(SETTINGS, **LOCAL_ONLY_SETTINGS)
        self.assertEqual(self.read_store(), expected)

    def test_the_snapshot_write_is_deterministic(self):
        self.write_store({"version": 1})
        self.snapshot()
        first = self.read_bytes()
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.makedirs(self.tmp, exist_ok=True)
        self.write_store({"version": 1})
        self.snapshot()
        self.assertEqual(self.read_bytes(), first)

    def test_a_second_snapshot_of_the_same_payload_changes_nothing(self):
        self.write_store({"version": 1,
                          "settings": dict(LOCAL_ONLY_SETTINGS)})
        self.snapshot()
        before = self.read_bytes()
        report = self.snapshot()
        self.assertFalse(report.written)
        self.assertStable(before, "a replayed snapshot must be a no-op")

    def test_document_keys_the_host_does_not_know_about_survive(self):
        self.write_store({"version": 42, "extra": {"kept": True},
                          "settings": dict(LOCAL_ONLY_SETTINGS)})
        self.snapshot()
        document = self.read_store()
        self.assertEqual(document["version"], 42)
        self.assertEqual(document["extra"], {"kept": True})

    def test_local_only_settings_keys_are_never_lost(self):
        self.write_store({"version": 1,
                          "settings": dict(LOCAL_ONLY_SETTINGS)})
        self.snapshot()
        settings = self.read_store()["settings"]
        self.assertEqual(settings["device_token"], "placeholder")
        self.assertEqual(settings["profile_dir"],
                         "C:/placeholder/profiles")
        self.assertEqual(settings["business_name"], SETTINGS["business_name"])

    def test_a_locally_dirty_customer_is_not_replaced(self):
        local = store_fixture()
        local["customers"][0]["notes"] = "LOCAL EDIT"
        self.write_store(local)
        self.snapshot(dirty={("customers", cloud("customers", "a1b2c3d4"))})
        self.assertEqual(self.read_store()["customers"][0]["notes"],
                         "LOCAL EDIT")
        # A row that is not dirty still takes the host copy.
        self.assertEqual(self.read_store()["owners"], [OWNER])

    def test_a_dirty_row_may_be_keyed_by_its_legacy_id_too(self):
        local = store_fixture()
        local["owners"][0]["passport"] = "LOCALPASS"
        self.write_store(local)
        self.snapshot(dirty={("owners", "e5f6a7b8")})
        self.assertEqual(self.read_store()["owners"][0]["passport"],
                         "LOCALPASS")

    def test_a_dirty_row_is_protected_by_the_hosts_own_cloud_id(self):
        # The outbox carries the id the *host* stamped on the row. Even when
        # that is not what this machine's uuid5 would produce, §9 must still
        # refuse to overwrite the local edit.
        local = store_fixture()
        local["owners"][0]["passport"] = "LOCAL EDIT"
        self.write_store(local)
        payload = bootstrap_payload(store_fixture())
        foreign = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        payload["collections"]["owners"][0]["id"] = foreign
        self.snapshot(payload=payload, dirty={("owners", foreign)})
        self.assertEqual(self.read_store()["owners"][0]["passport"],
                         "LOCAL EDIT")

    def test_a_dirty_row_absent_from_the_snapshot_is_kept(self):
        local = store_fixture()
        local["owners"].append(dict(OWNER, id="0a0b0c0d",
                                    passport="NEWLOCAL"))
        self.write_store(local)
        self.snapshot(dirty={("owners", cloud("owners", "0a0b0c0d"))})
        owners = self.read_store()["owners"]
        self.assertIn("0a0b0c0d", [row["id"] for row in owners])

    def test_a_dirty_transaction_survives_inside_a_remote_customer(self):
        local = store_fixture()
        local["customers"][0]["transactions"][0]["note"] = "LOCAL VOID"
        self.write_store(local)
        self.snapshot(dirty={("customer_transactions",
                              cloud("customer_transactions",
                                    "a1b2c3d4/0"))})
        transactions = self.read_store()["customers"][0]["transactions"]
        self.assertEqual(transactions[0]["note"], "LOCAL VOID")
        self.assertEqual(transactions[1], TRANSACTIONS[1])

    def test_a_clean_transaction_takes_the_host_copy(self):
        local = store_fixture()
        local["customers"][0]["transactions"][0]["note"] = "LOCAL VOID"
        self.write_store(local)
        self.snapshot()
        transactions = self.read_store()["customers"][0]["transactions"]
        self.assertEqual(transactions[0]["note"], TRANSACTIONS[0]["note"])

    def test_a_dirty_settings_row_keeps_the_whole_local_dict(self):
        local = store_fixture()
        local["settings"] = dict(SETTINGS, **LOCAL_ONLY_SETTINGS)
        local["settings"]["business_name"] = "LOCAL NAME"
        self.write_store(local)
        self.snapshot(dirty={("settings",
                              cloud("settings", mapper.SETTINGS_LEGACY_ID))})
        self.assertEqual(self.read_store()["settings"]["business_name"],
                         "LOCAL NAME")

    def test_the_snapshot_records_the_row_versions_it_wrote(self):
        self.write_store({"version": 1})
        self.snapshot()
        self.assertEqual(
            self.versions[("customers", cloud("customers", "a1b2c3d4"))], 1)
        self.assertEqual(
            self.versions[("settings",
                           cloud("settings", mapper.SETTINGS_LEGACY_ID))], 1)
        self.assertEqual(
            self.versions[("customer_transactions",
                           cloud("customer_transactions", "a1b2c3d4/0"))], 1)

    def test_a_protected_row_records_no_version(self):
        self.seed()
        self.snapshot(dirty={("owners", cloud("owners", "e5f6a7b8"))})
        self.assertNotIn(("owners", cloud("owners", "e5f6a7b8")),
                         self.versions)
        self.assertIn(("customers", cloud("customers", "a1b2c3d4")),
                      self.versions)

    def test_an_unresolvable_reference_fails_before_any_write(self):
        self.seed()
        before = self.read_bytes()
        payload = bootstrap_payload(store_fixture())
        payload["collections"]["settings"][0]["record"][
            "current_period_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        with self.assertRaises(mapper.UnresolvedReferenceError):
            self.snapshot(payload=payload)
        self.assertStable(before, "a rejected snapshot must not write")
        self.assertEqual(self.versions, {})

    def test_a_transaction_pointing_at_an_unknown_device_is_rejected(self):
        self.seed()
        before = self.read_bytes()
        payload = bootstrap_payload(store_fixture())
        payload["collections"]["customer_transactions"][0]["record"][
            "device_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        with self.assertRaises(mapper.UnresolvedReferenceError):
            self.snapshot(payload=payload)
        self.assertStable(before, "a rejected snapshot must not write")

    def test_a_payload_that_is_not_a_dict_is_rejected(self):
        self.seed()
        before = self.read_bytes()
        for payload in (None, [], "payload"):
            with self.assertRaises(BadResponseError):
                self.snapshot(payload=payload)
        self.assertStable(before, "a rejected payload must not write")

    def test_a_report_counts_what_was_taken_and_what_was_protected(self):
        self.seed()
        report = self.snapshot(dirty={("owners", cloud("owners", "e5f6a7b8"))})
        total = sum(len(value) for value in
                    bootstrap_payload(store_fixture())[
                        "collections"].values())
        self.assertEqual(report.protected, 1)
        self.assertEqual(report.applied, total - 1)


# --------------------------------------------------------------------------
# Incremental apply
# --------------------------------------------------------------------------

class IncrementalTests(ApplyCase):

    def setUp(self):
        super(IncrementalTests, self).setUp()
        self.before = self.seed()

    def test_a_new_row_is_inserted(self):
        record = wire("identities", dict(IDENTITY, id="99887766"))
        report = self.changes(change("identities", "99887766", record, seq=1))
        self.assertTrue(report.written)
        self.assertEqual(report.applied, 1)
        self.assertIn("99887766",
                      [row["id"] for row in self.read_store()["identities"]])
        self.assertEqual(
            self.versions[("identities", cloud("identities", "99887766"))], 1)

    def test_an_existing_row_is_replaced_by_a_newer_version(self):
        updated = dict(OWNER, passport="UPDATED")
        record = wire("owners", updated)
        report = self.changes(change("owners", "e5f6a7b8", record, seq=1,
                                     row_version=2))
        self.assertEqual(report.applied, 1)
        self.assertEqual(self.read_store()["owners"][0]["passport"],
                         "UPDATED")
        self.assertEqual(self.versions[("owners",
                                        cloud("owners", "e5f6a7b8"))], 2)

    def test_an_equal_row_version_is_a_noop(self):
        self.versions[("owners", cloud("owners", "e5f6a7b8"))] = 2
        record = wire("owners", dict(OWNER, passport="SHOULD NOT LAND"))
        report = self.changes(change("owners", "e5f6a7b8", record, seq=1,
                                     row_version=2))
        self.assertEqual(report.stale, 1)
        self.assertFalse(report.written)
        self.assertStable(self.before, "an equal version must not downgrade")

    def test_an_older_row_version_is_a_noop(self):
        self.versions[("owners", cloud("owners", "e5f6a7b8"))] = 5
        record = wire("owners", dict(OWNER, passport="SHOULD NOT LAND"))
        report = self.changes(change("owners", "e5f6a7b8", record, seq=1,
                                     row_version=3))
        self.assertEqual(report.stale, 1)
        self.assertStable(self.before, "an older version must not downgrade")

    def test_a_row_this_machine_has_never_seen_takes_any_version(self):
        record = wire("periods", dict(PERIOD_CLOSED, id="ccddeeff"))
        report = self.changes(change("periods", "ccddeeff", record, seq=1,
                                     row_version=9))
        self.assertEqual(report.applied, 1)
        self.assertIn("ccddeeff",
                      [row["id"] for row in self.read_store()["periods"]])

    def test_a_tombstone_removes_the_row(self):
        report = self.changes(change("identities", "c9d0e1f2", None, seq=1,
                                     row_version=2, tombstone=True))
        self.assertEqual(report.removed, 1)
        self.assertEqual(self.read_store()["identities"], [])
        self.assertNotEqual(self.read_bytes(), self.before)

    def test_a_tombstone_for_an_unknown_row_is_a_noop(self):
        report = self.changes(change("owners", "00000000", None, seq=1,
                                     row_version=2, tombstone=True))
        self.assertEqual(report.removed, 0)
        self.assertStable(self.before, "nothing to remove must write nothing")

    def test_a_tombstone_for_a_customer_removes_its_transactions(self):
        report = self.changes(change("customers", "a1b2c3d4", None, seq=1,
                                     row_version=4, tombstone=True))
        self.assertEqual(report.removed, 1)
        document = self.read_store()
        self.assertEqual(document["customers"], [])

    def test_a_locally_dirty_row_is_not_overwritten(self):
        local = store_fixture()
        local["owners"][0]["passport"] = "LOCAL EDIT"
        self.write_store(local)
        before = self.read_bytes()
        record = wire("owners", dict(OWNER, passport="REMOTE"))
        report = self.changes(
            change("owners", "e5f6a7b8", record, seq=1, row_version=7),
            dirty={("owners", cloud("owners", "e5f6a7b8"))})
        self.assertEqual(report.protected, 1)
        self.assertEqual(self.read_store()["owners"][0]["passport"],
                         "LOCAL EDIT")
        self.assertStable(before, "a dirty row must not be written over")
        self.assertNotIn(("owners", cloud("owners", "e5f6a7b8")),
                         self.versions)

    def test_a_dirty_row_is_protected_against_a_tombstone_too(self):
        report = self.changes(
            change("owners", "e5f6a7b8", None, seq=1, row_version=9,
                   tombstone=True),
            dirty={("owners", "e5f6a7b8")})       # local legacy id form
        self.assertEqual(report.protected, 1)
        self.assertEqual(len(self.read_store()["owners"]), 1)

    def test_settings_changes_merge_and_keep_device_local_keys(self):
        local = store_fixture()
        local["settings"] = dict(SETTINGS, **LOCAL_ONLY_SETTINGS)
        self.write_store(local)
        record = wire("settings", dict(SETTINGS, business_name="HOST NAME",
                                       current_period_id="bb33cc44"))
        report = self.changes(change("settings", mapper.SETTINGS_LEGACY_ID,
                                     record, seq=1, row_version=3))
        settings = self.read_store()["settings"]
        self.assertEqual(report.applied, 1)
        self.assertEqual(settings["business_name"], "HOST NAME")
        self.assertEqual(settings["current_period_id"], "bb33cc44")
        self.assertEqual(settings["profile_dir"],
                         "C:/placeholder/profiles")

    def test_a_customer_change_keeps_the_local_ledger(self):
        record = wire("customers", dict(CUSTOMER, notes="HOST NOTE"))
        self.changes(change("customers", "a1b2c3d4", record, seq=1,
                            row_version=6))
        customer = self.read_store()["customers"][0]
        self.assertEqual(customer["notes"], "HOST NOTE")
        self.assertEqual(customer["transactions"], TRANSACTIONS)

    def test_a_transaction_is_replaced_at_its_sequence(self):
        tx = dict(TRANSACTIONS[0], note="HOST VOID")
        record = wire("customer_transactions",
                      dict(tx, customer_id="a1b2c3d4", seq=0))
        report = self.changes(
            change("customer_transactions", "a1b2c3d4/0", record, seq=1,
                   row_version=5))
        self.assertEqual(report.applied, 1)
        transactions = self.read_store()["customers"][0]["transactions"]
        self.assertEqual(transactions[0]["note"], "HOST VOID")
        self.assertEqual(len(transactions), 2)
        self.assertEqual(transactions[1], TRANSACTIONS[1])

    def test_a_transaction_beyond_the_ledger_appends(self):
        tx = {"at": "2026-09-02 10:00:00", "amount": 1000,
              "note": "appended receipt", "kind": "receipt", "image": "",
              "device_id": "", "voided_at": "", "void_reason": ""}
        record = wire("customer_transactions",
                      dict(tx, customer_id="a1b2c3d4", seq=2))
        self.changes(change("customer_transactions", "a1b2c3d4/2", record,
                            seq=1, row_version=2))
        transactions = self.read_store()["customers"][0]["transactions"]
        self.assertEqual(len(transactions), 3)
        self.assertEqual(transactions[2]["note"], "appended receipt")

    def test_a_hole_in_the_ledger_fails_closed(self):
        tx = dict(TRANSACTIONS[0])
        record = wire("customer_transactions",
                      dict(tx, customer_id="a1b2c3d4", seq=5))
        before = self.read_bytes()
        with self.assertRaises(mapper.UnresolvedReferenceError):
            self.changes(change("customer_transactions", "a1b2c3d4/5",
                                record, seq=1, row_version=2))
        self.assertStable(before, "a rejected page must not write")
        self.assertEqual(self.versions, {})

    def test_a_transaction_whose_customer_is_absent_is_rejected(self):
        tx = dict(TRANSACTIONS[0], device_id="")
        record = wire("customer_transactions",
                      dict(tx, customer_id="deadbeef", seq=0))
        before = self.read_bytes()
        with self.assertRaises(mapper.UnresolvedReferenceError):
            self.changes(change("customer_transactions", "deadbeef/0",
                                record, seq=1, row_version=2))
        self.assertStable(before, "an unresolved reference must not write")
        self.assertEqual(self.versions, {},
                         "version state must not advance past a failed page")

    def test_a_transaction_pointing_at_a_missing_device_is_rejected(self):
        tx = dict(TRANSACTIONS[0],
                  device_id="ffffffff-ffff-4fff-8fff-ffffffffffff")
        record = wire("customer_transactions",
                      dict(tx, customer_id="a1b2c3d4", seq=0))
        with self.assertRaises(mapper.UnresolvedReferenceError):
            self.changes(change("customer_transactions", "a1b2c3d4/0",
                                record, seq=1, row_version=2))
        self.assertStable(self.before, "an unresolved reference must not write")

    def test_a_parent_and_its_child_apply_in_one_page(self):
        customer = dict(CUSTOMER, id="11223344",
                        transactions=[dict(TRANSACTIONS[0], device_id="")])
        customer_record = wire("customers", customer)
        tx_record = wire("customer_transactions",
                         dict(TRANSACTIONS[0], customer_id="11223344",
                              seq=0, device_id=""))
        report = self.changes(
            change("customers", "11223344", customer_record, seq=1),
            change("customer_transactions", "11223344/0", tx_record, seq=2))
        self.assertEqual(report.applied, 2)
        document = self.read_store()
        self.assertEqual(document["customers"][1]["id"], "11223344")
        self.assertEqual(len(document["customers"][1]["transactions"]), 1)

    def test_a_child_before_its_parent_is_rejected(self):
        tx_record = wire("customer_transactions",
                         dict(TRANSACTIONS[0], customer_id="11223344",
                              seq=0, device_id=""))
        with self.assertRaises(mapper.UnresolvedReferenceError):
            self.changes(
                change("customer_transactions", "11223344/0", tx_record,
                       seq=2),
                change("customers", "11223344",
                       wire("customers", dict(CUSTOMER, id="11223344")),
                       seq=1))
        self.assertStable(self.before, "a rejected page must not write")

    def test_a_page_is_idempotent_byte_for_byte(self):
        record = wire("owners", dict(OWNER, passport="UPDATED"))
        rows = (change("owners", "e5f6a7b8", record, seq=1, row_version=2),
                change("identities", "c9d0e1f2", None, seq=2,
                       row_version=2, tombstone=True))
        self.changes(*rows)
        first = self.read_bytes()
        # A second machine starting from the same document and no version
        # state must produce exactly the same bytes.
        self.write_store(store_fixture())
        apply.apply_changes(page(*rows), store=self.store,
                            source_installation_id=INSTALL, versions={})
        self.assertEqual(self.read_bytes(), first)
        # The first machine keeps its version state: the replay writes nothing.
        report = self.changes(*rows)
        self.assertFalse(report.written)
        self.assertEqual(report.stale, 2)
        self.assertEqual(self.read_bytes(), first)

    def test_the_cursor_is_never_read_or_written(self):
        original = page(change("identities", "c9d0e1f2", None, seq=1,
                               row_version=2, tombstone=True),
                        cursor=4242, has_more=True)
        snapshot_of_page = copy.deepcopy(original)
        apply.apply_changes(original, store=self.store,
                            source_installation_id=INSTALL,
                            versions=self.versions)
        self.assertEqual(original, snapshot_of_page)

    def test_an_empty_page_writes_nothing(self):
        report = apply.apply_changes(page(), store=self.store,
                                     source_installation_id=INSTALL,
                                     versions=self.versions)
        self.assertFalse(report.written)
        self.assertStable(self.before, "an empty page must not write")


class RejectTests(ApplyCase):

    def setUp(self):
        super(RejectTests, self).setUp()
        self.before = self.seed()

    def assertRejected(self, payload, message):
        with self.assertRaises(BadResponseError, msg=message) as caught:
            apply.apply_changes(payload, store=self.store,
                                source_installation_id=INSTALL,
                                versions=self.versions)
        self.assertEqual(caught.exception.code, BAD_PAYLOAD, message)
        self.assertStable(self.before, message)
        self.assertEqual(self.versions, {}, message)

    def test_a_page_that_is_not_a_dict_is_rejected(self):
        for value in (None, [], "page", 5):
            self.assertRejected(value, repr(value))

    def test_changes_that_are_not_a_list_are_rejected(self):
        self.assertRejected({"changes": None}, "None")
        self.assertRejected({"changes": {}}, "{}")

    def test_an_unknown_entity_is_rejected(self):
        self.assertRejected(
            page({"entity": "profiles", "id": "x", "seq": 1,
                  "row_version": 1, "record": {}}),
            "unknown entity")

    def test_a_missing_field_is_rejected(self):
        for field in ("entity", "id", "seq", "row_version", "record"):
            row = {"entity": "owners", "id": "x", "seq": 1, "row_version": 1,
                   "record": {}}
            del row[field]
            self.assertRejected(page(row), field)

    def test_a_malformed_row_is_rejected(self):
        good = {"entity": "owners", "id": "x", "seq": 1, "row_version": 1,
                "record": {}}
        for field, value in (("entity", "owner"), ("id", ""), ("id", 3),
                             ("seq", -1), ("seq", True), ("seq", "1"),
                             ("row_version", 0), ("row_version", True),
                             ("row_version", "1"), ("record", []),
                             ("record", "x")):
            row = dict(good, **{field: value})
            self.assertRejected(page(row), repr((field, value)))

    def test_repeated_row_keeps_first_position_but_latest_snapshot(self):
        first = {"entity": "owners", "id": "same-id", "seq": 1,
                 "row_version": 2, "record": {"id": "owner01", "name": "old"}}
        middle = {"entity": "customers", "id": "other-id", "seq": 2,
                  "row_version": 1, "record": {"id": "cust01"}}
        repeated = dict(first, seq=3, row_version=3,
                        record={"id": "owner01", "name": "latest"})
        parsed = apply._page_changes(
            page(first, middle, repeated), apply.CHANGES_ROUTE)
        self.assertEqual(parsed, [
            ("owners", "same-id", 3, {"id": "owner01", "name": "latest"}),
            ("customers", "other-id", 1, {"id": "cust01"}),
        ])

    def test_repeated_current_snapshot_with_same_version_is_collapsed(self):
        row = {"entity": "owners", "id": "same-id", "seq": 1,
               "row_version": 3, "record": {"id": "owner01"}}
        parsed = apply._page_changes(
            page(row, dict(row, seq=2)), apply.CHANGES_ROUTE)
        self.assertEqual(parsed, [
            ("owners", "same-id", 3, {"id": "owner01"}),
        ])

    def test_the_same_id_in_two_entities_is_allowed(self):
        owner = {"entity": "owners", "id": "same-id", "seq": 1,
                 "row_version": 1, "record": wire("owners", OWNER)}
        identity = {"entity": "identities", "id": "same-id", "seq": 2,
                    "row_version": 1, "record": wire("identities", IDENTITY)}
        report = apply.apply_changes(page(owner, identity), store=self.store,
                                     source_installation_id=INSTALL,
                                     versions=self.versions)
        self.assertEqual(report.applied, 2)


# --------------------------------------------------------------------------
# The injected I/O
# --------------------------------------------------------------------------

class FileStoreTests(ApplyCase):

    def test_the_store_lives_in_the_temporary_directory(self):
        self.assertTrue(os.path.abspath(self.path).startswith(
            os.path.abspath(self.tmp)))
        live = os.path.join(os.environ.get("LOCALAPPDATA") or "",
                            "irica", "crm_store.json")
        self.assertNotEqual(os.path.abspath(self.path).lower(),
                            os.path.abspath(live).lower(),
                            "the tests must never touch the live data directory")

    def test_write_then_read_round_trips_the_document(self):
        document = store_fixture()
        self.store.write(document)
        self.assertEqual(self.read_store(), document)
        self.assertFalse(os.path.exists(self.path + ".tmp"),
                         "a finished write leaves no temporary file")

    def test_a_second_write_rotates_one_generation_of_backup(self):
        self.store.write(store_fixture())
        self.assertTrue(os.path.exists(self.path + ".bak"))
        with open(self.path + ".bak", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), store_fixture())
        self.store.write({"version": 2})
        with open(self.path + ".bak", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle), store_fixture())

    def test_a_missing_file_reads_as_an_empty_document(self):
        self.assertEqual(self.store.read(), {})

    def test_a_corrupt_main_falls_back_to_the_backup(self):
        self.store.write(store_fixture())
        self.store.write({"version": 2})
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        self.assertEqual(self.store.read(), store_fixture())

    def test_a_corrupt_main_and_backup_fail_closed(self):
        self.store.write(store_fixture())
        for candidate in (self.path, self.path + ".bak"):
            with open(candidate, "w", encoding="utf-8") as handle:
                handle.write("{not json")
        with self.assertRaises(mapper.FieldTypeError):
            self.store.read()

    def test_a_first_write_seeds_the_backup_like_crm_does(self):
        self.store.write(store_fixture())
        self.assertTrue(os.path.exists(self.path + ".bak"))

    def test_writing_a_non_object_is_refused(self):
        for value in ([], None, "text", 4):
            with self.assertRaises(ValueError):
                self.store.write(value)

    def test_an_unreadable_local_store_stops_the_apply(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("[1, 2, 3]")
        with self.assertRaises(mapper.FieldTypeError):
            self.snapshot()

    def test_a_store_without_read_and_write_is_refused(self):
        for store in (None, object(), self.path):
            with self.assertRaises(TypeError):
                apply.apply_snapshot(bootstrap_payload(store_fixture()),
                                     store=store,
                                     source_installation_id=INSTALL,
                                     versions={})
            with self.assertRaises(TypeError):
                apply.apply_changes(page(), store=store,
                                    source_installation_id=INSTALL,
                                    versions={})

    def test_versions_is_required(self):
        with self.assertRaises(TypeError):
            apply.apply_snapshot(bootstrap_payload(store_fixture()),
                                 store=self.store,
                                 source_installation_id=INSTALL)
        with self.assertRaises(TypeError):
            apply.apply_changes(page(), store=self.store,
                                source_installation_id=INSTALL)

    def test_dirty_accepts_a_callable_a_set_or_nothing(self):
        local = store_fixture()
        local["owners"][0]["passport"] = "LOCAL EDIT"
        self.write_store(local)
        record = wire("owners", dict(OWNER, passport="REMOTE"))
        row = change("owners", "e5f6a7b8", record, seq=1, row_version=3)
        for dirty in (lambda entity, key: key == "e5f6a7b8",
                      {("owners", "e5f6a7b8")}, None):
            self.write_store(local)
            apply.apply_changes(page(row), store=self.store,
                                source_installation_id=INSTALL,
                                versions={}, dirty=dirty)
            expected = ("LOCAL EDIT" if dirty is not None else "REMOTE")
            self.assertEqual(self.read_store()["owners"][0]["passport"],
                             expected)

    def test_a_non_callable_dirty_is_refused(self):
        with self.assertRaises(TypeError):
            apply.apply_changes(page(), store=self.store,
                                source_installation_id=INSTALL,
                                versions={}, dirty=object())

    def test_a_dirty_set_of_bare_ids_is_refused(self):
        # A bare id would match nothing (every lookup carries the entity), so
        # the shape is rejected instead of silently protecting nothing.
        with self.assertRaises(TypeError):
            apply.apply_changes(page(), store=self.store,
                                source_installation_id=INSTALL,
                                versions={}, dirty={"e5f6a7b8"})

    def test_empty_remote_snapshot_does_not_wipe_local_store(self):
        # Safety guard against the data-loss loop on fresh server connection
        before = self.seed()
        empty_payload = {
            "ok": True,
            "collections": {entity: [] for entity in ids.ENTITIES},
            "cursor": 0,
            "dataset_epoch": 0,
            "tenant_id": TENANT,
            "bootstrap_status": "pending",
        }
        with self.assertRaises(RemoteNotReadyError):
            self.snapshot(empty_payload)
        self.assertStable(before, "local store was corrupted by empty remote snapshot")

    def test_pending_bootstrap_status_refuses_snapshot_apply(self):
        before = self.seed()
        payload = bootstrap_payload(store_fixture())
        payload["bootstrap_status"] = "pending"
        with self.assertRaises(RemoteNotReadyError):
            self.snapshot(payload)
        self.assertStable(before, "pending bootstrap status touched disk")

    def test_empty_remote_snapshot_allowed_if_local_store_is_also_empty(self):
        empty_doc = {
            "version": 1,
            "customers": [],
            "owners": [],
            "identities": [],
            "devices": [],
            "periods": [],
            "settings": {},
        }
        self.write_store(empty_doc)
        empty_payload = {
            "ok": True,
            "collections": {entity: [] for entity in ids.ENTITIES},
            "cursor": 0,
            "dataset_epoch": 1,
            "tenant_id": TENANT,
            "bootstrap_status": "done",
        }
        report = self.snapshot(empty_payload)
        self.assertEqual(report.applied, 0)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

class ReportTests(ApplyCase):

    def test_the_report_exposes_its_counters(self):
        report = apply.ApplyReport(applied=2, removed=1, stale=3,
                                   protected=4, written=True)
        self.assertEqual(report.changed, 3)
        self.assertIn("applied=2", repr(report))
        self.assertTrue(report.written)

    def test_an_unwritable_store_is_refused_even_when_nothing_changes(self):
        with self.assertRaises(TypeError):
            apply.apply_changes(page(), store={"read": lambda: {}},
                                source_installation_id=INSTALL,
                                versions={})


if __name__ == "__main__":
    unittest.main()
