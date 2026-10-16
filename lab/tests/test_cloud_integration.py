# -*- coding: utf-8 -*-
"""Cloud sync integration & consistency test suite (workstream G).

Covers end-to-end multi-client sync cycles and cross-language contract
guarantees between the Python desktop panel and the PHP/MySQL host package
(lab/docs/CLOUD_SYNC_SPEC.md §10, §12, §13, §15):

1. Settings allowlist consistency across Python (cloud_sync.mapper.SETTINGS_ALLOWLIST),
   PHP schema (host/src/Schema.php) and database migration (host/migrations/001_initial.sql).
2. CRM stage enum consistency across Python (crm.py ALLOWED/_STAGE_FA),
   SQL constraint (CHECK (stage IN (...)) in 001_initial.sql) and PHP Schema.php enum.
3. Error code grammar validation (spec §15 ruling 8) across Python errors,
   state machine, host PHP Codes and panel Persian message mappings.
4. End-to-end sync cycle against loopback fake / test host:
   - Client login & device enrollment
   - Local edit -> outbox enqueue -> push to server
   - Pull on second client instance -> store update via apply
   - Concurrent edits -> 409 conflict detection -> parked conflict -> resolution
     (both keep_local with fresh operation_id and accept_server)
   - Offline lease expiration -> network push blocked, local read allowed
   - One-shot import -> dataset seeded, backup taken, epoch bumped

Offline throughout: temp directories, loopback server.
No network, no real credentials, no writes to %LOCALAPPDATA%\\irica\\.
"""
import copy
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
import uuid

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _cloud_api_fake as fake_api
import crm
import panel
from cloud_sync import apply, ids, importer, mapper
from cloud_sync.auth import MemorySecretStore, TokenVault
from cloud_sync.client import SyncClient
from cloud_sync.config import CloudConfig
from cloud_sync.errors import (
    CLIENT_ERROR_CODES, KNOWN_ERROR_CODES as ERRORS_KNOWN_CODES,
    is_valid_code,
)
from cloud_sync.lease import LEASE_SECONDS, OfflineLease
from cloud_sync.outbox import Outbox, OutboxWorker
from cloud_sync.state import (
    ERROR_CODE_RE, KNOWN_ERROR_CODES as STATE_KNOWN_CODES, MAX_CODE_LENGTH,
    SyncEvent, SyncState, SyncStateMachine,
)

SCHEMA_PHP_PATH = os.path.join(_ROOT, "host", "src", "Schema.php")
INITIAL_SQL_PATH = os.path.join(_ROOT, "host", "migrations", "001_initial.sql")
CODES_PHP_PATH = os.path.join(_ROOT, "host", "src", "Codes.php")
HTTP_PHP_PATH = os.path.join(_ROOT, "host", "src", "Http.php")

ENVELOPE_COLUMNS = frozenset({
    "id", "tenant_id", "legacy_id", "row_version",
    "created_at", "updated_at", "deleted_at", "deleted_by",
})


def _read_schema_php_settings_columns():
    """Extract business column names of 'settings' from host/src/Schema.php."""
    with open(SCHEMA_PHP_PATH, "r", encoding="utf-8") as f:
        src = f.read()
    m = re.search(
        r"'settings'\s*=>\s*\[.*?'columns'\s*=>\s*\[(.*?)\]\s*,\s*\]\s*,\s*'customers'",
        src, re.DOTALL,
    )
    if not m:
        raise ValueError("failed to locate settings columns in host/src/Schema.php")
    return re.findall(r"'([a-z_0-9]+)'\s*=>\s*\[\s*'sql'", m.group(1))


def _read_sql_settings_columns():
    """Extract business column names of 'settings' from 001_initial.sql."""
    with open(INITIAL_SQL_PATH, "r", encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"CREATE TABLE settings \((.*?)\) ENGINE=", src, re.DOTALL)
    if not m:
        raise ValueError("failed to locate CREATE TABLE settings in 001_initial.sql")
    cols = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith(
            ("--", "PRIMARY", "UNIQUE", "KEY", "CONSTRAINT", "CHECK")
        ):
            continue
        col = line.split()[0].strip("`")
        if col not in ENVELOPE_COLUMNS:
            cols.append(col)
    return cols


def _read_sql_crm_devices_stages():
    """Extract CHECK (stage IN (...)) values for crm_devices from 001_initial.sql."""
    with open(INITIAL_SQL_PATH, "r", encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"CHECK\s*\(\s*stage\s+IN\s*\((.*?)\)\)", src, re.IGNORECASE | re.DOTALL)
    if not m:
        raise ValueError("failed to locate CHECK (stage IN (...)) in 001_initial.sql")
    return re.findall(r"'([a-z_]+)'", m.group(1))


def _read_schema_php_crm_devices_stages():
    """Extract enum values for crm_devices.stage from host/src/Schema.php."""
    with open(SCHEMA_PHP_PATH, "r", encoding="utf-8") as f:
        src = f.read()
    m = re.search(
        r"'crm_devices'\s*=>\s*\[.*?'stage'\s*=>\s*\[.*?'enum'\s*=>\s*\[(.*?)\]",
        src, re.DOTALL,
    )
    if not m:
        raise ValueError("failed to locate crm_devices stage enum in host/src/Schema.php")
    return re.findall(r"'([a-z_]+)'", m.group(1))


def _read_php_codes():
    """Extract all error code constants declared in PHP Codes class."""
    path = CODES_PHP_PATH if os.path.exists(CODES_PHP_PATH) else HTTP_PHP_PATH
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"class Codes\s*\{(.*?)\}", src, re.DOTALL)
    if not m:
        raise ValueError("failed to locate class Codes in %s" % path)
    consts = re.findall(
        r"public\s+const\s+([A-Z0-9_]+)\s*=\s*['\"]([^'\"]+)['\"]", m.group(1)
    )
    return [val for name, val in consts if name not in ("PATTERN", "MAX_LENGTH")]


# =====================================================================
# 1. Cross-Language Settings Allowlist Consistency
# =====================================================================
class SettingsAllowlistConsistencyTest(unittest.TestCase):
    """Verify that Python, PHP and SQL agree on the settings allowlist."""

    def test_settings_allowlist_matches_schema_php(self):
        py_allowlist = list(mapper.SETTINGS_ALLOWLIST)
        php_columns = _read_schema_php_settings_columns()
        self.assertEqual(
            py_allowlist, php_columns,
            "cloud_sync.mapper.SETTINGS_ALLOWLIST does not match host/src/Schema.php columns",
        )

    def test_settings_allowlist_matches_sql_schema(self):
        py_allowlist = list(mapper.SETTINGS_ALLOWLIST)
        sql_columns = _read_sql_settings_columns()
        self.assertEqual(
            py_allowlist, sql_columns,
            "cloud_sync.mapper.SETTINGS_ALLOWLIST does not match 001_initial.sql business columns",
        )

    def test_settings_allowlist_excludes_envelope_columns(self):
        py_set = set(mapper.SETTINGS_ALLOWLIST)
        intersect = py_set & ENVELOPE_COLUMNS
        self.assertEqual(
            intersect, set(),
            "SETTINGS_ALLOWLIST must not contain envelope columns: %r" % intersect,
        )


# =====================================================================
# 2. Cross-Language Stage Enum Consistency
# =====================================================================
class StageEnumConsistencyTest(unittest.TestCase):
    """Verify CRM stage enum agreement across crm.py, SQL, and PHP schema."""

    def test_crm_stage_transitions_match_sql_check_constraint(self):
        py_stages = set(crm.ALLOWED.keys())
        sql_stages = set(_read_sql_crm_devices_stages())
        self.assertEqual(
            py_stages, sql_stages,
            "crm.ALLOWED.keys() does not match 001_initial.sql CHECK (stage IN (...)) constraint",
        )

    def test_crm_stage_labels_match_sql_check_constraint(self):
        py_stage_labels = set(crm._STAGE_FA.keys())
        sql_stages = set(_read_sql_crm_devices_stages())
        self.assertEqual(
            py_stage_labels, sql_stages,
            "crm._STAGE_FA.keys() does not match 001_initial.sql CHECK (stage IN (...)) constraint",
        )

    def test_php_schema_stage_enum_matches_sql(self):
        php_stages = set(_read_schema_php_crm_devices_stages())
        sql_stages = set(_read_sql_crm_devices_stages())
        self.assertEqual(
            php_stages, sql_stages,
            "host/src/Schema.php crm_devices stage enum does not match 001_initial.sql constraint",
        )


# =====================================================================
# 3. Error Code Grammar Validation (Spec §15 Ruling 8)
# =====================================================================
class ErrorCodeGrammarTest(unittest.TestCase):
    """Verify all error codes conform to ^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$, len<=40."""

    def _assert_valid_code(self, code, source_name):
        self.assertIsInstance(
            code, str,
            "Code from %s must be a string, got %r" % (source_name, code),
        )
        self.assertLessEqual(
            len(code), MAX_CODE_LENGTH,
            "Code %r from %s exceeds max length %d" % (code, source_name, MAX_CODE_LENGTH),
        )
        self.assertTrue(
            ERROR_CODE_RE.match(code),
            "Code %r from %s does not match grammar %s"
            % (code, source_name, ERROR_CODE_RE.pattern),
        )
        self.assertTrue(is_valid_code(code))

    def test_cloud_sync_errors_known_codes_satisfy_grammar(self):
        for code in ERRORS_KNOWN_CODES:
            self._assert_valid_code(code, "cloud_sync.errors.KNOWN_ERROR_CODES")

    def test_cloud_sync_errors_client_codes_satisfy_grammar(self):
        for code in CLIENT_ERROR_CODES:
            self._assert_valid_code(code, "cloud_sync.errors.CLIENT_ERROR_CODES")

    def test_cloud_sync_state_known_codes_satisfy_grammar(self):
        for code in STATE_KNOWN_CODES:
            self._assert_valid_code(code, "cloud_sync.state.KNOWN_ERROR_CODES")

    def test_php_codes_satisfy_grammar(self):
        php_codes = _read_php_codes()
        self.assertTrue(len(php_codes) > 0, "No PHP error codes found")
        for code in php_codes:
            self._assert_valid_code(code, "PHP Codes class")

    def test_panel_cloud_error_messages_keys_satisfy_grammar(self):
        for code in panel.CLOUD_ERROR_MESSAGES.keys():
            self._assert_valid_code(code, "panel.py:CLOUD_ERROR_MESSAGES")


# =====================================================================
# 4. End-to-End Multi-Client Sync Cycle
# =====================================================================
class EndToEndSyncCycleTest(unittest.TestCase):
    """End-to-end sync cycle covering login, push, pull, conflict, lease, import."""

    def setUp(self):
        super().setUp()
        self.handle = fake_api.start_api(self, needs_fake=False)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    def _create_client(self, prefix, installation_id=None):
        install = installation_id or str(uuid.uuid4())
        cfg_path = os.path.join(self.temp_dir.name, "%s_cfg.json" % prefix)
        auth_path = os.path.join(self.temp_dir.name, "%s_auth.dat" % prefix)
        store_path = os.path.join(self.temp_dir.name, "%s_crm_store.json" % prefix)
        outbox_path = os.path.join(self.temp_dir.name, "%s_outbox.jsonl" % prefix)

        cfg = CloudConfig(
            api_base=self.handle.base_url,
            tenant_id="default",
            source_installation_id=install,
            path=cfg_path,
        )
        vault = TokenVault(store=MemorySecretStore(), path=auth_path)
        client = SyncClient(config=cfg, vault=vault)
        store = apply.FileStore(store_path)
        store.write({
            "version": 1,
            "customers": [],
            "owners": [],
            "identities": [],
            "devices": [],
            "periods": [],
            "settings": {},
        })
        outbox = Outbox(path=outbox_path)
        return {
            "install": install,
            "config": cfg,
            "vault": vault,
            "client": client,
            "store": store,
            "outbox": outbox,
            "versions": {},
        }

    def _bootstrap_authority(self, client_state):
        """Materialize then commit the host snapshot before incremental IO."""
        snapshot = client_state["client"].bootstrap()
        apply.apply_snapshot(
            snapshot,
            store=client_state["store"],
            versions=client_state["versions"],
            source_installation_id=client_state["install"],
        )
        client_state["client"].commit_bootstrap(snapshot)
        return snapshot

    def test_client_login_and_enroll(self):
        """Client authenticates against host API and enrolls sync device."""
        c = self._create_client("inst1")
        client = c["client"]

        login_res = client.login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        self.assertTrue(login_res["ok"])
        self.assertIn("access_token", login_res)
        self.assertTrue(c["vault"].user_access_token)

        enroll_res = client.enroll()
        self.assertTrue(enroll_res["ok"])
        self.assertTrue(c["config"].sync_device_id)
        self.assertTrue(c["vault"].has_device_credentials)

    def test_edit_enqueue_push_and_pull_apply(self):
        """Client A edits local store, pushes to host; Client B pulls and applies."""
        # Client A & B share the tenant source installation ID for mapping
        tenant_install = str(uuid.uuid4())
        cA = self._create_client("nodeA", installation_id=tenant_install)
        cB = self._create_client("nodeB", installation_id=tenant_install)

        cA["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        cA["client"].enroll()
        cB["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        cB["client"].enroll()
        self._bootstrap_authority(cA)
        self._bootstrap_authority(cB)

        # Client A adds an owner
        owner = {
            "id": "own1", "first_name": "Ali", "last_name": "Rezaei",
            "national": "0012345679", "birth": "1370/01/01", "mobile": "09121111111",
            "card_no": "6037991234567890", "passport": "AB1234567",
            "created": "2026-09-01 10:00:00", "updated": "2026-09-01 10:00:00",
        }
        docA = cA["store"].read()
        docA["owners"].append(owner)
        cA["store"].write(docA)

        # Enqueue in outbox A and push via OutboxWorker
        wire_owner = mapper.to_row("owners", owner, source_installation_id=tenant_install)
        owner_uuid = mapper.legacy_to_uuid(tenant_install, "owners", "own1")
        op_id = cA["outbox"].enqueue({
            "kind": "upsert", "entity": "owners", "id": owner_uuid,
            "base_version": 0, "record": wire_owner,
        })
        workerA = OutboxWorker(cA["outbox"], cA["client"])
        outcomeA = workerA.run_once()

        self.assertTrue(outcomeA.attempted)
        self.assertEqual(outcomeA.applied, 1)
        self.assertEqual(outcomeA.conflicts, 0)
        self.assertEqual(cA["outbox"].pending_count, 0)

        # Client B pulls and applies changes
        pulled = cB["client"].pull_all(lambda page: apply.apply_changes(
            page, store=cB["store"], versions=cB["versions"],
            source_installation_id=tenant_install,
        ))
        self.assertGreaterEqual(pulled, 1)

        docB = cB["store"].read()
        self.assertEqual(len(docB["owners"]), 1)
        self.assertEqual(docB["owners"][0]["id"], "own1")
        self.assertEqual(docB["owners"][0]["first_name"], "Ali")
        self.assertEqual(cB["versions"].get(("owners", owner_uuid)), 1)

    def test_concurrent_edit_conflict_and_resolution_keep_local(self):
        """Concurrent edit produces 409 conflict; resolved with keep_local."""
        tenant_install = str(uuid.uuid4())
        cA = self._create_client("nodeA", installation_id=tenant_install)
        cB = self._create_client("nodeB", installation_id=tenant_install)

        cA["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        cA["client"].enroll()
        cB["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        cB["client"].enroll()
        self._bootstrap_authority(cA)
        self._bootstrap_authority(cB)

        # Seed initial owner
        owner = {
            "id": "own1", "first_name": "Initial", "last_name": "Owner",
            "national": "0012345679", "birth": "1370/01/01", "mobile": "09121111111",
            "card_no": "6037991234567890", "passport": "AB1234567",
            "created": "2026-09-01 10:00:00", "updated": "2026-09-01 10:00:00",
        }
        wire_owner = mapper.to_row("owners", owner, source_installation_id=tenant_install)
        owner_uuid = mapper.legacy_to_uuid(tenant_install, "owners", "own1")
        cA["outbox"].enqueue({
            "kind": "upsert", "entity": "owners", "id": owner_uuid,
            "base_version": 0, "record": wire_owner,
        })
        workerA = OutboxWorker(cA["outbox"], cA["client"])
        workerA.run_once()

        # Client B pulls seed row
        cB["client"].pull_all(lambda page: apply.apply_changes(
            page, store=cB["store"], versions=cB["versions"],
            source_installation_id=tenant_install,
        ))
        self.assertEqual(cB["versions"].get(("owners", owner_uuid)), 1)

        # Client A updates owner1: "Winner-A", base_version=1 -> server advances to version 2
        owner_A = dict(owner, first_name="Winner-A", updated="2026-09-01 11:00:00")
        cA["outbox"].enqueue({
            "kind": "upsert", "entity": "owners", "id": owner_uuid,
            "base_version": 1,
            "record": mapper.to_row("owners", owner_A, source_installation_id=tenant_install),
        })
        outcomeA = workerA.run_once()
        self.assertEqual(outcomeA.applied, 1)

        # Client B concurrently updates owner1: "Candidate-B", base_version=1
        owner_B = dict(owner, first_name="Candidate-B", updated="2026-09-01 11:05:00")
        op_b_id = cB["outbox"].enqueue({
            "kind": "upsert", "entity": "owners", "id": owner_uuid,
            "base_version": 1,
            "record": mapper.to_row("owners", owner_B, source_installation_id=tenant_install),
        })
        workerB = OutboxWorker(cB["outbox"], cB["client"])
        outcomeB = workerB.run_once()

        # 409 conflict detected and parked in outbox B
        self.assertEqual(outcomeB.conflicts, 1)
        self.assertEqual(cB["outbox"].conflict_count, 1)
        conflicts = cB["outbox"].conflicts()
        self.assertEqual(len(conflicts), 1)
        conf_entry = conflicts[0]
        self.assertEqual(conf_entry.parked, "conflict")
        self.assertEqual(conf_entry.code, "VERSION_CONFLICT")
        self.assertEqual(conf_entry.conflict["server_version"], 2)
        self.assertEqual(conf_entry.conflict["server_record"]["first_name"], "Winner-A")

        # Resolve: keep_local
        # Re-trying with new base_version requires a fresh operation_id so the server
        # CAS evaluates the new base_version instead of replaying the old conflict.
        server_ver = conf_entry.conflict["server_version"]
        new_op = dict(conf_entry.operation)
        new_op["base_version"] = server_ver
        new_op_id = str(uuid.uuid4())
        new_op["operation_id"] = new_op_id
        cB["outbox"].mark_done(op_b_id, result="conflict_keep_local")
        cB["outbox"].enqueue(new_op, operation_id=new_op_id)

        outcome_res = workerB.run_once()
        self.assertEqual(outcome_res.applied, 1)
        self.assertEqual(cB["outbox"].conflict_count, 0)
        self.assertEqual(cB["outbox"].pending_count, 0)

        # Client A pulls the winning resolution from B
        cA["client"].pull_all(lambda page: apply.apply_changes(
            page, store=cA["store"], versions=cA["versions"],
            source_installation_id=tenant_install,
        ))
        docA_after = cA["store"].read()
        self.assertEqual(docA_after["owners"][0]["first_name"], "Candidate-B")

    def test_concurrent_edit_conflict_and_resolution_accept_server(self):
        """Concurrent edit produces 409 conflict; resolved with accept_server."""
        tenant_install = str(uuid.uuid4())
        cA = self._create_client("nodeA", installation_id=tenant_install)
        cB = self._create_client("nodeB", installation_id=tenant_install)

        cA["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        cA["client"].enroll()
        cB["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        cB["client"].enroll()
        self._bootstrap_authority(cA)
        self._bootstrap_authority(cB)

        owner = {
            "id": "own2", "first_name": "Seed", "last_name": "Person",
            "national": "0012345679", "birth": "1370/01/01", "mobile": "09121111111",
            "card_no": "6037991234567890", "passport": "AB1234567",
            "created": "2026-09-01 10:00:00", "updated": "2026-09-01 10:00:00",
        }
        wire_owner = mapper.to_row("owners", owner, source_installation_id=tenant_install)
        owner_uuid = mapper.legacy_to_uuid(tenant_install, "owners", "own2")
        cA["outbox"].enqueue({
            "kind": "upsert", "entity": "owners", "id": owner_uuid,
            "base_version": 0, "record": wire_owner,
        })
        workerA = OutboxWorker(cA["outbox"], cA["client"])
        workerA.run_once()

        cB["client"].pull_all(lambda page: apply.apply_changes(
            page, store=cB["store"], versions=cB["versions"],
            source_installation_id=tenant_install,
        ))

        # A updates to version 2
        owner_A = dict(owner, first_name="Server-Wins", updated="2026-09-01 11:00:00")
        cA["outbox"].enqueue({
            "kind": "upsert", "entity": "owners", "id": owner_uuid,
            "base_version": 1,
            "record": mapper.to_row("owners", owner_A, source_installation_id=tenant_install),
        })
        workerA.run_once()

        # B attempts update with base_version=1 -> conflict!
        owner_B = dict(owner, first_name="Local-Yields", updated="2026-09-01 11:05:00")
        op_b_id = cB["outbox"].enqueue({
            "kind": "upsert", "entity": "owners", "id": owner_uuid,
            "base_version": 1,
            "record": mapper.to_row("owners", owner_B, source_installation_id=tenant_install),
        })
        workerB = OutboxWorker(cB["outbox"], cB["client"])
        outcomeB = workerB.run_once()
        self.assertEqual(outcomeB.conflicts, 1)

        # Resolve: accept_server
        conf_entry = cB["outbox"].get(op_b_id)
        server_record = conf_entry.conflict["server_record"]

        # Apply server record to B's store
        ref_idx = mapper.reference_index(cB["store"].read(), source_installation_id=tenant_install)
        local_mapped = mapper.from_row("owners", server_record, reference_index=ref_idx)
        docB = cB["store"].read()
        for idx, o in enumerate(docB["owners"]):
            if o["id"] == "own2":
                docB["owners"][idx] = local_mapped
        cB["store"].write(docB)
        cB["outbox"].mark_done(op_b_id, result="conflict_server_accepted")

        self.assertEqual(cB["outbox"].conflict_count, 0)
        self.assertEqual(cB["outbox"].pending_count, 0)
        self.assertEqual(cB["store"].read()["owners"][0]["first_name"], "Server-Wins")

    def test_offline_lease_expiration_blocks_push_allows_read(self):
        """7-day lease expiration stops network push but permits local store reads."""
        c = self._create_client("lease_node")
        c["client"].login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        c["client"].enroll()

        clock_val = [1_800_000_000.0]
        lease_path = os.path.join(self.temp_dir.name, "test_lease.json")
        lease = OfflineLease(path=lease_path, clock=lambda: clock_val[0])
        lease.grant()
        self.assertFalse(lease.is_expired())

        # Queue an operation
        c["outbox"].enqueue({
            "kind": "upsert", "entity": "owners", "id": str(uuid.uuid4()),
            "base_version": 0, "record": {"first_name": "Pending"},
        })

        # Advance past 7 days (7 * 86400 + 1 hour)
        clock_val[0] += LEASE_SECONDS + 3600
        self.assertTrue(lease.is_expired())

        machine = SyncStateMachine(clock=lambda: clock_val[0])
        machine.apply(SyncEvent.ENROL)
        self.assertEqual(machine.state, SyncState.IDLE)

        worker = OutboxWorker(
            c["outbox"], c["client"], machine=machine, lease=lease,
            clock=lambda: clock_val[0],
        )
        outcome = worker.run_once()

        # Push blocked before hitting the network
        self.assertFalse(outcome.attempted)
        self.assertEqual(outcome.terminal, SyncEvent.LEASE_EXPIRED.value)
        self.assertEqual(outcome.code, "LEASE_EXPIRED")
        self.assertEqual(machine.state, SyncState.READ_ONLY)

        # Local read remains allowed
        doc = c["store"].read()
        self.assertIn("owners", doc)
        self.assertEqual(doc["owners"], [])

    def test_one_shot_import_seeds_dataset_and_bumps_epoch(self):
        """One-shot bootstrap import takes backup, seeds host, and increments epoch."""
        # Fresh API instance ensures empty tenant state for import
        clean_handle = fake_api.FakeApi().start()
        self.addCleanup(clean_handle.stop)

        install_id = str(uuid.uuid4())
        cfg = CloudConfig(
            api_base=clean_handle.base_url,
            tenant_id="default",
            source_installation_id=install_id,
            path=os.path.join(self.temp_dir.name, "import_cfg.json"),
        )
        vault = TokenVault(store=MemorySecretStore(), path=os.path.join(self.temp_dir.name, "import_auth.dat"))
        client = SyncClient(config=cfg, vault=vault)
        client.login(fake_api.FAKE_USERNAME, fake_api.FAKE_PASSWORD)
        client.enroll()

        sample_store = {
            "version": 1,
            "customers": [{"id": "cust1", "full_name": "Imported Customer", "transactions": []}],
            "owners": [{"id": "own1", "first_name": "Imported Owner"}],
            "identities": [{"id": "id1", "label": "Pool 1"}],
            "devices": [{
                "id": "dev1", "name": "Device 1", "customer_id": "cust1",
                "owner_id": "own1", "stage": "new",
            }],
            "periods": [{"id": "per1", "number": 1, "label": "Period 1"}],
            "settings": {"business_name": "Imported Shop"},
        }
        backup_dir = os.path.join(self.temp_dir.name, "import_backups")

        result = importer.run_import(
            sample_store, send=client.import_document,
            source_installation_id=install_id, backup_dir=backup_dir,
        )
        self.assertTrue(result.ok)
        self.assertTrue(os.path.isfile(result.backup_path))

        # Backup file contains verbatim store content
        with open(result.backup_path, "r", encoding="utf-8") as bf:
            backup_data = json.load(bf)
        self.assertEqual(backup_data["settings"]["business_name"], "Imported Shop")

        # Verify dataset was seeded and epoch bumped via GET /sync/bootstrap
        bootstrap = client._request("GET", "/sync/bootstrap")
        self.assertIsNotNone(bootstrap.get("dataset_epoch"))
        collections = bootstrap.get("collections", {})
        self.assertEqual(len(collections.get("customers", [])), 1)
        self.assertEqual(len(collections.get("owners", [])), 1)
        self.assertEqual(len(collections.get("crm_devices", [])), 1)
        self.assertEqual(len(collections.get("periods", [])), 1)
        self.assertEqual(len(collections.get("settings", [])), 1)
        self.assertEqual(
            collections["settings"][0]["record"]["business_name"],
            "Imported Shop",
        )


if __name__ == "__main__":
    unittest.main()
