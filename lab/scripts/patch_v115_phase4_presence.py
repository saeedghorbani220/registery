from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path, old, new):
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one anchor, found {count}: {old[:100]!r}")
    write(path, text.replace(old, new, 1))


presence_php = r'''<?php
/**
 * Presence.php — advisory record-presence heartbeats for concurrent operators.
 *
 * Presence is deliberately NOT a lock. Multiple devices may heartbeat the same
 * record at the same time; optimistic row_version conflict handling remains the
 * write authority. Rows are short-lived and contain only internal identifiers.
 */

declare(strict_types=1);

final class Presence
{
    private const TTL_SECONDS = 45;

    public function __construct(
        private readonly Database $db,
        private readonly Log $log
    ) {
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    public function heartbeat(Principal $device, Principal $user, array $body,
                              string $requestId): array
    {
        $this->assertContext($device, $user);
        $entity = isset($body['entity']) && is_string($body['entity'])
            ? trim($body['entity']) : '';
        $entityId = isset($body['entity_id']) && is_string($body['entity_id'])
            ? trim($body['entity_id']) : '';
        if ($entity === '' || Schema::tableForEntity($entity) === null) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'entity must name a synced entity');
        }
        if (!Ids::isUuid($entityId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'entity_id must be a UUID');
        }

        $nowEpoch = time();
        $now = gmdate('Y-m-d H:i:s', $nowEpoch);
        $expires = gmdate('Y-m-d H:i:s', $nowEpoch + self::TTL_SECONDS);

        // Expiry is the cleanup mechanism. It also makes a crashed desktop
        // disappear without requiring a close request to have reached us.
        $this->db->execute(
            'DELETE FROM record_presence WHERE expires_at <= ?', [$now]
        );

        // A duplicate PK is the same enrolled PC reopening/refreshing the same
        // record. Keep its original lease id/opened_at; refresh only identity
        // and heartbeat timestamps. This never excludes a different device.
        $candidateLease = Ids::v4();
        $this->db->execute(
            'INSERT INTO record_presence '
            . '(tenant_id,entity,entity_id,user_id,sync_device_id,lease_id,'
            . 'opened_at,heartbeat_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?) '
            . 'ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), '
            . 'heartbeat_at=VALUES(heartbeat_at), expires_at=VALUES(expires_at)',
            [
                $device->tenantId, $entity, $entityId, $user->userId,
                $device->deviceId, $candidateLease, $now, $now, $expires,
            ]
        );

        $self = $this->db->queryOne(
            'SELECT lease_id,opened_at,heartbeat_at,expires_at '
            . 'FROM record_presence WHERE tenant_id=? AND entity=? '
            . 'AND entity_id=? AND sync_device_id=?',
            [$device->tenantId, $entity, $entityId, $device->deviceId]
        );
        if ($self === null) {
            throw new ApiException(500, Codes::DB_UNAVAILABLE,
                'presence heartbeat was not persisted');
        }

        $peers = $this->db->query(
            'SELECT rp.user_id,rp.sync_device_id,rp.heartbeat_at,rp.expires_at,'
            . "COALESCE(NULLIF(u.display_name,''),u.username,'') AS display_name "
            . 'FROM record_presence rp LEFT JOIN users u '
            . 'ON u.id=rp.user_id AND u.tenant_id=rp.tenant_id '
            . 'WHERE rp.tenant_id=? AND rp.entity=? AND rp.entity_id=? '
            . 'AND rp.expires_at>? AND rp.sync_device_id<>? '
            . 'ORDER BY rp.heartbeat_at DESC',
            [$device->tenantId, $entity, $entityId, $now, $device->deviceId]
        );

        $this->log->line([
            'request_id' => $requestId,
            'tenant_id' => $device->tenantId,
            'user_id' => $user->userId,
            'device_id' => $device->deviceId,
            'entity' => $entity,
            'action' => 'presence.heartbeat',
            'outcome' => 'ok',
            'count' => count($peers),
        ]);

        return [
            'lease_id' => (string) $self['lease_id'],
            'opened_at' => (string) $self['opened_at'],
            'heartbeat_at' => (string) $self['heartbeat_at'],
            'expires_at' => (string) $self['expires_at'],
            'ttl_seconds' => self::TTL_SECONDS,
            'peers' => array_map(static function (array $row): array {
                return [
                    'user_id' => (string) $row['user_id'],
                    'sync_device_id' => (string) $row['sync_device_id'],
                    'display_name' => (string) $row['display_name'],
                    'heartbeat_at' => (string) $row['heartbeat_at'],
                    'expires_at' => (string) $row['expires_at'],
                ];
            }, $peers),
            'advisory' => true,
        ];
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    public function close(Principal $device, Principal $user, array $body,
                          string $requestId): array
    {
        $this->assertContext($device, $user);
        $leaseId = isset($body['lease_id']) && is_string($body['lease_id'])
            ? trim($body['lease_id']) : '';
        if (!Ids::isUuid($leaseId)) {
            throw new ApiException(400, Codes::BAD_PAYLOAD,
                'lease_id must be a UUID');
        }
        $affected = $this->db->execute(
            'DELETE FROM record_presence WHERE tenant_id=? AND lease_id=? '
            . 'AND sync_device_id=? AND user_id=?',
            [$device->tenantId, $leaseId, $device->deviceId, $user->userId]
        );
        $this->log->line([
            'request_id' => $requestId,
            'tenant_id' => $device->tenantId,
            'user_id' => $user->userId,
            'device_id' => $device->deviceId,
            'action' => 'presence.close',
            'outcome' => $affected > 0 ? 'ok' : 'noop',
        ]);
        return ['closed' => $affected > 0, 'advisory' => true];
    }

    private function assertContext(Principal $device, Principal $user): void
    {
        if (!$device->isDevice() || !$user->isUser()) {
            throw new ApiException(401, Codes::AUTH_REQUIRED,
                'device and acting user credentials are required');
        }
        if ($device->tenantId === '' || $device->tenantId !== $user->tenantId
            || $device->deviceId === '' || $user->userId === '') {
            throw new ApiException(403, Codes::PERMISSION_DENIED,
                'presence principals must belong to the same tenant');
        }
    }
}
'''
write("host/src/Presence.php", presence_php)

# Host front controller: load, route and serve advisory presence.
replace_once(
    "host/public/index.php",
    "    'RateLimit', 'Auth', 'Devices', 'Sync', 'Import', 'Finance',\n    'LegacyImport', 'LegacyVerify', 'LegacyApply',",
    "    'RateLimit', 'Auth', 'Devices', 'Sync', 'Import', 'Finance', 'Presence',\n    'LegacyImport', 'LegacyVerify', 'LegacyApply',",
)
replace_once(
    "host/public/index.php",
    "        '/sync/mutations' => ['POST'],\n        '/finance/transactions/append' => ['POST'],",
    "        '/sync/mutations' => ['POST'],\n        '/presence/heartbeat' => ['POST'],\n        '/presence/close' => ['POST'],\n        '/finance/transactions/append' => ['POST'],",
)
replace_once(
    "host/public/index.php",
    "    $finance = new Finance($db, $log, $config);\n    $legacyImport = new LegacyImport($db, $sync, $log, $config);",
    "    $finance = new Finance($db, $log, $config);\n    $presence = new Presence($db, $log);\n    $legacyImport = new LegacyImport($db, $sync, $log, $config);",
)
route_anchor = """        case '/finance/transactions/append':
            $device = requireDevice($auth, $request);
"""
route_insert = """        case '/presence/heartbeat':
            $device = requireDevice($auth, $request);
            $body = $request->jsonBody();
            $acting = $auth->actingUser($request);
            if ($acting === null) {
                throw new ApiException(401, Codes::AUTH_REQUIRED,
                    'an acting user token is required for presence');
            }
            $payload = $presence->heartbeat($device, $acting, $body, $requestId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/presence/close':
            $device = requireDevice($auth, $request);
            $body = $request->jsonBody();
            $acting = $auth->actingUser($request);
            if ($acting === null) {
                throw new ApiException(401, Codes::AUTH_REQUIRED,
                    'an acting user token is required for presence');
            }
            $payload = $presence->close($device, $acting, $body, $requestId);
            $statusCode = 200;
            $errorCode = '';
            Response::ok($payload);
            break;

        case '/finance/transactions/append':
            $device = requireDevice($auth, $request);
"""
replace_once("host/public/index.php", route_anchor, route_insert)

# Desktop transport: presence always carries both device and acting-user tokens.
client_anchor = """    def import_document(self, document):
"""
client_insert = """    def presence_heartbeat(self, entity, entity_id, lease_id=None):
        \"\"\"Refresh advisory presence for one server record.

        Presence never authorizes or blocks a write; row_version remains the
        concurrency boundary. The acting user header is mandatory so peers can
        be attributed without persisting the user access token.
        \"\"\"
        entity = str(entity or \"\").strip()
        entity_id = str(entity_id or \"\").strip()
        if not entity or not entity_id:
            raise ValueError(\"presence requires entity and entity_id\")
        body = {\"entity\": entity, \"entity_id\": entity_id}
        if lease_id:
            body[\"lease_id\"] = str(lease_id)
        return self._request(\"POST\", \"/presence/heartbeat\", body=body,
                             acting=True)

    def presence_close(self, lease_id):
        \"\"\"Best-effort early release of this device's advisory lease.\"\"\"
        lease_id = str(lease_id or \"\").strip()
        if not lease_id:
            raise ValueError(\"presence close requires lease_id\")
        return self._request(\"POST\", \"/presence/close\",
                             body={\"lease_id\": lease_id}, acting=True)

    def import_document(self, document):
"""
replace_once("cloud_sync/client.py", client_anchor, client_insert)

# Local panel proxy maps legacy local IDs to the canonical server UUID.
panel_helper_anchor = """def _cloud_route_guard(action, *args):
"""
panel_helper = '''def _cloud_presence_target(entity, local_id, runtime):
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


'''
replace_once("panel.py", panel_helper_anchor, panel_helper + panel_helper_anchor)

# Local HTTP routes are deliberately guarded like every other cloud action.
replace_once(
    "panel.py",
    '''        elif self.path in ("/cloud-sync", "/cloud-sync-now"):  # self.path == "/cloud-sync"\n            self._json(*_cloud_route_guard(cloud_sync_now))\n        elif self.path == "/cloud-resolve-conflict":''',
    '''        elif self.path in ("/cloud-sync", "/cloud-sync-now"):  # self.path == "/cloud-sync"\n            self._json(*_cloud_route_guard(cloud_sync_now))\n        elif self.path == "/cloud-presence":\n            self._json(*_cloud_route_guard(cloud_presence_heartbeat,\n                                           self._read_json()))\n        elif self.path == "/cloud-presence-close":\n            self._json(*_cloud_route_guard(cloud_presence_close,\n                                           self._read_json()))\n        elif self.path == "/cloud-resolve-conflict":''',
)

# Advisory UI. Heartbeats pause while a child dialog is open, resume on the
# case modal, and never gate an edit/action.
js_anchor = """var CASE_MODAL={id:'',sig:'',live:false,origin:''};
"""
js_presence = r'''var CASE_MODAL={id:'',sig:'',live:false,origin:''};
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
'''
replace_once("panel.py", js_anchor, js_presence)
replace_once(
    "panel.py",
    "  var back=DLG_BACK;DLG_BACK='';\n  var self=(CASE_MODAL.live&&CASE_MODAL.id===back)",
    "  var closingLiveCase=CASE_MODAL.live;\n  var back=DLG_BACK;DLG_BACK='';\n  if(closingLiveCase)presenceStop(true);\n  var self=(CASE_MODAL.live&&CASE_MODAL.id===back)",
)
replace_once(
    "panel.py",
    "  CASE_MODAL.id='';CASE_MODAL.sig='';CASE_MODAL.live=false;CASE_MODAL.origin='';\n  PER.live=false;",
    "  if(CASE_MODAL.live)presenceStop(true);\n  CASE_MODAL.id='';CASE_MODAL.sig='';CASE_MODAL.live=false;CASE_MODAL.origin='';\n  PER.live=false;",
)
replace_once(
    "panel.py",
    "    +'<span class=\"chip kbd\">'+esc(d.id)+'</span></div>'\n    +'<div style=\"margin:14px 0 6px\">'+railHtml(d)+'</div>'",
    "    +'<span class=\"chip kbd\">'+esc(d.id)+'</span></div>'\n    +'<div id=\"case-presence\" class=\"cloud-notice\" role=\"status\" hidden></div>'\n    +'<div style=\"margin:14px 0 6px\">'+railHtml(d)+'</div>'",
)
replace_once(
    "panel.py",
    "  CASE_MODAL.origin=origin;DLG_BACK=origin;\n}",
    "  CASE_MODAL.origin=origin;DLG_BACK=origin;\n  presenceStart('crm_devices',id);\n}",
)

# Host real-DB tests (MariaDB + MySQL 5.7).
presence_test = r'''# -*- coding: utf-8 -*-
"""Real DB verification for advisory record presence (Phase 4)."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HOST = os.path.join(ROOT, "host")
MIGRATIONS = os.path.join(HOST, "migrations")
MIGRATION_FILES = ("001_initial.sql", "002_server_crm_v2_foundation.sql",
                   "003_server_crm_v2_device_auth.sql")


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class PresenceStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = read(os.path.join(HOST, "src", "Presence.php"))
        cls.index = read(os.path.join(HOST, "public", "index.php"))
        cls.client = read(os.path.join(ROOT, "cloud_sync", "client.py"))

    def test_presence_is_advisory_not_a_write_lock(self):
        self.assertIn("Multiple devices may heartbeat", self.source)
        self.assertIn("ON DUPLICATE KEY UPDATE", self.source)
        self.assertNotIn("FOR UPDATE", self.source)
        self.assertNotIn("GET_LOCK", self.source)
        self.assertIn("'advisory' => true", self.source)

    def test_routes_and_client_require_acting_user(self):
        self.assertIn("'/presence/heartbeat' => ['POST']", self.index)
        self.assertIn("'/presence/close' => ['POST']", self.index)
        self.assertIn("$auth->actingUser($request)", self.index)
        self.assertIn('"/presence/heartbeat"', self.client)
        self.assertIn('"/presence/close"', self.client)
        self.assertIn("acting=True", self.client)


class PresenceDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mysql = os.environ.get("IRICA_MARIADB") or shutil.which("mariadb") or shutil.which("mysql")
        cls.php = os.environ.get("IRICA_PHP") or shutil.which("php")
        cls.password = os.environ.get("IRICA_DB_ROOT_PASSWORD")
        cls.host = os.environ.get("IRICA_DB_HOST", "127.0.0.1")
        cls.port = os.environ.get("IRICA_DB_PORT", "3307")
        if not cls.mysql or not cls.php or not cls.password:
            raise unittest.SkipTest("MariaDB/PHP test service is not configured")
        cls.db = "irica_presence_%s" % uuid.uuid4().hex[:12]
        cls.tenant = str(uuid.uuid4())
        cls.user1, cls.user2 = str(uuid.uuid4()), str(uuid.uuid4())
        cls.dev1, cls.dev2 = str(uuid.uuid4()), str(uuid.uuid4())
        cls._sql("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" % cls.db, select_db=False)
        try:
            for filename in MIGRATION_FILES:
                cls._sql(read(os.path.join(MIGRATIONS, filename)))
            cls._seed()
            cls.script_dir = tempfile.mkdtemp(prefix="irica_presence_php_")
            cls.script = os.path.join(cls.script_dir, "presence.php")
            cls._write_script()
        except Exception:
            cls._sql("DROP DATABASE IF EXISTS `%s`;" % cls.db, select_db=False, check=False)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "script_dir", ""), ignore_errors=True)
        if getattr(cls, "mysql", None) and getattr(cls, "db", None):
            cls._sql("DROP DATABASE IF EXISTS `%s`;" % cls.db, select_db=False, check=False)

    @classmethod
    def _sql(cls, sql, *, select_db=True, check=True):
        cmd = [cls.mysql, "-h", cls.host, "-P", str(cls.port), "-u", "root",
               "--protocol=TCP", "--default-character-set=utf8mb4", "--batch",
               "--skip-column-names"]
        if "mariadb" in os.path.basename(cls.mysql).lower():
            cmd.append("--ssl=FALSE")
        if select_db:
            cmd.append(cls.db)
        env = dict(os.environ); env["MYSQL_PWD"] = cls.password
        run = subprocess.run(cmd, input=sql, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", env=env, timeout=180)
        if check and run.returncode != 0:
            raise AssertionError("SQL failed: %s" % (run.stderr or "")[:1800])
        return run.stdout or ""

    @classmethod
    def scalar(cls, sql):
        lines = cls._sql(sql).strip().splitlines()
        return lines[-1] if lines else ""

    @classmethod
    def _seed(cls):
        now = "2026-10-16 09:00:00"
        rows = [
            "INSERT INTO tenants (id,slug,name,status,created_at,updated_at) VALUES ('%s','presence-v2','Presence Test','active','%s','%s');" % (cls.tenant, now, now),
        ]
        for idx, user in enumerate((cls.user1, cls.user2), 1):
            rows.append("INSERT INTO users (id,tenant_id,username,password_hash,display_name,must_change_password,status,token_version,row_version,created_at,updated_at) VALUES ('%s','%s','presence-user-%d','test-hash','Operator %d',0,'active',1,1,'%s','%s');" % (user, cls.tenant, idx, idx, now, now))
            rows.append("INSERT INTO memberships (id,tenant_id,user_id,role,created_at,updated_at) VALUES ('%s','%s','%s','user','%s','%s');" % (str(uuid.uuid4()), cls.tenant, user, now, now))
        for dev, user, name in ((cls.dev1, cls.user1, "PC 1"), (cls.dev2, cls.user2, "PC 2")):
            rows.append("INSERT INTO sync_devices (id,tenant_id,name,status,token_version,enrolled_by,owner_user_id,row_version,created_at,updated_at) VALUES ('%s','%s','%s','active',1,'%s','%s',1,'%s','%s');" % (dev, cls.tenant, name, user, user, now, now))
        cls._sql("\n".join(rows))

    @classmethod
    def _write_script(cls):
        required = ("Schema", "Database", "Http", "Ids", "Log", "Tokens", "Roles", "RateLimit", "Auth", "Presence")
        lines = ["<?php", "declare(strict_types=1);"]
        for name in required:
            lines.append("require_once %s;" % json.dumps(os.path.join(HOST, "src", name + ".php").replace("\\", "/")))
        lines.extend([
            "$db=Database::fromConfig(['host'=>getenv('IRICA_DB_HOST'),'port'=>(int)getenv('IRICA_DB_PORT'),'dbname'=>getenv('IRICA_PRESENCE_DB'),'user'=>'root','password'=>getenv('IRICA_DB_ROOT_PASSWORD')]);",
            "$svc=new Presence($db,new Log(null));",
            "$tenant=getenv('IRICA_PRESENCE_TENANT'); $dev=$argv[2]; $user=$argv[3];",
            "$dp=new Principal(Tokens::KIND_DEVICE,$dev,$tenant,Roles::USER,$user,$dev,Ids::v4(),1);",
            "$up=new Principal(Tokens::KIND_USER,$user,$tenant,Roles::USER,$user,'',Ids::v4(),1);",
            "try{if($argv[1]==='heartbeat'){$out=$svc->heartbeat($dp,$up,['entity'=>'crm_devices','entity_id'=>$argv[4]],Ids::v4());}else{$out=$svc->close($dp,$up,['lease_id'=>$argv[4]],Ids::v4());}echo json_encode(['ok'=>true,'result'=>$out]);}catch(ApiException $e){echo json_encode(['ok'=>false,'status'=>$e->status,'code'=>$e->errorCode]);exit(2);}",
        ])
        with open(cls.script, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def _call(self, action, dev, user, value):
        env = dict(os.environ)
        env.update({"IRICA_DB_ROOT_PASSWORD": self.password,
                    "IRICA_DB_HOST": self.host, "IRICA_DB_PORT": str(self.port),
                    "IRICA_PRESENCE_DB": self.db, "IRICA_PRESENCE_TENANT": self.tenant})
        run = subprocess.run([self.php, self.script, action, dev, user, value],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", env=env, cwd=ROOT, timeout=120)
        payload = json.loads((run.stdout or "").strip().splitlines()[-1])
        return run.returncode, payload

    def test_two_devices_can_be_present_on_same_record_without_locking(self):
        record = str(uuid.uuid4())
        code, first = self._call("heartbeat", self.dev1, self.user1, record)
        self.assertEqual(code, 0); self.assertTrue(first["ok"])
        self.assertEqual(first["result"]["peers"], [])
        lease1 = first["result"]["lease_id"]
        code, second = self._call("heartbeat", self.dev2, self.user2, record)
        self.assertEqual(code, 0); self.assertTrue(second["ok"])
        self.assertEqual(len(second["result"]["peers"]), 1)
        self.assertEqual(second["result"]["peers"][0]["sync_device_id"], self.dev1)
        code, again = self._call("heartbeat", self.dev1, self.user1, record)
        self.assertEqual(code, 0)
        self.assertEqual(again["result"]["lease_id"], lease1)
        self.assertEqual(len(again["result"]["peers"]), 1)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM record_presence WHERE entity_id='%s';" % record), "2")

    def test_close_is_scoped_and_idempotent(self):
        record = str(uuid.uuid4())
        _, one = self._call("heartbeat", self.dev1, self.user1, record)
        _, two = self._call("heartbeat", self.dev2, self.user2, record)
        lease1 = one["result"]["lease_id"]
        code, closed = self._call("close", self.dev1, self.user1, lease1)
        self.assertEqual(code, 0); self.assertTrue(closed["result"]["closed"])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM record_presence WHERE entity_id='%s';" % record), "1")
        _, closed_again = self._call("close", self.dev1, self.user1, lease1)
        self.assertFalse(closed_again["result"]["closed"])
        # The second device's lease was never touched.
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM record_presence WHERE lease_id='%s';" % two["result"]["lease_id"]), "1")

    def test_expired_presence_is_purged_by_next_heartbeat(self):
        record = str(uuid.uuid4())
        self._call("heartbeat", self.dev1, self.user1, record)
        self._sql("UPDATE record_presence SET expires_at='2000-01-01 00:00:00' WHERE entity_id='%s' AND sync_device_id='%s';" % (record, self.dev1))
        _, second = self._call("heartbeat", self.dev2, self.user2, record)
        peers = second["result"]["peers"]
        self.assertEqual(peers, [])
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM record_presence WHERE entity_id='%s';" % record), "1")


if __name__ == "__main__":
    unittest.main()
'''
write("lab/tests/test_server_crm_v2_presence.py", presence_test)

client_test = r'''# -*- coding: utf-8 -*-
"""Clean-checkout contracts for Phase-4 advisory presence wiring."""
import os
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def read(path):
    with open(os.path.join(ROOT, path), "r", encoding="utf-8") as handle:
        return handle.read()


class PresenceClientContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = read("cloud_sync/client.py")
        cls.panel = read("panel.py")

    def test_transport_uses_acting_user_for_heartbeat_and_close(self):
        self.assertIn("def presence_heartbeat", self.client)
        self.assertIn('"/presence/heartbeat"', self.client)
        self.assertIn("def presence_close", self.client)
        self.assertIn('"/presence/close"', self.client)
        self.assertGreaterEqual(self.client.count("acting=True"), 3)

    def test_case_modal_shows_presence_as_advisory_only(self):
        self.assertIn('id="case-presence"', self.panel)
        self.assertIn("presenceStart('crm_devices',id)", self.panel)
        self.assertIn("این فقط هشدار حضور است", self.panel)
        self.assertIn("ویرایش قفل نمی‌شود", self.panel)
        self.assertIn("/cloud-presence", self.panel)
        self.assertIn("/cloud-presence-close", self.panel)
        # Presence never enters stageReady/stageContinue as an edit gate.
        start = self.panel.index("function stageReady")
        end = self.panel.index("function stageActions", start)
        self.assertNotIn("presence", self.panel[start:end].lower())


if __name__ == "__main__":
    unittest.main()
'''
write("lab/tests/test_server_crm_v2_presence_client.py", client_test)

# Permanent CI gates on both production DB families and the Windows client.
replace_once(
    ".github/workflows/server-crm-v2.yml",
    "          test_server_crm_v2_finance_transport\n",
    "          test_server_crm_v2_finance_transport\n          test_server_crm_v2_presence_client\n",
)
replace_once(
    ".github/workflows/server-crm-v2.yml",
    "          test_server_crm_v2_backup_restore\n          test_v115_audit_config_switch\n",
    "          test_server_crm_v2_backup_restore\n          test_server_crm_v2_presence\n          test_v115_audit_config_switch\n",
)
# This anchor occurs once in mysql57-compatibility after host-foundation was
# already modified above.
replace_once(
    ".github/workflows/server-crm-v2.yml",
    "          test_server_crm_v2_database_resilience\n          test_server_crm_v2_backup_restore\n",
    "          test_server_crm_v2_database_resilience\n          test_server_crm_v2_backup_restore\n          test_server_crm_v2_presence\n",
)

# Release notes call out the completed advisory concurrency surface.
replace_once(
    "RELEASE_NOTES_v1.15.0.md",
    "- Optimistic row-version conflict handling prevents silent overwrites.\n",
    "- Optimistic row-version conflict handling prevents silent overwrites.\n- Advisory record presence shows when another enrolled PC has the same case open; it never locks editing and expires automatically.\n",
)

print("v1.15 Phase 4 presence patch applied")
