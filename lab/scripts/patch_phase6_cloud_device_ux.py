#!/usr/bin/env python3
"""One-shot Phase 6 patch for explicit desktop device/reconnect UX."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
PANEL = ROOT / "panel.py"
TESTS = ROOT / "lab" / "tests" / "test_cloud_ui.py"


def replace_exact(path, old, new, label, expected=1):
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise RuntimeError(f"{label}: expected {expected} matches, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def main():
    replace_exact(
        PANEL,
        '''        "tenant_id": "",
        "device_enrolled": False,
        "last_sync": None,
''',
        '''        "tenant_id": "",
        "device_enrolled": False,
        "device_id": "",
        "last_sync": None,
''',
        "status shell device id",
    )
    replace_exact(
        PANEL,
        '''        tenant_id=(getattr(config, "tenant_id", "") or ""),
        device_enrolled=bool(getattr(config, "sync_device_id", None)),
        last_sync=getattr(machine, "last_successful_sync", None),
''',
        '''        tenant_id=(getattr(config, "tenant_id", "") or ""),
        device_enrolled=bool(getattr(config, "sync_device_id", None)),
        device_id=(getattr(config, "sync_device_id", "") or ""),
        last_sync=getattr(machine, "last_successful_sync", None),
''',
        "status payload device id",
    )

    # panel.py carries two shipped cloud surfaces (the main panel and CRM).
    # Both must render the same status contract, so these anchors are required
    # to occur exactly twice rather than choosing one by accident.
    replace_exact(
        PANEL,
        '''      '<div class="cloud-fact"><span class="cloud-fact-l">آخرین همگام‌سازی موفق</span><span class="cloud-fact-v" id="cloud-last-sync">—</span></div>'+''',
        '''      '<div class="cloud-fact"><span class="cloud-fact-l">این دستگاه</span><span class="cloud-fact-v cloud-code" id="cloud-device">ثبت‌نشده</span></div>'+\
      '<div class="cloud-fact"><span class="cloud-fact-l">آخرین همگام‌سازی موفق</span><span class="cloud-fact-v" id="cloud-last-sync">—</span></div>'+''',
        "device fact shell", expected=2,
    )
    replace_exact(
        PANEL,
        '''    '<div class="cloud-error" id="cloud-error-line" role="alert">'+ICON.alert+'<span id="cloud-error-text"></span></div>'+\
    '<div class="cloud-status" id="cloud-beat-line" role="status"></div>'+''',
        '''    '<div class="cloud-error" id="cloud-error-line" role="alert">'+ICON.alert+'<span id="cloud-error-text"></span></div>'+\
    '<div class="cloud-notice" id="cloud-reconnect" role="status">'+ICON.info+\
      '<div><span class="cloud-banner-b">اتصال این دستگاه نیاز به بازسازی دارد</span>'+\
      '<p class="cloud-banner-p" id="cloud-reconnect-text"></p></div></div>'+\
    '<div class="cloud-status" id="cloud-beat-line" role="status"></div>'+''',
        "reconnect notice shell", expected=2,
    )
    replace_exact(
        PANEL,
        '''  document.getElementById('cloud-actor-name').textContent=name;
  document.getElementById('cloud-last-sync').textContent=(s&&s.last_sync)?faDateTime(s.last_sync):'—';
''',
        '''  document.getElementById('cloud-actor-name').textContent=name;
  var deviceId=s&&s.device_id?String(s.device_id):'';
  var deviceText=deviceId?(deviceId.length>12?deviceId.slice(0,8)+'…'+deviceId.slice(-4):deviceId):'ثبت‌نشده';
  document.getElementById('cloud-device').textContent=deviceText;
  document.getElementById('cloud-device').title=deviceId;
  document.getElementById('cloud-last-sync').textContent=(s&&s.last_sync)?faDateTime(s.last_sync):'—';
''',
        "paint device identity", expected=2,
    )
    replace_exact(
        PANEL,
        '''  document.getElementById('cloud-error-text').textContent=msg;
  document.getElementById('cloud-beat-line').textContent=cloudBeatLine(s);
''',
        '''  document.getElementById('cloud-error-text').textContent=msg;
  var reconnect=document.getElementById('cloud-reconnect');
  var reconnectText=document.getElementById('cloud-reconnect-text');
  var needsReconnect=Boolean(s&&['not_enrolled','auth_required','read_only'].indexOf(s.link)>=0);
  reconnect.classList.toggle('on',needsReconnect);
  if(needsReconnect){
    reconnectText.textContent=s.link==='not_enrolled'
      ?'با نام کاربری و رمز عبور میزبان وارد شوید؛ این رایانه با شناسه‌ی مستقل ثبت می‌شود.'
      :(s.link==='read_only'
        ?'مهلت آفلاین تمام شده است؛ برای تازه‌سازی مجوز این رایانه دوباره وارد میزبان شوید.'
        :'نشست ابری قابل استفاده نیست؛ دوباره وارد میزبان شوید. اگر دستگاه لغو شده باشد، ثبت دستگاه باید دوباره انجام شود.');
  }else{reconnectText.textContent='';}
  document.getElementById('cloud-beat-line').textContent=cloudBeatLine(s);
''',
        "paint reconnect guidance", expected=2,
    )

    replace_exact(
        TESTS,
        '''        self.assertEqual(payload["pending"], 3)
        self.assertEqual(payload["conflicts"], 2)
''',
        '''        self.assertEqual(payload["pending"], 3)
        self.assertEqual(payload["conflicts"], 2)

    def test_device_identity_is_visible_but_not_a_credential(self):
        device_id = "12345678-1234-4234-8234-123456789abc"
        payload = panel.cloud_status_payload(
            _fake_runtime(config=_fake_config(api_base="https://api.x.test",
                                              sync_device_id=device_id)))
        self.assertTrue(payload["device_enrolled"])
        self.assertEqual(payload["device_id"], device_id)
        self.assertNotIn("refresh", " ".join(payload.keys()).lower())
        self.assertNotIn("token", " ".join(payload.keys()).lower())
''',
        "status device test",
    )
    replace_exact(
        TESTS,
        ''' 'cloud-error-code','cloud-error-line','cloud-beat-line','cloud-action-status',
 'cloud-sync-btn','cloud-logout-btn','cloud-login-block','cloud-user','cloud-pass',
''',
        ''' 'cloud-error-code','cloud-error-line','cloud-reconnect','cloud-reconnect-text','cloud-beat-line','cloud-action-status',
 'cloud-device','cloud-sync-btn','cloud-logout-btn','cloud-login-block','cloud-user','cloud-pass',
''',
        "node ids",
    )
    replace_exact(
        TESTS,
        ''' 'cloud-actor','cloud-last-sync','cloud-pending','cloud-conflicts',
 'cloud-error-code','cloud-error-line','cloud-beat-line','cloud-action-status',
''',
        ''' 'cloud-actor','cloud-device','cloud-last-sync','cloud-pending','cloud-conflicts',
 'cloud-error-code','cloud-error-line','cloud-reconnect','cloud-reconnect-text','cloud-beat-line','cloud-action-status',
''',
        "shell required ids",
    )
    replace_exact(
        TESTS,
        '''              read_only:c.ro, pending:3, conflicts:c.conflicts||0,
              last_sync:'2026-10-05T10:00:00Z', error_code:null,
''',
        '''              read_only:c.ro, pending:3, conflicts:c.conflicts||0,
              device_id:'12345678-1234-4234-8234-123456789abc',
              last_sync:'2026-10-05T10:00:00Z', error_code:null,
''',
        "paint fixture device id",
    )
    replace_exact(
        TESTS,
        '''  ok(el('cloud-pill-text').textContent===c.label,
     c.name+': pill text is '+el('cloud-pill-text').textContent);
''',
        '''  ok(el('cloud-pill-text').textContent===c.label,
     c.name+': pill text is '+el('cloud-pill-text').textContent);
  ok(el('cloud-device').textContent.indexOf('12345678')===0,
     c.name+': device identity is not visible');
''',
        "paint device assertion",
    )
    replace_exact(
        TESTS,
        '''ok(el('cloud-beat-line').textContent.indexOf('متوقف')>=0, 'no worker line');
''',
        '''ok(el('cloud-beat-line').textContent.indexOf('متوقف')>=0, 'no worker line');
ok(el('cloud-reconnect').classList.contains('on'), 'read-only reconnect guidance hidden');
''',
        "read only reconnect assertion",
    )
    print("phase6 device UX patch applied")


if __name__ == "__main__":
    main()
