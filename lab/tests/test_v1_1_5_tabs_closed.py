"""v1.1.5 — CRM completed/problem tabs + terminal 'closed' (مختومه) state.

- New tabs: 'done_tab' («تکمیل شده‌ها»), 'problem_tab' («دارای اشکال»),
  'closed_tab' («مختومه‌ها») — ordered after 'reports', before 'settings'.
- New terminal stage 'closed': reachable ONLY from 'problem' and 'inquiry'
  via the 'close_case' action; requires a non-empty Persian reason stored as
  device['closed_reason'] plus device['closed_at'] ISO-ish timestamp.
- Closed cases are excluded from the scheduler watch set, periodic list,
  needsAction highlighting and every further advance() action.
"""
import json
import os
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

import crm  # noqa: E402
import panel  # noqa: E402


def crm_js():
    """Concatenated <script> bodies of CRM_PAGE (same trick as the rail test)."""
    return "\n".join(re.findall(r"<script>([\s\S]*?)</script>", panel.CRM_PAGE))


def fn_body_js(js, name):
    """Naive brace-matched body of `function name(...){...}` ("" if absent)."""
    m = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\{", js)
    if not m:
        return ""
    depth, i = 1, m.end()
    while i < len(js) and depth:
        if js[i] == "{":
            depth += 1
        elif js[i] == "}":
            depth -= 1
        i += 1
    return js[m.start():i]


class TempStoreCase(unittest.TestCase):
    """Isolated crm store per test (same pattern as test_crm_store)."""

    def setUp(self):
        self._old = os.environ.get("IRICA_CRM_STORE")
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(path)
        os.environ["IRICA_CRM_STORE"] = path
        self.path = path
        crm.reset_cache()
        self.addCleanup(crm.reset_cache)

    def tearDown(self):
        crm.reset_cache()
        if self._old:
            os.environ["IRICA_CRM_STORE"] = self._old
        else:
            os.environ.pop("IRICA_CRM_STORE", None)
        for suffix in ("", ".bak", ".tmp"):
            try:
                os.remove(self.path + suffix)
            except OSError:
                pass

    def _customer(self):
        rec, errs = crm.add_customer({"full_name": "علی رضایی"})
        assert errs == [], errs
        return rec

    def _device(self, **over):
        fields = {"name": "iPhone 13", "serial1": "356938035643809"}
        fields.update(over)
        rec, errs = crm.add_device(fields)
        assert errs == [], errs
        return rec


class CloseCaseTransitionTests(TempStoreCase):
    """close_case from problem/inquiry -> terminal closed with reason."""

    def _to_problem(self, device_id):
        crm.advance(device_id, "queue_inquiry")
        dev, errs = crm.advance(device_id, "mark_problem")
        assert errs == [], errs
        return dev

    def test_close_case_from_problem(self):
        customer = self._customer()
        device = self._device(customer_id=customer["id"])
        self._to_problem(device["id"])
        dev, errs = crm.advance(device["id"], "close_case",
                                reason="دستگاه ثبت‌شده بوده است")
        self.assertEqual(errs, [])
        self.assertEqual(dev["stage"], "closed")
        self.assertEqual(dev["closed_reason"], "دستگاه ثبت‌شده بوده است")
        self.assertTrue(dev.get("closed_at"))
        # all other fields preserved (additive change only)
        self.assertEqual(dev["name"], "iPhone 13")
        self.assertEqual(dev["serial1"], "356938035643809")
        self.assertEqual(dev["customer_id"], customer["id"])

    def test_close_case_from_inquiry(self):
        device = self._device()
        crm.advance(device["id"], "queue_inquiry")
        dev, errs = crm.advance(device["id"], "close_case", reason="انصراف مشتری")
        self.assertEqual(errs, [])
        self.assertEqual(dev["stage"], "closed")
        self.assertEqual(dev["closed_reason"], "انصراف مشتری")
        self.assertTrue(dev.get("closed_at"))

    def test_close_case_rejected_from_new(self):
        device = self._device()
        dev, errs = crm.advance(device["id"], "close_case", reason="هر چیزی")
        self.assertTrue(errs)
        self.assertIsNone(dev)

    def test_close_case_rejected_from_done(self):
        device = self._device()
        data = crm.store_read()
        dev = next(d for d in data["devices"] if d["id"] == device["id"])
        dev["stage"] = "done"
        crm.store_write(data)
        _, errs = crm.advance(device["id"], "close_case", reason="هر چیزی")
        self.assertTrue(errs)

    def test_close_case_empty_reason_rejected(self):
        device = self._device()
        self._to_problem(device["id"])
        for reason in ("", "   "):
            dev, errs = crm.advance(device["id"], "close_case", reason=reason)
            self.assertTrue(errs, f"empty reason {reason!r} must be rejected")
            self.assertIsNone(dev)
            data = crm.store_read()
            stored = next(d for d in data["devices"] if d["id"] == device["id"])
            self.assertEqual(stored["stage"], "problem")
            self.assertNotIn("closed_reason", stored)


class ClosedTerminalTests(TempStoreCase):
    """closed is terminal: no transitions, no rollback, no skip."""

    def _closed_device(self):
        device = self._device()
        crm.advance(device["id"], "queue_inquiry")
        crm.advance(device["id"], "close_case", reason="انصراف مشتری")
        return device

    def test_allowed_map_terminal(self):
        # v1.5: closed gains exactly one entry — detach_owner, a
        # link-mutating action (unlink passenger), NOT a stage transition.
        self.assertEqual(crm.ALLOWED["closed"], {"detach_owner": "closed"})
        self.assertEqual(crm.ALLOWED["problem"]["close_case"], "closed")
        self.assertEqual(crm.ALLOWED["inquiry"]["close_case"], "closed")

    def test_no_rollback_no_skip_from_closed(self):
        self.assertNotIn("closed", crm._STAGE_BACK)
        self.assertNotIn("closed", crm._STAGE_SKIP_NEXT)

    def test_advance_rejects_every_action_on_closed(self):
        device = self._closed_device()
        for action in ("queue_inquiry", "mark_problem", "mark_ready",
                       "requeue_inquiry", "close_case", "confirm_payment"):
            dev, errs = crm.advance(device["id"], action, reason="x",
                                    owner_id="whatever")
            self.assertTrue(errs, f"action {action} must be rejected on closed")
            self.assertIsNone(dev)

    def test_detach_on_closed_ownerless_fails_for_owner_not_stage(self):
        # v1.5: detach_owner IS allowed on closed — an ownerless closed case
        # must fail with the owner error, not the stage-gate error (the
        # bound-owner success path lives in test_v1_5_owner_detach).
        device = self._closed_device()
        dev, errs = crm.advance(device["id"], "detach_owner")
        self.assertEqual(errs, ["این مسافر به پرونده‌ای متصل نیست"])
        self.assertIsNone(dev)

    def test_stage_back_and_skip_rejected_on_closed(self):
        device = self._closed_device()
        for action in ("stage_back", "stage_skip"):
            dev, errs = crm.advance(device["id"], action)
            self.assertTrue(errs, f"{action} must be rejected on closed")
            self.assertIsNone(dev)

    def test_stage_fa_report_label(self):
        self.assertEqual(crm._STAGE_FA["closed"], "مختومه")

    def test_stage_membership_lists_exclude_closed(self):
        self.assertNotIn("closed", crm.INTAKE_STAGES)
        self.assertNotIn("closed", crm.WATCH_STAGES)


class ClosureTraceLogTests(TempStoreCase):
    """case_closed ledger event: presence + reason-length only (no text)."""

    def _mk_device(self, stage="problem"):
        dev, errs = crm.add_device({"name": "تریس", "serial1": "356938035643809"})
        assert not errs, errs
        if stage != "new":
            # walk the machine to the wanted stage via direct store write to
            # keep this test focused on the log contract
            data = crm.store_read()
            d = next(x for x in data["devices"] if x["id"] == dev["id"])
            d["stage"] = stage
            crm.store_write(data)
        return dev

    def test_case_closed_logged_without_reason_text(self):
        import panel as panel_mod
        dev = self._mk_device("problem")
        log_before = self._log_lines()
        dev2, errs = panel_mod.crm_advance_logged(dev["id"], "close_case",
                                                  reason="دلیل محرمانه")
        self.assertFalse(errs)
        new = [l for l in self._log_lines() if l not in log_before]
        events = [l for l in new if l.get("event") == "case_closed"]
        self.assertTrue(events, f"case_closed event missing in {new}")
        entry = events[-1]
        self.assertEqual(entry.get("device_id"), dev["id"])
        self.assertEqual(entry.get("reason_len"), len("دلیل محرمانه"))
        self.assertNotIn("reason", entry)
        self.assertNotIn("دلیل محرمانه", str(entry))

    def _log_lines(self):
        import json
        out = []
        try:
            with open(crm.log_path(), encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
        except FileNotFoundError:
            pass
        return out


class ClosedSchedulerExclusionTests(unittest.TestCase):
    """Scheduler/periodic paths must skip closed devices entirely."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.estelam = os.path.join(self.tmp.name, "estelam_store.json")
        self.crm_store = os.path.join(self.tmp.name, "crm_store.json")
        self.profiles = os.path.join(self.tmp.name, "profiles.json")
        with open(self.estelam, "w", encoding="utf-8") as handle:
            json.dump({"person": {}, "devices": []}, handle)
        with open(self.profiles, "w", encoding="utf-8") as handle:
            json.dump({"active_id": "", "profiles": []}, handle)
        self._patches = [
            patch.object(panel, "ESTELAM_PATH", self.estelam),
            patch.object(panel, "PROFILES_PATH", self.profiles),
            patch.object(panel, "INPUTS_PATH",
                         os.path.join(self.tmp.name, "inputs.json")),
            patch.object(panel, "_STORE_LOCK_PATH", self.profiles + ".lock"),
            patch.dict(os.environ, {"IRICA_CRM_STORE": self.crm_store}),
        ]
        for item in self._patches:
            item.start()
            self.addCleanup(item.stop)
        crm.reset_cache()
        self.addCleanup(crm.reset_cache)

    def _closed_device(self):
        device, errs = crm.add_device({"name": "iPhone 13",
                                       "serial1": "356938035643809"})
        assert errs == [], errs
        crm.advance(device["id"], "queue_inquiry")
        dev, errs = crm.advance(device["id"], "close_case",
                                reason="دستگاه ثبت‌شده بوده است")
        assert errs == [], errs
        return device

    def test_scheduler_tick_skips_closed(self):
        device = self._closed_device()
        result = panel.crm_scheduler_tick(origin="test")
        self.assertEqual(result["started"], [])
        with open(self.estelam, encoding="utf-8") as handle:
            est = json.load(handle)
        ids = [str(d.get("id")) for d in est.get("devices", [])]
        self.assertNotIn(str(device["id"]), ids,
                         "closed device must not be enqueued")

    def test_start_inquiry_rejects_closed(self):
        device = self._closed_device()
        result = panel.crm_start_inquiry(device["id"], service="gomrok",
                                         origin="test")
        self.assertFalse(result["ok"])
        self.assertTrue(any("مختومه" in e for e in result["errors"]))

    def test_periodic_toggle_rejects_closed(self):
        device = self._closed_device()
        result = panel.crm_periodic_toggle(device["id"], remove=False)
        self.assertFalse(result["ok"])
        self.assertTrue(any("مختومه" in e for e in result["errors"]))


class TabsMarkupTests(unittest.TestCase):
    """CRM page markup: new tabs, ordering, counts, close-case dialog."""

    def setUp(self):
        self.page = panel.CRM_PAGE
        self.js = crm_js()

    def _tabs_list(self):
        match = re.search(r"var TABS = \[([\s\S]*?)\];", self.js)
        self.assertTrue(match, "TABS array not found")
        return match.group(1)

    def test_tab_order_done_problem_closed_before_settings(self):
        tabs = self._tabs_list()
        order = ["'ledger'", "'reports'", "'done_tab'", "'problem_tab'",
                 "'closed_tab'", "'settings'"]
        positions = [tabs.find(token) for token in order]
        for pos in positions:
            self.assertGreaterEqual(pos, 0, f"missing tab token in {order}")
        self.assertEqual(positions, sorted(positions),
                         "tab order must be ledger,reports,done_tab,"
                         "problem_tab,closed_tab,settings")

    def test_tab_labels(self):
        self.assertIn("['done_tab','تکمیل شده‌ها']", self.page)
        self.assertIn("['problem_tab','دارای اشکال']", self.page)
        self.assertIn("['closed_tab','مختومه‌ها']", self.page)

    def test_tab_counts_in_render_tabs(self):
        self.assertIn("done_tab:devs.filter(d=>d.stage==='done').length",
                      self.page)
        self.assertIn("problem_tab:devs.filter(d=>d.stage==='problem').length",
                      self.page)
        self.assertIn("closed_tab:devs.filter(d=>d.stage==='closed').length",
                      self.page)

    def test_render_view_dispatches_new_tabs(self):
        self.assertIn("else if(TAB==='done_tab')body=doneTabHtml();", self.page)
        self.assertIn("else if(TAB==='problem_tab')body=problemTabHtml();",
                      self.page)
        self.assertIn("else if(TAB==='closed_tab')body=closedTabHtml();",
                      self.page)

    def test_kpi_completed_renamed_and_targets_done_tab(self):
        self.assertIn("k('k-ok','تکمیل شده‌ها',c.ok,'done_tab')", self.page)

    def test_done_tab_readonly_note(self):
        self.assertIn("function doneTabHtml(){", self.page)
        self.assertIn("از جریان اصلی خارج شده‌اند", self.page)

    def test_problem_tab_rows_and_requeue(self):
        self.assertIn("function problemTabHtml(){", self.page)
        self.assertIn("function devRequeue(id){", self.page)
        requeue = re.search(r"function devRequeue\(id\)\{[\s\S]*?\n\}", self.js)
        self.assertTrue(requeue, "devRequeue body not found")
        self.assertIn("confirmDlg(", requeue.group(0))
        self.assertIn("devTick(id,'requeue_inquiry')", requeue.group(0))

    def test_closed_tab_rows_show_reason_and_date(self):
        self.assertIn("function closedTabHtml(){", self.page)
        self.assertIn("esc(d.closed_reason||'—')", self.page)
        # v1.4.2: the closure date renders Jalali
        self.assertIn("faDate(d.closed_at)", self.page)

    def test_stage_fa_and_tone_have_closed(self):
        self.assertIn("'closed':'مختومه'", self.page)
        tone = re.search(r"var STAGE_TONE = \{([\s\S]*?)\};", self.js)
        self.assertTrue(tone, "STAGE_TONE not found")
        self.assertIn("'closed':'n'", tone.group(1))

    def test_close_button_on_problem_and_inquiry_cards(self):
        # v1.3.1: the case-detail close affordance moved from stageActions
        # (tools) to the quiet "other actions" row — still gated to
        # inquiry/problem exactly like the server's ALLOWED map.
        self.assertIn("((st==='inquiry'||st==='problem')?"
                      "'<button class=\"btn mini danger\" "
                      "onclick=\"devTick(\\''+d.id+'\\',\\'__close_case\\')\">"
                      "مختومه کردن</button>':'')",
                      self.page)

    def test_close_case_dialog_flow(self):
        self.assertIn("if(action==='__close_case'){", self.page)
        self.assertIn('id="closeReason" placeholder="دلیل مختومه‌کردن پرونده…"',
                      self.page)
        self.assertIn("function closeCaseYes(id){", self.page)
        submit = re.search(r"function closeCaseYes\(id\)\{[\s\S]*?\n\}", self.js)
        self.assertTrue(submit, "closeCaseYes body not found")
        body = submit.group(0)
        self.assertIn("if(!reason){toast(", body)
        self.assertIn("action:'close_case',reason:reason", body)
        # The irreversible close flow now owns a dedicated reason modal; the
        # legacy generic confirmDlg assertion became stale once that UX shipped.
        self.assertIn("function closeCaseDialog(id){", self.page)
        self.assertIn("openDlg('<h3>مختومه کردن پرونده</h3>'", self.page)

    def test_rail_and_guide_tolerate_closed(self):
        # 'closed' is off-rail: it must NOT be a numbered rail step and the
        # rail renderer must not special-case it (indexOf -> -1, no crash).
        steps = re.search(r"var RAIL_STEPS = \[([\s\S]*?)\]", self.js)
        self.assertTrue(steps)
        self.assertNotIn("'closed'", steps.group(1))
        # railHtml looks steps up by indexOf and must tolerate a stage that is
        # not on the rail ('closed' renders off-rail, like 'problem').
        rail = fn_body_js(self.js, "railHtml")
        self.assertTrue(rail, "railHtml not found")
        self.assertIn("RAIL_STEPS", rail)

    def test_needs_action_excludes_closed(self):
        match = re.search(r"function needsAction\(d\)\{[\s\S]*?\}", self.js)
        self.assertTrue(match)
        self.assertNotIn("'closed'", match.group(0))

    def test_periodic_map_excludes_closed(self):
        match = re.search(r"var PERIODIC_STAGES = \{([\s\S]*?)\};", self.js)
        self.assertTrue(match)
        self.assertNotIn("'closed'", match.group(1))

    def test_tick_route_forwards_reason(self):
        src = open(panel.__file__, encoding="utf-8").read()
        self.assertIn('reason=str(data.get("reason") or "")', src)


if __name__ == "__main__":
    unittest.main()
