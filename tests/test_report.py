"""
Report tests: simple/mt consistency, bounds, escaping of hostile captured
text, and wording that keeps "Unknown" distinct from a positive match.
"""

import contextlib
import html
import io
import json
import os
import re
import tempfile
import unittest

from dpi import report as rp
from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT

from tests import fixtures as fx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPTURES = os.path.join(ROOT, "samples", "captures")
HOSTILE = os.path.join(CAPTURES, "hostile_names.pcap")
MIXED = os.path.join(CAPTURES, "mixed_unsupported.pcap")

VOLATILE = ("generated_at",)


def _run(engine, in_path, out_path):
    with contextlib.redirect_stdout(io.StringIO()):
        engine.process_file(in_path, out_path)
    return engine


def _strip(report):
    r = json.loads(json.dumps(report))
    for k in VOLATILE:
        r.pop(k, None)
    r["run"].pop("threads", None)
    r["run"].pop("mode", None)
    return r


class ReportBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.dir.name, "out.pcap")

    def tearDown(self):
        self.dir.cleanup()

    def report_for(self, make, in_path, rules=lambda e: None, **kw):
        eng = make()
        rules(eng)
        _run(eng, in_path, self.out)
        return rp.build_report(eng, in_path, self.out, **kw)


class TestConsistency(ReportBase):
    def test_simple_and_mt_reports_are_identical(self):
        rules = lambda e: (e.block_domain("google"), e.block_ip("192.0.2.66"))
        a = self.report_for(DPIEngine, MIXED, rules)
        b = self.report_for(lambda: DPIEngineMT(2, 2), MIXED, rules)
        self.assertEqual(_strip(a), _strip(b))
        self.assertEqual(a["run"]["mode"], "simple")
        self.assertEqual(b["run"]["mode"], "mt")
        self.assertEqual(b["run"]["threads"], {"load_balancers": 2, "fast_paths_per_lb": 2})

    def test_report_accounting_matches_engine_stats(self):
        eng = _run(DPIEngine(), MIXED, self.out)
        r = rp.build_report(eng, MIXED, self.out)
        acc = r["accounting"]
        self.assertEqual(acc["total_packets"], eng.stats.total_packets)
        self.assertEqual(acc["retained"], eng.stats.forwarded_packets)
        self.assertEqual(acc["unsupported"], 3)
        self.assertEqual(acc["malformed"], 1)
        self.assertTrue(acc["reconciles"])
        self.assertEqual(acc["retained"] + acc["rule_filtered"] + acc["unsupported"] + acc["malformed"],
                         acc["total_packets"])

    def test_flows_listed_in_input_order_with_rule_and_action(self):
        r = self.report_for(DPIEngine, MIXED, lambda e: e.block_domain("google"))
        ids = [f["first_packet_id"] for f in r["flows"]["items"]]
        self.assertEqual(ids, sorted(ids))
        dropped = [f for f in r["flows"]["items"] if f["action"] == "drop"]
        self.assertEqual(len(dropped), 2)
        for f in dropped:
            self.assertEqual(f["rule"]["type"], "domain")
            self.assertIn("google", f["rule"]["detail"])
        for f in r["flows"]["items"]:
            if f["action"] == "forward":
                self.assertIsNone(f["rule"])
        self.assertEqual(r["flows_by_action"], {"forward": 24, "drop": 2})

    def test_observed_metadata_is_kept_per_protocol(self):
        r = self.report_for(DPIEngine, MIXED)
        by_kind = {"tls_sni": 0, "http_host": 0, "dns_query": 0}
        for f in r["flows"]["items"]:
            for k in by_kind:
                if f["observed"][k]:
                    by_kind[k] += 1
                    others = [o for o in by_kind if o != k]
                    self.assertTrue(all(f["observed"][o] is None for o in others), f)
        self.assertEqual(by_kind, {"tls_sni": 8, "http_host": 2, "dns_query": 3})

    def test_unknown_is_distinct_from_positive_classification(self):
        r = self.report_for(DPIEngine, MIXED)
        unknown = [f for f in r["flows"]["items"] if not f["classification"]["known"]]
        known = [f for f in r["flows"]["items"] if f["classification"]["known"]]
        self.assertEqual(len(unknown), 8)          # the 8 server->client SYN-ACK flows
        for f in unknown:
            self.assertEqual(f["classification"]["app"], "Unknown")
            self.assertEqual(f["classification"]["method"], "none")
        for f in known:
            self.assertNotEqual(f["classification"]["app"], "Unknown")
            self.assertIn(f["classification"]["method"], ("tls_sni", "http_host", "dns_port", "port_fallback"))
        for f in r["flows"]["items"]:
            self.assertTrue(f["classification"]["heuristic"])

    def test_disclaimer_present_and_never_claims_malice(self):
        r = self.report_for(DPIEngine, MIXED, lambda e: e.block_app("YouTube"))
        text = rp.to_json(r) + rp.to_html(r)
        self.assertIn("not evidence that traffic is malicious", text)
        for word in ("malware", "threat detected", "malicious traffic detected", "attack"):
            self.assertNotIn(word, text.lower())


class TestBounds(ReportBase):
    def test_max_flows_truncates_and_records_total(self):
        r = self.report_for(DPIEngine, MIXED, max_flows=5)
        self.assertEqual(r["flows"]["total"], 26)
        self.assertEqual(r["flows"]["listed"], 5)
        self.assertTrue(r["flows"]["truncated"])
        self.assertEqual(len(r["flows"]["items"]), 5)
        self.assertIn("Flow list truncated", rp.to_html(r))

    def test_max_flows_zero_lists_nothing_but_keeps_summary(self):
        r = self.report_for(DPIEngine, MIXED, max_flows=0)
        self.assertEqual(r["flows"]["items"], [])
        self.assertEqual(r["flows"]["total"], 26)
        self.assertTrue(r["accounting"]["reconciles"])

    def test_negative_max_flows_rejected(self):
        eng = _run(DPIEngine(), MIXED, self.out)
        with self.assertRaises(ValueError):
            rp.build_report(eng, MIXED, self.out, max_flows=-1)

    def test_maximum_length_name_is_kept_and_overlong_is_rejected_upstream(self):
        r = self.report_for(DPIEngine, HOSTILE)
        max_flows = [f for f in r["flows"]["items"]
                     if f["observed"]["tls_sni"] and f["observed"]["tls_sni"].startswith("a" * 50)]
        self.assertEqual(len(max_flows), 1)
        self.assertEqual(len(max_flows[0]["observed"]["tls_sni"]), 255)      # not clipped
        self.assertEqual([f for f in r["flows"]["items"]
                          if f["observed"]["tls_sni"] and "b" * 50 in f["observed"]["tls_sni"]], [],
                         "over-long SNI must not be extracted at all")

    def test_flow_record_clips_overlong_strings_defensively(self):
        from dpi.types import Connection, FiveTuple
        conn = Connection(tuple=FiveTuple(1, 2, 3, 4, 6))
        conn.tls_sni = "x" * 400
        rec = rp.flow_record(conn)
        sni = rec["observed"]["tls_sni"]
        self.assertEqual(len(sni), rp.MAX_NAME_LEN + 1)
        self.assertTrue(sni.endswith("\u2026"))

    def test_clean_text(self):
        self.assertIsNone(rp.clean_text(""))
        self.assertIsNone(rp.clean_text(None))
        self.assertEqual(rp.clean_text("a\x00b\x1fc\x7fd"), "a\ufffdb\ufffdc\ufffdd")
        self.assertEqual(rp.clean_text("x" * 300, limit=10), "x" * 10 + "\u2026")


class TestEscaping(ReportBase):
    HOSTILE_STRINGS = (
        "<script>alert(1)</script>",
        '"><script>alert(2)</script>',
        "<img src=x>",
    )

    def test_html_contains_no_raw_hostile_markup(self):
        r = self.report_for(DPIEngine, HOSTILE)
        page = rp.to_html(r)
        for s in self.HOSTILE_STRINGS:
            self.assertNotIn(s, page)
            self.assertIn(html.escape(s, quote=True), page)
        self.assertNotIn("<script", page.lower())
        self.assertNotIn("onerror", page.lower())
        self.assertEqual(page.count("<img"), 0)

    def test_json_preserves_hostile_strings_exactly(self):
        r = self.report_for(DPIEngine, HOSTILE)
        observed = [f["observed"] for f in r["flows"]["items"]]
        names = {v for o in observed for v in o.values() if v}
        self.assertIn("<script>alert(1)</script>.evil.test", names)
        self.assertIn('evil.test"><script>alert(2)</script>', names)
        self.assertIn("<img src=x>.evil.test", names)
        text = rp.to_json(r)
        self.assertTrue(text.isascii())
        json.loads(text)

    def test_rule_detail_is_escaped(self):
        r = self.report_for(DPIEngine, HOSTILE, lambda e: e.block_domain("<b>evil</b>.test"))
        # No flow matches this rule; the rule table still renders it escaped.
        page = rp.to_html(r)
        self.assertNotIn("<b>evil</b>", page)
        self.assertIn("&lt;b&gt;evil&lt;/b&gt;", page)

    def test_paths_are_escaped(self):
        eng = _run(DPIEngine(), HOSTILE, self.out)
        r = rp.build_report(eng, "<in>&.pcap", self.out)
        page = rp.to_html(r)
        self.assertNotIn("<in>&.pcap", page)
        self.assertIn("&lt;in&gt;&amp;.pcap", page)

    def test_html_is_static(self):
        r = self.report_for(DPIEngine, HOSTILE)
        page = rp.to_html(r)
        self.assertIsNone(re.search(r"<script\b", page, re.I))
        self.assertIsNone(re.search(r"\son\w+\s*=", page, re.I))
        self.assertIn("Content-Security-Policy", page)

    def test_hostile_domain_rule_matches_and_is_reported(self):
        r = self.report_for(lambda: DPIEngineMT(2, 2), HOSTILE, lambda e: e.block_domain("evil.test"))
        self.assertEqual(r["accounting"]["rule_filtered"], 3)
        dropped = [f for f in r["flows"]["items"] if f["action"] == "drop"]
        self.assertEqual(len(dropped), 3)
        page = rp.to_html(r)
        self.assertEqual(page.count('class="drop"'), 3)


class TestWriters(ReportBase):
    def test_write_json_and_html(self):
        r = self.report_for(DPIEngine, MIXED, generated_at="2026-01-01T00:00:00+00:00")
        pj = os.path.join(self.dir.name, "r.json")
        ph = os.path.join(self.dir.name, "r.html")
        rp.write_json(r, pj)
        rp.write_html(r, ph)
        with open(pj, encoding="utf-8") as f:
            back = json.load(f)
        self.assertEqual(back, r)
        self.assertEqual(back["schema"], rp.SCHEMA)
        self.assertEqual(back["generated_at"], "2026-01-01T00:00:00+00:00")
        with open(ph, encoding="utf-8") as f:
            page = f.read()
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        self.assertIn("2026-01-01T00:00:00+00:00", page)


if __name__ == "__main__":
    unittest.main()
