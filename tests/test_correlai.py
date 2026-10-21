import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlai.model import Event  # noqa: E402
from correlai.parsers import detect_source, load_jsonl, parse_record  # noqa: E402
from correlai.rules import Correlator  # noqa: E402
from correlai.samples import generate  # noqa: E402
from correlai.webui import render_html  # noqa: E402
from correlai.report import build_payload  # noqa: E402


def demo_events():
    return [e for e in (parse_record(rec, src) for src, rec in generate()) if e]


class ParserTests(unittest.TestCase):
    def test_detect_source(self):
        self.assertEqual(detect_source({"event": "login", "ip": "1.1.1.1"}), "sshoney")
        self.assertEqual(detect_source({"rule": "ssh_bruteforce"}), "logwatch")
        self.assertEqual(detect_source({"rule": "account_bruteforce"}), "loginguard")
        self.assertEqual(detect_source({"open_ports": []}), "netscan")

    def test_normalization(self):
        e = parse_record({"event": "login", "ts": 100, "ip": "9.9.9.9",
                          "username": "root", "password": "x", "success": False}, "sshoney")
        self.assertEqual((e.source, e.type, e.ip), ("sshoney", "honeypot_hit", "9.9.9.9"))

    def test_load_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.jsonl")
            with open(p, "w") as f:
                f.write('{"event":"login","ts":1,"ip":"1.2.3.4","username":"a","password":"b","success":false}\n')
                f.write('\n')  # linha vazia ignorada
                f.write('{"event":"command","ts":2,"ip":"1.2.3.4","username":"a","command":"wget x"}\n')
            events = load_jsonl(p)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[1].type, "malware_download")


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.incidents = Correlator().run(demo_events())
        self.rules = {i.rule for i in self.incidents}

    def test_honeypot_then_real_login_detected(self):
        self.assertIn("honeypot_then_real_login", self.rules)
        inc = next(i for i in self.incidents if i.rule == "honeypot_then_real_login")
        self.assertEqual(inc.severity, "critical")
        # o incidente cruza ao menos duas fontes
        self.assertGreaterEqual(len({e.source for e in inc.events}), 2)

    def test_expected_rules_fire(self):
        for r in ("bruteforce_then_success", "distributed_bruteforce",
                  "malware_on_honeypot", "repeat_offender"):
            self.assertIn(r, self.rules)

    def test_clean_events_produce_no_incident(self):
        # só eventos benignos e isolados
        events = [Event(ts=1, source="netscan", type="port_scan", ip="10.0.0.1"),
                  Event(ts=2, source="logwatch", type="generic", ip="10.0.0.2")]
        self.assertEqual(Correlator().run(events), [])


class OutputTests(unittest.TestCase):
    def test_html_renders_and_escapes(self):
        events = demo_events()
        events.append(Event(ts=1, source="logwatch", type="web_attack", ip="1.1.1.1",
                            message="<script>alert(1)</script>"))
        payload = build_payload(Correlator().run(events), events)
        doc = render_html(payload)
        self.assertIn("CorrelAI", doc)
        self.assertNotIn("<script>alert(1)", doc)


if __name__ == "__main__":
    unittest.main()
