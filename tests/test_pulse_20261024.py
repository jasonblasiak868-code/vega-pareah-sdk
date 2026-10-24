"""Heartbeat and probe: a pulse the adapter cannot fake, silence as an alarm, and gates tested from outside."""
import copy
import pathlib
import tempfile
import time
import unittest

from vega_custody.capsule import capsule as cap
from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_jacket import humanauth
from vega_jacket.commit.commit import Commit
from vega_jacket.humanauth import human_signer
from vega_pareah.adapter import adapter_card, pareah, pulse
from vega_pareah.cards import pre as pre_mod

PW, DEV, SURF = "correct horse battery", "dev-pu", "surf-pu"


class Rig:
    def __init__(self, **wkw):
        self.blob, pub = human_signer.generate(PW)
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.pdag = Dag([t / "pc.jsonl"], [t / "pl.jsonl"])
        self.led = Ledger([LocalBackend(t / "led.jsonl")])
        self.commit = Commit(humanauth.Verifier(pub, DEV, SURF), self.led, self.dag)
        self.card = adapter_card.mint_adapter_card("echo", "tool", ["echo"], "ab" * 32, "permissive", "https://example/echo")
        self.pre = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["echo"], 300)
        self.a, self.b = pareah.End("a"), pareah.End("b")
        params = {"union": pareah.union_hash(self.card, self.a, self.b, self.pre), "adapter": self.card["card_hash"], "pre": self.pre["card_hash"]}
        signed = human_signer.sign(self.blob, PW, DEV, SURF, pareah.UNION_ACTION, params, 300)
        self.conn = pareah.Pareah(self.commit, self.led, self.dag).connect(self.card, self.pre, self.a, self.b, signed, lambda p: p)
        self.now = {"t": time.time()}
        self.alarms = []
        self.w = pulse.Watcher(self.dag, self.pdag, clock=lambda: self.now["t"], on_alarm=lambda *x: self.alarms.append(x), **wkw)
        self.resp = pulse.Responder(self.b, self.card["card_hash"], self.conn, clock=lambda: self.now["t"])
        self.w.add("echo", self.card["card_hash"], self.b.public, self.resp.respond)

    def kinds(self, d):
        return [e["kind"] for e in d.content.entries()]


class Pulse(unittest.TestCase):
    def test_a_good_answer_passes_and_goes_to_the_pulse_chain_not_the_main_chain(self):
        r = Rig()
        before = len(r.dag.content.entries())
        self.assertEqual(r.w.pulse("echo"), {"ok": True, "reason": "ok"})
        self.assertEqual(r.kinds(r.pdag), ["PAREAH_PULSE"])
        self.assertEqual(len(r.dag.content.entries()), before)

    def test_an_old_answer_replayed_for_a_new_challenge_fails(self):
        r = Rig()
        seen = []

        def record_then_replay(ch):
            seen.append(r.resp.respond(ch))
            return seen[0]
        r.w._watched["echo"]["responder"] = record_then_replay
        self.assertTrue(r.w.pulse("echo")["ok"])
        self.assertFalse(r.w.pulse("echo")["ok"])                                   # same answer, new challenge
        self.assertIn("PAREAH_PULSE_FAILED", r.kinds(r.dag))
        self.assertTrue(r.alarms)

    def test_an_answer_signed_by_another_key_fails(self):
        r = Rig()
        impostor = pulse.Responder(pareah.End("b"), r.card["card_hash"], r.conn, clock=lambda: r.now["t"])
        r.w._watched["echo"]["responder"] = impostor.respond
        out = r.w.pulse("echo")
        self.assertFalse(out["ok"])
        self.assertIn("signature", out["reason"])

    def test_a_stale_timestamp_fails(self):
        r = Rig()
        old = pulse.Responder(r.b, r.card["card_hash"], r.conn, clock=lambda: r.now["t"] - 600)
        r.w._watched["echo"]["responder"] = old.respond
        self.assertIn("fresh", r.w.pulse("echo")["reason"])

    def test_a_link_that_reports_itself_closed_fails(self):
        r = Rig()
        r.conn.close("test")
        out = r.w.pulse("echo")
        self.assertFalse(out["ok"])
        self.assertIn("closed", out["reason"])

    def test_malformed_crashing_and_missing_answers_fail_without_raising(self):
        r = Rig()
        for fn in (lambda ch: None, lambda ch: {"challenge": ch}, lambda ch: 1 / 0, lambda ch: {"challenge": ch, "ts": "x", "state": {}, "sig": "00"}):
            r.w._watched["echo"]["responder"] = fn
            self.assertFalse(r.w.pulse("echo")["ok"])

    def test_silence_is_an_alarm_recorded_once_per_episode_and_a_good_pulse_ends_it(self):
        r = Rig(max_silence=60)
        self.assertEqual(r.w.check_silence(), [])
        r.now["t"] += 61
        self.assertEqual(r.w.check_silence(), ["echo"])
        r.w.check_silence()
        self.assertEqual(r.kinds(r.dag).count("PAREAH_PULSE_SILENT"), 1)
        self.assertTrue(r.w.pulse("echo")["ok"])
        r.now["t"] += 30
        self.assertEqual(r.w.check_silence(), [])

    def test_the_main_chain_gets_a_summary_every_n_pulses(self):
        r = Rig(summary_every=3)
        for _ in range(7):
            r.w.pulse("echo")
        self.assertEqual(r.kinds(r.dag).count("PAREAH_PULSE_SUMMARY"), 2)
        self.assertEqual(r.kinds(r.pdag).count("PAREAH_PULSE"), 7)

    def test_a_broken_alarm_handler_does_not_stop_the_watcher(self):
        r = Rig()
        r.w.on_alarm = lambda *a: 1 / 0
        r.w._watched["echo"]["responder"] = lambda ch: None
        self.assertFalse(r.w.pulse("echo")["ok"])
        self.assertIn("PAREAH_PULSE_FAILED", r.kinds(r.dag))


class Probe(unittest.TestCase):
    def test_a_working_gate_passes_the_good_probe_and_refuses_every_bad_one(self):
        r = Rig()
        out = pulse.probe_connection(r.conn, ("echo", "echo"))
        self.assertTrue(out["passed"], out)
        self.assertEqual([x["got"] for x in out["results"]], ["pass", "refuse", "refuse", "refuse"])
        self.assertIn("PAREAH_PROBE", r.kinds(r.dag))

    def test_the_probe_writes_no_denials_and_never_reaches_the_adapter(self):
        r = Rig()
        called = []
        r.conn._fn = lambda p: called.append(p) or p
        pulse.probe_connection(r.conn, ("echo", "echo"))
        self.assertEqual(called, [])
        self.assertNotIn("PAREAH_DENIED", r.kinds(r.dag))
        self.assertFalse(r.conn.closed)

    def test_a_broken_gate_is_reported_and_recorded(self):
        r = Rig()
        broken = copy.copy(r.conn)
        broken.pre = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["/"], 300)             # a scope that lets the "outside" probe in
        out = pulse.probe_connection(broken, ("echo", "/x"))
        self.assertFalse(out["passed"])
        self.assertIn("outside the PRE's scope", [x["probe"] for x in out["results"] if x["expected"] != x["got"]])

    def test_a_good_probe_that_is_refused_is_also_a_failure(self):
        r = Rig()
        out = pulse.probe_connection(r.conn, ("echo", "/not-in-scope"))
        self.assertFalse(out["passed"])
        self.assertEqual(out["results"][0]["got"], "refuse")


if __name__ == "__main__":
    unittest.main()
