"""Regression test (2026-10-20): the airlock matched an arrival against the owner's announcement and burned the announcement as two separate steps, so two arrivals from the
announced key, in parallel, were both EXPECTED on one single-use announcement."""
import pathlib
import tempfile
import threading
import time
import unittest

from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_jacket import humanauth
from vega_jacket.commit.commit import Commit
from vega_jacket.humanauth import human_signer
from vega_custody.capsule import capsule as cap
from vega_pareah.adapter import adapter_card, airlock as AL, pareah
from vega_pareah.cards import pre as pre_mod

PW, DEV, SURF = "correct horse battery", "dev-t", "surf-t"


class OneAnnouncementOneAdmission(unittest.TestCase):
    def build(self):
        blob, pub = human_signer.generate(PW)
        t = pathlib.Path(tempfile.mkdtemp())
        dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        led = Ledger([LocalBackend(t / "led.jsonl")])
        commit = Commit(humanauth.Verifier(pub, DEV, SURF), led, dag)
        door = AL.Airlock(commit, led, dag, "door-1")
        visitor = pareah.End("agent-side")
        signed = human_signer.sign(blob, PW, DEV, SURF, AL.ANNOUNCE_ACTION, {"expect_public": visitor.public.hex(), "card_hash": "", "not_before": 0}, 300)
        door.announce(visitor.public.hex(), signed)
        return door, visitor, dag

    def test_two_parallel_arrivals_from_the_announced_key_are_not_both_admitted(self):
        for _ in range(4):
            door, visitor, dag = self.build()
            inner = dag.record

            class Slow:
                def __getattr__(self, k):
                    return getattr(dag, k)

                def record(self, kind, payload, parents=None):
                    time.sleep(0.05)
                    return inner(kind, payload, parents)
            door.dag = Slow()
            arrivals = [AL.make_arrival(visitor, "door-1", door.challenge()) for _ in range(2)]
            gate, out, lock = threading.Barrier(2), [], threading.Lock()

            def go(a):
                gate.wait()
                r = door.admit(a)["status"]
                with lock:
                    out.append(r)
            ts = [threading.Thread(target=go, args=(a,)) for a in arrivals]
            for t in ts:
                t.start()
            for t in ts:
                t.join(30)
            self.assertEqual(sorted(out), ["EXPECTED", "TRAPPED"], out)
            used = [e for e in dag.content.entries() if e["kind"] == "AIRLOCK_EXPECTED_USED"]
            self.assertEqual(len(used), 1)


class RevokedPreStopsWorking(unittest.TestCase):
    """PreDeck.revoke() existed, but the connection and its gates never asked a deck, so a revoked PRE kept working."""

    def build(self, deck):
        blob, pub = human_signer.generate(PW)
        t = pathlib.Path(tempfile.mkdtemp())
        dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        led = Ledger([LocalBackend(t / "led.jsonl")])
        commit = Commit(humanauth.Verifier(pub, DEV, SURF), led, dag)
        pa = pareah.Pareah(commit, led, dag, pre_deck=deck)
        card = adapter_card.mint_adapter_card("echo", "tool", ["echo"], "ab" * 32, "permissive", "https://example/echo")
        pre = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["echo", "/work/"], 300)
        a, b = pareah.End("agent-side"), pareah.End("adapter-side")
        u = pareah.union_hash(card, a, b, pre)
        signed = human_signer.sign(blob, PW, DEV, SURF, pareah.UNION_ACTION, {"union": u, "adapter": card["card_hash"], "pre": pre["card_hash"]}, 300)
        return pa, card, pre, a, b, signed

    def test_revoking_the_pre_stops_an_open_connection(self):
        deck = pre_mod.PreDeck()
        pa, card, pre, a, b, signed = self.build(deck)
        deck.add(pre)
        conn = pa.connect(card, pre, a, b, signed, lambda p: "echo:%s" % p)
        req = lambda: cap.make("hi", {"action": "echo", "resource": "echo"})
        self.assertEqual(cap.data_of(conn.call(req())), "echo:hi")
        deck.revoke(pre["card_hash"])
        with self.assertRaises(pareah.PareahRefused) as cm:
            conn.call(req())
        self.assertIn("revoked", str(cm.exception))

    def test_a_revoked_pre_cannot_open_a_new_connection(self):
        deck = pre_mod.PreDeck()
        pa, card, pre, a, b, signed = self.build(deck)
        deck.add(pre)
        deck.revoke(pre["card_hash"])
        with self.assertRaises(pareah.PareahRefused) as cm:
            pa.connect(card, pre, a, b, signed, lambda p: p)
        self.assertIn("revoked", str(cm.exception))

    def test_without_a_deck_nothing_changes(self):
        pa, card, pre, a, b, signed = self.build(None)
        conn = pa.connect(card, pre, a, b, signed, lambda p: "echo:%s" % p)
        self.assertEqual(cap.data_of(conn.call(cap.make("hi", {"action": "echo", "resource": "echo"}))), "echo:hi")


class AnnouncementIsMatchableOnlyOnceRecorded(unittest.TestCase):
    def test_an_announcement_that_cannot_be_recorded_is_not_left_matchable(self):
        from vega_custody.dag.dag import RecordRefused
        blob, pub = human_signer.generate(PW)
        t = pathlib.Path(tempfile.mkdtemp())
        dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        led = Ledger([LocalBackend(t / "led.jsonl")])
        commit = Commit(humanauth.Verifier(pub, DEV, SURF), led, dag)
        door = AL.Airlock(commit, led, dag, "door-1")
        visitor = pareah.End("agent-side")
        signed = human_signer.sign(blob, PW, DEV, SURF, AL.ANNOUNCE_ACTION, {"expect_public": visitor.public.hex(), "card_hash": "", "not_before": 0}, 300)

        class Broken:
            def record(self, kind, payload, parents=None):
                raise RecordRefused("disk full")

            def __getattr__(self, k):
                return getattr(dag, k)
        door.dag = Broken()
        with self.assertRaises(Exception):
            door.announce(visitor.public.hex(), signed)
        self.assertEqual(door._ann, {})


if __name__ == "__main__":
    unittest.main()
