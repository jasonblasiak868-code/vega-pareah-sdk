"""The link is torn down for real at expiry or revocation: adapter function dropped, closing recorded once, later calls refused."""
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
from vega_pareah.adapter import adapter_card, pareah
from vega_pareah.cards import pre as pre_mod

PW, DEV, SURF = "correct horse battery", "dev-lc", "surf-lc"


class Rig:
    def __init__(self, deck=None, clock=time.time, who="agent"):
        self.blob, pub = human_signer.generate(PW)
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.led = Ledger([LocalBackend(t / "led.jsonl")])
        self.commit = Commit(humanauth.Verifier(pub, DEV, SURF), self.led, self.dag)
        self.card = adapter_card.mint_adapter_card("echo", "tool", ["echo"], "ab" * 32, "permissive", "https://example/echo")
        self.pre = pre_mod.mint_pre(who, ["connect_adapter", "echo"], ["echo"], 300, now=clock())
        self.deck = deck
        if deck is not None:
            deck.add(self.pre)
        self.pa = pareah.Pareah(self.commit, self.led, self.dag, clock=clock, pre_deck=deck)

    def connect(self, lease):
        a, b = pareah.End("a"), pareah.End("b")
        params = {"union": pareah.union_hash(self.card, a, b, self.pre), "adapter": self.card["card_hash"], "pre": self.pre["card_hash"]}
        signed = human_signer.sign(self.blob, PW, DEV, SURF, pareah.UNION_ACTION, params, lease)
        return self.pa.connect(self.card, self.pre, a, b, signed, lambda p: "echo:%s" % p)

    def closings(self):
        return [e for e in self.dag.content.entries() if e["kind"] == "PAREAH_LINK_CLOSED"]


def req():
    return cap.make("hi", {"action": "echo", "resource": "echo"})


class LinkClose(unittest.TestCase):
    def test_at_expiry_the_link_closes_by_itself_without_another_call(self):
        r = Rig()
        conn = r.connect(2)
        self.assertEqual(cap.data_of(conn.call(req())), "echo:hi")
        deadline = time.time() + 12
        while not conn.closed and time.time() < deadline:
            time.sleep(0.1)
        self.assertTrue(conn.closed)
        self.assertIsNone(conn._fn)                                                  # the adapter function is gone, not merely not called
        self.assertEqual(len(r.closings()), 1)
        self.assertIn("expired", r.closings()[0]["payload"]["reason"])
        with self.assertRaises(pareah.PareahRefused):
            conn.call(req())
        self.assertEqual(len(r.closings()), 1)                                      # still once

    def test_a_call_after_expiry_also_closes_it_once(self):
        now = {"t": 3_000_000.0}
        r = Rig(clock=lambda: now["t"])
        conn = r.connect(300)
        now["t"] = float(conn.commitment["expiry"]) + 1
        for _ in range(3):
            with self.assertRaises(pareah.PareahRefused):
                conn.call(req())
        self.assertEqual(len(r.closings()), 1)
        self.assertTrue(conn.closed and conn._fn is None)

    def test_revoking_the_pre_closes_the_open_link_at_once(self):
        r = Rig(deck=pre_mod.PreDeck())
        conn = r.connect(300)
        self.assertEqual(cap.data_of(conn.call(req())), "echo:hi")
        r.deck.revoke(self.pre_hash(r))
        self.assertTrue(conn.closed)                                                 # closed by the revocation itself, with no call needed
        self.assertIsNone(conn._fn)
        self.assertEqual(len(r.closings()), 1)
        self.assertIn("revoked", r.closings()[0]["payload"]["reason"])
        with self.assertRaises(pareah.PareahRefused):
            conn.call(req())

    @staticmethod
    def pre_hash(r):
        return r.pre["card_hash"]

    def test_the_owner_can_close_it_and_closing_twice_records_once(self):
        r = Rig()
        conn = r.connect(300)
        conn.close("done")
        conn.close("again")
        self.assertEqual([c["payload"]["reason"] for c in r.closings()], ["done"])
        with self.assertRaises(pareah.PareahRefused):
            conn.call(req())

    def test_revoking_one_pre_leaves_another_link_open(self):
        r = Rig(deck=pre_mod.PreDeck())
        other = Rig(deck=r.deck, who="agent-two")
        c1, c2 = r.connect(300), other.connect(300)
        r.deck.revoke(r.pre["card_hash"])
        self.assertTrue(c1.closed)
        self.assertFalse(c2.closed)
        self.assertEqual(cap.data_of(c2.call(req())), "echo:hi")


if __name__ == "__main__":
    unittest.main()
