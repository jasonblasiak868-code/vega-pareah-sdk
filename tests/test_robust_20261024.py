"""Regression tests (2026-10-24): an adapter that returned something that is not text or bytes raised a raw CapsuleError AFTER it had run, with no denial recorded; with an airlock
fitted, an end that was not an End object raised a raw AttributeError before any check."""
import pathlib
import tempfile
import unittest

from vega_custody.capsule import capsule as cap
from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_jacket import humanauth
from vega_jacket.commit.commit import Commit
from vega_jacket.humanauth import human_signer
from vega_pareah.adapter import adapter_card, airlock, pareah
from vega_pareah.cards import pre as pre_mod

PW, DEV, SURF = "correct horse battery", "dev-r", "surf-r"


class Rig:
    def __init__(self):
        self.blob, pub = human_signer.generate(PW)
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.led = Ledger([LocalBackend(t / "led.jsonl")])
        self.commit = Commit(humanauth.Verifier(pub, DEV, SURF), self.led, self.dag)
        self.card = adapter_card.mint_adapter_card("echo", "tool", ["echo"], "ab" * 32, "permissive", "https://example/echo")
        self.pre = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["echo", "/work/"], 300)

    def hug(self, x, y):
        u = pareah.union_hash(self.card, x, y, self.pre)
        return human_signer.sign(self.blob, PW, DEV, SURF, pareah.UNION_ACTION, {"union": u, "adapter": self.card["card_hash"], "pre": self.pre["card_hash"]}, 300)


class Robust(unittest.TestCase):
    def test_a_non_text_adapter_answer_is_a_recorded_denial(self):
        r = Rig()
        pa = pareah.Pareah(r.commit, r.led, r.dag)
        for ret in (None, 5, {"a": 1}, object()):
            x, y = pareah.End("rx"), pareah.End("ry")
            conn = pa.connect(r.card, r.pre, x, y, r.hug(x, y), lambda p, ret=ret: ret)
            before = sum(1 for e in r.dag.content.entries() if e["kind"] == "PAREAH_DENIED")
            with self.assertRaises(pareah.PareahRefused):
                conn.call(cap.make("hi", {"action": "echo", "resource": "echo"}))
            self.assertEqual(sum(1 for e in r.dag.content.entries() if e["kind"] == "PAREAH_DENIED"), before + 1)

    def test_with_an_airlock_fitted_odd_ends_are_refused_cleanly(self):
        r = Rig()
        pa2 = pareah.Pareah(r.commit, r.led, r.dag, airlock=airlock.Airlock(r.commit, r.led, r.dag, "door-r"))
        for ends in ((None, None), ("a", "b"), (pareah.End("only-one"), None)):
            with self.assertRaises(pareah.PareahRefused):
                pa2.connect(r.card, r.pre, ends[0], ends[1], None, len, {})


if __name__ == "__main__":
    unittest.main()
