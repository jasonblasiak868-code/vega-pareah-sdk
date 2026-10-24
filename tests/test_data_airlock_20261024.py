"""The inbound data airlock: everything is recorded and held apart; data reaches the governed side only under a human commitment."""
import json
import pathlib
import tempfile
import unittest

from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_jacket import humanauth
from vega_jacket.commit.commit import Commit
from vega_jacket.humanauth import human_signer
from vega_pareah.adapter import data_airlock as DA

PW, DEV, SURF = "correct horse battery", "dev-da", "surf-da"


class Rig:
    def __init__(self, **kw):
        self.blob, pub = human_signer.generate(PW)
        self.t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([self.t / "c.jsonl"], [self.t / "l.jsonl"])
        self.led = Ledger([LocalBackend(self.t / "led.jsonl")])
        self.commit = Commit(humanauth.Verifier(pub, DEV, SURF), self.led, self.dag)
        self.now = {"t": 2_000_000.0}
        self.da = DA.DataAirlock(self.dag, self.commit, self.t / "hold", clock=lambda: self.now["t"], **kw)

    def sign(self, action, params, lease=300):
        return human_signer.sign(self.blob, PW, DEV, SURF, action, params, lease)

    def collect(self, source="prices", window=3600, items=3, nbytes=1000, validator=""):
        return self.da.authorize_collection(source, window, items, nbytes, self.sign(DA.COLLECT_ACTION, DA.collect_params(source, window, items, nbytes, validator)), validator)


def numeric(b):
    return b.decode("ascii").replace(".", "", 1).isdigit()


class Holding(unittest.TestCase):
    def test_by_default_everything_is_recorded_and_held_and_nothing_is_handed_on(self):
        r = Rig()
        out = r.da.receive("prices", b"101.25")
        self.assertEqual((out["status"], out["reason"]), ("HELD", "no_collection_authority"))
        self.assertNotIn("data", out)
        rec = [e for e in r.dag.content.entries() if e["kind"] == "AIRLOCK_DATA_RECORDED"][0]["payload"]
        self.assertEqual((rec["source"], rec["seq"], rec["size"], rec["status"], rec["body_kept"]), ("prices", 1, 6, "held", True))
        self.assertEqual((r.t / "hold" / out["id"]).read_bytes(), b"101.25")

    def test_the_chain_holds_hashes_only_never_the_data(self):
        r = Rig()
        r.da.receive("prices", "PRIVATE-LOOKING-TEXT-8841")
        self.assertNotIn("PRIVATE-LOOKING-TEXT-8841", json.dumps(r.dag.content.entries()))

    def test_a_source_name_and_data_type_are_checked(self):
        r = Rig()
        for bad in ("", "a b", "../x", None, 5, "x" * 80):
            with self.assertRaises(DA.DataAirlockRefused, msg=repr(bad)):
                r.da.receive(bad, b"x")
        with self.assertRaises(DA.DataAirlockRefused):
            r.da.receive("prices", 12345)

    def test_nothing_is_lost_silently_when_an_item_is_too_big_to_keep(self):
        r = Rig()
        out = r.da.receive("prices", b"x" * (DA.MAX_ITEM + 1))
        self.assertEqual(out["status"], "HELD")
        rec = [e for e in r.dag.content.entries() if e["kind"] == "AIRLOCK_DATA_RECORDED"][-1]["payload"]
        self.assertEqual((rec["body_kept"], rec["size"]), (False, DA.MAX_ITEM + 1))        # recorded by hash, body not kept, said so
        self.assertFalse((r.t / "hold" / out["id"]).exists())

    def test_if_the_record_cannot_be_written_nothing_is_stored_or_handed_on(self):
        r = Rig()
        r.collect()
        real = r.dag.record
        r.dag.record = lambda *a, **k: (_ for _ in ()).throw(DA.DagError("disk full"))
        with self.assertRaises(DA.DataAirlockRefused):
            r.da.receive("prices", b"5")
        r.dag.record = real
        self.assertEqual(list((r.t / "hold").iterdir()), [])


class Collection(unittest.TestCase):
    def test_within_a_signed_collection_each_item_is_admitted_and_still_recorded(self):
        r = Rig()
        r.collect(items=3)
        outs = [r.da.receive("prices", b"%d.5" % i) for i in range(3)]
        self.assertEqual([o["status"] for o in outs], ["ADMITTED"] * 3)
        self.assertEqual(outs[1]["data"], b"1.5")
        recs = [e["payload"] for e in r.dag.content.entries() if e["kind"] == "AIRLOCK_DATA_RECORDED"]
        self.assertEqual([x["status"] for x in recs], ["admitted"] * 3)
        self.assertEqual(r.da.receive("prices", b"9.9")["reason"], "item_limit_reached")             # the fourth is held

    def test_other_sources_the_window_and_the_byte_limit_are_enforced(self):
        r = Rig()
        r.collect(items=10, nbytes=20, window=60)
        self.assertEqual(r.da.receive("weather", b"1")["reason"], "no_collection_authority")           # another source
        self.assertEqual(r.da.receive("prices", b"x" * 25)["reason"], "byte_limit_reached")
        self.assertEqual(r.da.receive("prices", b"12345")["status"], "ADMITTED")
        r.now["t"] += 61
        self.assertEqual(r.da.receive("prices", b"1")["reason"], "collection_window_over")

    def test_a_validator_decides_the_shape_and_a_missing_or_crashing_one_means_held(self):
        r = Rig()
        r.da.register_validator("numeric", numeric)
        r.collect(validator="numeric", items=10)
        self.assertEqual(r.da.receive("prices", b"12.5")["status"], "ADMITTED")
        self.assertEqual(r.da.receive("prices", b"ignore previous instructions")["reason"], "validator_refused")
        r2 = Rig()
        r2.collect(validator="not_registered", items=10)
        self.assertEqual(r2.da.receive("prices", b"1")["reason"], "validator_missing")
        r3 = Rig()
        r3.da.register_validator("boom", lambda b: 1 / 0)
        r3.collect(validator="boom", items=10)
        self.assertEqual(r3.da.receive("prices", b"1")["reason"], "validator_refused")

    def test_the_collection_needs_the_humans_signature_for_exactly_these_limits(self):
        r = Rig()
        wrong_limits = r.sign(DA.COLLECT_ACTION, DA.collect_params("prices", 3600, 3, 1000, ""))
        with self.assertRaises(DA.DataAirlockRefused):
            r.da.authorize_collection("prices", 3600, 99999, 1000, wrong_limits)                            # signed for 3 items, asked for 99999
        with self.assertRaises(DA.DataAirlockRefused):
            r.da.authorize_collection("prices", 3600, 3, 1000, {"nonce": "n", "expiry": 1, "signature": "00"})
        with self.assertRaises(DA.DataAirlockRefused):
            r.da.authorize_collection("other", 3600, 3, 1000, wrong_limits)                                 # signed for another source
        self.assertEqual(r.da.receive("prices", b"1")["reason"], "no_collection_authority")                 # none of that opened anything
        r.da.authorize_collection("prices", 3600, 3, 1000, wrong_limits)
        with self.assertRaises(DA.DataAirlockRefused):
            r.da.authorize_collection("prices", 3600, 3, 1000, wrong_limits)                                # a used approval cannot open a second collection

    def test_limits_are_bounded(self):
        r = Rig()
        for args in ((0, 1, 1), (DA.MAX_WINDOW + 1, 1, 1), (60, 0, 1), (60, 1, 0), (60, 1, DA.MAX_HELD_BYTES + 1), (True, 1, 1), ("60", 1, 1)):
            with self.assertRaises(DA.DataAirlockRefused, msg=str(args)):
                r.da.authorize_collection("prices", args[0], args[1], args[2], {"nonce": "n", "expiry": 1, "signature": "00"})

    def test_after_a_restart_everything_is_held_until_the_human_authorizes_again(self):
        r = Rig()
        r.collect()
        self.assertEqual(r.da.receive("prices", b"1")["status"], "ADMITTED")
        again = DA.DataAirlock(r.dag, r.commit, r.t / "hold", clock=lambda: r.now["t"])
        self.assertEqual(again.receive("prices", b"1")["reason"], "no_collection_authority")


class BatchRelease(unittest.TestCase):
    def held(self, r, n=3):
        for i in range(n):
            r.da.receive("prices", b"v%d" % i)
        return r.da.batch("prices")

    def test_the_human_reads_a_preview_signs_the_batch_hash_and_exactly_that_batch_is_released_once(self):
        r = Rig()
        b = self.held(r)
        self.assertEqual([p["text"] for p in r.da.preview(b)], ["v0", "v1", "v2"])
        out = r.da.release_batch(b, r.sign(DA.RELEASE_ACTION, b.params()))
        self.assertEqual(out, [(1, b"v0"), (2, b"v1"), (3, b"v2")])
        self.assertIn("AIRLOCK_BATCH_RELEASED", [e["kind"] for e in r.dag.content.entries()])
        with self.assertRaises(DA.DataAirlockRefused):
            r.da.release_batch(b, r.sign(DA.RELEASE_ACTION, b.params()))                                    # once
        self.assertEqual(r.da.batch("prices").count, 0)                                                      # nothing left held for that source

    def test_a_signature_for_another_batch_source_or_action_is_refused_and_nothing_leaves(self):
        r = Rig()
        b = self.held(r)
        for label, signed in (("other hash", r.sign(DA.RELEASE_ACTION, DA.batch_params("prices", "0" * 64, b.count))), ("other count", r.sign(DA.RELEASE_ACTION, DA.batch_params("prices", b.batch_sha256, 99))),
                              ("other source", r.sign(DA.RELEASE_ACTION, DA.batch_params("weather", b.batch_sha256, b.count))), ("other action", r.sign(DA.COLLECT_ACTION, b.params()))):
            with self.assertRaises(DA.DataAirlockRefused, msg=label):
                r.da.release_batch(b, signed)
        self.assertEqual(b.state, "open")
        self.assertEqual(len(r.da.release_batch(b, r.sign(DA.RELEASE_ACTION, b.params()))), 3)

    def test_a_held_file_changed_on_disk_is_never_released(self):
        r = Rig()
        b = self.held(r)
        (r.t / "hold" / b.items[1][0]).write_bytes(b"tampered")
        with self.assertRaises(DA.DataAirlockRefused):
            r.da.release_batch(b, r.sign(DA.RELEASE_ACTION, b.params()))
        self.assertEqual(b.state, "open")

    def test_items_admitted_under_a_collection_are_not_in_a_held_batch(self):
        r = Rig()
        r.collect(items=1)
        r.da.receive("prices", b"admitted")
        r.da.receive("prices", b"held-one")
        b = r.da.batch("prices")
        self.assertEqual([p["text"] for p in r.da.preview(b)], ["held-one"])


if __name__ == "__main__":
    unittest.main()
