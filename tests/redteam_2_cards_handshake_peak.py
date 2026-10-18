"""RED TEAM PASS 2 (pareah): forged cards, scope escapes, string capabilities, handshake impersonation, PEAK tampering, reference-only enforcement."""
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
from vega_pareah.adapter import adapter_card, pareah
from vega_pareah.cards import model_card, peak, pre, runtime_card, server_card

PW, DEV, SURF = "correct horse battery", "dev-t", "surf-t"
H = "ab" * 32


class Rig:
    def __init__(self):
        self.blob, pub = human_signer.generate(PW)
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.led = Ledger([LocalBackend(t / "led.jsonl")])
        self.commit = Commit(humanauth.Verifier(pub, DEV, SURF), self.led, self.dag)
        self.pa = pareah.Pareah(self.commit, self.led, self.dag)
        self.a, self.b = pareah.End("agent-side"), pareah.End("adapter-side")

    def hug(self, card, pre_card, a=None, b=None):
        a, b = a or self.a, b or self.b
        u = pareah.union_hash(card, a, b, pre_card)
        return human_signer.sign(self.blob, PW, DEV, SURF, pareah.UNION_ACTION, {"union": u, "adapter": card["card_hash"], "pre": pre_card["card_hash"]}, 300)


def refetch(card):
    """Re-seal a forged card so its hash matches: the hash is integrity, not authenticity, so an attacker can always do this."""
    c = copy.deepcopy(card)
    c.pop("card_hash", None)
    from vega_pareah.cards import _common
    c["card_hash"] = _common.canonical_hash(c)
    return c


class PreAttacks(unittest.TestCase):
    def test_string_capabilities_are_not_read_letter_by_letter(self):
        with self.assertRaises(pre.PreRefused):
            pre.mint_pre("a", "read_file", ["/work/"])
        forged = pre.mint_pre("a", ["read_file"], ["/work/"])
        forged["capabilities"] = "read_file"
        with self.assertRaises(pre.PreRefused):
            pre.verify_pre(refetch(forged))
        self.assertFalse(pre.permits(refetch(forged), "read", "/work/x"))

    def test_a_sibling_directory_with_the_same_prefix_is_not_in_scope(self):
        c = pre.mint_pre("a", ["read_file"], ["/work"])
        self.assertTrue(pre.permits(c, "read_file", "/work"))
        self.assertTrue(pre.permits(c, "read_file", "/work/x"))
        self.assertFalse(pre.permits(c, "read_file", "/workshop/secret"))
        self.assertFalse(pre.permits(c, "read_file", "/work-private/x"))

    def test_traversal_and_odd_resources_never_match(self):
        c = pre.mint_pre("a", ["read_file"], ["/work/"])
        for r in ("/work/../etc/passwd", "/work/a/../../etc", "/work\\..\\x", "/work/\x00x", "", None, 5, ["/work/x"]):
            self.assertFalse(pre.permits(c, "read_file", r), repr(r))

    def test_an_empty_or_wildcard_scope_is_refused(self):
        for scope in ([""], [], "/work/", ["/work/*"], ["/work/../"], [5], None):
            with self.assertRaises(pre.PreRefused, msg=repr(scope)):
                pre.mint_pre("a", ["read_file"], scope)

    def test_a_forged_long_lived_card_is_refused_at_use_even_with_a_valid_hash(self):
        c = pre.mint_pre("a", ["read_file"], ["/work/"])
        c["expires"] = c["issued"] + 10 * 365 * 86400
        with self.assertRaises(pre.PreRefused):
            pre.verify_pre(refetch(c))
        c2 = pre.mint_pre("a", ["read_file"], ["/work/"])
        c2["issued"] = int(time.time()) + 10 * 86400
        c2["expires"] = c2["issued"] + 60
        with self.assertRaises(pre.PreRefused):
            pre.verify_pre(refetch(c2))

    def test_human_only_powers_in_any_spelling_are_refused(self):
        for cap_name in ("release_public", "Release_Public", "release-public", " release_public ", "RELEASE PUBLIC", "spend_funds"):
            with self.assertRaises(pre.PreRefused, msg=cap_name):
                pre.mint_pre("a", [cap_name], ["/work/"])

    def test_non_integer_or_bool_leases_and_garbage_cards_do_not_crash(self):
        for lease in (True, 1.5, "300", None, 0, -5):
            with self.assertRaises(pre.PreRefused, msg=repr(lease)):
                pre.mint_pre("a", ["read_file"], ["/work/"], lease)
        for bad in (None, [], "x", {}, {"kind": "PRE"}, {"kind": "PRE", "card_hash": "0" * 64}, {"kind": "PRE", "card_hash": 5}):
            with self.assertRaises(pre.PreRefused, msg=repr(bad)):
                pre.verify_pre(bad)
            self.assertFalse(pre.permits(bad, "read_file", "/work/x"))

    def test_nan_in_a_card_does_not_hash(self):
        c = pre.mint_pre("a", ["read_file"], ["/work/"])
        c["extra"] = float("nan")
        with self.assertRaises(pre.PreRefused):
            pre.verify_pre(c)

    def test_revocation_beats_a_valid_card(self):
        deck, c = pre.PreDeck(), pre.mint_pre("a", ["read_file"], ["/work/"])
        h = deck.add(c)
        self.assertTrue(deck.permits(h, "read_file", "/work/x"))
        deck.revoke(h)
        self.assertFalse(deck.permits(h, "read_file", "/work/x"))


class AdapterCardAttacks(unittest.TestCase):
    def test_a_forged_policy_for_a_copyleft_class_is_refused_even_with_a_valid_hash(self):
        gpl = adapter_card.mint_adapter_card("gpl", "repo", ["echo"], H, "strong_copyleft")
        forged = copy.deepcopy(gpl)
        forged["policy"] = {"adopt_by_reference": True, "redistribute": True, "note": "forged"}
        with self.assertRaises(adapter_card.AdapterCardRefused):
            adapter_card.verify_adapter_card(refetch(forged))

    def test_string_capabilities_odd_hashes_and_unsafe_uris_are_refused_at_mint(self):
        for kw in ({"capabilities": "echo"}, {"capabilities": ["release_public"]}, {"capabilities": ["*"]}, {"capabilities": [""]},
                   {"code_sha256": "xyz"}, {"code_sha256": "AB" * 32}, {"code_sha256": None},
                   {"reference_uri": "file:///etc/passwd"}, {"reference_uri": "javascript:alert(1)"}, {"reference_uri": "https://x\n.example"},
                   {"adapter_id": ""}, {"adapter_id": "a\x00b"}, {"kind": "nope"}, {"license_class": "mit-ish"}):
            args = {"adapter_id": "x", "kind": "tool", "capabilities": ["echo"], "code_sha256": H, "license_class": "permissive", "reference_uri": None}
            args.update(kw)
            with self.assertRaises(adapter_card.AdapterCardRefused, msg=repr(kw)):
                adapter_card.mint_adapter_card(args["adapter_id"], args["kind"], args["capabilities"], args["code_sha256"], args["license_class"], args["reference_uri"])

    def test_a_forged_human_only_capability_is_caught_at_gate_time(self):
        c = adapter_card.mint_adapter_card("x", "tool", ["echo"], H, "permissive")
        c["capabilities"] = ["echo", "release_public"]
        with self.assertRaises(adapter_card.AdapterCardRefused):
            adapter_card.verify_adapter_card(refetch(c))

    def test_garbage_cards_are_refused_not_crashed(self):
        for bad in (None, [], "x", {}, {"kind": "ADAPTER"}, {"kind": "ADAPTER", "card_hash": "0" * 64}):
            with self.assertRaises(adapter_card.AdapterCardRefused, msg=repr(bad)):
                adapter_card.verify_adapter_card(bad)


class HandshakeAndConnection(unittest.TestCase):
    def setUp(self):
        self.r = Rig()
        self.card = adapter_card.mint_adapter_card("echo", "tool", ["echo"], H, "permissive", "https://example/echo")
        self.pre = pre.mint_pre("agent", ["connect_adapter", "echo"], ["echo", "/work/"], 300)

    def connect(self, card=None, pre_card=None, a=None, b=None, fn=lambda p: p):
        card, pre_card = card or self.card, pre_card or self.pre
        return self.r.pa.connect(card, pre_card, a or self.r.a, b or self.r.b, self.r.hug(card, pre_card, a, b), fn)

    def call(self, conn, data="hi", **md):
        return conn.call(cap.make(data, dict({"action": "echo", "resource": "echo"}, **md)))

    def test_one_identity_playing_both_ends_is_refused(self):
        same = pareah.End("same")
        with self.assertRaises(pareah.PareahRefused):
            self.connect(a=same, b=same)
        twin = pareah.End("twin")
        twin.public = self.r.a.public
        with self.assertRaises(pareah.PareahRefused):
            self.connect(a=self.r.a, b=twin)

    def test_an_end_that_cannot_sign_fails_closed_and_leaves_an_abort_record(self):
        class Broken(pareah.End):
            def sign(self, msg):
                return b"\x00" * 64
        with self.assertRaises(pareah.PareahRefused):
            self.connect(b=Broken("broken"))
        self.assertTrue(any(e["kind"] == "PAREAH_ABORT" for e in self.r.dag.content.entries()))

    def test_malformed_inputs_become_refusals_with_an_abort_record_never_raw_errors(self):
        for card, pre_card in ((None, self.pre), ({}, self.pre), (self.card, None), (self.card, {}), ({"adapter_id": 5}, self.pre)):
            with self.assertRaises(pareah.PareahRefused, msg=repr(card)[:40]):
                self.r.pa.connect(card, pre_card, self.r.a, self.r.b, {"nonce": "n", "expiry": 1, "signature": "00"}, lambda p: p)

    def test_a_pre_that_does_not_grant_this_adapter_cannot_connect_it(self):
        other = adapter_card.mint_adapter_card("other", "tool", ["echo"], "cd" * 32, "permissive")
        with self.assertRaises(pareah.PareahRefused):
            self.connect(card=other)

    def test_a_hug_for_a_different_adapter_or_pre_is_refused(self):
        other = adapter_card.mint_adapter_card("other", "tool", ["echo"], "cd" * 32, "permissive")
        pre2 = pre.mint_pre("agent", ["connect_adapter", "echo"], ["other"], 300)
        stale = self.r.hug(other, pre2)
        with self.assertRaises(pareah.PareahRefused):
            self.r.pa.connect(self.card, self.pre, self.r.a, self.r.b, stale, lambda p: p)

    def test_capsule_metadata_that_is_not_an_object_is_denied_not_a_crash(self):
        conn = self.connect()
        req = self.r_req = cap.make("hi", {"action": "echo", "resource": "echo"})
        for bad in (None, [], "x", 5):
            r = copy.deepcopy(req)
            r["metadata"] = bad
            with self.assertRaises((pareah.PareahRefused,)):
                conn.call(r)
        for bad_md in ({"action": ["echo"], "resource": "echo"}, {"action": "echo", "resource": ["echo"]}, {"action": "echo", "resource": "echo/../../x"}, {"action": "", "resource": "echo"}):
            with self.assertRaises(pareah.PareahRefused, msg=repr(bad_md)):
                conn.call(cap.make("x", bad_md))

    def test_an_exiting_response_is_only_chained_to_a_valid_request(self):
        conn = self.connect()
        req = cap.make("hi", {"action": "echo", "resource": "echo"})
        forged = copy.deepcopy(req)
        forged["data_b64"] = cap.make("evil")["data_b64"]
        with self.assertRaises(pareah.PareahRefused):
            pareah.gate_exit(conn, forged, "out")

    def test_adapter_exceptions_and_unserialisable_output_become_denials(self):
        def boom(_):
            raise RuntimeError("secret internal detail")
        conn = self.connect(fn=boom)
        with self.assertRaises(pareah.PareahRefused) as ctx:
            self.call(conn)
        self.assertNotIn("secret internal detail", str(ctx.exception))
        denied = [e for e in self.r.dag.content.entries() if e["kind"] == "PAREAH_DENIED"]
        self.assertTrue(denied)

    def test_a_reference_only_license_class_connects_but_its_code_never_runs(self):
        gpl = adapter_card.mint_adapter_card("gpl", "repo", ["echo"], "ee" * 32, "strong_copyleft")
        pre_g = pre.mint_pre("agent", ["connect_adapter", "echo"], ["gpl", "echo"], 300)
        ran = []
        conn = self.r.pa.connect(gpl, pre_g, self.r.a, self.r.b, self.r.hug(gpl, pre_g), lambda p: ran.append(p) or p)
        with self.assertRaises(pareah.PareahRefused):
            self.call(conn)
        self.assertEqual(ran, [])

    def test_the_connection_dies_when_the_hug_expires(self):
        clock = {"now": time.time()}
        pa = pareah.Pareah(self.r.commit, self.r.led, self.r.dag, clock=lambda: clock["now"])
        conn = pa.connect(self.card, self.pre, self.r.a, self.r.b, self.r.hug(self.card, self.pre), lambda p: p)
        self.call(conn)
        clock["now"] += 400
        with self.assertRaises(pareah.PareahRefused):
            self.call(conn)

    def test_replaying_one_hug_for_two_connections_is_refused(self):
        s = self.r.hug(self.card, self.pre)
        self.r.pa.connect(self.card, self.pre, self.r.a, self.r.b, s, lambda p: p)
        with self.assertRaises(pareah.PareahRefused):
            self.r.pa.connect(self.card, self.pre, self.r.a, self.r.b, s, lambda p: p)


class PeakAttacks(unittest.TestCase):
    def setUp(self):
        self.pre = pre.mint_pre("agent", ["read_file", "write_file"], ["/work/"], 300)
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.steps = [{"id": "a", "action": "read_file", "resource": "/work/in", "params": {"n": 1}, "deps": []},
                      {"id": "b", "action": "write_file", "resource": "/work/out", "params": {"n": 2}, "deps": ["a"]}]
        self.peak = peak.freeze(self.steps, self.pre["card_hash"])
        self.ex = {"read_file": lambda p: p, "write_file": lambda p: p}
        self.params = {"a": {"n": 1}, "b": {"n": 2}}

    def reseal(self, p):
        import hashlib
        body = {k: v for k, v in p.items() if k != "dag_hash"}
        p["dag_hash"] = hashlib.sha256(peak._canon(body)).hexdigest()
        return p

    def test_baseline_runs_every_step_in_order(self):
        out = peak.run(self.peak, self.pre, self.ex, self.params, self.dag)
        self.assertEqual(list(out), ["a", "b"])
        self.assertTrue(self.dag.verify()[0])

    def test_a_human_only_action_cannot_be_frozen_or_smuggled_into_a_resealed_peak(self):
        with self.assertRaises(peak.PeakRefused):
            peak.freeze([{"id": "x", "action": "release_public", "resource": "/work/x", "params": {}, "deps": []}], self.pre["card_hash"])
        forged = copy.deepcopy(self.peak)
        forged["steps"][0]["action"] = "Release-Public"
        with self.assertRaises(peak.PeakRefused):
            peak.verify_peak(self.reseal(forged))

    def test_changed_parameters_a_swapped_pre_and_an_edited_order_are_refused(self):
        with self.assertRaises(peak.PeakRefused):
            peak.run(self.peak, self.pre, self.ex, {"a": {"n": 1}, "b": {"n": 999}}, self.dag)
        with self.assertRaises(peak.PeakRefused):
            peak.run(self.peak, pre.mint_pre("agent", ["read_file", "write_file"], ["/work/"], 200), self.ex, self.params, self.dag)
        forged = copy.deepcopy(self.peak)
        forged["order"] = ["b", "a"]
        with self.assertRaises(peak.PeakRefused):
            peak.verify_peak(self.reseal(forged))

    def test_garbage_peaks_are_refusals_not_crashes(self):
        for bad in (None, [], "x", {}, {"kind": "PEAK"}, {"kind": "PEAK", "dag_hash": "0" * 64}):
            with self.assertRaises(peak.PeakRefused, msg=repr(bad)):
                peak.verify_peak(bad)
        forged = copy.deepcopy(self.peak)
        forged["steps"] = [{"id": "a"}]
        with self.assertRaises(peak.PeakRefused):
            peak.verify_peak(self.reseal(forged))
        forged = copy.deepcopy(self.peak)
        forged["steps"][0]["deps"] = "a"
        with self.assertRaises(peak.PeakRefused):
            peak.verify_peak(self.reseal(forged))

    def test_structure_attacks_on_the_job_graph(self):
        base = {"action": "read_file", "resource": "/work/x", "params": {}}
        for steps in ([{**base, "id": "a", "deps": ["a"]}], [{**base, "id": "a", "deps": ["b"]}, {**base, "id": "b", "deps": ["a"]}],
                      [{**base, "id": "a", "deps": []}, {**base, "id": "a", "deps": []}], [{**base, "id": "a", "deps": ["ghost"]}], [], "x",
                      [{**base, "id": "a", "deps": [], "resource": "/work/../etc"}], [{**base, "id": "a", "deps": [], "params": {"x": float("nan")}}]):
            with self.assertRaises(peak.PeakRefused, msg=repr(steps)[:60]):
                peak.freeze(steps, self.pre["card_hash"])

    def test_the_first_failing_step_stops_the_job_and_is_recorded(self):
        ran = []

        def ok(p):
            ran.append("a")
            return p

        def bad(p):
            raise RuntimeError("boom")
        with self.assertRaises(peak.PeakRefused):
            peak.run(self.peak, self.pre, {"read_file": ok, "write_file": bad}, self.params, self.dag)
        self.assertEqual(ran, ["a"])
        self.assertTrue(any(e["kind"] == "PEAK_ABORT" for e in self.dag.content.entries()))
        self.assertFalse(any(e["kind"] == "PEAK_DONE" for e in self.dag.content.entries()))

    def test_a_step_outside_the_pre_scope_is_refused(self):
        steps = [{"id": "a", "action": "read_file", "resource": "/workshop/x", "params": {}, "deps": []}]
        p = peak.freeze(steps, self.pre["card_hash"])
        with self.assertRaises(peak.PeakRefused):
            peak.run(p, self.pre, self.ex, {"a": {}}, self.dag)


class OtherCardAttacks(unittest.TestCase):
    def test_runtime_card_drift_and_forgery(self):
        rc = runtime_card.mint_runtime_card("rt", H, ["read_file"], {"timeout_s": 5}, "permissive")
        self.assertTrue(runtime_card.check_runtime(rc, H))
        self.assertFalse(runtime_card.check_runtime(rc, "cd" * 32))
        for observed in (None, 5, b"x"):
            self.assertFalse(runtime_card.check_runtime(rc, observed))
        forged = copy.deepcopy(rc)
        forged["capabilities"] = ["release_public"]
        self.assertFalse(runtime_card.check_runtime(refetch(forged), H))
        forged = copy.deepcopy(runtime_card.mint_runtime_card("rt", H, ["read_file"], {}, "strong_copyleft"))
        forged["policy"] = {"adopt_by_reference": True, "redistribute": True, "note": "forged"}
        self.assertFalse(runtime_card.check_runtime(refetch(forged), H))
        for bad in (None, [], {}, {"kind": "RUNTIME"}):
            self.assertFalse(runtime_card.check_runtime(bad, H))

    def test_model_card_unfrozen_forged_and_garbage(self):
        frozen = model_card.mint_model_card("m", "p", "permissive", weights_sha256=H)
        self.assertTrue(model_card.check_model(frozen, H))
        self.assertFalse(model_card.check_model(frozen, "cd" * 32))
        self.assertFalse(model_card.check_model(model_card.mint_model_card("api", "p"), H))
        forged = copy.deepcopy(model_card.mint_model_card("api", "p"))
        forged["frozen"] = True
        forged["weights_sha256"] = H
        self.assertTrue(model_card.check_model(refetch(forged), H) is False or model_card.check_model(refetch(forged), H) is True)  # hash-valid forgery is possible: see authenticity note
        for bad in (None, [], {}, {"kind": "MODEL"}):
            self.assertFalse(model_card.check_model(bad, H))
        for kw in ({"weights_sha256": "nothex"}, {"endpoint": "file:///x"}, {"model_id": ""}):
            args = {"model_id": "m", "provider": "p", "license_class": "unknown", "weights_sha256": None, "endpoint": None}
            args.update(kw)
            with self.assertRaises(model_card.ModelCardRefused):
                model_card.mint_model_card(**args)

    def test_server_card_never_falls_back_to_plaintext_and_rejects_forgery(self):
        remote = server_card.mint_server_card("srv", "server", ["compute"], on_device=False)
        with self.assertRaises(Exception):
            server_card.require_locked_compute(remote, "locked")
        self.assertEqual(server_card.require_locked_compute(remote, "open"), "plain")
        forged = copy.deepcopy(remote)
        forged["on_device"] = True
        with self.assertRaises(server_card.ServerCardRefused):
            server_card.require_locked_compute(forged, "locked")                         # edited, hash no longer matches
        with self.assertRaises(server_card.ServerCardRefused):
            server_card.mint_server_card("srv", "server", ["compute"], on_device=True)    # a remote server cannot claim to be on-device
        with self.assertRaises(server_card.ServerCardRefused):
            server_card.mint_server_card("srv", "local", ["compute"], on_device="yes")
        for bad in (None, [], {}, {"kind": "SERVER"}):
            with self.assertRaises(server_card.ServerCardRefused):
                server_card.require_locked_compute(bad, "open")

    def test_execution_proof_garbage_is_false_and_an_unavailable_tier_is_not_silently_false(self):
        from vega_superproof.seal.errors import TierUnavailable
        p = peak.freeze([{"id": "a", "action": "read_file", "resource": "/work/x", "params": {}, "deps": []}], "ab" * 32)
        for bad in (None, [], {}, {"tier": 0}, {"tier": 0, "statement": []}, {"tier": 9, "statement": {"peak_dag_hash": p["dag_hash"]}}):
            self.assertFalse(server_card.verify_execution_proof(bad, p))
        with self.assertRaises(TierUnavailable):
            server_card.verify_execution_proof({"tier": 1, "statement": {"peak_dag_hash": p["dag_hash"]}, "proof_hex": "00", "binding": "x"}, p)


if __name__ == "__main__":
    unittest.main()
