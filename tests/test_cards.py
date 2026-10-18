"""Selftest: exit 0 only if every check passes."""
import copy
import os
import pathlib
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from vega_pareah.cards import model_card, peak, pre, runtime_card, server_card  # noqa: E402
from vega_custody.dag.dag import Dag  # noqa: E402
from vega_superproof.seal import fhe, proof_tier0, proof_tier1  # noqa: E402
from vega_superproof.seal.errors import TierUnavailable  # noqa: E402

fails, N = [], 0


def check(name, cond):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


# --- PRE
card = pre.mint_pre("agent-1", ["read_file", "write_file"], ["/work/"], 300)
check("PRE mints and verifies", pre.permits(card, "read_file", "/work/a.txt"))
check("PRE denies outside scope", not pre.permits(card, "read_file", "/etc/passwd"))
check("PRE denies capability it lacks", not pre.permits(card, "delete_file", "/work/a.txt"))
check("PRE refuses HUMAN_ONLY capability", raises(pre.PreRefused, lambda: pre.mint_pre("a", ["spend_funds"], ["/"])))
check("PRE refuses wildcard", raises(pre.PreRefused, lambda: pre.mint_pre("a", ["*"], ["/"])))
check("PRE refuses over-cap lease", raises(pre.PreRefused, lambda: pre.mint_pre("a", ["read_file"], ["/"], 86400)))
forged = copy.deepcopy(card)
forged["capabilities"].append("release_public")
check("forged PRE with human-only power rejected", not pre.permits(forged, "release_public", "/work/"))
edited = copy.deepcopy(card)
edited["scope"] = ["/"]
check("edited PRE rejected", not pre.permits(edited, "read_file", "/etc/passwd"))
check("expired PRE denies", not pre.permits(card, "read_file", "/work/a.txt", now=card["expires"] + 1))
deck = pre.PreDeck()
h = deck.add(card)
check("deck permits then revokes", deck.permits(h, "read_file", "/work/x") and (deck.revoke(h) or True)
      and not deck.permits(h, "read_file", "/work/x"))

# --- PEAK
t = pathlib.Path(tempfile.mkdtemp())
dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
steps = [
    {"id": "a", "action": "read_file", "resource": "/work/in", "params": {"p": 1}, "deps": []},
    {"id": "b", "action": "write_file", "resource": "/work/out", "params": {"p": 2}, "deps": ["a"]},
]
pk = peak.freeze(steps, card["card_hash"])
check("PEAK freezes and verifies", peak.verify_peak(pk) is None and pk["order"] == ["a", "b"])
ran = []
ex = {"read_file": lambda p: ran.append("read") or "data", "write_file": lambda p: ran.append("write") or "ok"}
out = peak.run(pk, card, ex, {"a": {"p": 1}, "b": {"p": 2}}, dag)
check("PEAK runs in order and records every step", ran == ["read", "write"]
      and [e["kind"] for e in dag.content.entries()][-3:] == ["PEAK_STEP", "PEAK_STEP", "PEAK_DONE"])
check("changed params refused at run time",
      raises(peak.PeakRefused, lambda: peak.run(pk, card, ex, {"a": {"p": 1}, "b": {"p": 999}}, dag)))
check("abort is recorded in the DAG", any(e["kind"] == "PEAK_ABORT" for e in dag.content.entries()))
pk2 = copy.deepcopy(pk)
pk2["steps"][1]["action"] = "delete_file"
check("PEAK altered after freeze rejected", raises(peak.PeakRefused, lambda: peak.verify_peak(pk2)))
check("HUMAN_ONLY step cannot be frozen", raises(peak.PeakRefused, lambda: peak.freeze(
    [{"id": "x", "action": "release_public", "resource": "/", "params": {}, "deps": []}], card["card_hash"])))
check("cycle refused", raises(peak.PeakRefused, lambda: peak.freeze(
    [{"id": "x", "action": "read_file", "resource": "/work/", "params": {}, "deps": ["y"]},
     {"id": "y", "action": "read_file", "resource": "/work/", "params": {}, "deps": ["x"]}], card["card_hash"])))
narrow = pre.mint_pre("agent-1", ["read_file"], ["/work/"], 300)
pk3 = peak.freeze(steps, narrow["card_hash"])
check("step outside the PRE refused", raises(peak.PeakRefused,
      lambda: peak.run(pk3, narrow, ex, {"a": {"p": 1}, "b": {"p": 2}}, dag)))
check("job under a different PRE refused", raises(peak.PeakRefused,
      lambda: peak.run(pk, narrow, ex, {"a": {"p": 1}, "b": {"p": 2}}, dag)))

# --- runtime / model cards
rc = runtime_card.mint_runtime_card("rt1", "ab" * 32, ["read_file"], {"timeout_s": 30}, "permissive", "https://example/x")
check("runtime card detects drift", runtime_card.check_runtime(rc, "ab" * 32) and not runtime_card.check_runtime(rc, "cd" * 32))
check("runtime card refuses human-only power", raises(Exception, lambda: runtime_card.mint_runtime_card(
    "rt", "ab" * 32, ["spend_funds"], {})))
check("copyleft runtime stays reference-only", not runtime_card.mint_runtime_card(
    "rt2", "ab" * 32, ["read_file"], {}, "strong_copyleft")["policy"]["adopt_by_reference"])
mc = model_card.mint_model_card("m", "p", "permissive", weights_sha256="ee" * 32)
check("frozen model card matches weights hash", model_card.check_model(mc, "ee" * 32) and not model_card.check_model(mc, "ff" * 32))
check("API model card cannot be hash-checked and says so", not model_card.check_model(model_card.mint_model_card("api", "p"), "ee" * 32))

# --- server card
sc_remote = server_card.mint_server_card("srv", "server", ["compute"], on_device=False)
sc_local = server_card.mint_server_card("loc", "local", ["compute"], on_device=True)
check("open data off-device allowed", server_card.require_locked_compute(sc_remote, "open") == "plain")
check("locked data on-device stays plain", server_card.require_locked_compute(sc_local, "locked") == "plain")
check("locked data off-device without FHE refuses", raises(fhe.FHEUnavailable,
      lambda: server_card.require_locked_compute(sc_remote, "locked")))


class FakeFhe:
    def evaluate(self, op, cts):
        return b"ct"


fhe.register_backend(FakeFhe())
check("locked data off-device allowed once FHE is registered", server_card.require_locked_compute(sc_remote, "locked") == "locked")
fhe._BACKEND = None
check("server card refuses human-only power", raises(Exception, lambda: server_card.mint_server_card(
    "s", "server", ["grant_authority"], False)))

# --- execution proof
stmt = {"peak_dag_hash": pk["dag_hash"], "output_sha256": "aa" * 32}
p0 = proof_tier0.prove(stmt)
check("tier 0 execution proof binds this PEAK", server_card.verify_execution_proof(p0, pk))
check("proof about another PEAK rejected", not server_card.verify_execution_proof(p0, pk3))
tampered = copy.deepcopy(p0)
tampered["statement"]["output_sha256"] = "bb" * 32
check("tampered execution proof rejected", not server_card.verify_execution_proof(tampered, pk))
p1 = {"tier": 1, "statement": stmt, "proof_hex": "00", "binding": "x"}
check("tier 1 proof without a prover fails closed", raises(TierUnavailable, lambda: server_card.verify_execution_proof(p1, pk)))

print(f"{N - len(fails)}/{N} passed" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
