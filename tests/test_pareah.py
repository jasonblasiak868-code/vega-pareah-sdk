"""Selftest: exit 0 only if every check passes. Human signing is done by the human-side signer library, standing
in for the person at a console."""
import copy
import os
import pathlib
import sys
import tempfile
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from vega_jacket.humanauth import human_signer  # noqa: E402
from vega_jacket import humanauth  # noqa: E402
from vega_pareah.adapter import adapter_card, pareah, quarantine  # noqa: E402
from vega_custody.capsule import capsule as cap  # noqa: E402
from vega_pareah.cards import pre as pre_mod  # noqa: E402
from vega_jacket.commit.commit import Commit  # noqa: E402
from vega_custody.dag.dag import Dag  # noqa: E402
from vega_custody.ledger.backend_local import LocalBackend  # noqa: E402
from vega_custody.ledger.ledger import Ledger  # noqa: E402

fails, N = [], 0
PW, DEV, SURF = "correct horse battery", "dev-t", "surf-t"


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


blob, pub = human_signer.generate(PW)
t = pathlib.Path(tempfile.mkdtemp())
dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
led = Ledger([LocalBackend(t / "led.jsonl")])
ver = humanauth.Verifier(pub, DEV, SURF)
commit = Commit(ver, led, dag)
pa = pareah.Pareah(commit, led, dag)

card = adapter_card.mint_adapter_card("echo", "tool", ["echo"], "ab" * 32, "permissive", "https://example/echo")
pre = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["echo", "/work/"], 300)
a, b = pareah.End("agent-side"), pareah.End("adapter-side")


def hug(c=card, p=pre, x=a, y=b, lease=300):
    u = pareah.union_hash(c, x, y, p)
    params = {"union": u, "adapter": c["card_hash"], "pre": p["card_hash"]}
    return human_signer.sign(blob, PW, DEV, SURF, pareah.UNION_ACTION, params, lease)


check("STEPS is the one fixed sequence",
      pareah.STEPS == ("grant", "handshake", "union_commitment", "adapter", "sdk_wrap", "gate"))

conn = pa.connect(card, pre, a, b, hug(), lambda payload: f"echo:{payload}")
check("connect ran every step in order", pareah.transcript_ok(dag, "echo"))
req = cap.make("hi", {"action": "echo", "resource": "echo"})
resp = conn.call(req)
check("call passes both gates and is chained", cap.data_of(resp) == "echo:hi" and resp["predecessor"] == req["prefix_hash"])
check("call recorded", any(e["kind"] == "PAREAH_CALL" for e in dag.content.entries()))
check("request outside the PRE denied", raises(pareah.PareahRefused, lambda: conn.call(
    cap.make("x", {"action": "echo", "resource": "/etc/passwd"}))))
check("action the card does not declare denied", raises(pareah.PareahRefused, lambda: conn.call(
    cap.make("x", {"action": "delete", "resource": "/work/x"}))))
tamp = copy.deepcopy(req)
tamp["data_b64"] = cap.make("evil")["data_b64"]
check("tampered request capsule denied", raises(pareah.PareahRefused, lambda: conn.call(tamp)))

# --- the hug cannot be skipped, forged, replayed, or reused for another adapter
s = hug()
pa.connect(card, pre, a, b, s, lambda p: p)
check("replayed union approval refused", raises(pareah.PareahRefused, lambda: pa.connect(card, pre, a, b, s, lambda p: p)))
check("unsigned hug refused", raises(pareah.PareahRefused, lambda: pa.connect(
    card, pre, a, b, {"nonce": "n", "expiry": 1, "signature": "00"}, lambda p: p)))
other = adapter_card.mint_adapter_card("other", "tool", ["echo"], "cd" * 32, "permissive")
pre2 = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["other"], 300)
s_other = hug(other, pre2)
check("hug for one adapter cannot connect another",
      raises(pareah.PareahRefused, lambda: pa.connect(card, pre, a, b, s_other, lambda p: p)))

# --- grant, card integrity, human-only power
narrow = pre_mod.mint_pre("agent", ["echo"], ["echo"], 300)
check("no grant, no connection", raises(pareah.PareahRefused, lambda: pa.connect(card, narrow, a, b, hug(card, narrow), lambda p: p)))
bad_card = copy.deepcopy(card)
bad_card["capabilities"] = ["echo", "spend_funds"]
check("altered adapter card refused", raises(pareah.PareahRefused, lambda: pa.connect(bad_card, pre, a, b, hug(bad_card), lambda p: p)))
check("adapter card cannot be minted with a human-only power",
      raises(Exception, lambda: adapter_card.mint_adapter_card("x", "tool", ["release_public"], "ab" * 32)))
gpl = adapter_card.mint_adapter_card("gpl", "repo", ["echo"], "ee" * 32, "strong_copyleft")
pre_g = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["gpl", "echo"], 300)
gpl_conn = pa.connect(gpl, pre_g, a, b, hug(gpl, pre_g), lambda p: p)
check("copyleft adapter connects as reference-only",
      gpl_conn.card["policy"]["adopt_by_reference"] is False and gpl_conn.card["license_class"] == "strong_copyleft")

# --- lease: the connection dies when the hug expires
clock = {"now": 1_000_000.0}
pre_c = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["echo", "/work/"], 300, now=1_000_000.0)
exp_conn = pareah.Pareah(commit, led, dag, clock=lambda: clock["now"]).connect(
    card, pre_c, a, b, human_signer.sign(blob, PW, DEV, SURF, pareah.UNION_ACTION, {
        "union": pareah.union_hash(card, a, b, pre_c), "adapter": card["card_hash"], "pre": pre_c["card_hash"]}, 300),
    lambda p: p)
# real clock is far past the fake one, so move the fake clock past the commitment expiry
clock["now"] = float(exp_conn.commitment["expiry"]) + 1
check("expired hug kills the connection", raises(pareah.PareahRefused, lambda: exp_conn.call(
    cap.make("x", {"action": "echo", "resource": "echo"}))))

# --- quarantine
td = pathlib.Path(tempfile.mkdtemp())
good = td / "good.py"
good.write_text("print('ok')\n")
evil_net = td / "net.py"
evil_net.write_text("import socket\nsocket.create_connection(('example.com', 80))\n")
evil_eval = td / "ev.py"
evil_eval.write_text("eval('1+1')\n")
hang = td / "hang.py"
hang.write_text("import time\ntime.sleep(60)\n")
crash = td / "crash.py"
crash.write_text("raise SystemExit(3)\n")

c_ok = quarantine.quarantine_then_adopt(good, "good", "tool", ["echo"], "permissive", dag)
check("benign artifact allowed and carded", c_ok["adapter_id"] == "good" and c_ok["code_sha256"])
check("network import denied", raises(quarantine.QuarantineDenied, lambda: quarantine.quarantine_then_adopt(
    evil_net, "net", "tool", ["echo"], "permissive", dag)))
check("eval denied", raises(quarantine.QuarantineDenied, lambda: quarantine.quarantine_then_adopt(
    evil_eval, "ev", "tool", ["echo"], "permissive", dag)))
check("hang killed by timeout and denied", raises(quarantine.QuarantineDenied, lambda: quarantine.quarantine_then_adopt(
    hang, "hang", "tool", ["echo"], "permissive", dag, timeout=2)))
check("crash denied", raises(quarantine.QuarantineDenied, lambda: quarantine.quarantine_then_adopt(
    crash, "crash", "tool", ["echo"], "permissive", dag)))
verdicts = [e["payload"]["verdict"] for e in dag.content.entries() if e["kind"] == "QUARANTINE_VERDICT"]
check("every verdict recorded in the DAG", verdicts == ["ALLOW", "DENY", "DENY", "DENY", "DENY"])
c_gpl = quarantine.quarantine_then_adopt(good, "good-gpl", "repo", ["echo"], "strong_copyleft", dag)
check("copyleft artifact passes quarantine but stays reference-only", not c_gpl["policy"]["adopt_by_reference"])
pre_q = pre_mod.mint_pre("agent", ["connect_adapter", "echo"], ["good", "echo"], 300)
q_conn = pa.connect(c_ok, pre_q, a, b, hug(c_ok, pre_q), lambda p: f"q:{p}")
check("quarantined card then connects through the same fixed sequence",
      pareah.transcript_ok(dag, "good") and cap.data_of(q_conn.call(cap.make("z", {"action": "echo", "resource": "echo"}))) == "q:z")

check("DAG intact", dag.verify()[0])
print(f"{N - len(fails)}/{N} passed" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
