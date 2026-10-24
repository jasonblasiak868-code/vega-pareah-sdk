"""pulse.py - a heartbeat the adapter cannot fake and a probe that tests the gates from outside.

Two separate jobs, both eyes with no authority (they record and alarm; they never open, close, or allow anything):

  PULSE  A Watcher sends a fresh random challenge to the adapter side. The adapter side (a Responder holding the adapter end's key) signs the challenge, the time, and its own state.
         The Watcher checks the signature, that the challenge is the one it just sent (so a recorded answer cannot be replayed), that the time is fresh, and that the link is not reporting itself closed.
         Every pulse is written to its OWN chain (the pulse chain) so a long quiet run cannot bury the main chain; the main chain gets a summary every N pulses and any failure or silence at once.
         Silence is an alarm too: no good pulse inside `max_silence` seconds records PAREAH_PULSE_SILENT and calls `on_alarm`. Intervals are random so a hostile adapter cannot answer only on schedule.

  PROBE  probe_connection() tries a copy of a live connection's front gate with one request that should pass and several that must be refused (outside the PRE's scope, a tampered capsule, an action the
         card does not declare). The copy writes nothing and never reaches the adapter. If a bad request is let through, or the good one is refused, the report says so and the failure is recorded.

HONEST LIMITS: a pulse proves the holder of the adapter's key answered just now; it does not prove the adapter is behaving. The watcher should run OUTSIDE the process it watches (a separate process
or machine) or a compromised process can silence its own watcher. This module is the logic; where it runs is the deployer's choice."""
import copy
import hashlib
import json
import secrets
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vega_custody.capsule import capsule as capsule_mod
from vega_custody.dag.dag import DagError
from vega_pareah.adapter.pareah import PareahRefused, gate_entry

SKEW_SECONDS = 30
RESPONDER_TIMEOUT = 5.0


def _message(card_hash: str, challenge: str, ts: int, state: dict) -> bytes:
    return ("VEGA-PULSE-1|%s|%s|%d|%s" % (card_hash, challenge, ts, json.dumps(state, sort_keys=True, separators=(",", ":")))).encode("utf-8")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Responder:
    """The adapter side: answers a challenge with a signature over the challenge, the time, and the link's state."""

    def __init__(self, end, card_hash: str, conn=None, clock=time.time):
        self.end, self.card_hash, self.conn, self._clock = end, card_hash, conn, clock

    def respond(self, challenge: str) -> dict:
        ts = int(self._clock())
        state = {"closed": bool(getattr(self.conn, "closed", False))}
        sig = self.end.sign(_message(self.card_hash, challenge, ts, state))
        return {"challenge": challenge, "ts": ts, "state": state, "sig": sig.hex()}


class Watcher:
    def __init__(self, main_dag, pulse_dag, clock=time.time, max_silence=120, summary_every=20, on_alarm=None, skew=SKEW_SECONDS):
        self.main_dag, self.pulse_dag, self._clock = main_dag, pulse_dag, clock
        self.max_silence, self.summary_every, self.on_alarm, self.skew = max_silence, summary_every, on_alarm, skew
        self._watched, self._lock = {}, threading.RLock()
        self._stop, self._thread = threading.Event(), None

    def add(self, name: str, card_hash: str, public: bytes, responder):
        """`responder` is a function challenge -> answer dict (a Responder.respond, or a call across a process or network)."""
        with self._lock:
            self._watched[name] = {"card_hash": card_hash, "public": bytes(public), "responder": responder, "ok": 0, "failed": 0, "since_summary": 0,
                                   "last_ok": self._clock(), "alarmed": False, "last_entry": None}

    def pulse(self, name: str) -> dict:
        """One challenge. Returns {"ok": bool, "reason": str}. Never raises for a bad answer: a bad answer is a recorded alarm."""
        with self._lock:
            w = self._watched[name]
        challenge = secrets.token_hex(16)
        ok, reason = self._ask(w, challenge)
        with self._lock:
            now = self._clock()
            try:
                entry = self.pulse_dag.record("PAREAH_PULSE", {"watched": name, "ok": ok, "reason": reason, "challenge_sha256": _sha(challenge), "at": int(now)})
                w["last_entry"] = entry.get("entry_hash") if isinstance(entry, dict) else None
            except DagError:
                ok, reason = False, "the pulse could not be recorded"
            if ok:
                w["ok"] += 1
                w["last_ok"], w["alarmed"] = now, False
            else:
                w["failed"] += 1
                self._alarm(name, "PAREAH_PULSE_FAILED", reason)
            w["since_summary"] += 1
            if w["since_summary"] >= self.summary_every:
                self._summarize(name, w)
        return {"ok": ok, "reason": reason}

    def check_silence(self) -> list:
        """Names that have not given a good pulse within max_silence. Each silence episode is recorded once."""
        silent = []
        with self._lock:
            now = self._clock()
            for name, w in self._watched.items():
                if now - w["last_ok"] > self.max_silence:
                    silent.append(name)
                    if not w["alarmed"]:
                        w["alarmed"] = True
                        self._alarm(name, "PAREAH_PULSE_SILENT", "no good pulse for %d seconds" % int(now - w["last_ok"]))
        return silent

    def start(self, min_seconds=5.0, max_seconds=30.0):
        """Runs pulses on a random schedule in a background thread."""
        rng = secrets.SystemRandom()

        def loop():
            while not self._stop.wait(rng.uniform(min_seconds, max_seconds)):
                for name in list(self._watched):
                    self.pulse(name)
                self.check_silence()
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    # ---- internals ----
    def _ask(self, w, challenge):
        box = {}

        def run():
            try:
                box["answer"] = w["responder"](challenge)
            except Exception as exc:  # noqa: BLE001 - a responder that fails has not answered
                box["error"] = type(exc).__name__
        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(RESPONDER_TIMEOUT)
        if t.is_alive():
            return False, "no answer in time"
        if "error" in box:
            return False, "the responder failed (%s)" % box["error"]
        a = box.get("answer")
        if not isinstance(a, dict) or not all(k in a for k in ("challenge", "ts", "state", "sig")):
            return False, "the answer is malformed"
        if a["challenge"] != challenge:
            return False, "the answer is for a different challenge (replay)"
        if isinstance(a["ts"], bool) or not isinstance(a["ts"], int) or abs(int(self._clock()) - a["ts"]) > self.skew:
            return False, "the answer is not fresh"
        if not isinstance(a["state"], dict) or not isinstance(a["sig"], str):
            return False, "the answer is malformed"
        try:
            Ed25519PublicKey.from_public_bytes(w["public"]).verify(bytes.fromhex(a["sig"]), _message(w["card_hash"], challenge, a["ts"], a["state"]))
        except (InvalidSignature, ValueError, TypeError):
            return False, "the signature does not verify against the adapter's key"
        if a["state"].get("closed") is not False:
            return False, "the link reports itself closed"
        return True, "ok"

    def _alarm(self, name, kind, reason):
        try:
            self.main_dag.record(kind, {"watched": name, "reason": reason})
        except DagError:
            pass  # reviewed: the alarm callback below still fires; a record that cannot be written never hides the alarm
        if self.on_alarm is not None:
            try:
                self.on_alarm(name, kind, reason)
            except Exception:  # noqa: BLE001 - a broken alarm handler must not stop the watcher
                pass

    def _summarize(self, name, w):
        try:
            self.main_dag.record("PAREAH_PULSE_SUMMARY", {"watched": name, "ok": w["ok"], "failed": w["failed"], "last_pulse_entry": w["last_entry"] or ""})
        except DagError:
            return
        w["since_summary"] = 0


class _NullDag:
    def record(self, *a, **k):
        return {}


def probe_connection(conn, good: tuple, extra_bad=()) -> dict:
    """Tests the front gate of `conn` on a copy that writes nothing and never reaches the adapter.
    `good` is an (action, resource) the PRE permits and the card declares: it must pass. The built-in bad requests must all be refused.
    Returns {"passed": bool, "results": [{"probe", "expected", "got"}]} and records one PAREAH_PROBE entry on the connection's own chain."""
    p = copy.copy(conn)
    p._timer, p._fn, p._close_lock, p.dag = None, None, threading.Lock(), _NullDag()
    action, resource = good
    ok_req = capsule_mod.make("probe", {"action": action, "resource": resource})
    tampered = copy.deepcopy(ok_req)
    tampered["data_b64"] = capsule_mod.make("tampered")["data_b64"]
    probes = [("good", ok_req, "pass"),
              ("outside the PRE's scope", capsule_mod.make("probe", {"action": action, "resource": "/outside-the-scope-of-any-pre/" + secrets.token_hex(4)}), "refuse"),
              ("tampered capsule", tampered, "refuse"),
              ("action the card does not declare", capsule_mod.make("probe", {"action": "undeclared_" + secrets.token_hex(4), "resource": resource}), "refuse")]
    probes += [(label, req, "refuse") for (label, req) in extra_bad]
    results = []
    for label, req, expected in probes:
        try:
            gate_entry(p, req)
            got = "pass"
        except PareahRefused:
            got = "refuse"
        results.append({"probe": label, "expected": expected, "got": got})
    passed = all(r["expected"] == r["got"] for r in results)
    try:
        conn.dag.record("PAREAH_PROBE", {"adapter": conn.card["adapter_id"], "passed": passed, "failed_probes": [r["probe"] for r in results if r["expected"] != r["got"]]})
    except DagError:
        passed = False
    return {"passed": passed, "results": results}
