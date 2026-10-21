"""pareah.py - PAREAH, the external adapter. ONE fixed handshake sequence for every adapter (IV.5.1):

    grant -> handshake -> union_commitment (the hug) -> adapter -> sdk_wrap -> gate

  grant             a PRE must permit connecting this adapter
  handshake         fixed two-way proof of key possession over the adapter card hash and fresh nonces
  union_commitment  the HUMAN's signed commitment over the union of both ends (human key, minted)
  adapter           the adapter card is checked (hash, no human-only power, license policy)
  sdk_wrap          the adapter callable is wrapped so every call is gated at both ends
  gate              two-ended gating is live: gate_entry on the way in, gate_exit on the way out

Every step is written to the DAG as it happens; the sequence cannot be reordered or skipped, and a connection
dies when its union commitment expires or stops verifying in the ledger."""
import hashlib
import json
import os
import secrets
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from vega_pareah.adapter import adapter_card  # noqa: E402
from vega_custody.capsule import capsule as capsule_mod  # noqa: E402
from vega_pareah.cards import pre as pre_mod  # noqa: E402
from vega_jacket.commit.commit import CommitRefused  # noqa: E402
from vega_custody.dag.dag import DagError  # noqa: E402

STEPS = ("grant", "handshake", "union_commitment", "adapter", "sdk_wrap", "gate")
CONNECT_ACTION = "connect_adapter"
UNION_ACTION = "adapter_union"


class PareahRefused(Exception):
    pass


class Trapped(PareahRefused):
    """The arrival was not the owner's announced handshake: door 1 has locked behind it and it is in the room.
    `.room` is for the transport layer; what the visitor is shown is only ever what the room says."""

    def __init__(self, room, reason):
        super().__init__("not admitted")
        self.room, self.reason = room, reason


class End:
    """One end of a connection: an identity with a signing key. Real deployments supply a hardware/OS-backed
    signer with the same sign()/public interface."""

    def __init__(self, end_id: str):
        self.end_id = end_id
        self._sk = Ed25519PrivateKey.generate()
        self.public = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg)


def _sha(*parts) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p if isinstance(p, bytes) else str(p).encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()


def _handshake(card: dict, a: End, b: End) -> dict:
    """Fixed message shape, never varies by adapter: each end signs the card hash and the OTHER end's nonce."""
    na, nb = secrets.token_hex(16), secrets.token_hex(16)
    msg_a = f"VEGA-HS-1|{card['card_hash']}|{a.end_id}|{nb}".encode()
    msg_b = f"VEGA-HS-1|{card['card_hash']}|{b.end_id}|{na}".encode()
    if a.end_id == b.end_id or a.public == b.public:
        raise PareahRefused("handshake refused: the two ends must be different identities with different keys")
    try:
        sig_a, sig_b = a.sign(msg_a), b.sign(msg_b)
        Ed25519PublicKey.from_public_bytes(a.public).verify(sig_a, msg_a)
        Ed25519PublicKey.from_public_bytes(b.public).verify(sig_b, msg_b)
    except (InvalidSignature, ValueError, TypeError, AttributeError) as exc:
        raise PareahRefused("handshake failed: an end could not prove its key") from exc
    return {"a": a.end_id, "b": b.end_id}


def union_hash(card: dict, a: End, b: End, pre_card: dict) -> str:
    return _sha("VEGA-UNION-1", card["card_hash"], a.end_id, a.public.hex(), b.end_id, b.public.hex(),
                pre_card["card_hash"])


def union_commitment(commit, union: str, card_hash: str, pre_hash: str, signed: dict) -> dict:
    """The hug: the human commits to exactly this union. Verified with the human key and minted by the SDK."""
    try:
        return commit.commit(UNION_ACTION, {"union": union, "adapter": card_hash, "pre": pre_hash},
                             signed, route="human")
    except CommitRefused as exc:
        raise PareahRefused(f"union commitment refused: {exc}") from exc


def gate_entry(conn, request_capsule: dict) -> None:
    """Gate on the way IN to the adapter."""
    conn._live()
    try:
        capsule_mod.verify(request_capsule)
    except capsule_mod.CapsuleError as exc:
        conn._deny("entry", f"request capsule invalid: {exc}")
    md = request_capsule["metadata"]
    if not isinstance(md, dict):
        conn._deny("entry", "request capsule metadata is not an object")
    action, resource = md.get("action"), md.get("resource")
    if not (isinstance(action, str) and isinstance(resource, str) and action and resource) or not pre_mod.permits(conn.pre, action, resource, conn._clock()):
        conn._deny("entry", f"PRE does not permit {action!r} on {resource!r}")
    if action not in conn.card["capabilities"]:
        conn._deny("entry", f"adapter card does not declare {action!r}")
    if not conn.card["policy"]["adopt_by_reference"]:
        conn._deny("entry", f"license class {conn.card['license_class']!r} is reference-only: connecting is allowed, running its code is not")


def gate_exit(conn, request_capsule: dict, response_data) -> dict:
    """Gate on the way OUT of the adapter: response is capsuled, chained to the request, and only passes while
    the human's union commitment is still alive and still in the ledger."""
    conn._live()
    try:
        capsule_mod.verify(request_capsule)
    except capsule_mod.CapsuleError as exc:
        conn._deny("exit", f"request capsule invalid: {exc}")
    resp = capsule_mod.make(response_data, {"adapter": conn.card["adapter_id"], "direction": "exit"},
                            predecessor=request_capsule["prefix_hash"])
    conn.dag.record("PAREAH_CALL", {"adapter": conn.card["adapter_id"],
                                    "request": request_capsule["prefix_hash"], "response": resp["prefix_hash"]})
    return resp


class Connection:
    def __init__(self, card, pre_card, adapter_fn, commitment, ledger, dag, clock=time.time, pre_deck=None):
        self.card, self.pre, self._fn = card, pre_card, adapter_fn
        self.commitment, self.ledger, self.dag, self._clock = commitment, ledger, dag, clock
        self.pre_deck = pre_deck                        # a PreDeck: a PRE revoked there stops working on this open connection at its next call

    def _deny(self, side, reason):
        try:
            self.dag.record("PAREAH_DENIED", {"adapter": self.card["adapter_id"], "gate": side, "reason": reason})
        except DagError:
            pass  # reviewed: the refusal below is raised either way; a record that cannot be written never turns a denial into an allow
        raise PareahRefused(reason)

    def _live(self):
        if self.pre_deck is not None and self.pre_deck.is_revoked(self.pre["card_hash"]):
            self._deny("lease", "the PRE has been revoked")
        if int(self._clock()) >= int(self.commitment["expiry"]):
            self._deny("lease", "union commitment expired; the hug must be renewed by the human")
        if not self.ledger.verify(self.commitment):
            self._deny("lease", "union commitment no longer verifies in the ledger")

    def call(self, request_capsule: dict) -> dict:
        gate_entry(self, request_capsule)
        try:
            out = self._fn(capsule_mod.data_of(request_capsule))
        except Exception as exc:
            self._deny("adapter", f"adapter raised {type(exc).__name__}")
        return gate_exit(self, request_capsule, out)


class Pareah:
    def __init__(self, commit, ledger, dag, clock=time.time, airlock=None, pre_deck=None):
        self.commit, self.ledger, self.dag, self._clock, self.airlock = commit, ledger, dag, clock, airlock
        self.pre_deck = pre_deck                        # optional PreDeck: revoked PREs are refused at grant and stop working on open connections

    def _door(self, end_a, end_b, arrival):
        """Door 1. When an airlock is fitted EVERY connection passes it first; there is no way to ask for one without.
        The door's own identity can never be an end of a real connection (the room's line and the real egress stay separate)."""
        if end_b.end_id == self.airlock.door_id or end_a.end_id == self.airlock.door_id:
            raise PareahRefused("the door's identity cannot be an end of a connection")
        if isinstance(arrival, dict) and arrival.get("public") != end_a.public.hex():
            raise PareahRefused("the arrival was not made by this connection's visitor end")
        verdict = self.airlock.admit(arrival)
        if verdict["status"] != "EXPECTED":
            raise Trapped(verdict["room"], verdict["reason"])

    def connect(self, card: dict, pre_card: dict, end_a: End, end_b: End, union_signed: dict, adapter_fn, arrival: dict = None) -> Connection:
        if self.airlock is not None:
            self._door(end_a, end_b, arrival)
        state, last, conn = {}, None, None
        for step in STEPS:  # the only loop: order is the constant, not a parameter
            try:
                if step == "grant":
                    if not isinstance(card, dict) or not isinstance(card.get("adapter_id"), str):
                        raise PareahRefused("adapter card has no adapter_id")
                    pre_mod.verify_pre(pre_card, self._clock())
                    if self.pre_deck is not None and self.pre_deck.is_revoked(pre_card["card_hash"]):
                        raise PareahRefused("the PRE has been revoked")
                    if not pre_mod.permits(pre_card, CONNECT_ACTION, card["adapter_id"], self._clock()):
                        raise PareahRefused("PRE does not grant connecting this adapter")
                elif step == "handshake":
                    adapter_card.verify_adapter_card(card)
                    state["hs"] = _handshake(card, end_a, end_b)
                elif step == "union_commitment":
                    u = union_hash(card, end_a, end_b, pre_card)
                    state["union"] = union_commitment(self.commit, u, card["card_hash"], pre_card["card_hash"],
                                                      union_signed)
                elif step == "adapter":
                    state["mode"] = "adopt_by_reference" if card["policy"]["adopt_by_reference"] else "reference_only"
                elif step == "sdk_wrap":
                    conn = Connection(card, pre_card, adapter_fn, state["union"]["commitment"], self.ledger,
                                      self.dag, self._clock, self.pre_deck)
                elif step == "gate":
                    conn._live()
            except Exception as exc:  # any failure at any step fails closed and is recorded, never a raw KeyError/TypeError
                try:
                    self.dag.record("PAREAH_ABORT", {"adapter": card.get("adapter_id") if isinstance(card, dict) else None, "at_step": step,
                                                     "reason": str(exc)}, parents=[last] if last else None)
                except DagError:
                    pass  # reviewed: the connection is refused below either way; a missing abort record cannot open it
                if isinstance(exc, PareahRefused):
                    raise
                raise PareahRefused(f"{step}: {exc}") from exc
            last = self.dag.record("PAREAH_STEP", {"adapter": card["adapter_id"], "step": step},
                                   parents=[last] if last else None)["entry_hash"]
        return conn


def transcript_ok(dag, adapter_id: str) -> bool:
    """True if the last complete connection for this adapter ran exactly STEPS, in order."""
    seen = [e["payload"]["step"] for e in dag.content.entries()
            if e["kind"] == "PAREAH_STEP" and e["payload"]["adapter"] == adapter_id]
    return len(seen) >= len(STEPS) and tuple(seen[-len(STEPS):]) == STEPS
