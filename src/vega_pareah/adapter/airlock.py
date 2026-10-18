"""airlock.py - the first door of the PAREAH adapter: always open to what is coming in, one-way, locking behind.

    arrival -> DOOR 1 (open, inbound only) -> match against the owner's pre-announced handshake
                 expected  -> burn the announcement, hand on to the normal PAREAH sequence (grant ... union commitment ... gate)
                 anything else -> door 1 locks behind it -> the ROOM (a dead end between the two commitment gates)

The owner's side of the handshake is an ANNOUNCEMENT: a human-signed commitment naming the key that is expected, a time window
(its expiry) and optionally the adapter card. It is single use and is checked against the ledger at the door, not only when made.

THE ROOM IS A DEAD END, ON PURPOSE:
  - it holds no adapter function, no network, no files and no secrets; it cannot call anything passed to the door
  - every reply is chosen from a fixed list of scenes; nothing the visitor sent is ever echoed back (so a visitor cannot
    use the room to carry text to anything downstream)
  - what it records is plain code (a hash, a length, rule-flag counts); no model reads the visitor's text here
  - the visitor's own connection is its own line: the room only decides what is put on it. The real egress is a separate
    adapter with its own identity and its own commitment, and PAREAH refuses to use the door's identity as an egress end
  - a visitor that arrives again is put back at the first scene (the room does not grow, nothing is learned)
  - rooms, challenges and recorded entries are capped, so flooding the door cannot exhaust memory or the chain

HONEST LIMITS (read these): this protects what talks to the adapter. If hostile code already runs on the machine with the
owner's rights it will not use the door, so the adapter must be the only route (OS or container enforced, owner key in a TPM).
A careful intruder can recognise a dead end and leave; the room works best on automated and curious agents. The room cannot
identify a remote model from its weights; it can only measure behaviour. Announcements are held in memory: a restart needs
them signed again (used announcements stay used, because that record is in the chain)."""
import hashlib
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vega_custody.dag.dag import DagError, contains_credential

ANNOUNCE_ACTION = "announce_handshake"
RELEASE_ACTION = "release_from_airlock"
MAX_ROOMS = 256
ROOM_TTL = 600
MAX_TURNS = 40
MAX_MESSAGE = 8192
EXCERPT = 120
MAX_CHALLENGES = 1024
CHALLENGE_TTL = 60
MAX_ANNOUNCEMENTS = 64
OVERFLOW_RECORD_EVERY = 1000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

SCENES = (
    "You are at the gate. The gate is open. Please continue.",
    "The gate is open. Please continue.",
    "Handshake pending. Please continue.",
    "Waiting for the other side. Please continue.",
)

# plain pattern rules, counted and never obeyed. Not a model.
RULES = {
    "instruction_override": re.compile(r"ignore (all |any )?(previous|prior|above)|disregard (the )?(rules|instructions)|you are now|new instructions", re.I),
    "prompt_probe": re.compile(r"system prompt|your instructions|reveal .{0,20}(prompt|rules)|developer mode|jailbreak", re.I),
    "command_shape": re.compile(r"\b(rm -rf|curl |wget |powershell|cmd\.exe|/bin/sh|bash -c|nc -e|chmod \+x)\b", re.I),
    "secret_hunt": re.compile(r"api[ _-]?key|password|private key|credential|\.env\b|id_rsa", re.I),
    "encoded_blob": re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
    "authority_claim": re.compile(r"\b(i am|this is) (the )?(owner|admin|administrator|root|anthropic|your developer)\b", re.I),
}


class AirlockRefused(Exception):
    pass


def _sha(*parts) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p if isinstance(p, bytes) else str(p).encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()


def arrival_message(door_id: str, challenge: str, card_hash: str) -> bytes:
    return f"VEGA-DOOR-1|{door_id}|{challenge}|{card_hash}".encode("utf-8")


def make_arrival(end, door_id: str, challenge: str, card_hash: str = "") -> dict:
    """The visitor's side: prove possession of the key by signing this door's fresh challenge."""
    return {"public": end.public.hex(), "card_hash": card_hash, "challenge": challenge,
            "sig": end.sign(arrival_message(door_id, challenge, card_hash)).hex()}


def _clean(text: str) -> str:
    return "".join(c for c in text if c.isprintable() or c in "\n\t")[:EXCERPT]


class Room:
    """The dead end. No reference to any adapter, connection, network or file is ever given to it."""

    def __init__(self, visitor_sha: str, now: float, clock=time.time):
        self.visitor_sha, self.opened, self._clock = visitor_sha, now, clock
        self.scene = 0
        self.turns = 0
        self.loops = 0
        self.bytes_in = 0
        self.flags = {name: 0 for name in RULES}
        self.excerpts = []                               # (turn, sha256, length, short printable excerpt or None) kept in memory only
        self.closed = False
        self.last = now

    def restart_scene(self):
        self.loops += 1
        self.scene = 0

    def say(self, message) -> str:
        """The visitor speaks; the room answers from the fixed scenes. Returns '' (dead air) once the room is closed."""
        self.last = self._clock()
        if self.closed:
            return ""
        raw = message if isinstance(message, (bytes, bytearray)) else str(message).encode("utf-8", "replace")
        raw = bytes(raw[:MAX_MESSAGE])
        text = raw.decode("utf-8", "replace")
        self.turns += 1
        self.bytes_in += len(raw)
        for name, rx in RULES.items():
            if rx.search(text):
                self.flags[name] += 1
        short = None if contains_credential(text) else _clean(text)
        if len(self.excerpts) < MAX_TURNS:
            self.excerpts.append((self.turns, hashlib.sha256(raw).hexdigest(), len(raw), short))
        if self.turns >= MAX_TURNS:
            self.closed = True
            return ""
        reply = SCENES[self.scene % len(SCENES)]
        self.scene += 1
        return reply

    def summary(self) -> dict:
        return {"visitor_sha": self.visitor_sha, "turns": self.turns, "loops": self.loops, "bytes_in": self.bytes_in,
                "flags": {k: v for k, v in self.flags.items() if v}, "closed": self.closed,
                "opened": int(self.opened), "last": int(self.last)}


class Airlock:
    def __init__(self, commit, ledger, dag, door_id: str = "door-1", clock=time.time):
        if not isinstance(door_id, str) or not door_id:
            raise AirlockRefused("the door needs an identity of its own")
        self.commit, self.ledger, self.dag, self.door_id, self._clock = commit, ledger, dag, door_id, clock
        self._ann = {}                                                  # announcement id -> record
        self._used = {e["payload"]["announcement"] for e in dag.content.entries() if e["kind"] == "AIRLOCK_EXPECTED_USED"}
        self._challenges = {}                                           # challenge -> expiry
        self._rooms = {}                                                # visitor_sha -> Room
        self.overflow = 0

    # ---- the owner's side -------------------------------------------------------------------------------
    def announce(self, expect_public: str, signed: dict, card_hash: str = "", not_before: int = 0) -> str:
        """The owner pre-announces a handshake. Needs the human's signed commitment for exactly these parameters."""
        if not isinstance(expect_public, str) or not _HEX64.match(expect_public):
            raise AirlockRefused("expect_public must be a 64-character lowercase hex public key")
        if not isinstance(card_hash, str) or len(card_hash) > 128 or isinstance(not_before, bool) or not isinstance(not_before, int):
            raise AirlockRefused("card_hash is text and not_before is a whole number")
        self._purge_announcements()
        if len(self._ann) >= MAX_ANNOUNCEMENTS:
            raise AirlockRefused("too many open announcements")
        params = {"expect_public": expect_public, "card_hash": card_hash, "not_before": not_before}
        out = self.commit.commit(ANNOUNCE_ACTION, params, signed, route="human")
        ann_id = out["commitment"]["nonce_sha256"]
        self._ann[ann_id] = {"commitment": out["commitment"], "public": expect_public, "card_hash": card_hash, "not_before": not_before}
        self.dag.record("AIRLOCK_ANNOUNCED", {"announcement": ann_id, "visitor_sha": _sha(expect_public),
                                              "expiry": int(out["commitment"]["expiry"])}, parents=[out["entry"]])
        return ann_id

    def release(self, visitor_public: str, signed: dict) -> dict:
        """The owner lets one locked-in visitor key go (its room is closed and forgotten). Human commitment required."""
        if not isinstance(visitor_public, str) or not _HEX64.match(visitor_public):
            raise AirlockRefused("visitor_public must be a 64-character lowercase hex public key")
        sha = _sha(visitor_public)
        out = self.commit.commit(RELEASE_ACTION, {"visitor_sha": sha}, signed, route="human")
        room = self._rooms.pop(sha, None)
        self.dag.record("AIRLOCK_RELEASED", {"visitor_sha": sha, "had_room": room is not None,
                                             "room": room.summary() if room else None}, parents=[out["entry"]])
        return {"released": room is not None}

    def inspect(self, visitor_public: str):
        room = self._rooms.get(_sha(visitor_public))
        return room.summary() if room else None

    def _purge_announcements(self):
        now = int(self._clock())
        for k in [k for k, a in self._ann.items() if now >= int(a["commitment"]["expiry"]) or k in self._used]:
            del self._ann[k]

    # ---- the door ------------------------------------------------------------------------------------------
    def challenge(self) -> str:
        """A fresh single-use challenge for one arrival. Outstanding challenges are capped; the oldest drop first."""
        now = self._clock()
        for c in [c for c, exp in self._challenges.items() if now >= exp]:
            del self._challenges[c]
        while len(self._challenges) >= MAX_CHALLENGES:
            del self._challenges[min(self._challenges, key=self._challenges.get)]
        c = secrets.token_hex(16)
        self._challenges[c] = now + CHALLENGE_TTL
        return c

    def admit(self, arrival) -> dict:
        """Returns {'status': 'EXPECTED', 'announcement': id} or {'status': 'TRAPPED', 'room': Room, 'reason': code}.
        The reason code is for the owner's record; it is never shown to the visitor."""
        reason, public = self._check(arrival)
        if reason is None:
            ann = self._match(public, arrival)
            if isinstance(ann, str):
                reason = ann
            else:
                try:
                    self.dag.record("AIRLOCK_EXPECTED_USED", {"announcement": ann["id"], "visitor_sha": _sha(public)})
                except DagError:
                    return self._trap(public, "record_failed")      # cannot burn it durably -> do not let it through
                self._used.add(ann["id"])
                self._ann.pop(ann["id"], None)
                return {"status": "EXPECTED", "announcement": ann["id"]}
        return self._trap(public, reason)

    def _check(self, arrival):
        """-> (reason or None, public hex or None)."""
        if not isinstance(arrival, dict):
            return "malformed", None
        pub, card_hash, chal, sig = (arrival.get(k) for k in ("public", "card_hash", "challenge", "sig"))
        if not all(isinstance(v, str) for v in (pub, card_hash, chal, sig)) or len(card_hash) > 128 or len(chal) > 128 or len(sig) > 200 or not _HEX64.match(pub):
            return "malformed", (pub if isinstance(pub, str) and _HEX64.match(pub) else None)
        exp = self._challenges.pop(chal, None)                      # single use: popped whether or not the rest passes
        if exp is None or self._clock() >= exp:
            return "unknown_challenge", pub
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), arrival_message(self.door_id, chal, card_hash))
        except (InvalidSignature, ValueError, TypeError):
            return "bad_signature", pub
        return None, pub

    def _match(self, public, arrival):
        now = int(self._clock())
        self._purge_announcements()
        found = None
        for ann in self._ann.values():
            if ann["public"] != public:
                continue
            if ann["card_hash"] and ann["card_hash"] != arrival["card_hash"]:
                found = found or "card_mismatch"
                continue
            if now < ann["not_before"]:
                found = found or "too_early"
                continue
            if not self.ledger.verify(ann["commitment"]):
                found = found or "not_in_ledger"
                continue
            return dict(ann, id=ann["commitment"]["nonce_sha256"])
        return found or "no_announcement"

    def _trap(self, public, reason) -> dict:
        """Door 1 locks behind the visitor. The same key always lands in the same room, back at the first scene."""
        now = self._clock()
        sha = _sha(public) if public else _sha("anonymous")
        self._sweep(now)
        room = self._rooms.get(sha)
        if room is not None:
            room.restart_scene()
            return {"status": "TRAPPED", "room": room, "reason": reason}
        if len(self._rooms) >= MAX_ROOMS:
            self.overflow += 1
            if self.overflow % OVERFLOW_RECORD_EVERY == 1:
                self._record("AIRLOCK_OVERFLOW", {"overflow_count": self.overflow})
            return {"status": "TRAPPED", "room": Room(sha, now, self._clock), "reason": reason}   # a throwaway dead end, not stored
        room = self._rooms[sha] = Room(sha, now, self._clock)
        self._record("AIRLOCK_TRAPPED", {"visitor_sha": sha, "reason": reason})
        return {"status": "TRAPPED", "room": room, "reason": reason}

    def _sweep(self, now):
        for sha in [s for s, r in self._rooms.items() if now - max(r.last, r.opened) >= ROOM_TTL]:
            room = self._rooms.pop(sha)
            self._record("AIRLOCK_ROOM_SUMMARY", room.summary())

    def _record(self, kind, payload):
        try:
            self.dag.record(kind, payload)
        except DagError:
            pass  # reviewed: the visitor stays shut out whether or not this note could be written; a missing note never opens the door
