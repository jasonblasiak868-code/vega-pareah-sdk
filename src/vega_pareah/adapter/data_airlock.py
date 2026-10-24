"""data_airlock.py - the inbound DATA airlock: data from outside is RECORDED and HELD APART; it reaches the governed side only under a human commitment.

The default is that nothing enters. Everything that arrives is recorded (source, sequence, SHA-256, size, time) and kept in a holding area the governed side does not read. Two ways through:

  1. A COLLECTION commitment: the human signs `collect_data` for {source, window, max items, max bytes, validator name}. For that source, inside that window and those limits, and only if the
     named deterministic validator (if any) accepts it, each item is ADMITTED and handed on at once. Every item is still recorded. This is for feeds that change all day (prices): the commitment
     names the act of collecting, not every value.
  2. A BATCH release: the human reads preview() of what is being held and signs `release_data_batch` for {source, batch hash, count}. Exactly that batch is handed on, once.

Anything else stays held. Nothing is lost silently: an item too big to keep, or arriving when the holding area is full, is recorded by hash with body_kept = false.
The chain holds ids and hashes only, never the data. Rules live in memory: after a restart everything is held until the human authorizes again (fail closed).

HONEST LIMITS: the separation is only physical if the consumer cannot read the holding folder (run it in the box, with the holding folder outside the folders the box is given). Admitted data is
still DATA from outside: a validator can check shape and range, not honesty, so allow numbers and fixed choices, not free text a model might read as instructions."""
import hashlib
import os
import pathlib
import re
import threading
import time

from vega_custody.dag.dag import DagError
from vega_jacket import humanauth
from vega_jacket.commit.commit import CommitRefused

COLLECT_ACTION = "collect_data"
RELEASE_ACTION = "release_data_batch"
MAX_ITEM = 1024 * 1024
MAX_HELD_BYTES = 256 * 1024 * 1024
MAX_WINDOW = 24 * 3600
MAX_ITEMS_CAP = 1_000_000
_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,63}")


class DataAirlockRefused(Exception):
    pass


def collect_params(source: str, window_seconds: int, max_items: int, max_bytes: int, validator: str = "") -> dict:
    """The exact arguments the human signs to open one collection."""
    return {"source": source, "window_seconds": window_seconds, "max_items": max_items, "max_bytes": max_bytes, "validator": validator}


def batch_params(source: str, batch_sha256: str, count: int) -> dict:
    return {"source": source, "batch_sha256": batch_sha256, "count": count}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Batch:
    def __init__(self, source, items):
        self.source, self.items = source, items                                   # items: [(id, seq, sha256, size)]
        self.batch_sha256 = _sha(b"VEGA-DATA-BATCH-1\n" + "\n".join("%d:%s" % (i[1], i[2]) for i in items).encode("ascii"))
        self.count = len(items)
        self.state = "open"

    def params(self) -> dict:
        return batch_params(self.source, self.batch_sha256, self.count)


class DataAirlock:
    def __init__(self, dag, commit, hold_dir, clock=time.time):
        self.dag, self.commit, self._clock = dag, commit, clock
        self.hold_dir = pathlib.Path(hold_dir)
        self.hold_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._rules, self._validators, self._seq, self._items, self._held_bytes = {}, {}, {}, {}, 0

    # ---- the human's side ---------------------------------------------------------------------------------------------
    def register_validator(self, name: str, fn):
        """A deterministic check (bytes -> True/False) that a collection may name. Code you supply and trust; it must never call a model."""
        if not isinstance(name, str) or not name or not callable(fn):
            raise DataAirlockRefused("a validator has a name and a function")
        self._validators[name] = fn

    def authorize_collection(self, source, window_seconds, max_items, max_bytes, signed, validator=""):
        self._check_source(source)
        for v, hi, nm in ((window_seconds, MAX_WINDOW, "window_seconds"), (max_items, MAX_ITEMS_CAP, "max_items"), (max_bytes, MAX_HELD_BYTES, "max_bytes")):
            if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= hi:
                raise DataAirlockRefused("%s is a whole number from 1 to %d" % (nm, hi))
        if not isinstance(validator, str) or len(validator) > 64:
            raise DataAirlockRefused("validator is a short name")
        params = collect_params(source, window_seconds, max_items, max_bytes, validator)
        with self._lock:
            try:
                out = self.commit.commit(COLLECT_ACTION, params, signed, route="human")
            except (CommitRefused, humanauth.HumanAuthError) as exc:
                raise DataAirlockRefused("collection refused: %s" % exc) from exc
            expires = int(self._clock()) + window_seconds
            self._rules[source] = {"expires_at": expires, "max_items": max_items, "max_bytes": max_bytes, "validator": validator, "items": 0, "bytes": 0}
            self._record("AIRLOCK_COLLECTION_AUTHORIZED", {"source": source, "params_sha256": humanauth.action_hash(params), "expires_at": expires, "approved_by": out["entry"]},
                         parents=[out["entry"]])
        return expires

    def batch(self, source: str, max_items: int = 10_000) -> Batch:
        """The items now held for `source` whose bodies are kept, in arrival order. The human reads preview() and signs batch.params()."""
        self._check_source(source)
        with self._lock:
            rows = sorted((r for r in self._items.values() if r["source"] == source and r["status"] == "held" and r["kept"]), key=lambda r: r["seq"])[:max_items]
            return Batch(source, [(r["id"], r["seq"], r["sha256"], r["size"]) for r in rows])

    def preview(self, batch: Batch, limit: int = 20, width: int = 120) -> list:
        """What the human reads: the first items as text (or a note for binary), with their sizes and hashes."""
        out = []
        for (iid, seq, sha, size) in batch.items[:limit]:
            body = self._read(iid)
            try:
                shown = body.decode("utf-8")[:width]
            except UnicodeDecodeError:
                shown = "[binary]"
            out.append({"seq": seq, "size": size, "sha256": sha, "text": shown})
        return out

    def release_batch(self, batch: Batch, signed: dict) -> list:
        """Hands on exactly this batch, once, if the human signed its hash. Returns [(seq, bytes)]."""
        with self._lock:
            if batch.state != "open":
                raise DataAirlockRefused("this batch was already released")
            bodies = []
            for (iid, seq, sha, size) in batch.items:
                rec = self._items.get(iid)
                if rec is None or rec["status"] != "held" or not rec["kept"]:
                    raise DataAirlockRefused("an item of this batch is no longer held: build a new batch")
                body = self._read(iid)
                if _sha(body) != sha:
                    raise DataAirlockRefused("a held item no longer matches its recorded hash: nothing released")
                bodies.append((seq, body))
            try:
                out = self.commit.commit(RELEASE_ACTION, batch.params(), signed, route="human")
            except (CommitRefused, humanauth.HumanAuthError) as exc:
                raise DataAirlockRefused("release refused: %s" % exc) from exc
            self._record("AIRLOCK_BATCH_RELEASED", {"source": batch.source, "batch_sha256": batch.batch_sha256, "count": batch.count, "approved_by": out["entry"]}, parents=[out["entry"]])
            for (iid, _seq, _sha_, _size) in batch.items:
                self._items[iid]["status"] = "released"
            batch.state = "released"
            return bodies

    # ---- the arriving side ----------------------------------------------------------------------------------------------
    def receive(self, source: str, payload) -> dict:
        """Everything outside sends goes through here. Returns {"status": "ADMITTED", "id", "data"} or {"status": "HELD", "id", "reason"}. The chain is written BEFORE anything is stored or handed on."""
        self._check_source(source)
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        if not isinstance(payload, (bytes, bytearray)):
            raise DataAirlockRefused("data is bytes or text")
        payload = bytes(payload)
        sha, size = _sha(payload), len(payload)
        with self._lock:
            seq = self._seq.get(source, 0) + 1
            admit, reason = self._decide(source, payload, size)
            keep = (not admit) and size <= MAX_ITEM and self._held_bytes + size <= MAX_HELD_BYTES
            iid = _sha(("%s|%d|%s" % (source, seq, sha)).encode("utf-8"))[:24]
            self._record("AIRLOCK_DATA_RECORDED", {"id": iid, "source": source, "seq": seq, "sha256": sha, "size": size, "status": "admitted" if admit else "held",
                                                  "reason": reason, "body_kept": bool(keep), "at": int(self._clock())})
            self._seq[source] = seq
            rec = {"id": iid, "source": source, "seq": seq, "sha256": sha, "size": size, "status": "admitted" if admit else "held", "kept": bool(keep)}
            self._items[iid] = rec
            if admit:
                rule = self._rules[source]
                rule["items"] += 1
                rule["bytes"] += size
                return {"status": "ADMITTED", "id": iid, "data": payload}
            if keep:
                (self.hold_dir / iid).write_bytes(payload)
                self._held_bytes += size
            return {"status": "HELD", "id": iid, "reason": reason}

    # ---- internals -------------------------------------------------------------------------------------------------------
    def _decide(self, source, payload, size):
        rule = self._rules.get(source)
        if rule is None:
            return False, "no_collection_authority"
        if int(self._clock()) >= rule["expires_at"]:
            return False, "collection_window_over"
        if rule["items"] >= rule["max_items"]:
            return False, "item_limit_reached"
        if rule["bytes"] + size > rule["max_bytes"] or size > MAX_ITEM:
            return False, "byte_limit_reached"
        if rule["validator"]:
            fn = self._validators.get(rule["validator"])
            if fn is None:
                return False, "validator_missing"
            try:
                if fn(payload) is not True:
                    return False, "validator_refused"
            except Exception:  # noqa: BLE001 - a validator that fails has not accepted the data
                return False, "validator_refused"
        return True, "within_collection_authority"

    def _read(self, iid):
        try:
            return (self.hold_dir / iid).read_bytes()
        except OSError as exc:
            raise DataAirlockRefused("a held item could not be read") from exc

    def _record(self, kind, payload, parents=None):
        try:
            self.dag.record(kind, payload, parents)
        except DagError as exc:
            raise DataAirlockRefused("could not record: nothing stored or handed on (%s)" % type(exc).__name__) from exc

    @staticmethod
    def _check_source(source):
        if not isinstance(source, str) or not _SOURCE.fullmatch(source):
            raise DataAirlockRefused("a source is a short plain id")
