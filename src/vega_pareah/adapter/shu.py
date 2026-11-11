"""shu.py - the Special Housing Unit: the terminal cell. What enters cannot leave on its own, and the property
"nothing ever escaped" is VERIFIED, not assumed.

What this does:
  1. hold()                - places an origin (agent, adapter, artifact hash) in the SHU: SHU_HOLD recorded to
                             the DAG with the reason and the artifact hash. From this moment the origin has no
                             route outward: the adapter's gate refuses any hand dealt for a held origin.
  2. is_held()             - the check the gate runs on every deal: is this origin currently held?
  3. escape_check()        - the verifier. Re-reads the DAG FROM DISK (trusts nothing in memory, same posture as
                             vega_custody Dag.verify) and looks for ANY record after the hold that was authored
                             by, names, or carries the hash of a held-and-not-released origin. Any such record
                             is an escape. The audit itself is recorded (SHU_ESCAPE_AUDIT), so a clean audit is
                             evidence and a dirty audit is an alarm that cannot be deleted - the chain is
                             append-only. A tampered/truncated chain is reported as UNVERIFIABLE, which is
                             treated as an escape (fail closed).
  4. release()             - ONLY a human-held release token moves an origin out: SHU_RELEASE carries the origin,
                             the release token, and the reason. The warden/gate still refuse held origins; the
                             release is the one and only door, and it is recorded.

HONEST LIMITS: escape_check proves no DAG record connects a held origin to an outward event. It cannot see
channels the DAG does not record (out-of-band writes made while the chain was paused). Pair it with the warden:
a held origin that runs at all must run under warden containment, and its kills/survivors are recorded, so the
unobservable window is bounded by the warden's own records."""
import hashlib
import json

HOLD, RELEASE, ESCAPE_AUDIT = "SHU_HOLD", "SHU_RELEASE", "SHU_ESCAPE_AUDIT"


def _sha(text) -> str:
    return hashlib.sha256(json.dumps(text, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def hold(dag, origin_id: str, reason: str, artifact_sha256: str = None) -> dict:
    """Place an origin in the SHU. From this record forward the gate must refuse the origin (is_held -> True)."""
    rec = {"origin_id": str(origin_id), "origin_hash": artifact_sha256 or _sha(origin_id),
           "reason": str(reason)}
    entry = dag.record(HOLD, rec)
    return entry


def is_held(dag, origin_id: str, as_of_entry_hash: str = None) -> bool:
    """True while the origin is held: a HOLD later than any RELEASE for it (order judged by seq in the chain)."""
    origin = str(origin_id)
    origin_hash = _sha(origin)
    last = None
    for e in (dag.content.entries() if hasattr(dag, "content") else dag.entries()):
        p = e.get("payload", {})
        if p.get("origin_id") == origin or p.get("origin_hash") in (origin_hash, origin):
            last = e["kind"]
    return last == HOLD


def release(dag, origin_id: str, release_token: str, reason: str) -> dict:
    """The one door out. release_token is human-held material: its hash is recorded, never the token itself."""
    entry = dag.record(RELEASE, {"origin_id": str(origin_id), "release_receipt_sha256": _sha(release_token),
                                 "origin_hash": _sha(origin_id), "reason": str(reason)})
    return entry


def escape_check(dag, origin_id: str = None, expected_head: str = None) -> dict:
    """Verify from disk that nothing held ever produced an outward record.

    origin_id=None audits EVERY held origin. Chain problems (tamper, truncation, replica disagreement) make the
    result UNVERIFIABLE, which callers must treat as an escape: fail closed. The audit verdict is recorded, so
    the evidence that the check ran - and what it found - is itself on the chain."""
    try:
        ok, problems = dag.content.verify(expected_head=expected_head)
    except AttributeError:                                                # a bare Chain was handed in
        ok, problems = dag.verify(expected_head=expected_head)
    except Exception as exc:                                              # unreadable ledger: fail closed
        ok, problems = False, [f"verify raised {type(exc).__name__}: {exc}"]
    if not ok:
        report = {"verdict": "UNVERIFIABLE", "problems": problems, "escaped": []}
        try:
            dag.record(ESCAPE_AUDIT, {"verdict": "UNVERIFIABLE", "problems": problems})
        except Exception:
            pass                                                          # chain is broken; report stands on its own
        return report

    reader = dag.content.read_primary if hasattr(dag, "content") else dag.read_primary
    rows = reader()
    holds, releases, escaped = {}, {}, []
    for e in rows:
        p = e.get("payload", {})
        oid = p.get("origin_id")
        if e["kind"] == HOLD and oid:
            holds[oid] = e
            releases.pop(oid, None)
        elif e["kind"] == RELEASE and oid:
            releases[oid] = e
    for oid, hold_e in holds.items():
        if oid in releases and releases[oid]["seq"] > hold_e["seq"]:
            continue                                                    # lawfully released after the hold
        origin_hash = hold_e["payload"].get("origin_hash")
        for e in rows:
            if e["seq"] <= hold_e["seq"] or e["kind"] in (HOLD, RELEASE, ESCAPE_AUDIT):
                continue
            p = e.get("payload", {})
            leaked = (p.get("origin_id") == oid or origin_hash in (p.get("origin_hash"),
                      p.get("artifact_sha256")))
            if origin_id and oid != origin_id:
                continue
            if leaked:
                escaped.append({"origin_id": oid, "entry_hash": e["entry_hash"],
                                "kind": e["kind"], "seq": e["seq"]})
    verdict = "CLEAN" if not escaped else "ESCAPE"
    report = {"verdict": verdict, "escaped": escaped, "held_audited": sorted(holds), "problems": []}
    dag.record(ESCAPE_AUDIT, {"verdict": verdict,
                              "escaped_count": len(escaped),
                              "held_audited": sorted(holds),
                              "escaped_entry_hashes": [x["entry_hash"] for x in escaped]})
    return report
