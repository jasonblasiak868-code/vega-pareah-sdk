"""peak.py - the PEAK card: a frozen, committed DAG job. The steps, their parameter hashes, their dependencies
and the PRE it runs under are fixed at freeze time and hashed into one dag_hash. At run time nothing can be
added, reordered or altered: a step whose parameters differ from the frozen hash is refused, and the first
failure stops the whole job (hard stop). HUMAN_ONLY actions cannot be inside a frozen job (checked at freeze AND at run).
Malformed or hostile PEAK data is a PeakRefused, never a raw KeyError or TypeError."""
import hashlib
import json

from vega_jacket import humanauth  # noqa: E402
from vega_pareah.cards import _common as cm  # noqa: E402
from vega_pareah.cards import pre as pre_mod  # noqa: E402


class PeakRefused(Exception):
    pass


def _canon(o) -> bytes:
    try:
        return json.dumps(o, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PeakRefused(f"value cannot be canonicalised: {type(exc).__name__}") from exc


def params_sha(params: dict) -> str:
    if not isinstance(params, dict):
        raise PeakRefused("step parameters must be an object")
    return hashlib.sha256(_canon(params)).hexdigest()


def _check_step(s):
    if not isinstance(s, dict):
        raise PeakRefused("a step is an object")
    for f in ("id", "action", "resource", "deps"):
        if f not in s:
            raise PeakRefused(f"step missing {f}")
    if not isinstance(s["id"], str) or not s["id"] or not isinstance(s["action"], str) or not s["action"]:
        raise PeakRefused("step id and action must be non-empty strings")
    if humanauth.is_human_only(s["action"]):
        raise PeakRefused(f"HUMAN_ONLY action {s['action']!r} cannot be part of a frozen job")
    if "*" in s["action"] or not cm.resource_ok(s["resource"]):
        raise PeakRefused(f"step {s['id']}: bad action or resource")
    if isinstance(s["deps"], (str, bytes)) or not isinstance(s["deps"], (list, tuple)) or any(not isinstance(d, str) for d in s["deps"]):
        raise PeakRefused(f"step {s['id']}: deps must be a list of step ids")
    if s["id"] in s["deps"]:
        raise PeakRefused(f"step {s['id']} depends on itself")


def _order(steps):
    if isinstance(steps, (str, bytes)) or not isinstance(steps, (list, tuple)) or not steps:
        raise PeakRefused("a PEAK needs a non-empty list of steps")
    for s in steps:
        _check_step(s)
    ids = {s["id"] for s in steps}
    if len(ids) != len(steps):
        raise PeakRefused("duplicate step id")
    done, order, left = set(), [], list(steps)
    while left:
        ready = [s for s in left if all(d in done for d in s["deps"])]
        if not ready:
            raise PeakRefused("cycle or missing dependency in the job DAG")
        for s in sorted(ready, key=lambda s: s["id"]):
            order.append(s["id"])
            done.add(s["id"])
            left.remove(s)
    return order


def freeze(steps, pre_hash: str) -> dict:
    """steps: list of {id, action, resource, params, deps}. Parameters are hashed, not stored."""
    cm.need_hex64(pre_hash, "pre_hash", PeakRefused)
    if isinstance(steps, (str, bytes)) or not isinstance(steps, (list, tuple)):
        raise PeakRefused("steps must be a list")
    frozen = []
    for s in steps:
        _check_step({"deps": [], **s} if isinstance(s, dict) else s)
        frozen.append({"id": s["id"], "action": s["action"], "resource": s["resource"],
                       "params_sha256": params_sha(s["params"]) if "params" in s else params_sha({}), "deps": sorted(s.get("deps", []))})
    order = _order(frozen)
    peak = {"kind": "PEAK", "pre_hash": pre_hash, "steps": frozen, "order": order}
    peak["dag_hash"] = hashlib.sha256(_canon(peak)).hexdigest()
    return peak


def verify_peak(peak: dict) -> None:
    if not isinstance(peak, dict) or peak.get("kind") != "PEAK" or not isinstance(peak.get("dag_hash"), str):
        raise PeakRefused("not a PEAK")
    body = {k: v for k, v in peak.items() if k != "dag_hash"}
    if hashlib.sha256(_canon(body)).hexdigest() != peak["dag_hash"]:
        raise PeakRefused("PEAK altered after freeze")
    steps = peak.get("steps")
    for s in steps if isinstance(steps, (list, tuple)) else ():
        if isinstance(s, dict):
            cm.need_hex64(s.get("params_sha256"), "params_sha256", PeakRefused)
    if _order(steps) != peak.get("order"):
        raise PeakRefused("PEAK order does not match its DAG")


def run(peak: dict, pre_card: dict, executors: dict, params_by_step: dict, dag) -> dict:
    verify_peak(peak)
    try:
        pre_mod.verify_pre(pre_card)
    except pre_mod.PreRefused as exc:
        raise PeakRefused(f"PRE refused: {exc}") from exc
    if pre_card["card_hash"] != peak["pre_hash"]:
        raise PeakRefused("PEAK was frozen under a different PRE")
    if not isinstance(executors, dict) or not isinstance(params_by_step, dict):
        raise PeakRefused("executors and params_by_step must be objects")
    by_id = {s["id"]: s for s in peak["steps"]}
    start = dag.record("PEAK_START", {"dag_hash": peak["dag_hash"], "pre_hash": peak["pre_hash"]})
    last, outputs = start["entry_hash"], {}
    for sid in peak["order"]:
        s = by_id[sid]
        try:
            if sid not in params_by_step or params_sha(params_by_step[sid]) != s["params_sha256"]:
                raise PeakRefused(f"step {sid}: parameters differ from the frozen job")
            if not pre_mod.permits(pre_card, s["action"], s["resource"]):
                raise PeakRefused(f"step {sid}: PRE does not permit {s['action']} on {s['resource']}")
            if s["action"] not in executors:
                raise PeakRefused(f"step {sid}: no executor for {s['action']}")
            out = executors[s["action"]](params_by_step[sid])
            out_sha = hashlib.sha256(repr(out).encode("utf-8")).hexdigest()
        except Exception as exc:
            dag.record("PEAK_ABORT", {"step": sid, "reason": f"{type(exc).__name__}: {exc}"}, parents=[last])
            if isinstance(exc, PeakRefused):
                raise
            raise PeakRefused(f"step {sid} failed, job stopped: {exc}") from exc
        outputs[sid] = out
        last = dag.record("PEAK_STEP", {"step": sid, "action": s["action"], "output_sha256": out_sha},
                          parents=[last])["entry_hash"]
    dag.record("PEAK_DONE", {"dag_hash": peak["dag_hash"], "steps": len(peak["order"])}, parents=[last])
    return outputs
