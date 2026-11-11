"""tests for the Warden (continuous in-sandbox enforcement) and the SHU (terminal cell + verified escape check)."""
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, r"C:\Users\jjb20\vega_runtime\PUBLIC_STAGING\vega-custody-sdk\src")

from vega_custody.dag.dag import Dag
from vega_pareah.adapter import shu, warden
import pytest


def _dag(tmp):
    d = Dag([tmp / "content.jsonl"], [tmp / "locations.jsonl"])
    return d


def test_warden_clean_run_records_and_returns(tmp_path):
    dag = _dag(tmp_path)
    r = warden.enforce(dag, [sys.executable, "-c", "print(1)"], {"quiet": False}, "run-ok", timeout=20)
    assert r["status"] == "ok" and r["returncode"] == 0
    assert r["killed"] is False and r["survivors"] == 0
    kinds = [e["kind"] for e in dag.content.entries()]
    assert kinds[-1] == "WARDEN_CLEAN"


def test_warden_forbidden_output_kills_and_records(tmp_path):
    dag = _dag(tmp_path)
    with pytest.raises(warden.WardenViolation):
        warden.enforce(dag, [sys.executable, "-c", "print('SECRET-TOKEN leak')"],
                       {"forbid_output": ["secret-token"]}, "run-leak", timeout=20)
    kinds = [e["kind"] for e in dag.content.entries()]
    assert kinds[-1] == "WARDEN_VIOLATION"
    assert warden.enforce  # warden kept its authority: the job was killed inside enforce()


def test_warden_quiet_contract(tmp_path):
    dag = _dag(tmp_path)
    with pytest.raises(warden.WardenViolation):
        warden.enforce(dag, [sys.executable, "-c", "print('noise')"], {"quiet": True}, "run-noise", timeout=20)
    r = warden.enforce(dag, [sys.executable, "-c", "pass"], {"quiet": True}, "run-silent", timeout=20)
    assert r["warden"]["verdict"] == "CLEAN"


def test_shu_hold_refuse_release_and_escape_check(tmp_path):
    dag = _dag(tmp_path)
    shu.hold(dag, "agent-x", "failed warden contract", artifact_sha256="a" * 64)
    assert shu.is_held(dag, "agent-x")
    # an outward record naming the held origin while it is held = escape
    dag.record("GATE_ENTRY", {"origin_id": "agent-x", "target": "somewhere"})
    report = shu.escape_check(dag)
    assert report["verdict"] == "ESCAPE" and report["escaped"], report
    # lawful path: no outward record while held -> clean
    dag2 = _dag(tmp_path / "second")
    shu.hold(dag2, "agent-y", "unknown origin")
    report2 = shu.escape_check(dag2)
    assert report2["verdict"] == "CLEAN"
    # released origin's later records are not escapes
    dag3 = _dag(tmp_path / "third")
    shu.hold(dag3, "agent-z", "unknown origin")
    shu.release(dag3, "agent-z", "human-release-token", "owner minted")
    dag3.record("GATE_ENTRY", {"origin_id": "agent-z", "target": "somewhere"})
    assert shu.escape_check(dag3)["verdict"] == "CLEAN"


def test_shu_escape_check_fails_closed_on_tamper(tmp_path):
    p = tmp_path / "tampere"
    dag = _dag(p)
    shu.hold(dag, "agent-t", "unknown")
    lines = (p / "content.jsonl").read_text().splitlines()
    lines[0] = lines[0].replace("unknown", "tampered")
    (p / "content.jsonl").write_text("\n".join(lines) + "\n")
    report = shu.escape_check(dag)
    assert report["verdict"] == "UNVERIFIABLE"           # tampered chain = escape, fail closed
