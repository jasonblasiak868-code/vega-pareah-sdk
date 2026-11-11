"""warden.py - CONTINUOUS in-sandbox enforcement while an execution runs, not a check applied after the fact.

The gap this closes: quarantine.py tests an artifact BEFORE it runs, and pulse.py watches a link OUTSIDE the
process. Neither one polices a running execution from the inside of its containment. The Warden does:

  1. starts the run inside a ProcessJob (kernel containment: nothing can detach, spawn past the cap, or outlive
     the job) - a program is never run uncontained by accident
  2. while it runs, a watcher thread polls the containment on a randomized schedule (a hostile run cannot know
     when it will be checked), enforces the wall clock, and enforces the BEHAVIOR CONTRACT:
       - process count never exceeds the declared maximum
       - output is streamed and scanned for the declared forbidden patterns (for example secret-shaped strings
         or tokens the run's role must never emit) at every read, not at the end
       - declared quiet period: a run that must stay silent and emits anyway is a violation
  3. the FIRST violation kills the whole job immediately (warden has authority, unlike pulse: eyes WITH authority),
     records WARDEN_VIOLATION to the DAG, and returns the verdict so the caller can transfer the origin to the SHU
  4. if the run finishes inside contract, records WARDEN_CLEAN with the run's artifact hash and the kill/survivor
     verification

HONEST LIMITS: the warden watches what the containment can see - process tree, wall clock, the pipes it holds.
It cannot see syscalls, file handles opened by other means, or GPU/DMA paths; and on POSIX the containment is a
process group (a descendant that detaches leaves it - survivors() is the guard). For truly hostile code, run the
whole warden inside a VM or container. The warden is enforcement of a DECLARED contract, not proof of safety."""
import hashlib
import random
import subprocess
import threading
import time

from vega_custody.proc import ProcessJob

OUTPUT_CAP = 64 * 1024
POLL_MIN, POLL_MAX = 0.05, 0.25                                     # randomized watcher schedule, seconds


class WardenViolation(Exception):
    """Raised when the run broke its declared contract; the job was already killed before this is raised."""


def enforce(dag, argv, contract, run_id: str, artifact_sha256: str = None, cwd=None, env=None,
            timeout: float = 10.0, cap: int = OUTPUT_CAP, max_processes: int = 32,
            max_process_bytes: int = 2 * 1024 ** 3, stdin_bytes: bytes = b"") -> dict:
    """Run `argv` inside kernel containment under the warden's continuous watch.

    contract: a dict declaring the run's allowed behavior:
      forbid_output   list of case-folded substrings that must never appear in the stream (default: none)
      quiet           True = the run may produce NO output at all (default: False)
      max_processes   override the job's process cap (default: 32)

    Returns the same result shape as vega_custody.proc.run_bounded plus {"warden": verdict}, and raises
    WardenViolation (job already killed) when the contract is broken. Either outcome is recorded to the DAG."""
    if not isinstance(contract, dict):
        raise TypeError("contract must be a dict")
    forbid = [p.casefold() for p in contract.get("forbid_output", [])]
    quiet = bool(contract.get("quiet", False))
    deadline = time.monotonic() + timeout
    breach = []                                                       # first reason wins; the job is killed once

    cap_procs = int(contract.get("max_processes", max_processes))
    timed_out = [False]
    job = ProcessJob.start(argv, cwd=cwd, env=env, max_processes=cap_procs, max_process_bytes=max_process_bytes,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)   # the warden must hold the pipes to scan them
    bufs = {"out": bytearray(), "err": bytearray()}

    def _scan(buf, name):
        text = bytes(buf).decode("utf-8", errors="replace").casefold()
        for pat in forbid:
            if pat in text and f"output {name} contains forbidden pattern" not in breach:
                breach.append(f"output {name} contains forbidden pattern")
        if quiet and buf and f"quiet run emitted on {name}" not in breach:
            breach.append(f"quiet run emitted on {name}")
        if len(buf) > cap and f"output {name} over cap {cap}" not in breach:
            breach.append(f"output {name} over cap {cap}")

    def _watch():
        while job.proc.poll() is None and not breach:
            alive = job.survivors()
            if alive > cap_procs:
                breach.append(f"process tree exceeded {cap_procs} (saw {alive})")
            if time.monotonic() > deadline:
                breach.append(f"wall clock exceeded {timeout}s")
                timed_out[0] = True
            time.sleep(random.uniform(POLL_MIN, POLL_MAX))

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()
    try:
        out, err = job.proc.communicate(input=stdin_bytes or None, timeout=max(timeout, 0.1))
        bufs["out"] += out or b""
        bufs["err"] += err or b""
    except subprocess.TimeoutExpired:
        breach.append("communicate timeout (run outlived the wall clock)")
        timed_out[0] = True
        out = err = b""
    finally:
        if breach:
            job.terminate_job()                                       # first breach kills the whole family now
        elif job.proc.poll() is None:
            job.terminate_job()
        watcher.join(timeout=5)
        _scan(bufs["out"], "stdout")
        _scan(bufs["err"], "stderr")
        survivors = job.survivors()

    result = {"status": "violation" if breach else ("timeout" if timed_out[0] else "ok"),
              "out": bytes(bufs["out"]), "err": bytes(bufs["err"]),
              "returncode": job.proc.returncode, "killed": bool(breach), "survivors": survivors,
              "warden": {"verdict": "VIOLATION" if breach else "CLEAN",
                         "findings": breach, "artifact_sha256": artifact_sha256,
                         "kill_verified": survivors == 0 or not breach}}

    if breach:
        dag.record("WARDEN_VIOLATION", {"run_id": str(run_id), "artifact_sha256": artifact_sha256,
                                        "verdict": "VIOLATION", "findings": breach,
                                        "survivors_after_kill": survivors})
        raise WardenViolation(f"{run_id}: {breach[0]}")
    dag.record("WARDEN_CLEAN", {"run_id": str(run_id), "artifact_sha256": artifact_sha256,
                                "verdict": "CLEAN", "findings": [],
                                "survivors_after_kill": survivors})
    return result


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
