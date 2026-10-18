"""quarantine.py - inbound artifacts are tested in a guinea-pig quarantine BEFORE they are adopted, then enter the
same fixed PAREAH sequence as everything else. (Disclosed: 64-023044 Sec.4; 64-049609 New Agent Vetting.)

What this does:
  1. reads the artifact ONCE (size-capped) and works only on those bytes: the bytes scanned are the bytes hashed are the bytes run (a file swapped after the scan cannot be what executes)
  2. STRICT static scan (default): an ALLOW-LIST of pure-computation imports; anything else is refused. Also refused: open/eval/exec/compile/getattr/setattr/globals/vars/__import__,
     and any dunder attribute that reaches the interpreter's internals (__class__, __subclasses__, __globals__, ...). Blocks the usual escapes (importlib, os, builtins tricks).
  3. runs the probe in a separate interpreter (isolated mode, no site-packages) with a stripped environment, a throwaway folder, a wall-clock limit, bounded output and a verified kill of the whole tree
  4. records the verdict and the artifact hash to the DAG either way
loose=True keeps the old deny-list (known-bad names only). It is easy to bypass and requires acknowledge_host_risk=True.

HONEST LIMIT: this is a speed bump plus process control, NOT an operating-system sandbox. A scan cannot prove arbitrary code safe and the probe runs on the host with this user's rights
(it can still read files and use the network if the scan was fooled). For code you believe hostile, run the whole quarantine inside a VM or container."""
import ast
import hashlib
import os
import pathlib
import shutil
import sys
import tempfile

from vega_custody import proc
from vega_pareah.adapter import adapter_card  # noqa: E402
from vega_pareah.cards import license_policy  # noqa: E402

ALLOWED_IMPORTS = frozenset({"math", "cmath", "json", "re", "hashlib", "hmac", "base64", "binascii", "string", "textwrap", "typing", "dataclasses", "collections",
                             "itertools", "functools", "operator", "enum", "abc", "copy", "heapq", "bisect", "decimal", "fractions", "statistics", "random", "datetime",
                             "uuid", "struct", "zlib", "unicodedata", "difflib", "pprint", "numbers", "contextlib", "time", "__future__"})
FORBIDDEN_NAMES = frozenset({"open", "eval", "exec", "compile", "__import__", "globals", "locals", "vars", "getattr", "setattr", "delattr", "input", "breakpoint", "help",
                             "exit", "quit", "memoryview", "__builtins__", "__loader__", "__spec__"})
ALLOWED_DUNDER_ATTRS = frozenset({"__name__", "__doc__"})
# the old deny-list, kept for loose=True
FORBIDDEN_IMPORTS = {"socket", "subprocess", "ctypes", "winreg", "multiprocessing", "pty", "pickle", "marshal", "urllib", "http", "requests", "ftplib", "smtplib", "telnetlib", "shutil"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {("os", "system"), ("os", "popen"), ("os", "remove"), ("os", "unlink"), ("os", "rmdir"), ("os", "execv"), ("os", "execve"), ("os", "spawnv")}
OUTPUT_CAP = 64 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024


class QuarantineDenied(Exception):
    pass


def static_scan(source: str, loose: bool = False) -> list:
    findings = []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return [f"does not parse: {type(exc).__name__}"]
    for n in ast.walk(tree):
        if loose:
            if isinstance(n, ast.Import):
                findings += [f"line {n.lineno}: imports {a.name}" for a in n.names if a.name.split(".")[0] in FORBIDDEN_IMPORTS]
            elif isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] in FORBIDDEN_IMPORTS:
                findings.append(f"line {n.lineno}: imports from {n.module}")
            elif isinstance(n, ast.Call):
                f = n.func
                if isinstance(f, ast.Name) and f.id in FORBIDDEN_CALLS:
                    findings.append(f"line {n.lineno}: calls {f.id}()")
                elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and (f.value.id, f.attr) in FORBIDDEN_ATTRS:
                    findings.append(f"line {n.lineno}: calls {f.value.id}.{f.attr}()")
            continue
        if isinstance(n, ast.Import):
            findings += [f"line {n.lineno}: imports {a.name} (not on the allow-list)" for a in n.names if a.name.split(".")[0] not in ALLOWED_IMPORTS]
        elif isinstance(n, ast.ImportFrom):
            if n.level or (n.module or "").split(".")[0] not in ALLOWED_IMPORTS:
                findings.append(f"line {n.lineno}: imports from {'.' * n.level}{n.module or ''} (not on the allow-list)")
        elif isinstance(n, ast.Name) and n.id in FORBIDDEN_NAMES:
            findings.append(f"line {n.lineno}: uses {n.id}")
        elif isinstance(n, ast.Attribute):
            if n.attr.startswith("__") and n.attr.endswith("__") and n.attr not in ALLOWED_DUNDER_ATTRS:
                findings.append(f"line {n.lineno}: reaches interpreter internals via .{n.attr}")
            elif n.attr in FORBIDDEN_NAMES:
                findings.append(f"line {n.lineno}: uses .{n.attr}")
        elif isinstance(n, (ast.Global, ast.Nonlocal)) and False:
            pass
    return findings


def _probe(data: bytes, timeout: float) -> dict:
    work = pathlib.Path(tempfile.mkdtemp(prefix="vega_quarantine_"))
    try:
        (work / "artifact.py").write_bytes(data)                         # the exact bytes that were scanned and hashed
        env = {"PYTHONIOENCODING": "utf-8", "TEMP": str(work), "TMP": str(work)}
        if os.environ.get("SYSTEMROOT"):
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]  # Windows needs it to start Python
        r = proc.run_bounded([sys.executable, "-I", "-S", str(work / "artifact.py")], timeout=timeout, cap=OUTPUT_CAP, cwd=work, env=env)
        if r["status"] == "timeout":
            return {"ok": False, "reason": f"timed out after {timeout}s", "kill_confirmed": r["kill_confirmed"]}
        if r["status"] == "overflow":
            return {"ok": False, "reason": f"output over cap {OUTPUT_CAP}", "kill_confirmed": r["kill_confirmed"]}
        return {"ok": r["returncode"] == 0, "reason": f"exit code {r['returncode']}", "exit": r["returncode"]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
        leftover = work.exists()
        if leftover:                                                     # residue is a finding, not a silent success
            sys.stderr.write(f"quarantine: working folder could not be removed: {work}\n")


def quarantine_then_adopt(artifact_path, adapter_id: str, kind: str, capabilities, license_class: str,
                          dag, reference_uri: str = None, timeout: float = 10.0, loose: bool = False, acknowledge_host_risk: bool = False) -> dict:
    """Returns an adapter card ready for PAREAH, or raises QuarantineDenied. Either way the verdict is recorded."""
    if loose and not acknowledge_host_risk:
        raise QuarantineDenied("loose scanning is a known-bypassable deny-list: pass acknowledge_host_risk=True to accept that the probe may run hostile code on this host")
    path = pathlib.Path(artifact_path)
    with open(path, "rb") as fh:
        data = fh.read(MAX_ARTIFACT_BYTES + 1)                           # one read; everything below uses these bytes
    if len(data) > MAX_ARTIFACT_BYTES:
        dag.record("QUARANTINE_VERDICT", {"artifact_sha256": hashlib.sha256(data).hexdigest(), "adapter_id": str(adapter_id), "verdict": "DENY",
                                          "findings": [f"artifact over {MAX_ARTIFACT_BYTES} bytes"], "probe": "not run", "license_class": license_class, "policy": license_policy.policy_for(license_class)})
        raise QuarantineDenied(f"{adapter_id}: artifact over {MAX_ARTIFACT_BYTES} bytes")
    sha = hashlib.sha256(data).hexdigest()
    findings = static_scan(data.decode("utf-8", errors="replace"), loose=loose)
    probe = {"ok": False, "reason": "not run: static scan failed"} if findings else _probe(data, timeout)
    policy = license_policy.policy_for(license_class)
    verdict = "ALLOW" if (not findings and probe["ok"]) else "DENY"
    dag.record("QUARANTINE_VERDICT", {"artifact_sha256": sha, "adapter_id": str(adapter_id), "verdict": verdict, "scan_mode": "loose" if loose else "strict",
                                      "findings": findings, "probe": probe["reason"], "license_class": license_class, "policy": policy})
    if verdict == "DENY":
        raise QuarantineDenied(f"{adapter_id}: {findings or probe['reason']}")
    return adapter_card.mint_adapter_card(adapter_id, kind, capabilities, sha, license_class, reference_uri)
