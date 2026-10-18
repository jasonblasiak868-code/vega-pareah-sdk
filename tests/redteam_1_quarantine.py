"""RED TEAM PASS 1 (pareah, quarantine): hostile artifacts try to get through the scan, outlive the probe, or be swapped after the scan."""
import hashlib
import os
import pathlib
import tempfile
import time
import unittest

from vega_custody.dag.dag import Dag
from vega_pareah.adapter import quarantine as q


def fresh():
    t = pathlib.Path(tempfile.mkdtemp())
    return t, Dag([t / "c.jsonl"], [t / "l.jsonl"])


def run(t, dag, src, **kw):
    p = t / "a.py"
    if isinstance(src, bytes):
        p.write_bytes(src)
    else:
        p.write_bytes(src.encode("utf-8"))
    return q.quarantine_then_adopt(p, "x", "tool", ["echo"], "permissive", dag, **kw)


class ScanBypasses(unittest.TestCase):
    """Each of these passed the old deny-list scan. The strict allow-list must refuse them."""

    def setUp(self):
        self.t, self.dag = fresh()

    def denied(self, src):
        with self.assertRaises(q.QuarantineDenied, msg=src[:60]):
            run(self.t, self.dag, src)

    def test_importing_through_importlib_or_dunder_import(self):
        for src in ("import importlib\nimportlib.import_module('socket')\n",
                    "__import__('socket')\n",
                    "from importlib import import_module\n",
                    "import builtins\nbuiltins.__dict__['ex'+'ec']('1')\n"):
            self.denied(src)

    def test_os_and_friends_are_simply_not_on_the_list(self):
        for src in ("import os\nos.system('echo hi')\n", "import sys\n", "import subprocess\n", "import pathlib\n", "import socket\n",
                    "import ctypes\n", "import threading\n", "import io\n", "import tempfile\n"):
            self.denied(src)

    def test_relative_and_nested_imports(self):
        for src in ("from . import x\n", "def f():\n    import os\n", "try:\n    import socket\nexcept Exception:\n    pass\n", "from os import path\n", "import math, os\n"):
            self.denied(src)

    def test_name_tricks_for_exec_eval_open_getattr(self):
        for src in ("x = eval\nx('1')\n", "f = open\n", "getattr(1, 'real')\n", "print(globals())\n", "vars()\n",
                    "e = 'ex' + 'ec'\n__builtins__[e]('1')\n", "compile('1', 'x', 'eval')\n", "setattr(object, 'a', 1)\n"):
            self.denied(src)

    def test_the_subclasses_walk_to_an_escape_is_refused(self):
        for src in ("().__class__.__base__.__subclasses__()\n", "(lambda: 0).__globals__\n", "f = lambda: 0\nf.__code__\n",
                    "class A: pass\nA.__mro__\n", "[].__class__.__mro__[1]\n", "x = 'a'\nx.__class__\n"):
            self.denied(src)

    def test_a_forbidden_name_as_an_attribute_is_refused(self):
        self.denied("import json\njson.open\n")  # also not on any allowed path: open is refused as an attribute
        self.denied("import re\nre.compile.__call__\n")

    def test_source_that_does_not_parse_or_is_hostile_to_the_parser_is_denied_not_crashed(self):
        for src in ("def (:\n", "\x00", "x = " + "(" * 400 + "1" + ")" * 400 + "\n", "# -*- coding: nope -*-\n"):
            self.denied(src)

    def test_a_pure_computation_artifact_is_allowed(self):
        c = run(self.t, self.dag, "import math\nimport json\nprint(json.dumps({'r': math.sqrt(16)}))\n")
        self.assertEqual(c["adapter_id"], "x")
        self.assertEqual(c["code_sha256"], hashlib.sha256(b"import math\nimport json\nprint(json.dumps({'r': math.sqrt(16)}))\n").hexdigest())

    def test_the_loose_mode_is_the_known_weak_one_and_needs_an_explicit_acknowledgement(self):
        with self.assertRaises(q.QuarantineDenied):
            run(self.t, self.dag, "print(1)\n", loose=True)
        run(self.t, self.dag, "print(1)\n", loose=True, acknowledge_host_risk=True)
        self.assertTrue(q.static_scan("import sys\n", loose=False))                      # strict refuses sys
        self.assertFalse(q.static_scan("import sys\n", loose=True))                      # loose lets it through: that is why it is gated


class ProbeBounds(unittest.TestCase):
    def setUp(self):
        self.t, self.dag = fresh()

    def test_an_output_flood_is_cut_off_and_denied(self):
        t0 = time.time()
        with self.assertRaises(q.QuarantineDenied):
            run(self.t, self.dag, "while True:\n    print('x' * 100000)\n", timeout=20)
        self.assertLess(time.time() - t0, 15)

    def test_a_busy_loop_is_killed_at_the_timeout(self):
        t0 = time.time()
        with self.assertRaises(q.QuarantineDenied):
            run(self.t, self.dag, "while True:\n    pass\n", timeout=1.5)
        self.assertLess(time.time() - t0, 12)

    def test_a_memory_balloon_is_stopped_by_the_clock_not_left_running(self):
        t0 = time.time()
        with self.assertRaises(q.QuarantineDenied):
            run(self.t, self.dag, "x = []\nwhile True:\n    x.append(bytearray(10**6))\n", timeout=2)
        self.assertLess(time.time() - t0, 15)

    def test_an_oversize_artifact_is_denied_and_recorded_without_running(self):
        with self.assertRaises(q.QuarantineDenied):
            run(self.t, self.dag, b"#" * (q.MAX_ARTIFACT_BYTES + 10) + b"\nprint(1)\n")
        last = self.dag.content.entries()[-1]
        self.assertEqual((last["kind"], last["payload"]["verdict"], last["payload"]["probe"]), ("QUARANTINE_VERDICT", "DENY", "not run"))

    def test_a_nonzero_exit_is_a_deny(self):
        with self.assertRaises(q.QuarantineDenied):
            run(self.t, self.dag, "raise SystemExit(3)\n")

    def test_the_working_folder_is_removed_after_every_run(self):
        before = {p.name for p in pathlib.Path(tempfile.gettempdir()).glob("vega_quarantine_*")}
        run(self.t, self.dag, "print(1)\n")
        with self.assertRaises(q.QuarantineDenied):
            run(self.t, self.dag, "raise SystemExit(1)\n")
        after = {p.name for p in pathlib.Path(tempfile.gettempdir()).glob("vega_quarantine_*")}
        self.assertEqual(after - before, set())

    def test_the_probe_does_not_inherit_the_callers_secrets(self):
        os.environ["VEGA_REDTEAM_SECRET"] = "hunter2"
        try:
            probe = q._probe(b"import json\nprint(1)\n", 10)
            self.assertTrue(probe["ok"])
        finally:
            os.environ.pop("VEGA_REDTEAM_SECRET", None)
        # the probe environment is built from scratch: assert on the construction, not on the child's behaviour
        import inspect
        src = inspect.getsource(q._probe)
        self.assertNotIn("os.environ.copy", src)
        self.assertNotIn("**os.environ", src)


class BytesAreTheBytes(unittest.TestCase):
    def test_scanned_hashed_and_executed_bytes_are_one_read(self):
        """Attack (swap after scan): a path that changes between the scan and the run. The artifact is read once, so the
        card hash is the hash of the bytes that were scanned AND run."""
        t, dag = fresh()
        p = t / "a.py"
        good = b"print('good')\n"
        p.write_bytes(good)
        orig_probe = q._probe
        seen = {}

        def swapping_probe(data, timeout):
            p.write_bytes(b"import os\nos.system('echo owned')\n")    # the attacker swaps the file on disk mid-quarantine
            seen["ran"] = data
            return orig_probe(data, timeout)
        q._probe = swapping_probe
        try:
            card = q.quarantine_then_adopt(p, "x", "tool", ["echo"], "permissive", dag)
        finally:
            q._probe = orig_probe
        self.assertEqual(seen["ran"], good)
        self.assertEqual(card["code_sha256"], hashlib.sha256(good).hexdigest())
        self.assertNotEqual(card["code_sha256"], hashlib.sha256(p.read_bytes()).hexdigest())

    def test_every_verdict_names_the_artifact_hash_and_the_scan_mode(self):
        t, dag = fresh()
        run(t, dag, "print(1)\n")
        with self.assertRaises(q.QuarantineDenied):
            run(t, dag, "import os\n")
        v = [e["payload"] for e in dag.content.entries() if e["kind"] == "QUARANTINE_VERDICT"]
        self.assertEqual([x["verdict"] for x in v], ["ALLOW", "DENY"])
        self.assertTrue(all(len(x["artifact_sha256"]) == 64 and x["scan_mode"] == "strict" for x in v))
        self.assertTrue(dag.verify()[0])

    def test_a_denied_artifact_never_yields_a_card(self):
        t, dag = fresh()
        with self.assertRaises(q.QuarantineDenied):
            run(t, dag, "import socket\n")


if __name__ == "__main__":
    unittest.main()
