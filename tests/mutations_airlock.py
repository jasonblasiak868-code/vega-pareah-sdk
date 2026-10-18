"""Mutation check for the airlock: remove each protection in a COPY of the package and confirm redteam_3_airlock.py fails.
Run: source SDK_FAMILY/env_family.sh; python tests/mutations_airlock.py   (a mutation that does not fail the test SURVIVES: unprotected)"""
import os, pathlib, shutil, subprocess, sys, tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
A = "adapter/airlock.py"
P = "adapter/pareah.py"
MUTATIONS = [
    ("challenge is single use", A, "exp = self._challenges.pop(chal, None)", "exp = self._challenges.get(chal, None)"),
    ("signature must verify", A, 'return "bad_signature", pub', "pass"),
    ("card hash must match", A, 'if ann["card_hash"] and ann["card_hash"] != arrival["card_hash"]:', "if False:"),
    ("not-before is honoured", A, 'if now < ann["not_before"]:', "if False:"),
    ("ledger re-check at the door", A, 'if not self.ledger.verify(ann["commitment"]):', "if False:"),
    ("announcement burned on use", A, '                self._used.add(ann["id"])\n                self._ann.pop(ann["id"], None)\n', ""),
    ("room cap", A, "if len(self._rooms) >= MAX_ROOMS:", "if False:"),
    ("challenge cap", A, "while len(self._challenges) >= MAX_CHALLENGES:", "while False:"),
    ("room replies only from scenes", A, "reply = SCENES[self.scene % len(SCENES)]", "reply = text"),
    ("turn cap closes the room", A, "if self.turns >= MAX_TURNS:", "if False:"),
    ("credential-like text not kept", A, "short = None if contains_credential(text) else _clean(text)", "short = _clean(text)"),
    ("message size cap", A, "raw = bytes(raw[:MAX_MESSAGE])", "raw = bytes(raw)"),
    ("same key, same room", A, "room.restart_scene()\n            return", "return"),
    ("a burn that cannot be written means no entry", A, 'return self._trap(public, "record_failed")', 'return {"status": "EXPECTED", "announcement": ann["id"]}'),
    ("door identity cannot be an end", P, "if end_b.end_id == self.airlock.door_id or end_a.end_id == self.airlock.door_id:", "if False:"),
    ("trapped arrival raises", P, 'if verdict["status"] != "EXPECTED":', "if False:"),
    ("arrival must be the visitor end's", P, 'arrival.get("public") != end_a.public.hex()', "False"),
    ("door is fitted on every connect", P, "if self.airlock is not None:\n            self._door(end_a, end_b, arrival)", "pass"),
]

if __name__ != "__main__":
    MUTATIONS = []                       # importing this file (test discovery) must not start the mutation run
survivors = []
for name, fname, old, new in MUTATIONS:
    tmp = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(REPO / "src" / "vega_pareah", tmp / "vega_pareah")
    f = tmp / "vega_pareah" / fname
    text = f.read_text(encoding="utf-8")
    if old not in text:
        print("CANNOT APPLY", name)
        survivors.append(name + " (could not apply)")
        continue
    f.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run([sys.executable, "-W", "ignore", str(REPO / "tests" / "redteam_3_airlock.py")], capture_output=True, text=True, env=env, timeout=300)
    print(("killed   " if r.returncode != 0 else "SURVIVED ") + name)
    if r.returncode == 0:
        survivors.append(name)
    shutil.rmtree(tmp, ignore_errors=True)
print("survivors:", survivors or "none")
