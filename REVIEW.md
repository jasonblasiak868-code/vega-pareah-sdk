# REVIEW (automated), 2026-10-17T09:29:32

Repo: vega-pareah-sdk | python files 17 | seconds 19.1
Findings: high 0, medium 0, low 0, info 2
Tests: {"ran": true, "tests": 111, "ok": true, "redteam_files": {"1": 1, "2": 1}, "test_files": 4}
Network-capable modules imported: none

Limits: a clean scan is not proof of safety. Static rules are shallow; the copy check finds verbatim and light-edit copying against the 251-repo library only.

## info (2)
- `PY-SWALLOW-REVIEWED` src\vega_pareah\adapter\pareah.py:133 the refusal below is raised either way; a record that cannot be written never turns a denial into an allow
- `PY-SWALLOW-REVIEWED` src\vega_pareah\adapter\pareah.py:184 the connection is refused below either way; a missing abort record cannot open it

