# vega-pareah-sdk — Capabilities

Minute capability inventory. Every capability of this repo stated as:
**capability** / **why a policy-or-prompt-level approach structurally cannot provide it** / **where enforced in this repo's code** / **which test demonstrates it** / **honest limit**.

## 1. Fixed six-step handshake sequence for every adapter

**Capability:** Every adapter connection runs exactly six steps in order: grant → handshake → union_commitment → adapter → sdk_wrap → gate. The order is a constant tuple (`pareah.STEPS`), not a parameter. Steps cannot be reordered, skipped, or replayed.

**Why policy/prompt cannot provide it:** A prompt or policy is a statement of intent. The model (or a steered model) can ignore, reorder, or skip steps. There is no mechanism in a prompt to enforce that step 3 cryptographically binds both ends with a human signature before step 4 runs, or that step 6 verifies the commitment is still alive in the ledger on every call.

**Where enforced:** `src/vega_pareah/adapter/pareah.py::Pareah.connect` — the `for step in STEPS:` loop is the only loop; order is the constant. Each step records `PAREAH_STEP` to the DAG; any exception records `PAREAH_ABORT` and fails closed.

**Test:** `tests/test_pareah.py::check("STEPS is the one fixed sequence")` — asserts `pareah.STEPS == ("grant", "handshake", "union_commitment", "adapter", "sdk_wrap", "gate")` and `pareah.transcript_ok(dag, "echo")` confirms every step recorded in order.

**Honest limit:** The sequence is enforced in this process. If the process is compromised (hostile code with owner's rights), the sequence can be bypassed by not using the adapter. The adapter must be the only route (OS/container enforced, owner key in TPM).

## 2. Human-signed union commitment binds both ends (the "hug")

**Capability:** The union commitment is a human-signed commitment over the hash of both connection ends' identities, public keys, the adapter card hash, and the PRE card hash. It cannot be replayed (single-use, burned in ledger), forged (requires human key), or reused for another adapter (hash includes adapter card hash and PRE hash).

**Why policy/prompt cannot provide it:** A prompt cannot require a human to sign a specific cryptographic structure over both ends' keys. A model cannot produce a valid Ed25519 signature with a key it never holds. A policy cannot make "single-use" stick — a signature can be copied and replayed unless a ledger tracks usage.

**Where enforced:** `src/vega_pareah/adapter/pareah.py::union_commitment` calls `commit.commit(UNION_ACTION, {...}, signed, route="human")`. `Connection._live()` checks `ledger.verify(self.commitment)` on every call. `admit()` burns announcements via `AIRLOCK_EXPECTED_USED` record.

**Test:** `tests/test_pareah.py` lines 77–87: replayed union approval refused; unsigned refused; hug for one adapter cannot connect another.

**Honest limit:** The human must actually sign. If the human signs carelessly (wrong adapter, wrong PRE), the commitment is valid for that wrong configuration. The design tries to make approvals specific and small so careless approval is harder, but cannot remove the human.

## 3. Adapter card: one shape, verified at gate time with license policy re-derived

**Capability:** One `ADAPTER` card shape for all kinds (model, tool, server, repo, service). `verify_adapter_card` re-derives the policy from the license class at verify time — a forged card claiming `adopt_by_reference: true` for a copyleft class is refused. Capabilities are checked against `humanauth` at mint AND at verify.

**Why policy/prompt cannot provide it:** A prompt cannot enforce that a card's `policy` field matches the authoritative `license_policy.POLICY[license_class]` at the moment of use. A model can be told "check the license" but can hallucinate or be steered to skip the check. The re-derivation at gate time is code, not a request.

**Where enforced:** `src/vega_pareah/adapter/adapter_card.py::verify_adapter_card` line 58: `if card["policy"] != license_policy.policy_for(card["license_class"]): raise AdapterCardRefused("policy does not match the license class (forged card)")`. Also `_caps(card["capabilities"])` at verify time.

**Test:** `tests/redteam_2_cards_handshake_peak.py` lines 114–119: forged policy for `strong_copyleft` class refused even with valid hash.

**Honest limit:** License class is declared at mint; if the declarer lies about the class, the policy follows the lie. Counsel decides edge cases. The SDK redistributes no third-party source — everything is a reference.

## 4. PRE card: scoped permissions with lease capped by human-authority lease

**Capability:** PRE (Permission) card states subject, capabilities, resource scope (boundary-aware prefixes), issued/expires timestamps. Lease seconds capped by `humanauth.MAX_LEASE_SECONDS` checked at mint AND at `verify_pre` (forged long card refused). `PreDeck` adds revocation. `permits()` returns False on any verification failure.

**Why policy/prompt cannot provide it:** A prompt saying "only allow read_file on /work" has no enforcement. A model can be tricked into treating "/workshop/secret" as in scope (string prefix match). A forged long-lived PRE card would be accepted by a policy checker that only looks at the card's own expiry field. The lease cap is enforced by `humanauth.MAX_LEASE_SECONDS` at verify time, not by the card's claim.

**Where enforced:** `src/vega_pareah/cards/pre.py::mint_pre` (lease cap), `verify_pre` (re-checks lease, scope, capabilities), `permits` (returns False on any failure), `_check_scope` (boundary-aware: `/work` does not cover `/workshop`). `PreDeck.revoke` adds to revoked set.

**Test:** `tests/test_cards.py` lines 34–51: scope, expiry, revocation. `tests/redteam_2_cards_handshake_peak.py` lines 57–62: `/workshop/secret` not in scope of `/work`; lines 74–83: forged long lease refused at verify.

**Honest limit:** Scope is prefix-based; a resource named `/workx` would match `/work` (no trailing slash). The boundary-aware logic requires `/work/` or `/work` exact match to avoid this, but naming discipline is on the owner.

## 5. PEAK card: frozen DAG job — parameters, order, PRE fixed at freeze; first failure stops

**Capability:** `freeze()` takes steps with parameters, hashes parameters to `params_sha256`, topologically sorts into `order`, hashes entire frozen body to `dag_hash`. `run()` verifies `dag_hash`, checks each step's `params_sha256` matches provided params, checks PRE permits, calls executor. First failure records `PEAK_ABORT` and stops (hard stop); no further steps run. HUMAN_ONLY actions refused at freeze AND at run (resealed forgery caught).

**Why policy/prompt cannot provide it:** A prompt cannot freeze a job's parameter hashes, DAG order, and PRE binding into a single immutable hash that is then enforced at execution time. A model can be asked "run these steps in order" but can skip, reorder, or change parameters. The hard stop on first failure is code logic, not a request.

**Where enforced:** `src/vega_pareah/cards/peak.py::freeze` (hashes params, sorts, creates `dag_hash`), `verify_peak` (checks `dag_hash`, step hashes, order), `run` (line 115: `params_sha(params_by_step[sid]) != s["params_sha256"]` → `PeakRefused`; line 117: `pre_mod.permits` checked per step; line 123–127: any exception → `PEAK_ABORT`, hard stop).

**Test:** `tests/test_cards.py` lines 60–68: changed params refused; lines 80–83: step outside PRE refused; job under different PRE refused. `tests/redteam_2_cards_handshake_peak.py` lines 275–283: changed params, swapped PRE, edited order all refused; lines 306–318: first failing step stops job, `PEAK_ABORT` recorded, no `PEAK_DONE`.

**Honest limit:** The executors are provided at run time; a malicious executor could do anything. The PEAK only constrains *which* executor runs with *which* hashed parameters, in *which* order, under *which* PRE.

## 6. Model card: identity + license + optional frozen weights hash; API cards honestly say they cannot be hash-checked

**Capability:** `mint_model_card` creates MODEL card with provider, license_class, optional `weights_sha256` (frozen), optional endpoint. `check_model` returns `True` only if frozen card AND observed weights hash matches via `hmac.compare_digest`. Unfrozen (API) cards return `False` — they honestly say they cannot be hash-checked, rather than pretending.

**Why policy/prompt cannot provide it:** A prompt cannot enforce that a model card's `frozen` flag and `weights_sha256` are cryptographically bound to the actual model weights served. An API model can change weights at any time; a prompt claiming "this is model X" has no verification. The honest `False` for unfrozen cards is a design choice — code returns `False`, a model could be prompted to say "yes it matches."

**Where enforced:** `src/vega_pareah/cards/model_card.py::check_model` lines 35–42: returns `False` for malformed, altered, forged policy, unfrozen, or hash mismatch. Uses `hmac.compare_digest` for constant-time compare.

**Test:** `tests/test_cards.py` lines 92–94: frozen card matches hash, mismatched hash fails, API card returns `False`.

**Honest limit:** A frozen card's hash can be forged if the attacker also forges the card hash (integrity, not authenticity). The human's union commitment is what binds a model card to a person. Weight hash only proves the bytes match; it does not prove the model behaves as expected.

## 7. Runtime card: code hash + capabilities + limits; drift detected by hash comparison

**Capability:** `mint_runtime_card` binds `runtime_id`, `code_sha256`, capabilities, limits dict, license_class. `check_runtime` returns `True` only if observed `code_sha256` matches via `hmac.compare_digest`. Forged policy, human-only capability, or drift → `False`.

**Why policy/prompt cannot provide it:** A prompt cannot verify that the code actually running matches a declared hash. A model can be told "the runtime is version X" but has no way to measure the code on disk. Drift detection requires reading the actual bytes and hashing — code, not a statement.

**Where enforced:** `src/vega_pareah/cards/runtime_card.py::check_runtime` lines 45–51: hash match via `hmac.compare_digest`; `_caps` re-checks capabilities; policy re-derived from license_class.

**Test:** `tests/test_cards.py` line 87: drift detected (`ab*32` passes, `cd*32` fails); lines 88–91: human-only refused, copyleft stays reference-only.

**Honest limit:** Hash comparison detects drift but not *when* or *how* the code changed. The runtime must be the only code path (OS/container enforced).

## 8. Server card: locked data off-device requires FHE; never falls back to plaintext

**Capability:** `mint_server_card` declares `location_class` (local/external/server) and `on_device` boolean. `require_locked_compute(card, "locked")` returns `"locked"` ONLY if `fhe.available()` is true; otherwise raises `FHEUnavailable`. Never returns `"plain"` for locked data off-device. `verify_execution_proof` validates tier 0 (binding) or tiers 1/2 (need prover); malformed → `False`; unavailable tier → raises `TierUnavailable` (not silently `False`).

**Why policy/prompt cannot provide it:** A prompt saying "use FHE for sensitive data" has no enforcement. If FHE is unavailable, a model could silently fall back to plaintext. The code raises an exception instead — the caller *must* handle the unavailability, it cannot be ignored.

**Where enforced:** `src/vega_pareah/cards/server_card.py::require_locked_compute` lines 51–53: `if not fhe.available(): raise fhe.FHEUnavailable("locked data off-device needs FHE and none is registered; refusing plaintext")`. `verify_execution_proof` lines 73–74: `except TierUnavailable: raise`.

**Test:** `tests/test_cards.py` lines 99–111: locked off-device without FHE raises; with fake FHE backend registered, returns `"locked"`; tier 1 proof without prover raises `TierUnavailable`.

**Honest limit:** FHE hides data but does not prove the work was done correctly — that requires an execution proof (tier 0/1/2). Tier 0 only proves binding (this PEAK, this output hash), not correctness. Tiers 1/2 need a registered prover. If no prover, the check raises rather than passes.

## 9. Quarantine: strict allow-list static scan + isolated probe; one read of bytes

**Capability:** `quarantine_then_adopt` reads artifact ONCE (size-capped). Strict mode: allow-list of pure-computation imports only; forbids `open/eval/exec/compile/getattr/setattr/globals/vars/__import__` and dunder attributes reaching interpreter internals. Probe runs in separate interpreter (`-I -S`), stripped env, throwaway folder, wall-clock limit, bounded output, verified kill of whole tree. Verdict + artifact hash recorded to DAG either way.

**Why policy/prompt cannot provide it:** A prompt cannot enforce that the static scan runs on the exact bytes that are hashed and executed. A model can be asked "scan this code" but can miss imports, be fooled by obfuscation, or skip the probe. The one-read guarantee (scanned bytes = hashed bytes = executed bytes) is a code invariant: `data = fh.read(MAX_ARTIFACT_BYTES + 1)` once, then everything uses `data`.

**Where enforced:** `src/vega_pareah/adapter/quarantine.py::quarantine_then_adopt` lines 106–114: one read, `sha = hashlib.sha256(data).hexdigest()`, `findings = static_scan(data.decode(...))`, `probe = _probe(data, timeout)` if no findings. `static_scan` (lines 44–77): strict allow-list. `_probe` (lines 80–97): `proc.run_bounded` with `-I -S`, custom env, temp folder, timeout, cap, verified kill.

**Test:** `tests/redteam_1_quarantine.py` lines 37–61: importlib, `__import__`, os, subprocess, dunder walks all denied; lines 88–114: output flood cut, busy loop killed, memory balloon stopped by clock, oversize denied without probe, nonzero exit denied; lines 139–160: scanned=hashed=executed bytes (file swap attack fails).

**Honest limit:** This is a speed bump plus process control, NOT an OS sandbox. A scan cannot prove arbitrary code safe. The probe runs on the host with this user's rights — it can still read files and use network if the scan was fooled. For code believed hostile, run the whole quarantine inside a VM or container.

## 10. Airlock: owner pre-announces handshake; door 1 matches and burns announcement; else traps in dead-end room

**Capability:** Owner calls `announce(expect_public, signed, card_hash, not_before)` with human-signed commitment. `admit(arrival)` checks challenge single-use (popped), signature verifies, matches announcement (public key, card_hash, not_before, ledger verify). On match: burns announcement via `AIRLOCK_EXPECTED_USED` record, returns `EXPECTED`. On any mismatch: traps in `Room` (dead end), returns `TRAPPED` with reason code (never shown to visitor). If burn record cannot be written → traps (fail-closed).

**Why policy/prompt cannot provide it:** A prompt cannot enforce that an unannounced visitor is trapped in a room that has no adapter function, no network, no files, no secrets, and answers only from fixed scenes. A model can be told "be careful with unknown visitors" but can be social-engineered. The room's properties (no reference to anything downstream, fixed scenes, no echo) are structural — code that *cannot* do things, not code that *promises* not to.

**Where enforced:** `src/vega_pareah/adapter/airlock.py::Airlock.admit` lines 200–216: `_check` → `_match` → burn record → `EXPECTED` else `_trap`. `_trap` (lines 253–269): creates/reuses `Room`, records `AIRLOCK_TRAPPED`. `Room.say` (lines 110–131): returns only `SCENES`, tracks flags, never echoes visitor text. `_sweep` caps rooms by TTL. `MAX_ROOMS`, `MAX_CHALLENGES`, `MAX_TURNS` caps.

**Test:** `tests/redteam_3_airlock.py` lines 82–88: announced visitor passes, same visitor again trapped; lines 91–102: intruder trapped, shown only fixed scenes, text never echoed, adapter function never reached; lines 105–118: bad signature, replayed challenge, wrong door, malformed all trapped; lines 140–158: expired, early, wrong card, not in ledger all trapped; lines 160–178: same key same room, room cap, challenge cap, turn cap, message cap; lines 204–219: burn record fails → trapped.

**Honest limit:** Announcements held in memory; restart needs re-sign (used announcements stay used because recorded in chain). Room cannot identify remote model from weights — only measures behaviour via plain regex rules. Careful intruder can recognise dead end and leave.

## 11. License policy gate: six classes; only permissive allows adopt_by_reference; forged policy refused

**Capability:** Six license classes (`permissive`, `weak_copyleft`, `strong_copyleft`, `restricted`, `unknown`, `no_license`). `POLICY` dict maps each to `{adopt_by_reference, redistribute, note}`. Only `permissive` has `adopt_by_reference: true`. `verify_adapter_card` re-checks `card["policy"] == license_policy.policy_for(card["license_class"])` — forged policy refused even with valid hash.

**Why policy/prompt cannot provide it:** A prompt cannot enforce that a license class's policy is authoritatively looked up at gate time. A model can be told "copyleft means reference-only" but can be steered to ignore it. The re-derivation is code: `policy_for(license_class)` returns the canonical policy; any mismatch is a refusal.

**Where enforced:** `src/vega_pareah/cards/license_policy.py::POLICY` dict. `src/vega_pareah/adapter/adapter_card.py::verify_adapter_card` line 58. `src/vega_pareah/adapter/pareah.py::gate_entry` line 115: `if not conn.card["policy"]["adopt_by_reference"]: conn._deny("entry", "license class ... is reference-only: connecting is allowed, running its code is not")`.

**Test:** `tests/test_pareah.py` lines 97–101: copyleft adapter connects as reference-only. `tests/redteam_2_cards_handshake_peak.py` lines 114–119: forged policy for strong_copyleft refused.

**Honest limit:** License class is self-declared at mint; if the declarer misclassifies, the policy follows the declaration. This is a policy gate, not legal advice. Counsel decides edge cases.

---

## This repo's part in the family predictive loop

The family's predictive loop (from ORGANISM_MAP.md):
```
custody records → librarian distils lessons → dkg-lattice builds knowledge graph (origin + licence per fact)
→ reasoning/galaxy forecast from lattice → harness pre-registers predicted paths → metacog gates completion on evidence
→ feed/galaxy show it all to the human, who decides again.
```

**vega-pareah-sdk is the doorway protecting this loop from hostile inbound code.**

- **Quarantine** vets every artifact before it becomes an adapter card — the knowledge graph (layer 7) only ingests facts from vetted sources with known license classes.
- **Adapter cards** carry license class and policy — the dkg-lattice SDK consumes these to know which facts can be adopted by reference vs. reference-only.
- **Airlock** ensures only pre-announced, human-authorized visitors reach the adapter layer — automated probes, curious agents, and hostile actors are trapped in the dead-end room, recorded, and learn nothing.
- **PAREAH handshake** gates every call with live PRE permission and union commitment — the harness (layer 6) uses these same cards and PREs to gate tool use in predicted paths.
- **Server card + FHE + execution proofs** — when the harness or reasoning SDK needs off-device compute on locked data, the server card enforces FHE and proof tiers (from superproof, layer 2).

Without this doorway, the loop's inputs (artifacts, visitors, adapter calls) could be poisoned — hostile code in the knowledge graph, unauthorized visitors in the adapter layer, unchecked tool calls in predicted paths. PAREAH makes the doorway verifiable: every capability above is code-enforced, recorded in the custody DAG, and testable.