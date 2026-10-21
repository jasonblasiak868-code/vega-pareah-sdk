# vega-pareah-sdk — Specification

Spec v1.0 — 2026-10-19 — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

## 1. Purpose and scope

This specification covers the PAREAH adapter handshake, the six card types (PRE, PEAK, adapter, model, runtime, server), the quarantine for inbound artifacts, and the airlock that guards the adapter door. It specifies what the published code in `src/vega_pareah/` guarantees and what it does not.

Out of scope: hardware cards (designed only, not built), OS-level sandboxing, legal interpretation of license classes, and any deployment configuration.

## 2. Vocabulary

- **adapter card** — a reference (pointer + hash + license class) describing an external model, tool, server, repo, or service. Never the third-party code itself.
- **PRE** — Permission card. States which actions a subject may take, on which resource prefixes, until an expiry capped by the human-authority lease. Revocable via PreDeck.
- **PEAK** — a frozen, committed DAG job. Steps, parameter hashes, dependencies, and the PRE it runs under are fixed at freeze time into a single dag_hash. At run time nothing can be added, reordered, or altered.
- **quarantine** — one read of artifact bytes; strict allow-list static scan; isolated probe run; verdict and hash recorded to DAG.
- **airlock** — the owner's pre-announced handshake (a human-signed commitment). Door 1 matches and burns the announcement; anything else is trapped in a dead-end room.
- **dead-end room** — holds no adapter function, no network, no files, no secrets. Answers only from fixed scenes; never echoes visitor text; caps on rooms, challenges, turns.
- **union commitment** — the human's signed commitment over the union of both connection ends (the "hug"). Verified with the human key, minted by the SDK.
- **license class** — one of: permissive, weak_copyleft, strong_copyleft, restricted, unknown, no_license. Determines policy (adopt_by_reference, redistribute).
- **card hash** — SHA-256 of all card fields except card_hash. Proves the card was not edited after minting; does NOT prove who minted it. Authenticity comes from the human's signed union commitment.

## 3. Components

### 3.1 adapter/adapter_card.py

**Role:** One adapter card shape for everything (model, tool, server, repo, service). Verified at gate time, not only at mint: the policy is re-derived from the license class, and every field is shape-checked.

**Public interface:**
- `KINDS` — tuple of allowed kinds: ("model", "tool", "server", "repo", "service")
- `AdapterCardRefused` — exception
- `card_hash(card)` — returns canonical hash
- `mint_adapter_card(adapter_id, kind, capabilities, code_sha256, license_class, reference_uri)` → dict
- `verify_adapter_card(card)` → None (raises AdapterCardRefused)

**Behavior:** On success returns a card with kind="ADAPTER" and card_hash. On failure raises AdapterCardRefused with a descriptive message. A forged card claiming adopt_by_reference for a copyleft class is refused at verify time.

**Invariants:** card_hash matches canonical hash of all fields except card_hash; license_class is one of the six CLASSES; policy matches license_policy.policy_for(license_class); capabilities are checked against humanauth at mint AND at verify; code_sha256 is 64 lowercase hex; reference_uri is a safe-scheme URL or None.

### 3.2 adapter/airlock.py

**Role:** The first door of PAREAH. Door 1 is always open inbound; matches against the owner's pre-announced handshake; locks behind anything else into a dead-end room.

**Public interface:**
- `ANNOUNCE_ACTION`, `RELEASE_ACTION` — action strings for commitments
- `SCENES` — tuple of 4 fixed reply strings
- `RULES` — dict of regex patterns (instruction_override, prompt_probe, command_shape, secret_hunt, encoded_blob, authority_claim)
- `AirlockRefused` — exception
- `arrival_message(door_id, challenge, card_hash)` → bytes
- `make_arrival(end, door_id, challenge, card_hash)` → dict (visitor side)
- `Room` class — the dead end
- `Airlock` class — owns announce, release, inspect, challenge, admit, _door

**Behavior:**
- `announce(expect_public, signed, card_hash, not_before)` → ann_id: owner pre-announces a handshake; needs human-signed commitment; recorded as AIRLOCK_ANNOUNCED.
- `release(visitor_public, signed)` → dict: owner lets a locked-in visitor go; human commitment required; room forgotten; recorded as AIRLOCK_RELEASED.
- `inspect(visitor_public)` → Room summary or None.
- `challenge()` → str: fresh single-use challenge; capped at MAX_CHALLENGES.
- `admit(arrival)` → dict: status EXPECTED (announcement burned, recorded as AIRLOCK_EXPECTED_USED) or TRAPPED (room, reason). Fails closed: if the burn record cannot be written, the visitor is trapped.

**Room behavior:** `say(message)` → fixed scene reply; tracks turns, loops, bytes_in, rule-flag counts, excerpts (hash, length, printable excerpt or None if credential-like); closes after MAX_TURNS; restarts scene on repeat visitor. No reference to any adapter, connection, network, or file.

**Invariants:** challenge is single-use (popped); signature must verify; card_hash must match announcement; not_before honoured; ledger re-check at door; announcement burned on use; room cap (MAX_ROOMS); challenge cap; room replies only from SCENES; turn cap closes room; credential-like text not kept as excerpt; message size capped; same key always lands in same room (restarts scene); a burn that cannot be written means no entry.

### 3.3 adapter/pareah.py

**Role:** The external adapter. One fixed handshake sequence for every adapter (STEPS = grant, handshake, union_commitment, adapter, sdk_wrap, gate).

**Public interface:**
- `STEPS` — the fixed sequence tuple
- `CONNECT_ACTION`, `UNION_ACTION` — action strings
- `PareahRefused`, `Trapped` — exceptions
- `End` class — one end of a connection (identity + signing key)
- `_handshake(card, a, b)` → dict
- `union_hash(card, a, b, pre_card)` → str
- `union_commitment(commit, union, card_hash, pre_hash, signed)` → dict
- `gate_entry(conn, request_capsule)` → None (raises PareahRefused)
- `gate_exit(conn, request_capsule, response_data)` → response capsule
- `Connection` class — live connection with call(request_capsule) → response_capsule
- `Pareah` class — connect(card, pre_card, end_a, end_b, union_signed, adapter_fn, arrival) → Connection
- `transcript_ok(dag, adapter_id)` → bool

**Behavior:** `connect` runs STEPS in order; any failure at any step fails closed, records PAREAH_ABORT, raises PareahRefused. On success records PAREAH_STEP for each step, returns Connection. Connection.call runs gate_entry, calls adapter_fn, runs gate_exit (capsules response, chains to request, records PAREAH_CALL). Gate entry checks capsule validity, PRE permission, adapter card capability declaration, and license policy (reference-only classes cannot run code). Gate exit verifies union commitment still alive and in ledger. Airlock fitted: every connection passes door 1 first; door's identity can never be an end of a real connection.

**Invariants:** STEPS order is constant (not a parameter); union commitment cannot be replayed, forged, or reused for another adapter; adapter card verified at gate time; PRE checked at gate entry; license policy enforced at gate entry; connection dies when union commitment expires or stops verifying in ledger; malformed inputs become refusals with abort record, never raw errors.

### 3.4 adapter/quarantine.py

**Role:** Inbound artifacts tested in a guinea-pig quarantine BEFORE adoption, then enter the same fixed PAREAH sequence.

**Public interface:**
- `ALLOWED_IMPORTS`, `FORBIDDEN_NAMES`, `FORBIDDEN_IMPORTS` (loose mode), `FORBIDDEN_CALLS`, `FORBIDDEN_ATTRS`
- `QuarantineDenied` — exception
- `static_scan(source, loose=False)` → list of findings
- `_probe(data, timeout)` → dict (ok, reason, exit/kill_confirmed)
- `quarantine_then_adopt(artifact_path, adapter_id, kind, capabilities, license_class, dag, reference_uri, timeout, loose, acknowledge_host_risk)` → adapter card dict

**Behavior:** Reads artifact ONCE (size-capped). Strict mode: allow-list of pure-computation imports; forbids open/eval/exec/compile/getattr/setattr/globals/vars/__import__ and dunder attributes reaching interpreter internals. Loose mode: old deny-list; requires acknowledge_host_risk=True. Probe runs in separate interpreter (-I -S), stripped env, throwaway folder, wall-clock limit, bounded output, verified kill of whole tree. Verdict and artifact hash recorded to DAG as QUARANTINE_VERDICT either way. Returns minted adapter card on ALLOW, raises QuarantineDenied on DENY.

**Invariants:** scanned bytes = hashed bytes = executed bytes (one read); strict mode allow-list is fixed; probe environment built from scratch (no os.environ copy); working folder removed after every run; oversize artifact denied without running probe; nonzero exit is deny; loose mode gated by explicit acknowledgement.

### 3.5 cards/_common.py

**Role:** Shared validation for every PAREAH card.

**Public interface:**
- `canonical_hash(card, exc_type)` → str
- `hashes_match(card, exc_type)` → bool
- `need_id(value, name, exc_type, limit)` → str
- `need_hex64(value, name, exc_type, optional)` → str or None
- `need_uri(value, name, exc_type)` → str or None
- `resource_ok(resource)` → bool
- `in_scope(resource, scope_entry)` → bool

**Behavior:** canonical_hash sorts keys, forbids NaN/Infinity, non-JSON values. hashes_match compares card_hash to canonical_hash. need_id checks printable, non-empty, length limit, no control chars. need_hex64 validates 64 lowercase hex. need_uri validates safe schemes (https://, git+https://, ssh://), length, no control chars. resource_ok checks printable, no backslash, no .. traversal. in_scope does boundary-aware prefix match.

### 3.6 cards/license_policy.py

**Role:** What the SDK may do with third-party code, by license class. SDK redistributes no third-party source.

**Public interface:**
- `CLASSES` — tuple of six classes
- `POLICY` — dict mapping class to {adopt_by_reference, redistribute, note}
- `policy_for(license_class)` → dict (defaults to "unknown" policy)

**Behavior:** Only "permissive" has adopt_by_reference=True. All classes have redistribute=False. Anything unrecognised defaults to "unknown" policy.

### 3.7 cards/pre.py

**Role:** PRE card: scoped permissions with expiry capped by human-authority lease. Revocable deck.

**Public interface:**
- `PreRefused` — exception
- `mint_pre(subject, capabilities, scope, lease_seconds, now)` → dict
- `verify_pre(card, now)` → None (raises PreRefused)
- `permits(card, action, resource, now)` → bool
- `PreDeck` class — add(card), revoke(card_hash), permits(card_hash, action, resource)

**Behavior:** mint_pre checks capabilities via humanauth (no HUMAN_ONLY, no wildcard, no blank), scope (boundary-aware prefixes, no empty/wildcard/traversal), lease (1..MAX_LEASE_SECONDS). verify_pre re-checks all at use time (forged long card refused). permits returns False on any verification failure. PreDeck.add verifies then stores; revoke adds to revoked set; permits checks revoked.

**Invariants:** PRE can never carry HUMAN_ONLY capability (any spelling); expiry capped by humanauth.MAX_LEASE_SECONDS checked at mint AND at use; scope entries are boundary-aware prefixes ('/work' does not cover '/workshop'); empty scope and '..' traversal refused; PRE hash is integrity, not authenticity (human's union commitment binds it to a person).

### 3.8 cards/peak.py

**Role:** PEAK card: frozen DAG job. Steps, parameter hashes, dependencies, PRE fixed at freeze; first failure stops.

**Public interface:**
- `PeakRefused` — exception
- `params_sha(params)` → str
- `freeze(steps, pre_hash)` → dict (kind="PEAK", steps with params_sha256, order, dag_hash)
- `verify_peak(peak)` → None (raises PeakRefused)
- `run(peak, pre_card, executors, params_by_step, dag)` → outputs dict

**Behavior:** freeze validates steps (id, action, resource, deps), checks no HUMAN_ONLY actions, topologically sorts into order, hashes frozen body into dag_hash. verify_peak checks dag_hash, step params_sha256 present, order matches DAG. run verifies peak, verifies pre_card matches pre_hash, runs steps in order, checks params_sha256 matches, checks PRE permits, calls executor, records PEAK_STEP, on any failure records PEAK_ABORT and stops (hard stop), records PEAK_DONE on success.

**Invariants:** HUMAN_ONLY actions cannot be frozen (checked at freeze AND at run); parameter hashes fixed at freeze; step order fixed by DAG; first failure stops job; PRE checked at run time; PEAK under different PRE refused; cycle/missing dep/duplicate id refused at freeze.

### 3.9 cards/model_card.py

**Role:** Identity of a model: which one, from whom, under what license class, and (when frozen) hash of weights.

**Public interface:**
- `ModelCardRefused` — exception
- `mint_model_card(model_id, provider, license_class, weights_sha256, endpoint)` → dict
- `check_model(card, observed_weights_sha256)` → bool (never raises on hostile card)

**Behavior:** mint_model_card validates fields, policy from license_class. check_model returns False (never exception) for malformed/altered card, forged policy, unfrozen card (API card cannot be hash-checked and says so), or hash mismatch. Frozen card requires observed_weights_sha256 to match via hmac.compare_digest.

### 3.10 cards/runtime_card.py

**Role:** Declares an execution environment: what code it is, what it may do, its limits. Drift detected by hash comparison.

**Public interface:**
- `RuntimeCardRefused` — exception
- `mint_runtime_card(runtime_id, code_sha256, capabilities, limits, license_class, reference_uri)` → dict
- `check_runtime(card, observed_code_sha256)` → bool (never raises)

**Behavior:** mint validates capabilities via humanauth, license_class, limits is dict. check_runtime returns False for malformed/altered card, forged policy, human-only capability, or code drift (hash mismatch via hmac.compare_digest).

### 3.11 cards/server_card.py

**Role:** Declares a server (local, external, cloud) and what it is trusted to do. Off-device compute on locked data only allowed as LOCKED compute (FHE); never falls back to plaintext.

**Public interface:**
- `ServerCardRefused` — exception
- `LOCATIONS`, `SENSITIVITY` — tuples
- `mint_server_card(server_id, location_class, capabilities, on_device)` → dict
- `require_locked_compute(card, data_sensitivity)` → "plain" or "locked" (raises FHEUnavailable rather than returning weaker mode)
- `verify_execution_proof(proof, peak)` → bool (False for malformed; raises TierUnavailable if tier 1/2 prover unavailable)

**Behavior:** mint validates location_class, on_device bool, on_device true only for local, capabilities via humanauth. require_locked_compute: open data or on_device → "plain"; locked data off-device → requires FHE (raises FHEUnavailable if unavailable). verify_execution_proof: tier 0 verifies binding (this PEAK, this output hash); tiers 1/2 need registered prover; malformed is False; unavailable tier raises TierUnavailable (not silently False).

## 4. Guarantees and non-guarantees

### Guarantees

| Guarantee | Module | Test |
|---|---|---|
| Fixed six-step handshake order cannot be reordered or skipped | pareah.py | test_pareah.py line 60-64 |
| Union commitment cannot be replayed, forged, or reused for another adapter | pareah.py | test_pareah.py lines 77-87 |
| Adapter card policy re-derived from license class at verify time (forged policy refused) | adapter_card.py | redteam_2_cards_handshake_peak.py lines 114-119 |
| PRE expiry capped by human-authority lease at mint AND at use | pre.py | test_cards.py lines 40, 47 |
| PRE scope is boundary-aware (no /workshop from /work) | pre.py | redteam_2_cards_handshake_peak.py lines 57-62 |
| HUMAN_ONLY capabilities refused at mint AND at verify (any spelling) | pre.py, adapter_card.py, runtime_card.py, server_card.py | test_cards.py line 38; redteam_2 lines 85-88, 131-135 |
| PEAK frozen at freeze: params, order, PRE, DAG; first failure stops | peak.py | test_cards.py lines 60-68; redteam_2 lines 275-283, 306-318 |
| Quarantine: one read of bytes (scanned=hashed=executed) | quarantine.py | redteam_1_quarantine.py lines 139-160 |
| Quarantine strict mode: allow-list only; forbids interpreter internals access | quarantine.py | redteam_1_quarantine.py lines 37-61 |
| Airlock: announcement single-use, burned on use, ledger re-checked at door | airlock.py | redteam_3_airlock.py lines 87-88, 105-113, 140-158 |
| Dead-end room: no adapter/net/files/secrets; fixed scenes only; no echo | airlock.py | redteam_3_airlock.py lines 99-101 |
| Room caps: MAX_ROOMS, MAX_CHALLENGES, MAX_TURNS enforced | airlock.py | redteam_3_airlock.py lines 168-178 |
| Burn that cannot be written → visitor trapped (fail-closed) | airlock.py, pareah.py | redteam_3_airlock.py lines 204-219 |
| Door identity cannot be an end of a real connection | pareah.py | redteam_3_airlock.py lines 195-202 |
| License policy: only permissive allows adopt_by_reference | license_policy.py | test_pareah.py lines 97-101 |
| Server card: locked data off-device requires FHE, never falls back | server_card.py | test_cards.py lines 99-111 |

### Non-guarantees

| Non-guarantee | Module | Note |
|---|---|---|
| Quarantine is not an OS sandbox | quarantine.py | Hostile code on host with owner rights bypasses the door |
| Airlock announcements held in memory; restart needs re-sign | airlock.py | Used announcements stay used (recorded in chain) |
| Room cannot identify remote model from weights | airlock.py | Only measures behaviour |
| Card hash is integrity, not authenticity | _common.py, all cards | Authenticity from human's signed union commitment |
| License policy is policy gate, not legal advice | license_policy.py | Counsel decides edge cases |
| Cryptography not expert-reviewed | all | Reference implementation |
| Hardware cards (silicon, photonic) designed, not built | STATUS.md | Not in src/ |

## 5. Failure modes

| Failure mode | What happens | Test cite |
|---|---|---|
| Tampered adapter card (altered capabilities/policy) | Refused at verify_adapter_card (hash mismatch or policy re-check) | redteam_2 lines 114-119, 131-135 |
| Missing union commitment | connect refused at grant step (PRE check) or union_commitment step | test_pareah.py line 90-91 |
| Expired union commitment | Connection._live() denies with "union commitment expired" | test_pareah.py lines 103-113 |
| Replayed union commitment | connect refused (already used in ledger) | test_pareah.py lines 77-80 |
| Corrupt request capsule | gate_entry denies, records PAREAH_DENIED | test_pareah.py lines 73-75 |
| PEAK parameter drift | run refuses at step with param hash mismatch | test_cards.py line 67-68 |
| PEAK step outside PRE scope | run refuses at step | test_cards.py lines 80-81; redteam_2 line 321-325 |
| Quarantine artifact over size | DENY recorded, probe not run | redteam_1 lines 106-110 |
| Quarantine static scan findings | DENY recorded, probe not run | redteam_1 lines 30-70 |
| Quarantine probe timeout/kill/overflow/nonzero exit | DENY recorded | redteam_1 lines 88-114 |
| Airlock no announcement | admit → TRAPPED, reason "no_announcement" | redteam_3 lines 91-98 |
| Airlock bad signature / replayed challenge / wrong door / malformed | admit → TRAPPED, reason code | redteam_3 lines 105-118 |
| Airlock expired / early / wrong card / not in ledger | admit → TRAPPED, reason code | redteam_3 lines 140-158 |
| Burn record cannot be written | admit → TRAPPED, reason "record_failed" | redteam_3 lines 204-219 |
| Door identity used as connection end | connect refused (PareahRefused, not trapped) | redteam_3 lines 195-202 |

## 6. Dependencies and layer rules

Registry entry (verbatim from ORGANISM_MAP.md):
```
vega-pareah-sdk | 3 adapt | custody, jacket
```

Dependencies point down layers only, never up or sideways. This repo depends on:
- `vega-custody-sdk` (layer 0, record) — capsules, DAG, ledger
- `vega-governance-jacket-sdk` (layer 1, authority) — human commitments, humanauth, verifier
- `vega-superproof-sdk` (layer 2, seal) — FHE, proof tiers (for server_card)

No cycles. No two owners of one concern.

## 7. Conformance

A third party can verify by running the test suite:
```bash
python tests/test_pareah.py
python tests/test_cards.py
python tests/redteam_1_quarantine.py
python tests/redteam_2_cards_handshake_peak.py
python tests/redteam_3_airlock.py
```

Passing means: all 168 tests pass (per STATUS.md); the fixed handshake sequence runs in order; union commitments cannot be replayed; adapter cards enforce license policy at gate time; PRE expiry and scope are enforced; PEAK jobs are frozen and stop on first failure; quarantine scans and probes record verdicts; airlock traps unannounced visitors in dead-end rooms; license policy gates adopt_by_reference.

Passing does NOT mean: production-hardened; independently security-reviewed; cryptographically expert-reviewed; OS-level containment; legal compliance of license interpretations; hardware cards built.