# vega-pareah-sdk

![vega-pareah-sdk](assets/tile.svg)

PAREAH: one fixed handshake for every adapter, plus the card types.

> **Licensing.** Source-available, not open source. Free for personal use; free for registered small businesses (under US$1M revenue and valuation); everyone else needs a commercial license (see LICENSE; for a commercial license write to jasonblasiak.ai.mail@gmail.com). Patent pending. Draft licence text, not yet reviewed by an attorney.

Package: `vega_pareah` (src layout). Depends on: vega-custody-sdk, vega-governance-jacket-sdk, vega-superproof-sdk.

## Modules

| Module | What it does |
|---|---|
| `adapter` | PAREAH handshake with the human's commitment over the union, adapter cards, a quarantine for inbound code, and the airlock: door 1 is always open inbound, matches the owner's pre-announced handshake, and locks behind anything else into a dead-end room with no way out. |
| `cards` | PRE (permission), PEAK (frozen committed job), runtime, server and model cards. A card can never carry a human-only power. |

## What it does NOT do (read this)

- The quarantine is process containment, not an operating-system sandbox: run hostile code in a VM or container.
- The airlock protects what talks to the adapter. Hostile code already running on the machine with the owner's rights will not use the door: the adapter must be the only route (OS or container enforced, owner key in a TPM). A careful intruder can recognise a dead end; the room cannot identify a remote model from its weights, only measure behaviour.
- The expanded name 'Personal Architecture Environment Runtime Adapter Handshake' is the owner's wording; check it against the filings.

## Status

See STATUS.md. Tests: 163 tests in 5 files, all passing.  See SECURITY.md for the threat model.

## Run the tests

Put `src` of this repo and of the repos it depends on on PYTHONPATH, then run each file in `tests/`.
