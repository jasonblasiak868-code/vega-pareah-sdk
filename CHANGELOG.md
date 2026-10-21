# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **An announcement was matchable before it was recorded.** If the chain write failed, the announcement stayed live. It is now stored only after it is recorded.
- **A single-use announcement could admit two visitors.** Matching an arrival to an announcement and burning the announcement were two steps; two parallel arrivals from the announced key could both be EXPECTED. The door now handles one arrival, announcement or release at a time.
- **PRE revocation was not wired in.** `PreDeck.revoke()` existed ("revoked cards never permit anything") but the connection and its gates never asked a deck. `Pareah(..., pre_deck=deck)` now refuses a revoked PRE at grant and stops an open connection at its next call.
- **Docs:** the README now states that the handshake signs with caller-supplied `End` signers in one process and does not authenticate a remote party by itself.
