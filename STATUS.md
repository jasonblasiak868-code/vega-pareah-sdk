# STATUS 

## BUILT and tested

- adapter
- data airlock: inbound data recorded and held apart; released only under a collection commitment or a signed batch hash; 15 tests, 10 of 10 mutations caught
- link teardown: the link closes by itself at commitment expiry and at PRE revocation, recorded once; 5 tests, 4 of 6 mutations caught (the other two remove one of three overlapping refusals on a closed link; the call is still refused)
- heartbeat and probe (pulse.py): signed fresh-challenge pulses on their own chain, silence alarm, gate probe on a write-nothing copy; 13 tests, 9 of 10 mutations caught (the survivor removes the explicit challenge compare; the signature covers the challenge, so replay still fails)
- cards

Tests: 201 tests in 9 files, all passing.

## DESIGNED ONLY (not built)

- Silicon and photonic hardware cards are designed, not built.

## Release

Source-available under the LICENSE in this folder. Patent pending (U.S. provisional application 64/178,949 and others). The licence text is a draft that has not been reviewed by an attorney.
