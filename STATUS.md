# STATUS 

## BUILT and tested

- adapter
- data airlock: inbound data recorded and held apart; released only under a collection commitment or a signed batch hash; 15 tests, 10 of 10 mutations caught
- link teardown: the link closes by itself at commitment expiry and at PRE revocation, recorded once; 5 tests, 4 of 6 mutations caught (the other two remove one of three overlapping refusals on a closed link; the call is still refused)
- cards

Tests: 188 tests in 8 files, all passing.

## DESIGNED ONLY (not built)

- Silicon and photonic hardware cards are designed, not built.

## Release

Source-available under the LICENSE in this folder. Patent pending (U.S. provisional application 64/178,949 and others). The licence text is a draft that has not been reviewed by an attorney.
