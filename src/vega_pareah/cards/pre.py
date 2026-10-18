"""pre.py - the PRE card: Permission. States which actions a subject may take, on which resources, until when.

Hard rules (code, not config):
  - a PRE can never carry a HUMAN_ONLY capability (any spelling), nor a wildcard, nor a bare string (checked at mint AND at every use)
  - a PRE has an expiry no further than the human-authority lease cap, checked at mint AND at every use (a forged long card is refused)
  - scope entries are boundary-aware prefixes ('/work' does not cover '/workshop'); an empty scope entry and '..' traversal are refused
  - a PRE is data plus a hash; changing any field changes the hash and fails verification. The hash is integrity, not authenticity: the human's union commitment is what binds a PRE to a person."""
import time

from vega_jacket import humanauth  # noqa: E402
from vega_pareah.cards import _common as cm  # noqa: E402

CLOCK_SKEW = 60


class PreRefused(Exception):
    pass


def _hash(card: dict) -> str:
    return cm.canonical_hash(card, PreRefused)


def _check_caps(capabilities):
    try:
        humanauth.check_card_capabilities({"capabilities": capabilities})
    except humanauth.HumanAuthError as exc:
        raise PreRefused(str(exc)) from exc
    caps = set(capabilities)
    if not caps:
        raise PreRefused("a PRE must name at least one capability")
    if any(not c.strip() or c in ("any", "all") for c in caps):
        raise PreRefused("blank or blanket capability refused: permission is never blanket")


def _check_scope(scope):
    if isinstance(scope, (str, bytes)) or not isinstance(scope, (list, tuple, set, frozenset)) or not scope:
        raise PreRefused("a PRE must name a scope as a list of resource prefixes")
    for s in scope:
        if not isinstance(s, str) or not s or not cm.resource_ok(s) or any(ch in s for ch in "*?"):
            raise PreRefused(f"bad scope entry {s!r}: printable, non-empty, no '..', no wildcard")


def mint_pre(subject: str, capabilities, scope, lease_seconds: int = 300, now: float = None) -> dict:
    cm.need_id(subject, "subject", PreRefused)
    _check_caps(capabilities)
    _check_scope(scope)
    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not (0 < lease_seconds <= humanauth.MAX_LEASE_SECONDS):
        raise PreRefused(f"lease must be a whole number of seconds, 1..{humanauth.MAX_LEASE_SECONDS}")
    now = time.time() if now is None else now
    card = {"kind": "PRE", "subject": subject, "capabilities": sorted(set(capabilities)),
            "scope": sorted(set(scope)), "issued": int(now), "expires": int(now) + int(lease_seconds)}
    card["card_hash"] = _hash(card)
    return card


def verify_pre(card: dict, now: float = None) -> None:
    if not isinstance(card, dict) or card.get("kind") != "PRE" or not cm.hashes_match(card, PreRefused):
        raise PreRefused("PRE altered or not a PRE")
    try:
        _check_caps(card["capabilities"])  # again at use time: a forged card cannot smuggle a human-only power
        _check_scope(card["scope"])
        issued, expires = card["issued"], card["expires"]
    except KeyError as exc:
        raise PreRefused(f"PRE missing field {exc}") from exc
    if any(isinstance(v, bool) or not isinstance(v, int) for v in (issued, expires)):
        raise PreRefused("PRE times must be whole numbers")
    if not (0 < expires - issued <= humanauth.MAX_LEASE_SECONDS):
        raise PreRefused("PRE lease is longer than the human-authority cap (forged or edited card)")
    t = time.time() if now is None else now
    if issued > int(t) + CLOCK_SKEW:
        raise PreRefused("PRE is dated in the future")
    if expires <= int(t):
        raise PreRefused("PRE expired")


def permits(card: dict, action: str, resource: str, now: float = None) -> bool:
    try:
        verify_pre(card, now)
    except PreRefused:
        return False
    if not isinstance(action, str) or not cm.resource_ok(resource):
        return False
    return action in card["capabilities"] and any(cm.in_scope(resource, s) for s in card["scope"])


class PreDeck:
    """A set of PRE cards with revocation. Revoked cards never permit anything."""

    def __init__(self):
        self._cards, self._revoked = {}, set()

    def add(self, card: dict) -> str:
        verify_pre(card)
        self._cards[card["card_hash"]] = card
        return card["card_hash"]

    def revoke(self, card_hash: str):
        self._revoked.add(card_hash)

    def permits(self, card_hash: str, action: str, resource: str) -> bool:
        card = self._cards.get(card_hash)
        return card is not None and card_hash not in self._revoked and permits(card, action, resource)
