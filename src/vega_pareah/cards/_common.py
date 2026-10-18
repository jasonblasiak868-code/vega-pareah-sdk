"""_common.py - shared validation for every PAREAH card, so one fix covers all of them.

A card hash proves a card was not edited after minting. It does NOT prove who minted it: authenticity comes from the human's signed union commitment (pareah.py), never from the hash alone."""
import hashlib
import json
import re

_HEX64 = re.compile(r"[0-9a-f]{64}")
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")
SAFE_SCHEMES = ("https://", "git+https://", "ssh://")


def canonical_hash(card, exc_type=ValueError) -> str:
    """Hash of every field except card_hash. Non-JSON values and NaN/Infinity are refused, never coerced."""
    if not isinstance(card, dict):
        raise exc_type("a card is an object")
    body = {k: v for k, v in card.items() if k != "card_hash"}
    try:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise exc_type(f"card cannot be canonicalised: {type(exc).__name__}") from exc
    return hashlib.sha256(raw).hexdigest()


def hashes_match(card, exc_type=ValueError) -> bool:
    try:
        return isinstance(card.get("card_hash"), str) and canonical_hash(card, exc_type) == card["card_hash"]
    except exc_type:
        return False


def need_id(value, name, exc_type=ValueError, limit=200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or _BAD_CHARS.search(value):
        raise exc_type(f"{name} must be a short printable string")
    return value


def need_hex64(value, name, exc_type=ValueError, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise exc_type(f"{name} must be 64 lowercase hex characters (a sha256)")
    return value


def need_uri(value, name, exc_type=ValueError):
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith(SAFE_SCHEMES) or _BAD_CHARS.search(value) or len(value) > 2000:
        raise exc_type(f"{name} must be None or a URL starting with one of {SAFE_SCHEMES}")
    return value


def resource_ok(resource) -> bool:
    """A resource is a printable string without '..' segments, backslashes or NUL: no traversal out of a scope."""
    if not isinstance(resource, str) or not resource or _BAD_CHARS.search(resource) or "\\" in resource:
        return False
    return ".." not in resource.split("/")


def in_scope(resource, scope_entry) -> bool:
    """Boundary-aware prefix: scope '/work' covers '/work' and '/work/x', never '/workshop'. A scope ending in '/' covers everything under it."""
    if not resource_ok(resource) or not isinstance(scope_entry, str) or not scope_entry:
        return False
    if resource == scope_entry:
        return True
    return resource.startswith(scope_entry if scope_entry.endswith("/") else scope_entry + "/")
