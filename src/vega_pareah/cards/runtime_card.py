"""runtime_card.py - declares an execution environment: what code it is, what it may do, its limits. Drift is
detected by comparing the hash of the code actually present with the hash on the card. Shape-checked at mint and at check."""
import hmac

from vega_jacket import humanauth  # noqa: E402
from vega_pareah.cards import _common as cm  # noqa: E402
from vega_pareah.cards import license_policy  # noqa: E402


class RuntimeCardRefused(Exception):
    pass


def _hash(card):
    return cm.canonical_hash(card, RuntimeCardRefused)


def _caps(capabilities):
    try:
        humanauth.check_card_capabilities({"capabilities": capabilities})
    except humanauth.HumanAuthError as exc:
        raise RuntimeCardRefused(str(exc)) from exc


def mint_runtime_card(runtime_id: str, code_sha256: str, capabilities, limits: dict,
                      license_class: str = "unknown", reference_uri: str = None) -> dict:
    cm.need_id(runtime_id, "runtime_id", RuntimeCardRefused)
    cm.need_hex64(code_sha256, "code_sha256", RuntimeCardRefused)
    cm.need_uri(reference_uri, "reference_uri", RuntimeCardRefused)
    _caps(capabilities)
    if license_class not in license_policy.CLASSES:
        raise RuntimeCardRefused(f"unknown license class {license_class!r}")
    if not isinstance(limits, dict):
        raise RuntimeCardRefused("limits must be an object")
    card = {"kind": "RUNTIME", "runtime_id": runtime_id, "code_sha256": code_sha256,
            "capabilities": sorted(set(capabilities)), "limits": dict(limits),
            "license_class": license_class, "reference_uri": reference_uri,
            "policy": license_policy.policy_for(license_class)}
    card["card_hash"] = _hash(card)
    return card


def check_runtime(card: dict, observed_code_sha256: str) -> bool:
    """False (never an exception) for a malformed or altered card, a forged policy, a human-only power, or code drift."""
    try:
        if not isinstance(card, dict) or card.get("kind") != "RUNTIME" or not cm.hashes_match(card, RuntimeCardRefused):
            return False
        _caps(card["capabilities"])
        if card["policy"] != license_policy.policy_for(card["license_class"]):
            return False
        return isinstance(observed_code_sha256, str) and hmac.compare_digest(observed_code_sha256, card["code_sha256"])
    except (RuntimeCardRefused, KeyError, TypeError):
        return False
