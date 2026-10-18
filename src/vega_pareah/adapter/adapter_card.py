"""adapter_card.py - ONE adapter card shape for everything: a model, a tool, a server, a repo, a service. The
handshake never changes by adapter; only the data on the card does. An adapter card is a reference (pointer +
hash + license class), never the third-party code itself.

Verified at gate time, not only at mint time: the policy is RE-DERIVED from the license class (a forged card that
claims 'adopt_by_reference' for a copyleft class is refused), and every field is shape-checked."""
from vega_jacket import humanauth  # noqa: E402
from vega_pareah.cards import _common as cm  # noqa: E402
from vega_pareah.cards import license_policy  # noqa: E402

KINDS = ("model", "tool", "server", "repo", "service")


class AdapterCardRefused(Exception):
    pass


def card_hash(card: dict) -> str:
    return cm.canonical_hash(card, AdapterCardRefused)


def _caps(capabilities):
    try:
        humanauth.check_card_capabilities({"capabilities": capabilities})
    except humanauth.HumanAuthError as exc:
        raise AdapterCardRefused(str(exc)) from exc
    if any(not c.strip() for c in capabilities):
        raise AdapterCardRefused("blank capability")


def mint_adapter_card(adapter_id: str, kind: str, capabilities, code_sha256: str,
                      license_class: str = "unknown", reference_uri: str = None) -> dict:
    cm.need_id(adapter_id, "adapter_id", AdapterCardRefused)
    if kind not in KINDS:
        raise AdapterCardRefused(f"kind must be one of {KINDS}")
    if license_class not in license_policy.CLASSES:
        raise AdapterCardRefused(f"unknown license class {license_class!r}")
    cm.need_hex64(code_sha256, "code_sha256", AdapterCardRefused)
    cm.need_uri(reference_uri, "reference_uri", AdapterCardRefused)
    _caps(capabilities)
    card = {"kind": "ADAPTER", "adapter_id": adapter_id, "adapter_kind": kind,
            "capabilities": sorted(set(capabilities)), "code_sha256": code_sha256,
            "license_class": license_class, "reference_uri": reference_uri,
            "policy": license_policy.policy_for(license_class)}
    card["card_hash"] = card_hash(card)
    return card


def verify_adapter_card(card: dict) -> None:
    if not isinstance(card, dict) or card.get("kind") != "ADAPTER" or not cm.hashes_match(card, AdapterCardRefused):
        raise AdapterCardRefused("adapter card altered")
    try:
        cm.need_id(card["adapter_id"], "adapter_id", AdapterCardRefused)
        cm.need_hex64(card["code_sha256"], "code_sha256", AdapterCardRefused)
        cm.need_uri(card["reference_uri"], "reference_uri", AdapterCardRefused)
        if card["adapter_kind"] not in KINDS or card["license_class"] not in license_policy.CLASSES:
            raise AdapterCardRefused("unknown kind or license class")
        if card["policy"] != license_policy.policy_for(card["license_class"]):
            raise AdapterCardRefused("policy does not match the license class (forged card)")
        _caps(card["capabilities"])  # at gate time, not only at mint time
    except KeyError as exc:
        raise AdapterCardRefused(f"adapter card missing field {exc}") from exc
