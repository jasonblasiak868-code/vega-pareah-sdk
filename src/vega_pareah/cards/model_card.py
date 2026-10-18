"""model_card.py - identity of a model: which one, from whom, under what license class, and (when frozen) the
hash of its weights. Models are referenced, never redistributed. check_model never raises on a hostile card: it says False."""
import hmac

from vega_pareah.cards import _common as cm  # noqa: E402
from vega_pareah.cards import license_policy  # noqa: E402


class ModelCardRefused(Exception):
    pass


def _hash(card):
    return cm.canonical_hash(card, ModelCardRefused)


def mint_model_card(model_id: str, provider: str, license_class: str = "unknown",
                    weights_sha256: str = None, endpoint: str = None) -> dict:
    cm.need_id(model_id, "model_id", ModelCardRefused)
    cm.need_id(provider, "provider", ModelCardRefused)
    cm.need_hex64(weights_sha256, "weights_sha256", ModelCardRefused, optional=True)
    cm.need_uri(endpoint, "endpoint", ModelCardRefused)
    if license_class not in license_policy.CLASSES:
        raise ModelCardRefused(f"unknown license class {license_class!r}")
    card = {"kind": "MODEL", "model_id": model_id, "provider": provider, "license_class": license_class,
            "weights_sha256": weights_sha256, "endpoint": endpoint, "frozen": weights_sha256 is not None,
            "policy": license_policy.policy_for(license_class)}
    card["card_hash"] = _hash(card)
    return card


def check_model(card: dict, observed_weights_sha256: str = None) -> bool:
    """A frozen card requires the observed weights hash to match. An unfrozen (API) card cannot be hash-checked
    and says so: returns False rather than pretending."""
    try:
        if not isinstance(card, dict) or card.get("kind") != "MODEL" or not cm.hashes_match(card, ModelCardRefused):
            return False
        if card["policy"] != license_policy.policy_for(card["license_class"]):
            return False
        if card["frozen"] is not True or not isinstance(card["weights_sha256"], str):
            return False
        return isinstance(observed_weights_sha256, str) and hmac.compare_digest(observed_weights_sha256, card["weights_sha256"])
    except (ModelCardRefused, KeyError, TypeError):
        return False
