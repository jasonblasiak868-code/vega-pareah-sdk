"""server_card.py - declares a server (local, external, cloud) and what it is trusted to do. Off-device compute
on data the host must not see is only allowed as LOCKED compute (FHE); if that is not available the card
refuses. It never falls back to plaintext. FHE hides data but does not prove the work was done right, so a
frozen PEAK run is accompanied by an execution proof, verified with a proof tier (fails closed if the tier is
unavailable)."""
from vega_jacket import humanauth  # noqa: E402
from vega_pareah.cards import _common as cm  # noqa: E402
from vega_superproof.seal import fhe, proof_tier0, proof_tier1, proof_tier2  # noqa: E402
from vega_superproof.seal.errors import TierUnavailable  # noqa: E402

LOCATIONS = ("local", "external", "server")
SENSITIVITY = ("open", "locked")


class ServerCardRefused(Exception):
    pass


def _hash(card):
    return cm.canonical_hash(card, ServerCardRefused)


def mint_server_card(server_id: str, location_class: str, capabilities, on_device: bool) -> dict:
    cm.need_id(server_id, "server_id", ServerCardRefused)
    if location_class not in LOCATIONS:
        raise ServerCardRefused(f"location class must be one of {LOCATIONS}")
    if not isinstance(on_device, bool):
        raise ServerCardRefused("on_device must be true or false")
    if on_device and location_class != "local":
        raise ServerCardRefused("only a local server can be on-device")
    try:
        humanauth.check_card_capabilities({"capabilities": capabilities})
    except humanauth.HumanAuthError as exc:
        raise ServerCardRefused(str(exc)) from exc
    card = {"kind": "SERVER", "server_id": server_id, "location_class": location_class,
            "capabilities": sorted(set(capabilities)), "on_device": on_device}
    card["card_hash"] = _hash(card)
    return card


def require_locked_compute(card: dict, data_sensitivity: str) -> str:
    """Returns the compute mode allowed: 'plain' or 'locked'. Raises rather than ever returning a weaker mode."""
    if not isinstance(card, dict) or card.get("kind") != "SERVER" or not cm.hashes_match(card, ServerCardRefused):
        raise ServerCardRefused("server card altered")
    if data_sensitivity not in SENSITIVITY:
        raise ServerCardRefused(f"unknown sensitivity {data_sensitivity!r}")
    if card.get("on_device") is not True and card.get("on_device") is not False:
        raise ServerCardRefused("server card on_device must be true or false")
    if data_sensitivity == "open" or card["on_device"]:
        return "plain"
    if not fhe.available():
        raise fhe.FHEUnavailable("locked data off-device needs FHE and none is registered; refusing plaintext")
    return "locked"


def verify_execution_proof(proof: dict, peak: dict) -> bool:
    """True only if the proof is valid for its tier AND is about exactly this frozen PEAK.
    Tier 0 proves binding (this PEAK, this output hash), not correctness; tiers 1/2 need a registered prover.
    Anything malformed is False, never an exception."""
    try:
        if not isinstance(proof, dict) or not isinstance(peak, dict) or not isinstance(peak.get("dag_hash"), str):
            return False
        tier = proof.get("tier")
        stmt = proof.get("statement")
        if not isinstance(stmt, dict) or stmt.get("peak_dag_hash") != peak["dag_hash"]:
            return False
        if tier == 0:
            return bool(proof_tier0.verify(proof))
        if tier == 1:
            return bool(proof_tier1.verify(proof))
        if tier == 2:
            return bool(proof_tier2.verify(proof))
    except TierUnavailable:
        raise  # unavailable is not the same as invalid: the caller must see that the check could not run
    except Exception:
        return False
    return False
