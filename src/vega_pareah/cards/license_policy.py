"""license_policy.py - what the SDK may do with third-party code, by license class. The SDK redistributes no
third-party source: everything is a REFERENCE (pointer + hash + license class). A reference to permissively
licensed code may be adopted by pointer; every other class stays reference-only and is never copied in.
This is a policy gate, not legal advice; counsel decides edge cases."""

CLASSES = ("permissive", "weak_copyleft", "strong_copyleft", "restricted", "unknown", "no_license")

POLICY = {
    "permissive": {"adopt_by_reference": True, "redistribute": False, "note": "attribution/notice rules still apply"},
    "weak_copyleft": {"adopt_by_reference": False, "redistribute": False, "note": "reference only; counsel review"},
    "strong_copyleft": {"adopt_by_reference": False, "redistribute": False, "note": "reference only; never linked or copied in"},
    "restricted": {"adopt_by_reference": False, "redistribute": False, "note": "reference only; terms limit use"},
    "unknown": {"adopt_by_reference": False, "redistribute": False, "note": "unknown is treated as no permission"},
    "no_license": {"adopt_by_reference": False, "redistribute": False, "note": "no license means no permission"},
}


def policy_for(license_class: str) -> dict:
    return POLICY.get(license_class, POLICY["unknown"])  # anything unrecognised is treated as unknown
