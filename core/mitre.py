"""MITRE ATT&CK enrichment for Logener/Wazuh alerts.

Logener emits Wazuh-shaped alerts that carry ``rule.id``, ``rule.level`` and
``rule.groups`` but **no** ATT&CK metadata. Real Wazuh deployments attach
technique identifiers through rule metadata; this module is the equivalent
lookup layer for NekoWatch, so alerts become filterable by tactic/technique.

Enrichment is applied in three passes, most specific first:

1. exact ``rule.id`` match (:data:`RULE_TECHNIQUES`);
2. ``rule.groups`` match (:data:`GROUP_TECHNIQUES`);
3. behavioural heuristics, e.g. a Tor-looking device fingerprint.

Technique and tactic names follow ATT&CK Enterprise v14 wording.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    """A single ATT&CK technique together with the tactic it serves."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str

    @property
    def base_technique_id(self) -> str:
        """Parent technique id (``T1110.001`` -> ``T1110``)."""
        return self.technique_id.split(".", 1)[0]


# --------------------------------------------------------------------- tactics
TA0001 = ("TA0001", "Initial Access")
TA0006 = ("TA0006", "Credential Access")
TA0011 = ("TA0011", "Command and Control")
TA0040 = ("TA0040", "Impact")


# ------------------------------------------------------------------ techniques
T1110 = MitreTechnique("T1110", "Brute Force", *TA0006)
T1110_001 = MitreTechnique("T1110.001", "Password Guessing", *TA0006)
T1621 = MitreTechnique(
    "T1621", "Multi-Factor Authentication Request Generation", *TA0006
)
T1078 = MitreTechnique("T1078", "Valid Accounts", *TA0001)
T1090_003 = MitreTechnique("T1090.003", "Proxy: Multi-hop Proxy", *TA0011)
T1565 = MitreTechnique("T1565", "Data Manipulation", *TA0040)
T1565_001 = MitreTechnique("T1565.001", "Stored Data Manipulation", *TA0040)
T1499 = MitreTechnique("T1499", "Endpoint Denial of Service", *TA0040)

#: Every technique NekoWatch can attach, keyed by id (useful for UI dropdowns).
TECHNIQUE_CATALOG: dict[str, MitreTechnique] = {
    t.technique_id: t
    for t in (
        T1078,
        T1090_003,
        T1110,
        T1110_001,
        T1499,
        T1565,
        T1565_001,
        T1621,
    )
}

#: Wazuh ``rule.id`` -> techniques. Rule ids come from ``logener/logener2.py``.
RULE_TECHNIQUES: dict[str, tuple[MitreTechnique, ...]] = {
    "5710": (T1078,),          # successful password authentication
    "5711": (T1078,),          # successful OTP authentication
    "5712": (T1110,),          # authentication failed
    "5713": (T1078,),          # login from a new device
    "5742": (T1565,),          # large transfer initiated
    "5750": (T1565_001,),      # balance anomaly
    "5751": (T1078, T1565),    # security incident
    "5752": (T1110_001,),      # brute force attack
    "5753": (T1078,),          # geolocation anomaly
    "5760": (T1621,),          # OTP code sent (MFA-fatigue hunting)
    "5782": (T1499,),          # API rate limit approaching
    "5784": (T1499,),          # database connection timeout
    "5786": (T1499,),          # authentication service overloaded
}

#: Fallback mapping on ``rule.groups`` for rule ids we do not know yet.
GROUP_TECHNIQUES: dict[str, tuple[MitreTechnique, ...]] = {
    "bruteforce": (T1110,),
    "geo": (T1078,),
    "anomaly": (T1565,),
    "incident": (T1078,),
}

#: Device-fingerprint substrings that imply anonymising infrastructure.
_ANONYMISER_HINTS = ("tor", "proxy", "vpn")


def techniques_for(
    rule_id: str | None,
    groups: Sequence[str] | None = None,
    device_fingerprint: str | None = None,
) -> tuple[MitreTechnique, ...]:
    """Resolve ATT&CK techniques for one alert.

    Args:
        rule_id: Wazuh ``rule.id`` of the alert.
        groups: Wazuh ``rule.groups`` list, used when ``rule_id`` is unknown.
        device_fingerprint: Client fingerprint; Tor/proxy-looking values add
            :data:`T1090_003` on top of the rule-derived techniques.

    Returns:
        Deduplicated techniques, ordered deterministically by technique id.
    """
    found: dict[str, MitreTechnique] = {}

    if rule_id and rule_id in RULE_TECHNIQUES:
        for technique in RULE_TECHNIQUES[rule_id]:
            found[technique.technique_id] = technique
    elif groups:
        for group in groups:
            for technique in GROUP_TECHNIQUES.get(group.lower(), ()):
                found[technique.technique_id] = technique

    if device_fingerprint:
        lowered = device_fingerprint.lower()
        if any(hint in lowered for hint in _ANONYMISER_HINTS):
            found[T1090_003.technique_id] = T1090_003

    return tuple(sorted(found.values(), key=lambda t: t.technique_id))


def technique_ids(techniques: Iterable[MitreTechnique]) -> list[str]:
    """Extract sorted, unique technique ids."""
    return sorted({t.technique_id for t in techniques})


def tactic_ids(techniques: Iterable[MitreTechnique]) -> list[str]:
    """Extract sorted, unique tactic ids."""
    return sorted({t.tactic_id for t in techniques})


def matches_technique(stored_ids: Sequence[str], wanted: str) -> bool:
    """Check whether ``wanted`` matches any stored technique id.

    A parent technique matches its sub-techniques, so ``T1110`` matches an
    alert tagged ``T1110.001``, while ``T1110.001`` only matches exactly.
    """
    target = wanted.strip().upper()
    if not target:
        return True
    for stored in stored_ids:
        stored_up = stored.upper()
        if stored_up == target:
            return True
        if "." not in target and stored_up.split(".", 1)[0] == target:
            return True
    return False


def describe(technique_id: str) -> MitreTechnique | None:
    """Look up a technique by id, tolerating lower-case input."""
    return TECHNIQUE_CATALOG.get(technique_id.strip().upper())


def catalog() -> list[dict[str, str]]:
    """Serialisable technique catalog for API responses and UI filters."""
    return [
        {
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactic_id": t.tactic_id,
            "tactic_name": t.tactic_name,
        }
        for t in sorted(TECHNIQUE_CATALOG.values(), key=lambda x: x.technique_id)
    ]


def tactic_catalog() -> list[dict[str, str]]:
    """Serialisable tactic catalog (deduplicated, ordered by tactic id)."""
    seen: dict[str, str] = {
        t.tactic_id: t.tactic_name for t in TECHNIQUE_CATALOG.values()
    }
    return [
        {"tactic_id": tid, "tactic_name": name} for tid, name in sorted(seen.items())
    ]
