"""Confidence-scored AP/router identity from weak OUI and stronger WPS evidence."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, TYPE_CHECKING

from wifit3.wlan.fingerprint_vendors import VENDOR_BY_OUI

if TYPE_CHECKING:
    from wifit3.models import AccessPoint


@dataclass(frozen=True)
class RouterEvidence:
    source: str
    name: str
    value: str
    confidence: float
    passive: bool = True


@dataclass(frozen=True)
class RouterClaim:
    name: str
    value: str
    confidence: float
    evidence: tuple[RouterEvidence, ...]
    vendor: str | None = None


@dataclass(frozen=True)
class RouterFingerprint:
    label: str
    confidence: float
    vendor: str | None = None
    vendor_confidence: float = 0.0
    model: str | None = None
    model_confidence: float = 0.0
    kind: str = "router"
    kind_confidence: float = 0.0
    claims: tuple[RouterClaim, ...] = ()
    evidence: tuple[RouterEvidence, ...] = ()


RouterRule = Callable[["AccessPoint"], Iterable[RouterClaim]]
_PREFIX_LENGTHS = (9, 7, 6)
_VENDOR_ALIASES = {
    "asus": "ASUS",
    "belkin": "Belkin",
    "dlink": "D-Link",
    "edimax": "Edimax",
    "thomson": "Thomson",
    "upvel": "Upvel",
}


def _hex_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").upper()


def _vendor_for(mac: str) -> str | None:
    hex_mac = _hex_mac(mac)
    return next((VENDOR_BY_OUI[hex_mac[:n]] for n in _PREFIX_LENGTHS
                 if hex_mac[:n] in VENDOR_BY_OUI), None)


def _combine(confidences: Iterable[float], cap: float = 0.98) -> float:
    miss = 1.0
    for confidence in confidences:
        miss *= 1.0 - max(0.0, min(confidence, 1.0))
    return min(cap, 1.0 - miss)


def _confidence_for(claims: Iterable[RouterClaim], name: str, value: str | None) -> float:
    if value is None:
        return 0.0
    return _combine(claim.confidence for claim in claims if claim.name == name and claim.value == value)


def _best(claims: Iterable[RouterClaim], name: str) -> RouterClaim | None:
    matching = [claim for claim in claims if claim.name == name]
    return max(matching, key=lambda claim: claim.confidence, default=None)


def _text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip("\x00")
    return cleaned or None


def oui_vendor_rule(ap: "AccessPoint") -> Iterable[RouterClaim]:
    vendor = _vendor_for(ap.bssid)
    if vendor is None:
        return ()
    evidence = RouterEvidence("oui.vendor", "vendor", vendor, 0.30)
    return (RouterClaim("vendor", vendor, 0.30, (evidence,)),)


def router_oui_rule(ap: "AccessPoint") -> Iterable[RouterClaim]:
    from wifit3.campaigns.wps.wps_router_ouis import OUI_VENDOR

    vendor = OUI_VENDOR.get(_hex_mac(ap.bssid)[:6])
    if vendor is None:
        return ()
    label = _VENDOR_ALIASES.get(vendor, vendor.title())
    evidence = RouterEvidence("oui.router", "vendor", label, 0.45)
    return (
        RouterClaim("vendor", label, 0.45, (evidence,)),
        RouterClaim("kind", "router", 0.45, (evidence,)),
    )


def passive_wps_identity_rule(ap: "AccessPoint") -> Iterable[RouterClaim]:
    claims: list[RouterClaim] = []
    manufacturer = _text(getattr(ap, "wps_manufacturer", None))
    model = _text(getattr(ap, "wps_model_name", None)) or _text(getattr(ap, "wps_model_number", None))
    device_name = _text(getattr(ap, "wps_device_name", None))

    if manufacturer is not None:
        evidence = RouterEvidence("wps.passive", "manufacturer", manufacturer, 0.80)
        claims.append(RouterClaim("vendor", manufacturer, 0.80, (evidence,)))
        claims.append(RouterClaim("kind", "router", 0.65, (evidence,)))
    if model is not None:
        evidence = RouterEvidence("wps.passive", "model", model, 0.88)
        claims.append(RouterClaim("model", model, 0.88, (evidence,)))
    if device_name is not None:
        evidence = RouterEvidence("wps.passive", "device_name", device_name, 0.60)
        claims.append(RouterClaim("device_name", device_name, 0.60, (evidence,)))
    return claims


ROUTER_RULES: tuple[RouterRule, ...] = (
    oui_vendor_rule,
    router_oui_rule,
    passive_wps_identity_rule,
)


def fingerprint_router(ap: "AccessPoint", rules: Iterable[RouterRule] = ROUTER_RULES) -> RouterFingerprint | None:
    claims = tuple(claim for rule in rules for claim in rule(ap))
    if not claims:
        return None

    evidence = tuple(item for claim in claims for item in claim.evidence)
    vendor = _best(claims, "vendor")
    model = _best(claims, "model")
    kind = _best(claims, "kind")

    vendor_value = vendor.value if vendor is not None else None
    model_value = model.value if model is not None else None
    if vendor_value is None and model is not None and model.vendor is not None:
        vendor_value = model.vendor
        claims += (RouterClaim("vendor", model.vendor, model.confidence, model.evidence),)
    kind_value = kind.value if kind is not None else "router"
    vendor_confidence = _confidence_for(claims, "vendor", vendor_value)
    model_confidence = _confidence_for(claims, "model", model_value)
    kind_confidence = _confidence_for(claims, "kind", kind_value)
    identity_confidence = max(vendor_confidence, model_confidence, kind_confidence)

    label_parts = [vendor_value]
    if model_value is not None and model_confidence >= 0.75:
        label_parts.append(model_value)
    label_parts.append(kind_value)
    label = " ".join(dict.fromkeys(part for part in label_parts if part))
    if identity_confidence < 0.75:
        label = f"Possible {label}"
    elif identity_confidence < 0.90:
        label = f"Likely {label}"

    return RouterFingerprint(
        label=label,
        confidence=identity_confidence,
        vendor=vendor_value,
        vendor_confidence=vendor_confidence,
        model=model_value,
        model_confidence=model_confidence,
        kind=kind_value,
        kind_confidence=kind_confidence,
        claims=claims,
        evidence=evidence,
    )
