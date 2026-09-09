from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from rich.markup import escape

from wifit3.campaigns.mikrotik_probe import probe_mikrotik
from wifit3.campaigns.ubiquiti_probe import probe_ubnt
from wifit3.campaigns.wps.m1_probe import probe_wps_m1
from wifit3.dot11.wsc.identity import WpsM1Identity
from wifit3.models import AccessPoint
from wifit3.wlan.fingerprinting.router import RouterClaim, RouterEvidence


@dataclass(frozen=True)
class RouterProbeResult:
    ok: bool
    source: str = ""
    detail: str = ""
    wps_identity: Optional[WpsM1Identity] = None
    claims: tuple[RouterClaim, ...] = ()


ProbeLog = Callable[[str, str], None]


async def probe_router_info(array, ap: AccessPoint, iface=None, log: ProbeLog | None = None) -> RouterProbeResult:
    failures = []
    sources: list[str] = []
    claims: list[RouterClaim] = []
    wps_identity: WpsM1Identity | None = None

    if ap.wps:
        _log_probe_step(log, "try", "WPS M1")
        result = await probe_wps_m1(array, ap, iface=iface)
        if result.ok:
            _log_probe_step(log, "ok", "WPS M1")
            sources.append("wps.m1")
            wps_identity = _ap_wps_identity(ap)
        else:
            _log_probe_step(log, "fail", f"WPS M1: {result.detail}")
            failures.append(f"WPS M1: {result.detail}")

    _log_probe_step(log, "try", "MikroTik WinBox")
    result = await probe_mikrotik(array, ap, iface=iface)
    if result.ok:
        _log_probe_step(log, "ok", "MikroTik WinBox")
        sources.append(result.source)
        claims.extend(result.claims)
    else:
        _log_probe_step(log, "fail", f"MikroTik WinBox: {result.detail}")
        failures.append(f"MikroTik WinBox: {result.detail}")

    _log_probe_step(log, "try", "UBNT discovery")
    result = await probe_ubnt(array, ap, iface=iface)
    if result.ok:
        _log_probe_step(log, "ok", "UBNT discovery")
        sources.append("ubnt.discovery")
        claims.extend(result.claims)
    else:
        _log_probe_step(log, "fail", f"UBNT discovery: {result.detail}")
        failures.append(f"UBNT discovery: {result.detail}")

    if sources:
        return RouterProbeResult(
            ok=True,
            source=", ".join(dict.fromkeys(source for source in sources if source)),
            detail="; ".join(failures),
            wps_identity=wps_identity,
            claims=tuple(dict.fromkeys(claims)),
        )
    return RouterProbeResult(False, detail="; ".join(failures))


def _log_probe_step(log: ProbeLog | None, status: str, detail: str) -> None:
    if log is not None:
        log(status, detail)


def format_probe_step(status: str, detail: str) -> str:
    if status == "try":
        return f"trying {escape(detail)}"
    if status == "ok":
        return f"{escape(detail)} responded"
    return f"{escape(detail)} failed"


def format_probe_result(result: RouterProbeResult) -> str:
    parts: list[str] = []
    if result.wps_identity is not None:
        fields = format_wps_m1_identity(result.wps_identity)
        parts.append(f"WPS M1: {fields}" if fields else "WPS M1 received")
    if result.claims:
        fields = ", ".join(f"{claim.name}={escape(claim.value)} {round(claim.confidence * 100)}%"
                           for claim in result.claims)
        parts.append(f"{result.source}: {fields}" if result.source else fields)
    if parts:
        return "; ".join(parts)
    return result.source or "identity probe matched"


def format_wps_m1_identity(identity: WpsM1Identity) -> str:
    model_number = identity.model_number
    if model_number == identity.model_name:
        model_number = None
    parts = [
        ("mfr", identity.manufacturer),
        ("model", identity.model_name),
        ("model_no", model_number),
        ("name", identity.device_name),
        ("type", identity.primary_device_type),
    ]
    return ", ".join(f"{name}={escape(value)}" for name, value in parts if value)


def format_probe_evidence(result: RouterProbeResult) -> tuple[str, ...]:
    seen: set[RouterEvidence] = set()
    evidence = list(_wps_probe_evidence(result.wps_identity)) if result.wps_identity else []
    for claim in result.claims:
        evidence.extend(claim.evidence)
    unique = []
    for item in evidence:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return tuple(_format_evidence(item) for item in sorted(unique, key=_evidence_sort_key))


def _wps_probe_evidence(identity: WpsM1Identity) -> tuple[RouterEvidence, ...]:
    evidence = []
    if identity.manufacturer:
        evidence.append(RouterEvidence("wps.m1", "manufacturer", identity.manufacturer, 0.99, passive=False))
    model = identity.model_name or identity.model_number
    if model:
        evidence.append(RouterEvidence("wps.m1", "model", model, 0.99, passive=False))
    if identity.device_name:
        evidence.append(RouterEvidence("wps.m1", "device_name", identity.device_name, 0.99, passive=False))
    if identity.primary_device_type:
        evidence.append(RouterEvidence("wps.m1", "primary_device_type", identity.primary_device_type, 0.99, passive=False))
    return tuple(evidence)


def _format_evidence(evidence: RouterEvidence) -> str:
    return (
        f"[dim]{escape(evidence.source)}:[/dim] {escape(evidence.name)}={escape(evidence.value)} "
        f"({round(evidence.confidence * 100)}%)"
    )


def _evidence_sort_key(evidence: RouterEvidence) -> tuple[str, str, str, float, bool]:
    return (evidence.source, evidence.name, evidence.value, -evidence.confidence, evidence.passive)


def _ap_wps_identity(ap: AccessPoint) -> WpsM1Identity:
    return WpsM1Identity(
        manufacturer=ap.wps_m1_manufacturer or ap.wps_manufacturer,
        model_name=ap.wps_m1_model_name or ap.wps_model_name,
        model_number=ap.wps_m1_model_number or ap.wps_model_number,
        device_name=ap.wps_m1_device_name or ap.wps_device_name,
        primary_device_type=ap.wps_m1_primary_device_type or ap.wps_primary_device_type,
    )
