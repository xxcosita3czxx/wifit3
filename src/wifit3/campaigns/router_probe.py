from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from wifit3.campaigns.wps.m1_probe import WpsM1Identity, probe_wps_m1
from wifit3.models import AccessPoint


@dataclass(frozen=True)
class RouterProbeResult:
    ok: bool
    source: str = ""
    detail: str = ""
    wps_identity: Optional[WpsM1Identity] = None


async def probe_router_info(array, ap: AccessPoint, iface=None) -> RouterProbeResult:
    if ap.wps:
        result = await probe_wps_m1(array, ap, iface=iface)
        return RouterProbeResult(
            ok=result.ok,
            source="wps.m1",
            detail=result.detail,
            wps_identity=result.identity if result.ok else None,
        )
    return RouterProbeResult(False, detail="no active probe provider for this AP")
