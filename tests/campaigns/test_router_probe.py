from dataclasses import dataclass

from wifit3.campaigns.router_probe import format_probe_evidence, probe_router_info
from wifit3.models import AccessPoint
from wifit3.wlan.fingerprinting.router import RouterClaim, RouterEvidence


@dataclass(frozen=True)
class _Result:
    ok: bool
    source: str = ""
    detail: str = ""
    claims: tuple[RouterClaim, ...] = ()


async def test_router_info_probe_falls_back_to_ubnt(monkeypatch):
    async def fail_mikrotik(array, ap, iface=None):
        return _Result(False, detail="no WinBox response")

    async def find_ubnt(array, ap, iface=None):
        evidence = RouterEvidence("ubnt.discovery", "reachable", "true", 0.99, passive=False)
        return _Result(True, source="ubnt.discovery", claims=(RouterClaim("vendor", "Ubiquiti", 0.99, (evidence,)),))

    import wifit3.campaigns.router_probe as router_probe

    monkeypatch.setattr(router_probe, "probe_mikrotik", fail_mikrotik)
    monkeypatch.setattr(router_probe, "probe_ubnt", find_ubnt)

    result = await probe_router_info(None, AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6))

    assert result.ok is True
    assert result.source == "ubnt.discovery"
    assert result.claims[0].value == "Ubiquiti"


async def test_router_info_probe_runs_all_methods_after_wps_success(monkeypatch):
    calls = []
    steps = []

    async def find_wps(array, ap, iface=None):
        calls.append("wps")
        ap.wps_m1_manufacturer = "Kaon"
        ap.wps_m1_model_name = "O2SMARTBOX2"
        return _Result(True)

    async def find_mikrotik(array, ap, iface=None):
        calls.append("mikrotik")
        evidence = RouterEvidence("mikrotik.winbox.mac", "reachable", "true", 0.99, passive=False)
        return _Result(True, source="mikrotik.winbox.mac", claims=(
            RouterClaim("vendor", "MikroTik", 0.99, (evidence,)),
            RouterClaim("kind", "router", 0.99, (evidence,)),
        ))

    async def fail_ubnt(array, ap, iface=None):
        calls.append("ubnt")
        return _Result(False, detail="no reply")

    import wifit3.campaigns.router_probe as router_probe

    monkeypatch.setattr(router_probe, "probe_wps_m1", find_wps)
    monkeypatch.setattr(router_probe, "probe_mikrotik", find_mikrotik)
    monkeypatch.setattr(router_probe, "probe_ubnt", fail_ubnt)

    result = await probe_router_info(
        None,
        AccessPoint(bssid="aa:bb:cc:dd:ee:ff", channel=6, wps=True),
        log=lambda status, detail: steps.append((status, detail)),
    )

    assert calls == ["wps", "mikrotik", "ubnt"]
    assert result.ok is True
    assert result.source == "wps.m1, mikrotik.winbox.mac"
    assert result.wps_identity is not None
    assert result.wps_identity.model_name == "O2SMARTBOX2"
    assert {claim.value for claim in result.claims} == {"MikroTik", "router"}
    assert ("try", "UBNT discovery") in steps
    assert ("fail", "UBNT discovery: no reply") in steps
    evidence = format_probe_evidence(result)
    assert "[dim]wps.m1:[/dim] model=O2SMARTBOX2 (99%)" in evidence
    assert "[dim]mikrotik.winbox.mac:[/dim] reachable=true (99%)" in evidence
