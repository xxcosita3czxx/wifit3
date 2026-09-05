from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from wifit3.campaigns.auth_assoc import Association, WlanTransport, build_client_leaving
from wifit3.dot11 import str_to_mac
from wifit3.dot11.wsc import messages as M
from wifit3.dot11.wsc.assoc_ie import WPS_REQ_REGISTRAR, wps_assoc_ie
from wifit3.models import AccessPoint
from wifit3.wlan.lease import SPOOFABLE


@dataclass(frozen=True)
class WpsM1Identity:
    manufacturer: Optional[str] = None
    model_name: Optional[str] = None
    model_number: Optional[str] = None
    device_name: Optional[str] = None


@dataclass(frozen=True)
class WpsM1ProbeResult:
    ok: bool
    identity: WpsM1Identity = WpsM1Identity()
    detail: str = ""
    our_mac: Optional[str] = None


def _text(attrs: dict[int, bytes], attr: int) -> Optional[str]:
    raw = attrs.get(attr)
    if not raw:
        return None
    value = raw.strip(b"\x00").decode("utf-8", "replace").strip()
    return value or None


def identity_from_m1_attrs(attrs: dict[int, bytes]) -> WpsM1Identity:
    return WpsM1Identity(
        manufacturer=_text(attrs, M.ATTR_MANUFACTURER),
        model_name=_text(attrs, M.ATTR_MODEL_NAME),
        model_number=_text(attrs, M.ATTR_MODEL_NUMBER),
        device_name=_text(attrs, M.ATTR_DEV_NAME),
    )


async def _harvest_m1(transport: WlanTransport, bssid: bytes, our_mac: bytes,
                      tries: int = 10, timeout: float = 3.0) -> dict[int, bytes] | None:
    start = M.build_data_frame(bssid, our_mac, bssid, M.eapol_start())
    await transport.send_no_wait(start)
    last = start
    for _ in range(tries):
        frame = await transport.recv(timeout)
        if frame is None:
            await transport.send_no_wait(last)
            continue
        parsed = M.parse_rx_frame(frame)
        if parsed is None:
            continue
        if parsed.is_identity_request:
            last = M.build_data_frame(bssid, our_mac, bssid, M.eap_identity_response(parsed.eap_id))
            await transport.send_no_wait(last)
        elif parsed.wsc_msg_type == M.WPS_M1:
            return parsed.attrs
    return None


async def probe_wps_m1(array, ap: AccessPoint, iface=None) -> WpsM1ProbeResult:
    bssid = ap.bssid.lower()
    bssid_bytes = str_to_mac(bssid)
    try:
        lease = array.lease(channel=ap.channel, fake_mac=SPOOFABLE, bssid=bssid_bytes,
                            ack_tally=True, iface=iface)
    except Exception as exc:
        return WpsM1ProbeResult(False, detail=str(exc))

    async with lease as iface:
        if lease.mac is None:
            return WpsM1ProbeResult(False, detail="active monitor unavailable")
        our_mac = str_to_mac(lease.mac)
        assoc = Association(
            iface, bssid, ap.ssid or "", ap.channel, our_mac=our_mac,
            assoc_trailer_ies=wps_assoc_ie(WPS_REQ_REGISTRAR),
        )
        transport = WlanTransport(iface, bssid_bytes, our_mac)
        assoc.start()
        try:
            if not await assoc.associate():
                return WpsM1ProbeResult(
                    False, detail=assoc.fail_reason or "no association response", our_mac=lease.mac,
                )
            transport.start()
            attrs = await _harvest_m1(transport, bssid_bytes, our_mac)
        finally:
            transport.stop()
            assoc.stop()
            try:
                await iface.send_no_wait(build_client_leaving(bssid_bytes, our_mac))
            except Exception:
                pass

    if attrs is None:
        return WpsM1ProbeResult(False, detail="no WPS M1 response", our_mac=lease.mac)
    identity = identity_from_m1_attrs(attrs)
    if not any((identity.manufacturer, identity.model_name, identity.model_number, identity.device_name)):
        return WpsM1ProbeResult(False, identity=identity, detail="M1 had no identity fields", our_mac=lease.mac)
    return WpsM1ProbeResult(True, identity=identity, our_mac=lease.mac)
