from __future__ import annotations

import struct

from wifit3.wlan.fingerprinting.router_types import RouterClaim, RouterEvidence

_LLC_SNAP = b"\xaa\xaa\x03"
_RFC1042_OUI = b"\x00\x00\x00"
_CISCO_OUI = b"\x00\x00\x0c"
_ETHERTYPE_LLDP = b"\x88\xcc"
_PID_CDP = b"\x20\x00"
_CDP_MIN_LEN = 4

_LLDP_CAPS = {
    0x0004: "bridge",
    0x0008: "wlan_ap",
    0x0010: "router",
    0x0020: "telephone",
}
_CDP_CAP_ROUTER = 0x01
_CDP_CAP_SWITCH = 0x08


def discovery_claims_from_frame(frame: bytes, *, passive: bool = True) -> tuple[RouterClaim, ...]:
    payload = _snap_payload(frame)
    if payload is None:
        return ()
    if payload.startswith(_CISCO_OUI + _PID_CDP):
        return cdp_claims(payload[5:], passive=passive)
    if payload.startswith(_RFC1042_OUI + _ETHERTYPE_LLDP):
        return lldp_claims(payload[5:], passive=passive)
    return ()


def cdp_claims(payload: bytes, *, passive: bool = True) -> tuple[RouterClaim, ...]:
    if len(payload) < _CDP_MIN_LEN:
        return ()
    tlvs = _cdp_tlvs(payload[4:])
    evidence = _cdp_evidence(tlvs, passive=passive)
    if not evidence:
        return ()
    claims = [RouterClaim("vendor", "Cisco", 0.99, evidence)]
    kind = _cdp_kind(tlvs.get(4, b""))
    if kind is not None:
        claims.append(RouterClaim("kind", kind, 0.90, (RouterEvidence("cisco.cdp", "capabilities", kind, 0.90, passive=passive),)))
    return tuple(claims)


def lldp_claims(payload: bytes, *, passive: bool = True) -> tuple[RouterClaim, ...]:
    tlvs = _lldp_tlvs(payload)
    claims: list[RouterClaim] = []
    system_evidence = _lldp_system_evidence(tlvs, passive=passive)
    text = " ".join(evidence.value for evidence in system_evidence).lower()
    if "cisco" in text:
        claims.append(RouterClaim("vendor", "Cisco", 0.99, system_evidence))
    kind = _lldp_kind(tlvs.get(7, b""))
    if kind is not None:
        evidence = RouterEvidence("lldp", "capabilities", kind, 0.90, passive=passive)
        claims.append(RouterClaim("kind", kind, 0.90, (evidence,)))
    return tuple(claims)


def _snap_payload(frame: bytes) -> bytes | None:
    if len(frame) < 24 + len(_LLC_SNAP) + 5:
        return None
    fc0, fc1 = frame[0], frame[1]
    if ((fc0 >> 2) & 0x03) != 2 or fc1 & 0x40:
        return None
    body = frame[24:]
    if not body.startswith(_LLC_SNAP):
        return None
    return body[len(_LLC_SNAP):]


def _cdp_tlvs(data: bytes) -> dict[int, bytes]:
    tlvs: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(data):
        tlv_type, tlv_len = struct.unpack(">HH", data[offset:offset + 4])
        if tlv_len < 4 or offset + tlv_len > len(data):
            break
        tlvs.setdefault(tlv_type, data[offset + 4:offset + tlv_len])
        offset += tlv_len
    return tlvs


def _cdp_evidence(tlvs: dict[int, bytes], *, passive: bool) -> tuple[RouterEvidence, ...]:
    fields = ((1, "device_id"), (5, "software"), (6, "platform"))
    evidence = []
    for tlv_type, name in fields:
        value = _safe_text(tlvs.get(tlv_type, b""))
        if value:
            evidence.append(RouterEvidence("cisco.cdp", name, value, 0.99, passive=passive))
    if evidence:
        return tuple(evidence)
    return (RouterEvidence("cisco.cdp", "present", "true", 0.99, passive=passive),)


def _cdp_kind(value: bytes) -> str | None:
    if len(value) < 4:
        return None
    caps = int.from_bytes(value[:4], "big")
    if caps & _CDP_CAP_ROUTER:
        return "router"
    if caps & _CDP_CAP_SWITCH:
        return "router"
    return None


def _lldp_tlvs(data: bytes) -> dict[int, bytes]:
    tlvs: dict[int, bytes] = {}
    offset = 0
    while offset + 2 <= len(data):
        header = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        tlv_type = header >> 9
        tlv_len = header & 0x01FF
        if tlv_type == 0:
            break
        if offset + tlv_len > len(data):
            break
        tlvs.setdefault(tlv_type, data[offset:offset + tlv_len])
        offset += tlv_len
    return tlvs


def _lldp_system_evidence(tlvs: dict[int, bytes], *, passive: bool) -> tuple[RouterEvidence, ...]:
    evidence = []
    system_name = _safe_text(tlvs.get(5, b""))
    if system_name:
        evidence.append(RouterEvidence("lldp", "system_name", system_name, 0.99, passive=passive))
    system_description = _safe_text(tlvs.get(6, b""))
    if system_description:
        evidence.append(RouterEvidence("lldp", "system_description", system_description, 0.99, passive=passive))
    return tuple(evidence) or (RouterEvidence("lldp", "present", "true", 0.70, passive=passive),)


def _lldp_kind(value: bytes) -> str | None:
    if len(value) < 4:
        return None
    enabled = int.from_bytes(value[2:4], "big")
    if enabled & 0x0010:
        return "router"
    if enabled & 0x0008:
        return "router"
    if enabled & 0x0020:
        return "hotspot"
    if enabled & 0x0004:
        return "router"
    return next((_LLDP_CAPS[bit] for bit in _LLDP_CAPS if enabled & bit), None)


def _safe_text(value: bytes) -> str:
    return value.rstrip(b"\x00").decode("utf-8", "replace").strip()
