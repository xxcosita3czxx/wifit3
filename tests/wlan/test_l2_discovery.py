import struct

from wifit3.wlan.fingerprinting.l2_discovery import discovery_claims_from_frame


def _data_frame(body: bytes) -> bytes:
    bssid = bytes.fromhex("aabbccddeeff")
    client = bytes.fromhex("020000000001")
    return b"\x08\x02\x00\x00" + client + bssid + bssid + b"\x00\x00" + body


def _cdp_tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack(">HH", tlv_type, len(value) + 4) + value


def _lldp_tlv(tlv_type: int, value: bytes) -> bytes:
    header = (tlv_type << 9) | len(value)
    return header.to_bytes(2, "big") + value


def test_cdp_claims_cisco_vendor_and_router_kind():
    cdp = (
        b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
        + b"\x02\xb4\x00\x00"
        + _cdp_tlv(1, b"switch-1")
        + _cdp_tlv(4, b"\x00\x00\x00\x01")
        + _cdp_tlv(5, b"Cisco IOS Software")
        + _cdp_tlv(6, b"Cisco C9300")
    )

    claims = discovery_claims_from_frame(_data_frame(cdp))

    assert {claim.name for claim in claims} == {"vendor", "kind"}
    assert any(claim.name == "vendor" and claim.value == "Cisco" and claim.confidence == 0.99
               for claim in claims)
    assert any(claim.name == "kind" and claim.value == "router" and claim.confidence == 0.90
               for claim in claims)
    assert {e.name for claim in claims for e in claim.evidence} >= {"device_id", "software", "platform", "capabilities"}
    assert {e.source for claim in claims for e in claim.evidence} == {"cisco.cdp"}


def test_lldp_claims_cisco_vendor_and_router_kind():
    caps = b"\x00\x14\x00\x10"
    lldp = (
        b"\xaa\xaa\x03\x00\x00\x00\x88\xcc"
        + _lldp_tlv(1, b"\x04" + bytes.fromhex("aabbccddeeff"))
        + _lldp_tlv(2, b"\x03Gi1/0/1")
        + _lldp_tlv(3, b"\x00\x78")
        + _lldp_tlv(5, b"ap-1")
        + _lldp_tlv(6, b"Cisco AP Software")
        + _lldp_tlv(7, caps)
        + b"\x00\x00"
    )

    claims = discovery_claims_from_frame(_data_frame(lldp))

    assert any(claim.name == "vendor" and claim.value == "Cisco" and claim.confidence == 0.99
               for claim in claims)
    assert any(claim.name == "kind" and claim.value == "router" and claim.confidence == 0.90
               for claim in claims)
    assert {e.source for claim in claims for e in claim.evidence} == {"lldp"}
    assert any(e.name == "system_description" and e.value == "Cisco AP Software"
               for claim in claims for e in claim.evidence)


def test_lldp_without_vendor_text_can_still_identify_kind():
    lldp = b"\xaa\xaa\x03\x00\x00\x00\x88\xcc" + _lldp_tlv(7, b"\x00\x08\x00\x08") + b"\x00\x00"

    claims = discovery_claims_from_frame(_data_frame(lldp))

    assert claims[0].name == "kind"
    assert claims[0].value == "router"
    assert claims[0].evidence[0].source == "lldp"
