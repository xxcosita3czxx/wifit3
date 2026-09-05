from wifit3.models import AccessPoint
from wifit3.wlan.router_fingerprint import (
    RouterClaim,
    RouterEvidence,
    canonical_vendor,
    fingerprint_router,
    passive_wps_identity_rule,
)


def test_oui_only_is_possible_vendor_not_exact_router():
    fp = AccessPoint(bssid="00:00:0b:aa:bb:cc").router_fingerprint
    assert fp is not None
    assert fp.vendor == "Matrix"
    assert fp.model is None
    assert fp.vendor_confidence <= 0.45
    assert fp.model_confidence == 0.0
    assert fp.confidence == fp.vendor_confidence
    assert fp.label == "Possible Matrix router"


def test_passive_wps_manufacturer_and_model_make_stronger_router_fingerprint():
    ap = AccessPoint(
        bssid="02:00:00:00:00:01",
        wps_manufacturer="MikroTik",
        wps_model_name="hAP ac²",
        wps_device_name="Office AP",
    )
    fp = ap.router_fingerprint
    assert fp is not None
    assert fp.vendor == "MikroTik"
    assert fp.model == "hAP ac²"
    assert fp.vendor_confidence == 0.99
    assert fp.model_confidence == 0.99
    assert fp.kind_confidence == 0.99
    assert fp.confidence == 0.99
    assert fp.label == "MikroTik hAP ac² router"
    assert {e.name for e in fp.evidence} >= {"manufacturer", "model", "device_name"}


def test_rules_are_pluggable_for_router_specific_checks():
    def mikrotik_tool_rule(ap):
        evidence = RouterEvidence("mikrotik.winbox", "mac_server", "reachable", 0.92)
        return (RouterClaim("vendor", "MikroTik", 0.92, (evidence,)),)

    ap = AccessPoint(bssid="02:00:00:00:00:01")
    fp = fingerprint_router(ap, rules=(mikrotik_tool_rule,))
    assert fp is not None
    assert fp.vendor == "MikroTik"
    assert fp.vendor_confidence == 0.92
    assert fp.model_confidence == 0.0
    assert fp.confidence == 0.92
    assert fp.label == "MikroTik router"
    assert fp.evidence[0].source == "mikrotik.winbox"


def test_low_confidence_model_claim_does_not_enter_headline_label():
    def weak_model_rule(ap):
        evidence = RouterEvidence("ssid.pattern", "model", "hAP ac²", 0.40)
        return (
            RouterClaim("vendor", "MikroTik", 0.92, (evidence,)),
            RouterClaim("model", "hAP ac²", 0.40, (evidence,)),
        )

    fp = fingerprint_router(AccessPoint(bssid="02:00:00:00:00:01"), rules=(weak_model_rule,))
    assert fp is not None
    assert fp.vendor_confidence == 0.92
    assert fp.model == "hAP ac²"
    assert fp.model_confidence == 0.40
    assert fp.label == "MikroTik router"


def test_vendor_names_are_canonicalized():
    assert canonical_vendor("Tp-Link Technologies") == "TP-Link"
    assert canonical_vendor("TP-Link") == "TP-Link"
    assert canonical_vendor("AVM Audiovisuelles Marketing und Computersysteme") == "AVM"
    assert canonical_vendor("AMV Audio") == "AMV"
    assert canonical_vendor("Kaon Group") == "Kaon"
    assert canonical_vendor("Kaon") == "Kaon"
    assert canonical_vendor("Routerboard.com") == "MikroTik"


def test_oui_vendor_rule_uses_canonical_vendor_name():
    tplink = AccessPoint(bssid="00:0a:eb:11:22:33").router_fingerprint
    avm = AccessPoint(bssid="0c:72:74:11:22:33").router_fingerprint
    assert tplink is not None and tplink.vendor == "TP-Link"
    assert avm is not None and avm.vendor == "AVM"


def test_wps_manufacturer_uses_canonical_vendor_name():
    fp = AccessPoint(
        bssid="02:00:00:00:00:01",
        wps_manufacturer="Tp-Link Technologies",
    ).router_fingerprint
    assert fp is not None
    assert fp.vendor == "TP-Link"
    assert fp.label == "TP-Link router"


def test_specific_model_claim_can_imply_vendor():
    def known_model_rule(ap):
        evidence = RouterEvidence("rule.known_model", "model", "CCR2004", 0.97)
        return (RouterClaim("model", "CCR2004", 0.97, (evidence,), vendor="MikroTik"),)

    fp = fingerprint_router(AccessPoint(bssid="02:00:00:00:00:01"), rules=(known_model_rule,))
    assert fp is not None
    assert fp.vendor == "MikroTik"
    assert fp.vendor_confidence == 0.97
    assert fp.model == "CCR2004"
    assert fp.model_confidence == 0.97
    assert fp.label == "MikroTik CCR2004 router"


def test_wps_model_number_is_model_fallback():
    ap = AccessPoint(bssid="02:00:00:00:00:01", wps_manufacturer="Acme", wps_model_number="R9000")
    claims = list(passive_wps_identity_rule(ap))
    model_claim = next(claim for claim in claims if claim.name == "model")
    assert model_claim.value == "R9000"
