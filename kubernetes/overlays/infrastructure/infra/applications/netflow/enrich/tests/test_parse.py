import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from dns_tail import parse  # noqa: E402
from intel_update import cloud_rows, threat_rows  # noqa: E402

LINES = [
    "[2026-09-30 10:07:09]  INFO queryLog: query resolved answer=A (REDACTED_IP) client_ip=REDACTED_IP "
    "client_names=REDACTED_IP duration_ms=1 instance=blocky01 question_name=netbox.0b.au. question_type=A "
    "response_code=NOERROR response_reason=CONDITIONAL response_type=CONDITIONAL",
    "[2026-09-30 10:07:09]  INFO queryLog: query resolved answer=CNAME (e28622.api11.akamaiedge.net.), "
    "A (REDACTED_IP), A (REDACTED_IP) client_ip=REDACTED_IP client_names=REDACTED_IP duration_ms=11 "
    "instance=blocky01 question_name=Webcast.TikTokV.com. question_type=A response_code=NOERROR",
    "[2026-09-30 10:07:09]  INFO queryLog: query resolved answer=AAAA (2606:4700::1) client_ip=REDACTED_IP "
    "client_names=x instance=blocky01 question_name=v6.example. question_type=AAAA",
]


def test_parse_a_records_only():
    assert parse(LINES[0]) == [("REDACTED_IP", "REDACTED_IP", "netbox.0b.au")]
    assert parse(LINES[1]) == [("REDACTED_IP", "REDACTED_IP", "webcast.tiktokv.com"),
                               ("REDACTED_IP", "REDACTED_IP", "webcast.tiktokv.com")]
    assert parse(LINES[2]) == []
    assert parse("unrelated line") == []


def test_threat_rows_merge_sources():
    rows = threat_rows({"tor-exit": [("REDACTED_IP/32", "")], "crowdsec": [("REDACTED_IP/32", "ssh-bf"), ("REDACTED_IP/24", "")]})
    by = {r["network"]: r for r in rows}
    assert by["REDACTED_IP/32"]["sources"] == "tor-exit,crowdsec" and by["REDACTED_IP/32"]["detail"] == "ssh-bf"


def test_cloud_first_provider_wins():
    rows = cloud_rows({"gcp": [("REDACTED_IP/24", "Google Cloud", "", "us")], "google": [("REDACTED_IP/24", "Google", "", "")]})
    assert rows == [{"network": "REDACTED_IP/24", "provider": "Google Cloud", "service": "", "region": "us"}]


def test_blocked_answers_skipped():
    line = ("[2026-09-30 10:07:09]  INFO queryLog: query resolved answer=A (REDACTED_IP) client_ip=REDACTED_IP "
            "client_names=x instance=blocky01 question_name=ads.example. question_type=A")
    assert parse(line) == []
