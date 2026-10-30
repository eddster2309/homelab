import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from intel_update import cloud_rows, threat_rows  # noqa: E402


def test_threat_rows_merge_sources():
    rows = threat_rows({"tor-exit": [("REDACTED_IP/32", "")], "crowdsec": [("REDACTED_IP/32", "ssh-bf"), ("REDACTED_IP/24", "")]})
    by = {r["network"]: r for r in rows}
    assert by["REDACTED_IP/32"]["sources"] == "tor-exit,crowdsec" and by["REDACTED_IP/32"]["detail"] == "ssh-bf"


def test_cloud_first_provider_wins():
    rows = cloud_rows({"gcp": [("REDACTED_IP/24", "Google Cloud", "", "us")], "google": [("REDACTED_IP/24", "Google", "", "")]})
    assert rows == [{"network": "REDACTED_IP/24", "provider": "Google Cloud", "service": "", "region": "us"}]
