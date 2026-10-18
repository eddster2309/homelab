"""intel-update: threat lists, cloud provider ranges and IANA port names -> ClickHouse.

Each list is fetched independently; a failed download keeps the previous
contents of its table rather than emptying it.

Per-source results are pushed to VictoriaMetrics (METRICS_PUSH_URL, the vmagent
Prometheus import endpoint) at the end of each run.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import logging
import os
import sys
import uuid

import requests

from chclient import ClickHouse

log = logging.getLogger("intel")
UA = {"User-Agent": "homelab-netflow-intel/1.0"}
METRICS_URL = os.environ.get("METRICS_PUSH_URL", "")


def _get(url: str, **kw) -> requests.Response:
    r = requests.get(url, headers={**UA, **kw.pop("headers", {})}, timeout=120, **kw)
    r.raise_for_status()
    return r


def _v4(cidr: str) -> str | None:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    return str(net) if net.version == 4 else None


# ---------------------------------------------------------------- threat

def spamhaus_drop() -> list[tuple[str, str]]:
    out = []
    for line in _get("https://www.spamhaus.org/drop/drop_v4.json").text.splitlines():
        if '"cidr"' in line:
            import json
            d = json.loads(line)
            if (n := _v4(d["cidr"])):
                out.append((n, d.get("sblid", "")))
    return out


def plain_ips(url: str) -> list[tuple[str, str]]:
    return [(n, "") for line in _get(url).text.splitlines()
            if line.strip() and not line.startswith("#") and (n := _v4(line.split()[0]))]


def crowdsec() -> list[tuple[str, str]]:
    """All active decisions via a dedicated bouncer (its own stream position)."""
    key = os.environ.get("CROWDSEC_BOUNCER_KEY")
    if not key:
        return []
    url = os.environ.get("CROWDSEC_LAPI", "http://crowdsec-service.crowdsec.svc:8080")
    d = _get(f"{url}/v1/decisions/stream", params={"startup": "true"}, headers={"X-Api-Key": key}).json()
    return [(n, dec.get("scenario", "")) for dec in (d.get("new") or [])
            if dec.get("type") == "ban" and (n := _v4(dec.get("value", "")))]


THREAT_SOURCES = {
    "spamhaus-drop": spamhaus_drop,
    "feodo": lambda: plain_ips("https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    "tor-exit": lambda: plain_ips("https://check.torproject.org/torbulkexitlist"),
    "crowdsec": crowdsec,
}


def threat_rows(results: dict[str, list[tuple[str, str]]]) -> list[dict]:
    merged: dict[str, dict] = {}
    for source, entries in results.items():
        for net, detail in entries:
            row = merged.setdefault(net, {"network": net, "sources": [], "detail": []})
            if source not in row["sources"]:
                row["sources"].append(source)
            if detail and detail not in row["detail"]:
                row["detail"].append(detail)
    return [{"network": r["network"], "sources": ",".join(r["sources"]), "detail": "; ".join(r["detail"])[:200]}
            for r in merged.values()]


# ---------------------------------------------------------------- cloud

def aws() -> list[tuple[str, str, str, str]]:
    # Every AWS prefix is listed under "AMAZON" too; keep the most specific service per prefix.
    best: dict[str, tuple[str, str, str, str]] = {}
    for p in _get("https://ip-ranges.amazonaws.com/ip-ranges.json").json()["prefixes"]:
        n = _v4(p["ip_prefix"])
        if n and (n not in best or best[n][2] == "AMAZON"):
            best[n] = (n, "AWS", p["service"], p["region"] if p["region"] != "GLOBAL" else "")
    return list(best.values())


def gcp() -> list[tuple[str, str, str, str]]:
    return [(n, "Google Cloud", "", p.get("scope", "")) for p in _get("https://www.gstatic.com/ipranges/cloud.json").json()["prefixes"]
            if (n := _v4(p.get("ipv4Prefix", "")))]


def google() -> list[tuple[str, str, str, str]]:
    return [(n, "Google", "", "") for p in _get("https://www.gstatic.com/ipranges/goog.json").json()["prefixes"]
            if (n := _v4(p.get("ipv4Prefix", "")))]


def cloudflare() -> list[tuple[str, str, str, str]]:
    return [(n, "Cloudflare", "", "") for line in _get("https://www.cloudflare.com/ips-v4").text.split()
            if (n := _v4(line))]


def github() -> list[tuple[str, str, str, str]]:
    out: dict[str, tuple[str, str, str, str]] = {}
    for svc, nets in _get("https://api.github.com/meta").json().items():
        if isinstance(nets, list) and svc not in ("domains", "ssh_keys", "verifiable_password_authentication"):
            for net in nets:
                if isinstance(net, str) and (n := _v4(net)):
                    out.setdefault(n, (n, "GitHub", svc, ""))
    return list(out.values())


def microsoft365() -> list[tuple[str, str, str, str]]:
    out: dict[str, tuple[str, str, str, str]] = {}
    url = f"https://endpoints.office.com/endpoints/worldwide?clientrequestid={uuid.uuid4()}"
    for e in _get(url).json():
        for ip in e.get("ips", []):
            if (n := _v4(ip)):
                out.setdefault(n, (n, "Microsoft 365", e.get("serviceArea", ""), ""))
    return list(out.values())


# Order matters: earlier providers win where ranges are identical (e.g. Google Cloud inside goog.json).
CLOUD_SOURCES = {"aws": aws, "gcp": gcp, "google": google, "cloudflare": cloudflare, "github": github,
                 "microsoft365": microsoft365}


def cloud_rows(results: dict[str, list[tuple[str, str, str, str]]]) -> list[dict]:
    seen: dict[str, dict] = {}
    for name in CLOUD_SOURCES:
        for net, provider, service, region in results.get(name, []):
            seen.setdefault(net, {"network": net, "provider": provider, "service": service, "region": region})
    return list(seen.values())


# ---------------------------------------------------------------- ports

def port_rows() -> list[dict]:
    url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
    rows: dict[tuple[str, int], dict] = {}
    for r in csv.DictReader(io.StringIO(_get(url).text)):
        name, port, proto = r.get("Service Name", "").strip(), r.get("Port Number", "").strip(), \
            r.get("Transport Protocol", "").strip().upper()
        if not name or proto not in ("TCP", "UDP") or not port.isdigit():
            continue                                  # skips ranges ("6000-6063") and unassigned
        key = (proto, int(port))
        rows.setdefault(key, {"proto": proto, "port": int(port), "name": name,
                              "description": (r.get("Description") or "").strip()[:120]})
    # Common ports whose IANA name is unhelpful or missing
    for proto, port, name in (("UDP", 51820, "wireguard"), ("TCP", 8006, "proxmox"), ("TCP", 9100, "node-exporter"),
                              ("UDP", 443, "quic"), ("TCP", 6443, "kubernetes-api"), ("TCP", 8971, "frigate")):
        rows[(proto, port)] = {"proto": proto, "port": port, "name": name, "description": ""}
    return list(rows.values())


# ---------------------------------------------------------------- main

def _collect(sources: dict) -> tuple[dict, bool]:
    results, ok = {}, True
    for name, fn in sources.items():
        try:
            results[name] = fn()
            log.info("%-14s %6d entries", name, len(results[name]))
        except Exception as e:
            ok = False
            log.error("%-14s FAILED: %s", name, e)
    return results, ok


def push_metrics(results: dict[str, dict], healthy: bool) -> None:
    """netflow_intel_* gauges for the run; a source missing from results failed."""
    if not METRICS_URL:
        return
    lines = [f"netflow_intel_run_ok {int(healthy)}"]
    for kind, sources in (("threat", THREAT_SOURCES), ("cloud", CLOUD_SOURCES), ("ports", {"iana": None})):
        for name in sources:
            got = results[kind].get(name)
            lines.append(f'netflow_intel_source_ok{{list="{kind}",source="{name}"}} {int(got is not None)}')
            if got is not None:
                lines.append(f'netflow_intel_source_entries{{list="{kind}",source="{name}"}} {len(got)}')
    try:
        requests.post(METRICS_URL, data="\n".join(lines) + "\n", timeout=30).raise_for_status()
    except Exception as e:
        log.error("metrics push FAILED: %s", e)


def main() -> int:
    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)-7s %(message)s")
    ch = ClickHouse()
    healthy = True

    threat, ok = _collect(THREAT_SOURCES)
    healthy &= ok
    if ok:                      # a partial list would silently un-flag networks: keep the old table
        ch.replace("netflow.intel_threat", threat_rows(threat))

    cloud, ok = _collect(CLOUD_SOURCES)
    healthy &= ok
    if ok:
        ch.replace("netflow.intel_cloud", cloud_rows(cloud))

    ports = {}
    try:
        ports["iana"] = port_rows()
        ch.replace("netflow.port_names", ports["iana"])
    except Exception as e:
        ports.pop("iana", None)
        healthy = False
        log.error("port names FAILED: %s", e)

    push_metrics({"threat": threat, "cloud": cloud, "ports": ports}, healthy)
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())
