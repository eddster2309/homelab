"""Wazuh: each agent's syscollector inventory, read from the indexer as the read-only
user Grafana uses. Gives the ports a host listens on (with the process behind each),
its OS, and the board serial.

Listening ports beat the NetFlow guess (source_flows): they include services only
used inside one VLAN, which never cross the firewall's NetFlow export.
"""
from __future__ import annotations

import ipaddress
import os

import requests

from model import Collected, WazuhAgent

URL = os.environ.get("WAZUH_URL", "https://wazuh.internal:9200").rstrip("/")


def _bound_publicly(ip: str) -> bool:
    """Listening on a wildcard or a real address, not loopback."""
    try:
        return not ipaddress.ip_address(ip or "REDACTED_IP").is_loopback
    except ValueError:
        return False


def agents(system: list[dict], hardware: list[dict], ports: list[dict]) -> list[WazuhAgent]:
    """Indexer documents (_source) -> one WazuhAgent per agent."""
    out: dict[str, WazuhAgent] = {}
    for d in system:
        a, osd = d["agent"], ((d.get("host") or {}).get("os") or {})
        out[a["id"]] = WazuhAgent(name=a["name"], ip=(a.get("host") or {}).get("ip", ""),
                                  os=" ".join(x for x in (osd.get("name"), osd.get("version")) if x))
    for d in hardware:
        ag = out.get(d["agent"]["id"])
        if ag is not None:
            ag.serial = ((d.get("host") or {}).get("serial_number") or "").strip()
    for d in ports:
        ag = out.get(d["agent"]["id"])
        proto = (d.get("network") or {}).get("transport", "").rstrip("6")
        src = d.get("source") or {}
        state = (d.get("interface") or {}).get("state")
        port = int(src.get("port") or 0)
        if ag is None or proto not in ("tcp", "udp") or not port or not _bound_publicly(src.get("ip", "")):
            continue
        if (proto == "tcp" and state != "listening") or (proto == "udp" and (port >= 32768 or (d.get("destination") or {}).get("port"))):
            continue        # tcp: only listeners; udp: unconnected sockets below the ephemeral range
        name = ((d.get("process") or {}).get("name") or f"{proto}/{port}").strip()
        ag.listening.setdefault(name, set()).add(f"{proto}/{port}")
    return sorted(out.values(), key=lambda a: a.name)


def collect(c: Collected) -> None:
    s = requests.Session()
    s.auth = (os.environ.get("WAZUH_USER", "grafana"), os.environ["WAZUH_PASSWORD"])
    s.verify = os.environ.get("WAZUH_VERIFY_SSL", "false").lower() == "true"

    def docs(index: str) -> list[dict]:
        r = s.post(f"{URL}/{index}/_search", json={"size": 10000}, timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"Wazuh indexer {index}: {r.status_code} {r.text[:200]}")
        return [h["_source"] for h in r.json()["hits"]["hits"]]

    c.wazuh = agents(docs("wazuh-states-inventory-system-*"), docs("wazuh-states-inventory-hardware-*"),
                     docs("wazuh-states-inventory-ports-*"))
