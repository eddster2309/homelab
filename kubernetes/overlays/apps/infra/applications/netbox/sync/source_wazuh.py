"""Wazuh: each agent's syscollector inventory, read from the indexer as the read-only
user Grafana uses. Gives the ports a host listens on (with the process behind each),
its OS, and the board serial.

Listening ports beat the NetFlow guess (source_flows): they include services only
used inside one VLAN, which never cross the firewall's NetFlow export.
"""
from __future__ import annotations

import ipaddress
import logging
import os

import requests
from pydantic import BaseModel, ValidationError

from model import Collected, WazuhAgent, verify_ssl

log = logging.getLogger("wazuh")
URL = os.environ.get("WAZUH_URL", "https://wazuh.internal:9200").rstrip("/")


class _Agent(BaseModel):
    id: str


class _Host(BaseModel):
    ip: str = ""
    serial_number: str = ""
    os: dict[str, str] = {}


class SystemDocRaw(BaseModel):
    agent: _Agent
    host: _Host = _Host()


class HardwareDocRaw(BaseModel):
    agent: _Agent
    host: _Host = _Host()


class _Network(BaseModel):
    transport: str = ""


class _Source(BaseModel):
    ip: str = ""
    port: int = 0


class _Destination(BaseModel):
    port: int = 0


class _Interface(BaseModel):
    state: str | None = None


class _Process(BaseModel):
    name: str = ""


class PortDocRaw(BaseModel):
    agent: _Agent
    network: _Network = _Network()
    source: _Source = _Source()
    destination: _Destination = _Destination()
    interface: _Interface = _Interface()
    process: _Process = _Process()


def _bound_publicly(ip: str) -> bool:
    """Listening on a wildcard or a real address, not loopback."""
    try:
        return not ipaddress.ip_address(ip or "REDACTED_IP").is_loopback
    except ValueError:
        return False


def agents(system: list[dict], hardware: list[dict], ports: list[dict]) -> list[WazuhAgent]:
    """Indexer documents (_source) -> one WazuhAgent per agent."""
    out: dict[str, WazuhAgent] = {}
    for raw in system:
        try:
            d = SystemDocRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed system doc %r: %s", raw, e)
            continue
        osd = d.host.os
        out[d.agent.id] = WazuhAgent(name=raw["agent"]["name"], ip=d.host.ip,
                                     os=" ".join(x for x in (osd.get("name"), osd.get("version")) if x))
    for raw in hardware:
        try:
            d = HardwareDocRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed hardware doc %r: %s", raw, e)
            continue
        ag = out.get(d.agent.id)
        if ag is not None:
            ag.serial = d.host.serial_number.strip()
    for raw in ports:
        try:
            d = PortDocRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed port doc %r: %s", raw, e)
            continue
        ag = out.get(d.agent.id)
        proto = d.network.transport.rstrip("6")
        state = d.interface.state
        port = d.source.port
        if ag is None or proto not in ("tcp", "udp") or not port or not _bound_publicly(d.source.ip):
            continue
        if (proto == "tcp" and state != "listening") or (proto == "udp" and (port >= 32768 or d.destination.port)):
            continue        # tcp: only listeners; udp: unconnected sockets below the ephemeral range
        name = (d.process.name or f"{proto}/{port}").strip()
        ag.listening.setdefault(name, set()).add(f"{proto}/{port}")
    return sorted(out.values(), key=lambda a: a.name)


def collect(c: Collected) -> None:
    s = requests.Session()
    s.auth = (os.environ.get("WAZUH_USER", "grafana"), os.environ["WAZUH_PASSWORD"])
    s.verify = verify_ssl("WAZUH")

    def docs(index: str) -> list[dict]:
        r = s.post(f"{URL}/{index}/_search", json={"size": 10000}, timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"Wazuh indexer {index}: {r.status_code} {r.text[:200]}")
        return [h["_source"] for h in r.json()["hits"]["hits"]]

    c.wazuh = agents(docs("wazuh-states-inventory-system-*"), docs("wazuh-states-inventory-hardware-*"),
                     docs("wazuh-states-inventory-ports-*"))
