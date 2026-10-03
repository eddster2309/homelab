"""Export NetBox (as it is now, manual edits included) into ClickHouse lookup tables.

Reads through the NetBox API rather than the collector's in-memory state, so
anything a person changes in NetBox reaches flow enrichment on the next run.
The one exception is each prefix's `via` (the OPNsense interface it is routed
over), which comes from this run's OPNsense interfaces.
Each table is filled as <name>_new and swapped in with EXCHANGE TABLES, so the
dictionaries built on them never see a half-written table.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re

import requests

from model import FwInterface
from netbox_api import NetBox

log = logging.getLogger("export")
SITE_PREFIX = re.compile(r"^[A-Z0-9]+-[A-Z0-9]+\s+")
TUNNEL = re.compile(r"^(wg|tun|ovpn|ipsec|gif|gre)\d")


def _mac_by_iface(nb: NetBox) -> dict[tuple[str, int], str]:
    out = {}
    for otype, path in (("dcim.interface", "dcim/interfaces"), ("virtualization.vminterface", "virtualization/interfaces")):
        for i in nb.list(path):
            m = i.get("primary_mac_address")
            if m:
                out[(otype, i["id"])] = (m.get("mac_address") or "").lower()
    return out


def hosts_rows(nb: NetBox) -> list[dict]:
    devices = {d["id"]: d for d in nb.list("dcim/devices")}
    vms = {v["id"]: v for v in nb.list("virtualization/virtual-machines")}
    fhrp = {g["id"]: g for g in nb.list("ipam/fhrp-groups")}
    macs = _mac_by_iface(nb)
    rows = []
    for ip in nb.list("ipam/ip-addresses"):
        addr = ip["address"].split("/")[0]
        otype, obj = ip.get("assigned_object_type"), ip.get("assigned_object") or {}
        tags = [t["slug"] for t in ip.get("tags", [])]
        row = {"ip": addr, "name": "", "kind": "", "role": "", "vendor": "", "mac": "", "cluster": "", "connection": "",
               "fqdn": ip.get("dns_name") or "", "status": (ip.get("status") or {}).get("value", ""),
               "last_seen": (ip.get("custom_fields") or {}).get("last_seen") or None}
        parent = None
        if otype == "dcim.interface" and obj.get("device"):
            parent = devices.get(obj["device"]["id"])
            row["kind"] = ((parent or {}).get("custom_fields") or {}).get("host_kind") or \
                ((parent or {}).get("role") or {}).get("slug", "device")
        elif otype == "virtualization.vminterface" and obj.get("virtual_machine"):
            parent = vms.get(obj["virtual_machine"]["id"])
            row["kind"] = ((parent or {}).get("custom_fields") or {}).get("host_kind") or "vm"
            row["cluster"] = ((parent or {}).get("cluster") or {}).get("name", "")
        elif otype == "ipam.fhrpgroup":
            g = fhrp.get(obj.get("id"), obj)
            k8s = any(t["slug"] == "sync-k8s" for t in g.get("tags", []))
            row.update(name=g.get("description") or g.get("name", ""), kind="k8s-vip" if k8s else "vip",
                       role=(ip.get("role") or {}).get("value", "vip") if isinstance(ip.get("role"), dict) else "vip")
        if parent:
            row["name"] = parent["name"]
            row["role"] = (parent.get("role") or {}).get("slug", "") if parent.get("role") else ""
            row["vendor"] = (parent.get("custom_fields") or {}).get("vendor") or ""
            row["connection"] = (parent.get("custom_fields") or {}).get("connection") or ""
            tags += [t["slug"] for t in parent.get("tags", [])]
            row["mac"] = macs.get((otype, obj.get("id")), "")
        if not row["name"]:
            row["name"] = (row["fqdn"].split(".")[0] if row["fqdn"] else "") or ip.get("description", "")
            row["kind"] = row["kind"] or ("dns-only" if row["fqdn"] else "ip")
        row["tags"] = sorted(set(tags))
        if row["name"]:
            rows.append(row)
    return rows


def _segment(p: dict) -> str:
    desc = (p.get("description") or "").strip()
    if desc and SITE_PREFIX.match(desc):
        return SITE_PREFIX.sub("", desc)
    if p.get("vlan"):
        return SITE_PREFIX.sub("", p["vlan"]["name"].replace("-", " ", 1))
    if desc:
        return desc.split(",")[0].strip()[:40]
    return p["prefix"]


def routed_via(fw_interfaces: list[FwInterface]) -> list[tuple[ipaddress._BaseNetwork, str]]:
    """Networks the firewall reaches through a route (a WireGuard peer's AllowedIPs, a static
    route) or a tunnel, most specific first, with the interface. A LAN's own connected subnet
    is left out: its segment already says where it is."""
    out = []
    for fi in fw_interfaces:
        connected = set() if TUNNEL.match(fi.name) else {ipaddress.ip_interface(c).network for c in fi.cidrs}
        label = f"{fi.description} ({fi.name})" if fi.description and fi.description != fi.name else fi.name
        for r in fi.routes:
            net = ipaddress.ip_network(r, strict=False)
            if net not in connected:
                out.append((net, label))
    return sorted(out, key=lambda x: -x[0].prefixlen)


def prefix_rows(nb: NetBox, routes: list[tuple[ipaddress._BaseNetwork, str]] = ()) -> list[dict]:
    rows = []
    for p in nb.list("ipam/prefixes"):
        vlan = p.get("vlan") or {}
        net = ipaddress.ip_network(p["prefix"])
        via = next((label for r, label in routes if net.version == r.version and net.subnet_of(r)), "")
        rows.append({"prefix": p["prefix"], "segment": _segment(p), "vlan_vid": vlan.get("vid") or 0,
                     "vlan_name": vlan.get("name", ""), "role": (p.get("role") or {}).get("slug", ""),
                     "site": (p.get("scope") or {}).get("name", "") if p.get("scope_type") == "dcim.site" else "",
                     "via": via})
    return rows


def service_rows(nb: NetBox) -> list[dict]:
    ips = {i["id"]: i["address"].split("/")[0] for i in nb.list("ipam/ip-addresses")}
    rows = []
    for s in nb.list("ipam/services"):
        for ip_ref in s.get("ipaddresses", []):
            ip = ips.get(ip_ref["id"])
            for pm in s.get("port_mappings", []):
                proto, _, port = pm.partition("/")
                if ip and port.isdigit():
                    rows.append({"ip": ip, "proto": proto.upper(), "port": int(port),
                                 "name": s["name"], "description": s.get("description", "")})
    return rows


class ClickHouse:
    def __init__(self):
        self.url = os.environ.get("CLICKHOUSE_URL", "http://clickhouse-netflow.netflow.svc:8123")
        self.s = requests.Session()
        self.s.headers.update({"X-ClickHouse-User": os.environ.get("CLICKHOUSE_USER", "netbox_sync"),
                               "X-ClickHouse-Key": os.environ["CLICKHOUSE_PASSWORD"]})

    def q(self, sql: str, body: str | None = None) -> None:
        r = self.s.post(self.url, params={"query": sql}, data=(body or "").encode(), timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"ClickHouse: {sql[:80]}: {r.status_code} {r.text[:300]}")

    def replace(self, table: str, rows: list[dict]) -> None:
        self.q(f"TRUNCATE TABLE netflow.{table}_new")
        if rows:
            self.q(f"INSERT INTO netflow.{table}_new FORMAT JSONEachRow",
                   "\n".join(json.dumps(r, default=str) for r in rows))
        self.q(f"EXCHANGE TABLES netflow.{table} AND netflow.{table}_new")


def export(nb: NetBox, dry_run: bool, fw_interfaces: list[FwInterface] = ()) -> dict[str, int]:
    """fw_interfaces: OPNsense's interfaces this run, for the prefixes' `via`. Routes are live
    firewall state with no NetBox model, so they come from the collector rather than NetBox."""
    routes = routed_via(fw_interfaces)
    if not routes:
        log.warning("no routed networks from OPNsense this run: prefixes exported without via")
    tables = {"nb_hosts": hosts_rows(nb), "nb_prefixes": prefix_rows(nb, routes), "nb_services": service_rows(nb)}
    for r in tables["nb_prefixes"]:
        ipaddress.ip_network(r["prefix"])        # fail loudly on anything the IP_TRIE would reject
    counts = {t: len(rows) for t, rows in tables.items()}
    if dry_run:
        log.info("dry-run: would export %s", counts)
        return counts
    ch = ClickHouse()
    for table, rows in tables.items():
        ch.replace(table, rows)
    log.info("exported %s", counts)
    return counts
