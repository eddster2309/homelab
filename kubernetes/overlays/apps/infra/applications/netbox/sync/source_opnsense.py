"""OPNsense: ARP (live presence), dnsmasq leases + static hosts, Unbound overrides,
the firewall's own interfaces, and VLANs."""
from __future__ import annotations

import logging
import os
import re

import requests

from model import (
    ArpEntry, Collected, DhcpRange, FwInterface, Lease, PortForward, StaticName, VlanObs, WgPeer, is_usable_ip, norm_mac,
)

log = logging.getLogger("opnsense")


class OPNsense:
    def __init__(self, url: str, key: str, secret: str):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (key, secret)
        self.s.verify = os.environ.get("OPNSENSE_VERIFY_SSL", "false").lower() == "true"

    def call(self, *paths: str, search: bool = False, required: bool = True):
        """Try each path (OPNsense has renamed camelCase actions to snake_case over time)."""
        last = None
        for path in paths:
            url = f"{self.url}/api/{path}"
            r = self.s.post(url, json={"current": 1, "rowCount": -1}, timeout=30) if search else \
                self.s.get(url, timeout=30)
            if search and r.status_code in (404, 405):
                r = self.s.get(url, timeout=30)
            if r.status_code == 200:
                data = r.json()
                return data.get("rows", data) if search and isinstance(data, dict) else data
            last = f"{path}: {r.status_code}"
        if required:
            raise RuntimeError(f"OPNsense API failed ({last})")
        log.info("optional endpoint unavailable (%s)", last)
        return [] if search else {}


def _split(v) -> list[str]:
    if isinstance(v, list):
        return v
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


def _interfaces(api: OPNsense) -> list[FwInterface]:
    rows = api.call("interfaces/overview/interfaces_info", "interfaces/overview/interfacesInfo",
                    search=True, required=False)
    out = []
    for r in rows or []:
        cidrs = [a for a in _split(r.get("addr4")) + _split(r.get("addr6")) if "/" in a and is_usable_ip(a)]
        vid = r.get("vlan_tag")
        out.append(FwInterface(
            name=r.get("device") or r.get("identifier", ""),
            description=r.get("description") or r.get("identifier", ""),
            mac=norm_mac(r.get("macaddr")), cidrs=cidrs,
            vid=int(vid) if str(vid or "").isdigit() else None,
            routes=[x for x in _split(r.get("routes")) if "/" in x and is_usable_ip(x)]))
    if out:
        return out
    # Older API: device -> {macaddr, ipv4:[{ipaddr, subnetbits}]} plus a names map
    cfg = api.call("diagnostics/interface/get_interface_config", "diagnostics/interface/getInterfaceConfig")
    names = api.call("diagnostics/interface/get_interface_names", "diagnostics/interface/getInterfaceNames",
                     required=False) or {}
    for dev, v in (cfg or {}).items():
        if not isinstance(v, dict):
            continue
        cidrs = [f"{a['ipaddr']}/{a['subnetbits']}" for a in v.get("ipv4", []) if a.get("ipaddr")]
        m = re.match(r"^vlan0?\.?(\d+)$", dev) or re.match(r"^\w+?_vlan(\d+)$", dev)
        out.append(FwInterface(name=dev, description=names.get(dev, dev), mac=norm_mac(v.get("macaddr")),
                               cidrs=[c for c in cidrs if is_usable_ip(c)], vid=int(m.group(1)) if m else None))
    return out


def collect(c: Collected) -> None:
    api = OPNsense(os.environ["OPNSENSE_URL"], os.environ["OPNSENSE_KEY"], os.environ["OPNSENSE_SECRET"])

    c.fw_interfaces = _interfaces(api)

    arp = api.call("diagnostics/interface/search_arp", "diagnostics/interface/searchArp",
                   search=True, required=False) or \
        api.call("diagnostics/interface/get_arp", "diagnostics/interface/getArp")
    for a in arp:
        if a.get("expired") or not a.get("mac") or a.get("mac") == "(incomplete)":
            continue
        c.arp.append(ArpEntry(ip=a["ip"], mac=a["mac"], interface=a.get("intf", "")))

    # dnsmasq's lease file only holds current leases (expire=0 means infinite), so every row is active.
    for le in api.call("dnsmasq/leases/search", search=True, required=False):
        ip = le.get("address") or le.get("ip")
        if not ip:
            continue
        c.leases.append(Lease(ip=ip, mac=norm_mac(le.get("hwaddr") or le.get("mac")),
                              hostname=(le.get("hostname") or "").strip(), active=True))

    for r in api.call("dnsmasq/settings/search_range", "dnsmasq/settings/searchRange", search=True, required=False):
        if r.get("start_addr") and r.get("end_addr") and is_usable_ip(r["start_addr"]) and is_usable_ip(r["end_addr"]):
            c.dhcp_ranges.append(DhcpRange(start=r["start_addr"], end=r["end_addr"],
                                           interface=(r.get("%interface") or r.get("interface") or "").strip()))

    for h in api.call("dnsmasq/settings/search_host", "dnsmasq/settings/searchHost", search=True, required=False):
        name = (h.get("host") or "").strip()
        domain = (h.get("domain") or "").strip()
        macs = _split(h.get("hwaddr"))
        for ip in _split(h.get("ip")):
            if name:
                c.static_names.append(StaticName(ip=ip, name=name, fqdn=f"{name}.{domain}" if domain else "",
                                                 mac=norm_mac(macs[0]) if macs else None))

    for o in api.call("unbound/settings/search_host_override", "unbound/settings/searchHostOverride",
                      search=True, required=False):
        if str(o.get("enabled", "1")) != "1" or o.get("rr", "A") not in ("A", "AAAA", "A (IPv4 address)"):
            continue
        name, domain, ip = o.get("hostname", ""), o.get("domain", ""), o.get("server", "")
        if name and name != "*" and ip:
            c.static_names.append(StaticName(ip=ip, name=name, fqdn=f"{name}.{domain}".strip(".")))

    collect_extras(api, c)

    rows = api.call("interfaces/vlan_settings/search_item", "interfaces/vlan_settings/searchItem",
                    search=True, required=False)
    tag_counts: dict[str, int] = {}
    for v in rows:
        tag = str(v.get("tag") or v.get("vlan") or "")
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    for v in rows:
        tag = str(v.get("tag") or v.get("vlan") or "")
        if tag.isdigit():
            c.vlans.append(VlanObs(vid=int(tag), name=(v.get("descr") or f"VLAN{tag}").strip()))
            for fi in c.fw_interfaces:
                # By device name; else by tag (the overview's device name can differ from
                # vlanif, e.g. zero-padded), when only one VLAN uses that tag
                if fi.name == v.get("vlanif") or (fi.name != v.get("if") and fi.vid == int(tag)
                                                  and tag_counts[tag] == 1):
                    fi.vid = fi.vid if fi.vid is not None else int(tag)
                    fi.parent = (v.get("if") or "").strip()


MAX_FORWARD_PORTS = 256      # a port range bigger than this is left as its first port


def _ports(spec: str) -> list[int]:
    """'3478' -> [3478], '27017-27050' -> every port in the range."""
    lo, _, hi = str(spec or "").partition("-")
    if not lo.isdigit():
        return []
    hi = hi if hi.isdigit() else lo
    span = range(int(lo), int(hi) + 1)
    return list(span) if len(span) <= MAX_FORWARD_PORTS else [int(lo)]


def port_forwards(rows: list[dict]) -> list[PortForward]:
    """Destination NAT rules on the WAN -> one PortForward per (description, target)."""
    out: dict[tuple[str, str, str], PortForward] = {}
    for r in rows:
        if r.get("is_automatic") or str(r.get("disabled", "0")) == "1" or r.get("interface") != "wan":
            continue
        target = (r.get("target") or "").strip()
        if not is_usable_ip(target):
            continue                          # an alias target: no single host to point at
        protos = [p for p in ("tcp", "udp") if p in (r.get("protocol") or "").lower()]
        pf = out.setdefault((r.get("descr") or "", target, r.get("local-port") or ""),
                            PortForward(descr=(r.get("descr") or f"forward to {target}").strip(), port_mappings=[],
                                        target=target, local_port=str(r.get("local-port") or "")))
        pf.port_mappings += [f"{p}/{n}" for p in protos for n in _ports(r.get("destination.port"))]
    for pf in out.values():
        pf.port_mappings = sorted(set(pf.port_mappings), key=lambda x: (x.split("/")[0], int(x.split("/")[1])))
    return list(out.values())


def wg_peers(clients: list[dict], show: list[dict], servers: set[str]) -> list[WgPeer]:
    """Remote-access peers of the given WireGuard instances (not the Terraform-managed inter-site
    mesh). Only names, addresses and handshake times: the API also returns keys."""
    seen = {r.get("name"): int(r.get("latest-handshake") or 0) for r in show if r.get("type") == "peer"}
    endpoints = {r.get("name"): (r.get("endpoint") or "").rsplit(":", 1)[0].strip("[]") for r in show if r.get("type") == "peer"}
    out = []
    for r in clients:
        if r.get("%servers") not in servers:
            continue
        for addr in (r.get("tunneladdress") or "").split(","):
            ip = addr.strip().split("/")[0]
            if addr.strip().endswith("/32") and is_usable_ip(ip):
                out.append(WgPeer(server=r["%servers"], name=(r.get("name") or "").strip(), address=ip,
                                  enabled=str(r.get("enabled", "1")) == "1", handshake=seen.get(r.get("name"), 0),
                                  endpoint=endpoints.get(r.get("name"), "") if is_usable_ip(endpoints.get(r.get("name"), "")) else ""))
    return out


def collect_extras(api: OPNsense, c: Collected) -> None:
    """Port forwards, remote-access WireGuard peers and gateways. Each needs its own API
    privilege; one that's refused is skipped (left None) without failing the source."""
    try:
        c.port_forwards = port_forwards(api.call("firewall/d_nat/search_rule", search=True))
    except RuntimeError as e:
        log.info("port forwards unavailable: %s", e)
    try:
        servers = {s.strip() for s in os.environ.get("WG_REMOTE_ACCESS", "WG").split(",") if s.strip()}
        c.wg_peers = wg_peers(api.call("wireguard/client/search_client", search=True),
                              (api.call("wireguard/service/show") or {}).get("rows", []), servers)
    except RuntimeError as e:
        log.info("wireguard unavailable: %s", e)
    try:
        for g in api.call("routing/settings/search_gateway", search=True):
            if g.get("gateway") and is_usable_ip(g["gateway"]) and not g.get("disabled"):
                c.gateways[g["gateway"]] = g.get("name") or ""
    except RuntimeError as e:
        log.info("gateways unavailable: %s", e)
