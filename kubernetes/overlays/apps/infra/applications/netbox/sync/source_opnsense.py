"""OPNsense: ARP (live presence), dnsmasq leases + static hosts, Unbound overrides,
the firewall's own interfaces, and VLANs."""
from __future__ import annotations

import logging
import os
import re

import requests
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from model import (
    ArpEntry, Collected, DhcpRange, FwInterface, Lease, PortForward, StaticName, VlanObs, WgPeer, is_usable_ip, norm_mac,
    verify_ssl,
)

log = logging.getLogger("opnsense")


class IfaceRowRaw(BaseModel):
    """A row from interfaces/overview/interfacesInfo (the modern OPNsense API)."""
    device: str = ""
    identifier: str = ""
    description: str = ""
    macaddr: str | None = None
    addr4: str | list[str] = ""
    addr6: str | list[str] = ""
    vlan_tag: str | int | None = None
    routes: str | list[str] = ""


class _V4Addr(BaseModel):
    ipaddr: str = ""
    subnetbits: str | int = ""


class IfaceConfigRaw(BaseModel):
    """A per-device entry from diagnostics/interface/getInterfaceConfig (the legacy API)."""
    macaddr: str | None = None
    ipv4: list[_V4Addr] = []


class PortForwardRowRaw(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    is_automatic: bool = False
    disabled: str = "0"
    interface: str = ""
    target: str = ""
    protocol: str = ""
    destination_port: str = Field("", alias="destination.port")
    descr: str = ""
    local_port: str = Field("", alias="local-port")


class WgClientRowRaw(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    servers: str = Field("", alias="%servers")
    tunneladdress: str = ""
    name: str = ""
    enabled: str = "1"


class WgShowRowRaw(BaseModel):
    type: str = ""
    name: str = ""
    latest_handshake: str | int = Field(0, alias="latest-handshake")
    endpoint: str = ""


class ArpRowRaw(BaseModel):
    ip: str
    mac: str
    intf: str = ""
    expired: bool | str = False


class LeaseRowRaw(BaseModel):
    address: str | None = None
    ip: str | None = None
    hwaddr: str | None = None
    mac: str | None = None
    hostname: str = ""


class DhcpRangeRowRaw(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    start_addr: str = ""
    end_addr: str = ""
    interface: str = ""
    pct_interface: str = Field("", alias="%interface")


class StaticHostRowRaw(BaseModel):
    host: str = ""
    domain: str = ""
    hwaddr: str | list[str] = ""
    ip: str | list[str] = ""


class UnboundOverrideRowRaw(BaseModel):
    enabled: str = "1"
    rr: str = "A"
    hostname: str = ""
    domain: str = ""
    server: str = ""


class VlanRowRaw(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    tag: str | int | None = None
    vlan: str | int | None = None
    descr: str = ""
    vlanif: str = ""
    if_: str = Field("", alias="if")


class OPNsense:
    def __init__(self, url: str, key: str, secret: str):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (key, secret)
        self.s.verify = verify_ssl("OPNSENSE")

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
    for raw in rows or []:
        try:
            r = IfaceRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed interface row %r: %s", raw, e)
            continue
        cidrs = [a for a in _split(r.addr4) + _split(r.addr6) if "/" in a and is_usable_ip(a)]
        vid = r.vlan_tag
        out.append(FwInterface(
            name=r.device or r.identifier,
            description=r.description or r.identifier,
            mac=norm_mac(r.macaddr), cidrs=cidrs,
            vid=int(vid) if str(vid or "").isdigit() else None,
            routes=[x for x in _split(r.routes) if "/" in x and is_usable_ip(x)]))
    if out:
        return out
    # Older API: device -> {macaddr, ipv4:[{ipaddr, subnetbits}]} plus a names map
    cfg = api.call("diagnostics/interface/get_interface_config", "diagnostics/interface/getInterfaceConfig")
    names = api.call("diagnostics/interface/get_interface_names", "diagnostics/interface/getInterfaceNames",
                     required=False) or {}
    for dev, raw_v in (cfg or {}).items():
        if not isinstance(raw_v, dict):
            continue
        try:
            v = IfaceConfigRaw.model_validate(raw_v)
        except ValidationError as e:
            log.warning("skipping malformed interface config %r: %s", raw_v, e)
            continue
        cidrs = [f"{a.ipaddr}/{a.subnetbits}" for a in v.ipv4 if a.ipaddr]
        m = re.match(r"^vlan0?\.?(\d+)$", dev) or re.match(r"^\w+?_vlan(\d+)$", dev)
        out.append(FwInterface(name=dev, description=names.get(dev, dev), mac=norm_mac(v.macaddr),
                               cidrs=[c for c in cidrs if is_usable_ip(c)], vid=int(m.group(1)) if m else None))
    return out


def collect(c: Collected) -> None:
    api = OPNsense(os.environ["OPNSENSE_URL"], os.environ["OPNSENSE_KEY"], os.environ["OPNSENSE_SECRET"])

    c.fw_interfaces = _interfaces(api)

    arp_rows = api.call("diagnostics/interface/search_arp", "diagnostics/interface/searchArp",
                        search=True, required=False) or \
        api.call("diagnostics/interface/get_arp", "diagnostics/interface/getArp")
    for raw in arp_rows:
        try:
            a = ArpRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed arp row %r: %s", raw, e)
            continue
        if str(a.expired).lower() in ("1", "true") or not a.mac or a.mac == "(incomplete)":
            continue
        c.arp.append(ArpEntry(ip=a.ip, mac=a.mac, interface=a.intf))

    # dnsmasq's lease file only holds current leases (expire=0 means infinite), so every row is active.
    for raw in api.call("dnsmasq/leases/search", search=True, required=False):
        try:
            le = LeaseRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed lease row %r: %s", raw, e)
            continue
        ip = le.address or le.ip
        if not ip:
            continue
        c.leases.append(Lease(ip=ip, mac=norm_mac(le.hwaddr or le.mac),
                              hostname=le.hostname.strip(), active=True))

    for raw in api.call("dnsmasq/settings/search_range", "dnsmasq/settings/searchRange", search=True, required=False):
        try:
            r = DhcpRangeRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed dhcp range row %r: %s", raw, e)
            continue
        if r.start_addr and r.end_addr and is_usable_ip(r.start_addr) and is_usable_ip(r.end_addr):
            c.dhcp_ranges.append(DhcpRange(start=r.start_addr, end=r.end_addr,
                                           interface=(r.pct_interface or r.interface).strip()))

    for raw in api.call("dnsmasq/settings/search_host", "dnsmasq/settings/searchHost", search=True, required=False):
        try:
            h = StaticHostRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed static host row %r: %s", raw, e)
            continue
        name = h.host.strip()
        domain = h.domain.strip()
        macs = _split(h.hwaddr)
        for ip in _split(h.ip):
            if name:
                c.static_names.append(StaticName(ip=ip, name=name, fqdn=f"{name}.{domain}" if domain else "",
                                                 mac=norm_mac(macs[0]) if macs else None))

    for raw in api.call("unbound/settings/search_host_override", "unbound/settings/searchHostOverride",
                        search=True, required=False):
        try:
            o = UnboundOverrideRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed unbound override row %r: %s", raw, e)
            continue
        if o.enabled != "1" or o.rr not in ("A", "AAAA", "A (IPv4 address)"):
            continue
        name, domain, ip = o.hostname, o.domain, o.server
        if name and name != "*" and ip:
            c.static_names.append(StaticName(ip=ip, name=name, fqdn=f"{name}.{domain}".strip(".")))

    collect_extras(api, c)

    rows = api.call("interfaces/vlan_settings/search_item", "interfaces/vlan_settings/searchItem",
                    search=True, required=False)
    vlan_rows = []
    for raw in rows:
        try:
            vlan_rows.append(VlanRowRaw.model_validate(raw))
        except ValidationError as e:
            log.warning("skipping malformed vlan row %r: %s", raw, e)
    tag_counts: dict[str, int] = {}
    for v in vlan_rows:
        tag = str(v.tag or v.vlan or "")
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    for v in vlan_rows:
        tag = str(v.tag or v.vlan or "")
        if tag.isdigit():
            c.vlans.append(VlanObs(vid=int(tag), name=(v.descr or f"VLAN{tag}").strip()))
            for fi in c.fw_interfaces:
                # By device name; else by tag (the overview's device name can differ from
                # vlanif, e.g. zero-padded), when only one VLAN uses that tag
                if fi.name == v.vlanif or (fi.name != v.if_ and fi.vid == int(tag)
                                          and tag_counts[tag] == 1):
                    fi.vid = fi.vid if fi.vid is not None else int(tag)
                    fi.parent = v.if_.strip()


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
    for raw in rows:
        try:
            r = PortForwardRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed port forward rule %r: %s", raw, e)
            continue
        if r.is_automatic or r.disabled == "1" or r.interface != "wan":
            continue
        target = r.target.strip()
        if not is_usable_ip(target):
            continue                          # an alias target: no single host to point at
        protos = [p for p in ("tcp", "udp") if p in r.protocol.lower()]
        pf = out.setdefault((r.descr, target, r.local_port),
                            PortForward(descr=(r.descr or f"forward to {target}").strip(), port_mappings=[],
                                        target=target, local_port=r.local_port))
        pf.port_mappings += [f"{p}/{n}" for p in protos for n in _ports(r.destination_port)]
    for pf in out.values():
        pf.port_mappings = sorted(set(pf.port_mappings), key=lambda x: (x.split("/")[0], int(x.split("/")[1])))
    return list(out.values())


def wg_peers(clients: list[dict], show: list[dict], servers: set[str]) -> list[WgPeer]:
    """Remote-access peers of the given WireGuard instances (not the Terraform-managed inter-site
    mesh). Only names, addresses and handshake times: the API also returns keys."""
    seen: dict[str, int] = {}
    endpoints: dict[str, str] = {}
    for raw in show:
        try:
            r = WgShowRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed wg show row %r: %s", raw, e)
            continue
        if r.type != "peer":
            continue
        seen[r.name] = int(r.latest_handshake or 0)
        endpoints[r.name] = str(r.endpoint).rsplit(":", 1)[0].strip("[]")
    out = []
    for raw in clients:
        try:
            r = WgClientRowRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed wg client row %r: %s", raw, e)
            continue
        if r.servers not in servers:
            continue
        for addr in r.tunneladdress.split(","):
            ip = addr.strip().split("/")[0]
            if addr.strip().endswith("/32") and is_usable_ip(ip):
                out.append(WgPeer(server=r.servers, name=r.name.strip(), address=ip,
                                  enabled=r.enabled == "1", handshake=seen.get(r.name, 0),
                                  endpoint=endpoints.get(r.name, "") if is_usable_ip(endpoints.get(r.name, "")) else ""))
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
