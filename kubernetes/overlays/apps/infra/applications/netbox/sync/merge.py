"""Merge per-source observations into one desired set of hosts.

Pure functions only (no I/O) so the rules are unit-testable.

Identity: a host is keyed by MAC where one is known, falling back to IP.
Proxmox VMs, hypervisors and the firewall have their own keys and absorb the
MACs/IPs they own. Kubernetes LoadBalancer VIPs are answered by whichever node
holds them, so they show up in ARP with that node's MAC; they are pulled out
before MAC merging or every VIP would fold into a k8s node.
"""
from __future__ import annotations

import logging
import re

from model import (
    NAME_PRECEDENCE, Collected, Desired, HardwareObs, Host, IfaceSpec, InvItem, Link, SvcObs, is_private_ip,
    is_randomized_mac, is_usable_ip, norm_mac, plain_ip, platform_name, vendor_name,
)

log = logging.getLogger("merge")

FIREWALL_KEY = "fw"
MAC_LIKE = re.compile(r"^([0-9A-Fa-f]{2}[-:]?){5}[0-9A-Fa-f]{2}$")   # devices that report their MAC as hostname


def _short(name: str) -> str:
    """First DNS label, sanitised for a NetBox device name."""
    name = name.strip().rstrip(".").split(".")[0]
    return re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")


def vendor_for(mac: str) -> str:
    if is_randomized_mac(mac):
        return "Private MAC"
    try:
        from netaddr import EUI
        return EUI(mac).oui.registration().org
    except Exception:
        return ""


class _Index:
    def __init__(self) -> None:
        self.hosts: dict[str, Host] = {}
        self.by_mac: dict[str, Host] = {}
        self.by_ip: dict[str, Host] = {}

    def add(self, host: Host) -> Host:
        self.hosts[host.key] = host
        for mac in host.macs:
            self.by_mac.setdefault(mac, host)
        for ip in host.ips:
            self.by_ip.setdefault(ip, host)
        return host

    def attach_mac(self, host: Host, mac: str) -> None:
        host.macs.add(mac)
        self.by_mac.setdefault(mac, host)

    def attach_ip(self, host: Host, ip: str, iface: str | None = None) -> None:
        # An IP belongs to one host. DHCP reuse: the newest observation wins, so
        # drop it from whoever held it before.
        prev = self.by_ip.get(plain_ip(ip))
        if prev is not None and prev is not host:
            prev.ips.discard(plain_ip(ip))
            prev.cidrs.pop(plain_ip(ip), None)
            prev.ip_iface.pop(plain_ip(ip), None)
        host.add_ip(ip, iface)
        self.by_ip[plain_ip(ip)] = host

    def find(self, mac: str | None, ip: str | None) -> Host | None:
        if mac and mac in self.by_mac:
            return self.by_mac[mac]
        if ip and ip in self.by_ip:
            return self.by_ip[ip]
        return None


def merge(c: Collected, firewall_name: str) -> Desired:
    idx = _Index()
    vip_ips = {v.ip for v in c.vips}

    # 1. Things with authoritative identity first: firewall, hypervisors, VMs.
    # Only interfaces carrying an address are worth modelling (skips unassigned
    # NICs and pseudo-devices like lo0/enc0/pflog0).
    fw_ifaces = [fi for fi in c.fw_interfaces if any(is_usable_ip(x) for x in fi.cidrs)]
    if fw_ifaces:
        fw = Host(key=FIREWALL_KEY, kind="firewall", sources={"opnsense"}, present=True)
        fw.names["static"] = firewall_name
        for fi in fw_ifaces:
            # VLAN sub-interfaces share their parent NIC's MAC: it belongs to the parent when
            # known, else to the first only, or the one MACAddress object would be moved
            # between interfaces every run.
            if fi.mac and fi.mac not in fw.macs:
                fw.iface_mac.setdefault(fi.parent or fi.name, fi.mac)
                fw.macs.add(fi.mac)
            for cidr in fi.cidrs:
                if is_usable_ip(cidr) and plain_ip(cidr) not in vip_ips:
                    fw.add_ip(cidr, fi.name)
            if fi.vid is not None:
                fw.iface_spec[fi.name] = IfaceSpec(type="virtual" if fi.parent else "", parent=fi.parent,
                                                   untagged=fi.vid)
                if fi.parent:      # the trunk NIC carries every sub-interface's VLAN tagged
                    trunk = fw.iface_spec.setdefault(fi.parent, IfaceSpec())
                    trunk.tagged = sorted(set(trunk.tagged) | {fi.vid})
        idx.add(fw)

    for node in c.pve_nodes:
        h = Host(key=f"pve:{node.name}", kind="hypervisor", sources={"proxmox"}, present=True)
        h.names["proxmox"] = node.name
        if node.version:
            h.platform = platform_name(f"Proxmox VE {node.version}")
        if node.inventory is not None:
            h.inventory["proxmox"] = node.inventory
        if node.ifaces:
            names = {i.name for i in node.ifaces}
            for i in node.ifaces:
                spec = h.iface_spec.setdefault(i.name, IfaceSpec())
                spec.type, spec.parent = i.type, i.parent if i.parent in names else ""
                if i.vid and i.type == "virtual":
                    spec.untagged = i.vid
                for port in i.ports:
                    if port in names:
                        member = h.iface_spec.setdefault(port, IfaceSpec())
                        if i.type == "lag":
                            member.lag = i.name
                        else:
                            member.bridge = i.name
                for cidr in i.cidrs:
                    h.add_ip(cidr, i.name)
        else:
            for cidr in node.cidrs:
                if is_usable_ip(cidr):
                    h.add_ip(cidr, "vmbr0")
        idx.add(h)

    for vm in c.vms:
        h = Host(key=f"vm:{vm.vmid}", kind="lxc" if vm.lxc else "vm", sources={"proxmox"},
                 present=vm.status == "active", vm=vm)
        h.names["proxmox"] = vm.name
        h.platform = platform_name(vm.os)
        for vi in vm.ifaces:
            if vi.mac:
                h.macs.add(vi.mac)
                h.iface_mac.setdefault(vi.name, vi.mac)
            for cidr in vi.cidrs:
                if is_usable_ip(cidr) and plain_ip(cidr) not in vip_ips:
                    h.add_ip(cidr, vi.name)
            if vi.vid:
                h.iface_spec[vi.name] = IfaceSpec(untagged=vi.vid)
        idx.add(h)

    # 2. Live L2 presence from the firewall's ARP table.
    for a in c.arp:
        mac, ip = norm_mac(a.mac), plain_ip(a.ip)
        if not mac or not is_usable_ip(ip) or not is_private_ip(ip) or ip in vip_ips:
            continue
        h = idx.find(mac, None)
        if h is None:
            h = idx.find(None, ip)
            # Only reuse an IP match that has no MAC of its own (e.g. a VM without
            # guest agent config MACs). Otherwise this is a different machine now
            # holding that IP.
            if h is not None and h.macs and mac not in h.macs:
                h = None
        if h is None:
            h = idx.add(Host(key=f"mac:{mac}", kind="client"))
        if h.kind == "firewall":
            continue
        idx.attach_mac(h, mac)
        idx.attach_ip(h, ip)
        # The MAC answering for an address belongs on the interface holding it (a hypervisor's
        # bridge), unless a source already put that MAC on an interface.
        if h.ip_iface.get(ip) and mac not in h.iface_mac.values():
            h.iface_mac.setdefault(h.ip_iface[ip], mac)
        h.sources.add("opnsense")
        h.present = True

    # 3. DHCP leases: hostnames, and presence for active leases.
    for lease in c.leases:
        mac, ip = norm_mac(lease.mac), plain_ip(lease.ip)
        if not is_usable_ip(ip) or not is_private_ip(ip) or ip in vip_ips:
            continue
        h = idx.find(mac, ip)
        if h is None:
            if not lease.active:
                continue
            h = idx.add(Host(key=f"mac:{mac}" if mac else f"ip:{ip}", kind="client"))
        if h.kind == "firewall":
            continue
        if mac:
            idx.attach_mac(h, mac)
        if lease.active:
            idx.attach_ip(h, ip)
            h.present = True
        if lease.hostname and lease.hostname not in ("*", "?") and not MAC_LIKE.match(lease.hostname):
            h.names["dhcp"] = _short(lease.hostname)
        h.sources.add("opnsense")

    # 4. Curated static names (dnsmasq hosts, Unbound overrides).
    for s in c.static_names:
        ip = plain_ip(s.ip)
        if not is_usable_ip(ip) or ip in vip_ips:
            continue
        h = idx.find(norm_mac(s.mac), ip)
        if h is None or h.kind == "firewall":
            continue
        h.names["static"] = _short(s.name)
        if s.fqdn:
            h.fqdn = s.fqdn
        h.sources.add("opnsense")

    # 4b. Omada: client names (fallback below DHCP), and where each client connects.
    # Matched by MAC only: Omada's "ip" is its last-seen address and for k8s nodes
    # it can be a LoadBalancer VIP the node was answering for.
    for oc in c.omada_clients:
        mac, ip = norm_mac(oc.mac), plain_ip(oc.ip) if oc.ip else ""
        if not mac:
            continue
        ip_ok = bool(ip) and is_usable_ip(ip) and is_private_ip(ip) and ip not in vip_ips
        h = idx.find(mac, None)
        if h is None:
            # Active with no address: a quiet device (an iLO) Omada still sees on its port. The MAC
            # is enough to keep its NetBox device present and cabled.
            if not (oc.active and (ip_ok or (not ip and oc.uplink_mac and not oc.ssid))):
                continue
            h = idx.find(None, ip) if ip_ok else None
            if h is not None and h.macs and mac not in h.macs:
                h = None
            if h is None:
                h = idx.add(Host(key=f"mac:{mac}", kind="client"))
        if oc.active and oc.uplink_mac:
            h.links.append(Link(mac=mac, peer_mac=oc.uplink_mac, port=oc.port, ssid=oc.ssid, radio=oc.radio,
                                wifi_mode=oc.wifi_mode, vid=oc.vid))
        if h.kind == "firewall":
            continue
        idx.attach_mac(h, mac)
        if oc.active and ip_ok and ip not in h.ips and idx.by_ip.get(ip) in (None, h):
            idx.attach_ip(h, ip)
        if oc.name:
            h.names["omada"] = oc.name.strip()[:64]     # may be a human-set alias: keep it as typed
        if oc.hostname and not MAC_LIKE.match(oc.hostname):
            h.names["omada-host"] = _short(oc.hostname)
        h.connection = oc.connection or h.connection
        h.present = h.present or oc.active
        h.sources.add("omada")

    # 4c. Omada's own switches/APs. They're DHCP clients of the management LAN like
    # anything else, so ARP/leases usually created them already; this names them
    # ("Lounge Room AP", or model + MAC tail while Omada still shows the MAC).
    for od in c.omada_devices:
        ip = plain_ip(od.ip) if od.ip else ""
        ip_ok = bool(ip) and is_usable_ip(ip) and is_private_ip(ip) and ip not in vip_ips
        h = idx.find(od.mac, None)
        if h is None:
            h = idx.find(None, ip) if ip_ok else None
            if h is not None and h.macs and od.mac not in h.macs:
                h = None
            if h is None:
                if not ip_ok:
                    continue
                h = idx.add(Host(key=f"mac:{od.mac}", kind="network"))
        if h.kind == "firewall":
            continue
        idx.attach_mac(h, od.mac)
        if ip_ok and idx.by_ip.get(ip) in (None, h):
            idx.attach_ip(h, ip)
        if h.kind == "client":
            h.kind = "network"
        model = od.model.split()[0] if od.model else od.type or "omada"
        h.names["omada-device"] = _short(od.name) or f"{_short(model)}-{od.mac.replace(':', '')[-6:]}"
        if od.uplink_mac:
            h.links.append(Link(mac=od.mac, peer_mac=od.uplink_mac, port=od.uplink_port, local_port=od.local_port))
        h.sources.add("omada")

    # 5. Kubernetes nodes: tag the VM (matched by IP) or create a bare host.
    for node, ip in c.k8s_nodes.items():
        h = idx.find(None, ip)
        if h is None:
            h = idx.add(Host(key=f"ip:{ip}", kind="k8s-node", ips={ip}))
            idx.by_ip[ip] = h
        if h.kind in ("vm", "client"):
            h.kind = "k8s-node"
        h.names["k8s-node"] = _short(node)
        h.fqdn = h.fqdn or node
        if c.k8s_node_os.get(node):
            h.platform = platform_name(c.k8s_node_os[node])
        h.sources.add("k8s")

    # 6. Hosts behind selector-less k8s Services (external-service-frigate etc.).
    for ext in c.ext_services:
        h = idx.find(None, ext.ip)
        if h is None:
            h = idx.add(Host(key=f"ip:{ext.ip}", kind="external-service", ips={ext.ip}))
            idx.by_ip[ext.ip] = h
        if h.kind == "client":
            h.kind = "external-service"   # it serves something to the cluster: a server, not a client
        h.names["k8s-ext"] = _short(ext.name)
        h.services.append(_ext_service(ext))
        h.sources.add("k8s")

    # 7. IPA DNS: FQDNs for known hosts; unknown IPs become IP-only records.
    for ip, fqdn in c.ipa_names.items():
        if not is_usable_ip(ip) or ip in vip_ips:
            continue
        h = idx.find(None, ip)
        if h is None:
            h = idx.add(Host(key=f"ip:{ip}", kind="dns-only", ips={ip}))
            idx.by_ip[ip] = h
        h.names["ipa"] = _short(fqdn)
        h.fqdn = h.fqdn or fqdn
        h.sources.add("ipa")

    # 8. Hardware from physical hosts' node metrics, matched by their NICs' MACs (else the
    # instance's IP or name). Real NIC names replace guesses, and the MAC moves to the NIC
    # (a hypervisor's bridge shares its port's MAC).
    for hw in c.hardware:
        h = next((idx.by_mac[m] for m in hw.nics.values() if m in idx.by_mac), None)
        inst = hw.instance.rsplit(":", 1)[0] if re.match(r"^[\d.]+:\d+$", hw.instance) else hw.instance
        h = h or idx.by_ip.get(inst) or next(
            (x for x in idx.hosts.values() if x.vm is None and inst.lower() in {n.lower() for n in x.names.values()}), None)
        if h is None or h.vm is not None or h.kind in ("firewall", "dns-only"):
            continue
        h.hardware, h.serial = hw, hw.serial
        for name, mac in sorted(hw.nics.items()):
            for other in [n for n, m in h.iface_mac.items() if m == mac and n != name]:
                del h.iface_mac[other]
            h.iface_mac[name] = mac
            idx.attach_mac(h, mac)
        h.sources.add("metrics")

    # 8b. Frigate's camera names for camera IPs ("garage_door" -> "garage-door").
    for ip, name in c.cameras.items():
        h = idx.by_ip.get(ip)
        if h is None or h.vm is not None or h.kind in ("firewall", "dns-only"):
            continue
        h.names["frigate"] = _short(name.replace("_", "-"))
        if h.kind == "client":
            h.kind = "camera"
        h.sources.add("frigate")

    # 8c. BMCs: the hardware they see goes on the server (matched by its NICs' MACs), and the
    # BMC itself is part of the server: its MAC, address and switch port fold into the server
    # as a mgmt-only "iLO" interface, its address becoming the server's out-of-band IP.
    absorbed: set[str] = set()
    for b in c.bmcs:
        server = next((idx.by_mac[m] for m in b.system_macs if m in idx.by_mac), None)
        if server is not None and server.vm is None:
            server.inventory["bmc"] = list(b.inventory)
            server.firmware = b.host_firmware
            server.sources.add("bmc")
        bmc = idx.by_mac.get(b.mac)
        if server is not None and server.vm is None and b.mac:
            name = "iLO" if "ilo" in b.platform.lower() else "bmc"
            server.iface_mac[name] = b.mac
            server.iface_spec.setdefault(name, IfaceSpec()).mgmt_only = True
            ips = sorted(bmc.ips) if bmc is not None and bmc is not server else []
            ips = ips or ([b.address] if is_usable_ip(b.address) else [])
            for ip in ips:
                idx.attach_ip(server, bmc.cidrs.get(ip, ip) if bmc is not None and bmc is not server else ip, name)
                server.ip_iface[ip] = name
            server.oob_ip = ips[0] if ips else ""
            if bmc is not None and bmc is not server:
                server.links += [ln for ln in bmc.links if ln.mac == b.mac]     # its switch port
                server.present = server.present or bmc.present
                del idx.hosts[bmc.key]
            idx.by_mac[b.mac] = server
            server.macs.add(b.mac)
            absorbed.add(b.mac)
            continue
        if bmc is not None and bmc is not server and bmc.vm is None and bmc.kind not in ("firewall", "dns-only"):
            bmc.platform = bmc.platform or b.platform
            bmc.firmware = b.firmware
            name = next((n for n, m in bmc.iface_mac.items() if m == b.mac), "eth0")
            bmc.iface_mac.setdefault(name, b.mac)
            bmc.iface_spec.setdefault(name, IfaceSpec()).mgmt_only = True
            bmc.sources.add("bmc")

    # 8d. Home Assistant: names people gave devices, their make/model/firmware and room.
    # Zigbee/Bluetooth devices aren't on IP: inventory items on their coordinator (by HA's
    # via_device link) or on the HA host itself.
    ha_hosts: dict[str, Host] = {}
    url_ips: dict[str, int] = {}
    for d in c.ha_devices:
        url_ips[d.ip] = url_ips.get(d.ip, 0) + 1
    for d in c.ha_devices:
        h = next((idx.by_mac[m] for m in d.macs if m in idx.by_mac), None)
        if h is None and d.ip and url_ips[d.ip] == 1:      # a hub's sub-devices share its URL: not theirs
            h = idx.by_ip.get(d.ip)
        if h is None or h.vm is not None or h.kind in ("firewall", "dns-only"):
            continue
        ha_hosts[d.id] = h
        if d.name:
            h.names["ha" if d.user_named else "ha-auto"] = _short(d.name)
        if d.manufacturer and d.model and h.hardware is None:
            h.hardware = HardwareObs(instance="homeassistant", vendor=vendor_name(d.manufacturer), model=d.model)
        h.firmware = h.firmware or d.firmware
        h.location = h.location or d.area
        h.sources.add("homeassistant")
    ha_host = idx.by_ip.get(c.ha_host_ip) if c.ha_host_ip else None
    if c.ha_devices:        # HA answered: radios it no longer lists go from NetBox too
        for h in {id(x): x for x in list(ha_hosts.values()) + ([ha_host] if ha_host else [])}.values():
            h.inventory.setdefault("homeassistant", [])
    for d in c.ha_devices:
        if not d.radio:
            continue
        parent = ha_hosts.get(d.via) or ha_host
        if parent is None:
            continue
        parent.inventory.setdefault("homeassistant", []).append(InvItem(
            d.radio, d.name[:64], vendor_name(d.manufacturer), d.model, d.radio_addr,
            ", ".join(x for x in (d.radio.title(), d.area) if x)))
        parent.sources.add("homeassistant")

    # 9. Wazuh agents, by agent name (a dual-boot box has one agent per OS on one IP: only
    # the one named like the host counts), else by IP when only one agent has it.
    ip_agents: dict[str, int] = {}
    for ag in c.wazuh:
        ip_agents[ag.ip] = ip_agents.get(ag.ip, 0) + 1
    for ag in c.wazuh:
        short = ag.name.lower().split(".")[0]
        h = next((x for x in idx.hosts.values() if x.kind != "dns-only" and short in
                  {n.lower().split(".")[0] for n in x.names.values()} | {x.fqdn.lower().split(".")[0]} - {""}), None)
        if h is None and ip_agents[ag.ip] == 1:
            h = idx.by_ip.get(ag.ip)
        if h is None or h.kind in ("firewall", "dns-only"):
            continue
        h.platform = h.platform or platform_name(ag.os)
        if h.vm is None:
            h.serial = h.serial or ag.serial
        for proc, pms in sorted(ag.listening.items()):
            h.services.append(SvcObs(name=proc[:100], port_mappings=sorted(pms), description="listening (Wazuh)",
                                     source="wazuh"))
        h.sources.add("wazuh")

    # 10. FreeIPA enrolment: an enrolled host's FQDN resolves (IPA DNS) to one of the hosts.
    by_fqdn = {}
    for ip, fqdn in c.ipa_names.items():
        by_fqdn.setdefault(fqdn.lower(), ip)
    for z in c.dns_zones or []:
        for name, rtype, value in z.records:
            if rtype in ("A", "AAAA"):
                by_fqdn.setdefault((z.name if name == "@" else f"{name}.{z.name}").lower(), value)
    for fqdn in c.ipa_hosts:
        h = idx.by_ip.get(by_fqdn.get(fqdn, "")) or next(
            (x for x in idx.hosts.values() if fqdn.split(".")[0] in {n.lower().split(".")[0] for n in x.names.values()}), None)
        if h is not None and h.kind != "dns-only":
            h.ipa_enrolled = True

    hosts = list(idx.hosts.values())
    _bridge_uplinks(hosts)
    _drop_shared_ports(hosts)
    for h in hosts:
        macs = sorted(h.macs)
        if macs:
            h.randomized_mac = all(is_randomized_mac(m) for m in macs)
            h.vendor = h.vendor or vendor_for(macs[0])
    resolve_names(hosts)

    prefixes: dict[str, tuple[str, int | None]] = {cidr: (desc, None) for cidr, desc in c.k8s_prefixes.items()}
    for fi in fw_ifaces:
        for cidr in fi.cidrs:
            net = _network(cidr)
            if net and is_usable_ip(cidr) and is_private_ip(cidr):
                prefixes.setdefault(net, (fi.description, fi.vid))

    return Desired(hosts=hosts, vips=list(c.vips), prefixes=prefixes, vlans=list(c.vlans),
                   healthy=dict(c.healthy), omada_devices=list(c.omada_devices), dhcp_ranges=list(c.dhcp_ranges),
                   reserved_ips={plain_ip(s.ip) for s in c.static_names}, flow_services=c.flow_services,
                   lb_pools=list(c.lb_pools), port_forwards=c.port_forwards, wg_peers=c.wg_peers,
                   gateways=dict(c.gateways), cloud_vms=list(c.cloud_vms), wazuh=list(c.wazuh),
                   dns_zones=c.dns_zones, absorbed_macs=absorbed)


def _bridge_uplinks(hosts: list[Host]) -> None:
    """A switch port where only VMs show up, all on one hypervisor bridge, is that bridge's
    uplink: the hypervisor's own MAC is never seen there (a bridge with no address of its
    own sends nothing), so cable it by interface name instead."""
    by_key = {h.key: h for h in hosts}
    vm_ports: dict[tuple[str, int], set[tuple[str, str]]] = {}
    other_ports: set[tuple[str, int]] = set()
    for h in hosts:
        for ln in h.links:
            if ln.wireless or ln.port is None:
                continue
            k = (ln.peer_mac, ln.port)
            if h.vm is None:
                other_ports.add(k)
            else:
                bridge = next((vi.bridge for vi in h.vm.ifaces if vi.mac == ln.mac), "")
                vm_ports.setdefault(k, set()).add((h.vm.node, bridge))
    for k, owners in sorted(vm_ports.items()):
        if k in other_ports or len(owners) != 1:
            continue
        node, bridge = next(iter(owners))
        hv = by_key.get(f"pve:{node}")
        if hv is None or not bridge or bridge not in hv.iface_spec:
            continue
        hv.links.append(Link(mac="", peer_mac=k[0], port=k[1], iface=bridge))


def _drop_shared_ports(hosts: list[Host]) -> None:
    """A cable joins one interface to one switch port. When several NetBox devices sit on
    the same port (an unmanaged switch or a hub behind it) there's no single cable to
    draw, so none of them gets one; the connection text still says where they are.
    If exactly one of them is an Omada switch or AP, though (an in-wall AP's LAN ports),
    that's what is plugged in: it keeps its cable and the rest are behind it.
    VMs share their hypervisor's port and never get cables, so they don't count."""
    by_port: dict[tuple[str, int], set[str]] = {}
    kinds = {h.key: h.kind for h in hosts}
    for h in hosts:
        if h.vm is None and h.kind != "dns-only":
            for ln in h.links:
                if not ln.wireless and ln.port is not None:
                    by_port.setdefault((ln.peer_mac, ln.port), set()).add(h.key)
    keep: dict[tuple[str, int], str | None] = {}     # shared port -> the one host still cabled to it
    for k, keys in by_port.items():
        if len(keys) > 1:
            network = [key for key in keys if kinds[key] == "network"]
            keep[k] = network[0] if len(network) == 1 else None
            log.info("switch %s port %s has %d devices: %s", k[0], k[1], len(keys),
                     f"cable to {keep[k]} only" if keep[k] else "no cables")
    for h in hosts:
        h.links = [ln for ln in h.links if ln.wireless or (ln.peer_mac, ln.port) not in keep
                   or keep[(ln.peer_mac, ln.port)] == h.key]


def _ext_service(ext) -> SvcObs:
    return SvcObs(name=ext.name, port_mappings=list(ext.port_mappings),
                  description=f"k8s {ext.k8s_service}")


def _network(cidr: str) -> str | None:
    import ipaddress
    try:
        net = ipaddress.ip_interface(cidr).network
    except ValueError:
        return None
    return None if net.prefixlen in (32, 128) else str(net)


def resolve_names(hosts: list[Host]) -> None:
    """Pick each host's name by precedence, then make device-backed names unique.

    VM names are unique by construction (Proxmox); hosts that become NetBox
    Devices (clients, hypervisors, external-service) share one namespace per
    site, so a duplicate DHCP hostname ("iPhone") gets the MAC tail appended.
    """
    for h in hosts:
        h.name = next((h.names[s] for s in NAME_PRECEDENCE if h.names.get(s)), "")
        if not h.name:
            tail = sorted(h.macs)[0].replace(":", "")[-6:] if h.macs else sorted(h.ips)[0].replace(".", "-")
            h.name = f"client-{tail}" if h.macs else f"host-{tail}"

    seen: dict[str, Host] = {}
    for h in sorted(hosts, key=lambda x: (x.kind in ("client",), x.key)):
        if h.kind in ("vm", "lxc", "k8s-node") and h.vm is not None:
            seen.setdefault(h.name.lower(), h)
            continue
        if h.kind == "dns-only":
            continue
        low = h.name.lower()
        if low in seen and seen[low] is not h:
            tail = (sorted(h.macs)[0].replace(":", "")[-4:] if h.macs
                    else sorted(h.ips)[0].split(".")[-1])
            h.name = f"{h.name}-{tail}"
        seen[h.name.lower()] = h
