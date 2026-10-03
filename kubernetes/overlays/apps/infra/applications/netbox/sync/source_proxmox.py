"""Proxmox VE: hypervisor nodes (with their NICs, bonds, bridges and VLANs), QEMU VMs
and LXC containers with MACs, IPs, VLANs and disks."""
from __future__ import annotations

import os
import re

import requests

from model import (
    Collected, InvItem, PveIface, PveNodeObs, VipObs, VmDisk, VmIface, VmObs, is_usable_ip, norm_mac, vendor_name,
)

SKIP_IFACES = ("lo", "docker", "br-", "veth", "virbr", "flannel", "cni", "cilium", "lxc", "tunl", "dummy", "kube-")
STATUS = {"running": "active", "stopped": "offline", "paused": "paused"}
NIC_MODELS = ("virtio", "e1000", "e1000e", "vmxnet3", "rtl8139")
MIB = 1024 * 1024
# Proxmox network type -> NetBox interface type ("" = a physical NIC: leave NetBox's type alone)
PVE_IF_TYPES = {"eth": "", "bridge": "bridge", "OVSBridge": "bridge", "bond": "lag", "OVSBond": "lag",
                "vlan": "virtual", "OVSIntPort": "virtual"}
DISK_KEY = re.compile(r"^(scsi|virtio|sata|ide)\d+$|^rootfs$|^mp\d+$")
SIZE_MB = {"K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}


class Proxmox:
    def __init__(self, url: str, token_id: str, token_secret: str):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.verify = os.environ.get("PROXMOX_VERIFY_SSL", "false").lower() == "true"
        self.s.headers["Authorization"] = f"PVEAPIToken={token_id}={token_secret}"

    def get(self, path: str, optional: bool = False):
        r = self.s.get(f"{self.url}/api2/json{path}", timeout=20)
        if r.status_code >= 400:
            if optional:
                return None
            raise RuntimeError(f"Proxmox {path}: {r.status_code} {r.text[:200]}")
        return r.json().get("data")


def _kv(val: str) -> dict[str, str]:
    return dict(p.split("=", 1) for p in val.split(",") if "=" in p)


def _nic_vid(parts: dict[str, str], bridge_vids: dict[str, int],
             vnets: dict[str, tuple[str, int]] | None = None) -> int | None:
    """A NIC's VLAN: its own tag, else its SDN VNet's tag, else the VLAN its (non-VLAN-aware)
    bridge is built on."""
    tag = parts.get("tag", "")
    if tag.isdigit():
        return int(tag)
    if parts.get("bridge", "") in (vnets or {}):
        return vnets[parts["bridge"]][1]
    return bridge_vids.get(parts.get("bridge", ""))


def _nic_bridge(parts: dict[str, str], vnets: dict[str, tuple[str, int]]) -> str:
    """The node bridge a NIC really sits on: an SDN VNet ("infcore") is a VLAN on its zone's bridge."""
    bridge = parts.get("bridge", "")
    return vnets[bridge][0] if bridge in vnets else bridge


def _sdn_vnets(api: "Proxmox") -> dict[str, tuple[str, int]]:
    """SDN VNets in VLAN zones -> (zone bridge, VLAN tag). VXLAN/EVPN zones have no node bridge."""
    zones = {z["zone"]: z.get("bridge") for z in api.get("/cluster/sdn/zones", optional=True) or []
             if z.get("type") in ("vlan", "qinq") and z.get("bridge")}
    return {v["vnet"]: (zones[v["zone"]], int(v["tag"])) for v in api.get("/cluster/sdn/vnets", optional=True) or []
            if v.get("zone") in zones and str(v.get("tag") or "").isdigit()}


def _disks(cfg: dict) -> list[VmDisk]:
    """'local-lvm:vm-100-disk-0,size=32G' -> VmDisk('scsi0', 32768, 'local-lvm'). CD-ROMs and
    bind mounts (no size) are left out."""
    out = []
    for key, val in sorted(cfg.items()):
        if not DISK_KEY.match(key) or not isinstance(val, str):
            continue
        parts = _kv(val)
        m = re.fullmatch(r"(\d+(?:\.\d+)?)([KMGT])", parts.get("size", ""))
        if parts.get("media") == "cdrom" or not m:
            continue
        storage = val.split(",")[0].split(":")[0] if ":" in val.split(",")[0] else ""
        out.append(VmDisk(key, int(float(m.group(1)) * SIZE_MB[m.group(2)]), storage))
    return out


# Disk model prefixes -> manufacturer (Proxmox reports the model string only)
DISK_VENDORS = (("CT", "Crucial"), ("Samsung", "Samsung"), ("SAMSUNG", "Samsung"), ("WDC", "Western Digital"),
                ("WD", "Western Digital"), ("ST", "Seagate"), ("INTEL", "Intel"), ("KINGSTON", "Kingston"),
                ("TOSHIBA", "Toshiba"), ("HGST", "HGST"), ("Micron", "Micron"))
# PCI class prefix -> inventory role; everything else (bridges, chipset functions) is left out
PCI_ROLES = {"0x02": "nic", "0x01": "storage-controller", "0x03": "gpu"}


def _size(b: int) -> str:
    for unit, div in (("TB", 1e12), ("GB", 1e9)):
        if b >= div:
            return f"{b / div:.1f} {unit}"
    return f"{b} B"


def _inventory(disks: list[dict] | None, pci: list[dict] | None, status: dict | None) -> list[InvItem] | None:
    """A node's disks, CPU and add-in PCI devices. None when Proxmox answered none of it."""
    if disks is None and pci is None and status is None:
        return None
    out = []
    for d in disks or []:
        model = (d.get("model") or "").strip()
        out.append(InvItem(
            "disk", (d.get("devpath") or "").rsplit("/", 1)[-1], next((v for p, v in DISK_VENDORS if model.startswith(p)), ""),
            model, (d.get("serial") or "").strip(),
            ", ".join(x for x in (f"{_size(int(d.get('size') or 0))} {d.get('type') or ''}".strip(), d.get("used") or "",
                                  f"SMART {d['health']}" if d.get("health") else "",
                                  f"wearout {d['wearout']}%" if str(d.get("wearout", "")).isdigit() else "") if x)))
    cpu = (status or {}).get("cpuinfo") or {}
    if cpu.get("model"):
        out.append(InvItem("cpu", "cpu0", vendor_name({"GenuineIntel": "Intel", "AuthenticAMD": "AMD"}.get(cpu.get("vendor"), "")),
                           cpu["model"], description=f"{cpu.get('sockets', 1)} socket, {cpu.get('cores')} cores, "
                                                     f"{cpu.get('cpus')} threads"))
    for p in pci or []:
        role = PCI_ROLES.get(str(p.get("class", ""))[:4])
        if role and p.get("id", "").endswith(".0"):        # one per card, not per function
            out.append(InvItem(role, p["id"], vendor_name(p.get("vendor_name") or ""), (p.get("device_name") or "")[:50]))
    return out


def _node_ifaces(net: list[dict]) -> list[PveIface]:
    """Physical NICs that carry something, plus every bond, bridge and VLAN interface."""
    rows = {n["iface"]: n for n in net if n.get("iface") and n.get("iface") != "lo"}
    used = {p for n in rows.values() for p in (n.get("bridge_ports") or "").split() + (n.get("slaves") or "").split()}
    out = []
    for name, n in sorted(rows.items()):
        typ = PVE_IF_TYPES.get(n.get("type", ""))
        if typ is None:
            continue
        cidrs = [c for c in (n.get("cidr"), n.get("cidr6")) if c and is_usable_ip(c)]
        if typ == "" and name not in used and not cidrs:
            continue                                # unplugged/unused NIC
        parent, vid = n.get("vlan-raw-device") or "", n.get("vlan-id")
        if typ == "virtual" and "." in name:        # vmbr0.110: parent and tag are in the name
            parent, _, vid = name.rpartition(".")
        out.append(PveIface(name=name, type=typ,
                            ports=(n.get("bridge_ports") or "").split() + (n.get("slaves") or "").split(),
                            parent=parent if typ == "virtual" else "",
                            vid=int(vid) if str(vid or "").isdigit() else None, cidrs=cidrs))
    return out


def _bridge_vids(ifaces: list[PveIface]) -> dict[str, int]:
    """vmbr110 whose only port is a VLAN interface (enp1s0.110) puts untagged guests in VLAN 110."""
    vids = {i.name: i.vid for i in ifaces if i.vid}
    return {i.name: vids[i.ports[0]] for i in ifaces if i.type == "bridge" and len(i.ports) == 1 and i.ports[0] in vids}


def _qemu_ifaces(api: Proxmox, node: str, vmid: int, running: bool, cfg: dict,
                 bridge_vids: dict[str, int], vnets: dict[str, tuple[str, int]]) -> list[VmIface]:
    config_macs, config_vids, config_bridges = [], {}, {}
    for key, val in sorted(cfg.items()):
        if key.startswith("net") and key[3:].isdigit():
            parts = _kv(val)
            mac = next((norm_mac(parts[m]) for m in NIC_MODELS if m in parts), None)
            if mac:
                config_macs.append(mac)
                config_vids[mac] = _nic_vid(parts, bridge_vids, vnets)
                config_bridges[mac] = _nic_bridge(parts, vnets)

    agent = api.get(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces", optional=True) if running else None
    ifaces: list[VmIface] = []
    for gi in (agent or {}).get("result", []) or []:
        name = gi.get("name", "")
        mac = norm_mac(gi.get("hardware-address"))
        if not name or name.startswith(SKIP_IFACES) or (mac and mac not in config_macs):
            continue                                  # skip container/bridge/virtual NICs inside the guest
        cidrs = [f"{a['ip-address']}/{a.get('prefix', 32)}" for a in gi.get("ip-addresses", [])
                 if is_usable_ip(a.get("ip-address", ""))]
        ifaces.append(VmIface(name=name, mac=mac, cidrs=cidrs, vid=config_vids.get(mac),
                              bridge=config_bridges.get(mac, "")))
    seen = {i.mac for i in ifaces}
    for n, mac in enumerate(config_macs):          # NICs the agent didn't report (or no agent)
        if mac not in seen:
            ifaces.append(VmIface(name=f"net{n}", mac=mac, vid=config_vids.get(mac), bridge=config_bridges.get(mac, "")))
    return ifaces


def _lxc_ifaces(api: Proxmox, node: str, vmid: int, running: bool, cfg: dict,
                bridge_vids: dict[str, int], vnets: dict[str, tuple[str, int]]) -> list[VmIface]:
    live = {}
    if running:
        for li in api.get(f"/nodes/{node}/lxc/{vmid}/interfaces", optional=True) or []:
            live[li.get("name")] = [a for a in (li.get("inet"), li.get("inet6")) if a and is_usable_ip(a)]
    ifaces = []
    for key, val in sorted(cfg.items()):
        if not (key.startswith("net") and key[3:].isdigit()):
            continue
        parts = _kv(val)
        name = parts.get("name", key)
        cidrs = live.get(name) or [parts[k] for k in ("ip", "ip6")
                                   if parts.get(k) and "/" in parts[k] and is_usable_ip(parts[k])]
        ifaces.append(VmIface(name=name, mac=norm_mac(parts.get("hwaddr")), cidrs=cidrs,
                              vid=_nic_vid(parts, bridge_vids, vnets), bridge=_nic_bridge(parts, vnets)))
    return ifaces


def _vip_names() -> dict[str, str]:
    """VIP_NAMES="REDACTED_IP=dns,REDACTED_IP=dns" names keepalived VIPs (else 'vip on <holder>')."""
    out = {}
    for item in os.environ.get("VIP_NAMES", "").split(","):
        ip, _, name = item.partition("=")
        if ip.strip() and name.strip():
            out[ip.strip()] = name.strip()
    return out


def _split_floating(vm: VmObs, vips: dict[str, VipObs], names: dict[str, str]) -> None:
    """An extra IPv4 /32 on an interface that also has a real subnet address is a
    keepalived-style floating IP: record it as a VIP, not as the VM's own address."""
    for iface in vm.ifaces:
        has_subnet = any(not c.endswith("/32") and ":" not in c for c in iface.cidrs)
        if not has_subnet:
            continue
        keep = []
        for cidr in iface.cidrs:
            if cidr.endswith("/32") and ":" not in cidr:
                ip = cidr.split("/")[0]
                vip = vips.setdefault(ip, VipObs(ip=ip, owners=[], kind="vrrp", name=names.get(ip, "")))
                vip.owners.append(vm.name)
                vip.holders.append((vm.name, iface.name))
            else:
                keep.append(cidr)
        iface.cidrs = keep


def collect(c: Collected) -> None:
    api = Proxmox(os.environ["PROXMOX_URL"], os.environ["PROXMOX_TOKEN_ID"], os.environ["PROXMOX_TOKEN_SECRET"])
    vnets = _sdn_vnets(api)
    for node in api.get("/nodes"):
        name = node["node"]
        net = api.get(f"/nodes/{name}/network", optional=True) or []
        cidrs = [n["cidr"] for n in net if n.get("cidr") and is_usable_ip(n["cidr"])]
        ver = (api.get(f"/nodes/{name}/version", optional=True) or {}).get("version", "")
        node_ifaces = _node_ifaces(net)
        bridge_vids = _bridge_vids(node_ifaces)
        inventory = _inventory(api.get(f"/nodes/{name}/disks/list", optional=True),
                               api.get(f"/nodes/{name}/hardware/pci", optional=True),
                               api.get(f"/nodes/{name}/status", optional=True))
        c.pve_nodes.append(PveNodeObs(name=name, cidrs=cidrs, version=ver, ifaces=node_ifaces, inventory=inventory))
        if node.get("status") != "online":
            continue
        for kind in ("qemu", "lxc"):
            for vm in api.get(f"/nodes/{name}/{kind}") or []:
                if vm.get("template"):
                    continue
                vmid, running = int(vm["vmid"]), vm.get("status") == "running"
                cfg = api.get(f"/nodes/{name}/{kind}/{vmid}/config", optional=True) or {}
                ifaces = (_qemu_ifaces if kind == "qemu" else _lxc_ifaces)(api, name, vmid, running, cfg, bridge_vids, vnets)
                os_name = ""
                if kind == "qemu" and running:
                    info = (api.get(f"/nodes/{name}/qemu/{vmid}/agent/get-osinfo", optional=True) or {}).get("result") or {}
                    os_name = info.get("pretty-name") or ""
                elif kind == "lxc":
                    os_name = (cfg.get("ostype") or "").title()
                c.vms.append(VmObs(
                    vmid=vmid, name=vm.get("name") or f"{kind}-{vmid}", node=name, lxc=kind == "lxc",
                    status=STATUS.get(vm.get("status", ""), "offline"),
                    vcpus=float(vm.get("cpus") or vm.get("maxcpu") or 0) or None,
                    memory_mb=int(vm.get("maxmem", 0)) // MIB or None,
                    disk_mb=int(vm.get("maxdisk", 0)) // MIB or None,
                    tags=[t for t in re.split(r"[;, ]+", vm.get("tags") or "") if t],
                    ifaces=ifaces, os=os_name, disks=_disks(cfg)))
    vips: dict[str, VipObs] = {}
    names = _vip_names()
    for vm in c.vms:
        _split_floating(vm, vips, names)
    c.vips.extend(sorted(vips.values(), key=lambda v: v.ip))
