"""Observations collected from each source, and the merged desired state.

Sources only fill in the raw dataclasses below; merge.py turns them into
Hosts/Vips/Prefixes; reconcile.py writes those to NetBox.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# Naming precedence, highest first. A host's name comes from the first source
# in this list that named it. "locked" is never produced by a source: objects
# tagged sync-locked in NetBox keep whatever name they have.
# Omada's client name ranks last, below its own current hostname: unless someone renames the
# client in Omada it's the first name Omada ever detected and never updates
# (both phones "iPhone", every camera "Camera1"), and the OpenAPI can't tell a
# real alias from that. Omada's own switches/APs ("omada-device") rank above DHCP:
# their DHCP hostname is just the model ("SG2210P"), shared by every unit.
# "ha" is a name someone gave the device in Home Assistant (curated, so high); "ha-auto" is
# HA's own default name ("SHIELD Android TV"), better than a bare hostname but below DHCP.
NAME_PRECEDENCE = ("proxmox", "k8s-node", "static", "ha", "frigate", "omada-device", "k8s-ext", "ipa", "dhcp", "ha-auto",
                   "omada-host", "omada")


def norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.strip().lower().replace("-", ":")
    return mac if len(mac) == 17 and mac != "00:00:00:00:00:00" else None


def is_randomized_mac(mac: str) -> bool:
    """Locally administered bit (0x02 of the first octet) — phones' private Wi-Fi addresses."""
    return bool(int(mac[:2], 16) & 0x02)


def platform_name(os_name: str) -> str:
    """'Debian GNU/Linux 13 (trixie)' -> 'Debian 13', 'Ubuntu 24.04.1 LTS' -> 'Ubuntu 24.04'."""
    s = re.sub(r"\(.*?\)", "", os_name or "")
    s = re.sub(r"\b(GNU/Linux|Linux|LTS)\b", "", s)
    words = s.split()
    for i, w in enumerate(words):
        if w[:1].isdigit():
            ver = ".".join(w.split(".")[:2])
            return " ".join(words[:i] + [ver])[:100]
    return " ".join(words)[:100]


VENDORS = {"dell inc.": "Dell", "hewlett-packard": "HP", "hewlett-packard company": "HP",
           "hewlett packard enterprise": "HPE", "hpe": "HPE", "lenovo": "Lenovo", "intel corporation": "Intel",
           "asustek computer inc.": "ASUS", "micro-star international co., ltd.": "MSI",
           "gigabyte technology co., ltd.": "Gigabyte", "supermicro": "Supermicro",
           "broadcom inc. and subsidiaries": "Broadcom", "advanced micro devices, inc. [amd]": "AMD",
           "advanced micro devices, inc. [amd/ati]": "AMD", "mellanox technologies": "Mellanox"}


def vendor_name(v: str) -> str:
    """'Dell Inc.' -> 'Dell'; unknown vendors lose a trailing Inc./Corp./Co., Ltd."""
    v = (v or "").strip()
    return VENDORS.get(v.lower()) or re.sub(r"[,.]?\s+(inc\.?|corp(oration)?\.?|co\.,? ltd\.?|ltd\.?)$", "", v,
                                            flags=re.I).strip()


def plain_ip(addr: str) -> str:
    return addr.split("/")[0]


def is_private_ip(addr: str) -> bool:
    """RFC1918/ULA and friends: the LAN. Public addresses (WAN side, ISP gateway) are not inventoried."""
    try:
        return ipaddress.ip_address(plain_ip(addr)).is_private
    except ValueError:
        return False


def is_usable_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(plain_ip(addr))
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


# ---------------------------------------------------------------- raw observations

@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str = ""


@dataclass
class Lease:
    ip: str
    mac: str | None
    hostname: str
    active: bool = True


@dataclass
class StaticName:
    """A curated name for an IP (and optionally MAC): dnsmasq host entry or Unbound override."""
    ip: str
    name: str
    fqdn: str = ""
    mac: str | None = None


@dataclass
class OmadaClient:
    mac: str
    ip: str
    name: str            # Omada's client name: an alias, or the first name it detected ('' when MAC/hostname)
    hostname: str
    connection: str      # "switch SG2210P port 16" / "wifi Home @ Lounge-AP"
    active: bool = True
    uplink_mac: str | None = None   # the switch or AP it's attached to
    port: int | None = None         # wired: switch port number
    ssid: str = ""                  # wireless: SSID (empty = wired)
    radio: int | None = None        # wireless: 0 = 2.4 GHz, 1 = 5 GHz, 2 = 5 GHz-2/6 GHz
    wifi_mode: int | None = None    # wireless: Omada's wifiMode (0 11a … 7 11ax-2.4)
    vid: int | None = None          # VLAN Omada put it in


@dataclass
class SwitchPort:
    num: int
    name: str            # Omada's port name ("Port7", or a human one like "Router Uplink")
    profile: str         # port profile, e.g. "Users", "All", "Disable"
    untagged: int | None = None                         # native VLAN ID
    tagged: list[int] = field(default_factory=list)     # tagged VLAN IDs
    tagged_all: bool = False                            # carries every network Omada has
    type: str = ""                                      # NetBox interface type: what the port can do ("" unknown)
    # Live link state (Omada web API). up None: not collected this run, leave NetBox's alone
    up: bool | None = None
    speed_mbps: int | None = None                       # negotiated
    duplex: str = ""                                    # full | half


@dataclass
class OmadaDevice:
    """A switch/AP/gateway Omada manages (not a client)."""
    mac: str
    ip: str
    name: str            # set in Omada ('' when it's still the MAC)
    model: str           # "SG2210P v5.20"
    type: str            # switch | ap | gateway
    ports: list[SwitchPort] = field(default_factory=list)   # switches
    uplink_mac: str | None = None                            # the switch it's wired to
    uplink_port: int | None = None                           # ...and that switch's port (None: unknown)
    local_port: int | None = None                            # switches: its own port facing the uplink
    serial: str = ""
    firmware: str = ""


@dataclass
class Link:
    """Where one of a host's MACs attaches to the Omada network (from active clients only)."""
    mac: str                        # the host's MAC on this link
    peer_mac: str                   # switch or AP
    port: int | None = None         # wired: switch port (None: known switch, unknown port)
    local_port: int | None = None   # switch-to-switch: this switch's own port (cable port to port)
    iface: str = ""                 # the host's interface by name, when no MAC of its own is seen there
    ssid: str = ""
    radio: int | None = None
    wifi_mode: int | None = None
    vid: int | None = None

    @property
    def wireless(self) -> bool:
        return bool(self.ssid)


@dataclass
class FwInterface:
    name: str           # OS device, e.g. vlan0.110
    description: str    # OPNsense description, e.g. infra_core
    mac: str | None
    cidrs: list[str] = field(default_factory=list)
    vid: int | None = None
    parent: str = ""    # VLAN sub-interface: the NIC it's tagged on, e.g. ix1
    routes: list[str] = field(default_factory=list)  # networks routed out of it, e.g. a WireGuard peer's AllowedIPs


@dataclass
class DhcpRange:
    start: str
    end: str
    interface: str      # OPNsense interface description, e.g. "Users"


@dataclass
class PortForward:
    """An OPNsense port forward (destination NAT) on the WAN."""
    descr: str
    port_mappings: list[str]  # outside ports, ["tcp/3478", "udp/3478"]
    target: str               # inside address
    local_port: str = ""      # inside port when it differs


@dataclass
class WgPeer:
    """A remote-access WireGuard peer: its tunnel address and when it last handshook."""
    server: str               # OPNsense WireGuard instance name ("WG")
    name: str
    address: str              # tunnel address, no mask
    enabled: bool = True
    handshake: int = 0        # epoch seconds, 0 = never
    endpoint: str = ""        # the address it last connected from (a cloud VM's public IP ties it to that VM)


@dataclass
class CloudVm:
    """A VM at a cloud/VPS provider (Binary Lane)."""
    provider: str             # "Binary Lane"
    id: int
    name: str
    region: str               # "syd"
    status: str               # NetBox VM status
    vcpus: float | None = None
    memory_mb: int | None = None
    disk_mb: int | None = None
    os: str = ""
    ips: list[tuple[str, str]] = field(default_factory=list)   # (cidr, interface): public on eth0, private on eth1


@dataclass
class DnsZone:
    """A DNS zone as FreeIPA serves it: SOA and the records worth mirroring."""
    name: str                 # "internal", "20.20.10.in-addr.arpa"
    mname: str                # primary nameserver, "ipa01.internal"
    rname: str                # "hostmaster.internal"
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    minimum: int | None = None
    default_ttl: int | None = None
    records: list[tuple[str, str, str]] = field(default_factory=list)   # (name, type, value): "@" is the apex


@dataclass
class LbPool:
    """A Cilium LoadBalancer IP pool block: where k8s LoadBalancer VIPs come from."""
    name: str
    start: str
    end: str


@dataclass
class HardwareObs:
    """A physical host as its own node metrics describe it (DMI and NICs with burned-in MACs)."""
    instance: str             # metrics instance label: hostname or ip:port
    vendor: str = ""          # "Dell", "HP"
    model: str = ""           # "OptiPlex 3060"
    sku: str = ""             # "085C", "776935-B21"
    serial: str = ""
    nics: dict[str, str] = field(default_factory=dict)   # physical NIC name -> mac


@dataclass
class FlowService:
    """A LAN address seen answering on a fixed port (NetFlow): server port -> many client ports."""
    ip: str
    proto: str          # tcp | udp
    port: int
    name: str           # IANA name, e.g. "https" ('' when unknown)
    clients: int


@dataclass
class VlanObs:
    vid: int
    name: str


@dataclass
class VmIface:
    name: str
    mac: str | None
    cidrs: list[str] = field(default_factory=list)
    vid: int | None = None    # VLAN the NIC lands in: its Proxmox tag, else its bridge's VLAN
    bridge: str = ""          # the hypervisor bridge it's plugged into (vmbr1)


@dataclass
class VmDisk:
    name: str                 # scsi0, rootfs, mp0
    size_mb: int
    storage: str = ""         # Proxmox storage, e.g. local-lvm


@dataclass
class VmObs:
    vmid: int
    name: str
    node: str
    lxc: bool
    status: str               # NetBox VM status
    vcpus: float | None
    memory_mb: int | None
    disk_mb: int | None
    tags: list[str]
    ifaces: list[VmIface] = field(default_factory=list)
    os: str = ""              # guest agent pretty name, or the LXC ostype
    disks: list[VmDisk] = field(default_factory=list)


@dataclass
class PveIface:
    """A hypervisor network interface from /nodes/{node}/network."""
    name: str
    type: str                 # NetBox interface type: "" (physical, leave as is) | bridge | lag | virtual
    ports: list[str] = field(default_factory=list)   # bridge ports / bond slaves
    parent: str = ""          # VLAN interface: the device it's tagged on
    vid: int | None = None
    cidrs: list[str] = field(default_factory=list)


@dataclass
class InvItem:
    """A part inside a device (NetBox inventory item): a disk, CPU or PCI card."""
    role: str                 # disk | cpu | nic | storage-controller | gpu
    name: str                 # sda, cpu0, 0000:03:00.0
    manufacturer: str = ""
    part_id: str = ""         # model
    serial: str = ""
    description: str = ""


@dataclass
class BmcObs:
    """A server's BMC (HPE iLO, via Redfish): the hardware it sees and its own NIC."""
    address: str              # where it was queried
    system_macs: list[str] = field(default_factory=list)   # the server's own NICs: which host it belongs to
    mac: str = ""             # the BMC's dedicated NIC
    platform: str = ""        # "HPE iLO 4"
    firmware: str = ""        # BMC firmware version, "2.82"
    host_firmware: str = ""   # "BIOS P99 v2.00 (12/27/2015); iLO 4 v2.82"
    inventory: list[InvItem] = field(default_factory=list)  # DIMMs, PSUs


@dataclass
class PveNodeObs:
    name: str
    cidrs: list[str]
    version: str = ""         # "9.2.2"
    ifaces: list[PveIface] = field(default_factory=list)
    inventory: list[InvItem] | None = None    # None: Proxmox wouldn't say (leave NetBox's alone)


@dataclass
class SvcObs:
    name: str                 # NetBox service name
    port_mappings: list[str]  # ["tcp/443"]
    description: str = ""
    comments: str = ""
    source: str = "k8s"       # which source owns it (tags it, ages it out)


@dataclass
class WazuhAgent:
    """A host as its Wazuh agent's syscollector inventory describes it."""
    name: str
    ip: str
    os: str = ""              # "Fedora Linux 44 (Sway)"
    serial: str = ""
    listening: dict[str, set[str]] = field(default_factory=dict)   # process -> {"tcp/53", "udp/53"}


@dataclass
class VipObs:
    ip: str
    owners: list[str]         # k8s: ["traefik/traefik", ...]; keepalived: VMs currently holding it
    services: list[SvcObs] = field(default_factory=list)
    kind: str = "k8s"         # k8s (LoadBalancer IP) | vrrp (keepalived floating IP)
    name: str = ""            # display name; default: owners joined
    holders: list[tuple[str, str]] = field(default_factory=list)   # vrrp: (VM name, interface) holding it now


@dataclass
class ExtServiceObs:
    """A selector-less k8s Service whose endpoints are a host outside the cluster."""
    ip: str
    name: str                 # e.g. "frigate"
    k8s_service: str          # e.g. "default/external-service-frigate"
    port_mappings: list[str] = field(default_factory=list)


@dataclass
class Collected:
    healthy: dict[str, bool] = field(default_factory=dict)
    # opnsense
    arp: list[ArpEntry] = field(default_factory=list)
    leases: list[Lease] = field(default_factory=list)
    static_names: list[StaticName] = field(default_factory=list)
    fw_interfaces: list[FwInterface] = field(default_factory=list)
    vlans: list[VlanObs] = field(default_factory=list)
    dhcp_ranges: list[DhcpRange] = field(default_factory=list)
    port_forwards: list[PortForward] | None = None      # None: OPNsense wouldn't say
    wg_peers: list[WgPeer] | None = None
    gateways: dict[str, str] = field(default_factory=dict)   # gateway ip -> name ("WAN_DHCP")
    # proxmox
    pve_nodes: list[PveNodeObs] = field(default_factory=list)
    vms: list[VmObs] = field(default_factory=list)
    # kubernetes
    k8s_nodes: dict[str, str] = field(default_factory=dict)   # node name -> InternalIP
    k8s_node_os: dict[str, str] = field(default_factory=dict)  # node name -> osImage
    vips: list[VipObs] = field(default_factory=list)
    ext_services: list[ExtServiceObs] = field(default_factory=list)
    k8s_prefixes: dict[str, str] = field(default_factory=dict)  # cidr -> description
    lb_pools: list[LbPool] = field(default_factory=list)
    # metrics (VictoriaMetrics node exporters)
    hardware: list[HardwareObs] = field(default_factory=list)
    # wazuh (syscollector inventory)
    wazuh: list[WazuhAgent] = field(default_factory=list)
    # frigate
    cameras: dict[str, str] = field(default_factory=dict)      # camera ip -> Frigate camera name
    # bmc (Redfish)
    bmcs: list[BmcObs] = field(default_factory=list)
    # home assistant (device registry: source_homeassistant.HaDevice)
    ha_devices: list = field(default_factory=list)
    ha_host_ip: str = ""
    # cloud providers
    cloud_vms: list[CloudVm] = field(default_factory=list)
    # ipa
    ipa_names: dict[str, str] = field(default_factory=dict)   # ip -> fqdn
    dns_zones: list[DnsZone] | None = None                    # None: IPA didn't answer
    ipa_hosts: set[str] = field(default_factory=set)          # fqdns of IPA-enrolled hosts
    # omada
    omada_clients: list[OmadaClient] = field(default_factory=list)
    omada_devices: list[OmadaDevice] = field(default_factory=list)
    # flows (None: not refreshed this run, leave flow-derived services alone)
    flow_services: list[FlowService] | None = None


# ---------------------------------------------------------------- merged desired state

@dataclass
class IfaceSpec:
    """How one interface relates to its siblings and VLANs (names and VIDs; reconcile resolves ids)."""
    type: str = ""            # NetBox type to set: bridge | lag | virtual ("" leaves it)
    parent: str = ""          # VLAN sub-interface -> the interface it's tagged on
    bridge: str = ""          # bridge port -> its bridge
    lag: str = ""             # bond slave -> its bond
    untagged: int | None = None
    tagged: list[int] = field(default_factory=list)
    mgmt_only: bool = False       # an out-of-band management port (a BMC's NIC)


@dataclass
class Host:
    key: str                      # stable merge key: vm:<vmid>, pve:<node>, fw, mac:<mac>, ip:<ip>
    kind: str                     # firewall|hypervisor|vm|lxc|k8s-node|external-service|network|camera|client|dns-only
    names: dict[str, str] = field(default_factory=dict)   # source -> name
    fqdn: str = ""
    macs: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)            # plain addresses
    cidrs: dict[str, str] = field(default_factory=dict)   # plain ip -> cidr when a source gave a mask
    ip_iface: dict[str, str] = field(default_factory=dict)  # plain ip -> interface name
    iface_mac: dict[str, str] = field(default_factory=dict)  # interface name -> mac
    iface_spec: dict[str, IfaceSpec] = field(default_factory=dict)  # interface name -> type/parent/VLANs
    sources: set[str] = field(default_factory=set)
    present: bool = False         # seen live this run (ARP/active lease/running VM)
    vendor: str = ""
    randomized_mac: bool = False
    vm: VmObs | None = None
    services: list[SvcObs] = field(default_factory=list)
    connection: str = ""          # where it plugs in (Omada): switch port or Wi-Fi SSID/AP
    links: list[Link] = field(default_factory=list)       # the same, structured: becomes cables / Wi-Fi in NetBox
    platform: str = ""            # "Debian 13", "Proxmox VE 9.2"
    hardware: HardwareObs | None = None   # physical hosts with node metrics: make/model/serial
    serial: str = ""              # physical hosts: from node metrics, else Wazuh
    firmware: str = ""            # BIOS/BMC versions (custom field "firmware")
    location: str = ""            # room (Home Assistant area): NetBox location, filled when empty
    ipa_enrolled: bool = False    # a FreeIPA host (tag ipa-enrolled)
    oob_ip: str = ""              # its BMC's address (on its mgmt-only "iLO" interface): NetBox oob_ip
    inventory: dict[str, list[InvItem]] = field(default_factory=dict)   # source -> parts it reported this run
    name: str = ""                # resolved by merge.resolve_names

    def add_ip(self, cidr_or_ip: str, iface: str | None = None) -> None:
        ip = plain_ip(cidr_or_ip)
        self.ips.add(ip)
        if "/" in cidr_or_ip:
            self.cidrs[ip] = cidr_or_ip
        if iface:
            self.ip_iface.setdefault(ip, iface)


@dataclass
class Desired:
    hosts: list[Host]
    vips: list[VipObs]
    prefixes: dict[str, tuple[str, int | None]]   # cidr -> (description if NetBox has none, VLAN vid)
    vlans: list[VlanObs]
    healthy: dict[str, bool]
    omada_devices: list[OmadaDevice] = field(default_factory=list)
    dhcp_ranges: list[DhcpRange] = field(default_factory=list)
    reserved_ips: set[str] = field(default_factory=set)       # static DHCP hosts / overrides: not "dhcp" status
    flow_services: list[FlowService] | None = None
    lb_pools: list[LbPool] = field(default_factory=list)
    port_forwards: list[PortForward] | None = None
    wg_peers: list[WgPeer] | None = None
    gateways: dict[str, str] = field(default_factory=dict)
    cloud_vms: list[CloudVm] = field(default_factory=list)
    wazuh: list = field(default_factory=list)                 # agents (cloud VMs take their services)
    dns_zones: list[DnsZone] | None = None
    absorbed_macs: set[str] = field(default_factory=set)      # BMC MACs folded into their server this run
