import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from merge import merge  # noqa: E402
from model import (  # noqa: E402
    ArpEntry, Collected, ExtServiceObs, FwInterface, Lease, OmadaDevice, StaticName, SvcObs, VipObs, VmIface, VmObs,
    is_randomized_mac,
)
from reconcile import stale_action  # noqa: E402

NODE_MAC = "bc:24:11:00:00:30"


def _vm(vmid, name, mac, cidr, status="active"):
    return VmObs(vmid=vmid, name=name, node="pve01", lxc=False, status=status, vcpus=2, memory_mb=2048,
                 disk_mb=None, tags=[], ifaces=[VmIface(name="eth0", mac=mac, cidrs=[cidr])])


def _by_key(desired):
    return {h.key: h for h in desired.hosts}


def test_vip_not_merged_into_node_via_arp():
    c = Collected(
        vms=[_vm(130, "k8s-node-1", NODE_MAC, "REDACTED_IP/24")],
        arp=[ArpEntry("REDACTED_IP", NODE_MAC), ArpEntry("REDACTED_IP", NODE_MAC)],
        vips=[VipObs(ip="REDACTED_IP", owners=["traefik/traefik"])],
        k8s_nodes={"k8s-node-1.k8s.internal": "REDACTED_IP"},
    )
    d = merge(c, "jack-cbr-fw01")
    node = _by_key(d)["vm:130"]
    assert node.ips == {"REDACTED_IP"}
    assert node.kind == "k8s-node"
    assert node.name == "k8s-node-1"          # Proxmox name beats the k8s node FQDN
    assert not any("REDACTED_IP" in h.ips for h in d.hosts)


def test_arp_mac_matches_vm_and_marks_present():
    c = Collected(vms=[_vm(101, "frigate", "bc:24:11:aa:bb:cc", "REDACTED_IP/24", status="offline")],
                  arp=[ArpEntry("REDACTED_IP", "BC:24:11:AA:BB:CC")])
    h = _by_key(merge(c, "fw"))["vm:101"]
    assert h.present and "opnsense" in h.sources
    assert h.cidrs["REDACTED_IP"] == "REDACTED_IP/24"


def test_name_precedence_static_beats_dhcp_and_ipa():
    mac = "00:11:32:00:00:01"
    c = Collected(
        arp=[ArpEntry("REDACTED_IP", mac)],
        leases=[Lease("REDACTED_IP", mac, "DiskStation")],
        static_names=[StaticName("REDACTED_IP", "nas", fqdn="nas.internal")],
        ipa_names={"REDACTED_IP": "truenas.internal"},
    )
    h = _by_key(merge(c, "fw"))[f"mac:{mac}"]
    assert h.name == "nas"
    assert h.fqdn == "nas.internal"


def test_dhcp_name_used_when_nothing_better():
    mac = "3c:22:fb:00:00:01"
    c = Collected(arp=[ArpEntry("REDACTED_IP", mac)], leases=[Lease("REDACTED_IP", mac, "Jacks-MacBook.lan")])
    h = _by_key(merge(c, "fw"))[f"mac:{mac}"]
    assert h.name == "Jacks-MacBook"
    assert h.kind == "client"


def test_duplicate_client_names_get_mac_suffix():
    a, b = "da:00:00:00:11:11", "da:00:00:00:22:22"
    c = Collected(arp=[ArpEntry("REDACTED_IP", a), ArpEntry("REDACTED_IP", b)],
                  leases=[Lease("REDACTED_IP", a, "iPhone"), Lease("REDACTED_IP", b, "iPhone")])
    names = sorted(h.name for h in merge(c, "fw").hosts)
    assert names == ["iPhone", "iPhone-2222"]


def test_unnamed_client_fallback_and_randomized_mac():
    mac = "da:a1:19:12:34:56"
    assert is_randomized_mac(mac)
    h = merge(Collected(arp=[ArpEntry("REDACTED_IP", mac)]), "fw").hosts[0]
    assert h.name == "client-123456"
    assert h.randomized_mac and h.vendor == "Private MAC"


def test_dhcp_ip_reassigned_to_new_mac():
    old, new = "00:00:5e:00:00:01", "00:00:5e:00:00:02"
    c = Collected(leases=[Lease("REDACTED_IP", old, "old-laptop", active=False)],
                  arp=[ArpEntry("REDACTED_IP", new)])
    hosts = _by_key(merge(c, "fw"))
    assert hosts[f"mac:{new}"].ips == {"REDACTED_IP"}
    assert f"mac:{old}" not in hosts            # inactive lease for an unseen MAC creates nothing


def test_external_service_names_backend_host():
    c = Collected(arp=[ArpEntry("REDACTED_IP", "bc:24:11:aa:bb:cc")],
                  ext_services=[ExtServiceObs(ip="REDACTED_IP", name="frigate",
                                              k8s_service="default/external-service-frigate",
                                              port_mappings=["tcp/8971", "tcp/8554"])])
    h = merge(c, "fw").hosts[0]
    assert h.name == "frigate"
    assert h.services[0].port_mappings == ["tcp/8971", "tcp/8554"]


def test_firewall_owns_its_interface_ips():
    c = Collected(fw_interfaces=[FwInterface("vlan0.110", "infra_core", "00:0d:b9:00:00:01", ["REDACTED_IP/24"])],
                  arp=[ArpEntry("REDACTED_IP", "00:0d:b9:00:00:01")])
    d = merge(c, "jack-cbr-fw01")
    assert [h.key for h in d.hosts] == ["fw"]
    assert d.hosts[0].name == "jack-cbr-fw01"
    assert d.prefixes == {"REDACTED_IP/24": ("infra_core", None)}


def test_ipa_only_ip_is_dns_only():
    d = merge(Collected(ipa_names={"REDACTED_IP": "ipa01.internal"}), "fw")
    h = d.hosts[0]
    assert (h.kind, h.name, h.fqdn) == ("dns-only", "ipa01", "ipa01.internal")


def test_stale_action():
    day = 86400
    # present -> active; missing briefly -> nothing; 7d -> stale; 30d -> delete (clients only)
    assert stale_action(present=True, age=None, kind="client", healthy=True) == "active"
    assert stale_action(present=False, age=2 * day, kind="client", healthy=True) is None
    assert stale_action(present=False, age=8 * day, kind="client", healthy=True) == "stale"
    assert stale_action(present=False, age=31 * day, kind="client", healthy=True) == "delete"
    assert stale_action(present=False, age=31 * day, kind="vm", healthy=True) == "stale"
    # an unhealthy source never ages anything
    assert stale_action(present=False, age=90 * day, kind="client", healthy=False) is None


def test_vip_services_passthrough():
    vip = VipObs(ip="REDACTED_IP", owners=["traefik/traefik"],
                 services=[SvcObs("traefik/traefik websecure", ["tcp/443"])])
    d = merge(Collected(vips=[vip]), "fw")
    assert d.vips[0].services[0].port_mappings == ["tcp/443"]


def test_physical_k8s_node_from_arp_is_server_device():
    mac = "6c:2b:59:e5:8a:74"
    c = Collected(arp=[ArpEntry("REDACTED_IP", mac), ArpEntry("REDACTED_IP", mac)],
                  vips=[VipObs(ip="REDACTED_IP", owners=["netflow/goflow2"])],
                  static_names=[StaticName("REDACTED_IP", "k8s-node-1")],
                  k8s_nodes={"k8s-node-1.k8s.internal": "REDACTED_IP"})
    h = merge(c, "fw").hosts[0]
    assert (h.kind, h.name, h.ips) == ("k8s-node", "k8s-node-1", {"REDACTED_IP"})
    assert h.vm is None


def test_one_mac_on_two_vlans_is_one_host():
    mac = "54:bf:64:91:ec:5e"
    c = Collected(arp=[ArpEntry("REDACTED_IP", mac), ArpEntry("REDACTED_IP", mac)],
                  static_names=[StaticName("REDACTED_IP", "frigate01"), StaticName("REDACTED_IP", "frigate01")],
                  ext_services=[ExtServiceObs("REDACTED_IP", "frigate", "default/external-service-frigate", ["tcp/8971"])])
    hosts = merge(c, "fw").hosts
    assert len(hosts) == 1
    assert (hosts[0].name, hosts[0].ips, hosts[0].kind) == ("frigate01", {"REDACTED_IP", "REDACTED_IP"}, "external-service")


def test_public_arp_and_prefixes_skipped():
    c = Collected(fw_interfaces=[FwInterface("ix0", "WAN", "7c:5a:1c:84:54:88", ["REDACTED_IP/22"]),
                                 FwInterface("igb0", "Unassigned Interface", "7c:5a:1c:84:54:8c", []),
                                 FwInterface("vlan0.010", "Users", "7c:5a:1c:84:54:89", ["REDACTED_IP/24"], vid=10)],
                  arp=[ArpEntry("REDACTED_IP", "00:a2:00:b2:00:c2")])
    d = merge(c, "fw")
    assert [h.key for h in d.hosts] == ["fw"]
    assert set(d.hosts[0].iface_mac) == {"ix0", "vlan0.010"}
    assert d.prefixes == {"REDACTED_IP/24": ("Users", 10)}


def test_floating_vips_split_from_vm(monkeypatch):
    import source_proxmox
    monkeypatch.setenv("VIP_NAMES", "REDACTED_IP=dns")
    vm = _vm(104, "blocky01", "bc:24:11:e0:48:46", "REDACTED_IP/24")
    vm.ifaces[0].cidrs += ["REDACTED_IP/32", "REDACTED_IP/32"]
    vips = {}
    source_proxmox._split_floating(vm, vips, source_proxmox._vip_names())
    assert vm.ifaces[0].cidrs == ["REDACTED_IP/24"]
    assert vips["REDACTED_IP"].name == "dns" and vips["REDACTED_IP"].kind == "vrrp"
    assert vips["REDACTED_IP"].owners == ["blocky01"]
    d = merge(Collected(vms=[vm], vips=list(vips.values()),
                        arp=[ArpEntry("REDACTED_IP", "bc:24:11:e0:48:46")]), "fw")
    assert _by_key(d)["vm:104"].ips == {"REDACTED_IP"}


def test_vlan_subinterfaces_share_mac_only_first_gets_it():
    mac = "7c:5a:1c:84:54:89"
    c = Collected(fw_interfaces=[FwInterface("ix1", "LAN", mac, ["REDACTED_IP/24"]),
                                 FwInterface("vlan0.010", "Users", mac, ["REDACTED_IP/24"], vid=10)])
    fw = merge(c, "fw").hosts[0]
    assert fw.iface_mac == {"ix1": mac}
    assert fw.ip_iface == {"REDACTED_IP": "ix1", "REDACTED_IP": "vlan0.010"}


def test_mac_shaped_hostname_ignored():
    mac = "9c:a2:f4:b1:ba:f8"
    c = Collected(arp=[ArpEntry("REDACTED_IP", mac)], leases=[Lease("REDACTED_IP", mac, "9C-A2-F4-B1-BA-F8")])
    assert merge(c, "fw").hosts[0].name == "client-b1baf8"


def test_omada_connection_and_dhcp_beats_omada_name():
    # Omada keeps the first name it detected ("iPhone") after the device's hostname changes
    from model import OmadaClient
    mac = "7c:c0:6f:11:45:a3"
    c = Collected(arp=[ArpEntry("REDACTED_IP", mac)], leases=[Lease("REDACTED_IP", mac, "Lucys-iphone")],
                  omada_clients=[OmadaClient(mac=mac, ip="REDACTED_IP", name="iPhone", hostname="",
                                             connection="wifi Home @ Lounge")])
    h = merge(c, "fw").hosts[0]
    assert (h.name, h.connection) == ("Lucys-iphone", "wifi Home @ Lounge")
    assert "omada" in h.sources


def test_omada_name_used_without_dhcp_hostname():
    from model import OmadaClient
    mac = "50:23:a2:41:64:22"
    c = Collected(arp=[ArpEntry("REDACTED_IP", mac)], leases=[Lease("REDACTED_IP", mac, "*")],
                  omada_clients=[OmadaClient(mac=mac, ip="REDACTED_IP", name="Jennys-iPad", hostname="",
                                             connection="")])
    assert merge(c, "fw").hosts[0].name == "Jennys-iPad"


def test_omada_vip_ip_not_attached_to_node():
    from model import OmadaClient
    mac = "6c:2b:59:f4:ce:95"
    c = Collected(arp=[ArpEntry("REDACTED_IP", mac)], vips=[VipObs(ip="REDACTED_IP", owners=["traefik/traefik"])],
                  omada_clients=[OmadaClient(mac=mac, ip="REDACTED_IP", name="", hostname="k8s-node-2", connection="")])
    h = merge(c, "fw").hosts[0]
    assert h.ips == {"REDACTED_IP"} and h.name == "k8s-node-2"


def test_omada_only_client_created():
    from model import OmadaClient
    c = Collected(omada_clients=[OmadaClient(mac="0c:37:96:16:e6:88", ip="REDACTED_IP", name="", hostname="",
                                             connection="wifi Home @ Lounge")])
    h = merge(c, "fw").hosts[0]
    assert h.kind == "client" and h.ips == {"REDACTED_IP"} and h.connection == "wifi Home @ Lounge"


def test_omada_hostname_beats_omada_name():
    # Camera sends "*" over DHCP; Omada's name is the frozen first-seen "Camera1"
    from model import OmadaClient
    mac = "ec:71:db:c1:14:e4"
    c = Collected(arp=[ArpEntry("REDACTED_IP", mac)], leases=[Lease("REDACTED_IP", mac, "*")],
                  omada_clients=[OmadaClient(mac=mac, ip="REDACTED_IP", name="Camera1", hostname="IPC-BO",
                                             connection="")])
    assert merge(c, "fw").hosts[0].name == "IPC-BO"


def test_omada_devices_named_from_omada_not_dhcp():
    sw, ap = "28:87:ba:b1:38:69", "9c:a2:f4:3b:1a:be"
    c = Collected(
        arp=[ArpEntry("REDACTED_IP", sw), ArpEntry("REDACTED_IP", ap)],
        leases=[Lease("REDACTED_IP", sw, "SG2210P")],
        omada_devices=[OmadaDevice(sw, "REDACTED_IP", "", "SG2210P v5.20", "switch"),
                       OmadaDevice(ap, "REDACTED_IP", "Lounge Room AP", "EAP615-Wall(US) v1.0", "ap")])
    hosts = _by_key(merge(c, "fw"))
    assert hosts[f"mac:{sw}"].name == "SG2210P-b13869"
    assert hosts[f"mac:{ap}"].name == "Lounge-Room-AP"
    assert {hosts[f"mac:{sw}"].kind, hosts[f"mac:{ap}"].kind} == {"network"}


def test_omada_device_not_in_arp_is_created():
    mac = "9c:a2:f4:b1:ba:f8"
    d = merge(Collected(omada_devices=[OmadaDevice(mac, "REDACTED_IP", "", "SG3428 v2.30", "switch")]), "fw")
    h = _by_key(d)[f"mac:{mac}"]
    assert h.name == "SG3428-b1baf8" and h.ips == {"REDACTED_IP"} and "omada" in h.sources


# --------------------------------------------------------------------- interface structure / disks

PVE_NETWORK = [
    {"iface": "lo", "type": "loopback"},
    {"iface": "enp1s0", "type": "eth"}, {"iface": "enp2s0", "type": "eth"},
    {"iface": "enp3s0", "type": "eth"},                                         # unplugged: dropped
    {"iface": "bond0", "type": "bond", "slaves": "enp1s0 enp2s0"},
    {"iface": "vmbr0", "type": "bridge", "bridge_ports": "bond0", "cidr": "REDACTED_IP/24"},
    {"iface": "vmbr0.110", "type": "vlan"},
    {"iface": "vmbr110", "type": "bridge", "bridge_ports": "vmbr0.110"},
]


def test_proxmox_node_network_and_disks():
    import source_proxmox as sp
    ifaces = {i.name: i for i in sp._node_ifaces(PVE_NETWORK)}
    assert set(ifaces) == {"enp1s0", "enp2s0", "bond0", "vmbr0", "vmbr0.110", "vmbr110"}
    assert ifaces["bond0"].type == "lag" and ifaces["bond0"].ports == ["enp1s0", "enp2s0"]
    assert ifaces["vmbr0.110"].parent == "vmbr0" and ifaces["vmbr0.110"].vid == 110
    assert ifaces["enp1s0"].type == "" and ifaces["vmbr0"].cidrs == ["REDACTED_IP/24"]
    vids = sp._bridge_vids(list(ifaces.values()))
    assert vids == {"vmbr110": 110}
    assert sp._nic_vid(sp._kv("virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=510"), vids) == 510
    assert sp._nic_vid(sp._kv("virtio=BC:24:11:00:00:01,bridge=vmbr110"), vids) == 110
    assert sp._nic_vid(sp._kv("virtio=BC:24:11:00:00:01,bridge=vmbr0"), vids) is None

    disks = sp._disks({"scsi0": "local-lvm:vm-100-disk-0,iothread=1,size=32G", "ide2": "none,media=cdrom",
                       "efidisk0": "local-lvm:vm-100-disk-1,size=4M", "virtio1": "nas:100/vm-100-disk-2.qcow2,size=1T",
                       "rootfs": "local-zfs:subvol-101-disk-0,size=512M", "mp0": "/mnt/media,mp=/media"})
    assert [(d.name, d.size_mb, d.storage) for d in disks] == \
        [("rootfs", 512, "local-zfs"), ("scsi0", 32768, "local-lvm"), ("virtio1", 1048576, "nas")]


def test_hypervisor_and_vm_interface_specs():
    import source_proxmox as sp
    from model import PveNodeObs
    node = PveNodeObs("pve01", ["REDACTED_IP/24"], ifaces=sp._node_ifaces(PVE_NETWORK))
    vm = _vm(130, "k8s-node-1", NODE_MAC, "REDACTED_IP/24")
    vm.ifaces[0].vid = 510
    d = merge(Collected(pve_nodes=[node], vms=[vm], arp=[ArpEntry("REDACTED_IP", "58:47:ca:00:00:02")]), "fw")
    pve = _by_key(d)["pve:pve01"]
    spec = pve.iface_spec
    assert spec["enp1s0"].lag == "bond0" and spec["bond0"].bridge == "vmbr0" and spec["bond0"].type == "lag"
    assert spec["vmbr0.110"].parent == "vmbr0" and spec["vmbr0.110"].untagged == 110
    assert spec["vmbr0.110"].bridge == "vmbr110" and spec["vmbr110"].type == "bridge"
    assert pve.ip_iface == {"REDACTED_IP": "vmbr0"}
    assert pve.iface_mac == {"vmbr0": "58:47:ca:00:00:02"}          # the MAC ARP saw for the bridge's address
    assert _by_key(d)["vm:130"].iface_spec["eth0"].untagged == 510


def test_firewall_vlan_subinterfaces_hang_off_their_trunk():
    mac = "7c:5a:1c:84:54:89"
    c = Collected(fw_interfaces=[FwInterface("vlan0.010", "Users", mac, ["REDACTED_IP/24"], vid=10, parent="ix1"),
                                 FwInterface("vlan0.510", "kubernetes", mac, ["REDACTED_IP/24"], vid=510, parent="ix1")])
    fw = merge(c, "fw").hosts[0]
    assert fw.iface_mac == {"ix1": mac}
    assert fw.iface_spec["vlan0.010"].parent == "ix1" and fw.iface_spec["vlan0.010"].type == "virtual"
    assert fw.iface_spec["ix1"].tagged == [10, 510]



def test_opnsense_vlan_parent_matched_by_tag_when_device_names_differ(monkeypatch):
    import source_opnsense

    class Api:
        def call(self, *paths, search=False, required=True):
            p = paths[0]
            if p.startswith("interfaces/overview"):
                return [{"device": "vlan0.010", "description": "Users", "macaddr": "7c:5a:1c:84:54:89",
                         "addr4": "REDACTED_IP/24", "vlan_tag": "10"},
                        {"device": "ix1", "description": "LAN", "macaddr": "7c:5a:1c:84:54:89",
                         "addr4": "REDACTED_IP/24"}]
            if p.startswith("interfaces/vlan_settings"):
                return [{"if": "ix1", "tag": "10", "descr": "Users", "vlanif": "vlan0.10"}]
            return []
    monkeypatch.setattr(source_opnsense, "OPNsense", lambda *a: Api())
    for k in ("OPNSENSE_URL", "OPNSENSE_KEY", "OPNSENSE_SECRET"):
        monkeypatch.setenv(k, "x")
    c = Collected()
    source_opnsense.collect(c)
    fis = {f.name: f for f in c.fw_interfaces}
    assert fis["vlan0.010"].parent == "ix1" and fis["ix1"].parent == ""


# --------------------------------------------------------------------- Omada wiring (real payload shapes)

def test_omada_topology_and_web_port_status():
    import source_omada as so
    from model import SwitchPort
    core = OmadaDevice("9c:a2:f4:b1:ba:f8", "REDACTED_IP", "", "SG3428 v2.30", "switch",
                       ports=[SwitchPort(n, f"Port{n}", "All") for n in (3, 14, 25)])
    edge = OmadaDevice("28:87:ba:b1:38:69", "REDACTED_IP", "", "SG2210P v5.20", "switch",
                       ports=[SwitchPort(n, f"Port{n}", "All") for n in (1, 7, 8)])
    ap = OmadaDevice("9c:a2:f4:3b:1a:be", "REDACTED_IP", "Lounge Room AP", "EAP615-Wall(US) v1.0", "ap",
                     uplink_mac="28:87:ba:b1:38:69")
    so.apply_topology({
        "topologyNodes": [
            {"type": "switch", "mac": "9C-A2-F4-B1-BA-F8"},
            {"type": "switch", "mac": "28-87-BA-B1-38-69",
             "upperInfo": {"port": {"port": 8}, "upLinkPort": {"port": 3}, "linkSpeed": 3, "duplex": 2}},
            {"type": "ap", "mac": "9C-A2-F4-3B-1A-BE"}],
        "topologyEdges": [{"upLinkMac": "9C-A2-F4-B1-BA-F8", "downLinkMac": "28-87-BA-B1-38-69"},
                          {"upLinkMac": "28-87-BA-B1-38-69", "downLinkMac": "9C-A2-F4-3B-1A-BE"}]},
        [core, edge, ap])
    assert (edge.uplink_mac, edge.uplink_port, edge.local_port) == ("9c:a2:f4:b1:ba:f8", 3, 8)
    assert core.uplink_mac is None and ap.uplink_port is None

    so.apply_port_status(core, {"ports": [
        {"port": 3, "type": 1, "maxSpeed": 3, "portStatus": {"linkStatus": 1, "linkSpeed": 3, "duplex": 2}},
        {"port": 14, "type": 1, "maxSpeed": 3, "portStatus": {"linkStatus": 1, "linkSpeed": 2, "duplex": 2}},
        {"port": 25, "type": 3, "maxSpeed": 3, "portStatus": {"linkStatus": 0, "linkSpeed": 0, "duplex": 0}}]},
        {})
    p = {x.num: x for x in core.ports}
    assert (p[14].type, p[14].up, p[14].speed_mbps, p[14].duplex) == ("1000base-t", True, 100, "full")
    assert (p[25].type, p[25].up, p[25].speed_mbps) == ("1000base-x-sfp", False, None)
    so.apply_port_status(edge, {"ports": [], "downlinkList": [
        {"port": 1, "mac": "9C-A2-F4-3B-1A-BE", "type": "ap", "linkSpeed": 3, "duplex": 2}]},
        {o.mac: o for o in (core, edge, ap)})
    assert (ap.uplink_mac, ap.uplink_port) == ("28:87:ba:b1:38:69", 1)


def test_sdn_vnet_resolves_to_its_zone_bridge_and_tag():
    import source_proxmox as sp

    class Api:
        def get(self, path, optional=False):
            return {"/cluster/sdn/zones": [{"zone": "sdnnet", "type": "vlan", "bridge": "vmbr1"},
                                           {"zone": "vxlan", "type": "vxlan"}],
                    "/cluster/sdn/vnets": [{"vnet": "infcore", "zone": "sdnnet", "tag": 110},
                                           {"vnet": "test", "zone": "vxlan", "tag": 4000}]}[path]
    vnets = sp._sdn_vnets(Api())
    assert vnets == {"infcore": ("vmbr1", 110)}
    parts = sp._kv("virtio=BC:24:11:E0:48:46,bridge=infcore")
    assert sp._nic_vid(parts, {}, vnets) == 110 and sp._nic_bridge(parts, vnets) == "vmbr1"
    assert sp._nic_bridge(sp._kv("virtio=BC:24:11:00:00:01,bridge=test"), vnets) == "test"


# --------------------------------------------------------------------- hardware from node metrics

def _vm_row(value, **labels):
    return {"metric": labels, "value": [0, str(value)]}


HYDROGEN_DMI = _vm_row(1, instance="hydrogen", system_vendor="HP", product_name="ProLiant ML110 Gen9",
                       product_sku="776935-B21", product_serial="SGH605YSJJ", chassis_vendor="HP")
NODE_DMI = _vm_row(1, instance="REDACTED_IP:9100", system_vendor="Dell Inc.", product_name="OptiPlex 3060",
                   product_sku="085C", chassis_vendor="Dell Inc.")
QEMU_DMI = _vm_row(1, instance="ipa01.internal", system_vendor="QEMU", chassis_vendor="QEMU",
                   product_name="Standard PC (i440FX + PIIX, 1996)")


def _metrics_hardware():
    import source_metrics as sm
    nics = [("hydrogen", "eno1", "94:57:a5:b4:70:dc", 0, 125000000), ("hydrogen", "eno2", "94:57:a5:b4:70:dd", 0, 125000000),
            ("hydrogen", "eno2.110", "94:57:a5:b4:70:dd", 2, 125000000), ("hydrogen", "vmbr0", "94:57:a5:b4:70:dc", 3, 0),
            ("hydrogen", "lo", "00:00:00:00:00:00", 0, 0),
            ("REDACTED_IP:9100", "eth0", "6c:2b:59:e5:8a:74", 0, 125000000),
            ("REDACTED_IP:9100", "cilium_wg0", "", 0, 0)]
    return sm.hardware([HYDROGEN_DMI, NODE_DMI, QEMU_DMI],
                       [_vm_row(a, instance=i, device=d) for i, d, _, a, _ in nics],
                       [_vm_row(sp, instance=i, device=d) for i, d, _, _, sp in nics if sp],
                       [_vm_row(1, instance=i, device=d, address=m) for i, d, m, _, _ in nics])


def test_metrics_hardware_keeps_physical_hosts_and_their_burned_in_nics():
    hw = {h.instance: h for h in _metrics_hardware()}
    assert set(hw) == {"hydrogen", "REDACTED_IP:9100"}                     # QEMU guests left to Proxmox
    assert (hw["hydrogen"].vendor, hw["hydrogen"].model, hw["hydrogen"].sku, hw["hydrogen"].serial) == \
        ("HP", "ProLiant ML110 Gen9", "776935-B21", "SGH605YSJJ")
    assert hw["hydrogen"].nics == {"eno1": "94:57:a5:b4:70:dc", "eno2": "94:57:a5:b4:70:dd"}
    assert (hw["REDACTED_IP:9100"].vendor, hw["REDACTED_IP:9100"].serial) == ("Dell", "")
    assert hw["REDACTED_IP:9100"].nics == {"eth0": "6c:2b:59:e5:8a:74"}


def test_hardware_attaches_by_mac_and_moves_the_mac_to_the_real_nic():
    from model import PveNodeObs
    c = Collected(pve_nodes=[PveNodeObs("hydrogen", ["REDACTED_IP/24"])], arp=[ArpEntry("REDACTED_IP", "94:57:a5:b4:70:dc"),
                  ArpEntry("REDACTED_IP", "6c:2b:59:e5:8a:74")],
                  k8s_nodes={"k8s-node-1": "REDACTED_IP"}, hardware=_metrics_hardware())
    hosts = _by_key(merge(c, "fw"))
    hv = hosts["pve:hydrogen"]
    assert hv.hardware.model == "ProLiant ML110 Gen9"
    assert hv.iface_mac == {"eno1": "94:57:a5:b4:70:dc", "eno2": "94:57:a5:b4:70:dd"}   # off vmbr0
    node = hosts["mac:6c:2b:59:e5:8a:74"]
    assert node.hardware.model == "OptiPlex 3060" and node.iface_mac == {"eth0": "6c:2b:59:e5:8a:74"}


# --------------------------------------------------------------------- Wazuh

def _wazuh_agents():
    import source_wazuh as sw
    sysd = lambda i, n, ip, os_n, ver: {"agent": {"id": i, "name": n, "host": {"ip": ip}},  # noqa: E731
                                        "host": {"os": {"name": os_n, "version": ver}}}
    port = lambda i, proto, ip, p, state, proc, dport=0: {  # noqa: E731
        "agent": {"id": i}, "network": {"transport": proto}, "source": {"ip": ip, "port": p},
        "destination": {"port": dport}, "interface": {"state": state} if state else {}, "process": {"name": proc}}
    return sw.agents(
        [sysd("001", "jp-desktop", "REDACTED_IP", "Fedora Linux", "44 (Sway)"),
         sysd("003", "DESKTOP-DG7P6D4", "REDACTED_IP", "Microsoft Windows 11 IoT Enterprise LTSC 2024", "10.0"),
         sysd("004", "blocky01", "REDACTED_IP", "Debian GNU/Linux", "13 (trixie)")],
        [{"agent": {"id": "001"}, "host": {"serial_number": "07D5411_LB1E725776"}}],
        [port("004", "tcp6", "::", 53, "listening", "blocky"), port("004", "udp6", "::", 53, None, "blocky"),
         port("004", "tcp", "REDACTED_IP", 22, "listening", "sshd"), port("004", "tcp", "REDACTED_IP", 12345, "listening", "alloy"),
         port("004", "tcp", "REDACTED_IP", 50514, "established", "alloy"), port("004", "udp", "REDACTED_IP", 41234, None, "x"),
         port("003", "tcp", "REDACTED_IP", 445, "listening", "System")])


def test_wazuh_listening_ports_only():
    ag = {a.name: a for a in _wazuh_agents()}
    assert ag["blocky01"].listening == {"blocky": {"tcp/53", "udp/53"}, "sshd": {"tcp/22"}}   # no loopback/established/ephemeral
    assert ag["jp-desktop"].serial == "07D5411_LB1E725776" and ag["jp-desktop"].os == "Fedora Linux 44 (Sway)"


def test_wazuh_attaches_by_name_and_skips_the_other_os_of_a_dual_boot():
    c = Collected(arp=[ArpEntry("REDACTED_IP", "d8:bb:c1:9b:c1:dc")], leases=[Lease("REDACTED_IP", "d8:bb:c1:9b:c1:dc", "jp-desktop")],
                  vms=[_vm(104, "blocky01.inf.internal", "bc:24:11:e0:48:46", "REDACTED_IP/24")], wazuh=_wazuh_agents())
    hosts = _by_key(merge(c, "fw"))
    desk = hosts["mac:d8:bb:c1:9b:c1:dc"]
    assert desk.platform == "Fedora 44" and desk.serial == "07D5411_LB1E725776"
    assert not any(s.name == "System" for s in desk.services)                   # the Windows agent's
    blocky = hosts["vm:104"]
    assert {(s.name, tuple(s.port_mappings), s.source) for s in blocky.services} == \
        {("blocky", ("tcp/53", "udp/53"), "wazuh"), ("sshd", ("tcp/22",), "wazuh")}
    assert blocky.serial == ""                                                   # VMs have no serial


# --------------------------------------------------------------------- Frigate

FRIGATE_CFG = {
    "go2rtc": {"streams": {
        "garage": ["ffmpeg:http://REDACTED_IP/flv?port=1935&app=bcs&stream=channel0_main.bcs&user=frigate&password=x#video=copy"],
        "garage_sub": ["ffmpeg:http://REDACTED_IP/flv?port=1935&app=bcs&stream=channel0_ext.bcs&user=frigate&password=x"],
        "garage_door": ["ffmpeg:http://REDACTED_IP/flv?port=1935&app=bcs&stream=channel0_main.bcs&user=frigate&password=x"]}},
    "cameras": {
        "garage": {"enabled": True, "ffmpeg": {"inputs": [{"path": "rtsp://REDACTED_IP:8554/garage"},
                                                         {"path": "rtsp://REDACTED_IP:8554/garage_sub"}]}},
        "garage_door": {"enabled": True, "ffmpeg": {"inputs": [{"path": "rtsp://REDACTED_IP:8554/garage_door"}]}},
        "driveway": {"enabled": True, "ffmpeg": {"inputs": [{"path": "rtsp://admin:pw@REDACTED_IP:554/stream1"}]}},
        "old": {"enabled": False, "ffmpeg": {"inputs": [{"path": "rtsp://REDACTED_IP/x"}]}}}}


def test_frigate_camera_ips_via_go2rtc_and_direct():
    import source_frigate
    assert source_frigate.camera_ips(FRIGATE_CFG) == {"REDACTED_IP": "garage", "REDACTED_IP": "garage_door",
                                                      "REDACTED_IP": "driveway"}


def test_frigate_names_the_camera_over_its_dhcp_hostname():
    import source_frigate
    c = Collected(arp=[ArpEntry("REDACTED_IP", "ec:71:db:35:4b:69")],
                  leases=[Lease("REDACTED_IP", "ec:71:db:35:4b:69", "FrontDoor")],
                  cameras=source_frigate.camera_ips(FRIGATE_CFG))
    h = merge(c, "fw").hosts[0]
    assert (h.name, h.kind) == ("garage", "camera")


def test_proxmox_inventory_disks_cpu_and_cards():
    import source_proxmox as sp
    inv = sp._inventory(
        [{"devpath": "/dev/sda", "model": "CT1000MX500SSD1", "serial": "2230E64CE32D", "size": 1000204886016,
          "type": "ssd", "wearout": 73, "health": "PASSED", "used": "zfs_member"}],
        [{"id": "0000:00:04.0", "class": "0x088000", "vendor_name": "Intel Corporation", "device_name": "DMA Channel 0"},
         {"id": "0000:03:00.0", "class": "0x020000", "vendor_name": "Broadcom Inc. and subsidiaries",
          "device_name": "NetXtreme BCM5720 Gigabit Ethernet PCIe"},
         {"id": "0000:03:00.1", "class": "0x020000", "vendor_name": "Broadcom Inc. and subsidiaries",
          "device_name": "NetXtreme BCM5720 Gigabit Ethernet PCIe"}],
        {"cpuinfo": {"model": "Intel(R) Xeon(R) CPU E5-2683 v4 @ 2.10GHz", "vendor": "GenuineIntel", "sockets": 1,
                     "cores": 16, "cpus": 32}})
    by = {(i.role, i.name): i for i in inv}
    disk = by[("disk", "sda")]
    assert (disk.manufacturer, disk.part_id, disk.serial) == ("Crucial", "CT1000MX500SSD1", "2230E64CE32D")
    assert disk.description == "1.0 TB ssd, zfs_member, SMART PASSED, wearout 73%"
    assert by[("cpu", "cpu0")].manufacturer == "Intel" and "16 cores" in by[("cpu", "cpu0")].description
    assert [k for k in by if k[0] == "nic"] == [("nic", "0000:03:00.0")]          # one per card; chipset left out
    assert by[("nic", "0000:03:00.0")].manufacturer == "Broadcom"
    assert sp._inventory(None, None, None) is None


# --------------------------------------------------------------------- BMC (Redfish)

REDFISH = {
    "/redfish/v1/Systems/1/": {"Manufacturer": "HPE", "Model": "ProLiant ML110 Gen9", "BiosVersion": "P99 v2.00 (12/27/2015)"},
    "/redfish/v1/Managers/1/": {"FirmwareVersion": "iLO 4 v2.82"},
    "/redfish/v1/Systems/1/EthernetInterfaces/": {"Members": [{"@odata.id": "/s/1"}, {"@odata.id": "/s/2"}]},
    "/s/1": {"MacAddress": "94:57:A5:B4:70:DC"}, "/s/2": {"MacAddress": "94:57:A5:B4:70:DD"},
    "/redfish/v1/Managers/1/EthernetInterfaces/": {"Members": [{"@odata.id": "/m/2"}, {"@odata.id": "/m/1"}]},
    "/m/1": {"MacAddress": "94:57:A5:B4:70:DE", "Status": {"State": "Enabled"}},
    "/m/2": {"MacAddress": "94:57:A5:B4:70:DF", "Status": {"State": "Disabled"}},
    "/redfish/v1/Systems/1/Memory/": {"Members": [{"@odata.id": "/d/1"}, {"@odata.id": "/d/2"}]},
    "/d/1": {"Name": "proc1dimm1", "SizeMB": 32768, "DIMMType": "DDR4", "MaximumFrequencyMHz": 2133, "DIMMStatus": "GoodInUse"},
    "/d/2": {"Name": "proc1dimm2", "SizeMB": 0, "DIMMStatus": "NotPresent"},
    "/redfish/v1/Chassis/1/Power/": {"PowerSupplies": [{"Model": "512327-B21", "SerialNumber": "5AQNB0C4D8N0JE",
                                                         "PowerCapacityWatts": 750, "FirmwareVersion": "2.01",
                                                         "Status": {"Health": "OK", "State": "Enabled"}}]},
}


def test_bmc_redfish_parsing_and_attachment():
    import source_bmc
    from model import PveNodeObs
    b = source_bmc.bmc_obs("REDACTED_IP", REDFISH.__getitem__)
    assert (b.mac, b.platform, b.firmware) == ("94:57:a5:b4:70:de", "HPE iLO 4", "2.82")
    assert b.system_macs == ["94:57:a5:b4:70:dc", "94:57:a5:b4:70:dd"]
    assert [(i.role, i.name, i.part_id, i.serial) for i in b.inventory] == \
        [("memory", "proc1dimm1", "DDR4 32 GB", ""), ("psu", "PSU 1", "512327-B21", "5AQNB0C4D8N0JE")]
    c = Collected(pve_nodes=[PveNodeObs("hydrogen", ["REDACTED_IP/24"])], bmcs=[b],
                  arp=[ArpEntry("REDACTED_IP", "94:57:a5:b4:70:dc"), ArpEntry("REDACTED_IP", "94:57:a5:b4:70:de")])
    d = merge(c, "fw")
    hosts = _by_key(d)
    hv = hosts["pve:hydrogen"]
    assert "mac:94:57:a5:b4:70:de" not in hosts                          # the iLO is part of hydrogen now
    assert [i.role for i in hv.inventory["bmc"]] == ["memory", "psu"] and hv.firmware.startswith("BIOS P99")
    assert hv.iface_mac["iLO"] == "94:57:a5:b4:70:de" and hv.iface_spec["iLO"].mgmt_only
    assert hv.ip_iface["REDACTED_IP"] == "iLO" and hv.oob_ip == "REDACTED_IP" and d.absorbed_macs == {"94:57:a5:b4:70:de"}


# --------------------------------------------------------------------- OPNsense NAT / WireGuard

def test_port_forwards_and_wireguard_peers():
    import source_opnsense as so
    fwd = so.port_forwards([
        {"is_automatic": True, "interface": "lan", "target": "", "destination.port": "443"},
        {"disabled": "0", "interface": "wan", "protocol": "tcp/udp", "destination.port": "3478", "target": "REDACTED_IP",
         "descr": "COD BO3"},
        {"disabled": "0", "interface": "wan", "protocol": "tcp", "destination.port": "27017-27019", "target": "REDACTED_IP",
         "descr": "COD BO3"},
        {"disabled": "1", "interface": "wan", "protocol": "tcp", "destination.port": "22", "target": "REDACTED_IP", "descr": "off"},
        {"disabled": "0", "interface": "wan", "protocol": "tcp", "destination.port": "80", "target": "webservers", "descr": "alias"}])
    assert len(fwd) == 1 and fwd[0].target == "REDACTED_IP"
    assert fwd[0].port_mappings == ["tcp/3478", "tcp/27017", "tcp/27018", "tcp/27019", "udp/3478"]
    peers = so.wg_peers(
        [{"name": "phone", "tunneladdress": "REDACTED_IP/32", "%servers": "WG", "enabled": "1", "pubkey": "x", "psk": "y"},
         {"name": "ASHER_CBR", "tunneladdress": "REDACTED_IP/32,REDACTED_IP/24", "%servers": "INTERSITE", "enabled": "1"}],
        [{"type": "peer", "name": "phone", "latest-handshake": 1790978436}], {"WG"})
    assert [(p.name, p.address, p.handshake) for p in peers] == [("phone", "REDACTED_IP", 1790978436)]
    assert not any(hasattr(p, "pubkey") or hasattr(p, "psk") for p in peers)


# --------------------------------------------------------------------- Home Assistant

def _ha():
    import source_homeassistant as ha
    reg = [
        {"id": "plug", "name": "P100", "name_by_user": "Christmas Tree", "manufacturer": "TP-Link", "model": "P100",
         "sw_version": "1.2.5", "area_id": "red", "connections": [["mac", "98:25:4a:60:81:bf"]]},
        {"id": "slzb", "name": "SLZB-06", "manufacturer": "SMLIGHT", "model": "SLZB-06", "configuration_url": "http://REDACTED_IP",
         "connections": [["mac", "c8:2e:18:52:42:64"]]},
        {"id": "blinds", "name": "TS0601", "name_by_user": "Jack Blinds", "manufacturer": "_TZE200", "model": "TS0601",
         "connections": [["zigbee", "04:CD:15:FF:FE:3D:0B:2B"]], "via_device_id": "slzb"},
        {"id": "sensor", "name": "H5101", "name_by_user": "Study Sensor", "manufacturer": "Govee", "model": "H5101",
         "area_id": "study", "connections": [["bluetooth", "A4:C1:38:51:E8:51"]]},
        {"id": "cam1", "name": "Garage", "manufacturer": "Frigate", "configuration_url": "http://REDACTED_IP:5000/cameras/garage"},
        {"id": "cam2", "name": "Front Door", "manufacturer": "Frigate", "configuration_url": "http://REDACTED_IP:5000/cameras/front"},
        {"id": "sw", "name": "28-87-BA-B1-38-69", "manufacturer": "TP-Link", "model": "SG2210P v5.20",
         "connections": [["mac", "28:87:ba:b1:38:69"]]},
        {"id": "svc", "name": "Sun", "entry_type": "service"}]
    return ha.devices(reg, [{"area_id": "red", "name": "Red Room"}, {"area_id": "study", "name": "Study"}])


def test_home_assistant_names_types_rooms_and_radios():
    from model import PveNodeObs  # noqa: F401
    c = Collected(arp=[ArpEntry("REDACTED_IP", "98:25:4a:60:81:bf"), ArpEntry("REDACTED_IP", "c8:2e:18:52:42:67"),
                       ArpEntry("REDACTED_IP", "54:bf:64:91:ec:5e"), ArpEntry("REDACTED_IP", "e4:5f:01:f9:ab:83"),
                       ArpEntry("REDACTED_IP", "28:87:ba:b1:38:69")],
                  leases=[Lease("REDACTED_IP", "98:25:4a:60:81:bf", "P100")], ha_devices=_ha(), ha_host_ip="REDACTED_IP")
    hosts = {h.key: h for h in merge(c, "fw").hosts}
    plug = hosts["mac:98:25:4a:60:81:bf"]
    assert (plug.name, plug.hardware.vendor, plug.hardware.model, plug.firmware, plug.location) == \
        ("Christmas-Tree", "TP-Link", "P100", "1.2.5", "Red Room")
    slzb = hosts["mac:c8:2e:18:52:42:67"]                      # matched by its configuration URL's address
    assert slzb.hardware.model == "SLZB-06" and [i.name for i in slzb.inventory["homeassistant"]] == ["Jack Blinds"]
    assert "ha" not in hosts["mac:54:bf:64:91:ec:5e"].names and "ha-auto" not in hosts["mac:54:bf:64:91:ec:5e"].names
    assert not {"ha", "ha-auto"} & set(hosts["mac:28:87:ba:b1:38:69"].names)   # MAC-shaped HA name ignored
    pi = hosts["mac:e4:5f:01:f9:ab:83"]                        # HA's host: its own Bluetooth devices
    assert [(i.role, i.name, i.serial) for i in pi.inventory["homeassistant"]] == \
        [("bluetooth", "Study Sensor", "a4:c1:38:51:e8:51")]
