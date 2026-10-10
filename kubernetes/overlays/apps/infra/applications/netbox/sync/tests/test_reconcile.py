import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from bootstrap import bootstrap  # noqa: E402
from export import hosts_rows, prefix_rows, routed_via, service_rows  # noqa: E402
from fake_netbox import FakeNetBox  # noqa: E402
from merge import merge  # noqa: E402
from model import (  # noqa: E402
    ArpEntry, Collected, ExtServiceObs, FwInterface, Lease, SvcObs, VipObs, VmIface, VmObs,
)
from reconcile import Reconciler  # noqa: E402

HEALTHY = {"opnsense": True, "proxmox": True, "k8s": True, "ipa": True}


def _world() -> Collected:
    return Collected(
        healthy=dict(HEALTHY),
        fw_interfaces=[FwInterface("vlan0.510", "kubernetes", "00:0d:b9:00:00:01", ["REDACTED_IP/24"], vid=510)],
        vms=[VmObs(130, "k8s-node-1", "pve01", False, "active", 4, 8192, 51200, [],
                   [VmIface("eth0", "bc:24:11:00:00:30", ["REDACTED_IP/24"])])],
        arp=[ArpEntry("REDACTED_IP", "bc:24:11:00:00:30"), ArpEntry("REDACTED_IP", "bc:24:11:00:00:30"),
             ArpEntry("REDACTED_IP", "3c:22:fb:00:00:01"), ArpEntry("REDACTED_IP", "bc:24:11:aa:bb:cc")],
        leases=[Lease("REDACTED_IP", "3c:22:fb:00:00:01", "jacks-mbp")],
        k8s_nodes={"k8s-node-1.k8s.internal": "REDACTED_IP"},
        vips=[VipObs("REDACTED_IP", ["traefik/traefik"],
                     [SvcObs("traefik/traefik websecure", ["tcp/443"], "cctv.0b.au")]),
              VipObs("REDACTED_IP", ["blocky01"], kind="vrrp", name="dns")],
        ext_services=[ExtServiceObs("REDACTED_IP", "frigate", "default/external-service-frigate", ["tcp/8971"])],
        ipa_names={"REDACTED_IP": "ipa01.internal"},
    )


def _netbox() -> FakeNetBox:
    nb = FakeNetBox()
    nb.seed("dcim/sites", {"name": "JACK-CBR", "slug": "jack-cbr"})
    site = nb.list("dcim/sites")[0]["id"]
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "JACK-CBR kubernetes"})
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "JACK-CBR users"})
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "JACK-CBR infra-core"})
    nb.seed("dcim/devices", {"name": "jack-cbr-fw01", "site": site, "status": "active"})
    return nb


def _run(nb, c):
    ctx = bootstrap(nb, "jack-cbr", "pve-jack-cbr", "jack-cbr-fw01")
    nb.writes = {"create": 0, "update": 0, "delete": 0}
    Reconciler(nb, ctx, merge(c, "jack-cbr-fw01")).run()
    return dict(nb.writes)


def _names(nb, path):
    return {o["name"]: o for o in nb.store.get(path, {}).values()}


def test_first_run_builds_inventory_and_second_run_is_noop():
    nb = _netbox()
    first = _run(nb, _world())
    assert first["create"] > 0

    vms = _names(nb, "virtualization/virtual-machines")
    assert vms["k8s-node-1"]["custom_fields"]["host_kind"] == "k8s-node"
    assert {t["slug"] for t in vms["k8s-node-1"]["tags"]} >= {"netbox-sync", "sync-proxmox", "k8s-node"}

    devs = _names(nb, "dcim/devices")
    assert devs["jacks-mbp"]["role"]["slug"] == "client"
    assert devs["frigate"]["custom_fields"]["host_kind"] == "external-service"

    ips = {o["address"]: o for o in nb.store["ipam/ip-addresses"].values()}
    assert ips["REDACTED_IP/24"]["assigned_object_type"] == "dcim.interface"   # mask from the NetBox prefix
    assert ips["REDACTED_IP/24"]["role"] == "vip"
    assert ips["REDACTED_IP/24"]["assigned_object_type"] == "ipam.fhrpgroup"
    assert ips["REDACTED_IP/24"]["dns_name"] == "ipa01.internal"

    assert ips["REDACTED_IP/24"]["role"] == "vrrp"
    groups = {g["name"]: g for g in nb.store["ipam/fhrp-groups"].values()}
    assert groups["vip REDACTED_IP"]["description"] == "dns"
    assert groups["vip REDACTED_IP"]["protocol"]["value"] == "vrrp2"

    svcs = {s["name"]: s for s in nb.store["ipam/services"].values()}
    assert svcs["traefik/traefik websecure"]["port_mappings"] == ["tcp/443"]
    assert svcs["frigate"]["parent_object_type"] == "dcim.device"

    second = _run(nb, _world())
    assert second == {"create": 0, "update": 0, "delete": 0}, second


def test_locked_name_survives_and_stale_client_ages_out():
    nb = _netbox()
    _run(nb, _world())
    dev = _names(nb, "dcim/devices")["jacks-mbp"]
    dev["tags"].append({"slug": "sync-locked"})
    nb.store["dcim/devices"][dev["id"]]["name"] = "Jack laptop"
    nb.store["dcim/devices"][dev["id"]]["tags"] = dev["tags"]
    _run(nb, _world())
    assert "Jack laptop" in _names(nb, "dcim/devices")

    # The laptop disappears: backdate last_seen past the delete threshold.
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    nb.store["dcim/devices"][dev["id"]]["custom_fields"]["last_seen"] = old
    c = _world()
    c.arp = [a for a in c.arp if a.ip != "REDACTED_IP"]
    c.leases = []
    _run(nb, c)
    assert "Jack laptop" not in _names(nb, "dcim/devices")
    assert "REDACTED_IP/24" not in {o["address"] for o in nb.store["ipam/ip-addresses"].values()}


def test_unhealthy_source_never_ages_out():
    nb = _netbox()
    _run(nb, _world())
    dev = _names(nb, "dcim/devices")["jacks-mbp"]
    nb.store["dcim/devices"][dev["id"]]["custom_fields"]["last_seen"] = \
        (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    c = _world()
    c.arp, c.leases, c.healthy["opnsense"] = [], [], False
    _run(nb, c)
    assert _names(nb, "dcim/devices")["jacks-mbp"]["status"]["value"] == "active"


def test_export_rows():
    nb = _netbox()
    _run(nb, _world())
    # FakeNetBox doesn't nest assigned_object; emulate the fields export reads.
    for ip in nb.store["ipam/ip-addresses"].values():
        t, i = ip.get("assigned_object_type"), ip.get("assigned_object_id")
        if t == "dcim.interface":
            ifc = nb.store["dcim/interfaces"][i]
            ip["assigned_object"] = {"id": i, "device": ifc["device"]}
        elif t == "virtualization.vminterface":
            ifc = nb.store["virtualization/interfaces"][i]
            ip["assigned_object"] = {"id": i, "virtual_machine": ifc["virtual_machine"]}
        elif t == "ipam.fhrpgroup":
            ip["assigned_object"] = {"id": i}
    rows = {r["ip"]: r for r in hosts_rows(nb)}
    assert rows["REDACTED_IP"]["name"] == "k8s-node-1" and rows["REDACTED_IP"]["kind"] == "k8s-node"
    assert rows["REDACTED_IP"]["kind"] == "k8s-vip" and rows["REDACTED_IP"]["name"] == "traefik/traefik"
    assert rows["REDACTED_IP"]["name"] == "frigate"
    assert rows["REDACTED_IP"]["kind"] == "dns-only" and rows["REDACTED_IP"]["name"] == "ipa01"
    assert rows["REDACTED_IP"]["kind"] == "vip" and rows["REDACTED_IP"]["name"] == "dns"
    svc = {(r["ip"], r["port"]): r for r in service_rows(nb)}
    assert svc[("REDACTED_IP", 443)]["proto"] == "TCP"


def test_prefix_via_is_the_interface_a_route_goes_out_of():
    nb = FakeNetBox()
    for p, desc in (("REDACTED_IP/24", "JACK-CBR users"), ("REDACTED_IP/24", "WireGuard overlay, all sites"),
                    ("REDACTED_IP/32", "Asher MEL, its inter-site WireGuard overlay address"),
                    ("REDACTED_IP/24", "Asher CBR, reached over the inter-site WireGuard"),
                    ("REDACTED_IP/16", "Asher MEL, reached over the inter-site WireGuard")):
        nb.seed("ipam/prefixes", {"prefix": p, "description": desc})
    fw = [FwInterface("vlan0.010", "Users", None, ["REDACTED_IP/24"], routes=["REDACTED_IP/24"]),
          FwInterface("wg1", "INTER_WG_TO_CBR", None, ["REDACTED_IP/24"],
                      routes=["REDACTED_IP/24", "REDACTED_IP/24", "REDACTED_IP/16", "REDACTED_IP/22"])]
    rows = {r["prefix"]: r for r in prefix_rows(nb, routed_via(fw))}
    # A LAN's connected subnet has no via; everything on a tunnel does, its own subnet included
    assert rows["REDACTED_IP/24"]["via"] == "" and rows["REDACTED_IP/24"]["via"] == "INTER_WG_TO_CBR (wg1)"
    assert rows["REDACTED_IP/24"]["via"] == "INTER_WG_TO_CBR (wg1)"
    assert rows["REDACTED_IP/16"]["via"] == "INTER_WG_TO_CBR (wg1)"
    assert rows["REDACTED_IP/24"]["segment"] == "Asher CBR"
    assert rows["REDACTED_IP/32"]["via"] == "INTER_WG_TO_CBR (wg1)" and rows["REDACTED_IP/32"]["segment"] == "Asher MEL"
    assert {r["via"] for r in prefix_rows(nb)} == {""}


def test_duplicate_vip_groups_from_a_race_are_removed():
    nb = _netbox()
    _run(nb, _world())
    # Simulate a second concurrent run having created the same VIP again
    g = next(g for g in nb.store["ipam/fhrp-groups"].values() if g["name"] == "k8s-lb REDACTED_IP")
    dup = nb.seed("ipam/fhrp-groups", {"name": g["name"], "protocol": "other", "group_id": g["group_id"],
                                       "description": g["description"]})
    dup["tags"] = [{"slug": "netbox-sync"}]
    ipdup = nb.seed("ipam/ip-addresses", {"address": "REDACTED_IP/24", "status": "active", "role": "vip",
                                          "assigned_object_type": "ipam.fhrpgroup", "assigned_object_id": dup["id"]})
    ipdup["tags"] = [{"slug": "netbox-sync"}]
    _run(nb, _world())
    assert [x["name"] for x in nb.store["ipam/fhrp-groups"].values()].count("k8s-lb REDACTED_IP") == 1
    assert [x["address"] for x in nb.store["ipam/ip-addresses"].values()].count("REDACTED_IP/24") == 1
    assert _run(nb, _world()) == {"create": 0, "update": 0, "delete": 0}


def test_failed_source_does_not_rename_or_untag():
    from model import OmadaClient
    nb = _netbox()
    c = _world()
    c.leases = [Lease("REDACTED_IP", "3c:22:fb:00:00:01", "")]   # no DHCP hostname, so Omada names it
    c.omada_clients = [OmadaClient(mac="3c:22:fb:00:00:01", ip="REDACTED_IP", name="Jack laptop",
                                   hostname="", connection="switch x port 1")]
    c.healthy["omada"] = True
    _run(nb, c)
    assert "Jack laptop" in _names(nb, "dcim/devices")
    # Omada times out next run: the name must survive, and the source tag stay
    c2 = _world()
    c2.leases = list(c.leases)
    c2.healthy["omada"] = False
    _run(nb, c2)
    dev = _names(nb, "dcim/devices").get("Jack laptop")
    assert dev is not None
    assert "sync-omada" in {t["slug"] for t in dev["tags"]}


def test_hypervisor_keeps_real_name_when_a_mac_duplicate_cant_be_tied_back():
    """A hypervisor Host never carries its own MAC (merge.py only learns one for it
    opportunistically, from ARP/DHCP/Omada matching its IP). When that match misses for a
    run -- here, ARP reports the same MAC against a different, unrecognised IP -- it
    surfaces as a second, name-less Host that still resolves to the same NetBox device by
    MAC. Its generated placeholder name must not clobber the device's real name."""
    from model import PveNodeObs
    nb = _netbox()
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "JACK-CBR legacy-services"})
    MAC = "94:57:a5:b4:70:dc"

    c = Collected(healthy=dict(HEALTHY), pve_nodes=[PveNodeObs("hydrogen", ["REDACTED_IP/24"])],
                 arp=[ArpEntry("REDACTED_IP", MAC)])
    _run(nb, c)
    assert "hydrogen" in _names(nb, "dcim/devices")

    c2 = Collected(healthy=dict(HEALTHY), pve_nodes=[PveNodeObs("hydrogen", ["REDACTED_IP/24"])],
                  arp=[ArpEntry("REDACTED_IP", MAC)])
    _run(nb, c2)
    names = _names(nb, "dcim/devices")
    assert "hydrogen" in names
    assert not any(n.startswith("client-") for n in names)


# --------------------------------------------------------------------- links (Omada)

SW, AP, LAPTOP, PHONE = "9c:a2:f4:b1:ba:f8", "9c:a2:f4:3b:1a:be", "3c:22:fb:00:00:01", "0a:ef:8e:5a:e1:44"


def _omada_world(laptop_port=16, phone_wifi=True):
    from model import OmadaClient, OmadaDevice, SwitchPort
    c = _world()
    c.healthy["omada"] = True
    c.arp += [ArpEntry("REDACTED_IP", SW), ArpEntry("REDACTED_IP", AP), ArpEntry("REDACTED_IP", PHONE)]
    c.leases.append(Lease("REDACTED_IP", PHONE, "Pixel-9"))
    c.omada_devices = [
        OmadaDevice(SW, "REDACTED_IP", "", "SG3428 v2.30", "switch",
                    ports=[SwitchPort(n, "Router Uplink" if n == 1 else f"Port{n}", "Users") for n in range(1, 25)]),
        OmadaDevice(AP, "REDACTED_IP", "Lounge Room AP", "EAP615-Wall(US) v1.0", "ap", uplink_mac=SW)]
    c.omada_clients = [OmadaClient(LAPTOP, "REDACTED_IP", "", "", "", uplink_mac=SW, port=laptop_port, vid=10)]
    if phone_wifi:
        c.omada_clients.append(OmadaClient(PHONE, "REDACTED_IP", "", "Pixel-9", "", uplink_mac=AP, ssid="Home",
                                           radio=1, wifi_mode=7, vid=10))
    else:
        c.omada_clients.append(OmadaClient(PHONE, "REDACTED_IP", "", "Pixel-9", "", uplink_mac=SW, port=5, vid=10))
    return c


def _ifaces(nb, device):
    return {i["name"]: i for i in nb.store["dcim/interfaces"].values() if i["device"]["name"] == device}


def _cable_ends(nb):
    ifs = nb.store["dcim/interfaces"]
    return {tuple(sorted(f"{ifs[t['object_id']]['device']['name']}/{ifs[t['object_id']]['name']}"
                         for t in c["a_terminations"] + c["b_terminations"]))
            for c in nb.store.get("dcim/cables", {}).values()}


def test_wired_client_gets_a_cable_and_wifi_client_joins_the_ssid():
    nb = _netbox()
    nb.seed("ipam/vlans", {"vid": 10, "name": "users"})
    _run(nb, _omada_world())
    sw = _ifaces(nb, "SG3428-b1baf8")
    assert sw["1/0/1"]["label"] == "Router Uplink" and sw["1/0/2"]["label"] == ""
    assert _cable_ends(nb) == {("SG3428-b1baf8/1/0/16", "jacks-mbp/eth0")}

    wlan = next(iter(nb.store["wireless/wireless-lans"].values()))
    assert wlan["ssid"] == "Home" and wlan["vlan"]["id"] == nb.list("ipam/vlans")[0]["id"]
    phone = _ifaces(nb, "Pixel-9")["wlan0"]
    assert phone["type"]["value"] == "ieee802.11ax" and phone["rf_role"]["value"] == "station"
    assert [w["id"] for w in phone["wireless_lans"]] == [wlan["id"]]
    assert phone["description"] == "Lounge-Room-AP 5 GHz"
    radios = _ifaces(nb, "Lounge-Room-AP")
    assert set(radios) >= {"radio0", "radio1"} and "radio2" not in radios
    assert [w["id"] for w in radios["radio1"]["wireless_lans"]] == [wlan["id"]]

    devs = _names(nb, "dcim/devices")
    assert devs["jacks-mbp"]["custom_fields"]["connection"] == "switch SG3428-b1baf8 port 16"
    assert devs["Pixel-9"]["custom_fields"]["connection"] == "wifi Home @ Lounge-Room-AP 5 GHz"
    assert devs["Lounge-Room-AP"]["custom_fields"]["connection"] == "switch SG3428-b1baf8"

    assert _run(nb, _omada_world()) == {"create": 0, "update": 0, "delete": 0}


def test_cable_follows_a_move_and_wifi_to_wired_converts_the_interface():
    nb = _netbox()
    _run(nb, _omada_world())
    _run(nb, _omada_world(laptop_port=7, phone_wifi=False))
    assert _cable_ends(nb) == {("SG3428-b1baf8/1/0/7", "jacks-mbp/eth0"), ("Pixel-9/eth0", "SG3428-b1baf8/1/0/5")}
    phone = _ifaces(nb, "Pixel-9")
    assert set(phone) == {"eth0"} and phone["eth0"]["type"]["value"] == "other" and not phone["eth0"]["wireless_lans"]
    assert _run(nb, _omada_world(laptop_port=7, phone_wifi=False)) == {"create": 0, "update": 0, "delete": 0}


def test_hand_made_cable_is_left_alone():
    nb = _netbox()
    _run(nb, _omada_world())
    cable = next(iter(nb.store["dcim/cables"].values()))
    cable["tags"] = []                                  # someone re-drew it by hand
    _run(nb, _omada_world(laptop_port=7))
    assert _cable_ends(nb) == {("SG3428-b1baf8/1/0/16", "jacks-mbp/eth0")}


def test_shared_port_gets_no_cable():
    from model import OmadaClient
    nb = _netbox()
    c = _omada_world()
    c.omada_clients.append(OmadaClient("3c:22:fb:00:00:99", "REDACTED_IP", "", "", "", uplink_mac=SW, port=16))
    c.arp.append(ArpEntry("REDACTED_IP", "3c:22:fb:00:00:99"))
    _run(nb, c)
    assert _cable_ends(nb) == set()


# --------------------------------------------------------------------- enrichment

def _rich_world():
    from model import DhcpRange, FlowService, PveNodeObs, StaticName
    c = _world()
    c.pve_nodes = [PveNodeObs("pve01", ["REDACTED_IP/24"], version="9.2.2")]
    c.vms[0].os = "Debian GNU/Linux 13 (trixie)"
    c.dhcp_ranges = [DhcpRange("REDACTED_IP", "REDACTED_IP", "Users")]
    c.static_names.append(StaticName("REDACTED_IP", "printer", mac="3c:22:fb:00:00:50"))
    c.arp.append(ArpEntry("REDACTED_IP", "3c:22:fb:00:00:50"))
    c.flow_services = [FlowService("REDACTED_IP", "tcp", 8006, "proxmox", 4),
                       FlowService("REDACTED_IP", "tcp", 53, "domain", 3),            # dns-only IP: no parent
                       FlowService("REDACTED_IP", "tcp", 8971, "frigate", 3),        # k8s ext service covers it
                       FlowService("REDACTED_IP", "tcp", 22, "ssh", 2),
                       FlowService("REDACTED_IP", "udp", 53, "domain", 2),
                       FlowService("REDACTED_IP", "tcp", 53, "domain", 2)]
    return c


def test_platforms_vm_placement_dhcp_and_flow_services():
    nb = _netbox()
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "JACK-CBR legacy-services"})
    _run(nb, _rich_world())

    devs, vms = _names(nb, "dcim/devices"), _names(nb, "virtualization/virtual-machines")
    plats = {p["id"]: p["name"] for p in nb.store["dcim/platforms"].values()}
    assert plats[devs["pve01"]["platform"]["id"]] == "Proxmox VE 9.2"
    assert plats[vms["k8s-node-1"]["platform"]["id"]] == "Debian 13"
    assert vms["k8s-node-1"]["device"]["id"] == devs["pve01"]["id"]
    assert devs["pve01"]["cluster"]["id"] == vms["k8s-node-1"]["cluster"]["id"]

    rng = next(iter(nb.store["ipam/ip-ranges"].values()))
    assert (rng["start_address"], rng["end_address"], rng["description"]) == \
        ("REDACTED_IP/24", "REDACTED_IP/24", "DHCP pool, Users")
    ips = {o["address"]: o for o in nb.store["ipam/ip-addresses"].values()}
    assert ips["REDACTED_IP/24"]["status"]["value"] == "dhcp"      # in the pool, no reservation
    assert ips["REDACTED_IP/24"]["status"]["value"] == "active"    # static host
    assert ips["REDACTED_IP/24"]["status"]["value"] == "active"   # outside any pool

    svcs = {(s["name"], s["parent_object_id"]): s for s in nb.store["ipam/services"].values()}
    frigate = devs["frigate"]["id"]
    assert svcs[("proxmox", devs["pve01"]["id"])]["port_mappings"] == ["tcp/8006"]
    assert svcs[("domain", frigate)]["port_mappings"] == ["tcp/53", "udp/53"]
    assert ("ssh", frigate) in svcs and ("frigate", frigate) in svcs
    assert [s["name"] for s in nb.store["ipam/services"].values()].count("frigate") == 1   # k8s one only
    assert not any(s["name"] == "domain" and s["parent_object_id"] != frigate for s in nb.store["ipam/services"].values())

    assert _run(nb, _rich_world()) == {"create": 0, "update": 0, "delete": 0}

    # Hourly refresh skipped: flow services stay. Refreshed without ssh: it goes.
    c = _rich_world(); c.flow_services = None
    _run(nb, c)
    assert any(s["name"] == "ssh" for s in nb.store["ipam/services"].values())
    c = _rich_world(); c.flow_services = [f for f in c.flow_services if f.port != 22]
    _run(nb, c)
    assert not any(s["name"] == "ssh" for s in nb.store["ipam/services"].values())
    assert any(s["name"] == "traefik/traefik websecure" for s in nb.store["ipam/services"].values())


def test_dhcp_pool_overlapping_a_terraform_range_is_skipped_and_status_kept_when_opnsense_down():
    nb = _netbox()
    nb.seed("ipam/ip-ranges", {"start_address": "REDACTED_IP/24", "end_address": "REDACTED_IP/24",
                               "description": "terraform"})
    _run(nb, _rich_world())
    assert [r["description"] for r in nb.store["ipam/ip-ranges"].values()] == ["terraform"]
    ip = next(o for o in nb.store["ipam/ip-addresses"].values() if o["address"] == "REDACTED_IP/24")
    assert ip["status"]["value"] == "dhcp"
    c = _rich_world(); c.healthy["opnsense"] = False; c.dhcp_ranges = []
    _run(nb, c)
    assert nb.store["ipam/ip-addresses"][ip["id"]]["status"]["value"] == "dhcp"


def test_switch_port_vlans_and_access_client():
    from model import SwitchPort
    nb = _netbox()
    users = nb.seed("ipam/vlans", {"vid": 10, "name": "users"})
    k8s = nb.seed("ipam/vlans", {"vid": 510, "name": "kubernetes"})
    c = _omada_world()
    sw = c.omada_devices[0]
    sw.ports = [SwitchPort(1, "Router Uplink", "All", untagged=1, tagged=[10, 510], tagged_all=True),
                SwitchPort(2, "Port2", "Trunk", untagged=10, tagged=[510]),
                SwitchPort(3, "Port3", "Disable"),
                *[SwitchPort(n, f"Port{n}", "Users", untagged=10) for n in range(4, 25)]]
    serial_sw = c.omada_devices[0]; serial_sw.serial, serial_sw.firmware = "2229045000037", "2.30.7"
    _run(nb, c)
    p = _ifaces(nb, "SG3428-b1baf8")
    assert p["1/0/1"]["mode"]["value"] == "tagged-all" and p["1/0/1"]["untagged_vlan"] is None
    assert p["1/0/2"]["mode"]["value"] == "tagged" and p["1/0/2"]["untagged_vlan"]["id"] == users["id"]
    assert [v["id"] for v in p["1/0/2"]["tagged_vlans"]] == [k8s["id"]]
    assert not p["1/0/3"]["mode"] and p["1/0/3"]["enabled"] is False
    assert p["1/0/16"]["mode"]["value"] == "access" and p["1/0/16"]["untagged_vlan"]["id"] == users["id"]
    laptop = _ifaces(nb, "jacks-mbp")["eth0"]
    assert laptop["mode"]["value"] == "access" and laptop["untagged_vlan"]["id"] == users["id"]
    dev = _names(nb, "dcim/devices")["SG3428-b1baf8"]
    assert dev["serial"] == "2229045000037" and dev["custom_fields"]["firmware"] == "2.30.7"
    dtype = nb.store["dcim/device-types"][dev["device_type"]["id"]]
    assert dtype["model"] == "SG3428" and dtype["part_number"] == "SG3428 v2.30"
    assert _run(nb, c) == {"create": 0, "update": 0, "delete": 0}


# --------------------------------------------------------------------- native links (interfaces, VIPs, tenancy)

PVE_MAC, NODE2_MAC = "58:47:ca:00:00:02", "58:47:ca:00:00:31"


def _linked_world(holder="blocky01", pve_tags=("prod",)):
    import source_proxmox as sp
    from model import DhcpRange, OmadaClient, PveNodeObs, VlanObs, VmDisk
    c = _omada_world()
    c.fw_interfaces = [FwInterface("vlan0.510", "kubernetes", "00:0d:b9:00:00:01", ["REDACTED_IP/24"], vid=510,
                                   parent="ix1")]
    c.vlans = [VlanObs(510, "kubernetes"), VlanObs(110, "infra_core"), VlanObs(30, "iot")]
    c.pve_nodes = [PveNodeObs("pve01", ["REDACTED_IP/24"], ifaces=sp._node_ifaces([
        {"iface": "enp1s0", "type": "eth"}, {"iface": "enp2s0", "type": "eth"},
        {"iface": "bond0", "type": "bond", "slaves": "enp1s0 enp2s0"},
        {"iface": "vmbr0", "type": "bridge", "bridge_ports": "bond0", "cidr": "REDACTED_IP/24"},
        {"iface": "vmbr0.110", "type": "vlan"}]))]
    c.arp.append(ArpEntry("REDACTED_IP", PVE_MAC))
    c.omada_clients.append(OmadaClient(PVE_MAC, "REDACTED_IP", "", "", "", uplink_mac=SW, port=3))
    node = c.vms[0]
    node.ifaces[0].vid, node.tags, node.node = 510, list(pve_tags), "pve01"
    node.disks = [VmDisk("scsi0", 51200, "local-lvm"), VmDisk("scsi1", 1024, "local-lvm")]
    blockies = [VmObs(104 + n, f"blocky0{n}", "pve01", False, "active", 1, 1024, None, [],
                      [VmIface("eth0", f"bc:24:11:e0:48:4{n}", [f"REDACTED_IP{n + 1}/24"], vid=110)])
                for n in (1, 2)]
    c.vms += blockies
    c.vips = [v for v in c.vips if v.kind == "k8s"] + [
        VipObs("REDACTED_IP", [holder], kind="vrrp", name="dns", holders=[(holder, "eth0")])]
    c.k8s_nodes["k8s-node-2"] = "REDACTED_IP"                         # a physical node
    c.arp.append(ArpEntry("REDACTED_IP", NODE2_MAC))
    c.dhcp_ranges = [DhcpRange("REDACTED_IP", "REDACTED_IP", "Users")]
    return c


def _linked_netbox():
    nb = _netbox()
    tenant = nb.seed("tenancy/tenants", {"name": "jack", "slug": "jack"})
    site = nb.store["dcim/sites"][nb.list("dcim/sites")[0]["id"]]
    site["tenant"] = {"id": tenant["id"]}
    group = nb.seed("ipam/vlan-groups", {"name": "JACK-CBR", "slug": "jack-cbr"})
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "JACK-CBR legacy-services"})
    nb.seed("ipam/vlans", {"vid": 10, "name": "users", "site": site["id"]})
    return nb, tenant["id"], group["id"]


def test_interfaces_vips_disks_and_tenancy_use_native_links():
    nb, tenant, group = _linked_netbox()
    _run(nb, _linked_world())
    vlans = {v["vid"]: v for v in nb.store["ipam/vlans"].values()}
    assert vlans[510]["group"]["id"] == group and vlans[510]["tenant"]["id"] == tenant
    assert "group" not in vlans[10] or not vlans[10].get("group")     # not ours: left alone

    pve = _ifaces(nb, "pve01")
    assert pve["bond0"]["type"]["value"] == "lag" and pve["vmbr0"]["type"]["value"] == "bridge"
    assert pve["enp1s0"]["lag"]["id"] == pve["bond0"]["id"] and pve["bond0"]["bridge"]["id"] == pve["vmbr0"]["id"]
    assert pve["vmbr0.110"]["parent"]["id"] == pve["vmbr0"]["id"]
    assert pve["vmbr0.110"]["mode"]["value"] == "access" and pve["vmbr0.110"]["untagged_vlan"]["id"] == vlans[110]["id"]
    assert ("SG3428-b1baf8/1/0/3", "pve01/enp1s0") in _cable_ends(nb)   # the NIC under the bridge, not vmbr0

    fw = _ifaces(nb, "jack-cbr-fw01")
    assert fw["vlan0.510"]["parent"]["id"] == fw["ix1"]["id"] and fw["vlan0.510"]["type"]["value"] == "virtual"
    assert [v["id"] for v in fw["ix1"]["tagged_vlans"]] == [vlans[510]["id"]]

    vms = _names(nb, "virtualization/virtual-machines")
    node_if = next(i for i in nb.store["virtualization/interfaces"].values()
                   if i["virtual_machine"]["id"] == vms["k8s-node-1"]["id"])
    assert node_if["mode"]["value"] == "access" and node_if["untagged_vlan"]["id"] == vlans[510]["id"]
    assert "pve-prod" in {t["slug"] for t in vms["k8s-node-1"]["tags"]}
    assert vms["k8s-node-1"]["tenant"]["id"] == tenant
    assert not vms["k8s-node-1"].get("disk")                          # NetBox sums the virtual disks
    disks = {d["name"]: d["size"] for d in nb.store["virtualization/virtual-disks"].values()}
    assert disks == {"scsi0": 51200, "scsi1": 1024}

    group_ = next(g for g in nb.store["ipam/fhrp-groups"].values() if g["name"] == "vip REDACTED_IP")
    assigned = [(a["interface_type"], a["interface_id"]) for a in nb.store["ipam/fhrp-group-assignments"].values()
                if a["group"]["id"] == group_["id"]]
    blocky01_if = next(i["id"] for i in nb.store["virtualization/interfaces"].values()
                       if i["virtual_machine"]["id"] == vms["blocky01"]["id"])
    assert assigned == [("virtualization.vminterface", blocky01_if)]

    devs = _names(nb, "dcim/devices")
    k8s_cluster = next(c for c in nb.store["virtualization/clusters"].values() if c["name"] == "k8s-jack-cbr")
    assert devs["k8s-node-2"]["cluster"]["id"] == k8s_cluster["id"]
    assert devs["pve01"]["cluster"]["id"] != k8s_cluster["id"]
    assert devs["jacks-mbp"]["tenant"]["id"] == tenant
    rng = next(iter(nb.store["ipam/ip-ranges"].values()))
    assert rng["mark_populated"] is True and rng["tenant"]["id"] == tenant
    assert all(ip["tenant"]["id"] == tenant for ip in nb.store["ipam/ip-addresses"].values())

    assert _run(nb, _linked_world()) == {"create": 0, "update": 0, "delete": 0}

    # keepalived fails over, a Proxmox tag and a disk go away
    c = _linked_world(holder="blocky02", pve_tags=())
    c.vms[0].disks = c.vms[0].disks[:1]
    _run(nb, c)
    blocky02_if = next(i["id"] for i in nb.store["virtualization/interfaces"].values()
                       if i["virtual_machine"]["id"] == vms["blocky02"]["id"])
    assert [a["interface_id"] for a in nb.store["ipam/fhrp-group-assignments"].values()] == [blocky02_if]
    assert "pve-prod" not in {t["slug"] for t in _names(nb, "virtualization/virtual-machines")["k8s-node-1"]["tags"]}
    assert {d["name"] for d in nb.store["virtualization/virtual-disks"].values()} == {"scsi0"}


def test_cabled_interface_becoming_a_bridge_moves_the_cable_to_its_nic():
    """Before the hypervisor's NICs were known, its MAC (and Omada cable) sat on a plain vmbr0."""
    nb, _, _ = _linked_netbox()
    c = _linked_world()
    node = c.pve_nodes[0]
    plain = type(node)(node.name, node.cidrs)                       # old style: no interface list
    c.pve_nodes = [plain]
    _run(nb, c)
    assert ("SG3428-b1baf8/1/0/3", "pve01/vmbr0") in _cable_ends(nb)
    _run(nb, _linked_world())
    ends = _cable_ends(nb)
    assert ("SG3428-b1baf8/1/0/3", "pve01/enp1s0") in ends and ("SG3428-b1baf8/1/0/3", "pve01/vmbr0") not in ends
    assert _ifaces(nb, "pve01")["vmbr0"]["type"]["value"] == "bridge"
    assert _run(nb, _linked_world()) == {"create": 0, "update": 0, "delete": 0}


def test_firewall_mac_moves_to_the_trunk_once_its_parent_is_known():
    nb, _, _ = _linked_netbox()
    c = _linked_world()
    c.fw_interfaces[0].parent = ""                                   # before OPNsense's VLAN parent was read
    _run(nb, c)
    assert _ifaces(nb, "jack-cbr-fw01")["vlan0.510"]["primary_mac_address"]
    _run(nb, _linked_world())
    fw = _ifaces(nb, "jack-cbr-fw01")
    mac = next(m for m in nb.store["dcim/mac-addresses"].values() if m["mac_address"] == "00:0d:b9:00:00:01")
    assert mac["assigned_object_id"] == fw["ix1"]["id"] and fw["ix1"]["primary_mac_address"]["id"] == mac["id"]
    assert not fw["vlan0.510"]["primary_mac_address"]
    assert _run(nb, _linked_world()) == {"create": 0, "update": 0, "delete": 0}


def test_unreadable_vm_config_keeps_its_disks():
    nb, _, _ = _linked_netbox()
    _run(nb, _linked_world())
    c = _linked_world()
    c.vms[0].disks = []                                              # config GET failed this run
    assert _run(nb, c) == {"create": 0, "update": 0, "delete": 0}
    assert len(nb.store["virtualization/virtual-disks"]) == 2


def test_unsluggable_proxmox_tag_is_skipped():
    nb, _, _ = _linked_netbox()
    _run(nb, _linked_world(pve_tags=("prod", "🔐")))
    assert "pve-" not in {t["slug"] for t in nb.store["extras/tags"].values()}
    vm = _names(nb, "virtualization/virtual-machines")["k8s-node-1"]
    assert {t["slug"] for t in vm["tags"] if t["slug"].startswith("pve-")} == {"pve-prod"}


# --------------------------------------------------------------------- switch-to-switch links and link speed

EDGE, KVM = "28:87:ba:b1:38:69", "44:b7:d0:e6:b7:f1"


def _wired_world(kvm_speed=100, web=True):
    from model import OmadaClient, OmadaDevice, SwitchPort
    c = _omada_world()
    core, ap = c.omada_devices
    core.ports.append(SwitchPort(25, "Port25", "All"))
    edge = OmadaDevice(EDGE, "REDACTED_IP", "", "SG2210P v5.20", "switch",
                       ports=[SwitchPort(n, "Uplink" if n == 8 else f"Port{n}", "All") for n in range(1, 9)],
                       uplink_mac=SW, uplink_port=3, local_port=8)
    ap.uplink_mac, ap.uplink_port = EDGE, 1
    c.omada_devices.append(edge)
    c.arp += [ArpEntry("REDACTED_IP", EDGE), ArpEntry("REDACTED_IP", KVM)]
    c.omada_clients.append(OmadaClient(KVM, "REDACTED_IP", "", "", "", uplink_mac=SW, port=14))
    if web:
        for sw in (core, edge):
            for p in sw.ports:
                p.type = "1000base-x-sfp" if p.num == 25 else "1000base-t"
                p.up, p.speed_mbps, p.duplex = (p.num != 25), (1000 if p.num != 25 else None), \
                    ("full" if p.num != 25 else "")
        kvm_port = next(p for p in core.ports if p.num == 14)
        kvm_port.speed_mbps = kvm_speed
    return c


def test_switch_uplinks_and_ap_get_cables_and_ports_carry_link_speed():
    nb = _netbox()
    _run(nb, _wired_world())
    ends = _cable_ends(nb)
    assert ("SG2210P-b13869/1/0/8", "SG3428-b1baf8/1/0/3") in ends            # switch to switch, port to port
    assert ("Lounge-Room-AP/eth0", "SG2210P-b13869/1/0/1") in ends            # AP on its real port
    assert not any("SG2210P-b13869/eth0" in e for e in ends)                  # not the switch's management iface

    core = _ifaces(nb, "SG3428-b1baf8")
    assert core["1/0/14"]["type"]["value"] == "1000base-t" and core["1/0/14"]["speed"] == 100000
    assert core["1/0/14"]["duplex"]["value"] == "full"
    assert core["1/0/25"]["type"]["value"] == "1000base-x-sfp" and core["1/0/25"]["speed"] is None
    kvm = next(d for d in _names(nb, "dcim/devices") if d.startswith("client-"))
    kvm_if = _ifaces(nb, kvm)["eth0"]
    assert kvm_if["speed"] == 100000 and kvm_if["duplex"]["value"] == "full"   # its end of the 100M link
    assert _ifaces(nb, "jacks-mbp")["eth0"]["speed"] == 1000000
    devs = _names(nb, "dcim/devices")
    assert devs["SG2210P-b13869"]["custom_fields"]["connection"] == "switch SG3428-b1baf8 port 3"
    assert _run(nb, _wired_world()) == {"create": 0, "update": 0, "delete": 0}

    # renegotiates at gigabit: both ends follow
    _run(nb, _wired_world(kvm_speed=1000))
    assert _ifaces(nb, "SG3428-b1baf8")["1/0/14"]["speed"] == 1000000 and _ifaces(nb, kvm)["eth0"]["speed"] == 1000000

    # web API down this run: speeds and SFP type stay as they were, cables too
    assert _run(nb, _wired_world(kvm_speed=1000, web=False)) == {"create": 0, "update": 0, "delete": 0}


def test_device_behind_an_ap_lan_port_leaves_the_cable_to_the_ap():
    from model import OmadaClient
    nb = _netbox()
    c = _wired_world()
    c.arp.append(ArpEntry("REDACTED_IP", "98:41:5c:c3:f8:03"))        # plugged into the AP's wall-plate port
    c.omada_clients.append(OmadaClient("98:41:5c:c3:f8:03", "REDACTED_IP", "", "", "switch x port 1",
                                       uplink_mac=EDGE, port=1))
    _run(nb, c)
    ends = _cable_ends(nb)
    assert ("Lounge-Room-AP/eth0", "SG2210P-b13869/1/0/1") in ends
    assert not any("client-c3f803" in e for end in ends for e in end)


ILO = "94:57:a5:b4:70:de"


def _hydrogen_world():
    """hydrogen: eno1 under vmbr0 (its address) on port 17, eno2 under vmbr1 (VMs only) on port 22,
    and its iLO on port 21, which Omada sees by MAC only."""
    import source_proxmox as sp
    from model import OmadaClient, PveNodeObs
    c = _wired_world()
    c.pve_nodes = [PveNodeObs("pve01", ["REDACTED_IP/24"], ifaces=sp._node_ifaces([
        {"iface": "eno1", "type": "eth"}, {"iface": "eno2", "type": "eth"},
        {"iface": "vmbr0", "type": "bridge", "bridge_ports": "eno1", "cidr": "REDACTED_IP/24"},
        {"iface": "vmbr1", "type": "bridge", "bridge_ports": "eno2"}]))]
    c.arp.append(ArpEntry("REDACTED_IP", PVE_MAC))
    c.omada_clients.append(OmadaClient(PVE_MAC, "REDACTED_IP", "", "", "", uplink_mac=SW, port=17))
    c.vms[0].node = "pve01"
    c.vms[0].ifaces[0].bridge = "vmbr1"
    c.vms.append(VmObs(104, "blocky01", "pve01", False, "active", 1, 1024, None, [],
                       [VmIface("eth0", "bc:24:11:e0:48:46", ["REDACTED_IP/24"], bridge="vmbr1")]))
    for vm in c.vms:
        c.omada_clients.append(OmadaClient(vm.ifaces[0].mac, vm.ifaces[0].cidrs[0].split("/")[0], "", "", "",
                                           uplink_mac=SW, port=22))
    c.omada_clients.append(OmadaClient(ILO, "", "", "", "", uplink_mac=SW, port=21))   # no IP
    return c


def test_vm_only_port_is_the_bridge_uplink_and_a_mac_only_ilo_stays_cabled():
    nb = _netbox()
    _run(nb, _hydrogen_world())
    ends = _cable_ends(nb)
    assert ("SG3428-b1baf8/1/0/17", "pve01/eno1") in ends
    assert ("SG3428-b1baf8/1/0/22", "pve01/eno2") in ends                  # vmbr1's uplink, from its VMs
    ilo = "client-b470de"                                                  # named from its MAC tail
    assert ("SG3428-b1baf8/1/0/21", f"{ilo}/eth0") in ends
    assert _names(nb, "dcim/devices")[ilo]["custom_fields"]["last_seen"]     # present: won't age out
    assert _run(nb, _hydrogen_world()) == {"create": 0, "update": 0, "delete": 0}


def test_port_shared_by_vms_and_their_hypervisor_gets_no_extra_cable():
    c = _hydrogen_world()
    c.vms[1].ifaces[0].bridge = "vmbr0"
    c.omada_clients[-2].port = 17                                          # blocky01 on vmbr0, seen on 17
    from merge import merge
    hv = next(h for h in merge(c, "fw").hosts if h.key == "pve:pve01")
    assert sorted((ln.port, ln.iface) for ln in hv.links) == [(17, ""), (22, "vmbr1")]


def test_hardware_sets_device_type_serial_and_renames_the_guessed_nic():
    from model import HardwareObs, LbPool
    nb = _netbox()
    c = _wired_world()
    _run(nb, c)                                                     # jacks-mbp: guessed eth0, cabled to port 16
    c.hardware = [HardwareObs("jacks-mbp", "Dell", "OptiPlex 7060", "085A", "FKDCBS2", {"eno2": LAPTOP})]
    c.lb_pools = [LbPool("infranet", "REDACTED_IP", "REDACTED_IP")]
    _run(nb, c)
    dev = _names(nb, "dcim/devices")["jacks-mbp"]
    dtype = nb.store["dcim/device-types"][dev["device_type"]["id"]]
    assert (dtype["model"], dtype["part_number"], dev["serial"]) == ("OptiPlex 7060", "085A", "FKDCBS2")
    assert nb.store["dcim/manufacturers"][dtype["manufacturer"]["id"]]["slug"] == "dell"
    assert set(_ifaces(nb, "jacks-mbp")) == {"eno2"}                # renamed, not added beside eth0
    assert ("SG3428-b1baf8/1/0/16", "jacks-mbp/eno2") in _cable_ends(nb)
    rng = {r["description"]: r for r in nb.store["ipam/ip-ranges"].values()}["k8s LoadBalancer pool infranet"]
    assert (rng["start_address"], rng["end_address"]) == ("REDACTED_IP/24", "REDACTED_IP/24")
    assert {t["slug"] for t in rng["tags"]} == {"netbox-sync", "sync-k8s"}
    assert _run(nb, c) == {"create": 0, "update": 0, "delete": 0}
    c.lb_pools = []
    _run(nb, c)
    assert "k8s LoadBalancer pool infranet" not in {r["description"] for r in nb.store["ipam/ip-ranges"].values()}


def test_wazuh_services_are_kept_in_step_and_suppress_netflow_guesses():
    from model import FlowService, WazuhAgent
    nb = _netbox()
    c = _world()
    c.healthy["wazuh"] = True
    c.wazuh = [WazuhAgent("k8s-node-1", "REDACTED_IP", "Ubuntu 24.04", listening={"sshd": {"tcp/22"}, "kubelet": {"tcp/10250"}})]
    c.flow_services = [FlowService("REDACTED_IP", "tcp", 22, "ssh", 9)]
    _run(nb, c)
    svcs = {s["name"]: s for s in nb.store["ipam/services"].values()}
    assert svcs["sshd"]["port_mappings"] == ["tcp/22"] and "sync-wazuh" in {t["slug"] for t in svcs["sshd"]["tags"]}
    assert "ssh" not in svcs                                                     # NetFlow's guess is covered
    assert _run(nb, c) == {"create": 0, "update": 0, "delete": 0}
    c.wazuh[0].listening.pop("kubelet")
    _run(nb, c)
    assert "kubelet" not in {s["name"] for s in nb.store["ipam/services"].values()}
    c.healthy["wazuh"] = False                                                  # indexer down: nothing removed
    c.wazuh = []
    _run(nb, c)
    assert "sshd" in {s["name"] for s in nb.store["ipam/services"].values()}


def test_hypervisor_inventory_items_follow_disks_by_serial():
    from model import InvItem, PveNodeObs
    nb = _netbox()
    c = _world()
    disks = lambda names: [InvItem("disk", n, "Crucial", "CT1000MX500SSD1", s, "1.0 TB ssd") for n, s in names]  # noqa: E731
    c.pve_nodes = [PveNodeObs("pve01", ["REDACTED_IP/24"], inventory=disks([("sda", "S1"), ("sdb", "S2")]) +
                              [InvItem("cpu", "cpu0", "Intel", "Xeon E5-2683 v4")])]
    _run(nb, c)
    items = lambda: {(i["name"], i["serial"]) for i in nb.store["dcim/inventory-items"].values()}  # noqa: E731
    assert items() == {("sda", "S1"), ("sdb", "S2"), ("cpu0", "")}
    assert _run(nb, c) == {"create": 0, "update": 0, "delete": 0}
    c.pve_nodes[0].inventory = disks([("sdb", "S1")]) + [InvItem("cpu", "cpu0", "Intel", "Xeon E5-2683 v4")]   # S2 pulled, S1 renamed
    _run(nb, c)
    assert items() == {("sdb", "S1"), ("cpu0", "")}
    c.pve_nodes[0].inventory = None                                     # Proxmox didn't answer: leave them
    _run(nb, c)
    assert items() == {("sdb", "S1"), ("cpu0", "")}



def test_inventory_sources_dont_touch_each_others_items():
    from model import InvItem, PveNodeObs
    nb = _netbox()
    c = _world()
    c.pve_nodes = [PveNodeObs("pve01", ["REDACTED_IP/24"], inventory=[InvItem("disk", "sda", "Crucial", "CT1000", "S1")])]

    def run(bmc_items):
        d = merge(c, "jack-cbr-fw01")
        hv = next(h for h in d.hosts if h.key == "pve:pve01")
        if bmc_items is not None:                       # None: the BMC didn't answer this run
            hv.inventory["bmc"] = bmc_items
        Reconciler(nb, bootstrap(nb, "jack-cbr", "pve-jack-cbr", "jack-cbr-fw01"), d).run()
        return {i["name"] for i in nb.store["dcim/inventory-items"].values()}

    assert run([InvItem("psu", "PSU 1", "HPE", "512327-B21", "P1")]) == {"sda", "PSU 1"}
    assert run(None) == {"sda", "PSU 1"}                # Proxmox's pass leaves the BMC's PSU alone
    assert run([]) == {"sda"}                            # the BMC answered: the PSU is really gone


def test_port_forwards_nat_and_wireguard_peer_ips():
    from model import PortForward, WgPeer
    nb = _netbox()
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "Remote-access WireGuard"})
    c = _world()
    c.fw_interfaces.append(FwInterface("ix0", "WAN", "00:0d:b9:00:00:00", ["REDACTED_IP/22"]))
    c.port_forwards = [PortForward("COD BO3", ["tcp/3478", "udp/3478"], "REDACTED_IP")]
    now = int(datetime.now(timezone.utc).timestamp())
    c.wg_peers = [WgPeer("WG", "phone", "REDACTED_IP", handshake=now - 600), WgPeer("WG", "proxy2", "REDACTED_IP")]
    c.gateways = {"REDACTED_IP": "WAN_DHCP"}
    _run(nb, c)
    ips = {o["address"]: o for o in nb.store["ipam/ip-addresses"].values()}
    wan, laptop = ips["REDACTED_IP/22"], ips["REDACTED_IP/24"]
    assert wan["nat_inside"]["id"] == laptop["id"]
    svc = next(s for s in nb.store["ipam/services"].values() if s["name"] == "forward: COD BO3")
    assert svc["port_mappings"] == ["tcp/3478", "udp/3478"] and [i["id"] for i in svc["ipaddresses"]] == [wan["id"]]
    assert ips["REDACTED_IP/24"]["status"]["value"] == "active" and ips["REDACTED_IP/24"]["custom_fields"]["last_seen"]
    assert ips["REDACTED_IP/24"]["status"]["value"] == "deprecated"          # never handshook
    assert ips["REDACTED_IP/22"]["description"] == "gateway WAN_DHCP"
    assert _run(nb, c) == {"create": 0, "update": 0, "delete": 0}
    c.port_forwards = []
    _run(nb, c)
    assert not any(s["name"].startswith("forward:") for s in nb.store["ipam/services"].values())
    assert not nb.store["ipam/ip-addresses"][wan["id"]].get("nat_inside")


def test_room_fills_an_empty_location_only():
    nb = _netbox()
    c = _world()
    d = merge(c, "jack-cbr-fw01")
    next(h for h in d.hosts if h.name == "jacks-mbp").location = "Study"
    Reconciler(nb, bootstrap(nb, "jack-cbr", "pve-jack-cbr", "jack-cbr-fw01"), d).run()
    dev = _names(nb, "dcim/devices")["jacks-mbp"]
    loc = nb.store["dcim/locations"][dev["location"]["id"]]
    assert (loc["name"], loc["slug"]) == ("Study", "study")
    other = nb.seed("dcim/locations", {"name": "Garage", "slug": "garage"})
    nb.store["dcim/devices"][dev["id"]]["location"] = {"id": other["id"]}     # moved by hand
    d = merge(c, "jack-cbr-fw01")
    next(h for h in d.hosts if h.name == "jacks-mbp").location = "Study"
    Reconciler(nb, bootstrap(nb, "jack-cbr", "pve-jack-cbr", "jack-cbr-fw01"), d).run()
    assert nb.store["dcim/devices"][dev["id"]]["location"]["id"] == other["id"]


def test_binary_lane_vm_with_wireguard_and_wazuh_services():
    import source_binarylane as bl
    from model import WazuhAgent, WgPeer
    nb = _netbox()
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "Remote-access WireGuard"})
    c = _world()
    c.healthy["binarylane"] = True
    c.cloud_vms = bl.cloud_vms([{
        "id": 517192, "name": "edge01.internal", "status": "active", "vcpus": 1, "memory": 1024, "disk": 20,
        "region": {"slug": "syd"}, "image": {"full_name": "Debian 13"},
        "networks": {"v4": [{"ip_address": "REDACTED_IP", "netmask": "REDACTED_IP", "type": "public"},
                            {"ip_address": "REDACTED_IP", "netmask": "REDACTED_IP", "type": "private"}],
                     "v6": [{"ip_address": "2404:9400:2:0:216:3eff:fee7:e448", "netmask": 64, "type": "public"}]}}])
    now = int(datetime.now(timezone.utc).timestamp())
    c.wg_peers = [WgPeer("WG", "NewEdgeProxy", "REDACTED_IP", handshake=now - 60, endpoint="REDACTED_IP"),
                  WgPeer("WG", "proxy.au.cloud", "REDACTED_IP", handshake=now - 62 * 86400, endpoint="REDACTED_IP")]
    c.wazuh = [WazuhAgent("edge01", "REDACTED_IP", listening={"haproxy": {"tcp/80", "tcp/443"}})]
    _run(nb, c)
    vm = _names(nb, "virtualization/virtual-machines")["edge01.internal"]
    cluster = nb.store["virtualization/clusters"][vm["cluster"]["id"]]
    assert cluster["name"] == "Binary Lane syd" and (vm["vcpus"], vm["memory"], vm["disk"]) == (1.0, 1024, 20480)
    ifs = {i["id"]: i["name"] for i in nb.store["virtualization/interfaces"].values() if i["virtual_machine"]["id"] == vm["id"]}
    ips = {o["address"]: o for o in nb.store["ipam/ip-addresses"].values()}
    assert ifs[ips["REDACTED_IP/24"]["assigned_object_id"]] == "eth0"
    assert ifs[ips["REDACTED_IP/16"]["assigned_object_id"]] == "eth1"
    assert ifs[ips["2404:9400:2:0:216:3eff:fee7:e448/64"]["assigned_object_id"]] == "eth0"
    assert ifs[ips["REDACTED_IP/24"]["assigned_object_id"]] == "wg0"
    assert not ips["REDACTED_IP/24"].get("assigned_object_id")           # older peer from the same address
    assert vm["primary_ip4"]["id"] == ips["REDACTED_IP/24"]["id"]
    svc = next(s for s in nb.store["ipam/services"].values() if s["name"] == "haproxy")
    assert svc["parent_object_id"] == vm["id"] and svc["port_mappings"] == ["tcp/443", "tcp/80"]
    assert _run(nb, c) == {"create": 0, "update": 0, "delete": 0}
    c.cloud_vms = []
    _run(nb, c)
    assert nb.store["virtualization/virtual-machines"][vm["id"]]["status"]["value"] == "decommissioning"


def test_dns_zones_dnssync_prefixes_and_plain_records():
    from model import DnsZone
    nb = _netbox()
    nb.seed("plugins/netbox-dns/views", {"name": "_default_", "default_view": True, "prefixes": []})
    c = _world()
    core = DnsZone("internal", "ipa01.internal", "hostmaster.internal", refresh=15,
                   records=[("ipa01", "A", "REDACTED_IP"),                     # the IP's dns_name: DNSsync's
                            ("_kerberos._udp", "SRV", "0 100 88 ipa01.internal."),
                            ("auth", "CNAME", "ipa01.internal.")])
    ob = DnsZone("0b.au", "ipa01.internal", "hostmaster.0b.au", records=[("cctv", "A", "REDACTED_IP")])
    rev = DnsZone("20.20.10.in-addr.arpa", "ipa01.internal", "hostmaster.20.20.10.in-addr.arpa")
    internal = DnsZone("internal", "ipa01.internal", "hostmaster.internal")
    c.dns_zones = [core, ob, rev, internal]
    _run(nb, c)
    zones = {z["name"]: z for z in nb.store["plugins/netbox-dns/zones"].values()}
    assert set(zones) == {"internal", "0b.au", "20.20.10.in-addr.arpa", "internal"}
    assert zones["internal"]["soa_refresh"] == 15
    assert zones["internal"]["soa_rname"] == "hostmaster.internal"     # single-label domain: invalid RName
    ns = next(iter(nb.store["plugins/netbox-dns/nameservers"].values()))
    assert ns["name"] == "ipa01.internal" and [n["id"] for n in zones["0b.au"]["nameservers"]] == [ns["id"]]
    view = next(iter(nb.store["plugins/netbox-dns/views"].values()))
    lan = {p["id"] for p in nb.store["ipam/prefixes"].values() if not p["prefix"].startswith(("10.42.", "10.43."))}
    assert {p["id"] for p in view["prefixes"]} == lan
    recs = {(r["name"], r["type"]["value"] if isinstance(r["type"], dict) else r["type"]): r
            for r in nb.store["plugins/netbox-dns/records"].values()}
    assert set(recs) == {("_kerberos._udp", "SRV"), ("auth", "CNAME"), ("cctv", "A")}      # not ipa01: DNSsync makes it
    assert recs[("cctv", "A")]["disable_ptr"] is True
    vip_ip = next(i for i in nb.store["ipam/ip-addresses"].values() if i["address"] == "REDACTED_IP/24")
    assert recs[("cctv", "A")]["ipam_ip_address"]["id"] == vip_ip["id"]        # links to the shared VIP, for the UI
    assert _run(nb, c) == {"create": 0, "update": 0, "delete": 0}
    # a plain record DNSsync now owns is removed before the IP is saved
    nb.seed("plugins/netbox-dns/records", {"zone": zones["internal"]["id"], "name": "ipa01", "type": "A",
                                           "value": "REDACTED_IP", "managed": False})["tags"] = [{"slug": "netbox-sync"}]
    core.records.append(("old", "A", "REDACTED_IP"))
    _run(nb, c)
    names = {r["name"] for r in nb.store["plugins/netbox-dns/records"].values()}
    assert "ipa01" not in names and "old" in names
    core.records.pop()
    _run(nb, c)
    assert "old" not in {r["name"] for r in nb.store["plugins/netbox-dns/records"].values()}


def test_bmc_folds_into_its_server_and_stays_there():
    import source_bmc
    from model import OmadaClient, PveNodeObs
    from test_merge import REDFISH
    nb = _netbox()
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "JACK-CBR net-mgmt"})
    nb.seed("ipam/prefixes", {"prefix": "REDACTED_IP/24", "description": "JACK-CBR legacy-services"})
    ILO_MAC, HV_MAC = "94:57:a5:b4:70:de", "94:57:a5:b4:70:dc"

    def world(bmc=True):
        c = _wired_world()
        c.pve_nodes = [PveNodeObs("hydrogen", ["REDACTED_IP/24"])]
        c.arp += [ArpEntry("REDACTED_IP", HV_MAC), ArpEntry("REDACTED_IP", ILO_MAC)]
        c.omada_clients.append(OmadaClient(ILO_MAC, "", "", "", "", uplink_mac=SW, port=21))
        c.healthy["bmc"] = bmc
        c.bmcs = [source_bmc.bmc_obs("REDACTED_IP", REDFISH.__getitem__)] if bmc else []
        return c

    _run(nb, world(bmc=False))                       # today: the iLO is its own device on port 21
    ilo_dev = next(d for d in _names(nb, "dcim/devices") if d.startswith("client-b470de"))
    assert ("SG3428-b1baf8/1/0/21", f"{ilo_dev}/eth0") in _cable_ends(nb)

    _run(nb, world())                                # Redfish says whose it is: one device
    devs = _names(nb, "dcim/devices")
    assert ilo_dev not in devs
    hv = devs["hydrogen"]
    ilo_if = _ifaces(nb, "hydrogen")["iLO"]
    assert ilo_if["mgmt_only"] is True and ("SG3428-b1baf8/1/0/21", "hydrogen/iLO") in _cable_ends(nb)
    ips = {o["address"]: o for o in nb.store["ipam/ip-addresses"].values()}
    assert ips["REDACTED_IP/24"]["assigned_object_id"] == ilo_if["id"]
    assert hv["oob_ip"]["id"] == ips["REDACTED_IP/24"]["id"] and hv["primary_ip4"]["id"] == ips["REDACTED_IP/24"]["id"]
    mac = next(m for m in nb.store["dcim/mac-addresses"].values() if m["mac_address"] == ILO_MAC)
    assert mac["assigned_object_id"] == ilo_if["id"]
    assert _run(nb, world()) == {"create": 0, "update": 0, "delete": 0}

    _run(nb, world(bmc=False))                       # iLO unreachable: it doesn't split off again
    assert not any(d.startswith("client-b470de") for d in _names(nb, "dcim/devices"))
    assert ("SG3428-b1baf8/1/0/21", "hydrogen/iLO") in _cable_ends(nb)
