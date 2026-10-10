"""Write the merged desired state into NetBox.

Every write goes through NetBox.update(), which diffs first, so a steady-state
run makes no changes (and leaves no changelog noise). last_seen is only bumped
when it is more than LAST_SEEN_GRANULARITY old, for the same reason.

Ownership: objects this job creates carry the netbox-sync tag. Ageing out and
deleting only ever touch those. Objects tagged sync-locked keep their
name/description/dns_name; everything else (IPs, interfaces, status) still syncs.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone

from bootstrap import IPA_TAG, K8S_NODE_TAG, LOCK_TAG, OWNER_TAG, PVE_TAG_PREFIX, SOURCE_TAGS, Ctx
from model import GENERATED_NAME, Desired, Host, SvcObs, VipObs, VmDisk
from nb_models import (
    Cable, Cluster, ClusterType, Device, DeviceType, FhrpGroup, FhrpGroupAssignment, IPAddress, Interface,
    InventoryItem, InventoryItemRole, IpRange, Location, MacAddress, Manufacturer, Platform, Prefix, Service, Tag,
    VMInterface, Vlan, VirtualDisk, VirtualMachine, WirelessLan,
)
from nb_write import (
    ClusterTypeWrite, ClusterWrite, DeviceTypeWrite, DeviceWrite, FhrpGroupAssignmentWrite, FhrpGroupWrite,
    IPAddressWrite, InterfaceWrite, InventoryItemRoleWrite, InventoryItemWrite, IpRangeWrite, LocationWrite,
    MacAddressWrite, ManufacturerWrite, PlatformWrite, PrefixWrite, ServiceWrite, TagWrite, VMInterfaceWrite,
    VirtualDiskWrite, VirtualMachineWrite, VlanWrite,
)
from netbox_api import NetBox
from reconcile_common import (
    DAY, DELETE_AFTER, DEV_IF, FHRP, FHRP_PRIORITY, STALE_AFTER, VIRTUAL_TYPES, VM_IF, WIRED_TYPE, _has_tag,
    _parse_ts, _tags, stale_action,
)
from reconcile_dns import DnsMixin
from reconcile_links import LinksMixin

log = logging.getLogger("reconcile")

LAST_SEEN_GRANULARITY = timedelta(hours=1)


class Reconciler(DnsMixin, LinksMixin):
    def __init__(self, nb: NetBox, ctx: Ctx, desired: Desired):
        self.nb, self.ctx, self.d = nb, ctx, desired
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.touched: dict[str, set[int]] = {"device": set(), "vm": set(), "ip": set(), "service": set()}
        self.present: dict[str, set[int]] = {"device": set(), "vm": set(), "ip": set()}

    # ------------------------------------------------------------------ load

    def load(self) -> None:
        nb, site = self.nb, self.ctx.site_id
        self.devices = {d.id: d for d in nb.list("dcim/devices", model=Device, site_id=site)}
        # In dry-run a cluster bootstrap would create has a placeholder (negative) id: nothing in it yet.
        cluster = self.ctx.cluster_id
        self.vms = {v.id: v for v in nb.list("virtualization/virtual-machines", model=VirtualMachine, cluster_id=cluster)} \
            if cluster > 0 else {}
        self.dev_ifaces = {i.id: i for i in nb.list("dcim/interfaces", model=Interface, site_id=site)}
        self.vm_ifaces = {i.id: i for i in nb.list("virtualization/interfaces", model=VMInterface, cluster_id=cluster)} \
            if cluster > 0 else {}
        self.macs: dict[str, list] = {}
        for m in nb.list("dcim/mac-addresses", model=MacAddress):
            self.macs.setdefault(m.mac_address.lower(), []).append(m)
        self._absorbed_from: dict[int, set[str]] = {}       # device id -> BMC MACs it held before this run
        for mac in self.d.absorbed_macs:
            for m in self.macs.get(mac, []):
                iface = self.dev_ifaces.get(m.assigned_object_id) if m.assigned_object_type == DEV_IF else None
                if iface and iface.device:
                    self._absorbed_from.setdefault(iface.device.id, set()).add(mac)
        self.ip_list = nb.list("ipam/ip-addresses", model=IPAddress)
        self.ips: dict[str, IPAddress] = {}
        for ip in self.ip_list:
            self.ips.setdefault(ip.address.split("/")[0], ip)
        self.prefixes = nb.list("ipam/prefixes", model=Prefix)
        self.vlans = nb.list("ipam/vlans", model=Vlan, site_id=site)
        self.fhrp_list = nb.list("ipam/fhrp-groups", model=FhrpGroup)
        self.fhrp = {}
        for g in self.fhrp_list:
            self.fhrp.setdefault(g.name, g)
        self.services = nb.list("ipam/services", model=Service)
        self.cables = {c.id: c for c in nb.list("dcim/cables", model=Cable, site_id=site)}
        self.ip_ranges = nb.list("ipam/ip-ranges", model=IpRange)
        self.platforms = {p.slug: p for p in nb.list("dcim/platforms", model=Platform)}
        self.omada_by_mac = {od.mac: od for od in self.d.omada_devices}
        self.pools = [(int(ipaddress.ip_address(r.start)), int(ipaddress.ip_address(r.end)))
                      for r in self.d.dhcp_ranges]
        self.wlans = {w.ssid: w for w in nb.list("wireless/wireless-lans", model=WirelessLan)}
        self.fhrp_assignments = nb.list("ipam/fhrp-group-assignments", model=FhrpGroupAssignment)
        self.vdisks = nb.list("virtualization/virtual-disks", model=VirtualDisk)
        self.inv_items = nb.list("dcim/inventory-items", model=InventoryItem, site_id=site)
        self.inv_roles = {r.slug: r for r in nb.list("dcim/inventory-item-roles", model=InventoryItemRole)}
        self._manus: dict[str, Manufacturer] = {}             # manufacturer slug -> object, filled on demand
        self._dtypes: dict[str, DeviceType] = {}               # device type slug -> object
        self.tag_slugs = {t.slug for t in nb.list("extras/tags", model=Tag)}
        self.spec_mode_ifaces: set[int] = set()              # interfaces whose VLAN mode a source set
        self.mac_iface: dict[str, tuple] = {}   # mac -> (device, interface), filled by sync_host
        self.host_dev: dict[str, object] = {}                  # host key -> its device, filled by sync_host

    # ------------------------------------------------------------------ run

    def dedupe(self) -> None:
        """Remove duplicates of objects this job owns, e.g. left by two runs racing
        (a manual Job alongside the scheduled one). NetBox doesn't enforce unique
        FHRP group names, and VIP-role IPs may repeat."""
        by_name: dict[str, list] = {}
        for g in self.fhrp_list:
            by_name.setdefault(g.name, []).append(g)
        dead_groups = set()
        for name, groups in by_name.items():
            owned = [g for g in groups if _has_tag(g, OWNER_TAG)]
            if len(groups) < 2 or len(owned) < 2:
                continue
            with_svc = {s.parent_object_id for s in self.services if s.parent_object_type == FHRP}
            keep = next((g for g in sorted(owned, key=lambda g: g.id) if g.id in with_svc), min(owned, key=lambda g: g.id))
            self.fhrp[name] = keep
            for g in owned:
                if g is not keep:
                    dead_groups.add(g.id)
                    self.nb.delete("ipam/fhrp-groups", g, what=f"{name} (duplicate)")
        by_ip: dict[str, list] = {}
        for ip in self.ip_list:
            by_ip.setdefault(ip.address.split("/")[0], []).append(ip)
        for addr, ips in by_ip.items():
            if len(ips) < 2:
                continue
            live = [i for i in ips if not (i.assigned_object_type == FHRP and i.assigned_object_id in dead_groups)]
            keep = live[0] if live else ips[0]
            self.ips[addr] = keep
            for ip in ips:
                cascaded = ip.assigned_object_type == FHRP and ip.assigned_object_id in dead_groups
                if ip is not keep and _has_tag(ip, OWNER_TAG) and not cascaded:   # NetBox already deleted those with the group
                    self.nb.delete("ipam/ip-addresses", ip, what=f"{ip.address} (duplicate)")
        self.services = [s for s in self.services
                         if not (s.parent_object_type == FHRP and s.parent_object_id in dead_groups)]
        self.fhrp_assignments = [a for a in self.fhrp_assignments if a.group.id not in dead_groups]

    def run(self) -> None:
        self.load()
        self.dedupe()
        try:
            self.dns_prepass()
        except Exception as e:
            log.error("dns prepass: %s", e)
        self.sync_vlans_and_prefixes()
        if self.d.healthy.get("opnsense"):
            self.sync_dhcp_ranges()
        if self.d.healthy.get("k8s"):
            self.sync_ranges("k8s", {(p.start, p.end): f"k8s LoadBalancer pool {p.name}" for p in self.d.lb_pools})
        for h in self.d.hosts:
            try:
                self.sync_host(h)
            except Exception as e:  # one bad host must not stop the run
                log.error("host %s (%s): %s", h.name, h.key, e)
        for vip in self.d.vips:
            try:
                self.sync_vip(vip)
            except Exception as e:
                log.error("vip %s: %s", vip.ip, e)
        self.place_vms()
        absorbed_devs = self._bmc_devices()
        if self.d.healthy.get("omada"):
            try:
                self.sync_links()
            except Exception as e:
                log.error("links: %s", e)
        for dev in absorbed_devs:
            try:
                self._remove_absorbed(dev)
            except Exception as e:
                log.error("remove %s: %s", dev.name, e)
        if self.d.healthy.get("opnsense"):
            try:
                self.sync_opnsense_extras()
            except Exception as e:
                log.error("opnsense extras: %s", e)
        if self.d.healthy.get("binarylane"):
            try:
                self.sync_cloud()
            except Exception as e:
                log.error("cloud vms: %s", e)
        if self.d.flow_services is not None:
            try:
                self.sync_flow_services()
            except Exception as e:
                log.error("flow services: %s", e)
        self.age_out()
        if self.d.healthy.get("ipa") and self.d.dns_zones is not None:
            try:
                self.sync_dns()
            except Exception as e:
                log.error("dns: %s", e)

    # ------------------------------------------------------------------ prefixes

    def sync_vlans_and_prefixes(self) -> None:
        by_vid = {v.vid: v for v in self.vlans}
        group = {"group": self.ctx.vlan_group_id} if self.ctx.vlan_group_id else {}
        if self.d.healthy.get("opnsense"):
            for v in self.d.vlans:
                if v.vid not in by_vid:
                    by_vid[v.vid] = self.nb.create("ipam/vlans", {
                        "vid": v.vid, "name": v.name, "status": "active", "site": self.ctx.site_id,
                        **group, **self._tenant(),
                        "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["opnsense"]}]}, model=Vlan,
                        write_model=VlanWrite)
                    self.vlans.append(by_vid[v.vid])
                elif _has_tag(by_vid[v.vid], OWNER_TAG) and (group or self._tenant()):
                    i = self.vlans.index(by_vid[v.vid])
                    self.vlans[i] = by_vid[v.vid] = self.nb.update("ipam/vlans", by_vid[v.vid],
                                                                   {**group, **self._tenant()}, model=Vlan,
                                                                   write_model=VlanWrite, what=v.name)
        existing = {p.prefix: p for p in self.prefixes}
        for cidr, (desc, vid) in self.d.prefixes.items():
            vlan = by_vid.get(vid) if vid else None
            p = existing.get(cidr)
            if p is None:
                p = self.nb.create("ipam/prefixes", {
                    "prefix": cidr, "status": "active", "description": desc[:200],
                    "scope_type": "dcim.site", "scope_id": self.ctx.site_id,
                    **({"vlan": vlan.id} if vlan else {}), **self._tenant(),
                    "tags": [{"slug": OWNER_TAG}]}, model=Prefix, write_model=PrefixWrite)
                self.prefixes.append(p)
                continue
            # Existing prefixes are hand-curated: fill gaps, never overwrite.
            patch = {}
            if not p.description and desc:
                patch["description"] = desc[:200]
            if vlan and not p.vlan:
                patch["vlan"] = vlan.id
            if self.ctx.tenant_id and not p.tenant:
                patch["tenant"] = self.ctx.tenant_id
            if patch:
                self.nb.update("ipam/prefixes", p, patch, model=Prefix, write_model=PrefixWrite)

    def sync_dhcp_ranges(self) -> None:
        """OPNsense's dnsmasq pools as IP ranges."""
        self.sync_ranges("opnsense", {(r.start, r.end): f"DHCP pool, {r.interface}".strip(", ")
                                      for r in self.d.dhcp_ranges})

    def sync_ranges(self, source: str, ranges: dict[tuple[str, str], str]) -> None:
        """Address pools a source hands out from (DHCP, k8s LoadBalancer) as IP ranges, marked
        populated: their addresses aren't free for static use. Each source only touches ranges
        it tagged. Ranges someone else made (Terraform) win: an overlapping pool is skipped,
        never adjusted."""
        want = {}
        for (start, end), desc in ranges.items():
            plen = self._prefix_len(start)
            want[(f"{start}/{plen}", f"{end}/{plen}")] = desc
        mine = [r for r in self.ip_ranges if _has_tag(r, OWNER_TAG) and _has_tag(r, SOURCE_TAGS[source])]
        for r in mine:
            if (r.start_address, r.end_address) not in want:
                self.nb.delete("ipam/ip-ranges", r, what=f"{r.start_address}-{r.end_address}")
                self.ip_ranges.remove(r)
        span = lambda a, b: (int(ipaddress.ip_interface(a).ip), int(ipaddress.ip_interface(b).ip))  # noqa: E731
        for (start, end), desc in want.items():
            have = [r for r in self.ip_ranges if (r.start_address, r.end_address) == (start, end)]
            if have:
                if _has_tag(have[0], OWNER_TAG):
                    self.nb.update("ipam/ip-ranges", have[0], {"description": desc, "status": "active",
                                                               "mark_populated": True, **self._tenant()},
                                   model=IpRange, write_model=IpRangeWrite, what=desc)
                continue
            lo, hi = span(start, end)
            if any(lo <= span(r.start_address, r.end_address)[1] and span(r.start_address, r.end_address)[0] <= hi
                   for r in self.ip_ranges):
                log.info("%s pool %s-%s overlaps an existing range; leaving that one", source, start, end)
                continue
            self.ip_ranges.append(self.nb.create("ipam/ip-ranges", {
                "start_address": start, "end_address": end, "status": "active", "description": desc,
                # a DHCP pool is in use as a whole: its addresses aren't free for static use
                "mark_populated": True, **self._tenant(),
                "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS[source]}]}, model=IpRange,
                write_model=IpRangeWrite, what=desc))

    def _tenant(self) -> dict:
        return {"tenant": self.ctx.tenant_id} if self.ctx.tenant_id else {}

    def _ip_status(self, ip: str, obj: IPAddress | None) -> str:
        """'dhcp' for a pool address without a static reservation, else 'active'. With OPNsense
        down there are no pools to go by: keep whatever it was."""
        if not self.d.healthy.get("opnsense"):
            have = obj.status if obj else None
            return have if have in ("active", "dhcp") else "active"
        n = int(ipaddress.ip_address(ip))
        in_pool = any(lo <= n <= hi for lo, hi in self.pools)
        return "dhcp" if in_pool and ip not in self.d.reserved_ips else "active"

    def _platform(self, name: str) -> int | None:
        if not name:
            return None
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:100]
        p = self.platforms.get(slug)
        if p is None:
            p = self.platforms[slug] = self.nb.create("dcim/platforms", {
                "name": name, "slug": slug, "tags": [{"slug": OWNER_TAG}]}, model=Platform,
                write_model=PlatformWrite, what=name)
        return p.id

    INV_ROLES = {"disk": ("Disk", "607d8b"), "cpu": ("CPU", "9c27b0"), "nic": ("NIC", "00897b"),
                 "memory": ("Memory", "3f51b5"), "psu": ("Power supply", "f44336"),
                 "zigbee": ("Zigbee device", "ffc107"), "bluetooth": ("Bluetooth device", "2196f3"),
                 "storage-controller": ("Storage controller", "795548"), "gpu": ("GPU", "ff9800")}

    def _location(self, name: str) -> int:
        """A room (Location) at the site, found by name or made."""
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:100] or "room"
        if not hasattr(self, "_locations"):
            self._locations = {loc.slug: loc for loc in self.nb.list("dcim/locations", model=Location,
                                                                      site_id=self.ctx.site_id)}
        loc = self._locations.get(slug) or next((x for x in self._locations.values() if x.name.lower() == name.lower()), None)
        if loc is None:
            loc = self._locations[slug] = self.nb.create("dcim/locations", {
                "name": name[:100], "slug": slug, "site": self.ctx.site_id, "status": "active", **self._tenant(),
                "tags": [{"slug": OWNER_TAG}]}, model=Location, write_model=LocationWrite, what=name)
        return loc.id

    def _find_or_create(self, cache: dict, key: str, find, path: str, data: dict, model: type = dict,
                        write_model: type = None):
        """Cache-first find-or-create: `find()` is only called on a cache miss, and must
        return NetBox's current matches for `key` (empty when there are none yet)."""
        if key not in cache:
            found = find()
            cache[key] = found[0] if found else self.nb.create(path, data, model=model, write_model=write_model)
        return cache[key]

    def _manufacturer(self, name: str) -> int | None:
        if not name:
            return None
        mslug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        return self._find_or_create(
            self._manus, mslug,
            lambda: self.nb.list("dcim/manufacturers", model=Manufacturer, slug=mslug) or
                    self.nb.list("dcim/manufacturers", model=Manufacturer, name=name),
            "dcim/manufacturers", {"name": name, "slug": mslug}, model=Manufacturer,
            write_model=ManufacturerWrite).id

    def _inv_source(self, item) -> str | None:
        """Which source made an owned inventory item (the first ones carried no source tag: Proxmox)."""
        if not _has_tag(item, OWNER_TAG):
            return None
        return next((s for s, tag in SOURCE_TAGS.items() if _has_tag(item, tag)), "proxmox")

    def sync_inventory(self, dev: Device, source: str, items: list) -> None:
        """Parts a source reports inside a device, as inventory items, matched by serial (disks
        get renamed sdX across boots) else role + name. Each source changes or removes only
        the items it made, so one source being down never drops another's."""
        have = [i for i in self.inv_items if i.device and i.device.id == dev.id]
        used: set[int] = set()
        for it in items:
            role = self.inv_roles.get(it.role)
            if role is None:
                name, color = self.INV_ROLES.get(it.role, (it.role.title(), "9e9e9e"))
                role = self.inv_roles[it.role] = self.nb.create("dcim/inventory-item-roles",
                                                                {"name": name, "slug": it.role, "color": color},
                                                                model=InventoryItemRole,
                                                                write_model=InventoryItemRoleWrite)
            match = next((i for i in have if it.serial and i.serial == it.serial), None) or \
                next((i for i in have if i.name == it.name and i.role and i.role.id == role.id), None)
            want = {"name": it.name[:64], "role": role.id, "manufacturer": self._manufacturer(it.manufacturer),
                    "part_id": it.part_id[:50], "serial": it.serial[:50], "description": it.description[:200],
                    "discovered": True, "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS[source]}]}
            if match is None:
                obj = self.nb.create("dcim/inventory-items", {"device": dev.id, **want}, model=InventoryItem,
                                     write_model=InventoryItemWrite, what=f"{dev.name}/{it.name}")
                self.inv_items.append(obj)
            elif self._inv_source(match) == source:
                obj = self.nb.update("dcim/inventory-items", match, want, model=InventoryItem,
                                     write_model=InventoryItemWrite, what=f"{dev.name}/{it.name}")
            else:
                obj = match
            used.add(obj.id)
        for i in have:
            if i.id not in used and self._inv_source(i) == source:
                self.nb.delete("dcim/inventory-items", i, what=f"{dev.name}/{i.name} (gone)")
                self.inv_items.remove(i)

    def _omada_device_type(self, od) -> int:
        """One device type per Omada model ("SG3428")."""
        return self._device_type("TP-Link", od.model.split()[0] if od.model else od.type.upper(), od.model)

    def _device_type(self, vendor: str, model: str, part_number: str = "") -> int:
        """Manufacturer + device type for a real make/model ("Dell", "OptiPlex 3060"), found or made."""
        mslug = re.sub(r"[^a-z0-9]+", "-", vendor.lower()).strip("-")
        manu = self._manufacturer(vendor)
        slug = f"{mslug}-" + re.sub(r"[^a-z0-9]+", "-", model.lower()).strip("-")
        return self._find_or_create(
            self._dtypes, slug, lambda: self.nb.list("dcim/device-types", model=DeviceType, slug=slug),
            "dcim/device-types", {"manufacturer": manu, "model": model[:100], "slug": slug[:100],
                                  "part_number": part_number[:50], "u_height": 0, "tags": [{"slug": OWNER_TAG}]},
            model=DeviceType, write_model=DeviceTypeWrite).id

    def _prefix_len(self, ip: str) -> int:
        addr = ipaddress.ip_address(ip)
        best = None
        for p in self.prefixes:
            net = ipaddress.ip_network(p.prefix)
            if addr in net and (best is None or net.prefixlen > best):
                best = net.prefixlen
        return best if best is not None else (32 if addr.version == 4 else 128)

    # ------------------------------------------------------------------ hosts

    def _frozen(self, obj) -> bool:
        """The object is tagged with a source that failed this run: its data from that
        source is missing, so renaming it now would flap (and flip back next run)."""
        return any(_has_tag(obj, SOURCE_TAGS[s]) and not ok for s, ok in self.d.healthy.items() if s in SOURCE_TAGS)

    def _host_tags(self, h: Host, obj) -> list[dict]:
        # Keep tags of sources that failed this run: they didn't say the host is gone.
        down = [SOURCE_TAGS[s] for s, ok in self.d.healthy.items() if not ok and s in SOURCE_TAGS and _has_tag(obj, SOURCE_TAGS[s])]
        slugs = [OWNER_TAG] + [SOURCE_TAGS[s] for s in sorted(h.sources) if s in SOURCE_TAGS] + down
        if h.kind == "k8s-node":
            slugs.append(K8S_NODE_TAG)
        if h.ipa_enrolled or (not self.d.healthy.get("ipa") and _has_tag(obj, IPA_TAG)):
            slugs.append(IPA_TAG)
        return _tags(obj, *slugs, keep_also=(IPA_TAG,))

    def _last_seen(self, obj, present: bool) -> dict:
        if not present:
            return {}
        prev = _parse_ts((obj.custom_fields if obj else {}).get("last_seen"))
        if prev and self.now - prev < LAST_SEEN_GRANULARITY:
            return {}
        return {"last_seen": self.now.isoformat()}

    def _bmc_devices(self) -> list[Device]:
        """Devices that held a BMC's MAC before this run folded it into its server (hydrogen-ilo),
        once the MAC really is on the server now."""
        out = []
        for dev_id, macs in self._absorbed_from.items():
            dev = self.devices.get(dev_id)
            moved = all((self.mac_iface[m][0].id if m in self.mac_iface else dev_id) != dev_id for m in macs)
            if dev and _has_tag(dev, OWNER_TAG) and moved:
                out.append(dev)
        return out

    def _remove_absorbed(self, dev: Device) -> None:
        """The BMC's old device, emptied (its MAC, IP and cable now on the server): delete it."""
        for iface in [i for i in self.dev_ifaces.values() if i.device and i.device.id == dev.id]:
            cid = iface.cable.id if iface.cable else None
            if cid and _has_tag(self.cables.get(cid), OWNER_TAG):
                self._drop_cable(cid)
        self.nb.delete("dcim/devices", dev, what=f"{dev.name} (folded into its server)")
        self.devices.pop(dev.id, None)

    def _behind_oob_port(self, h: Host) -> bool:
        """A host whose MAC already sits on another device's out-of-band port is that device's BMC
        (folded in on a run when Redfish could say so): keep it there, don't make it a device again."""
        for mac in h.macs:
            for m in self.macs.get(mac, []):
                iface = self.dev_ifaces.get(m.assigned_object_id) if m.assigned_object_type == DEV_IF else None
                if iface and iface.mgmt_only and _has_tag(iface, OWNER_TAG) and iface.device:
                    dev = self.devices.get(iface.device.id)
                    host_kind = dev.custom_fields.get("host_kind") if dev else None
                    if host_kind not in (None, "client"):
                        return True
        return False

    def sync_host(self, h: Host) -> None:
        if h.kind in ("client", "network") and h.vm is None and self._behind_oob_port(h):
            log.debug("host %s is a BMC already folded into its server; leaving it there", h.name)
            return
        if h.kind == "dns-only":
            for ip in sorted(h.ips):
                self.ensure_ip(ip, h, None, None)
            return
        if h.kind == "firewall":
            if not self.ctx.firewall:
                log.warning("firewall device not in NetBox; skipping its interfaces")
                return
            parent_type, parent = "device", self.ctx.firewall
            self.devices.setdefault(parent.id, parent)
        elif h.vm is not None:
            parent_type, parent = "vm", self.ensure_vm(h)
        else:
            parent_type, parent = "device", self.ensure_device(h)

        # Interfaces: every name a source gave us, else a single eth0 (wlan0 when Omada has it on Wi-Fi).
        if h.links:
            default = "wlan0" if all(ln.wireless for ln in h.links) else "eth0"
        else:   # not on Omada right now: keep whichever it has
            table = self.dev_ifaces if parent_type == "device" else self.vm_ifaces
            key = "device" if parent_type == "device" else "virtual_machine"
            default = "wlan0" if any(getattr(i, key) and getattr(i, key).id == parent.id and i.name == "wlan0"
                                     for i in table.values()) else "eth0"
        iface_names = sorted(set(h.iface_mac) | set(h.ip_iface.values()) | set(h.iface_spec)) or [default]
        if parent_type == "device" and h.hardware is not None:
            self._rename_guess(parent, iface_names)
        ifaces = {n: self.ensure_iface(parent_type, parent, n, h.iface_mac.get(n),
                                       h.iface_spec[n].type if n in h.iface_spec else None)
                  for n in iface_names}
        if h.iface_spec:
            ifaces = self._apply_specs(h, parent_type, ifaces)
        if not h.iface_mac and h.macs and default in ifaces:
            self.ensure_mac(parent_type, ifaces[default], sorted(h.macs)[0])
        if parent_type == "device":
            self.host_dev[h.key] = parent
            # Which interface each MAC lives on, for cables: the one named for it (or, under a
            # bridge/bond/VLAN, the physical NIC beneath it), else the only one
            by_mac = {m: ifaces[self._cable_end(h, n)] for n, m in h.iface_mac.items() if n in ifaces}
            if not h.iface_mac and h.macs and default in ifaces:
                by_mac.setdefault(sorted(h.macs)[0], ifaces[default])
            for m in h.macs:
                if m not in by_mac and len(ifaces) == 1:
                    by_mac[m] = next(iter(ifaces.values()))
            for m, iface in by_mac.items():
                self.mac_iface[m] = (parent, self.dev_ifaces.get(iface.id, iface))

        if parent_type == "device" and _has_tag(self.devices.get(parent.id, parent), OWNER_TAG):
            for source, items in sorted(h.inventory.items()):
                self.sync_inventory(parent, source, items)

        primary = oob = None
        for ip in sorted(h.ips, key=lambda a: (ipaddress.ip_address(a).version, a)):
            iface = ifaces.get(h.ip_iface.get(ip, ""), ifaces[iface_names[0]])
            obj = self.ensure_ip(ip, h, parent_type, iface)
            if ip == h.oob_ip:
                oob = obj                       # the BMC's address: never the primary
            elif primary is None and ipaddress.ip_address(ip).version == 4 and obj:
                primary = obj
        if primary and h.kind != "firewall":
            path = "dcim/devices" if parent_type == "device" else "virtualization/virtual-machines"
            model = Device if parent_type == "device" else VirtualMachine
            write_model = DeviceWrite if parent_type == "device" else VirtualMachineWrite
            parent = self.nb.update(path, parent, {"primary_ip4": primary.id}, model=model,
                                    write_model=write_model, what=h.name)
        if oob and parent_type == "device" and _has_tag(self.devices.get(parent.id, parent), OWNER_TAG):
            parent = self.nb.update("dcim/devices", self.devices.get(parent.id, parent), {"oob_ip": oob.id},
                                    model=Device, write_model=DeviceWrite, what=f"{h.name} oob")
            self.devices[parent.id] = parent

        for svc in h.services:
            self.ensure_service("dcim.device" if parent_type == "device" else "virtualization.virtualmachine",
                                parent.id, svc, [primary.id] if primary else [], source=svc.source)

    def _rename_guess(self, dev: Device, names: list[str]) -> None:
        """Once a host's real NICs are known, the eth0/wlan0 this job guessed for it becomes the
        one real NIC it lacks, keeping its cable, MAC and IPs, rather than lingering beside it."""
        mine = {i.name: i for i in self.dev_ifaces.values() if i.device and i.device.id == dev.id}
        missing = [n for n in names if n not in mine]
        guesses = [i for n, i in mine.items() if n in ("eth0", "wlan0") and n not in names and _has_tag(i, OWNER_TAG)]
        if len(missing) == 1 and len(guesses) == 1:
            iface = self.nb.update("dcim/interfaces", guesses[0], {"name": missing[0]}, model=Interface,
                                   write_model=InterfaceWrite, what=f"{dev.name}/{guesses[0].name} -> {missing[0]}")
            self.dev_ifaces[iface.id] = iface

    @staticmethod
    def _cable_end(h: Host, name: str) -> str:
        """The physical interface beneath a bridge, bond or VLAN interface: where a cable plugs in."""
        seen: set[str] = set()
        while name not in seen:
            seen.add(name)
            spec = h.iface_spec.get(name)
            if spec and spec.parent:
                name = spec.parent
                continue
            members = sorted(n for n, sp in h.iface_spec.items() if name in (sp.bridge, sp.lag))
            if not members:
                break
            name = members[0]
        return name

    def _apply_specs(self, h: Host, parent_type: str, ifaces: dict) -> dict:
        """Interface types, parent/bridge/LAG links and VLANs from the host's sources, on
        interfaces this job owns. Bonds and bridges go first: NetBox checks a member's LAG
        is a LAG-type interface."""
        device = parent_type == "device"
        path, table = ("dcim/interfaces", self.dev_ifaces) if device else ("virtualization/interfaces", self.vm_ifaces)
        model = Interface if device else VMInterface
        write_model = InterfaceWrite if device else VMInterfaceWrite
        order = sorted(ifaces, key=lambda n: (not (h.iface_spec.get(n) and h.iface_spec[n].type), n))
        for name in order:
            spec = h.iface_spec.get(name)
            iface = table.get(ifaces[name].id, ifaces[name])
            if spec is None or not _has_tag(iface, OWNER_TAG):
                continue
            ref = lambda n: ifaces[n].id if n and n in ifaces else None  # noqa: E731
            want: dict = {"parent": ref(spec.parent), "bridge": ref(spec.bridge)}
            if device:
                want["lag"] = ref(spec.lag)
                if spec.mgmt_only:
                    want["mgmt_only"] = True
                if spec.type:
                    cable = iface.cable.id if iface.cable else None
                    if spec.type in VIRTUAL_TYPES and cable:
                        if not self._cable_ok_to_drop(cable):
                            log.info("%s/%s: a hand-made cable is on it; not making it %s",
                                     h.name, name, spec.type)
                            spec = None
                        else:
                            self._drop_cable(cable)   # sync_links re-cables the NIC beneath it
                    if spec is not None:
                        want["type"] = spec.type
            if spec is None:
                continue
            untagged = self._vlan_id(spec.untagged)
            tagged = sorted(i for i in map(self._vlan_id, spec.tagged) if i)
            if tagged:
                want.update(mode="tagged", untagged_vlan=untagged, tagged_vlans=tagged)
            elif untagged:
                want.update(mode="access", untagged_vlan=untagged)
            if "mode" in want:
                self.spec_mode_ifaces.add(iface.id)
            iface = self.nb.update(path, iface, want, model=model, write_model=write_model, what=f"{h.name}/{name}")
            table[iface.id] = ifaces[name] = iface
        return ifaces

    def _find_device_by_mac(self, h: Host) -> Device | None:
        for mac in sorted(h.macs):
            for m in self.macs.get(mac, []):
                if m.assigned_object_type == DEV_IF:
                    iface = self.dev_ifaces.get(m.assigned_object_id)
                    if iface and iface.device and iface.device.id in self.devices:
                        return self.devices[iface.device.id]
        return None

    def ensure_device(self, h: Host) -> Device:
        role = {"client": "client", "hypervisor": "hypervisor", "network": "network", "camera": "camera"}.get(h.kind, "server")
        dev = self._find_device_by_mac(h)
        if dev is None:
            by_name = [d for d in self.devices.values() if d.name and d.name.lower() == h.name.lower()]
            dev = by_name[0] if by_name else None
        od = next((self.omada_by_mac[m] for m in sorted(h.macs) if m in self.omada_by_mac), None)
        cf = {"host_kind": h.kind, "vendor": h.vendor, "randomized_mac": h.randomized_mac,
              **({"firmware": od.firmware} if od and od.firmware else {"firmware": h.firmware[:200]} if h.firmware else {}),
              # with links, sync_links writes it (using the switch/AP's NetBox name)
              **({"connection": h.connection} if h.connection and not h.links else {}),
              **self._last_seen(dev, h.present)}
        extra = {}    # set on devices this job owns
        if h.platform:
            extra["platform"] = self._platform(h.platform)
        if h.kind == "hypervisor" and self.ctx.cluster_id > 0:
            extra["cluster"] = self.ctx.cluster_id     # VMs can only be placed on a device in their cluster
        elif h.kind == "k8s-node" and self.ctx.k8s_cluster_id > 0:
            extra["cluster"] = self.ctx.k8s_cluster_id
        extra.update(self._tenant())
        if h.location and not (dev.location if dev else None):
            extra["location"] = self._location(h.location)     # fill a gap; a room set by hand wins
        if od is not None:
            extra["device_type"] = self._omada_device_type(od)
            if od.serial:
                extra["serial"] = od.serial
        else:
            if h.hardware is not None and h.hardware.vendor and h.hardware.model:
                extra["device_type"] = self._device_type(h.hardware.vendor, h.hardware.model, h.hardware.sku)
            if h.serial:
                extra["serial"] = h.serial[:50]
        if dev is None:
            dev = self.nb.create("dcim/devices", {
                "name": h.name, "role": self.ctx.roles[role], "device_type": self.ctx.device_types[role],
                "site": self.ctx.site_id, "status": "active", "custom_fields": cf,
                "tags": self._host_tags(h, None), **extra}, model=Device, write_model=DeviceWrite)
        else:
            want = {"custom_fields": cf, "tags": self._host_tags(h, dev)}
            if _has_tag(dev, OWNER_TAG):
                want["role"] = self.ctx.roles[role]
                if h.present:
                    want["status"] = "active"
                want.update(extra)
            # A MAC merge.py couldn't tie back to its real Host this run (an ARP/DHCP/Omada
            # miss) surfaces as a second, identity-less Host that still resolves to this same
            # device by MAC. Don't let its generated placeholder name clobber a real one.
            if not _has_tag(dev, LOCK_TAG) and not self._frozen(dev) and not (
                    GENERATED_NAME.match(h.name) and dev.name and not GENERATED_NAME.match(dev.name)):
                want["name"] = h.name
            dev = self.nb.update("dcim/devices", dev, want, model=Device, write_model=DeviceWrite, what=h.name)
        self.devices[dev.id] = dev
        self.touched["device"].add(dev.id)
        if h.present:
            self.present["device"].add(dev.id)
        return dev

    def ensure_vm(self, h: Host) -> VirtualMachine:
        vm = h.vm
        found = [v for v in self.vms.values() if v.custom_fields.get("vmid") == vm.vmid]
        if not found:
            found = [v for v in self.vms.values() if v.name.lower() == vm.name.lower()]
        obj = found[0] if found else None
        has_vdisks = bool(vm.disks) or any(d.virtual_machine and d.virtual_machine.id == (obj.id if obj else None)
                                           for d in self.vdisks)
        # site up front (place_vms adds the device): NetBox checks interface VLANs against it
        want = {"cluster": self.ctx.cluster_id, "site": self.ctx.site_id, "status": vm.status,
                "vcpus": vm.vcpus, "memory": vm.memory_mb,
                # with virtual disks NetBox computes disk itself, and refuses a different value
                **({} if has_vdisks else {"disk": vm.disk_mb}), **self._tenant(),
                "custom_fields": {"vmid": vm.vmid, "host_kind": h.kind, **self._last_seen(obj, h.present)},
                "tags": self._vm_tags(h, obj)}
        if h.platform:
            want["platform"] = self._platform(h.platform)
        if obj is None:
            obj = self.nb.create("virtualization/virtual-machines", {"name": vm.name, **want}, model=VirtualMachine,
                                 write_model=VirtualMachineWrite)
        else:
            if not _has_tag(obj, LOCK_TAG) and not self._frozen(obj):
                want["name"] = vm.name
            obj = self.nb.update("virtualization/virtual-machines", obj, want, model=VirtualMachine,
                                 write_model=VirtualMachineWrite, what=vm.name)
        self.vms[obj.id] = obj
        self.touched["vm"].add(obj.id)
        if h.present:
            self.present["vm"].add(obj.id)
        self.sync_disks(obj, vm.disks)
        return obj

    def _vm_tags(self, h: Host, obj) -> list[dict]:
        """The usual host tags plus the VM's Proxmox tags as pve-<tag> (dropped when removed in Proxmox)."""
        tags = [t for t in self._host_tags(h, obj) if not t["slug"].startswith(PVE_TAG_PREFIX)]
        for tag in sorted(set(h.vm.tags)):
            slug = PVE_TAG_PREFIX + re.sub(r"[^a-z0-9_-]+", "-", tag.lower()).strip("-")
            if slug == PVE_TAG_PREFIX:
                continue            # nothing sluggable in it (emoji, punctuation)
            if slug not in self.tag_slugs:
                self.nb.create("extras/tags", {"name": f"pve: {tag}", "slug": slug, "color": "e65100",
                                               "description": "Proxmox VM tag (netbox-sync)"}, model=Tag,
                               write_model=TagWrite, what=slug)
                self.tag_slugs.add(slug)
            tags.append({"slug": slug})
        return sorted(tags, key=lambda t: t["slug"])

    def sync_disks(self, vm_obj: VirtualMachine, disks: list[VmDisk]) -> None:
        """Proxmox disks as virtual disks. Only disks this job made are resized or removed. No
        disks at all means the VM's config couldn't be read this run: leave them be."""
        if not disks:
            return
        have = {d.name: d for d in self.vdisks if d.virtual_machine and d.virtual_machine.id == vm_obj.id}
        for disk in disks:
            want = {"size": disk.size_mb, "description": disk.storage}
            d = have.get(disk.name)
            if d is None:
                self.vdisks.append(self.nb.create("virtualization/virtual-disks", {
                    "virtual_machine": vm_obj.id, "name": disk.name, **want,
                    "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["proxmox"]}]},
                    model=VirtualDisk, write_model=VirtualDiskWrite, what=f"{vm_obj.name}/{disk.name}"))
            elif _has_tag(d, OWNER_TAG):
                self.nb.update("virtualization/virtual-disks", d, want, model=VirtualDisk,
                               write_model=VirtualDiskWrite, what=f"{vm_obj.name}/{disk.name}")
        names = {d.name for d in disks}
        for name, d in have.items():
            if name not in names and _has_tag(d, OWNER_TAG):
                self.nb.delete("virtualization/virtual-disks", d, what=f"{vm_obj.name}/{name}")
                self.vdisks.remove(d)

    # ------------------------------------------------------------------ interfaces / MACs / IPs

    def ensure_iface(self, parent_type: str, parent, name: str, mac: str | None,
                     itype: str | None = None):
        if parent_type == "device":
            path, table, key, model, write_model = "dcim/interfaces", self.dev_ifaces, "device", Interface, InterfaceWrite
        else:
            path, table, key, model, write_model = ("virtualization/interfaces", self.vm_ifaces, "virtual_machine",
                                                     VMInterface, VMInterfaceWrite)
        found = [i for i in table.values() if getattr(i, key) and getattr(i, key).id == parent.id and i.name == name]
        if not found and name in ("eth0", "wlan0"):
            # A client that moved between wired and Wi-Fi: rename its interface rather than add one
            other = "wlan0" if name == "eth0" else "eth0"
            prev = [i for i in table.values() if getattr(i, key) and getattr(i, key).id == parent.id and i.name == other
                    and _has_tag(i, OWNER_TAG) and not i.cable]
            if prev:
                found = [self.nb.update(path, prev[0], {"name": name}, model=model, write_model=write_model,
                                        what=f"{parent.name}/{other}")]
                table[found[0].id] = found[0]
        if found:
            iface = found[0]
        else:
            data = {key: parent.id, "name": name, "tags": [{"slug": OWNER_TAG}]}
            if parent_type == "device":
                data["type"] = itype or WIRED_TYPE
            iface = self.nb.create(path, data, model=model, write_model=write_model, what=f"{parent.name}/{name}")
            table[iface.id] = iface
        if mac:
            self.ensure_mac(parent_type, iface, mac)
        return iface

    def ensure_mac(self, parent_type: str, iface, mac: str) -> None:
        otype = DEV_IF if parent_type == "device" else VM_IF
        path = "dcim/interfaces" if parent_type == "device" else "virtualization/interfaces"
        model = Interface if parent_type == "device" else VMInterface
        write_model = InterfaceWrite if parent_type == "device" else VMInterfaceWrite
        candidates = self.macs.get(mac, [])
        mine = [m for m in candidates if m.assigned_object_type == otype and m.assigned_object_id == iface.id]
        if mine:
            m = mine[0]
        else:
            movable = [m for m in candidates if _has_tag(m, OWNER_TAG) or not m.assigned_object_id]
            want = {"mac_address": mac, "assigned_object_type": otype, "assigned_object_id": iface.id}
            if movable:
                self._release_primary_mac(movable[0])
                m = self.nb.update("dcim/mac-addresses", movable[0], want, model=MacAddress,
                                   write_model=MacAddressWrite, what=mac)
            else:
                m = self.nb.create("dcim/mac-addresses", {**want, "tags": [{"slug": OWNER_TAG}]},
                                   model=MacAddress, write_model=MacAddressWrite, what=mac)
                self.macs.setdefault(mac, []).append(m)
        self.nb.update(path, iface, {"primary_mac_address": m.id}, model=model, write_model=write_model,
                       what=f"{iface.name} primary MAC")

    def _release_primary_mac(self, mac_obj) -> None:
        """NetBox refuses to move a MAC that is still its interface's primary MAC."""
        otype, oid = mac_obj.assigned_object_type, mac_obj.assigned_object_id
        path, table, model, write_model = ("dcim/interfaces", self.dev_ifaces, Interface, InterfaceWrite) if otype == DEV_IF else \
            ("virtualization/interfaces", self.vm_ifaces, VMInterface, VMInterfaceWrite) if otype == VM_IF else (None, {}, None, None)
        iface = table.get(oid)
        if iface and iface.primary_mac_address and iface.primary_mac_address.id == mac_obj.id:
            table[oid] = self.nb.update(path, iface, {"primary_mac_address": None}, model=model,
                                        write_model=write_model, what=f"{iface.name} release primary MAC")

    def _release_primary(self, ip_obj: IPAddress) -> None:
        """NetBox refuses to move an IP that is still some parent's primary_ip4."""
        for path, table, model, write_model in (("dcim/devices", self.devices, Device, DeviceWrite),
                                                 ("virtualization/virtual-machines", self.vms, VirtualMachine,
                                                  VirtualMachineWrite)):
            for parent in table.values():
                if parent.primary_ip4 and parent.primary_ip4.id == ip_obj.id:
                    self.nb.update(path, parent, {"primary_ip4": None}, model=model, write_model=write_model,
                                   what=f"{parent.name} release primary")
                    parent.primary_ip4 = None

    def ensure_ip(self, ip: str, h: Host | None, parent_type: str | None, target,
                  role: str | None = None, description: str | None = None,
                  sources: set[str] | None = None) -> IPAddress | None:
        cidr = (h.cidrs.get(ip) if h else None) or f"{ip}/{self._prefix_len(ip)}"
        obj = self.ips.get(ip)
        srcs = sources if sources is not None else (h.sources if h else set())
        want: dict = {"address": cidr, "status": self._ip_status(ip, obj) if h else "active", **self._tenant(),
                      "tags": _tags(obj, OWNER_TAG, *[SOURCE_TAGS[s] for s in sorted(srcs) if s in SOURCE_TAGS])}
        if target is not None:
            otype = {"fhrp": FHRP, "device": DEV_IF}.get(parent_type, VM_IF)
            want["assigned_object_type"], want["assigned_object_id"] = otype, target.id
        if role:
            want["role"] = role
        locked = _has_tag(obj, LOCK_TAG)
        if h and not locked:
            want["dns_name"] = h.fqdn if (h.fqdn and len(h.ips) == 1) else (obj.dns_name if obj else "")
        if description is not None and not locked:
            want["description"] = description[:200]
        present = h.present if h else True
        want["custom_fields"] = self._last_seen(obj, present)
        if obj is None:
            obj = self.nb.create("ipam/ip-addresses", want, model=IPAddress, write_model=IPAddressWrite, what=cidr)
        else:
            if (obj.assigned_object_id, obj.assigned_object_type) != \
                    (want.get("assigned_object_id"), want.get("assigned_object_type")) and target is not None:
                self._release_primary(obj)
            obj = self.nb.update("ipam/ip-addresses", obj, want, model=IPAddress, write_model=IPAddressWrite, what=cidr)
        self.ips[ip] = obj
        self.touched["ip"].add(obj.id)
        if present:
            self.present["ip"].add(obj.id)
        return obj

    # ------------------------------------------------------------------ VIPs / services

    def sync_vip(self, vip: VipObs) -> None:
        k8s = vip.kind == "k8s"
        name = f"k8s-lb {vip.ip}" if k8s else f"vip {vip.ip}"
        source = "k8s" if k8s else "proxmox"
        desc = (vip.name or ", ".join(vip.owners) if k8s else
                vip.name or f"floating on {', '.join(vip.owners)}")[:200]
        group = self.fhrp.get(name)
        want = {"protocol": "other" if k8s else "vrrp2", "group_id": int(ipaddress.ip_address(vip.ip)) & 0x7FFF,
                "name": name, "tags": _tags(group, OWNER_TAG, SOURCE_TAGS[source])}
        if not _has_tag(group, LOCK_TAG):
            want["description"] = desc
        group = self.nb.create("ipam/fhrp-groups", want, model=FhrpGroup, write_model=FhrpGroupWrite) if group is None else \
            self.nb.update("ipam/fhrp-groups", group, want, model=FhrpGroup, write_model=FhrpGroupWrite, what=name)
        self.fhrp[name] = group
        ip_obj = self.ensure_ip(vip.ip, None, "fhrp", group, role="vip" if k8s else "vrrp",
                                description=group.description or desc, sources={source})
        for svc in vip.services:
            self.ensure_service(FHRP, group.id, svc, [ip_obj.id] if ip_obj else [])
        if not k8s and self.d.healthy.get("proxmox") and _has_tag(group, OWNER_TAG):
            self.ensure_fhrp_assignments(group, {(VM_IF, i) for i in map(self._vm_iface_id, vip.holders) if i})

    def _vm_iface_id(self, holder: tuple[str, str]) -> int | None:
        """(Proxmox VM name, interface) -> NetBox VM interface id, via the VMID (NetBox names can be locked)."""
        vm_name, iface_name = holder
        vmid = next((h.vm.vmid for h in self.d.hosts if h.vm is not None and h.vm.name == vm_name), None)
        vm = next((v for v in self.vms.values() if vmid is not None and v.custom_fields.get("vmid") == vmid), None)
        return next((i.id for i in self.vm_ifaces.values()
                     if vm and i.virtual_machine and i.virtual_machine.id == vm.id and i.name == iface_name), None)

    def ensure_fhrp_assignments(self, group: FhrpGroup, want: set[tuple[str, int]]) -> None:
        """Which interfaces hold the VIP right now (keepalived's MASTER), as FHRP group assignments."""
        have = {(a.interface_type, a.interface_id): a for a in self.fhrp_assignments
                if a.group and a.group.id == group.id}
        for otype, iid in sorted(want - set(have)):
            self.fhrp_assignments.append(self.nb.create("ipam/fhrp-group-assignments", {
                "group": group.id, "interface_type": otype, "interface_id": iid, "priority": FHRP_PRIORITY},
                model=FhrpGroupAssignment, write_model=FhrpGroupAssignmentWrite, what=f"{group.name} on {otype}:{iid}"))
        for key in set(have) - want:
            self.nb.delete("ipam/fhrp-group-assignments", have[key], what=f"{group.name} off {key[0]}:{key[1]}")
            self.fhrp_assignments.remove(have[key])

    def ensure_service(self, parent_type: str, parent_id: int, svc: SvcObs, ip_ids: list[int],
                       source: str = "k8s") -> None:
        found = [s for s in self.services if s.parent_object_type == parent_type
                 and s.parent_object_id == parent_id and s.name == svc.name]
        want = {"parent_object_type": parent_type, "parent_object_id": parent_id, "name": svc.name,
                "port_mappings": svc.port_mappings, "ipaddresses": [i for i in ip_ids if i > 0] or ip_ids,
                "description": svc.description[:200], "comments": svc.comments,
                "tags": _tags(found[0] if found else None, OWNER_TAG, SOURCE_TAGS[source])}
        if found:
            obj = self.nb.update("ipam/services", found[0], want, model=Service, write_model=ServiceWrite, what=svc.name)
        else:
            obj = self.nb.create("ipam/services", want, model=Service, write_model=ServiceWrite, what=svc.name)
            self.services.append(obj)
        self.touched["service"].add(obj.id)

    # ------------------------------------------------------------------ VM placement

    def place_vms(self) -> None:
        """Pin each VM to the hypervisor it runs on (Proxmox node -> NetBox device)."""
        for h in self.d.hosts:
            if h.vm is None:
                continue
            dev = self.host_dev.get(f"pve:{h.vm.node}")
            vm = next((v for v in self.vms.values() if v.custom_fields.get("vmid") == h.vm.vmid), None)
            if dev is None or vm is None or not _has_tag(vm, OWNER_TAG):
                continue
            self.vms[vm.id] = self.nb.update("virtualization/virtual-machines", vm,
                                             {"site": self.ctx.site_id, "device": dev.id}, model=VirtualMachine,
                                             write_model=VirtualMachineWrite, what=f"{vm.name} on {dev.name}")

    # ------------------------------------------------------------------ OPNsense: NAT, WireGuard, gateways

    def _wan_ip(self) -> IPAddress | None:
        """The firewall's public address (on its WAN interface)."""
        fw = self.ctx.firewall
        if not fw:
            return None
        fw_ifaces = {i.id for i in self.dev_ifaces.values() if i.device and i.device.id == fw.id}
        return next((ip for ip in self.ips.values() if ip.assigned_object_type == DEV_IF
                     and ip.assigned_object_id in fw_ifaces
                     and not ipaddress.ip_interface(ip.address).ip.is_private), None)

    def sync_opnsense_extras(self) -> None:
        wan = self._wan_ip()
        if self.d.port_forwards is not None and wan is not None and self.ctx.firewall:
            for pf in self.d.port_forwards:
                to = pf.target + (f":{pf.local_port}" if pf.local_port else "")
                self.ensure_service("dcim.device", self.ctx.firewall.id,
                                    SvcObs(name=f"forward: {pf.descr}"[:100], port_mappings=pf.port_mappings,
                                           description=f"port forward to {to}", source="opnsense"),
                                    [wan.id], source="opnsense")
            # One inside host behind every forward: the WAN address's NAT inside is that host
            targets = {pf.target for pf in self.d.port_forwards}
            inside = self.ips.get(next(iter(targets))) if len(targets) == 1 else None
            if _has_tag(wan, OWNER_TAG):
                self.ips[wan.address.split("/")[0]] = self.nb.update(
                    "ipam/ip-addresses", wan, {"nat_inside": inside.id if inside else None},
                    model=IPAddress, write_model=IPAddressWrite, what=f"{wan.address} NAT")
        if self.d.wg_peers is not None:
            for p in self.d.wg_peers:
                self._ensure_peer_ip(p)
        for ip, name in self.d.gateways.items():
            obj = self.ips.get(ip)
            # The ISP's subnet isn't a NetBox prefix: a gateway on the WAN shares the WAN address's mask
            wan_net = ipaddress.ip_interface(wan.address).network if wan else None
            plen = wan_net.prefixlen if wan_net and ipaddress.ip_address(ip) in wan_net else self._prefix_len(ip)
            want = {"address": f"{ip}/{plen}", "status": "active", **self._tenant(),
                    "tags": _tags(obj, OWNER_TAG, SOURCE_TAGS["opnsense"])}
            if not _has_tag(obj, LOCK_TAG):
                want["description"] = f"gateway {name}".strip()[:200]
            obj = self.nb.create("ipam/ip-addresses", want, model=IPAddress, write_model=IPAddressWrite, what=ip) \
                if obj is None else \
                self.nb.update("ipam/ip-addresses", obj, want, model=IPAddress, write_model=IPAddressWrite, what=ip)
            self.ips[ip] = obj
            self.touched["ip"].add(obj.id)
            self.present["ip"].add(obj.id)

    def _ensure_peer_ip(self, p) -> None:
        """A remote-access peer's tunnel address, unassigned (the far end isn't ours to model),
        with when it last handshook. Not seen for STALE_AFTER: deprecated."""
        seen = datetime.fromtimestamp(p.handshake, timezone.utc) if p.handshake else None
        recent = p.enabled and seen is not None and (self.now - seen).total_seconds() < STALE_AFTER
        obj = self.ips.get(p.address)
        want = {"address": f"{p.address}/{self._prefix_len(p.address)}", "status": "active" if recent else "deprecated",
                **self._tenant(), "tags": _tags(obj, OWNER_TAG, SOURCE_TAGS["opnsense"])}
        if not _has_tag(obj, LOCK_TAG):
            want["description"] = f"WireGuard {p.server} peer {p.name}"[:200]
        if seen:
            prev = _parse_ts((obj.custom_fields if obj else {}).get("last_seen"))
            if prev is None or abs((seen - prev).total_seconds()) >= LAST_SEEN_GRANULARITY.total_seconds():
                want["custom_fields"] = {"last_seen": seen.replace(microsecond=0).isoformat()}
        obj = self.nb.create("ipam/ip-addresses", want, model=IPAddress, write_model=IPAddressWrite, what=p.address) \
            if obj is None else \
            self.nb.update("ipam/ip-addresses", obj, want, model=IPAddress, write_model=IPAddressWrite, what=p.address)
        self.ips[p.address] = obj
        self.touched["ip"].add(obj.id)
        self.present["ip"].add(obj.id)          # its status is managed here, not by ageing

    # ------------------------------------------------------------------ cloud VMs (Binary Lane)

    def _cloud_cluster(self, provider: str, region: str):
        ctype = (self.nb.list("virtualization/cluster-types", model=ClusterType, slug="cloud") or
                 [self.nb.create("virtualization/cluster-types", {"name": "Cloud", "slug": "cloud"},
                                 model=ClusterType, write_model=ClusterTypeWrite)])[0]
        name = f"{provider} {region}".strip()
        return (self.nb.list("virtualization/clusters", model=Cluster, name=name) or
                [self.nb.create("virtualization/clusters", {
                    "name": name, "type": ctype.id, "status": "active", **self._tenant(),
                    "description": f"{provider} VPS, region {region}", "tags": [{"slug": OWNER_TAG}]},
                    model=Cluster, write_model=ClusterWrite)])[0]

    def sync_cloud(self) -> None:
        """VPSes as VMs in a per-provider/region cloud cluster: public addresses on eth0, private on
        eth1, and the WireGuard tunnel address of the peer that connects from its public address
        on wg0. Their Wazuh agents' listening ports become their services."""
        seen: dict[int, set[int]] = {}
        for cv in self.d.cloud_vms:
            cluster = self._cloud_cluster(cv.provider, cv.region)
            if cluster.id not in seen:
                seen[cluster.id] = set()
                if cluster.id > 0:
                    for i in self.nb.list("virtualization/interfaces", model=VMInterface, cluster_id=cluster.id):
                        self.vm_ifaces[i.id] = i
            vms = self.nb.list("virtualization/virtual-machines", model=VirtualMachine, cluster_id=cluster.id) \
                if cluster.id > 0 else []
            obj = next((v for v in vms if v.name.lower() == cv.name.lower()), None)
            h = Host(key=f"cloud:{cv.id}", kind="cloud-vm", present=cv.status == "active", sources={"binarylane"},
                     fqdn=cv.name if "." in cv.name else "")
            for cidr, _ in cv.ips:
                h.add_ip(cidr)
            want = {"cluster": cluster.id, "status": cv.status, "vcpus": cv.vcpus, "memory": cv.memory_mb,
                    "disk": cv.disk_mb, **self._tenant(),
                    "custom_fields": {"host_kind": "cloud-vm", **self._last_seen(obj, h.present)},
                    "tags": _tags(obj, OWNER_TAG, SOURCE_TAGS["binarylane"])}
            if cv.os:
                want["platform"] = self._platform(cv.os)
            if obj is None:
                obj = self.nb.create("virtualization/virtual-machines", {"name": cv.name, **want},
                                     model=VirtualMachine, write_model=VirtualMachineWrite, what=cv.name)
            else:
                obj = self.nb.update("virtualization/virtual-machines", obj, want, model=VirtualMachine,
                                     write_model=VirtualMachineWrite, what=cv.name)
            seen[cluster.id].add(obj.id)
            ifaces = {n: self.ensure_iface("vm", obj, n, None) for n in sorted({n for _, n in cv.ips})}
            primary = None
            for cidr, name in cv.ips:
                ip = self.ensure_ip(cidr.split("/")[0], h, "vm", ifaces[name])
                if primary is None and ip and ":" not in cidr:
                    primary = ip
            if primary:
                obj = self.nb.update("virtualization/virtual-machines", obj, {"primary_ip4": primary.id},
                                     model=VirtualMachine, write_model=VirtualMachineWrite, what=cv.name)
            # The peer last seen connecting from its public address is this VM's tunnel (an older
            # peer from the same address, e.g. a VPS rebuilt in place, isn't)
            public = {c.split("/")[0] for c, n in cv.ips if n == "eth0"}
            peer = max((p for p in self.d.wg_peers or [] if p.endpoint in public and p.handshake),
                       key=lambda p: p.handshake, default=None)
            wg_if = next((i for i in self.vm_ifaces.values()
                          if i.virtual_machine and i.virtual_machine.id == obj.id and i.name == "wg0"), None)
            if peer and self.ips.get(peer.address):
                wg_if = wg_if or self.ensure_iface("vm", obj, "wg0", None)
                self.ips[peer.address] = self.nb.update("ipam/ip-addresses", self.ips[peer.address], {
                    "assigned_object_type": VM_IF, "assigned_object_id": wg_if.id}, model=IPAddress,
                    write_model=IPAddressWrite, what=f"{peer.address} on {cv.name}/wg0")
            if wg_if is not None:
                for addr, ipo in list(self.ips.items()):
                    if ipo.assigned_object_type == VM_IF and ipo.assigned_object_id == wg_if.id \
                            and (peer is None or addr != peer.address) and _has_tag(ipo, OWNER_TAG):
                        self.ips[addr] = self.nb.update("ipam/ip-addresses", ipo, {
                            "assigned_object_type": None, "assigned_object_id": None}, model=IPAddress,
                            write_model=IPAddressWrite, what=f"{addr} off {cv.name}/wg0")
            short = cv.name.lower().split(".")[0]
            for ag in self.d.wazuh:
                if ag.name.lower().split(".")[0] == short:
                    for proc, pms in sorted(ag.listening.items()):
                        self.ensure_service("virtualization.virtualmachine", obj.id,
                                            SvcObs(name=proc[:100], port_mappings=sorted(pms), description="listening (Wazuh)",
                                                   source="wazuh"), [primary.id] if primary else [], source="wazuh")
        # Gone from the provider (even its last server): decommissioning
        listed = {i for ids in seen.values() for i in ids}
        for v in self.nb.list("virtualization/virtual-machines", model=VirtualMachine, tag=SOURCE_TAGS["binarylane"]):
            if v.id not in listed and _has_tag(v, OWNER_TAG) and _has_tag(v, SOURCE_TAGS["binarylane"]) \
                    and v.status != "decommissioning":
                self.nb.update("virtualization/virtual-machines", v, {"status": "decommissioning"}, model=VirtualMachine,
                               write_model=VirtualMachineWrite, what=f"{v.name} (gone)")

    # ------------------------------------------------------------------ services seen in NetFlow

    def sync_flow_services(self) -> None:
        """Ports LAN hosts answer on (source_flows), as NetBox services on the host, VM or VIP
        owning the address, unless a service already covers that port. One service per
        IANA name, so DNS on tcp+udp/53 is one 'domain' service."""
        parents = {DEV_IF: ("dcim.device", lambda i: (self.dev_ifaces.get(i).device.id if self.dev_ifaces.get(i) and self.dev_ifaces.get(i).device else None)),
                   VM_IF: ("virtualization.virtualmachine", lambda i: (self.vm_ifaces.get(i).virtual_machine.id if self.vm_ifaces.get(i) and self.vm_ifaces.get(i).virtual_machine else None)),
                   FHRP: (FHRP, lambda i: i)}
        covered: set[tuple[str, int | None, str]] = set()
        for s in self.services:
            if _has_tag(s, SOURCE_TAGS["flows"]):
                continue
            for pm in s.port_mappings or []:
                covered.add((s.parent_object_type, s.parent_object_id, pm))
                for ref in s.ipaddresses or []:
                    covered.add(("ip", ref.id, pm))
        groups: dict[tuple[str, int, str], tuple[set[str], int]] = {}
        for fs in self.d.flow_services:
            ip_obj = self.ips.get(fs.ip)
            ptype = ip_obj.assigned_object_type if ip_obj else None
            if ptype not in parents:
                continue      # an address without a host to hang a service on
            otype, pid = parents[ptype][0], parents[ptype][1](ip_obj.assigned_object_id)
            pm = f"{fs.proto}/{fs.port}"
            if pid is None or (otype, pid, pm) in covered or ("ip", ip_obj.id, pm) in covered:
                continue
            key = (otype, pid, fs.name or pm)
            pms, _ = groups.get(key, (set(), ip_obj.id))
            groups[key] = (pms | {pm}, ip_obj.id)
        touched = set()
        for (otype, pid, name), (pms, ip_id) in sorted(groups.items(), key=lambda kv: str(kv[0])):
            self.ensure_service(otype, pid, SvcObs(name=name, port_mappings=sorted(pms), description="seen in NetFlow"),
                                [ip_id], source="flows")
            touched |= {s.id for s in self.services if s.parent_object_type == otype
                        and s.parent_object_id == pid and s.name == name}
        for s in list(self.services):
            if _has_tag(s, SOURCE_TAGS["flows"]) and _has_tag(s, OWNER_TAG) and s.id not in touched and s.id > 0:
                self.nb.delete("ipam/services", s, what=f"{s.name} (no longer seen in NetFlow)")
                self.services.remove(s)

    # ------------------------------------------------------------------ ageing

    def _healthy_for(self, obj) -> bool:
        srcs = [src for src, tag in SOURCE_TAGS.items() if _has_tag(obj, tag)]
        return bool(srcs) and all(self.d.healthy.get(s, False) for s in srcs)

    def _age(self, obj) -> float | None:
        ts = _parse_ts(obj.custom_fields.get("last_seen")) or _parse_ts(obj.created)
        return (self.now - ts).total_seconds() if ts else None

    def age_out(self) -> None:
        deleted_ifaces: set[int] = set()
        for dev in list(self.devices.values()):
            if not _has_tag(dev, OWNER_TAG) or dev.id in self.present["device"]:
                continue
            kind = dev.custom_fields.get("host_kind") or "client"
            action = stale_action(False, self._age(dev), kind, self._healthy_for(dev))
            if action == "stale" and dev.status != "offline":
                self.nb.update("dcim/devices", dev, {"status": "offline"}, model=Device, write_model=DeviceWrite,
                               what=f"{dev.name} (stale)")
            elif action == "delete":
                for iface in [i for i in self.dev_ifaces.values() if i.device and i.device.id == dev.id]:
                    deleted_ifaces.add(iface.id)
                    cid = iface.cable.id if iface.cable else None
                    if cid and _has_tag(self.cables.get(cid), OWNER_TAG):
                        self._drop_cable(cid)   # NetBox would leave it dangling from the switch port
                    for m in [m for ms in self.macs.values() for m in ms
                              if m.assigned_object_type == DEV_IF and m.assigned_object_id == iface.id]:
                        self.nb.delete("dcim/mac-addresses", m, what=m.mac_address)
                for ip in [i for i in self.ips.values() if i.assigned_object_type == DEV_IF
                           and i.assigned_object_id in deleted_ifaces]:
                    self.nb.delete("ipam/ip-addresses", ip, what=ip.address)
                    self.touched["ip"].add(ip.id)       # handled
                self.nb.delete("dcim/devices", dev, what=f"{dev.name} (gone {DELETE_AFTER // DAY}d)")

        if self.d.healthy.get("proxmox"):
            for vm in self.vms.values():
                if _has_tag(vm, OWNER_TAG) and vm.id not in self.touched["vm"] \
                        and vm.status != "decommissioning":
                    self.nb.update("virtualization/virtual-machines", vm, {"status": "decommissioning"},
                                   model=VirtualMachine, write_model=VirtualMachineWrite,
                                   what=f"{vm.name} (gone from Proxmox)")

        for ip in self.ips.values():
            if not _has_tag(ip, OWNER_TAG) or ip.id in self.present["ip"] or ip.id < 0:
                continue
            if ip.assigned_object_id in deleted_ifaces:
                continue
            action = stale_action(False, self._age(ip), "ip", self._healthy_for(ip))
            if action == "stale" and ip.status != "deprecated":
                self.nb.update("ipam/ip-addresses", ip, {"status": "deprecated"}, model=IPAddress,
                               write_model=IPAddressWrite, what=f"{ip.address} (stale)")

        for src in ("k8s", "wazuh", "opnsense"):    # services a source describes in full each run
            if not self.d.healthy.get(src) or (src == "opnsense" and self.d.port_forwards is None):
                continue
            for svc in self.services:
                if _has_tag(svc, OWNER_TAG) and _has_tag(svc, SOURCE_TAGS[src]) \
                        and svc.id not in self.touched["service"] and svc.id > 0:
                    self.nb.delete("ipam/services", svc, what=svc.name)
