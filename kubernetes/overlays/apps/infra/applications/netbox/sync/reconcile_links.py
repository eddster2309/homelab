"""Omada network topology: switch ports and AP radios as interfaces, wired clients as
cables to their switch port, Wi-Fi clients as members of their SSID's wireless LAN.

Split out of reconcile.py: this is a self-contained subsystem (Omada-derived
physical/wireless topology) with minimal coupling to the rest of the
Reconciler beyond self.mac_iface/self.host_dev/self.dev_ifaces, all built
during host sync.
"""
from __future__ import annotations

import logging

from bootstrap import OWNER_TAG, SOURCE_TAGS
from model import Link, OmadaDevice
from nb_models import Cable, Device, FK, Interface, WirelessLan
from nb_write import CableWrite, DeviceWrite, InterfaceWrite, WirelessLanWrite
from reconcile_common import DEV_IF, RADIO_LABELS, WIFI_TYPES, WIRED_TYPE, _ap_radio_type, _has_tag, _is_wireless_type, _link_state

log = logging.getLogger("reconcile")


class LinksMixin:
    def sync_links(self) -> None:
        """Switch ports and AP radios as interfaces, wired clients as cables to their switch
        port, Wi-Fi clients as members of their SSID's wireless LAN.

        NetBox wireless links are point-to-point (one per interface), so an AP radio can't
        link to every client: Wi-Fi is modelled as wireless-LAN membership, with the AP and
        band in the client interface's description. Only cables tagged netbox-sync are ever
        moved or deleted; a hand-made cable on either end wins and the link is skipped.
        """
        ports: dict[tuple[str, int], Interface] = {}
        port_cfg: dict[tuple[str, int], object] = {}
        radios: dict[str, dict[int, Interface]] = {}
        for od in self.d.omada_devices:
            dev = self.mac_iface.get(od.mac, (None, None))[0]
            if dev is None:
                continue
            if od.type == "switch":
                for p in od.ports:
                    ports[(od.mac, p.num)] = self._ensure_port(dev, p)
                    port_cfg[(od.mac, p.num)] = p
            elif od.type == "ap":
                used = {ln.radio for h in self.d.hosts for ln in h.links if ln.peer_mac == od.mac and ln.wireless}
                radios[od.mac] = {r: self._ensure_radio(dev, od, r) for r in sorted({0, 1} | (used & set(RADIO_LABELS)))}

        ssid_vids: dict[str, dict[int, int]] = {}
        for h in self.d.hosts:
            for ln in h.links:
                if ln.wireless and ln.vid:
                    counts = ssid_vids.setdefault(ln.ssid, {})
                    counts[ln.vid] = counts.get(ln.vid, 0) + 1
        for ssid, counts in sorted(ssid_vids.items()):
            self._ensure_wlan(ssid, max(counts, key=counts.get))
        for ap_radios in radios.values():   # every AP broadcasts every SSID; sticky so quiet SSIDs don't flap
            for r, iface in ap_radios.items():
                have = [w.id for w in iface.wireless_lans]
                want = sorted(set(have) | {w.id for w in self.wlans.values()})
                ap_radios[r] = self._update_iface(iface, {"wireless_lans": want})

        for h in self.d.hosts:
            texts = []
            for ln in h.links:
                peer = self.mac_iface.get(ln.peer_mac, (None, None))[0]
                peer_name = peer.name if peer else ln.peer_mac
                if ln.wireless:
                    band = RADIO_LABELS.get(ln.radio, f"radio{ln.radio}")
                    texts.append(f"wifi {ln.ssid} @ {peer_name} {band}".strip())
                else:
                    texts.append(f"switch {peer_name}" + (f" port {ln.port}" if ln.port is not None else ""))
                dev, iface = self.mac_iface.get(ln.mac, (None, None))
                if ln.local_port is not None:
                    # switch to switch: port to port, not the downstream switch's management interface
                    iface = ports.get((ln.mac, ln.local_port))
                elif ln.iface:
                    # by name (a bridge's uplink): the physical NIC beneath it
                    dev = self.host_dev.get(h.key)
                    name = self._cable_end(h, ln.iface)
                    iface = next((i for i in self.dev_ifaces.values()
                                  if dev and i.device and i.device.id == dev.id and i.name == name), None)
                if iface is None:
                    continue    # a VM (shares its hypervisor's port) or not a device
                try:
                    if ln.wireless:
                        self._wifi_member(iface, ln, peer_name)
                    elif ln.port is not None and (ln.peer_mac, ln.port) in ports:
                        self._ensure_cable(iface, ports[(ln.peer_mac, ln.port)], what=f"{dev.name} <-> {peer_name}:{ln.port}")
                        if ln.local_port is not None:
                            continue    # both ends are switch ports: their VLANs and speeds come from Omada
                        port = port_cfg[(ln.peer_mac, ln.port)]
                        cfg = self._port_vlans(port)
                        mine = self.dev_ifaces.get(iface.id, iface)
                        want = {}
                        if cfg["mode"] == "access" and mine.id not in self.spec_mode_ifaces:
                            want.update(mode="access", untagged_vlan=cfg["untagged_vlan"])
                        if port.up is not None:     # the device's end negotiated what the switch port did
                            want.update(_link_state(port))
                        if want and _has_tag(mine, OWNER_TAG):
                            self._update_iface(mine, want)
                except Exception as e:
                    log.error("link %s -> %s: %s", dev.name, peer_name, e)
            dev = self.host_dev.get(h.key)
            if dev is not None and texts and _has_tag(self.devices.get(dev.id), OWNER_TAG):
                cur = self.devices[dev.id]
                self.devices[dev.id] = self.nb.update(
                    "dcim/devices", cur, {"custom_fields": {"connection": "; ".join(texts)[:200]}},
                    model=Device, write_model=DeviceWrite, what=f"{cur.name} connection")

    def _update_iface(self, iface: Interface, want: dict) -> Interface:
        iface = self.nb.update("dcim/interfaces", self.dev_ifaces.get(iface.id, iface), want, model=Interface,
                               write_model=InterfaceWrite,
                               what=f"{(iface.device.name or '') if iface.device else ''}/{iface.name}")
        self.dev_ifaces[iface.id] = iface
        return iface

    def _dev_iface(self, dev: Device, name: str, data: dict) -> Interface:
        found = [i for i in self.dev_ifaces.values() if i.device and i.device.id == dev.id and i.name == name]
        if found:
            return self._update_iface(found[0], data) if _has_tag(found[0], OWNER_TAG) else found[0]
        iface = self.nb.create("dcim/interfaces", {"device": dev.id, "name": name, **data,
                                                   "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["omada"]}]},
                               model=Interface, write_model=InterfaceWrite, what=f"{dev.name}/{name}")
        self.dev_ifaces[iface.id] = iface
        return iface

    def _vlan_id(self, vid: int | None) -> int | None:
        return next((v.id for v in self.vlans if v.vid == vid), None) if vid else None

    def _port_vlans(self, p) -> dict:
        """802.1Q settings for a switch port from its Omada profile. VLANs NetBox doesn't
        have (Omada's default VLAN 1) are left out."""
        if p.profile == "Disable" or (p.untagged is None and not p.tagged):
            return {"mode": None, "untagged_vlan": None, "tagged_vlans": []}
        untagged = self._vlan_id(p.untagged)
        if p.tagged_all:
            return {"mode": "tagged-all", "untagged_vlan": untagged, "tagged_vlans": []}
        if p.tagged:
            return {"mode": "tagged", "untagged_vlan": untagged,
                    "tagged_vlans": sorted(i for i in map(self._vlan_id, p.tagged) if i)}
        return {"mode": "access", "untagged_vlan": untagged, "tagged_vlans": []}

    def _ensure_port(self, dev: Device, p) -> Interface:
        label = p.name if p.name and p.name != f"Port{p.num}" else ""
        name = f"1/0/{p.num}"
        exists = any(i.device and i.device.id == dev.id and i.name == name for i in self.dev_ifaces.values())
        # type only from the web API (or a new port's default): without it, keep what NetBox has
        typ = {"type": p.type} if p.type else ({} if exists else {"type": "1000base-t"})
        return self._dev_iface(dev, name, {
            **typ, "label": label[:64], "description": f"profile {p.profile}"[:200] if p.profile else "",
            "enabled": p.profile != "Disable", **self._port_vlans(p),
            **(_link_state(p) if p.up is not None else {})})

    def _ensure_radio(self, dev: Device, od: OmadaDevice, radio: int) -> Interface:
        return self._dev_iface(dev, f"radio{radio}", {
            "type": _ap_radio_type(od.model), "label": RADIO_LABELS[radio], "rf_role": "ap"})

    def _ensure_wlan(self, ssid: str, vid: int) -> None:
        vlan = next((v for v in self.vlans if v.vid == vid), None)
        want = {"ssid": ssid, "status": "active", **({"vlan": vlan.id} if vlan else {})}
        w = self.wlans.get(ssid)
        if w is None:
            self.wlans[ssid] = self.nb.create("wireless/wireless-lans", {
                **want, **self._tenant(), "scope_type": "dcim.site", "scope_id": self.ctx.site_id,
                "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["omada"]}]}, model=WirelessLan,
                write_model=WirelessLanWrite, what=ssid)
        elif _has_tag(w, OWNER_TAG):
            self.wlans[ssid] = self.nb.update("wireless/wireless-lans", w, {**want, **self._tenant()},
                                              model=WirelessLan, write_model=WirelessLanWrite, what=ssid)

    def _cable_ok_to_drop(self, cable_id: int | None) -> bool:
        """A cable on an interface we're about to (re)link: drop it if it's ours, else leave everything."""
        if not cable_id:
            return True
        cable = self.cables.get(cable_id)
        return cable is None or _has_tag(cable, OWNER_TAG)

    def _drop_cable(self, cable_id: int) -> None:
        cable = self.cables.pop(cable_id, None) or {"id": cable_id}
        self.nb.delete("dcim/cables", cable, what=f"cable {cable_id}")
        for i in self.dev_ifaces.values():
            if i.cable and i.cable.id == cable_id:
                i.cable = None

    def _ensure_cable(self, a: Interface, b: Interface, what: str) -> None:
        a, b = self.dev_ifaces.get(a.id, a), self.dev_ifaces.get(b.id, b)
        ca, cb = (a.cable.id if a.cable else None), (b.cable.id if b.cable else None)
        if ca and ca == cb:
            return
        if not (self._cable_ok_to_drop(ca) and self._cable_ok_to_drop(cb)):
            log.info("%s: a hand-made cable is in the way; leaving it", what)
            return
        if _is_wireless_type(a.type):   # was on Wi-Fi: make it a wired interface again
            a = self._update_iface(a, {"type": WIRED_TYPE, "rf_role": "", "wireless_lans": [], "description": ""})
        for cid in {ca, cb} - {None}:
            self._drop_cable(cid)
        cable = self.nb.create("dcim/cables", {
            "a_terminations": [{"object_type": DEV_IF, "object_id": a.id}],
            "b_terminations": [{"object_type": DEV_IF, "object_id": b.id}],
            "status": "connected", "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["omada"]}]},
            model=Cable, write_model=CableWrite, what=what)
        self.cables[cable.id] = cable
        for i in (a, b):
            i.cable = FK(id=cable.id)
            self.dev_ifaces[i.id] = i

    def _wifi_member(self, iface: Interface, ln: Link, ap_name: str) -> None:
        iface = self.dev_ifaces.get(iface.id, iface)
        if not _has_tag(iface, OWNER_TAG):
            return
        cid = iface.cable.id if iface.cable else None
        if cid:
            if not self._cable_ok_to_drop(cid):
                return
            self._drop_cable(cid)
        wlan = self.wlans.get(ln.ssid)
        self._update_iface(iface, {
            "type": WIFI_TYPES.get(ln.wifi_mode, "other-wireless"), "rf_role": "station",
            "mode": None, "untagged_vlan": None,     # the SSID's wireless LAN carries the VLAN
            "wireless_lans": [wlan.id] if wlan else [],
            "description": f"{ap_name} {RADIO_LABELS.get(ln.radio, f'radio{ln.radio}')}".strip()})
