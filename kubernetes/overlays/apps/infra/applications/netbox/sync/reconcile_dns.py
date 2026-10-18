"""DNS (netbox-dns plugin): FreeIPA's zones mirrored into NetBox, plus the handoff to
the DNSsync plugin for address records derived from hosts' own dns_name.

Split out of reconcile.py: this is a self-contained subsystem (its own NetBox
sub-API under plugins/netbox-dns) with minimal coupling to the rest of the
Reconciler beyond self.prefixes and self.d.hosts/dns_zones.
"""
from __future__ import annotations

import ipaddress
import logging

from bootstrap import OWNER_TAG, SOURCE_TAGS
from nb_models import DnsNameserver, DnsRecord
from nb_models import DnsZone as NbDnsZone
from nb_models import DnsView
from nb_write import DnsNameserverWrite, DnsRecordWrite, DnsViewWrite
from nb_write import DnsZoneWrite as NbDnsZoneWrite
from reconcile_common import _has_tag

log = logging.getLogger("reconcile")


class DnsMixin:
    DNS = "plugins/netbox-dns"

    @staticmethod
    def _rkey(name: str, rtype: str, value: str) -> tuple[str, str, str]:
        return (name.lower().rstrip("."), str(rtype).upper(), value.lower().rstrip("."))

    def _dnssync_names(self) -> set[tuple[str, str]]:
        """(fqdn, ip) pairs DNSsync owns: every host whose single address carries its FQDN."""
        return {(h.fqdn.lower().rstrip("."), ip) for h in self.d.hosts if h.fqdn and len(h.ips) == 1 for ip in h.ips}

    def _dns_loaded(self) -> bool:
        if not hasattr(self, "dns_zones"):
            try:
                self.dns_views = self.nb.list(f"{self.DNS}/views", model=DnsView)
            except RuntimeError:
                self.dns_zones = None                   # plugin not installed
                return False
            self.dns_zones = self.nb.list(f"{self.DNS}/zones", model=NbDnsZone)
            self.dns_records = self.nb.list(f"{self.DNS}/records", model=DnsRecord)
        return self.dns_zones is not None

    def dns_prepass(self) -> None:
        """Before IPs are saved: drop our plain address records that DNSsync is about to own,
        or the plugin refuses the IP update as a duplicate."""
        if not self._dns_loaded():
            return
        zones = {z.id: z.name.rstrip(".").lower() for z in self.dns_zones}
        owned = self._dnssync_names()
        for r in list(self.dns_records):
            if r.managed or not _has_tag(r, OWNER_TAG) or r.type not in ("A", "AAAA"):
                continue
            zone = zones.get(r.zone.id if r.zone else None, "")
            fqdn = zone if r.name == "@" else f"{r.name}.{zone}".lower()
            if (fqdn, r.value) in owned:
                self.nb.delete(f"{self.DNS}/records", r, what=f"{fqdn} {r.value} (DNSsync's now)")
                self.dns_records.remove(r)

    def sync_dns(self) -> None:
        """FreeIPA's zones in netbox-dns. Host addresses come from DNSsync (the LAN prefixes are in the
        default view, so each IP's dns_name makes a linked A/AAAA record, and a PTR where the reverse
        zone exists); IPA's other records (aliases, CNAME, SRV, MX) are mirrored as plain records."""
        if not self._dns_loaded():
            return
        view = next((v for v in self.dns_views if v.default_view), self.dns_views[0] if self.dns_views else None)
        if view is None:
            return
        # Nameservers (SOA MNAME)
        ns_have = {n.name.rstrip(".").lower(): n for n in self.nb.list(f"{self.DNS}/nameservers", model=DnsNameserver)}
        ns_ids = {}
        for mname in sorted({z.mname for z in self.d.dns_zones if z.mname}):
            ns = ns_have.get(mname.lower()) or self.nb.create(f"{self.DNS}/nameservers", {
                "name": mname, "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["ipa"]}]},
                model=DnsNameserver, write_model=DnsNameserverWrite, what=mname)
            ns_ids[mname] = ns.id
        # Zones
        have = {z.name.rstrip(".").lower(): z for z in self.dns_zones}
        zone_ids: dict[str, int] = {}
        for z in self.d.dns_zones:
            # The plugin wants the SOA contact's domain to have 2+ labels: IPA's default for a
            # single-label zone ("hostmaster.internal") fails, so use the nameserver's domain then.
            rname = z.rname if z.rname.split(".", 1)[-1].count(".") else \
                f"{z.rname.split('.', 1)[0]}.{z.mname.split('.', 1)[-1]}" if "." in z.mname else z.rname
            want = {"name": z.name, "view": view.id, "status": "active",
                    "nameservers": [ns_ids[z.mname]] if z.mname in ns_ids else [],
                    "soa_rname": rname, **({"soa_mname": ns_ids[z.mname]} if z.mname in ns_ids else {}),
                    **{f"soa_{k}": v for k, v in (("refresh", z.refresh), ("retry", z.retry), ("expire", z.expire),
                                                    ("minimum", z.minimum)) if v},
                    **({"default_ttl": z.default_ttl} if z.default_ttl else {}), **self._tenant(),
                    "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["ipa"]}]}
            obj = have.get(z.name.lower())
            try:
                if obj is None:
                    obj = self.nb.create(f"{self.DNS}/zones", want, model=NbDnsZone, write_model=NbDnsZoneWrite,
                                         what=z.name)
                    self.dns_zones.append(obj)
                elif _has_tag(obj, OWNER_TAG):
                    obj = self.nb.update(f"{self.DNS}/zones", obj, want, model=NbDnsZone, write_model=NbDnsZoneWrite,
                                         what=z.name)
            except RuntimeError as e:              # one zone NetBox refuses mustn't stop the rest
                log.error("dns zone %s: %s", z.name, e)
                continue
            zone_ids[z.name.lower()] = obj.id
        wanted_zones = {z.name.lower() for z in self.d.dns_zones}
        for name, obj in list(have.items()):
            if name not in wanted_zones and _has_tag(obj, OWNER_TAG):
                self.nb.delete(f"{self.DNS}/zones", obj, what=f"{name} (gone from IPA)")
        # DNSsync: the LAN prefixes in the default view (added to, never taken from)
        lan = {p.id for p in self.prefixes if p.id > 0 and ipaddress.ip_network(p.prefix).is_private
               and not any(p.prefix == c for c in ("REDACTED_IP/16", "REDACTED_IP/16"))}
        cur = {x.id for x in view.prefixes}
        if lan - cur:
            self.nb.update(f"{self.DNS}/views", view, {"prefixes": sorted(cur | lan)}, model=DnsView,
                           write_model=DnsViewWrite, what=f"view {view.name} prefixes")
            self.dns_records = self.nb.list(f"{self.DNS}/records", model=DnsRecord)   # DNSsync just made records
        # Plain records: everything IPA has that DNSsync doesn't produce
        exists = {(r.zone.id,) + self._rkey(r.name, r.type, r.value): r
                  for r in self.dns_records if r.zone}
        dnssync = self._dnssync_names()
        wanted: set[tuple] = set()
        for z in self.d.dns_zones:
            zid = zone_ids.get(z.name.lower())
            if not zid:
                continue
            for name, rtype, value in z.records:
                fqdn = z.name.lower() if name == "@" else f"{name}.{z.name}".lower()
                if rtype in ("A", "AAAA") and (fqdn, value) in dnssync:
                    continue
                key = (zid,) + self._rkey(name, rtype, value)
                wanted.add(key)
                # link to the underlying IPAM IP (e.g. a shared k8s LB VIP) so the NetBox UI
                # shows the relation even though this record isn't DNSsync's own
                ip_obj = self.ips.get(value) if rtype in ("A", "AAAA") else None
                obj = exists.get(key)
                if obj is not None:
                    if ip_obj and _has_tag(obj, OWNER_TAG) and (obj.ipam_ip_address.id if obj.ipam_ip_address else None) != ip_obj.id:
                        try:
                            self.nb.update(f"{self.DNS}/records", obj, {"ipam_ip_address": ip_obj.id},
                                           model=DnsRecord, write_model=DnsRecordWrite,
                                           what=f"{fqdn} {rtype} {value} (ipam link)")
                        except RuntimeError as e:
                            log.error("dns record %s %s %s: %s", fqdn, rtype, value, e)
                    continue
                try:
                    created = self.nb.create(f"{self.DNS}/records", {
                        "zone": zid, "name": name, "type": rtype, "value": value, "status": "active",
                        **({"ipam_ip_address": ip_obj.id} if ip_obj else {}),
                        # aliases (ingress names on a VIP): only a host's own name should answer reverse lookups
                        **({"disable_ptr": True} if rtype in ("A", "AAAA") else {}),
                        "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["ipa"]}]},
                        model=DnsRecord, write_model=DnsRecordWrite, what=f"{fqdn} {rtype} {value}")
                    self.dns_records.append(created)
                    exists[key] = created
                except RuntimeError as e:
                    log.error("dns record %s %s %s: %s", fqdn, rtype, value, e)
        for r in list(self.dns_records):
            if r.managed or not _has_tag(r, OWNER_TAG) or not r.zone:
                continue
            if (r.zone.id,) + self._rkey(r.name, r.type, r.value) not in wanted and r.zone.id in zone_ids.values():
                self.nb.delete(f"{self.DNS}/records", r, what=f"{r.name} {r.value} (gone from IPA)")
                self.dns_records.remove(r)
