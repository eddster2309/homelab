"""netbox-sync: OPNsense + Proxmox + Kubernetes + FreeIPA -> NetBox -> ClickHouse.

  main.py [--dry-run] [--sources opnsense,proxmox,k8s,ipa,omada,flows,metrics,wazuh,frigate,bmc,homeassistant,binarylane] [--no-export]

A source that fails is logged and marked unhealthy; nothing it owns is aged
out on that run. The job exits non-zero if any source or NetBox itself failed,
so a broken credential shows up as a failed Job rather than silent drift.
"""
from __future__ import annotations

import argparse
import importlib
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bootstrap import bootstrap  # noqa: E402
from export import export  # noqa: E402
from merge import merge  # noqa: E402
from model import Collected  # noqa: E402
from netbox_api import NetBox  # noqa: E402
from reconcile import Reconciler  # noqa: E402

SOURCES = {"opnsense": "source_opnsense", "proxmox": "source_proxmox", "k8s": "source_kubernetes", "ipa": "source_ipa",
           "omada": "source_omada", "flows": "source_flows", "metrics": "source_metrics",
           "wazuh": "source_wazuh", "frigate": "source_frigate",
           "bmc": "source_bmc", "homeassistant": "source_homeassistant",
           "binarylane": "source_binarylane"}
log = logging.getLogger("netbox-sync")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    default=os.environ.get("SYNC_DRY_RUN", "").lower() in ("1", "true", "yes"),
                    help="log planned NetBox writes, write nothing (env SYNC_DRY_RUN)")
    ap.add_argument("--sources", default=os.environ.get("SYNC_SOURCES", ",".join(SOURCES)))
    ap.add_argument("--no-export", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)-7s %(name)-10s %(message)s")

    c = Collected()
    for name in [s.strip() for s in args.sources.split(",") if s.strip()]:
        t = time.monotonic()
        try:
            importlib.import_module(SOURCES[name]).collect(c)
            c.healthy[name] = True
            log.info("source %-8s ok (%.1fs)", name, time.monotonic() - t)
        except Exception as e:
            c.healthy[name] = False
            log.error("source %-8s FAILED: %s", name, e)
    log.info("collected: %d arp, %d leases, %d static names, %d fw ifaces, %d vlans, %d pve nodes, %d vms, "
             "%d k8s nodes, %d vips, %d ext services, %d ipa names, %d omada clients, %d omada devices, "
             "%d dhcp ranges, %s flow services, %d hardware, %d lb pools, %d wazuh agents, %d cameras, %d bmcs, %d ha devices, %d cloud vms",
             len(c.arp), len(c.leases), len(c.static_names), len(c.fw_interfaces), len(c.vlans), len(c.pve_nodes),
             len(c.vms), len(c.k8s_nodes), len(c.vips), len(c.ext_services), len(c.ipa_names), len(c.omada_clients),
             len(c.omada_devices), len(c.dhcp_ranges),
             "skipped" if c.flow_services is None else len(c.flow_services), len(c.hardware), len(c.lb_pools), len(c.wazuh), len(c.cameras), len(c.bmcs), len(c.ha_devices), len(c.cloud_vms))

    firewall = os.environ.get("FIREWALL_NAME", "jack-cbr-fw01")
    desired = merge(c, firewall)
    kinds: dict[str, int] = {}
    for h in desired.hosts:
        kinds[h.kind] = kinds.get(h.kind, 0) + 1
    log.info("merged: %d hosts %s, %d vips, %d prefixes", len(desired.hosts), kinds, len(desired.vips),
             len(desired.prefixes))

    nb = NetBox(os.environ["NETBOX_URL"], os.environ["NETBOX_TOKEN"], dry_run=args.dry_run)
    ctx = bootstrap(nb, os.environ.get("SITE_SLUG", "jack-cbr"), os.environ.get("PVE_CLUSTER", "pve-jack-cbr"), firewall,
                    os.environ.get("K8S_CLUSTER", "k8s-jack-cbr"))
    Reconciler(nb, ctx, desired).run()
    log.info("netbox writes%s: %s", " (dry-run, not applied)" if args.dry_run else "", nb.writes)

    if not args.no_export:
        export(nb, args.dry_run, c.fw_interfaces)
    return 0 if all(c.healthy.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
