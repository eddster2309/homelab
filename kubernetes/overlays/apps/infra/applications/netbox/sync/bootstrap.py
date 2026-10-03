"""Idempotently create the NetBox scaffolding the sync relies on."""
from __future__ import annotations

from dataclasses import dataclass

from netbox_api import NetBox

OWNER_TAG = "netbox-sync"          # everything this job created/manages
LOCK_TAG = "sync-locked"           # set by hand: sync leaves names/descriptions alone
SOURCE_TAGS = {"opnsense": "sync-opnsense", "proxmox": "sync-proxmox", "k8s": "sync-k8s", "ipa": "sync-ipa",
               "omada": "sync-omada", "flows": "sync-flows", "metrics": "sync-metrics",
               "wazuh": "sync-wazuh", "frigate": "sync-frigate", "bmc": "sync-bmc",
               "homeassistant": "sync-homeassistant", "binarylane": "sync-binarylane"}
K8S_NODE_TAG = "k8s-node"
IPA_TAG = "ipa-enrolled"
PVE_TAG_PREFIX = "pve-"            # Proxmox VM tags, mirrored onto the VM (created on demand)

TAGS = {
    OWNER_TAG: ("netbox-sync", "9e9e9e", "Managed by the netbox-sync CronJob"),
    LOCK_TAG: ("sync-locked", "f44336", "netbox-sync must not change this object's name/description"),
    "sync-opnsense": ("source: opnsense", "ff9800", ""),
    "sync-proxmox": ("source: proxmox", "e65100", ""),
    "sync-k8s": ("source: kubernetes", "2196f3", ""),
    "sync-ipa": ("source: ipa", "4caf50", ""),
    "sync-omada": ("source: omada", "00897b", ""),
    "sync-flows": ("source: netflow", "795548", "Seen answering on this port in NetFlow"),
    "sync-metrics": ("source: metrics", "9c27b0", "Hardware from the host's node metrics"),
    "sync-wazuh": ("source: wazuh", "3f51b5", "From the host's Wazuh agent inventory"),
    "sync-frigate": ("source: frigate", "ff5722", "Camera name from Frigate"),
    "sync-bmc": ("source: bmc", "607d8b", "From the server's BMC (Redfish)"),
    "sync-homeassistant": ("source: home assistant", "03a9f4", "From Home Assistant's device registry"),
    "sync-binarylane": ("source: binary lane", "673ab7", "Binary Lane VPS"),
    K8S_NODE_TAG: ("k8s-node", "326ce5", "Kubernetes node"),
    IPA_TAG: ("ipa-enrolled", "4caf50", "Enrolled in FreeIPA"),
}

HOST_TYPES = ["dcim.device", "virtualization.virtualmachine"]
CUSTOM_FIELDS = [
    # name, type, object types, label
    ("last_seen", "datetime", HOST_TYPES + ["ipam.ipaddress"], "Last seen"),
    ("host_kind", "text", HOST_TYPES, "Host kind"),
    ("vendor", "text", ["dcim.device"], "Vendor (OUI)"),
    ("randomized_mac", "boolean", ["dcim.device"], "Randomized MAC"),
    ("vmid", "integer", ["virtualization.virtualmachine"], "Proxmox VMID"),
    ("connection", "text", ["dcim.device"], "Connection (Omada)"),
    ("firmware", "text", ["dcim.device"], "Firmware"),
]

# kind -> (device role slug, role name, colour)
ROLES = {
    "client": ("client", "Client", "9e9e9e"),
    "hypervisor": ("hypervisor", "Hypervisor", "e65100"),
    "network": ("network", "Network", "00897b"),
    "camera": ("camera", "Camera", "ff5722"),
    "server": ("server", "Server", "3f51b5"),
}


@dataclass
class Ctx:
    site_id: int
    cluster_id: int
    roles: dict[str, int]          # role slug -> id
    device_types: dict[str, int]   # role slug -> device type id
    firewall: dict | None
    tenant_id: int | None = None   # the site's tenant: given to everything the sync creates
    vlan_group_id: int | None = None   # the site's VLAN group (Terraform names it after the site slug)
    k8s_cluster_id: int = 0        # Kubernetes cluster, for k8s nodes that are physical devices


def _ensure(nb: NetBox, path: str, lookup: dict, data: dict) -> dict:
    found = nb.list(path, **lookup)
    return found[0] if found else nb.create(path, data)


def bootstrap(nb: NetBox, site_slug: str, cluster_name: str, firewall_name: str,
              k8s_cluster_name: str = "k8s-jack-cbr") -> Ctx:
    for slug, (name, color, desc) in TAGS.items():
        _ensure(nb, "extras/tags", {"slug": slug}, {"name": name, "slug": slug, "color": color, "description": desc})

    for name, typ, types, label in CUSTOM_FIELDS:
        cf = _ensure(nb, "extras/custom-fields", {"name": name},
                     {"name": name, "label": label, "type": typ, "object_types": types,
                      "ui_editable": "yes", "group_name": "netbox-sync"})
        missing = sorted(set(types) - set(cf.get("object_types", [])))
        if missing:
            nb.update("extras/custom-fields", cf, {"object_types": sorted(set(cf["object_types"]) | set(types))})

    sites = nb.list("dcim/sites", slug=site_slug)
    if not sites:
        raise RuntimeError(f"site {site_slug!r} not found in NetBox")
    site_id = sites[0]["id"]
    tenant_id = (sites[0].get("tenant") or {}).get("id")
    groups = nb.list("ipam/vlan-groups", slug=site_slug)

    manu = _ensure(nb, "dcim/manufacturers", {"slug": "generic"}, {"name": "Generic", "slug": "generic"})
    roles, types = {}, {}
    for slug, name, color in ROLES.values():
        roles[slug] = _ensure(nb, "dcim/device-roles", {"slug": slug},
                              {"name": name, "slug": slug, "color": color})["id"]
        types[slug] = _ensure(nb, "dcim/device-types", {"slug": f"generic-{slug}"},
                              {"manufacturer": manu["id"], "model": f"Generic {name}",
                               "slug": f"generic-{slug}", "u_height": 0})["id"]

    ctype = _ensure(nb, "virtualization/cluster-types", {"slug": "proxmox"}, {"name": "Proxmox", "slug": "proxmox"})
    tenant = {"tenant": tenant_id} if tenant_id else {}
    cluster = _ensure(nb, "virtualization/clusters", {"name": cluster_name},
                      {"name": cluster_name, "type": ctype["id"], "status": "active",
                       "scope_type": "dcim.site", "scope_id": site_id, **tenant})
    k8s_type = _ensure(nb, "virtualization/cluster-types", {"slug": "kubernetes"},
                       {"name": "Kubernetes", "slug": "kubernetes"})
    k8s = _ensure(nb, "virtualization/clusters", {"name": k8s_cluster_name},
                  {"name": k8s_cluster_name, "type": k8s_type["id"], "status": "active",
                   "scope_type": "dcim.site", "scope_id": site_id, **tenant,
                   "tags": [{"slug": OWNER_TAG}, {"slug": SOURCE_TAGS["k8s"]}]})

    fw = nb.list("dcim/devices", name=firewall_name)
    return Ctx(site_id=site_id, cluster_id=cluster["id"], roles=roles, device_types=types,
               firewall=fw[0] if fw else None, tenant_id=tenant_id,
               vlan_group_id=groups[0]["id"] if groups else None, k8s_cluster_id=k8s["id"])
