"""Binary Lane (VPS provider): its servers as cloud VMs (edge01).

BINARYLANE_TOKEN is the account's API token (shared with the garage repo's
Terraform); only GET /v2/servers is used.
"""
from __future__ import annotations

import ipaddress
import os

import requests

from model import CloudVm, Collected, platform_name

STATUS = {"active": "active", "off": "offline", "new": "planned", "archive": "decommissioning"}


def cloud_vms(servers: list[dict]) -> list[CloudVm]:
    out = []
    for sv in servers:
        ips = []
        for fam in ("v4", "v6"):
            for n in (sv.get("networks") or {}).get(fam) or []:
                addr, mask = n.get("ip_address"), n.get("netmask")
                if not addr:
                    continue
                plen = mask if isinstance(mask, int) else ipaddress.ip_network(f"REDACTED_IP/{mask}").prefixlen if mask else 32
                iface = ipaddress.ip_interface(f"{addr}/{plen}")
                if iface.ip == iface.network.network_address and iface.network.num_addresses > 2:
                    continue                  # a routed prefix delegated to the server, not an address
                ips.append((f"{addr}/{plen}", "eth0" if n.get("type") == "public" else "eth1"))
        image = sv.get("image") or {}
        out.append(CloudVm(
            provider="Binary Lane", id=int(sv["id"]), name=sv["name"], region=(sv.get("region") or {}).get("slug", ""),
            status=STATUS.get(sv.get("status", ""), "active"), vcpus=float(sv.get("vcpus") or 0) or None,
            memory_mb=int(sv.get("memory") or 0) or None, disk_mb=int(sv.get("disk") or 0) * 1024 or None,
            os=platform_name(image.get("full_name") or image.get("name") or image.get("distribution") or ""), ips=ips))
    return out


def collect(c: Collected) -> None:
    r = requests.get("https://api.binarylane.com.au/v2/servers", params={"per_page": 200}, timeout=30,
                     headers={"Authorization": f"Bearer {os.environ['BINARYLANE_TOKEN']}"})
    if r.status_code != 200:
        raise RuntimeError(f"Binary Lane: {r.status_code} {r.text[:200]}")
    c.cloud_vms = cloud_vms(r.json().get("servers") or [])
