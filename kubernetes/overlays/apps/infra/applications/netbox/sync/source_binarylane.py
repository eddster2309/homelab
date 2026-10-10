"""Binary Lane (VPS provider): its servers as cloud VMs (edge01).

BINARYLANE_TOKEN is the account's API token (shared with the garage repo's
Terraform); only GET /v2/servers is used.
"""
from __future__ import annotations

import ipaddress
import logging
import os

import requests
from pydantic import BaseModel, ValidationError

from model import CloudVm, Collected, platform_name

log = logging.getLogger("binarylane")
STATUS = {"active": "active", "off": "offline", "new": "planned", "archive": "decommissioning"}


class NetworkRaw(BaseModel):
    ip_address: str | None = None
    netmask: int | str | None = None
    type: str = ""


class ImageRaw(BaseModel):
    full_name: str = ""
    name: str = ""
    distribution: str = ""


class RegionRaw(BaseModel):
    slug: str = ""


class ServerRaw(BaseModel):
    id: int
    name: str
    status: str = ""
    vcpus: float | None = None
    memory: int | None = None
    disk: int | None = None
    region: RegionRaw = RegionRaw()
    image: ImageRaw = ImageRaw()
    networks: dict[str, list[NetworkRaw]] = {}


def cloud_vms(servers: list[dict]) -> list[CloudVm]:
    out = []
    for raw in servers:
        try:
            sv = ServerRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed server %r: %s", raw, e)
            continue
        ips = []
        for fam in ("v4", "v6"):
            for n in sv.networks.get(fam) or []:
                if not n.ip_address:
                    continue
                mask = n.netmask
                plen = mask if isinstance(mask, int) else ipaddress.ip_network(f"REDACTED_IP/{mask}").prefixlen if mask else 32
                iface = ipaddress.ip_interface(f"{n.ip_address}/{plen}")
                if iface.ip == iface.network.network_address and iface.network.num_addresses > 2:
                    continue                  # a routed prefix delegated to the server, not an address
                ips.append((f"{n.ip_address}/{plen}", "eth0" if n.type == "public" else "eth1"))
        out.append(CloudVm(
            provider="Binary Lane", id=sv.id, name=sv.name, region=sv.region.slug,
            status=STATUS.get(sv.status, "active"), vcpus=sv.vcpus or None,
            memory_mb=sv.memory or None, disk_mb=(sv.disk or 0) * 1024 or None,
            os=platform_name(sv.image.full_name or sv.image.name or sv.image.distribution), ips=ips))
    return out


def collect(c: Collected) -> None:
    r = requests.get("https://api.binarylane.com.au/v2/servers", params={"per_page": 200}, timeout=30,
                     headers={"Authorization": f"Bearer {os.environ['BINARYLANE_TOKEN']}"})
    if r.status_code != 200:
        raise RuntimeError(f"Binary Lane: {r.status_code} {r.text[:200]}")
    c.cloud_vms = cloud_vms(r.json().get("servers") or [])
