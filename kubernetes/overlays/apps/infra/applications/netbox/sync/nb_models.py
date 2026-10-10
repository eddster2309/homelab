"""Typed wrappers around NetBox's REST objects.

NetBox returns nested FKs as ``{"id": ..., "name": ..., "slug": ...}`` and
choice fields as ``{"value": ..., "label": ...}``. These models collapse both
representations at the validation boundary (see `Choice`/`FK` below) so
reconcile*.py can use plain attribute access instead of the
`(x.get("y") or {}).get("z")` chains `netbox_api._scalar()` used to paper over.

Every model allows extra fields (`extra="allow"`): this sync only declares the
fields it actually reads or writes, and NetBox's API grows new ones over time.
"""
from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict


def _choice(v: Any) -> Any:
    if isinstance(v, dict) and "value" in v:
        return v["value"]
    return v


Choice = Annotated[str, BeforeValidator(_choice)]
OptChoice = Annotated[str | None, BeforeValidator(_choice)]


class NbObject(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: int
    display: str = ""
    tags: list[Tag] = []
    custom_fields: dict[str, Any] = {}
    created: str | None = None
    last_updated: str | None = None


class Tag(BaseModel):
    model_config = ConfigDict(extra="allow")
    slug: str
    name: str | None = None


class FK(BaseModel):
    """A nested foreign key: NetBox always includes at least `id`."""
    model_config = ConfigDict(extra="allow")
    id: int
    name: str | None = None
    slug: str | None = None


NbObject.model_rebuild()


class Device(NbObject):
    name: str | None = None
    status: OptChoice = None
    site: FK | None = None
    role: FK | None = None
    device_type: FK | None = None
    cluster: FK | None = None
    location: FK | None = None
    platform: FK | None = None
    tenant: FK | None = None
    primary_ip4: FK | None = None
    oob_ip: FK | None = None
    serial: str = ""


class VirtualMachine(NbObject):
    name: str | None = None
    status: OptChoice = None
    cluster: FK | None = None
    site: FK | None = None
    device: FK | None = None
    platform: FK | None = None
    tenant: FK | None = None
    primary_ip4: FK | None = None
    vcpus: float | None = None
    memory: int | None = None
    disk: int | None = None


class Interface(NbObject):
    name: str | None = None
    device: FK | None = None
    type: OptChoice = None
    mode: OptChoice = None
    enabled: bool = True
    mgmt_only: bool = False
    label: str = ""
    description: str = ""
    parent: FK | None = None
    bridge: FK | None = None
    lag: FK | None = None
    untagged_vlan: FK | None = None
    tagged_vlans: list[FK] = []
    primary_mac_address: FK | None = None
    cable: FK | None = None
    speed: int | None = None
    duplex: OptChoice = None
    wireless_lans: list[FK] = []
    rf_role: OptChoice = None


class VMInterface(NbObject):
    name: str | None = None
    virtual_machine: FK | None = None
    mode: OptChoice = None
    untagged_vlan: FK | None = None
    tagged_vlans: list[FK] = []
    primary_mac_address: FK | None = None


class MacAddress(NbObject):
    mac_address: str | None = None
    assigned_object_type: str | None = None
    assigned_object_id: int | None = None


class IPAddress(NbObject):
    address: str | None = None
    status: OptChoice = None
    role: OptChoice = None
    dns_name: str = ""
    description: str = ""
    tenant: FK | None = None
    assigned_object_type: str | None = None
    assigned_object_id: int | None = None
    nat_inside: FK | None = None


class Prefix(NbObject):
    prefix: str | None = None
    description: str = ""
    vlan: FK | None = None
    tenant: FK | None = None
    scope_type: str | None = None
    scope_id: int | None = None


class Vlan(NbObject):
    vid: int | None = None
    name: str | None = None
    site: FK | None = None
    group: FK | None = None
    tenant: FK | None = None


class IpRange(NbObject):
    start_address: str | None = None
    end_address: str | None = None
    description: str = ""
    status: OptChoice = None
    mark_populated: bool = False
    tenant: FK | None = None


class Cable(NbObject):
    status: OptChoice = None
    a_terminations: list[dict[str, Any]] = []
    b_terminations: list[dict[str, Any]] = []


class FhrpGroup(NbObject):
    name: str | None = None
    protocol: OptChoice = None
    group_id: int | None = None
    description: str = ""


class FhrpGroupAssignment(NbObject):
    group: FK | None = None
    interface_type: str | None = None
    interface_id: int | None = None
    priority: int | None = None


class Service(NbObject):
    name: str | None = None
    parent_object_type: str | None = None
    parent_object_id: int | None = None
    port_mappings: list[str] = []
    ipaddresses: list[FK] = []
    description: str = ""
    comments: str = ""


class Platform(NbObject):
    name: str | None = None
    slug: str | None = None


class Manufacturer(NbObject):
    name: str | None = None
    slug: str | None = None


class DeviceType(NbObject):
    model: str | None = None
    slug: str | None = None
    manufacturer: FK | None = None
    part_number: str = ""


class DeviceRole(NbObject):
    name: str | None = None
    slug: str | None = None


class InventoryItem(NbObject):
    name: str | None = None
    device: FK | None = None
    role: FK | None = None
    manufacturer: FK | None = None
    part_id: str = ""
    serial: str = ""
    description: str = ""
    discovered: bool = False


class InventoryItemRole(NbObject):
    name: str | None = None
    slug: str | None = None


class Location(NbObject):
    name: str | None = None
    slug: str | None = None
    site: FK | None = None
    tenant: FK | None = None


class VirtualDisk(NbObject):
    name: str | None = None
    virtual_machine: FK | None = None
    size: int | None = None
    description: str = ""


class WirelessLan(NbObject):
    ssid: str | None = None
    status: OptChoice = None
    vlan: FK | None = None
    tenant: FK | None = None
    scope_type: str | None = None
    scope_id: int | None = None


class Cluster(NbObject):
    name: str | None = None
    type: FK | None = None
    tenant: FK | None = None


class ClusterType(NbObject):
    name: str | None = None
    slug: str | None = None


class Site(NbObject):
    name: str | None = None
    slug: str | None = None
    tenant: FK | None = None


class VlanGroup(NbObject):
    name: str | None = None
    slug: str | None = None


# ----------------------------------------------------------------- netbox-dns plugin

class DnsView(NbObject):
    name: str | None = None
    default_view: bool = False
    prefixes: list[FK] = []


class DnsZone(NbObject):
    name: str | None = None
    view: FK | None = None
    status: OptChoice = None
    nameservers: list[FK] = []
    soa_mname: FK | None = None
    soa_rname: str = ""
    tenant: FK | None = None


class DnsNameserver(NbObject):
    name: str | None = None


class DnsRecord(NbObject):
    zone: FK | None = None
    name: str | None = None
    type: OptChoice = None
    value: str | None = None
    status: OptChoice = None
    managed: bool = False
    disable_ptr: bool = False
    ipam_ip_address: FK | None = None
