"""Typed, validated outbound PATCH/POST bodies for NetBox writes.

Unlike nb_models.py (which reads NetBox's nested-FK/choice API responses),
these models describe what this sync *sends*: FKs are bare integer ids (what
NetBox's write API accepts), and every field is optional since every write is
a sparse patch. `extra="forbid"` catches a typo'd field name as a validation
error instead of NetBox silently ignoring (create) or 400ing opaquely
(update) on an unknown key.

Used via `netbox_api.NetBox.create/update(..., write_model=XWrite)`: the
caller's `want` dict is re-validated through the model and re-serialized with
`model_dump(exclude_unset=True)`. Pydantic's "unset" tracking is exactly the
fields the caller actually passed -- including ones explicitly set to None,
which this codebase relies on throughout to clear a field (release a primary
MAC, unassign an interface, drop an interface's VLAN mode). A naive
`exclude_none` dump would silently turn every one of those into a no-op, so
this module must only ever be read via `exclude_unset`.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class Write(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeviceWrite(Write):
    name: str | None = None
    role: int | None = None
    device_type: int | None = None
    site: int | None = None
    status: str | None = None
    cluster: int | None = None
    tenant: int | None = None
    location: int | None = None
    platform: int | None = None
    serial: str | None = None
    primary_ip4: int | None = None
    oob_ip: int | None = None
    custom_fields: dict[str, Any] | None = None
    tags: list[dict] | None = None


class VirtualMachineWrite(Write):
    name: str | None = None
    cluster: int | None = None
    site: int | None = None
    device: int | None = None
    status: str | None = None
    vcpus: float | None = None
    memory: int | None = None
    disk: int | None = None
    tenant: int | None = None
    platform: int | None = None
    primary_ip4: int | None = None
    custom_fields: dict[str, Any] | None = None
    tags: list[dict] | None = None


class InterfaceWrite(Write):
    device: int | None = None
    name: str | None = None
    type: str | None = None
    label: str | None = None
    description: str | None = None
    enabled: bool | None = None
    mgmt_only: bool | None = None
    parent: int | None = None
    bridge: int | None = None
    lag: int | None = None
    mode: str | None = None
    untagged_vlan: int | None = None
    tagged_vlans: list[int] | None = None
    primary_mac_address: int | None = None
    rf_role: str | None = None
    wireless_lans: list[int] | None = None
    speed: int | None = None
    duplex: str | None = None
    tags: list[dict] | None = None


class VMInterfaceWrite(Write):
    virtual_machine: int | None = None
    name: str | None = None
    parent: int | None = None
    bridge: int | None = None
    mode: str | None = None
    untagged_vlan: int | None = None
    tagged_vlans: list[int] | None = None
    primary_mac_address: int | None = None
    tags: list[dict] | None = None


class MacAddressWrite(Write):
    mac_address: str | None = None
    assigned_object_type: str | None = None
    assigned_object_id: int | None = None
    tags: list[dict] | None = None


class IPAddressWrite(Write):
    address: str | None = None
    status: str | None = None
    role: str | None = None
    dns_name: str | None = None
    description: str | None = None
    tenant: int | None = None
    assigned_object_type: str | None = None
    assigned_object_id: int | None = None
    nat_inside: int | None = None
    custom_fields: dict[str, Any] | None = None
    tags: list[dict] | None = None


class PrefixWrite(Write):
    prefix: str | None = None
    status: str | None = None
    description: str | None = None
    scope_type: str | None = None
    scope_id: int | None = None
    vlan: int | None = None
    tenant: int | None = None
    tags: list[dict] | None = None


class VlanWrite(Write):
    vid: int | None = None
    name: str | None = None
    status: str | None = None
    site: int | None = None
    group: int | None = None
    tenant: int | None = None
    tags: list[dict] | None = None


class IpRangeWrite(Write):
    start_address: str | None = None
    end_address: str | None = None
    status: str | None = None
    description: str | None = None
    mark_populated: bool | None = None
    tenant: int | None = None
    tags: list[dict] | None = None


class CableWrite(Write):
    a_terminations: list[dict] | None = None
    b_terminations: list[dict] | None = None
    status: str | None = None
    tags: list[dict] | None = None


class FhrpGroupWrite(Write):
    protocol: str | None = None
    group_id: int | None = None
    name: str | None = None
    description: str | None = None
    tags: list[dict] | None = None


class FhrpGroupAssignmentWrite(Write):
    group: int | None = None
    interface_type: str | None = None
    interface_id: int | None = None
    priority: int | None = None


class ServiceWrite(Write):
    parent_object_type: str | None = None
    parent_object_id: int | None = None
    name: str | None = None
    port_mappings: list[str] | None = None
    ipaddresses: list[int] | None = None
    description: str | None = None
    comments: str | None = None
    tags: list[dict] | None = None


class PlatformWrite(Write):
    name: str | None = None
    slug: str | None = None
    tags: list[dict] | None = None


class LocationWrite(Write):
    name: str | None = None
    slug: str | None = None
    site: int | None = None
    status: str | None = None
    tenant: int | None = None
    tags: list[dict] | None = None


class ManufacturerWrite(Write):
    name: str | None = None
    slug: str | None = None


class DeviceTypeWrite(Write):
    manufacturer: int | None = None
    model: str | None = None
    slug: str | None = None
    part_number: str | None = None
    u_height: int | None = None
    tags: list[dict] | None = None


class DeviceRoleWrite(Write):
    name: str | None = None
    slug: str | None = None
    color: str | None = None


class InventoryItemWrite(Write):
    device: int | None = None
    name: str | None = None
    role: int | None = None
    manufacturer: int | None = None
    part_id: str | None = None
    serial: str | None = None
    description: str | None = None
    discovered: bool | None = None
    tags: list[dict] | None = None


class InventoryItemRoleWrite(Write):
    name: str | None = None
    slug: str | None = None
    color: str | None = None


class VirtualDiskWrite(Write):
    virtual_machine: int | None = None
    name: str | None = None
    size: int | None = None
    description: str | None = None
    tags: list[dict] | None = None


class WirelessLanWrite(Write):
    ssid: str | None = None
    status: str | None = None
    vlan: int | None = None
    tenant: int | None = None
    scope_type: str | None = None
    scope_id: int | None = None
    tags: list[dict] | None = None


class ClusterWrite(Write):
    name: str | None = None
    type: int | None = None
    status: str | None = None
    scope_type: str | None = None
    scope_id: int | None = None
    tenant: int | None = None
    description: str | None = None
    tags: list[dict] | None = None


class ClusterTypeWrite(Write):
    name: str | None = None
    slug: str | None = None


class TagWrite(Write):
    name: str | None = None
    slug: str | None = None
    color: str | None = None
    description: str | None = None


class SiteWrite(Write):
    name: str | None = None
    slug: str | None = None
    tenant: int | None = None


class VlanGroupWrite(Write):
    name: str | None = None
    slug: str | None = None


class CustomFieldWrite(Write):
    name: str | None = None
    label: str | None = None
    type: str | None = None
    object_types: list[str] | None = None
    ui_editable: str | None = None
    group_name: str | None = None


# ----------------------------------------------------------------- netbox-dns plugin

class DnsViewWrite(Write):
    prefixes: list[int] | None = None


class DnsZoneWrite(Write):
    name: str | None = None
    view: int | None = None
    status: str | None = None
    nameservers: list[int] | None = None
    soa_mname: int | None = None
    soa_rname: str | None = None
    soa_refresh: int | None = None
    soa_retry: int | None = None
    soa_expire: int | None = None
    soa_minimum: int | None = None
    default_ttl: int | None = None
    tenant: int | None = None
    tags: list[dict] | None = None


class DnsNameserverWrite(Write):
    name: str | None = None
    tags: list[dict] | None = None


class DnsRecordWrite(Write):
    zone: int | None = None
    name: str | None = None
    type: str | None = None
    value: str | None = None
    status: str | None = None
    ipam_ip_address: int | None = None
    disable_ptr: bool | None = None
    tags: list[dict] | None = None
