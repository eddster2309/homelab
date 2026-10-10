"""Server BMCs over Redfish (HPE iLO 4 and later): the parts the OS can't see or
Proxmox doesn't report (DIMMs, power supplies), BIOS/BMC firmware, and the BMC's
own NIC so its NetBox device is marked out-of-band management.

BMC_HOSTS lists the BMCs ("REDACTED_IP"); BMC_USER/BMC_PASSWORD is a read-only login.
iLO 4 drops persistent connections, so every request closes its own.
"""
from __future__ import annotations

import logging
import os

import requests
from pydantic import BaseModel, Field, ValidationError

from model import BmcObs, Collected, InvItem, norm_mac, vendor_name, verify_ssl

log = logging.getLogger("bmc")


class _Status(BaseModel):
    State: str | None = None
    Health: str | None = None


class SystemRaw(BaseModel):
    Manufacturer: str = ""
    BiosVersion: str = ""


class ManagerRaw(BaseModel):
    FirmwareVersion: str = ""


class _Member(BaseModel):
    odata_id: str = Field("", alias="@odata.id")


class MemberCollectionRaw(BaseModel):
    Members: list[_Member] = []


class EthernetInterfaceRaw(BaseModel):
    MacAddress: str | None = None
    Status: _Status = _Status()


class MemoryModuleRaw(BaseModel):
    Name: str = ""
    SizeMB: int | None = None
    CapacityMiB: int | None = None
    DIMMStatus: str | None = None
    Status: _Status = _Status()
    DIMMType: str = ""
    MemoryDeviceType: str = ""
    MaximumFrequencyMHz: int | None = None
    OperatingSpeedMhz: int | None = None
    Manufacturer: str = ""
    PartNumber: str = ""
    SerialNumber: str = ""


class PowerSupplyRaw(BaseModel):
    Model: str = ""
    SparePartNumber: str = ""
    SerialNumber: str = ""
    PowerCapacityWatts: int | None = None
    FirmwareVersion: str = ""
    Status: _Status = _Status()


class PowerRaw(BaseModel):
    PowerSupplies: list[PowerSupplyRaw] = []


def _get(get, path: str, model):
    try:
        return model.model_validate(get(path))
    except ValidationError as e:
        log.warning("skipping malformed Redfish document %s: %s", path, e)
        return model()


def bmc_obs(address: str, get) -> BmcObs:
    """Redfish documents (get(path) -> dict) -> BmcObs."""
    system = _get(get, "/redfish/v1/Systems/1/", SystemRaw)
    manager = _get(get, "/redfish/v1/Managers/1/", ManagerRaw)
    b = BmcObs(address=address)
    for m in _get(get, "/redfish/v1/Systems/1/EthernetInterfaces/", MemberCollectionRaw).Members:
        mac = norm_mac(_get(get, m.odata_id, EthernetInterfaceRaw).MacAddress)
        if mac:
            b.system_macs.append(mac)
    for m in _get(get, "/redfish/v1/Managers/1/EthernetInterfaces/", MemberCollectionRaw).Members:
        nic = _get(get, m.odata_id, EthernetInterfaceRaw)
        if nic.Status.State == "Enabled" and norm_mac(nic.MacAddress):
            b.mac = norm_mac(nic.MacAddress)
            break
    fw = manager.FirmwareVersion                                    # "iLO 4 v2.82"
    if fw:
        b.platform = f"HPE {fw.rsplit(' v', 1)[0]}" if " v" in fw else f"HPE {fw}"
        b.firmware = fw.rsplit(" v", 1)[-1] if " v" in fw else fw
    b.host_firmware = "; ".join(x for x in (f"BIOS {system.BiosVersion}" if system.BiosVersion else "", fw) if x)

    manu = vendor_name(system.Manufacturer)
    for m in _get(get, "/redfish/v1/Systems/1/Memory/", MemberCollectionRaw).Members:
        d = _get(get, m.odata_id, MemoryModuleRaw)
        size = d.SizeMB or d.CapacityMiB
        status = d.DIMMStatus or d.Status.State
        if not size or status in ("NotPresent", "Absent"):
            continue
        kind = d.DIMMType or d.MemoryDeviceType
        speed = d.MaximumFrequencyMHz or d.OperatingSpeedMhz
        b.inventory.append(InvItem(
            "memory", d.Name or m.odata_id.rstrip("/").rsplit("/", 1)[-1],
            vendor_name(d.Manufacturer), (d.PartNumber or f"{kind} {size // 1024} GB").strip(),
            d.SerialNumber.strip(),
            ", ".join(x for x in (f"{size // 1024} GB {kind}".strip(), f"{speed} MHz" if speed else "", status or "") if x)))
    for i, ps in enumerate(_get(get, "/redfish/v1/Chassis/1/Power/", PowerRaw).PowerSupplies, 1):
        if ps.Status.State == "Absent":
            continue
        b.inventory.append(InvItem(
            "psu", f"PSU {i}", manu, (ps.Model or ps.SparePartNumber).strip(), ps.SerialNumber.strip(),
            ", ".join(x for x in (f"{ps.PowerCapacityWatts} W" if ps.PowerCapacityWatts else "",
                                  f"firmware {ps.FirmwareVersion}" if ps.FirmwareVersion else "",
                                  ps.Status.Health or "") if x)))
    return b


def collect(c: Collected) -> None:
    hosts = [h.strip() for h in os.environ.get("BMC_HOSTS", "").split(",") if h.strip()]
    if not hosts:
        return
    s = requests.Session()
    s.auth = (os.environ["BMC_USER"], os.environ["BMC_PASSWORD"])
    s.verify = verify_ssl("BMC")
    s.headers["Connection"] = "close"
    for host in hosts:
        def get(path: str) -> dict:
            r = s.get(f"https://{host}{path}", timeout=30)
            if r.status_code != 200:
                raise RuntimeError(f"Redfish {host}{path}: {r.status_code}")
            return r.json()
        c.bmcs.append(bmc_obs(host, get))
