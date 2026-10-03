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

from model import BmcObs, Collected, InvItem, norm_mac, vendor_name

log = logging.getLogger("bmc")


def bmc_obs(address: str, get) -> BmcObs:
    """Redfish documents (get(path) -> dict) -> BmcObs."""
    system = get("/redfish/v1/Systems/1/")
    manager = get("/redfish/v1/Managers/1/")
    b = BmcObs(address=address)
    for m in get("/redfish/v1/Systems/1/EthernetInterfaces/").get("Members") or []:
        mac = norm_mac(get(m["@odata.id"]).get("MacAddress"))
        if mac:
            b.system_macs.append(mac)
    for m in get("/redfish/v1/Managers/1/EthernetInterfaces/").get("Members") or []:
        nic = get(m["@odata.id"])
        if (nic.get("Status") or {}).get("State") == "Enabled" and norm_mac(nic.get("MacAddress")):
            b.mac = norm_mac(nic["MacAddress"])
            break
    fw = manager.get("FirmwareVersion") or ""                       # "iLO 4 v2.82"
    if fw:
        b.platform = f"HPE {fw.rsplit(' v', 1)[0]}" if " v" in fw else f"HPE {fw}"
        b.firmware = fw.rsplit(" v", 1)[-1] if " v" in fw else fw
    b.host_firmware = "; ".join(x for x in (f"BIOS {system['BiosVersion']}" if system.get("BiosVersion") else "", fw) if x)

    manu = vendor_name(system.get("Manufacturer") or "")
    for m in get("/redfish/v1/Systems/1/Memory/").get("Members") or []:
        d = get(m["@odata.id"])
        size = d.get("SizeMB") or d.get("CapacityMiB")
        status = d.get("DIMMStatus") or ((d.get("Status") or {}).get("State"))
        if not size or status in ("NotPresent", "Absent"):
            continue
        kind = d.get("DIMMType") or d.get("MemoryDeviceType") or ""
        speed = d.get("MaximumFrequencyMHz") or d.get("OperatingSpeedMhz")
        b.inventory.append(InvItem(
            "memory", d.get("Name") or m["@odata.id"].rstrip("/").rsplit("/", 1)[-1],
            vendor_name(d.get("Manufacturer") or ""), (d.get("PartNumber") or f"{kind} {size // 1024} GB").strip(),
            (d.get("SerialNumber") or "").strip(),
            ", ".join(x for x in (f"{size // 1024} GB {kind}".strip(), f"{speed} MHz" if speed else "", status or "") if x)))
    for i, ps in enumerate(get("/redfish/v1/Chassis/1/Power/").get("PowerSupplies") or [], 1):
        if (ps.get("Status") or {}).get("State") == "Absent":
            continue
        b.inventory.append(InvItem(
            "psu", f"PSU {i}", manu, (ps.get("Model") or ps.get("SparePartNumber") or "").strip(), (ps.get("SerialNumber") or "").strip(),
            ", ".join(x for x in (f"{ps['PowerCapacityWatts']} W" if ps.get("PowerCapacityWatts") else "",
                                  f"firmware {ps['FirmwareVersion']}" if ps.get("FirmwareVersion") else "",
                                  (ps.get("Status") or {}).get("Health") or "") if x)))
    return b


def collect(c: Collected) -> None:
    hosts = [h.strip() for h in os.environ.get("BMC_HOSTS", "").split(",") if h.strip()]
    if not hosts:
        return
    s = requests.Session()
    s.auth = (os.environ["BMC_USER"], os.environ["BMC_PASSWORD"])
    s.verify = os.environ.get("BMC_VERIFY_SSL", "false").lower() == "true"
    s.headers["Connection"] = "close"
    for host in hosts:
        def get(path: str) -> dict:
            r = s.get(f"https://{host}{path}", timeout=30)
            if r.status_code != 200:
                raise RuntimeError(f"Redfish {host}{path}: {r.status_code}")
            return r.json()
        c.bmcs.append(bmc_obs(host, get))
