"""Home Assistant's device registry: what HA knows about devices on the network.

- Network devices (a "mac" connection, or a configuration URL on a LAN address):
  the name someone gave them in HA, their manufacturer/model (a real device type),
  firmware, and HA's area as their NetBox location.
- Zigbee and Bluetooth devices aren't on IP: they become inventory items on what
  they hang off (the Zigbee coordinator's device, or the HA host for its own radios).

HA_URL, HA_TOKEN: a long-lived token of a non-admin HA user. The registry is only
on HA's websocket API.
"""
from __future__ import annotations

import json
import logging
import os
import re

from pydantic import BaseModel, ValidationError

from model import Collected, HaDevice, norm_mac

log = logging.getLogger("homeassistant")
JUNK = {"", "unk_manufacturer", "unk_model", "unknown"}
MAC_LIKE = re.compile(r"^([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}$")


class DeviceEntryRaw(BaseModel):
    id: str
    name: str = ""
    name_by_user: str | None = None
    disabled_by: str | None = None
    entry_type: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    sw_version: str | None = None
    area_id: str | None = None
    configuration_url: str | None = None
    via_device_id: str | None = None
    connections: list[tuple[str, str]] = []


class AreaEntryRaw(BaseModel):
    area_id: str
    name: str = ""


def devices(registry: list[dict], areas: list[dict]) -> list[HaDevice]:
    area: dict[str, str] = {}
    for raw in areas:
        try:
            a = AreaEntryRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed area %r: %s", raw, e)
            continue
        area[a.area_id] = a.name
    out = []
    for raw in registry:
        try:
            d = DeviceEntryRaw.model_validate(raw)
        except ValidationError as e:
            log.warning("skipping malformed device %r: %s", raw, e)
            continue
        if d.disabled_by or d.entry_type == "service":
            continue
        conns = dict(d.connections)
        url_ip = re.search(r"//(\d{1,3}(?:\.\d{1,3}){3})", d.configuration_url or "")
        h = HaDevice(id=d.id, name=(d.name_by_user or d.name or "").strip(),
                     user_named=bool(d.name_by_user),
                     manufacturer="" if (d.manufacturer or "") in JUNK else d.manufacturer.strip(),
                     model="" if (d.model or "") in JUNK else d.model.strip(),
                     firmware=(d.sw_version or "").strip(), area=area.get(d.area_id or "", ""),
                     macs=[m for m in [norm_mac(conns.get("mac"))] if m], ip=url_ip.group(1) if url_ip else "",
                     via=d.via_device_id or "")
        for radio in ("zigbee", "bluetooth"):
            if radio in conns and not h.macs:
                h.radio, h.radio_addr = radio, conns[radio].lower()
        if not h.user_named and (h.name.startswith("unk_") or MAC_LIKE.match(h.name)):
            h.name = f"{h.radio} {h.radio_addr[-8:]}" if h.radio else ""     # no real name: don't offer one
        if h.macs or h.ip or h.radio:
            out.append(h)
    return out


def collect(c: Collected) -> None:
    import websocket
    url = os.environ.get("HA_URL", "http://REDACTED_IP:8123").rstrip("/")
    ws = websocket.create_connection(re.sub(r"^http", "ws", url) + "/api/websocket", timeout=30,
                                     sslopt={"cert_reqs": 0} if url.startswith("https") else None)
    try:
        ws.recv()
        ws.send(json.dumps({"type": "auth", "access_token": os.environ["HA_TOKEN"]}))
        if json.loads(ws.recv()).get("type") != "auth_ok":
            raise RuntimeError("Home Assistant: auth failed")

        def call(i: int, kind: str) -> list[dict]:
            ws.send(json.dumps({"id": i, "type": kind}))
            r = json.loads(ws.recv())
            if not r.get("success"):
                raise RuntimeError(f"Home Assistant {kind}: {r.get('error')}")
            return r["result"]

        c.ha_devices = devices(call(1, "config/device_registry/list"), call(2, "config/area_registry/list"))
        m = re.search(r"//([\d.]+)", url)
        c.ha_host_ip = m.group(1) if m else ""
    finally:
        ws.close()
