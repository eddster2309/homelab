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
import os
import re
from dataclasses import dataclass, field

from model import Collected, norm_mac


@dataclass
class HaDevice:
    id: str
    name: str                 # what someone named it in HA, else HA's own name
    user_named: bool
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    area: str = ""
    macs: list[str] = field(default_factory=list)
    ip: str = ""              # from its configuration URL
    radio: str = ""           # zigbee | bluetooth (not on IP)
    radio_addr: str = ""
    via: str = ""             # device id it's reached through (a Zigbee coordinator)


JUNK = {"", "unk_manufacturer", "unk_model", "unknown"}
MAC_LIKE = re.compile(r"^([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}$")


def devices(registry: list[dict], areas: list[dict]) -> list[HaDevice]:
    area = {a["area_id"]: a.get("name", "") for a in areas}
    out = []
    for d in registry:
        if d.get("disabled_by") or d.get("entry_type") == "service":
            continue
        conns = {kind: addr for kind, addr in d.get("connections") or []}
        url_ip = re.search(r"//(\d{1,3}(?:\.\d{1,3}){3})", d.get("configuration_url") or "")
        h = HaDevice(id=d["id"], name=(d.get("name_by_user") or d.get("name") or "").strip(),
                     user_named=bool(d.get("name_by_user")),
                     manufacturer="" if (d.get("manufacturer") or "") in JUNK else d["manufacturer"].strip(),
                     model="" if (d.get("model") or "") in JUNK else d["model"].strip(),
                     firmware=(d.get("sw_version") or "").strip(), area=area.get(d.get("area_id"), ""),
                     macs=[m for m in [norm_mac(conns.get("mac"))] if m], ip=url_ip.group(1) if url_ip else "",
                     via=d.get("via_device_id") or "")
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
