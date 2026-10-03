"""TP-Link Omada controller (OpenAPI, client credentials): client names (a naming
fallback below DHCP), where each client connects (switch port, or Wi-Fi SSID/AP),
Omada's own switches/APs with their names, and how they're wired to each other.

Live port state (link up, negotiated speed/duplex) and the switch port each AP
plugs into aren't in the OpenAPI: they come from the controller's web API, as a
read-only user (OMADA_USER/OMADA_PASS, the omada-exporter's). That part is
optional: without it, or if it fails, everything else still syncs and NetBox
keeps the speeds it had.
"""
from __future__ import annotations

import logging
import os
import re

import requests

from model import Collected, OmadaClient, OmadaDevice, SwitchPort, norm_mac

log = logging.getLogger("omada")
MAC_LIKE = re.compile(r"^([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}$")
# Omada's linkSpeed / maxSpeed enum -> Mbps
SPEED_MBPS = {1: 10, 2: 100, 3: 1000, 4: 2500, 5: 10000, 6: 5000, 7: 25000, 8: 100000, 9: 40000}
DUPLEX = {1: "half", 2: "full"}
COPPER_TYPES = {10: "10base-t", 100: "100base-tx", 1000: "1000base-t", 2500: "2.5gbase-t", 5000: "5gbase-t",
                10000: "10gbase-t"}
SFP_TYPES = {1000: "1000base-x-sfp", 10000: "10gbase-x-sfpp", 25000: "25gbase-x-sfp28", 40000: "40gbase-x-qsfpp",
             100000: "100gbase-x-qsfp28"}


def port_type(media: int | None, max_speed: int | None) -> str:
    """Omada port type (1 copper, 2 combo, 3 SFP) and maxSpeed -> NetBox interface type."""
    mbps = SPEED_MBPS.get(max_speed or 3, 1000)
    if media == 3:
        return SFP_TYPES.get(mbps, "1000base-x-sfp")
    return COPPER_TYPES.get(mbps, "1000base-t")


def apply_port_status(sw: OmadaDevice, detail: dict, by_mac: dict[str, OmadaDevice]) -> None:
    """Web API switch detail -> live state on sw's ports, and the switch port each AP
    (from the switch's downlinkList) is wired to."""
    status = {p.get("port"): p for p in detail.get("ports") or []}
    for port in sw.ports:
        p = status.get(port.num)
        if p is None:
            continue
        st = p.get("portStatus") or {}
        port.type = port_type(p.get("type"), p.get("maxSpeed"))
        port.up = st.get("linkStatus") == 1
        port.speed_mbps = SPEED_MBPS.get(st.get("linkSpeed")) if port.up else None
        port.duplex = DUPLEX.get(st.get("duplex"), "") if port.up else ""
    for d in detail.get("downlinkList") or []:
        od = by_mac.get(norm_mac(d.get("mac")) or "")
        if od is not None and od.type == "ap" and d.get("port"):
            od.uplink_mac, od.uplink_port = sw.mac, int(d["port"])


def _connection(c: dict) -> str:
    if c.get("wireless"):
        where = " @ ".join(x for x in (c.get("ssid"), c.get("apName")) if x)
        return f"wifi {where}".strip()
    if c.get("switchName") or c.get("port"):
        return f"switch {c.get('switchName') or c.get('switchMac', '')} port {c.get('port')}".strip()
    return ""


def _port(p: dict, profiles: dict, nets: dict) -> SwitchPort:
    """A switch port with its 802.1Q setup, from its LAN profile (native + tagged networks)."""
    prof = profiles.get(p.get("profileId")) or {}
    untagged = nets.get(prof.get("nativeNetworkId"))
    tagged = sorted({nets[i] for i in prof.get("tagNetworkIds") or [] if nets.get(i)} - {untagged})
    every = {v for v in nets.values() if v} - {untagged}
    return SwitchPort(int(p["port"]), (p.get("name") or "").strip(), (p.get("profileName") or "").strip(),
                      untagged=untagged, tagged=tagged, tagged_all=bool(tagged) and set(tagged) >= every)


def collect(c: Collected) -> None:
    host = os.environ.get("OMADA_URL", "https://REDACTED_IP").rstrip("/")
    s = requests.Session()
    s.verify = os.environ.get("OMADA_VERIFY_SSL", "false").lower() == "true"
    # The OC200 is slow (its own exporter times out at 10s regularly; a 60s read has
    # timed out too). One retry on timeout.
    timeout = int(os.environ.get("OMADA_TIMEOUT", "120"))
    from requests.adapters import HTTPAdapter, Retry
    s.mount("https://", HTTPAdapter(max_retries=Retry(total=2, read=1, connect=1, backoff_factor=5,
                                                      allowed_methods=None)))
    oc = s.get(f"{host}/api/info", timeout=timeout).json()["result"]["omadacId"]
    tok = s.post(f"{host}/openapi/authorize/token", params={"grant_type": "client_credentials"}, timeout=timeout,
                 json={"omadacId": oc, "client_id": os.environ["OMADA_CLIENT_ID"],
                       "client_secret": os.environ["OMADA_CLIENT_SECRET"]}).json()
    if tok.get("errorCode") != 0:
        raise RuntimeError(f"Omada token: {tok.get('msg')}")
    s.headers["Authorization"] = f"AccessToken={tok['result']['accessToken']}"

    def get(path: str, **params):
        d = s.get(f"{host}/openapi/v1/{oc}{path}", params=params, timeout=timeout).json()
        if d.get("errorCode") != 0:
            raise RuntimeError(f"Omada {path}: {d.get('msg')}")
        return d["result"]

    for site in get("/sites", page=1, pageSize=100)["data"]:
        nets = {n["id"]: n.get("vlan") for n in get(f"/sites/{site['siteId']}/lan-networks", page=1, pageSize=1000).get("data", [])}
        profiles = {p["id"]: p for p in get(f"/sites/{site['siteId']}/lan-profiles", page=1, pageSize=1000).get("data", [])}
        for d in get(f"/sites/{site['siteId']}/devices", page=1, pageSize=1000).get("data", []):
            mac = norm_mac(d.get("mac"))
            if not mac:
                continue
            name = (d.get("name") or "").strip()
            od = OmadaDevice(mac=mac, ip=d.get("ip") or "", name="" if MAC_LIKE.match(name) else name,
                             model=(d.get("model") or "").strip(), type=d.get("type") or "",
                             serial=(d.get("sn") or "").strip(), firmware=(d.get("firmwareVersion") or "").strip())
            base = f"/sites/{site['siteId']}"
            if od.type == "switch":
                od.ports = [_port(p, profiles, nets)
                            for p in get(f"{base}/switches/{d['mac']}").get("portList", []) if p.get("port")]
            elif od.type == "ap":
                # Names the switch but not the port: no cable, just the connection text
                up = (get(f"{base}/aps/{d['mac']}/wired-uplink") or {}).get("wiredUplink") or {}
                od.uplink_mac = norm_mac(up.get("uplinkMac"))
            c.omada_devices.append(od)
        _uplinks(s, host, oc, site["siteId"], c.omada_devices, timeout)
        _web_port_status(s, host, oc, site["siteId"], c.omada_devices, timeout)
        page = 1
        while True:
            res = get(f"/sites/{site['siteId']}/clients", page=page, pageSize=1000)
            for cl in res.get("data", []):
                mac = norm_mac(cl.get("mac"))
                if not mac:
                    continue
                name = (cl.get("name") or "").strip()
                c.omada_clients.append(OmadaClient(
                    mac=mac, ip=cl.get("ip") or "",
                    # Unnamed clients carry their MAC as the name; only a distinct name counts
                    name="" if not name or MAC_LIKE.match(name) or name == cl.get("hostName") else name,
                    hostname=(cl.get("hostName") or "").strip(),
                    connection=_connection(cl), active=bool(cl.get("active", True)),
                    uplink_mac=norm_mac(cl.get("apMac") if cl.get("wireless") else cl.get("switchMac")),
                    port=cl.get("port") if not cl.get("wireless") else None,
                    ssid=(cl.get("ssid") or "") if cl.get("wireless") else "",
                    radio=cl.get("radioId"), wifi_mode=cl.get("wifiMode"), vid=cl.get("vid")))
            if page * 1000 >= int(res.get("totalRows", 0)):
                break
            page += 1


def apply_topology(topo: dict, devices: list[OmadaDevice]) -> None:
    """OpenAPI v2 topology: which switch each switch hangs off, with the port on both ends."""
    by_mac = {od.mac: od for od in devices}
    up = {norm_mac(e.get("downLinkMac")): norm_mac(e.get("upLinkMac")) for e in topo.get("topologyEdges") or []}
    for n in topo.get("topologyNodes") or []:
        od = by_mac.get(norm_mac(n.get("mac")) or "")
        info = n.get("upperInfo") or {}
        if od is None or od.type != "switch" or not info or not up.get(od.mac):
            continue
        od.uplink_mac = up[od.mac]
        od.uplink_port = (info.get("upLinkPort") or {}).get("port")
        od.local_port = (info.get("port") or {}).get("port")


def _uplinks(s: requests.Session, host: str, oc: str, site: str, devices: list[OmadaDevice], timeout: int) -> None:
    try:
        d = s.get(f"{host}/openapi/v2/{oc}/sites/{site}/topology", timeout=timeout).json()
        if d.get("errorCode") != 0:
            raise RuntimeError(d.get("msg"))
        apply_topology(d["result"], devices)
    except Exception as e:      # optional: cables between switches just aren't drawn this run
        log.warning("topology unavailable: %s", e)


def _web_port_status(s: requests.Session, host: str, oc: str, site: str, devices: list[OmadaDevice],
                     timeout: int) -> None:
    user, password = os.environ.get("OMADA_USER"), os.environ.get("OMADA_PASS")
    if not (user and password):
        return
    web = requests.Session()
    web.verify, web.adapters = s.verify, s.adapters
    try:
        r = web.post(f"{host}/{oc}/api/v2/login", json={"username": user, "password": password}, timeout=timeout).json()
        if r.get("errorCode") != 0:
            raise RuntimeError(f"login: {r.get('msg')}")
        web.headers["Csrf-Token"] = r["result"]["token"]
        by_mac = {od.mac: od for od in devices}
        for sw in [od for od in devices if od.type == "switch"]:
            mac = sw.mac.upper().replace(":", "-")
            d = web.get(f"{host}/{oc}/api/v2/sites/{site}/switches/{mac}", timeout=timeout).json()
            if d.get("errorCode") != 0:
                raise RuntimeError(f"switch {mac}: {d.get('msg')}")
            apply_port_status(sw, d["result"], by_mac)
    except Exception as e:      # optional: port speeds stay as they were
        log.warning("web API port status unavailable: %s", e)
    finally:
        try:
            web.post(f"{host}/{oc}/api/v2/logout", timeout=10)
        except Exception:
            pass
