"""FreeIPA DNS: IP -> FQDN from forward A/AAAA records (reverse zones aren't populated)."""
from __future__ import annotations

import logging
import os
from typing import Annotated

import requests
from pydantic import BaseModel, BeforeValidator, ValidationError

from model import Collected, DnsZone, is_usable_ip

log = logging.getLogger("ipa")
MIRRORED = (("arecord", "A"), ("aaaarecord", "AAAA"), ("cnamerecord", "CNAME"), ("srvrecord", "SRV"), ("mxrecord", "MX"))


def _dn(v) -> str:
    """IPA returns DNS names as strings or {"__dns_name__": ...}."""
    v = v[0] if isinstance(v, list) and v else v
    return (v if isinstance(v, str) else (v or {}).get("__dns_name__", "")).rstrip(".")


def _int(v) -> int | None:
    v = v[0] if isinstance(v, list) and v else v
    return int(v) if str(v or "").isdigit() else None


def _active(v) -> bool:
    """IPA wraps booleans in a one-element list too; missing/empty means active."""
    if not v:
        return True
    v = v[0] if isinstance(v, list) else v
    return bool(v)


DnsName = Annotated[str, BeforeValidator(_dn)]
OptInt = Annotated[int | None, BeforeValidator(_int)]
ActiveFlag = Annotated[bool, BeforeValidator(_active)]


class ZoneRaw(BaseModel):
    idnsname: DnsName
    idnszoneactive: ActiveFlag = True
    idnssoarname: DnsName = ""
    idnssoamname: DnsName = ""
    idnssoarefresh: OptInt = None
    idnssoaretry: OptInt = None
    idnssoaexpire: OptInt = None
    idnssoaminimum: OptInt = None
    dnsdefaultttl: OptInt = None


class RecordRaw(BaseModel):
    idnsname: DnsName
    arecord: list[str] = []
    aaaarecord: list[str] = []
    cnamerecord: list[str] = []
    srvrecord: list[str] = []
    mxrecord: list[str] = []


class HostRaw(BaseModel):
    fqdn: DnsName


def collect(c: Collected) -> None:
    base = os.environ.get("IPA_URL", "https://ipa01.internal").rstrip("/")
    s = requests.Session()
    s.verify = os.environ.get("IPA_CA_BUNDLE", True)
    s.headers.update({"Referer": f"{base}/ipa", "Accept": "application/json"})
    r = s.post(f"{base}/ipa/session/login_password", timeout=20,
               data={"user": os.environ["IPA_USER"], "password": os.environ["IPA_PASSWORD"]})
    if r.status_code != 200:
        raise RuntimeError(f"IPA login: {r.status_code}")

    def rpc(method: str, args: list, opts: dict):
        resp = s.post(f"{base}/ipa/session/json", timeout=60,
                      json={"method": method, "params": [args, {"version": "2.254", **opts}], "id": 0})
        resp.raise_for_status()
        body = resp.json()
        if body.get("error"):
            raise RuntimeError(f"IPA {method}: {body['error'].get('message')}")
        return body["result"]["result"]

    c.dns_zones = []
    for raw_z in rpc("dnszone_find", [], {"sizelimit": 0, "all": True}):
        try:
            z = ZoneRaw.model_validate(raw_z)
        except ValidationError as e:
            log.warning("skipping malformed zone %r: %s", raw_z, e)
            continue
        zone = z.idnsname
        if not z.idnszoneactive:
            continue
        rname = z.idnssoarname
        dz = DnsZone(name=zone, mname=z.idnssoamname,
                     rname=rname if "." in rname else f"{rname}.{zone}",
                     refresh=z.idnssoarefresh, retry=z.idnssoaretry,
                     expire=z.idnssoaexpire, minimum=z.idnssoaminimum,
                     default_ttl=z.dnsdefaultttl)
        c.dns_zones.append(dz)
        reverse = zone.endswith(".in-addr.arpa") or zone.endswith(".ip6.arpa")
        for raw_rec in rpc("dnsrecord_find", [zone], {"sizelimit": 0}):
            try:
                rec = RecordRaw.model_validate(raw_rec)
            except ValidationError as e:
                log.warning("skipping malformed dns record %r: %s", raw_rec, e)
                continue
            label = rec.idnsname or "@"
            if not reverse:
                for key, rtype in MIRRORED:
                    for value in getattr(rec, key):
                        dz.records.append((label, rtype, str(value)))
            if reverse or label.startswith("*"):
                continue                      # wildcard records name no single host
            fqdn = zone if label in ("@", "") else f"{label}.{zone}"
            for ip in rec.arecord + rec.aaaarecord:
                # First name wins so a host's canonical record isn't replaced by an alias.
                if is_usable_ip(ip):
                    c.ipa_names.setdefault(ip, fqdn)

    for raw_h in rpc("host_find", [], {"sizelimit": 0}):
        try:
            h = HostRaw.model_validate(raw_h)
        except ValidationError as e:
            log.warning("skipping malformed host %r: %s", raw_h, e)
            continue
        c.ipa_hosts.add(h.fqdn.lower())
