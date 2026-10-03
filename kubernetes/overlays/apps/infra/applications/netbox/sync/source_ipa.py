"""FreeIPA DNS: IP -> FQDN from forward A/AAAA records (reverse zones aren't populated)."""
from __future__ import annotations

import os

import requests

from model import Collected, DnsZone, is_usable_ip

MIRRORED = (("arecord", "A"), ("aaaarecord", "AAAA"), ("cnamerecord", "CNAME"), ("srvrecord", "SRV"), ("mxrecord", "MX"))


def _dn(v) -> str:
    """IPA returns DNS names as strings or {"__dns_name__": ...}."""
    v = v[0] if isinstance(v, list) and v else v
    return (v if isinstance(v, str) else (v or {}).get("__dns_name__", "")).rstrip(".")


def _int(v) -> int | None:
    v = v[0] if isinstance(v, list) and v else v
    return int(v) if str(v or "").isdigit() else None


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
    for z in rpc("dnszone_find", [], {"sizelimit": 0, "all": True}):
        zone = _dn(z["idnsname"])
        if not (z.get("idnszoneactive") or [True])[0]:
            continue
        rname = _dn(z.get("idnssoarname"))
        dz = DnsZone(name=zone, mname=_dn(z.get("idnssoamname")),
                     rname=rname if "." in rname else f"{rname}.{zone}",
                     refresh=_int(z.get("idnssoarefresh")), retry=_int(z.get("idnssoaretry")),
                     expire=_int(z.get("idnssoaexpire")), minimum=_int(z.get("idnssoaminimum")),
                     default_ttl=_int(z.get("dnsdefaultttl")))
        c.dns_zones.append(dz)
        reverse = zone.endswith(".in-addr.arpa") or zone.endswith(".ip6.arpa")
        for rec in rpc("dnsrecord_find", [zone], {"sizelimit": 0}):
            label = rec["idnsname"][0]
            label = label if isinstance(label, str) else label.get("__dns_name__", "")
            label = label.rstrip(".") or "@"
            if not reverse:
                for key, rtype in MIRRORED:
                    for value in rec.get(key, []):
                        dz.records.append((label, rtype, str(value)))
            if reverse or label.startswith("*"):
                continue                      # wildcard records name no single host
            fqdn = zone if label in ("@", "") else f"{label}.{zone}"
            for ip in rec.get("arecord", []) + rec.get("aaaarecord", []):
                # First name wins so a host's canonical record isn't replaced by an alias.
                if is_usable_ip(ip):
                    c.ipa_names.setdefault(ip, fqdn)

    for h in rpc("host_find", [], {"sizelimit": 0}):
        c.ipa_hosts.add(_dn(h.get("fqdn")).lower())
