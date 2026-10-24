"""VictoriaMetrics: what physical hosts' own node exporters say about their hardware.

node_dmi_info gives make, model, SKU and serial (VMs report QEMU and are left
out: Proxmox describes them). A host's physical NICs are those with a burned-in
MAC (addr_assign_type 0) and a link speed; that drops lo, WireGuard, bridges,
VLAN interfaces and veths. Their MACs tie the metrics instance ("hydrogen",
"REDACTED_IP:9100") to the host the other sources built.
"""
from __future__ import annotations

import logging
import os
import re

import requests
from pydantic import BaseModel, ValidationError

from model import Collected, HardwareObs, norm_mac, vendor_name

log = logging.getLogger("metrics")

URL = os.environ.get("VM_URL", "http://vmselect-vicmetrics-victoria-metrics-k8s-stack.monitoring.svc.cluster.local.:8481"
                     "/select/0/prometheus")
# DMI placeholders boards ship with instead of a real value
JUNK = re.compile(r"^(|0+|none|default string|to be filled by o\.e\.m\.|system (serial number|product name)|"
                  r"not specified|chassis serial number|123456789)$", re.I)


def _clean(v: str | None) -> str:
    v = (v or "").strip()
    return "" if JUNK.match(v) else v


class PromRowRaw(BaseModel):
    """One Prometheus instant-query result row: {metric: {labels}, value: [ts, "val"]}."""
    metric: dict[str, str] = {}
    value: tuple[float, str] = (0.0, "0")


def _rows(raw: list[dict], what: str) -> list[PromRowRaw]:
    out = []
    for r in raw:
        try:
            out.append(PromRowRaw.model_validate(r))
        except ValidationError as e:
            log.warning("skipping malformed %s row %r: %s", what, r, e)
    return out


def hardware(dmi: list[dict], assign: list[dict], speed: list[dict], info: list[dict]) -> list[HardwareObs]:
    """Instant-query results (Prometheus 'result' rows) -> one HardwareObs per physical instance."""
    out: dict[str, HardwareObs] = {}
    for r in _rows(dmi, "node_dmi_info"):
        m = r.metric
        if (m.get("chassis_vendor") or m.get("system_vendor") or "").upper() == "QEMU":
            continue
        out[m["instance"]] = HardwareObs(
            instance=m["instance"], vendor=vendor_name(_clean(m.get("system_vendor")) or _clean(m.get("board_vendor"))),
            model=_clean(m.get("product_name")) or _clean(m.get("board_name")), sku=_clean(m.get("product_sku")),
            serial=_clean(m.get("product_serial")) or _clean(m.get("chassis_serial")) or _clean(m.get("board_serial")))
    burned = {(r.metric["instance"], r.metric["device"]) for r in _rows(assign, "node_network_address_assign_type")
              if float(r.value[1]) == 0}
    linked = {(r.metric["instance"], r.metric["device"]) for r in _rows(speed, "node_network_speed_bytes")
              if float(r.value[1]) > 0}
    for r in _rows(info, "node_network_info"):
        m = r.metric
        key = (m.get("instance"), m.get("device"))
        mac = norm_mac(m.get("address"))
        if key[0] in out and key in burned and key in linked and mac:
            out[key[0]].nics[key[1]] = mac
    return sorted(out.values(), key=lambda h: h.instance)


def collect(c: Collected) -> None:
    s = requests.Session()

    def q(expr: str) -> list[dict]:
        r = s.get(f"{URL}/api/v1/query", params={"query": expr}, timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"VictoriaMetrics: {r.status_code} {r.text[:300]}")
        return r.json()["data"]["result"]

    c.hardware = hardware(q("node_dmi_info"), q("node_network_address_assign_type"),
                          q("node_network_speed_bytes"), q("node_network_info"))
