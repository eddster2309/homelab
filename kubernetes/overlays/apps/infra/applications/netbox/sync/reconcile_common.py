"""Constants and small pure helpers shared by Reconciler and its DNS/links mixins.

Kept dependency-free of reconcile.py itself (only bootstrap/model), so
reconcile_dns.py and reconcile_links.py can import from here without a
circular import back to reconcile.py, which imports their mixins.
"""
from __future__ import annotations

from datetime import datetime

from bootstrap import OWNER_TAG, SOURCE_TAGS
from nb_models import NbObject

DAY = 86400
STALE_AFTER = 7 * DAY
DELETE_AFTER = 30 * DAY
DELETABLE_KINDS = ("client",)

DEV_IF, VM_IF, FHRP = "dcim.interface", "virtualization.vminterface", "ipam.fhrpgroup"

# Omada's wifiMode -> NetBox interface type
WIFI_TYPES = {0: "ieee802.11a", 1: "ieee802.11g", 2: "ieee802.11g", 3: "ieee802.11n", 4: "ieee802.11n",
              5: "ieee802.11ac", 6: "ieee802.11ax", 7: "ieee802.11ax", 8: "ieee802.11be", 9: "ieee802.11be"}
RADIO_LABELS = {0: "2.4 GHz", 1: "5 GHz", 2: "6 GHz"}
WIRED_TYPE = "other"   # what ensure_iface creates; a cable can attach to it
VIRTUAL_TYPES = ("bridge", "lag", "virtual")   # NetBox refuses a cable on these
FHRP_PRIORITY = 100    # keepalived priorities aren't visible to the sync: one value for every holder


def _is_wireless_type(t: str | None) -> bool:
    return bool(t) and (t.startswith("ieee802.11") or t == "other-wireless")


def _ap_radio_type(model: str) -> str:
    m = model.upper()
    return ("ieee802.11be" if m.startswith("EAP7") else "ieee802.11ax" if m.startswith("EAP6")
            else "ieee802.11ac" if m.startswith("EAP2") else "other-wireless")


def _link_state(port) -> dict:
    """Negotiated speed (NetBox: Kbps) and duplex of a switch port's link; cleared while it's down.
    The interface type keeps saying what the port can do, so a gigabit port at 100M shows both."""
    return {"speed": port.speed_mbps * 1000 if port.up and port.speed_mbps else None,
            "duplex": port.duplex or None if port.up else None}


def stale_action(present: bool, age: float | None, kind: str, healthy: bool) -> str | None:
    """What to do with a synced object this run: active | stale | delete | None (leave it)."""
    if present:
        return "active"
    if not healthy or age is None:
        return None
    if age >= DELETE_AFTER and kind in DELETABLE_KINDS:
        return "delete"
    if age >= STALE_AFTER:
        return "stale"
    return None


def _tags(obj: NbObject | None, *slugs: str, keep_also: tuple[str, ...] = ()) -> list[dict]:
    """Existing non-sync tags plus ours: PATCH replaces the whole tag list. Tags in keep_also are
    managed by the caller too (dropped unless in slugs)."""
    existing = obj.tags if obj is not None else []
    keep = {t.slug for t in existing
            if t.slug not in SOURCE_TAGS.values() and t.slug != OWNER_TAG and t.slug not in keep_also}
    return [{"slug": s} for s in sorted(keep | set(slugs))]


def _has_tag(obj: NbObject | None, slug: str) -> bool:
    return obj is not None and any(t.slug == slug for t in obj.tags)


def _parse_ts(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
