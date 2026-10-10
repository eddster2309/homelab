"""Minimal NetBox REST client (v2 "Bearer nbt_…" tokens), with dry-run and diffing.

pynetbox is avoided on purpose: NetBox 4.7's v2 tokens and port_mappings are
newer than what it reliably handles, and this is all we need.
"""
from __future__ import annotations

import itertools
import logging

import requests

log = logging.getLogger("netbox")

# Foreign keys NetBox returns as nested objects ({"id": …}) rather than bare ids.
NESTED_FKS = {"site", "role", "device_type", "cluster", "device", "virtual_machine", "vlan", "manufacturer",
              "type", "primary_ip4", "primary_mac_address", "tenant", "group", "parent", "bridge", "lag",
              "untagged_vlan", "platform", "nat_inside", "location", "view", "soa_mname", "zone", "oob_ip"}


def _get(obj, key, default=None):
    """Read `key` off a dict or a pydantic model alike, during the migration to typed objects."""
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


def _scalar(v):
    """Reduce NetBox's nested API representations to comparable scalars."""
    if isinstance(v, dict):
        if "value" in v and "label" in v:        # choice field, e.g. status
            return v["value"]
        if "id" in v:                             # nested FK
            return v["id"]
    elif hasattr(v, "id") and not isinstance(v, (str, int, float)):
        return v.id                               # a typed FK/object: compare by id
    return v


def diff(existing, desired: dict) -> dict:
    """Return the subset of `desired` that differs from `existing`."""
    patch = {}
    for key, want in desired.items():
        have = _get(existing, key)
        if key == "tags":
            have_s = sorted(_get(t, "slug") for t in (have or []))
            want_s = sorted(t["slug"] for t in want)
            if have_s != want_s:
                patch[key] = want
        elif key == "custom_fields":
            have = have or {}
            changed = {k: v for k, v in want.items() if _get(have, k) != v}
            if changed:
                patch[key] = changed
        elif isinstance(want, list) and want and isinstance(want[0], int):
            if sorted(_scalar(x) for x in (have or [])) != sorted(want):
                patch[key] = want
        else:
            if _scalar(have) != want and not (have in (None, "") and want in (None, "")):
                patch[key] = want
    return patch


def _parse(model, raw):
    return raw if model is dict or raw is None else model.model_validate(raw)


def _validate_write(write_model, data: dict) -> dict:
    """Re-validate an outbound PATCH/POST body against its Write model: a typo'd or
    wrong-typed field becomes a ValidationError instead of NetBox silently ignoring it
    (create) or 400ing opaquely (update). exclude_unset, not exclude_none: this codebase
    sends explicit None to clear fields (release a primary MAC, drop a VLAN mode, ...),
    and exclude_none would silently turn every one of those into a no-op."""
    if write_model is None:
        return data
    return write_model(**data).model_dump(exclude_unset=True)


class NetBox:
    def __init__(self, url: str, token: str, dry_run: bool = False):
        self.url = url.rstrip("/")
        self.dry_run = dry_run
        self.s = requests.Session()
        # Accept the token with or without a scheme prefix ("Bearer nbt_…" / "Token …")
        token = token.strip()
        for prefix in ("Bearer ", "Token "):
            token = token.removeprefix(prefix)
        self.s.headers.update({
            "Authorization": f"Bearer {token}" if token.startswith("nbt_") else f"Token {token}",
            "Accept": "application/json",
        })
        self._fake_ids = itertools.count(-1, -1)
        self.writes = {"create": 0, "update": 0, "delete": 0}

    def _req(self, method: str, path: str, **kw):
        r = self.s.request(method, f"{self.url}/api/{path.strip('/')}/", timeout=60, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path}: {r.status_code} {r.text[:500]}")
        return r.json() if r.content else None

    def list(self, path: str, model: type = dict, **params) -> list:
        params = {"limit": 1000, **params}
        out, url = [], f"{self.url}/api/{path.strip('/')}/"
        while url:
            r = self.s.get(url, params=params, timeout=120)
            if r.status_code >= 400:
                raise RuntimeError(f"GET {path}: {r.status_code} {r.text[:500]}")
            data = r.json()
            out.extend(data["results"])
            url, params = data.get("next"), None
        return [_parse(model, o) for o in out] if model is not dict else out

    # ------------------------------------------------------------- writes

    def create(self, path: str, data: dict, model: type = dict, write_model: type = None, what: str = ""):
        data = _validate_write(write_model, data)
        self.writes["create"] += 1
        log.info("CREATE %s %s", path, what or data.get("name") or data.get("address") or data)
        if self.dry_run:
            # Shape it like an API response (nested FKs) so later code works on it unchanged.
            nested = {k: ({"id": v} if k in NESTED_FKS and isinstance(v, int) else v) for k, v in data.items()}
            return _parse(model, {**nested, "id": next(self._fake_ids), "_dry": True})
        return _parse(model, self._req("POST", path, json=data))

    def update(self, path: str, obj, desired: dict, model: type = dict, write_model: type = None, what: str = ""):
        desired = _validate_write(write_model, desired)
        patch = diff(obj, desired)
        if not patch:
            return obj
        self.writes["update"] += 1
        obj_id = _get(obj, "id")
        log.info("UPDATE %s %s %s", path, what or _get(obj, "display") or obj_id, sorted(patch))
        if self.dry_run or (obj_id or 0) < 0:
            base = obj if isinstance(obj, dict) else obj.model_dump()
            return _parse(model, {**base, **patch})
        return _parse(model, self._req("PATCH", f"{path}/{obj_id}", json=patch))

    def delete(self, path: str, obj, what: str = "") -> None:
        self.writes["delete"] += 1
        obj_id = _get(obj, "id")
        log.info("DELETE %s %s", path, what or _get(obj, "display") or obj_id)
        if not self.dry_run and (obj_id or 0) > 0:
            r = self.s.delete(f"{self.url}/api/{path.strip('/')}/{obj_id}/", timeout=60)
            if r.status_code >= 400 and r.status_code != 404:   # 404: already gone (e.g. cascaded)
                raise RuntimeError(f"DELETE {path}: {r.status_code} {r.text[:300]}")
