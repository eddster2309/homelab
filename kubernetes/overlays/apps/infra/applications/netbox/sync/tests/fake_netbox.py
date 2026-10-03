"""In-memory stand-in for NetBox's REST API, shaped like the real responses
(nested FKs, {value,label} choices), for end-to-end reconcile tests."""
import itertools

from netbox_api import NetBox

FK = {"site", "role", "device_type", "cluster", "device", "virtual_machine", "vlan", "manufacturer",
      "primary_ip4", "primary_mac_address", "untagged_vlan", "platform", "cluster", "tenant", "group", "parent",
      "bridge", "lag", "nat_inside", "location", "view", "soa_mname", "zone", "oob_ip"}
CHOICE = {"status", "protocol", "type", "rf_role", "mode", "duplex"}


class FakeNetBox(NetBox):
    def __init__(self):
        super().__init__("http://fake", "nbt_x.y")
        self.store: dict[str, dict[int, dict]] = {}
        self.ids = itertools.count(1)

    def _shape(self, path, data):
        out = {}
        for k, v in data.items():
            if k in FK and isinstance(v, int):
                ref = next((o for objs in self.store.values() for o in objs.values() if o["id"] == v), {})
                v = {"id": v, "name": ref.get("name"), "slug": ref.get("slug")}
            elif k in CHOICE and isinstance(v, str):
                v = {"value": v, "label": v}
            elif k in ("ipaddresses", "wireless_lans", "tagged_vlans", "nameservers", "prefixes"):
                v = [{"id": i} for i in v]
            out[k] = v
        return out

    def seed(self, path, data):
        obj = {"id": next(self.ids), "tags": [], "custom_fields": {}, **self._shape(path, data)}
        self.store.setdefault(path, {})[obj["id"]] = obj
        return obj

    def list(self, path, **params):
        res = []
        for o in self.store.get(path, {}).values():
            ok = True
            for k, v in params.items():
                if k in ("limit",):
                    continue
                if k == "tag":
                    if not any(t["slug"] == v for t in o.get("tags", [])):
                        ok = False
                elif k.endswith("_id"):
                    ref = o.get(k[:-3])
                    if isinstance(ref, dict) and ref.get("id") != v:
                        ok = False
                elif o.get(k) != v:
                    ok = False
            if ok:
                res.append(dict(o))
        return res

    def create(self, path, data, what=""):
        self.writes["create"] += 1
        obj = self.seed(path, data)
        if path == "dcim/cables":   # like NetBox: each end's interface shows the cable
            for t in data["a_terminations"] + data["b_terminations"]:
                self.store["dcim/interfaces"][t["object_id"]]["cable"] = {"id": obj["id"]}
        return dict(obj)

    def update(self, path, obj, desired, what=""):
        from netbox_api import diff
        patch = diff(obj, desired)
        if not patch:
            return obj
        self.writes["update"] += 1
        stored = self.store[path][obj["id"]]
        self._validate(path, stored, patch)
        shaped = self._shape(path, patch)
        if "custom_fields" in shaped:
            shaped["custom_fields"] = {**stored.get("custom_fields", {}), **shaped["custom_fields"]}
        stored.update(shaped)
        return dict(stored)

    def _validate(self, path, stored, patch):
        """The NetBox model checks the sync has to work around."""
        if path == "dcim/mac-addresses" and "assigned_object_id" in patch:
            for ifpath in ("dcim/interfaces", "virtualization/interfaces"):
                old = self.store.get(ifpath, {}).get(stored.get("assigned_object_id"))
                if old and old.get("primary_mac_address") and old["primary_mac_address"]["id"] == stored["id"] \
                        and stored.get("assigned_object_type") == ("dcim.interface" if ifpath == "dcim/interfaces"
                                                                   else "virtualization.vminterface"):
                    raise RuntimeError("Cannot reassign MAC Address while it is designated as the primary MAC")
        if path == "dcim/interfaces":
            typ = patch.get("type", (stored.get("type") or {}).get("value"))
            if typ in ("bridge", "lag", "virtual") and stored.get("cable"):
                raise RuntimeError(f"{typ} interfaces cannot have a cable attached")
            lag = patch.get("lag")
            if lag and (self.store["dcim/interfaces"][lag].get("type") or {}).get("value") != "lag":
                raise RuntimeError("lag must be a LAG interface")

    def delete(self, path, obj, what=""):
        self.writes["delete"] += 1
        self.store[path].pop(obj["id"], None)
        if path == "dcim/cables":
            for i in self.store.get("dcim/interfaces", {}).values():
                if (i.get("cable") or {}).get("id") == obj["id"]:
                    i["cable"] = None
        if path == "ipam/fhrp-groups":   # like NetBox: an FHRP group's IPs go with it
            for ip in [i for i in self.store.get("ipam/ip-addresses", {}).values()
                       if i.get("assigned_object_type") == "ipam.fhrpgroup" and i.get("assigned_object_id") == obj["id"]]:
                self.store["ipam/ip-addresses"].pop(ip["id"])
