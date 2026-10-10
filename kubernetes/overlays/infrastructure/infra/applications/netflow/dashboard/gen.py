#!/usr/bin/env python3
"""Generates the opnsense-netflow Grafana dashboard (ClickHouse-backed) as a gcx manifest.

  python3 gen.py && gcx resources push -p opnsense-netflow.json

LAN-side names/segments come from NetBox (netbox-sync -> netflow.nb_* ->
flows.{src,dst}_host/_segment at ingest). Devices are grouped by IP and labelled
with their *current* NetBox name, so a renamed device stays one row; the name
recorded at ingest is the fallback for addresses NetBox no longer has, then the IP.
"""
import json, os

DS = {"type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow"}

def cond(var, col):
    # "All" uses allValue '__all' (pre-quoted: Grafana inserts a custom allValue
    # raw, ignoring :singlequote) so flows whose value isn't in the option list
    # (e.g. local traffic with no country) still match.
    return f"('__all' IN (${{{var}:singlequote}}) OR {col} IN (${{{var}:singlequote}}))"

# Filters for the flows_5m rollup. It has no LAN segment, so Segment can't apply
# to the panels built on it (map, countries, remote networks).
F5 = " AND ".join([cond("country", "remote_country"), cond("proto", "proto")])
NO_SEG = " Not filtered by Segment (the country/ASN rollup has no LAN side)."

def name_of(side):
    """Current NetBox name, else the name recorded at ingest, else the IP."""
    return (f"dictGetOrDefault('netflow.nb_host_dict', 'name', tuple({side}_addr), "
            f"if({side}_host != '', {side}_host, {side}_addr))")


def name_for(addr):
    return f"dictGetOrDefault('netflow.nb_host_dict', 'name', tuple({addr}), {addr})"


PREFIX_ATTR = "dictGetOrDefault('netflow.nb_prefix_dict', '{attr}', toIPv6OrDefault({addr}), {default})"


def seg_of(addr, stored):
    """Segment for one address: the one stored at ingest, else NetBox's current prefix (for flows
    from before a prefix existed, e.g. the remote sites), plus " via <interface>" when it's routed."""
    via = PREFIX_ATTR.format(attr="via", addr=addr, default="''")
    return (f"concat(if({stored} != '', {stored}, {PREFIX_ATTR.format(attr='segment', addr=addr, default=repr(''))}), "
            f"if({via} = '', '', concat(' via ', {via})))")


# Rollups (flows_lan_5m, flows_domain_5m): group by lan_ip, label with the current name
LAN_NAME = "dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(lan_ip), any(lan_host))"


# Raw flows: derive the same remote-side fields the rollup MV computes
RAW_WITH = (
    "WITH multiIf(dst_country != '', 'out', src_country != '', 'in', 'local') AS dir,\n"
    "     dir = 'in' AS remote_is_src,\n"
    "     if(remote_is_src, src_country, dst_country) AS rc,\n"
    "     if(remote_is_src, dst_addr, src_addr) AS lan_addr,\n"
    "     if(remote_is_src, src_addr, dst_addr) AS remote_addr,\n"
    f"     {name_of('src')} AS src_name,\n"
    f"     {name_of('dst')} AS dst_name,\n"
    "     if(remote_is_src, dst_name, src_name) AS lan_name,\n"
    "     if(remote_is_src, dst_segment, src_segment) AS lan_segment\n"
)
SEG = ("('__all' IN (${segment:singlequote}) OR src_segment IN (${segment:singlequote}) "
       "OR dst_segment IN (${segment:singlequote}))")
FR = " AND ".join(["$__timeFilter(time_received)", cond("country", "rc"), cond("proto", "proto"), SEG])
# flows_domain_5m (internet traffic by LAN host x domain, 1y)
FDOM = " AND ".join(["$__timeFilter(ts)", cond("country", "remote_country"), cond("proto", "proto"),
                     cond("segment", "lan_segment")])
PORTNAME = "dictGetOrDefault('netflow.port_names_dict', 'name', (proto, toUInt16({0})), '')"
# flows_lan_5m (per-LAN-host rollup, 1y)
FLAN = " AND ".join(["$__timeFilter(ts)", cond("country", "peer_country"), cond("proto", "proto"),
                     cond("segment", "lan_segment")])

BUCKET = "greatest($__interval_s, 300)"

def target(sql, ts=False):
    return {"refId": "A", "datasource": DS, "editorType": "sql", "rawSql": sql.strip(),
            "format": 0 if ts else 1, "queryType": "timeseries" if ts else "table"}

panels = []
def panel(id, title, type, gp, sql, desc="", ts=False, unit=None, options=None, fc=None, overrides=None):
    p = {"id": id, "title": title, "type": type, "datasource": DS, "description": desc,
         "gridPos": dict(zip("xywh", gp)), "targets": [target(sql, ts)],
         "fieldConfig": {"defaults": fc or {}, "overrides": overrides or []},
         "options": options or {}}
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    panels.append(p)

STAT = {"colorMode": "value", "graphMode": "none", "justifyMode": "center", "textMode": "value",
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": ""}}
def stat(id, x, w, title, sql, unit, desc, color):
    panel(id, title, "stat", (x, 0, w, 4), sql, desc, unit=unit, options=STAT,
          fc={"color": {"mode": "fixed", "fixedColor": color}, "decimals": 1 if unit == "decbytes" else 0})

# Headline numbers come from the per-LAN-host rollup so Segment applies. Internet
# peers have peer_segment 'internet'; for LAN<->LAN each flow has one tx row
# (its source), so sum(tx_bytes) counts it once.
stat(11, 0, 3, "Internet download", f"SELECT sum(rx_bytes) FROM netflow.flows_lan_5m WHERE {FLAN} AND peer_segment = 'internet'",
     "decbytes", "Bytes from internet hosts to the LAN.", "blue")
stat(12, 3, 3, "Internet upload", f"SELECT sum(tx_bytes) FROM netflow.flows_lan_5m WHERE {FLAN} AND peer_segment = 'internet'",
     "decbytes", "Bytes from the LAN to internet hosts.", "orange")
stat(10, 6, 3, "LAN ↔ LAN routed", f"SELECT sum(tx_bytes) FROM netflow.flows_lan_5m WHERE {FLAN} AND peer_segment != 'internet'",
     "decbytes", "Bytes OPNsense routed between local subnets (same-subnet traffic never reaches it). "
     "With a Segment selected: bytes sent from that segment.", "purple")
stat(13, 9, 3, "Active LAN devices", f"SELECT uniqExact(lan_ip) FROM netflow.flows_lan_5m WHERE {FLAN} AND peer_segment = 'internet'",
     "short", "Distinct LAN addresses that exchanged traffic with the internet.", "text")

panel(1, "Where is my network talking to?", "geomap", (0, 12, 12, 11), f"""
SELECT remote_lat AS lat, remote_lon AS lon,
       remote_country_name AS country, any(remote_city) AS city,
       topK(1)(remote_as_org)[1] AS network,
       sum(bytes) AS bytes, sum(flows) AS flows
FROM netflow.flows_5m
WHERE $__timeFilter(ts) AND remote_country != '' AND (remote_lat != 0 OR remote_lon != 0) AND {F5}
GROUP BY lat, lon, country
ORDER BY bytes DESC
LIMIT 2000""", "Remote end of every internet flow (in and out), sized by bytes. Location is MaxMind GeoLite2 city-level." + NO_SEG,
      options={
          "basemap": {"config": {}, "name": "Basemap", "type": "default"},
          "controls": {"mouseWheelZoom": True, "showAttribution": True, "showZoom": True,
                       "showDebug": False, "showMeasure": False, "showScale": False},
          "layers": [{
              "type": "markers", "name": "Remote hosts", "tooltip": True,
              "location": {"mode": "coords", "latitude": "lat", "longitude": "lon"},
              "config": {"showLegend": False, "style": {
                  "color": {"fixed": "dark-orange"}, "opacity": 0.6,
                  "size": {"field": "bytes", "fixed": 5, "min": 3, "max": 25},
                  "symbol": {"fixed": "img/icons/marker/circle.svg", "mode": "fixed"}}}}],
          "view": {"id": "zero", "lat": 10, "lon": 60, "zoom": 1},
          "tooltip": {"mode": "details"}},
      overrides=[{"matcher": {"id": "byName", "options": "bytes"}, "properties": [{"id": "unit", "value": "decbytes"}]},
                 {"matcher": {"id": "byName", "options": "flows"}, "properties": [{"id": "unit", "value": "short"}]}])

TSOPTS = {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max"]},
          "tooltip": {"mode": "multi", "sort": "desc"}}
TSFC = {"custom": {"drawStyle": "line", "fillOpacity": 15, "lineWidth": 1, "stacking": {"mode": "normal", "group": "A"},
                   "showPoints": "never", "axisSoftMin": 0}}

# Internet only: download above the axis, upload mirrored below. LAN<->LAN lives
# in its own row, where its much larger volume doesn't flatten this chart.
panel(2, "Internet throughput", "timeseries", (0, 4, 24, 8), f"""
SELECT toStartOfInterval(ts, INTERVAL {BUCKET} second) AS time,
       sum(rx_bytes) * 8 / {BUCKET} AS download,
       sum(tx_bytes) * 8 / {BUCKET} AS upload
FROM netflow.flows_lan_5m
WHERE {FLAN} AND peer_segment = 'internet'
GROUP BY time ORDER BY time""",
      "Average bits/s per 5-minute (or wider) bucket. Download above the axis, upload below.",
      ts=True, unit="bps", options=TSOPTS,
      fc={"custom": {**TSFC["custom"], "stacking": {"mode": "none", "group": "A"}, "axisSoftMin": None, "fillOpacity": 25}},
      overrides=[{"matcher": {"id": "byName", "options": "download"}, "properties": [
                     {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
                 {"matcher": {"id": "byName", "options": "upload"}, "properties": [
                     {"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}},
                     {"id": "custom.transform", "value": "negative-Y"}]}])

panel(4, "Top countries", "barchart", (12, 12, 12, 11), f"""
SELECT remote_country_name AS country,
       sumIf(bytes, direction = 'in') AS downloaded,
       sumIf(bytes, direction = 'out') AS uploaded
FROM netflow.flows_5m
WHERE $__timeFilter(ts) AND remote_country != '' AND {F5}
GROUP BY country ORDER BY downloaded + uploaded DESC LIMIT 12""",
      "Bytes by remote country." + NO_SEG, unit="decbytes",
      options={"orientation": "horizontal", "stacking": "normal", "showValue": "never", "xTickLabelRotation": 0,
               "legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
      fc={"custom": {"fillOpacity": 80}},
      overrides=[{"matcher": {"id": "byName", "options": n}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
                 for n, c in (("downloaded", "blue"), ("uploaded", "orange"))])

TABLE = {"cellHeight": "sm", "showHeader": True, "footer": {"show": False}}
COLORS = {"downloaded": "blue", "uploaded": "orange"}
def bytes_cols(*names):
    return [{"matcher": {"id": "byName", "options": n}, "properties": [{"id": "unit", "value": "decbytes"},
            {"id": "color", "value": {"mode": "fixed", "fixedColor": COLORS[n]}},
            {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}}]} for n in names]

panel(5, "Top remote networks", "table", (11, 35, 8, 11), f"""
SELECT topK(1)(remote_as_org)[1] AS network, remote_asn AS asn,
       topK(1)(remote_country)[1] AS country,
       sumIf(bytes, direction = 'in') AS downloaded,
       sumIf(bytes, direction = 'out') AS uploaded
FROM netflow.flows_5m
WHERE $__timeFilter(ts) AND remote_asn != 0 AND {F5}
GROUP BY asn ORDER BY downloaded + uploaded DESC LIMIT 25""",
      "Autonomous systems (MaxMind GeoLite2 ASN) ranked by total bytes." + NO_SEG, options=TABLE,
      overrides=bytes_cols("downloaded", "uploaded") + [{"matcher": {"id": "byName", "options": "asn"}, "properties": [{"id": "custom.width", "value": 80}]},
                                                       {"matcher": {"id": "byName", "options": "country"}, "properties": [{"id": "custom.width", "value": 80}]}])

panel(6, "Top LAN devices", "table", (0, 24, 12, 10), f"""
SELECT {LAN_NAME} AS device, lan_ip AS ip, {seg_of('lan_ip', 'any(lan_segment)')} AS segment,
       sum(rx_bytes) AS downloaded, sum(tx_bytes) AS uploaded,
       uniqExact(peer) AS remote_networks, sum(flows) AS flows
FROM netflow.flows_lan_5m
WHERE {FLAN} AND peer_segment = 'internet'
GROUP BY ip ORDER BY downloaded + uploaded DESC LIMIT 25""",
      "LAN hosts (NetBox names) ranked by internet traffic. From the per-host rollup, so it works over long ranges.",
      options=TABLE, overrides=bytes_cols("downloaded", "uploaded"))

panel(7, "Top internet services (remote port)", "table", (12, 67, 12, 10), f"""
{RAW_WITH}SELECT if(remote_is_src, src_port, dst_port) AS port, proto, {PORTNAME.format('port')} AS service_name,
       sumIf(bytes, dir = 'in') AS downloaded,
       sumIf(bytes, dir = 'out') AS uploaded,
       uniqExact(remote_addr) AS remote_hosts,
       count() AS flows
FROM netflow.flows
WHERE {FR} AND dir != 'local' AND port != 0
GROUP BY port, proto ORDER BY downloaded + uploaded DESC LIMIT 25""",
      "Remote-side port of internet flows, i.e. the service being used (443 = HTTPS, 53 = DNS...).",
      options=TABLE, overrides=bytes_cols("downloaded", "uploaded"))

# --- Devices: LAN<->internet only; LAN-to-LAN is in "Inside the network".

TALK_BUCKET = "greatest($__interval_s, 60)"
panel(21, "LAN talkers over time (top 8)", "timeseries", (12, 24, 12, 10), f"""
SELECT toStartOfInterval(ts, INTERVAL {BUCKET} second) AS time,
       {LAN_NAME} AS device, lan_ip AS ip,
       sum(tx_bytes + rx_bytes) * 8 / {BUCKET} AS bps
FROM netflow.flows_lan_5m
WHERE {FLAN} AND peer_segment = 'internet' AND lan_ip IN (
    SELECT lan_ip FROM netflow.flows_lan_5m
    WHERE {FLAN} AND peer_segment = 'internet'
    GROUP BY lan_ip ORDER BY sum(tx_bytes + rx_bytes) DESC LIMIT 8)
GROUP BY time, ip ORDER BY time""",
      "Internet bits/s (in + out) for the 8 LAN addresses with the most internet bytes in the range. LAN-to-LAN traffic excluded.",
      ts=True, unit="bps", options={**TSOPTS, "legend": {"displayMode": "list", "placement": "bottom"}},
      fc={**json.loads(json.dumps(TSFC)), "displayName": "${__field.labels.device}", "color": {"mode": "palette-classic"}})

# --- LAN<->LAN: only flows where neither end resolved to a GeoIP location.
# NetFlow only sees traffic OPNsense routes (inter-VLAN/subnet), not
# same-subnet traffic switched directly between hosts.

# Unordered pair: a = lower address, b = higher, so A->B and B->A roll up together
PAIR_WITH = (
    "WITH least(src_addr, dst_addr) AS a, greatest(src_addr, dst_addr) AS b\n"
)
FL = " AND ".join(["$__timeFilter(time_received)", "src_country = ''", "dst_country = ''", cond("proto", "proto"), SEG])

panel(31, "Top LAN pairs", "table", (12, 47, 12, 10), f"""
{PAIR_WITH}SELECT {name_for('a')} AS device_a, {name_for('b')} AS device_b, a AS ip_a, b AS ip_b,
       sumIf(bytes, src_addr = a) AS a_to_b,
       sumIf(bytes, src_addr = b) AS b_to_a,
       sum(bytes) AS total,
       topK(1)(concat(proto, '/', toString(least(src_port, dst_port))))[1] AS main_service,
       count() AS flows
FROM netflow.flows
WHERE {FL}
GROUP BY a, b ORDER BY total DESC LIMIT 25""",
      "Total traffic between two local addresses, both directions combined. main_service = most common proto/lower port. "
      "Only traffic routed by OPNsense between subnets is visible; same-subnet traffic never reaches the firewall.",
      options=TABLE,
      overrides=[{"matcher": {"id": "byName", "options": n}, "properties": [{"id": "unit", "value": "decbytes"}]} for n in ("a_to_b", "b_to_a")]
               + [{"matcher": {"id": "byName", "options": "total"}, "properties": [
                   {"id": "unit", "value": "decbytes"}, {"id": "color", "value": {"mode": "fixed", "fixedColor": "purple"}},
                   {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}}]}])

# --- Network segments: NetBox prefix names (users, kubernetes, cctv...), falling
# back to the routing prefix OPNsense exports for each end. REDACTED_IP/0 = internet.

# Segment stored at ingest, else NetBox's current prefix for the address (prefixes added
# later, e.g. remote sites), else OPNsense's routing prefix; plus the interface it's
# routed over when that isn't a local VLAN (" via INTER_WG_TO_CBR (wg1)").
SEGNAME = ("concat(if({0}_segment != '', {0}_segment, if({0}_net = 'REDACTED_IP/0', 'internet', "
           + PREFIX_ATTR.format(attr="segment", addr="{0}_addr", default="{0}_net") + ")), "
           "if(" + PREFIX_ATTR.format(attr="via", addr="{0}_addr", default="''") + " = '', '', concat(' via ', "
           + PREFIX_ATTR.format(attr="via", addr="{0}_addr", default="''") + ")))")
panel(41, "Traffic between segments", "table", (0, 47, 12, 10), f"""
{RAW_WITH}SELECT {SEGNAME.format('src')} AS from_segment, {SEGNAME.format('dst')} AS to_segment,
       sum(bytes) AS bytes, sum(packets) AS packets, count() AS flows,
       uniqExact(src_addr) AS senders, uniqExact(dst_addr) AS receivers
FROM netflow.flows
WHERE {FR}
GROUP BY from_segment, to_segment ORDER BY bytes DESC LIMIT 30""",
      "Routed traffic by source → destination segment (NetBox prefix names). One-way: A→B and B→A are separate rows. "
      "Segments reached over a tunnel or route say which OPNsense interface (via ...).",
      options=TABLE,
      overrides=[{"matcher": {"id": "byName", "options": "bytes"}, "properties": [
                     {"id": "unit", "value": "decbytes"}, {"id": "color", "value": {"mode": "fixed", "fixedColor": "purple"}},
                     {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}}]},
                 {"matcher": {"id": "byName", "options": "packets"}, "properties": [{"id": "unit", "value": "short"}]}])

panel(42, "Throughput by segment", "timeseries", (0, 57, 24, 8), f"""
{RAW_WITH}SELECT toStartOfInterval(time_received, INTERVAL {TALK_BUCKET} second) AS time,
       arrayJoin(arrayFilter(n -> n != 'internet', [{SEGNAME.format('src')}, {SEGNAME.format('dst')}])) AS subnet,
       sum(bytes) * 8 / {TALK_BUCKET} AS bps
FROM netflow.flows
WHERE {FR}
GROUP BY time, subnet
HAVING subnet IN (
    {RAW_WITH}SELECT arrayJoin(arrayFilter(n -> n != 'internet', [{SEGNAME.format('src')}, {SEGNAME.format('dst')}])) AS s
    FROM netflow.flows WHERE {FR}
    GROUP BY s ORDER BY sum(bytes) DESC LIMIT 8)
ORDER BY time""",
      "Bits/s of all routed traffic touching each local segment (internet and inter-segment, both directions). "
      "Inter-segment traffic counts toward both. Top 8 segments.",
      ts=True, unit="bps", options=TSOPTS,
      fc={**json.loads(json.dumps(TSFC)), "displayName": "${__field.labels.subnet}", "color": {"mode": "palette-classic"},
          "custom": {**TSFC["custom"], "stacking": {"mode": "none", "group": "A"}}})

# --- Services NetBox knows about (collapsed "Services & raw flows" row)

panel(61, "Services in use", "table", (0, 67, 12, 10), f"""
{RAW_WITH}SELECT service,
       if(dst_host_kind IN ('k8s-vip', 'external-service') OR dst_segment != lan_segment, src_name, dst_name) AS client,
       if(dst_host_kind IN ('k8s-vip', 'external-service') OR dst_segment != lan_segment, src_addr, dst_addr) AS client_ip,
       sum(bytes) AS bytes, count() AS flows, max(time_received) AS last_seen
FROM netflow.flows
WHERE {FR} AND service != ''
GROUP BY service, client, client_ip ORDER BY bytes DESC LIMIT 30""",
      "Traffic to services NetBox knows about: k8s LoadBalancer ports (with the hosts Traefik routes on them) "
      "and hosts behind k8s external-service entries. client = the other end.",
      options=TABLE, overrides=[{"matcher": {"id": "byName", "options": "bytes"}, "properties": [
                                   {"id": "unit", "value": "decbytes"}, {"id": "color", "value": {"mode": "fixed", "fixedColor": "purple"}},
                                   {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}}]},
                                {"matcher": {"id": "byName", "options": "last_seen"}, "properties": [{"id": "custom.width", "value": 170}]}])

# Multicast/broadcast/unspecified destinations are not devices
REAL_HOST = "NOT isIPAddressInRange(ip, 'REDACTED_IP/4') AND ip NOT IN ('REDACTED_IP', 'REDACTED_IP') AND NOT endsWith(ip, '.255')"
UNIDENTIFIED = f"""
{RAW_WITH}SELECT arrayJoin(if(dir = 'local', [src_addr, dst_addr], [lan_addr])) AS ip,
       {name_for('ip')} AS netbox_name,
       {seg_of('ip', 'any(if(ip = src_addr, src_segment, dst_segment))')} AS segment,
       sumIf(bytes, ip = src_addr) AS sent, sumIf(bytes, ip = dst_addr) AS received,
       count() AS flows, max(time_received) AS last_seen
FROM netflow.flows
WHERE {FR}
GROUP BY ip
HAVING (netbox_name = ip OR startsWith(netbox_name, 'client-')) AND sent > 0 AND {REAL_HOST}"""
panel(62, "Unidentified hosts", "table", (0, 82, 12, 10), UNIDENTIFIED + "\nORDER BY sent + received DESC LIMIT 30",
      "Local addresses that sent traffic but have no NetBox host, or only a generated client-xxxxxx name. Name them in NetBox "
      "(tag sync-locked so the sync keeps your name) and new flows pick it up within ~7 minutes. "
      "Addresses that never answer are under No reply.",
      options=TABLE, overrides=[{"matcher": {"id": "byName", "options": n}, "properties": [{"id": "unit", "value": "decbytes"}]}
                                for n in ("sent", "received")]
                               + [{"matcher": {"id": "byName", "options": "last_seen"}, "properties": [{"id": "custom.width", "value": 170}]}])

# Routed LAN destinations that never sent a packet in the range: dead hosts, moved
# IPs, or roaming devices looking for their other network. Any real reply would
# be routed back through OPNsense, so its absence is meaningful.
NO_REPLY = f"""
{RAW_WITH}SELECT dst_addr AS ip, {name_for('ip')} AS netbox_name, {seg_of('ip', 'any(dst_segment)')} AS segment,
       arrayStringConcat(groupUniqArray(4)(src_name), ', ') AS callers,
       arrayStringConcat(groupUniqArray(4)(concat(proto, '/', toString(dst_port))), ', ') AS ports,
       count() AS flows, max(time_received) AS last_seen
FROM netflow.flows
WHERE {FR} AND dir = 'local'
GROUP BY ip
HAVING ip NOT IN (SELECT DISTINCT src_addr FROM netflow.flows WHERE $__timeFilter(time_received)) AND {REAL_HOST}"""
panel(63, "No reply", "table", (12, 82, 12, 10), NO_REPLY + "\nORDER BY flows DESC LIMIT 30",
      "Local addresses that were sent traffic but never sent anything back in the range: a device that's off or "
      "changed IP (fix whatever still points at it), or a laptop/phone looking for devices on another network it joined. "
      "callers = who keeps trying.",
      options=TABLE, overrides=[{"matcher": {"id": "byName", "options": "last_seen"}, "properties": [{"id": "custom.width", "value": 170}]}])

# --- Hygiene: things that are usually empty/small; a row showing up is worth a look.
# Counted in the "Needs attention" stat; the tables sit in the collapsed "Security & hygiene" row.

EXT_DNS = "dir != 'local' AND if(remote_is_src, src_port, dst_port) IN (53, 853)"
panel(51, "LAN devices using external DNS", "table", (0, 72, 8, 10), f"""
{RAW_WITH}SELECT lan_name AS device, lan_addr AS ip, remote_addr AS resolver,
       any(if(remote_is_src, src_as_org, dst_as_org)) AS network,
       concat(proto, '/', toString(if(remote_is_src, src_port, dst_port))) AS service,
       count() AS flows, max(time_received) AS last_seen
FROM netflow.flows
WHERE {FR} AND {EXT_DNS}
GROUP BY device, ip, resolver, service ORDER BY flows DESC LIMIT 25""",
      "LAN devices talking DNS (53) or DNS-over-TLS (853) straight to internet resolvers instead of the local resolver. "
      "Empty is healthy. DNS-over-HTTPS (443) can't be told apart from normal HTTPS here.",
      options=TABLE, overrides=[{"matcher": {"id": "byName", "options": "last_seen"}, "properties": [{"id": "custom.width", "value": 170}]}])

panel(52, "TCP resets (RST-only flows)", "table", (8, 72, 8, 10), f"""
{RAW_WITH}SELECT src_name AS source, src_addr AS src_ip, dst_name AS destination, dst_addr AS dst_ip, dst_port AS port,
       if(dst_country != '', dst_as_org, if(src_country != '', src_as_org, 'LAN')) AS network,
       count() AS flows, max(time_received) AS last_seen
FROM netflow.flows
WHERE {FR} AND proto = 'TCP' AND tcp_flags = 4
GROUP BY source, src_ip, destination, dst_ip, port, network ORDER BY flows DESC LIMIT 25""",
      "TCP flows whose only flag is RST: connections refused, or torn down by one side. "
      "A steady stream to one destination usually means something retrying against a dead or blocked endpoint.",
      options=TABLE, overrides=[{"matcher": {"id": "byName", "options": "last_seen"}, "properties": [{"id": "custom.width", "value": 170}]},
                                {"matcher": {"id": "byName", "options": "port"}, "properties": [{"id": "custom.width", "value": 60}]}])

# First-seen is computed over everything retained (30d TTL), not just the time range
LOCAL_ADDRS = "arrayJoin(if(dir = 'local', [src_addr, dst_addr], [lan_addr]))"
NEW_DEVICES = f"""
{RAW_WITH}SELECT {LOCAL_ADDRS} AS ip, {name_for('ip')} AS device,
       min(time_received) AS first_seen,
       max(time_received) AS last_seen,
       sum(bytes) AS bytes
FROM netflow.flows
GROUP BY ip
HAVING first_seen >= $__fromTime AND {REAL_HOST}"""
panel(53, "Newly seen LAN devices", "table", (16, 72, 8, 10), NEW_DEVICES + "\nORDER BY first_seen DESC LIMIT 25",
      "Local addresses whose first flow in the retained data (up to 30 days) falls inside the selected time range. "
      "Until the store has some history, everything counts as new.",
      options=TABLE, overrides=[{"matcher": {"id": "byName", "options": "bytes"}, "properties": [{"id": "unit", "value": "decbytes"}]}]
                               + [{"matcher": {"id": "byName", "options": n}, "properties": [{"id": "custom.width", "value": 170}]}
                                  for n in ("first_seen", "last_seen")])

# --- Destinations: DNS names (Blocky answers matched to flows), cloud services, threat lists.

panel(71, "Top domains", "table", (0, 35, 11, 11), f"""
SELECT if(domain != '', domain, concat('(no DNS) ', remote_org)) AS destination,
       sum(rx_bytes) AS downloaded, sum(tx_bytes) AS uploaded,
       uniqExact(lan_ip) AS devices,
       sumIf(rx_bytes + tx_bytes, domain_names <= 1) / greatest(sum(rx_bytes + tx_bytes), 1) AS certain
FROM netflow.flows_domain_5m
WHERE {FDOM}
GROUP BY destination ORDER BY downloaded + uploaded DESC LIMIT 30""",
      "Internet traffic by the domain the device looked up (Blocky DNS answers matched to flows). "
      "'(no DNS)' = no matching lookup: DNS-over-HTTPS, hard-coded IPs, or a lookup older than a day. "
      "certain = share of bytes where the device had only this one name for the IP; lower means the name is the "
      "best guess among several sharing an IP (CDNs, the Traefik VIP).",
      options=TABLE, overrides=bytes_cols("downloaded", "uploaded") + [{"matcher": {"id": "byName", "options": "certain"}, "properties": [{"id": "unit", "value": "percentunit"}, {"id": "decimals", "value": 0}, {"id": "custom.width", "value": 80}]}])

panel(73, "DNS coverage", "stat", (12, 0, 3, 4), f"""
SELECT sumIf(tx_bytes + rx_bytes, domain != '') / greatest(sum(tx_bytes + rx_bytes), 1)
FROM netflow.flows_domain_5m WHERE {FDOM}""",
      "Share of internet bytes whose destination was matched to a DNS lookup.", unit="percentunit",
      options=STAT, fc={"color": {"mode": "fixed", "fixedColor": "green"}, "decimals": 0})

panel(74, "Cloud services", "barchart", (19, 35, 5, 11), f"""
SELECT remote_cloud AS service, sum(rx_bytes + tx_bytes) AS bytes
FROM netflow.flows_domain_5m
WHERE {FDOM} AND remote_cloud != ''
GROUP BY service ORDER BY bytes DESC LIMIT 10""",
      "Internet bytes by cloud provider/service/region, from published ranges (AWS, Google, Cloudflare, GitHub, Microsoft 365).",
      unit="decbytes", options={"orientation": "horizontal", "showValue": "never", "legend": {"showLegend": False},
                                "xTickLabelRotation": 0, "tooltip": {"mode": "single"}},
      fc={"custom": {"fillOpacity": 80}, "color": {"mode": "fixed", "fixedColor": "blue"}})

panel(75, "Traffic to listed threats", "table", (0, 66, 24, 6), f"""
{RAW_WITH}SELECT lan_name AS device, lan_addr AS ip, remote_addr AS remote, threat, domain,
       any(if(remote_is_src, src_as_org, dst_as_org)) AS network, rc AS country,
       sum(bytes) AS bytes, count() AS flows, max(time_received) AS last_seen
FROM netflow.flows
WHERE {FR} AND threat != ''
GROUP BY device, ip, remote, threat, domain, country ORDER BY last_seen DESC LIMIT 50""",
      "Flows whose remote end is on a threat list: Spamhaus DROP (hijacked/criminal netblocks), abuse.ch Feodo "
      "(botnet C2), Tor exit nodes, or an active CrowdSec ban. Empty is healthy; Tor may be expected.",
      options=TABLE, overrides=[{"matcher": {"id": "byName", "options": "bytes"}, "properties": [{"id": "unit", "value": "decbytes"}]},
                                {"matcher": {"id": "byName", "options": "threat"}, "properties": [
                                    {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                                    {"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]},
                                {"matcher": {"id": "byName", "options": "last_seen"}, "properties": [{"id": "custom.width", "value": 170}]}])

panel(8, "Recent internet flows", "table", (0, 77, 24, 12), f"""
{RAW_WITH}SELECT time_received AS time, dir AS direction,
       concat(src_name, ':', toString(src_port)) AS source,
       concat(dst_name, ':', toString(dst_port)) AS destination,
       concat(domain, if(domain_names > 1, concat(' (1 of ', toString(domain_names), ')'), '')) AS domain,
       service, remote_cloud AS cloud, threat,
       proto, bytes, packets,
       rc AS country,
       if(remote_is_src, src_city, dst_city) AS city,
       if(remote_is_src, src_as_org, dst_as_org) AS network,
       src_addr, dst_addr
FROM netflow.flows
WHERE {FR} AND dir != 'local'
ORDER BY time_received DESC LIMIT 500""",
      "Latest 500 internet flows, newest first.", options={**TABLE, "sortBy": []},
      overrides=[{"matcher": {"id": "byName", "options": "bytes"}, "properties": [{"id": "unit", "value": "decbytes"}]},
                 {"matcher": {"id": "byName", "options": "time"}, "properties": [{"id": "custom.width", "value": 190}]},
                 {"matcher": {"id": "byName", "options": "direction"}, "properties": [{"id": "custom.width", "value": 90}]}])

# One number per hygiene table, so the collapsed "Security & hygiene" row only needs opening when one is non-zero
panel(80, "Needs attention", "stat", (15, 0, 9, 4), f"""
SELECT ({RAW_WITH}SELECT uniqExact(lan_addr) FROM netflow.flows WHERE {FR} AND threat != '') AS `Threat contacts`,
       ({RAW_WITH}SELECT uniqExact(lan_addr) FROM netflow.flows WHERE {FR} AND {EXT_DNS}) AS `External DNS`,
       (SELECT count() FROM ({UNIDENTIFIED})) AS `Unidentified`,
       (SELECT count() FROM ({NO_REPLY})) AS `No reply`,
       (SELECT count() FROM ({NEW_DEVICES})) AS `New devices`""",
      "LAN devices that contacted a listed threat or used an internet DNS resolver, local addresses NetBox can't name, "
      "local addresses that never answer, "
      "and addresses first seen in this time range. Details: the Security & hygiene row below.",
      options={**STAT, "textMode": "value_and_name", "colorMode": "background", "wideLayout": True},
      fc={"color": {"mode": "thresholds"}, "decimals": 0,
          "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 1}]}},
      overrides=[{"matcher": {"id": "byName", "options": "Threat contacts"}, "properties": [{"id": "thresholds", "value": {
                     "mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 1}]}}]}])

# Every local host -> the Host Traffic dashboard (gen_host.py) for that IP.
HOST_URL = "/d/netflow-host/host-traffic?var-ip=IP_VALUE&${__url_time_range}"


def host_links(ip_ref):
    return [{"title": "Investigate this host", "url": HOST_URL.replace("IP_VALUE", ip_ref)}]


# panel id -> [(column, column holding its IP)]
TABLE_LINKS = {
    6: [("device", "ip"), ("ip", "ip")],
    31: [("device_a", "ip_a"), ("device_b", "ip_b"), ("ip_a", "ip_a"), ("ip_b", "ip_b")],
    51: [("device", "ip"), ("ip", "ip")],
    52: [("source", "src_ip"), ("destination", "dst_ip"), ("src_ip", "src_ip"), ("dst_ip", "dst_ip")],
    53: [("device", "ip"), ("ip", "ip")],
    61: [("client", "client_ip"), ("client_ip", "client_ip")],
    62: [("ip", "ip"), ("netbox_name", "ip")],
    63: [("ip", "ip")],
    75: [("device", "ip"), ("ip", "ip")],
    8: [("source", "src_addr"), ("destination", "dst_addr")],
}
HIDDEN = {8: ["src_addr", "dst_addr"], 31: ["ip_a", "ip_b"]}
for p in panels:
    for col, ip_col in TABLE_LINKS.get(p["id"], []):
        p["fieldConfig"]["overrides"].append({"matcher": {"id": "byName", "options": col},
                                              "properties": [{"id": "links", "value": host_links(f"${{__data.fields.{ip_col}}}")}]})
    for col in HIDDEN.get(p["id"], []):
        p["fieldConfig"]["overrides"].append({"matcher": {"id": "byName", "options": col},
                                              "properties": [{"id": "custom.hidden", "value": True}]})
    if p["id"] == 21:        # series carry the IP as a label
        p["fieldConfig"]["defaults"]["links"] = host_links("${__field.labels.ip}")

# Rows: (id, title, y, collapsed, children). A collapsed row carries its panels;
# open rows just head whatever sits below them.
ROWS = [(20, "Devices (internet traffic)", 23, False, []),
        (70, "Destinations (DNS, networks, cloud)", 34, False, []),
        (30, "Inside the network (routed between local subnets)", 46, False, []),
        (50, "Security & hygiene", 65, True, [75, 51, 52, 53, 62, 63]),
        (60, "Services & raw flows", 66, True, [61, 7, 8])]
for rid, title, y, collapsed, children in ROWS:
    kids = [p for p in panels if p["id"] in children]
    panels[:] = [p for p in panels if p["id"] not in children]
    panels.append({"id": rid, "type": "row", "title": title, "collapsed": collapsed,
                   "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": kids})
panels.sort(key=lambda p: (p["gridPos"]["y"], p["gridPos"]["x"]))


def var(name, label, query=None, custom=None):
    v = {"name": name, "label": label, "multi": True, "includeAll": True, "allValue": "'__all'",
         "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "hide": 0}
    if custom:
        v.update({"type": "custom", "query": custom,
                  "options": [{"text": o, "value": o, "selected": False} for o in custom.split(",")]})
    else:
        v.update({"type": "query", "datasource": DS, "query": query, "definition": query, "refresh": 2, "sort": 1})
    return v

dash = {
    "apiVersion": "dashboard.grafana.app/v1beta1",
    "kind": "Dashboard",
    "metadata": {"name": "opnsense-netflow"},
    "spec": {
        "title": "Home Network Traffic",
        "description": "OPNsense NetFlow: goflow2 -> Kafka -> ClickHouse (netflow namespace), enriched with GeoIP/ASN, NetBox hosts, Blocky DNS names, cloud ranges and threat lists. Source: kubernetes/overlays/infrastructure/infra/applications/netflow/dashboard/gen.py",
        "tags": ["gcx", "opnsense", "netflow", "home-network", "clickhouse"],
        "timezone": "browser", "schemaVersion": 42, "refresh": "1m", "editable": True,
        "time": {"from": "now-6h", "to": "now"},
        "links": [{"title": "Host Traffic", "type": "link", "icon": "dashboard", "targetBlank": False,
                   "tooltip": "Investigate one local IP (or click any local host in a table)",
                   "url": "/d/netflow-host/host-traffic?${__url_time_range}"}],
        "templating": {"list": [
            var("country", "Country", query="SELECT DISTINCT remote_country FROM netflow.flows_5m WHERE $__timeFilter(ts) AND remote_country != ''"),
            var("proto", "Protocol", query="SELECT DISTINCT proto FROM netflow.flows_5m WHERE $__timeFilter(ts)"),
            var("segment", "Segment", query="SELECT DISTINCT segment FROM netflow.nb_prefixes ORDER BY segment"),
        ]},
        "panels": panels,
    },
}
out = os.path.join(os.path.dirname(__file__), "opnsense-netflow.json")
json.dump(dash, open(out, "w"), indent=2)
print(out)
