#!/usr/bin/env python3
"""Generates the netflow-host Grafana dashboard: everything about one local IP.

  python3 gen_host.py && gcx resources push -p netflow-host.json

Opened from the main dashboard (opnsense-netflow): every local IP there links
here with ?var-ip=<ip> and the current time range. LAN peers link back here too.
"""
import json
import os

DS = {"type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow"}
UID = "netflow-host"
H = "'${ip}'"                               # the host under investigation
LINK = f"/d/{UID}/host-traffic?var-ip=IP_VALUE&${{__url_time_range}}"
BUCKET = "greatest($__interval_s, 300)"

TABLE = {"cellHeight": "sm", "showHeader": True, "footer": {"show": False}}
STAT = {"colorMode": "value", "graphMode": "none", "justifyMode": "center", "textMode": "value",
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": ""}}
TSFC = {"custom": {"drawStyle": "line", "fillOpacity": 15, "lineWidth": 1, "showPoints": "never", "axisSoftMin": 0,
                   "stacking": {"mode": "none", "group": "A"}}}

# Raw flows touching the host, with the other end resolved the same way the main dashboard does
RAW = (f"WITH src_addr = {H} AS host_is_src,\n"
       "     if(host_is_src, dst_addr, src_addr) AS peer_ip,\n"
       "     if(host_is_src, dst_country, src_country) AS peer_country,\n"
       "     if(host_is_src, dst_as_org, src_as_org) AS peer_org,\n"
       "     if(host_is_src, dst_segment, src_segment) AS peer_segment,\n"
       "     if(host_is_src, dst_net, src_net) AS peer_net,\n"
       "     if(host_is_src, dst_port, src_port) AS peer_port,\n"
       "     if(host_is_src, src_port, dst_port) AS host_port,\n"
       "     dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(peer_ip),\n"
       "         if(host_is_src, if(dst_host != '', dst_host, dst_addr), if(src_host != '', src_host, src_addr))) AS peer\n")
WHERE = f"$__timeFilter(time_received) AND (src_addr = {H} OR dst_addr = {H})"
LAN5 = f"$__timeFilter(ts) AND lan_ip = {H}"
PORTNAME = "dictGetOrDefault('netflow.port_names_dict', 'name', (proto, toUInt16({0})), '')"
PREFIX = "dictGetOrDefault('netflow.nb_prefix_dict', '{attr}', toIPv6OrDefault({addr}), {default})"

panels = []


def target(sql, ts=False):
    return {"refId": "A", "datasource": DS, "editorType": "sql", "rawSql": sql.strip(),
            "format": 0 if ts else 1, "queryType": "timeseries" if ts else "table"}


def panel(id, title, type, gp, sql, desc="", ts=False, unit=None, options=None, fc=None, overrides=None):
    p = {"id": id, "title": title, "type": type, "datasource": DS, "description": desc,
         "gridPos": dict(zip("xywh", gp)), "targets": [target(sql, ts)],
         "fieldConfig": {"defaults": fc or {}, "overrides": overrides or []}, "options": options or {}}
    if unit:
        p["fieldConfig"]["defaults"]["unit"] = unit
    panels.append(p)


def row(id, title, y):
    panels.append({"id": id, "type": "row", "title": title, "collapsed": False,
                   "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []})


def by_name(name, *props):
    return {"matcher": {"id": "byName", "options": name}, "properties": list(props)}


def unit(u):
    return {"id": "unit", "value": u}


def width(w):
    return {"id": "custom.width", "value": w}


def gauge(color):
    return [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}},
            {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}}]


def host_link(ip_field):
    """Link a column to this dashboard for the row's IP (drill through to a LAN peer)."""
    return {"id": "links", "value": [{"title": "Investigate this host",
                                      "url": LINK.replace("IP_VALUE", f"${{__data.fields.{ip_field}}}")}]}


BYTES = lambda *names: [by_name(n, unit("decbytes"), *gauge("blue" if "down" in n or "rx" in n or "received" in n else "orange"))
                        for n in names]

# ------------------------------------------------------------------ identity + totals
panel(1, "Host", "table", (0, 0, 24, 4), f"""
SELECT {H} AS ip,
       dictGetOrDefault('netflow.nb_host_dict', 'name', tuple({H}), '(not in NetBox)') AS name,
       dictGetOrDefault('netflow.nb_host_dict', 'kind', tuple({H}), '') AS kind,
       dictGetOrDefault('netflow.nb_prefix_dict', 'segment', toIPv6OrDefault({H}), '') AS segment,
       dictGetOrDefault('netflow.nb_prefix_dict', 'via', toIPv6OrDefault({H}), '') AS via,
       dictGetOrDefault('netflow.nb_host_dict', 'vendor', tuple({H}), '') AS vendor,
       (SELECT any(mac) FROM netflow.nb_hosts WHERE ip = {H}) AS mac,
       dictGetOrDefault('netflow.nb_host_dict', 'connection', tuple({H}), '') AS connection,
       dictGetOrDefault('netflow.nb_host_dict', 'fqdn', tuple({H}), '') AS fqdn,
       (SELECT any(last_seen) FROM netflow.nb_hosts WHERE ip = {H}) AS last_seen_netbox""",
      "What NetBox knows about this address (netbox-sync: OPNsense, Proxmox, Kubernetes, FreeIPA, Omada). "
      "'(not in NetBox)': name it there, tagged sync-locked.",
      options=TABLE, overrides=[by_name("ip", width(130)), by_name("kind", width(120)), by_name("segment", width(120)),
                                by_name("mac", width(150)), by_name("last_seen_netbox", width(170))])


def stat(id, x, title, sql, u, desc, color):
    panel(id, title, "stat", (x, 3, 4, 4), sql, desc, unit=u, options=STAT,
          fc={"color": {"mode": "fixed", "fixedColor": color}, "decimals": 1 if u == "decbytes" else 0})


stat(10, 0, "Internet download", f"SELECT sum(rx_bytes) FROM netflow.flows_lan_5m WHERE {LAN5} AND peer_segment = 'internet'",
     "decbytes", "Bytes received from the internet.", "blue")
stat(11, 4, "Internet upload", f"SELECT sum(tx_bytes) FROM netflow.flows_lan_5m WHERE {LAN5} AND peer_segment = 'internet'",
     "decbytes", "Bytes sent to the internet.", "orange")
stat(12, 8, "LAN received", f"SELECT sum(rx_bytes) FROM netflow.flows_lan_5m WHERE {LAN5} AND peer_segment != 'internet'",
     "decbytes", "Bytes received from other local subnets (routed through OPNsense).", "blue")
stat(13, 12, "LAN sent", f"SELECT sum(tx_bytes) FROM netflow.flows_lan_5m WHERE {LAN5} AND peer_segment != 'internet'",
     "decbytes", "Bytes sent to other local subnets.", "orange")
stat(14, 16, "Domains", f"SELECT uniqExact(domain) FROM netflow.flows WHERE {WHERE} AND domain != ''",
     "short", "Distinct DNS names this host's traffic went to.", "text")
stat(15, 20, "Peers", f"{RAW}SELECT uniqExact(peer_ip) FROM netflow.flows WHERE {WHERE}",
     "short", "Distinct addresses (internet and LAN) it exchanged traffic with.", "text")

panel(2, "Throughput", "timeseries", (0, 7, 24, 8), f"""
SELECT toStartOfInterval(ts, INTERVAL {BUCKET} second) AS time,
       sumIf(rx_bytes, peer_segment = 'internet') * 8 / {BUCKET} AS `internet ↓`,
       sumIf(tx_bytes, peer_segment = 'internet') * 8 / {BUCKET} AS `internet ↑`,
       sumIf(rx_bytes, peer_segment != 'internet') * 8 / {BUCKET} AS `LAN ↓`,
       sumIf(tx_bytes, peer_segment != 'internet') * 8 / {BUCKET} AS `LAN ↑`
FROM netflow.flows_lan_5m
WHERE {LAN5}
GROUP BY time ORDER BY time""",
      "Average bits/s per 5-minute (or wider) bucket, split internet vs other local subnets.", ts=True, unit="bps",
      options={"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max"]},
               "tooltip": {"mode": "multi", "sort": "desc"}},
      fc=json.loads(json.dumps(TSFC)),
      overrides=[by_name(n, {"id": "color", "value": {"mode": "fixed", "fixedColor": c}})
                 for n, c in (("internet ↓", "blue"), ("internet ↑", "orange"), ("LAN ↓", "green"), ("LAN ↑", "yellow"))])

# ------------------------------------------------------------------ internet
row(20, "Internet", 15)
panel(21, "Domains", "table", (0, 16, 9, 11), f"""
{RAW}SELECT if(domain != '', domain, concat('(no DNS) ', peer_org)) AS destination,
       sumIf(bytes, NOT host_is_src) AS downloaded, sumIf(bytes, host_is_src) AS uploaded, count() AS flows,
       sumIf(bytes, domain_names <= 1) / greatest(sum(bytes), 1) AS certain
FROM netflow.flows
WHERE {WHERE} AND peer_segment = 'internet'
GROUP BY destination ORDER BY downloaded + uploaded DESC LIMIT 40""",
      "Where its internet traffic went, by the DNS name it looked up for each connection. certain = share of bytes "
      "where it had only this one name for the IP; lower = best guess among names sharing the IP.", options=TABLE,
      overrides=BYTES("downloaded", "uploaded") + [{"matcher": {"id": "byName", "options": "certain"}, "properties": [{"id": "unit", "value": "percentunit"}, {"id": "decimals", "value": 0}, {"id": "custom.width", "value": 80}]}])

panel(22, "Remote networks", "table", (9, 16, 8, 11), f"""
{RAW}SELECT peer_org AS network, peer_country AS country, any(remote_cloud) AS cloud,
       sumIf(bytes, NOT host_is_src) AS downloaded, sumIf(bytes, host_is_src) AS uploaded,
       uniqExact(peer_ip) AS hosts
FROM netflow.flows
WHERE {WHERE} AND peer_segment = 'internet'
GROUP BY network, country ORDER BY downloaded + uploaded DESC LIMIT 30""",
      "Autonomous systems (and cloud service, where the range is published) it talked to.", options=TABLE,
      overrides=BYTES("downloaded", "uploaded") + [by_name("country", width(70))])

panel(23, "Where it talks to", "geomap", (17, 16, 7, 11), f"""
{RAW}SELECT if(host_is_src, dst_lat, src_lat) AS lat, if(host_is_src, dst_lon, src_lon) AS lon,
       any(peer_org) AS network, any(domain) AS domain, sum(bytes) AS bytes
FROM netflow.flows
WHERE {WHERE} AND peer_segment = 'internet' AND (lat != 0 OR lon != 0)
GROUP BY lat, lon ORDER BY bytes DESC LIMIT 1000""",
      "Remote internet ends, sized by bytes.",
      options={"basemap": {"config": {}, "name": "Basemap", "type": "default"},
               "controls": {"mouseWheelZoom": True, "showZoom": True, "showAttribution": True},
               "layers": [{"type": "markers", "name": "Remote", "tooltip": True,
                           "location": {"mode": "coords", "latitude": "lat", "longitude": "lon"},
                           "config": {"showLegend": False, "style": {
                               "color": {"fixed": "dark-orange"}, "opacity": 0.6,
                               "size": {"field": "bytes", "fixed": 5, "min": 3, "max": 20},
                               "symbol": {"fixed": "img/icons/marker/circle.svg", "mode": "fixed"}}}}],
               "view": {"id": "zero", "lat": 10, "lon": 60, "zoom": 1}, "tooltip": {"mode": "details"}},
      overrides=[by_name("bytes", unit("decbytes"))])

# ------------------------------------------------------------------ LAN + services
row(30, "Local network and services", 27)
panel(34, "Traffic by segment", "table", (0, 28, 24, 7), f"""
{RAW}SELECT if(peer_segment != '', peer_segment, if(peer_net = 'REDACTED_IP/0', 'internet',
          {PREFIX.format(attr="segment", addr="peer_ip", default="peer_net")})) AS segment,
       {PREFIX.format(attr="via", addr="peer_ip", default="''")} AS via,
       sumIf(bytes, NOT host_is_src) AS received, sumIf(bytes, host_is_src) AS sent,
       uniqExact(peer_ip) AS peers,
       arrayStringConcat(topK(5)(peer), ', ') AS top_peers,
       topK(1)(if(service != '', service, concat(proto, '/', toString(least(src_port, dst_port)))))[1] AS main_service,
       count() AS flows
FROM netflow.flows
WHERE {WHERE}
GROUP BY segment, via ORDER BY received + sent DESC""",
      "Which network segments (NetBox prefix names, or OPNsense's routing prefix where NetBox has none) the traffic to and "
      "from this host comes from and goes to. via = the OPNsense interface a remote segment is reached over (e.g. the "
      "inter-site WireGuard); blank for local VLANs. received = sourced from that segment. top_peers = most frequent peers "
      "there, by flow count. Same-subnet traffic doesn't pass OPNsense and isn't visible.",
      options=TABLE, overrides=[by_name("received", unit("decbytes"), *gauge("blue")), by_name("sent", unit("decbytes"), *gauge("orange")),
                                by_name("segment", width(160)), by_name("via", width(190)), by_name("peers", width(70)),
                                by_name("flows", width(90))])
panel(31, "LAN peers", "table", (0, 35, 12, 10), f"""
{RAW}SELECT peer AS peer_name, peer_ip, peer_segment AS segment,
       topK(1)(if(service != '', service, concat(proto, '/', toString(least(src_port, dst_port)))))[1] AS main_service,
       sumIf(bytes, host_is_src) AS sent, sumIf(bytes, NOT host_is_src) AS received, count() AS flows
FROM netflow.flows
WHERE {WHERE} AND peer_segment != 'internet'
GROUP BY peer_name, peer_ip, segment ORDER BY sent + received DESC LIMIT 30""",
      "Other local addresses it exchanged routed traffic with. Click a peer to investigate it. "
      "Same-subnet traffic doesn't pass OPNsense and isn't visible.",
      options=TABLE,
      overrides=[by_name("sent", unit("decbytes"), *gauge("orange")), by_name("received", unit("decbytes"), *gauge("blue")),
                 by_name("peer_name", host_link("peer_ip")), by_name("peer_ip", host_link("peer_ip"), width(120))])

panel(32, "Services it uses", "table", (12, 35, 6, 10), f"""
{RAW}SELECT if(service != '', service, concat(proto, '/', toString(peer_port), ' ', {PORTNAME.format('peer_port')})) AS service_used,
       sum(bytes) AS bytes, uniqExact(peer_ip) AS servers, count() AS flows
FROM netflow.flows
WHERE {WHERE} AND host_is_src AND peer_port < host_port AND peer_port != 0
GROUP BY service_used ORDER BY bytes DESC LIMIT 25""",
      "Ports/services it connects out to (the lower, server-side port), NetBox service names where known.",
      options=TABLE, overrides=[by_name("bytes", unit("decbytes"), *gauge("purple"))])

panel(33, "Services it serves", "table", (18, 35, 6, 10), f"""
{RAW}SELECT concat(proto, '/', toString(host_port), ' ', {PORTNAME.format('host_port')}) AS listening,
       any(service) AS netbox_service, uniqExact(peer_ip) AS clients, sum(bytes) AS bytes
FROM netflow.flows
WHERE {WHERE} AND NOT host_is_src AND host_port < peer_port AND host_port != 0
GROUP BY listening ORDER BY clients DESC, bytes DESC LIMIT 25""",
      "Ports on this host that others connected to (it answered on the lower port). Empty for pure clients.",
      options=TABLE, overrides=[by_name("bytes", unit("decbytes"))])

# ------------------------------------------------------------------ DNS + hygiene
row(40, "DNS and hygiene", 45)
panel(41, "DNS lookups", "table", (0, 46, 10, 10), f"""
SELECT domain, count() AS answers, uniqExact(ip) AS addresses, max(ts) AS last_lookup
FROM netflow.dns_answers
WHERE $__timeFilter(ts) AND client = {H}
GROUP BY domain ORDER BY answers DESC LIMIT 40""",
      "Names this host resolved through Blocky (A records answered), whether or not it then sent traffic. "
      "Empty: it uses another resolver or DNS-over-HTTPS. Kept 30 days.",
      options=TABLE, overrides=[by_name("last_lookup", width(170))])

panel(42, "Findings", "table", (10, 46, 14, 10), f"""
{RAW}SELECT multiIf(threat != '', concat('threat list: ', threat),
               host_is_src AND peer_segment = 'internet' AND peer_port IN (53, 853), 'external DNS resolver',
               proto = 'TCP' AND tcp_flags = 4, 'TCP reset only (LAN)',
               'other') AS finding,
       peer, peer_ip, concat(proto, '/', toString(peer_port)) AS port, any(domain) AS domain,
       count() AS flows, max(time_received) AS last_seen
FROM netflow.flows
WHERE {WHERE} AND (threat != '' OR (host_is_src AND peer_segment = 'internet' AND peer_port IN (53, 853))
                   OR (proto = 'TCP' AND tcp_flags = 4 AND peer_segment != 'internet'))
GROUP BY finding, peer, peer_ip, port ORDER BY last_seen DESC LIMIT 50""",
      "Traffic worth a look: remote ends on a threat list, DNS sent straight to internet resolvers, and TCP flows to "
      "local peers that were only a reset (refused connections: a dead or blocked local service). Internet resets are "
      "normal HTTPS teardown and left out. Empty is healthy.",
      options=TABLE, overrides=[by_name("finding", {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                                        {"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}),
                                by_name("peer_ip", host_link("peer_ip")), by_name("last_seen", width(170))])

# ------------------------------------------------------------------ Suricata (eve_*, 05-eve.sql)
row(43, "Seen on the wire (Suricata)", 56)
panel(44, "Names it connected to (TLS / HTTP)", "table", (0, 57, 10, 10), f"""
SELECT * FROM (
    SELECT sni AS name, 'tls' AS via, count() AS connections, uniqExact(dst) AS servers,
           any(if(dst_host != '', dst_host, dst_as_org)) AS server, max(ts) AS last_seen
    FROM netflow.eve_tls WHERE $__timeFilter(ts) AND src = {H} AND sni != '' GROUP BY name
    UNION ALL
    SELECT host, 'http', count(), uniqExact(dst), any(if(dst_host != '', dst_host, dst_as_org)), max(ts)
    FROM netflow.eve_http WHERE $__timeFilter(ts) AND src = {H} AND host != '' GROUP BY host
) ORDER BY connections DESC LIMIT 40""",
      "Server names this host asked for in TLS handshakes (SNI) and plaintext HTTP requests (Host), as Suricata on "
      "OPNsense saw them. Unlike DNS-based names these are certain, and they work with DNS-over-HTTPS. Only VLANs "
      "Suricata listens on are covered.",
      options=TABLE, overrides=[by_name("last_seen", width(170)), by_name("via", width(60))])

panel(45, "TLS clients (JA4)", "table", (10, 57, 7, 10), f"""
SELECT ja4, version, count() AS handshakes, uniqExact(sni) AS names, any(sni) AS example
FROM netflow.eve_tls
WHERE $__timeFilter(ts) AND src = {H} AND ja4 != ''
GROUP BY ja4, version ORDER BY handshakes DESC LIMIT 20""",
      "JA4 fingerprints of the TLS client software on this host: each browser, app or library has its own. A new one "
      "on a device that normally has two or three is worth a look.", options=TABLE)

panel(46, "IDS alerts", "table", (17, 57, 7, 10), f"""
SELECT ts AS time, signature, severity, if(src = {H}, 'out', 'in') AS direction,
       if(src = {H}, if(dst_host != '', dst_host, dst), if(src_host != '', src_host, src)) AS peer,
       if(src = {H}, dst_as_org, src_as_org) AS peer_org, action
FROM netflow.eve_alert
WHERE $__timeFilter(ts) AND (src = {H} OR dst = {H})
ORDER BY ts DESC LIMIT 50""",
      "Suricata rule matches involving this host. Empty if no rulesets are enabled in OPNsense.",
      options=TABLE, overrides=[by_name("time", width(170))])

# ------------------------------------------------------------------ raw
panel(50, "Recent flows", "table", (0, 67, 24, 12), f"""
{RAW}SELECT time_received AS time, if(host_is_src, 'out', 'in') AS direction, peer, peer_ip,
       concat(proto, '/', toString(peer_port)) AS peer_port_, host_port,
       concat(domain, if(domain_names > 1, concat(' (1 of ', toString(domain_names), ')'), '')) AS domain,
       service, remote_cloud AS cloud, peer_country AS country, bytes, packets, threat
FROM netflow.flows
WHERE {WHERE}
ORDER BY time_received DESC LIMIT 500""",
      "Latest 500 flows to or from this host, newest first.", options={**TABLE, "sortBy": []},
      overrides=[by_name("bytes", unit("decbytes")), by_name("time", width(180)), by_name("direction", width(80)),
                 by_name("peer_ip", host_link("peer_ip"), width(130)), by_name("peer_port_", {"id": "displayName", "value": "peer port"})])

dash = {
    "apiVersion": "dashboard.grafana.app/v1beta1",
    "kind": "Dashboard",
    "metadata": {"name": UID},
    "spec": {
        "title": "Host Traffic",
        "description": "Everything NetFlow + NetBox + DNS + Suricata know about one local IP. Linked from Home Network Traffic. "
                       "Source: kubernetes/overlays/infrastructure/infra/applications/netflow/dashboard/gen_host.py",
        "tags": ["gcx", "opnsense", "netflow", "home-network", "clickhouse"],
        "timezone": "browser", "schemaVersion": 42, "refresh": "1m", "editable": True,
        "time": {"from": "now-24h", "to": "now"},
        "links": [{"title": "Home Network Traffic", "type": "link", "url": "/d/opnsense-netflow/home-network-traffic?${__url_time_range}",
                   "icon": "dashboard", "targetBlank": False}],
        "templating": {"list": [{"name": "ip", "label": "Local IP", "type": "textbox", "hide": 0,
                                 "query": "REDACTED_IP", "current": {"text": "REDACTED_IP", "value": "REDACTED_IP"}}]},
        "panels": panels,
    },
}
for p in panels:
    if p["id"] != 1:
        p["gridPos"]["y"] += 1
out = os.path.join(os.path.dirname(__file__), "netflow-host.json")
json.dump(dash, open(out, "w"), indent=2)
print(out)
