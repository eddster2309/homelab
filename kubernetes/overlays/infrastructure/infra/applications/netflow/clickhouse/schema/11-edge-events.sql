-- Public connection attempts to edge01 and the layer that decided each one: which
-- layer dropped (or served) it, and why. Read by the NetFlow UI for a verdict per
-- connection. dns-tail (enrich/dns_tail.py) fills it from Loki:
--   layer 'haproxy'   every frontend's close line (garage/edge haproxy role): served,
--                     or dropped by the per-source limit, non-TLS, or unknown SNI.
--                     One row per session (per request on :80).
--   layer 'nftables'  the kernel's "edge-drop <reason>: " log lines (garage/edge
--                     nftables role), SAMPLED: each reason is rate-limited, so a row
--                     is an example of a drop, not every one (sampled = 1). Exact
--                     totals per reason are Prometheus' edge_nft_counter_packets_total.
--   layer 'traefik'   reserved, unused: the CrowdSec plugin's log lines name neither
--                     the IP nor the decision, so a ban/AppSec block is only visible
--                     as a 403 with no service in traefik_requests.
-- reason: geo, hosting, rate-source, rate-global, port, invalid (nftables);
-- conn-rate, conn-limit, not-tls, no-sni, unknown-sni, unknown-host, served, redirect
-- (haproxy). Lines from before the verdicts existed get derived reasons
-- ('no-sni-or-not-tls', 'unknown-sni', 'unknown-drop', 'aborted'), see the parsers.
--
-- dns-tail -> edge_events_queue (Null) -> edge_events_mv (GeoIP/ASN, like
-- edge_sessions_mv) -> edge_events.

CREATE TABLE IF NOT EXISTS netflow.edge_events_queue
(
    ts DateTime64(3, 'UTC'),          -- when the connection was accepted / the packet dropped
    logged DateTime64(9, 'UTC'),      -- Loki line time: dns-tail's cursor, per layer
    layer String,                     -- nftables | haproxy | traefik
    action String,                    -- drop | served | ban | appsec
    reason String,
    client String,
    client_port UInt16,
    dst_port UInt16,                  -- the port the client dialled
    proto String,                     -- TCP | UDP | ICMP ...
    sni String,                       -- 443: the SNI; 80: the Host; '' otherwise
    backend String,
    termination String,               -- HAProxy %ts
    bytes UInt64,                     -- HAProxy %B
    duration_ms UInt32,               -- HAProxy %Tt (%Ta on :80)
    sampled UInt8
)
ENGINE = Null;

CREATE TABLE IF NOT EXISTS netflow.edge_events
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    logged DateTime64(9, 'UTC'),
    layer LowCardinality(String),
    action LowCardinality(String),
    reason LowCardinality(String),
    client String,
    client_port UInt16,
    dst_port UInt16,
    proto LowCardinality(String),
    sni String,
    backend LowCardinality(String),
    termination LowCardinality(String),
    bytes UInt64,
    duration_ms UInt32,
    sampled UInt8,
    client_country LowCardinality(String),
    client_asn UInt32,
    client_as_org LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- Recreated on every run so query changes apply. A dns-tail insert while it's
-- missing is lost; the cursor has moved on by then, so keep this cheap to replace.
DROP VIEW IF EXISTS netflow.edge_events_mv;
CREATE MATERIALIZED VIEW netflow.edge_events_mv TO netflow.edge_events AS
WITH
    toIPv6OrDefault(client) AS c_ip,
    -- the registered country for blocks with no city, as in flows_mv
    dictGet('netflow.geoip_city_blocks', 'geoname_id', c_ip) AS c_gid_city,
    if(c_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', c_ip), c_gid_city) AS c_gid
SELECT ts, logged, layer, action, reason, client, client_port, dst_port, proto, sni, backend,
       termination, bytes, duration_ms, sampled,
       dictGet('netflow.geoip_city_locations', 'country_iso_code', c_gid) AS client_country,
       dictGet('netflow.geoip_asn', 'autonomous_system_number', c_ip) AS client_asn,
       dictGet('netflow.geoip_asn', 'autonomous_system_organization', c_ip) AS client_as_org
FROM netflow.edge_events_queue;
