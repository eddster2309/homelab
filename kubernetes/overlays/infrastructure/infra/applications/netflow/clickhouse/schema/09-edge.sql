-- Sessions HAProxy on edge01 proxied: one row per connection to a backend, from its
-- `edge-session` connect line (garage/edge haproxy role, log-profile pipeline),
-- which dns-tail reads from Loki. A session has two legs, each seen by a different
-- flow sensor:
--   public leg  client:port -> frontend_addr:443          edge01's softflowd
--   tunnel leg  proxy_addr:proxy_port -> server_addr:port  OPNsense (wg)
-- conn_domains_edge_mv names both with the SNI, so their flows get a certain domain.
-- Sessions HAProxy refused before connecting a backend have no line; they're only
-- in flows (and in HAProxy's close line in Loki).
--
-- dns-tail -> edge_sessions_queue (Null) -> edge_sessions_mv (GeoIP/ASN, like the
-- eve_* tables) -> edge_sessions -> conn_domains_edge_mv -> conn_domains.

CREATE TABLE IF NOT EXISTS netflow.edge_sessions_queue
(
    ts DateTime64(3, 'UTC'),          -- accepted (HAProxy %Ts.%ms)
    logged DateTime64(9, 'UTC'),      -- Loki line time: dns-tail's cursor
    client String,
    client_port UInt16,
    frontend_addr String,             -- the public address the client reached
    frontend_port UInt16,
    proxy_addr String,                -- edge01's end of the tunnel leg
    proxy_port UInt16,
    server_addr String,
    server_port UInt16,
    backend String,
    sni String
)
ENGINE = Null;

CREATE TABLE IF NOT EXISTS netflow.edge_sessions
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    logged DateTime64(9, 'UTC'),
    client String,
    client_port UInt16,
    frontend_addr String,
    frontend_port UInt16,
    proxy_addr String,
    proxy_port UInt16,
    server_addr String,
    server_port UInt16,
    backend LowCardinality(String),
    sni String,
    client_country LowCardinality(String),
    client_asn UInt32,
    client_as_org LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- JA4 of the client's TLS ClientHello (HAProxy logs the hello, dns-tail fingerprints it;
-- see services/dns-tail/ja4.py). Joins traefik_requests on (client, client_port) = the
-- PROXY-protocol source. '' when the line carried no hello or it was cut short.
ALTER TABLE netflow.edge_sessions_queue ADD COLUMN IF NOT EXISTS ja4 String;
ALTER TABLE netflow.edge_sessions ADD COLUMN IF NOT EXISTS ja4 LowCardinality(String) DEFAULT '';

-- Recreated on every run so query changes apply. A dns-tail insert while it's
-- missing is lost; the cursor has moved on by then, so keep this cheap to replace.
DROP VIEW IF EXISTS netflow.edge_sessions_mv;
CREATE MATERIALIZED VIEW netflow.edge_sessions_mv TO netflow.edge_sessions AS
WITH
    toIPv6OrDefault(client) AS c_ip,
    -- the registered country for blocks with no city, as in flows_mv
    dictGet('netflow.geoip_city_blocks', 'geoname_id', c_ip) AS c_gid_city,
    if(c_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', c_ip), c_gid_city) AS c_gid
SELECT ts, logged, client, client_port, frontend_addr, frontend_port, proxy_addr, proxy_port,
       server_addr, server_port, backend, sni, ja4,
       dictGet('netflow.geoip_city_locations', 'country_iso_code', c_gid) AS client_country,
       dictGet('netflow.geoip_asn', 'autonomous_system_number', c_ip) AS client_asn,
       dictGet('netflow.geoip_asn', 'autonomous_system_organization', c_ip) AS client_as_org
FROM netflow.edge_sessions_queue;

-- Both legs -> conn_domains, certain (names = 1). source 'edge' ranks with sni/http
-- over the DNS guess (conn_domain_dict, 02-intel.sql). IP literals aren't names.
-- The legs read through the alias s: the output names (client, ...) would otherwise
-- shadow the columns they're built from.
DROP VIEW IF EXISTS netflow.conn_domains_edge_mv;
CREATE MATERIALIZED VIEW netflow.conn_domains_edge_mv TO netflow.conn_domains AS
SELECT leg.1 AS client, leg.2 AS client_port, leg.3 AS server, leg.4 AS server_port, 'TCP' AS proto,
       s.ts AS started, s.sni AS domain, toUInt16(1) AS names, 'edge' AS source
FROM netflow.edge_sessions AS s
ARRAY JOIN arrayFilter(x -> x.1 != '' AND x.3 != '', [
    (s.client, s.client_port, s.frontend_addr, s.frontend_port),
    (s.proxy_addr, s.proxy_port, s.server_addr, s.server_port)]) AS leg
WHERE s.sni NOT IN ('', '-') AND NOT isIPv4String(s.sni) AND NOT isIPv6String(s.sni);
