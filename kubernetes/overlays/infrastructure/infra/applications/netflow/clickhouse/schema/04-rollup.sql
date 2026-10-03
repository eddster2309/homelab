-- 5-minute rollup keyed on the *remote* side of each flow (whichever end
-- GeoIP resolved), so the geomap shows both outbound and return traffic.
-- direction: 'out' = remote is dst, 'in' = remote is src, 'local' = neither.

CREATE TABLE IF NOT EXISTS netflow.flows_5m
(
    ts DateTime,
    direction LowCardinality(String),
    proto LowCardinality(String),
    remote_country LowCardinality(String),
    remote_country_name LowCardinality(String),
    remote_asn UInt32,
    remote_as_org LowCardinality(String),
    remote_city String,
    remote_lat Float32,
    remote_lon Float32,
    bytes UInt64,
    packets UInt64,
    flows UInt64
)
ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, direction, proto, remote_country, remote_asn, remote_city, remote_lat, remote_lon)
TTL ts + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.flows_5m_mv TO netflow.flows_5m AS
WITH
    multiIf(dst_country != '', 'out', src_country != '', 'in', 'local') AS dir,
    dir = 'in' AS remote_is_src
SELECT
    toStartOfFiveMinutes(time_received) AS ts,
    dir AS direction,
    proto,
    if(remote_is_src, src_country, dst_country) AS remote_country,
    if(remote_is_src, src_country_name, dst_country_name) AS remote_country_name,
    if(remote_is_src, src_asn, dst_asn) AS remote_asn,
    if(remote_is_src, src_as_org, dst_as_org) AS remote_as_org,
    if(remote_is_src, src_city, dst_city) AS remote_city,
    if(remote_is_src, src_lat, dst_lat) AS remote_lat,
    if(remote_is_src, src_lon, dst_lon) AS remote_lon,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows
FROM netflow.flows
GROUP BY ts, direction, proto, remote_country, remote_country_name, remote_asn, remote_as_org, remote_city, remote_lat, remote_lon;

-- Per-LAN-host 5-minute rollup (1y), for device panels beyond the 30d raw TTL.
-- One row per LAN endpoint of a flow: an outbound flow yields a tx row for its
-- source; an inbound flow an rx row for its destination; a LAN->LAN flow both.
-- peer is the other end: AS organisation for internet peers, NetBox name (or IP) for LAN peers.

CREATE TABLE IF NOT EXISTS netflow.flows_lan_5m
(
    ts DateTime,
    lan_ip String,
    lan_host String,
    lan_kind LowCardinality(String),
    lan_segment LowCardinality(String),
    peer String,
    peer_segment LowCardinality(String),
    peer_country LowCardinality(String),
    service LowCardinality(String),
    proto LowCardinality(String),
    tx_bytes UInt64,
    rx_bytes UInt64,
    packets UInt64,
    flows UInt64
)
ENGINE = SummingMergeTree((tx_bytes, rx_bytes, packets, flows))
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, lan_ip, lan_host, lan_kind, lan_segment, peer, peer_segment, peer_country, service, proto)
TTL ts + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.flows_lan_5m_mv TO netflow.flows_lan_5m AS
SELECT
    toStartOfFiveMinutes(time_received) AS ts,
    e.1 AS lan_ip,
    e.2 AS lan_host,
    e.3 AS lan_kind,
    e.4 AS lan_segment,
    e.5 AS peer,
    e.6 AS peer_segment,
    e.7 AS peer_country,
    service,
    proto,
    sumIf(bytes, e.8) AS tx_bytes,
    sumIf(bytes, NOT e.8) AS rx_bytes,
    sum(packets) AS packets,
    count() AS flows
FROM netflow.flows
ARRAY JOIN arrayFilter(x -> x.1 != '', [
    -- source as the LAN end (it transmitted)
    tuple(if(src_country = '', src_addr, ''), if(src_host != '', src_host, src_addr), src_host_kind, src_segment,
          if(dst_country != '', dst_as_org, if(dst_host != '', dst_host, dst_addr)), dst_segment, dst_country, true),
    -- destination as the LAN end (it received)
    tuple(if(dst_country = '', dst_addr, ''), if(dst_host != '', dst_host, dst_addr), dst_host_kind, dst_segment,
          if(src_country != '', src_as_org, if(src_host != '', src_host, src_addr)), src_segment, src_country, false)
]) AS e
GROUP BY ts, lan_ip, lan_host, lan_kind, lan_segment, peer, peer_segment, peer_country, service, proto;

-- Internet traffic by LAN host x domain (1y). Not an MV: the enricher inserts
-- each 5-minute bucket once it is 10 minutes old, after the late domain fixup,
-- so rows carry the final domain.
CREATE TABLE IF NOT EXISTS netflow.flows_domain_5m
(
    ts DateTime,
    lan_host String,
    lan_segment LowCardinality(String),
    domain String,
    lan_ip String,
    remote_org LowCardinality(String),
    remote_country LowCardinality(String),
    remote_cloud LowCardinality(String),
    threat LowCardinality(String),
    proto LowCardinality(String),
    tx_bytes UInt64,
    rx_bytes UInt64,
    flows UInt64,
    domain_names SimpleAggregateFunction(max, UInt16)   -- >1: the domain is a best guess among several
)
ENGINE = SummingMergeTree((tx_bytes, rx_bytes, flows))
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, lan_host, lan_segment, domain, remote_org, remote_country, remote_cloud, threat, proto, lan_ip)
TTL ts + INTERVAL 365 DAY;
ALTER TABLE netflow.flows_domain_5m ADD COLUMN IF NOT EXISTS domain_names SimpleAggregateFunction(max, UInt16);
-- lan_ip (2026-10-01): dashboards group by address, not by the name stored at
-- ingest, so a renamed device stays one row. A new column can join the sorting
-- key only at its end, in the same ALTER; on later runs both parts are no-ops.
ALTER TABLE netflow.flows_domain_5m
    ADD COLUMN IF NOT EXISTS lan_ip String AFTER domain,
    MODIFY ORDER BY (ts, lan_host, lan_segment, domain, remote_org, remote_country, remote_cloud, threat, proto, lan_ip);
