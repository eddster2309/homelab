-- 5-minute rollup keyed on the *remote* side of each flow (whichever end
-- GeoIP resolved), so the geomap shows both outbound and return traffic.
-- direction: 'out' = remote is dst, 'in' = remote is src, 'local' = neither.
-- Remote means not ours (flows.src/dst_local: no GeoIP country, or an exporter's own
-- public address). Every rollup is keyed by exporter, the sensor that saw the flow;
-- rows from before 2026-10-16 have exporter = '' (all OPNsense).
--
-- Storage layout (2026-10-18): the 365-day tables were ~1 GiB projected, half of it
-- UInt64 counters at ~2.5x. So: counters use CODEC(T64, ZSTD(1)) (T64 packs the
-- small values into few bits), ts uses Delta, every other column ZSTD(1), and
-- string dimensions with modest cardinality are LowCardinality. The sort key now
-- starts with toStartOfDay(ts) and ends with ts: within a day all rows of one host
-- (or peer, domain) sit together, so the dimension columns compress far better than
-- when each 5-minute bucket interleaves every host. toStartOfDay(ts) is a function
-- of ts, so the SummingMergeTree grouping (the sort key) is unchanged; a day-aligned
-- ts is still last, so rows of the same key merge as before. PARTITION BY and TTL
-- are unchanged. An existing table cannot change its sort key, so it was rebuilt
-- with migrate-table.sh; the historical ALTER ... ADD COLUMN / MODIFY ORDER BY
-- statements that used to follow each CREATE (for tables older than the exporter and
-- lan_ip columns) were removed then: they name the old key and would fail on the
-- new tables, and every table now has those columns. No statement here may refer
-- to a table's sort key.
--
-- The MVs are created empty and then given their query with MODIFY QUERY on every
-- run, which swaps it atomically: no flow is missed and query edits apply.

CREATE TABLE IF NOT EXISTS netflow.flows_5m
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    direction LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    remote_country LowCardinality(String) CODEC(ZSTD(1)),
    remote_country_name LowCardinality(String) CODEC(ZSTD(1)),
    remote_asn UInt32 CODEC(ZSTD(1)),
    remote_as_org LowCardinality(String) CODEC(ZSTD(1)),
    remote_city LowCardinality(String) CODEC(ZSTD(1)),  -- ~500 distinct
    remote_lat Float32 CODEC(ZSTD(1)),
    remote_lon Float32 CODEC(ZSTD(1)),
    bytes UInt64 CODEC(T64, ZSTD(1)),
    packets UInt64 CODEC(T64, ZSTD(1)),
    flows UInt64 CODEC(T64, ZSTD(1)),
    exporter LowCardinality(String) CODEC(ZSTD(1))
)
ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), direction, proto, remote_country, remote_asn, remote_city, remote_lat, remote_lon, exporter, ts)
TTL ts + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.flows_5m_mv TO netflow.flows_5m AS
SELECT toStartOfFiveMinutes(time_received) AS ts FROM netflow.flows WHERE 0;
ALTER TABLE netflow.flows_5m_mv MODIFY QUERY
WITH
    multiIf(NOT dst_local, 'out', NOT src_local, 'in', 'local') AS dir,
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
    count() AS flows,
    exporter
FROM netflow.flows
GROUP BY ts, direction, proto, remote_country, remote_country_name, remote_asn, remote_as_org, remote_city, remote_lat, remote_lon, exporter;

-- Per-LAN-host 5-minute rollup (1y), for device panels beyond the 30d raw TTL.
-- One row per LAN endpoint of a flow: an outbound flow yields a tx row for its
-- source; an inbound flow an rx row for its destination; a LAN->LAN flow both.
-- peer is the other end: AS organisation for internet peers, NetBox name (or IP) for LAN peers.

CREATE TABLE IF NOT EXISTS netflow.flows_lan_5m
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    lan_ip LowCardinality(String) CODEC(ZSTD(1)),  -- ~300 distinct
    lan_host LowCardinality(String) CODEC(ZSTD(1)),  -- ~350
    lan_kind LowCardinality(String) CODEC(ZSTD(1)),
    lan_segment LowCardinality(String) CODEC(ZSTD(1)),
    peer LowCardinality(String) CODEC(ZSTD(1)),  -- ~1200 (AS orgs and LAN names)
    peer_segment LowCardinality(String) CODEC(ZSTD(1)),
    peer_country LowCardinality(String) CODEC(ZSTD(1)),
    service LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    tx_bytes UInt64 CODEC(T64, ZSTD(1)),
    rx_bytes UInt64 CODEC(T64, ZSTD(1)),
    packets UInt64 CODEC(T64, ZSTD(1)),
    flows UInt64 CODEC(T64, ZSTD(1)),
    exporter LowCardinality(String) CODEC(ZSTD(1))
)
ENGINE = SummingMergeTree((tx_bytes, rx_bytes, packets, flows))
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), lan_ip, lan_host, lan_kind, lan_segment, peer, peer_segment, peer_country, service, proto, exporter, ts)
TTL ts + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.flows_lan_5m_mv TO netflow.flows_lan_5m AS
SELECT toStartOfFiveMinutes(time_received) AS ts FROM netflow.flows WHERE 0;
ALTER TABLE netflow.flows_lan_5m_mv MODIFY QUERY
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
    count() AS flows,
    exporter
FROM netflow.flows
-- (an exporter's own public address is a LAN end too, with no peer_country)
ARRAY JOIN arrayFilter(x -> x.1 != '', [
    -- source as the LAN end (it transmitted)
    tuple(if(src_local, src_addr, ''), if(src_host != '', src_host, src_addr), src_host_kind, src_segment,
          if(NOT dst_local, dst_as_org, if(dst_host != '', dst_host, dst_addr)), dst_segment, if(dst_local, '', dst_country), true),
    -- destination as the LAN end (it received)
    tuple(if(dst_local, dst_addr, ''), if(dst_host != '', dst_host, dst_addr), dst_host_kind, dst_segment,
          if(NOT src_local, src_as_org, if(src_host != '', src_host, src_addr)), src_segment, if(src_local, '', src_country), false)
]) AS e
GROUP BY ts, lan_ip, lan_host, lan_kind, lan_segment, peer, peer_segment, peer_country, service, proto, exporter;

-- Internet traffic by LAN host x domain (1y). Not an MV: the enricher inserts
-- each 5-minute bucket once it is 10 minutes old, after the late domain fixup,
-- so rows carry the final domain.
CREATE TABLE IF NOT EXISTS netflow.flows_domain_5m
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    lan_host LowCardinality(String) CODEC(ZSTD(1)),  -- ~120 distinct
    lan_segment LowCardinality(String) CODEC(ZSTD(1)),
    domain LowCardinality(String) CODEC(ZSTD(1)),  -- ~7.6k distinct per month
    lan_ip LowCardinality(String) CODEC(ZSTD(1)),  -- ~170
    remote_org LowCardinality(String) CODEC(ZSTD(1)),
    remote_country LowCardinality(String) CODEC(ZSTD(1)),
    remote_cloud LowCardinality(String) CODEC(ZSTD(1)),
    threat LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    tx_bytes UInt64 CODEC(T64, ZSTD(1)),
    rx_bytes UInt64 CODEC(T64, ZSTD(1)),
    flows UInt64 CODEC(T64, ZSTD(1)),
    domain_names SimpleAggregateFunction(max, UInt16) CODEC(ZSTD(1)),  -- >1: the domain is a best guess among several
    exporter LowCardinality(String) CODEC(ZSTD(1))
)
ENGINE = SummingMergeTree((tx_bytes, rx_bytes, flows))
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), lan_host, lan_segment, domain, remote_org, remote_country, remote_cloud, threat, proto, lan_ip, exporter, ts)
TTL ts + INTERVAL 365 DAY;
