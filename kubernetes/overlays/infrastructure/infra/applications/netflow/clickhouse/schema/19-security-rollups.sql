-- Hourly rollups (90 days) for the netflowui Security pages, which scanned a week of raw
-- flows (11M rows, 12-25 CPU s each) for the segment matrix, exposure (services and
-- inbound), resolver bypass and lookup-only. Each is a few hundred thousand rows a week.
--
-- The first three are not MVs: pf's verdict (fw_blocks) arrives separately and `domain` is labelled late, so
-- dns-tail (rollup_seg / rollup_svc / rollup_wan) inserts each 5-minute bucket once it is
-- SETTLE minutes old, with `blocked` counted in the same statement: the flows of the
-- bucket whose 5-tuple pf blocked as a connection attempt (BLOCKED in dns_tail.py, kept in
-- step with netflowui's app/queries/firewall.py). Several inserts to one hourly row
-- merge: AggregatingMergeTree with the counters as SimpleAggregateFunction(sum) (a
-- SummingMergeTree keeps the first value of its other columns). last_seen is also
-- dns-tail's cursor. On an empty table dns-tail starts at the current hour; older history
-- comes from clickhouse/backfill-rollups.sh, one day at a time. Distinct sources are
-- uniq(src_addr) over the keyed rows, so every column that isn't a counter is on the key
-- (hosts, segments and GeoIP follow the address, so they add no rows).

-- LAN-to-LAN flows between two different segments, by pair of addresses and service port:
-- client = the side with the higher port (dst_port <= src_port: the destination serves).
CREATE TABLE IF NOT EXISTS netflow.flows_seg_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    client_segment LowCardinality(String) CODEC(ZSTD(1)),
    server_segment LowCardinality(String) CODEC(ZSTD(1)),
    client String CODEC(ZSTD(1)),
    client_host LowCardinality(String) CODEC(ZSTD(1)),
    server String CODEC(ZSTD(1)),
    server_host LowCardinality(String) CODEC(ZSTD(1)),
    port UInt16 CODEC(ZSTD(1)),                 -- least(src_port, dst_port)
    proto LowCardinality(String) CODEC(ZSTD(1)),
    flows SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    blocked SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    bytes SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    last_seen SimpleAggregateFunction(max, DateTime64(3)) CODEC(Delta, ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), client_segment, server_segment, client, server, port, proto, client_host, server_host, ts)
TTL ts + INTERVAL 90 DAY;

-- Flows to a LAN address that look like connections to a service (dst_port <= src_port)
-- or go to one NetBox lists, by source address: backs exposure/services (all sources) and
-- exposure/inbound (src_segment = 'internet'). lt: dst_port < src_port.
CREATE TABLE IF NOT EXISTS netflow.flows_svc_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    dst_addr String CODEC(ZSTD(1)),
    dst_host LowCardinality(String) CODEC(ZSTD(1)),
    dst_segment LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    dst_port UInt16 CODEC(ZSTD(1)),
    src_addr String CODEC(ZSTD(1)),
    src_segment LowCardinality(String) CODEC(ZSTD(1)),
    lt UInt8 CODEC(ZSTD(1)),
    src_country LowCardinality(String) CODEC(ZSTD(1)),
    src_as_org LowCardinality(String) CODEC(ZSTD(1)),
    flows SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    blocked SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    bytes SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    last_seen SimpleAggregateFunction(max, DateTime64(3)) CODEC(Delta, ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), dst_addr, proto, dst_port, src_addr, lt, src_segment, src_country, src_as_org, dst_host, dst_segment, ts)
TTL ts + INTERVAL 90 DAY;

-- Flows to the internet by source, destination, port and the name the source resolved
-- (domain): backs dns/bypass (and the posture's count of bypassing hosts) and
-- dns/lookup-only (which addresses each client reached).
CREATE TABLE IF NOT EXISTS netflow.flows_wan_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    src_addr String CODEC(ZSTD(1)),
    src_host LowCardinality(String) CODEC(ZSTD(1)),
    src_segment LowCardinality(String) CODEC(ZSTD(1)),
    dst_addr String CODEC(ZSTD(1)),
    dst_host LowCardinality(String) CODEC(ZSTD(1)),
    dst_as_org LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    dst_port UInt16 CODEC(ZSTD(1)),
    domain String CODEC(ZSTD(1)),
    flows SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    blocked SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    bytes SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    last_seen SimpleAggregateFunction(max, DateTime64(3)) CODEC(Delta, ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), src_addr, dst_addr, proto, dst_port, domain, src_host, src_segment, dst_host, dst_as_org, ts)
TTL ts + INTERVAL 90 DAY;

-- The (client, name, address) DNS answers of each hour, for lookup-only: dns_answers has
-- 3M rows a week, this ~300k. A repeat in the hour adds to answers.
--
-- An MV (dns_answers has no late fixup). As in 18-fw-summary-rollup.sql, the backfill runs
-- before the MV exists and only into an empty table; answers inserted in the seconds
-- between are missed on the first apply.
CREATE TABLE IF NOT EXISTS netflow.dns_pairs_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    client String CODEC(ZSTD(1)),
    ip String CODEC(ZSTD(1)),
    domain LowCardinality(String) CODEC(ZSTD(1)),
    answers SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), client, ip, domain, ts)
TTL ts + INTERVAL 90 DAY;

INSERT INTO netflow.dns_pairs_1h
SELECT toStartOfHour(ts) AS ts, client, ip, domain, count() AS answers
FROM netflow.dns_answers
WHERE (SELECT count() FROM netflow.dns_pairs_1h) = 0
GROUP BY ts, client, ip, domain;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.dns_pairs_1h_mv TO netflow.dns_pairs_1h AS
SELECT toStartOfHour(ts) AS ts FROM netflow.dns_answers WHERE 0;
ALTER TABLE netflow.dns_pairs_1h_mv MODIFY QUERY
SELECT toStartOfHour(ts) AS ts, client, ip, domain, count() AS answers
FROM netflow.dns_answers
GROUP BY ts, client, ip, domain;
