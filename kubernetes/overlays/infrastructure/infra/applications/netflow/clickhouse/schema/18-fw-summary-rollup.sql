-- pf blocks by source, destination, port and rule (hourly, 1y), for the netflowui
-- firewall summary page. fw_blocks_1h (12-retention.sql) can't serve it: it has no
-- destination or interface. The page ran seven aggregations over 2M fw_blocks rows a
-- week; this is ~30k rows a week.
--
-- Every filter the page offers except the source port is on the key (addresses, hosts,
-- segments, port, proto, rule, label, interface, attempt), so the summary reads it for
-- hour-aligned ranges. attempt is ATTEMPT_SQL in the backend's queries/firewall.py.
-- blocks add up; last_ts is the newest packet. Distinct sources/targets are exact over
-- the keyed rows (uniqExact(src), uniqExact(dst, dst_port)).
--
-- An MV (fw_blocks has no late fixup). As elsewhere, the backfill below runs before the
-- MV exists and only into an empty table; blocks inserted in the seconds between are
-- missed on the first apply.
CREATE TABLE IF NOT EXISTS netflow.fw_blocks_dst_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    iface LowCardinality(String) CODEC(ZSTD(1)),
    dir LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    rule_nr UInt32 CODEC(ZSTD(1)),
    label LowCardinality(String) CODEC(ZSTD(1)),
    src LowCardinality(String) CODEC(ZSTD(1)),
    src_host LowCardinality(String) CODEC(ZSTD(1)),
    src_segment LowCardinality(String) CODEC(ZSTD(1)),
    dst String CODEC(ZSTD(1)),
    dst_host LowCardinality(String) CODEC(ZSTD(1)),
    dst_segment LowCardinality(String) CODEC(ZSTD(1)),
    dst_port UInt16 CODEC(ZSTD(1)),
    attempt UInt8 CODEC(ZSTD(1)),
    blocks SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    last_ts SimpleAggregateFunction(max, DateTime64(3, 'UTC')) CODEC(Delta, ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), src, dst, proto, dst_port, rule_nr, label, iface, dir, attempt, src_host, src_segment, dst_host, dst_segment, ts)
TTL ts + INTERVAL 365 DAY;

INSERT INTO netflow.fw_blocks_dst_1h
SELECT
    toStartOfHour(t) AS ts, iface, dir, proto, rule_nr, label, src, src_host, src_segment, dst, dst_host, dst_segment, dst_port,
    toUInt8(proto != 'TCP' OR (position(tcp_flags, 'S') > 0 AND position(tcp_flags, 'A') = 0)) AS attempt,
    count() AS blocks, max(t) AS last_ts
FROM (SELECT *, ts AS t FROM netflow.fw_blocks)
WHERE (SELECT count() FROM netflow.fw_blocks_dst_1h) = 0
GROUP BY ts, iface, dir, proto, rule_nr, label, src, src_host, src_segment, dst, dst_host, dst_segment, dst_port, attempt;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.fw_blocks_dst_1h_mv TO netflow.fw_blocks_dst_1h AS
SELECT toStartOfHour(ts) AS ts FROM netflow.fw_blocks WHERE 0;
ALTER TABLE netflow.fw_blocks_dst_1h_mv MODIFY QUERY
SELECT
    toStartOfHour(t) AS ts, iface, dir, proto, rule_nr, label, src, src_host, src_segment, dst, dst_host, dst_segment, dst_port,
    toUInt8(proto != 'TCP' OR (position(tcp_flags, 'S') > 0 AND position(tcp_flags, 'A') = 0)) AS attempt,
    count() AS blocks, max(t) AS last_ts
FROM (SELECT *, ts AS t FROM netflow.fw_blocks)
GROUP BY ts, iface, dir, proto, rule_nr, label, src, src_host, src_segment, dst, dst_host, dst_segment, dst_port, attempt;
