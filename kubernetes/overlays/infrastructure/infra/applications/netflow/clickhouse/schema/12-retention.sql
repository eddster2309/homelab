-- Year-long rollups of what the 30-day raw tables would otherwise lose: ports, pf
-- blocks by rule, DNS lookups, TLS fingerprints, k8s egress, per-host daily stats and
-- the first time each LAN host reached each AS.
--
-- Conventions as in 04-rollup.sql: counters CODEC(T64, ZSTD(1)), ts Delta, dimensions
-- LowCardinality, sort keys start with the day and end with ts, MVs created empty and
-- given their query with MODIFY QUERY on every run.
--
-- Backfills: each runs before its MV exists and only into an empty table, so a re-run
-- never counts anything twice. The cost is that rows inserted between the backfill's
-- read and the MV's creation (a few seconds, first apply only) are missed. The
-- first-seen table is min/max, so its backfill is idempotent anyway.

-- Traffic by LAN host and port (hourly). One row per LAN end, as in flows_lan_5m (a
-- LAN->LAN flow books both ends). port is the lower of the two ports, which is the
-- service port for ordinary client/server traffic; when both are ephemeral (>= 32768,
-- e.g. QUIC or P2P) it is 0, so random high ports don't explode the key.
CREATE TABLE IF NOT EXISTS netflow.flows_port_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    lan_ip LowCardinality(String) CODEC(ZSTD(1)),
    lan_host LowCardinality(String) CODEC(ZSTD(1)),
    lan_segment LowCardinality(String) CODEC(ZSTD(1)),
    peer_segment LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    port UInt16 CODEC(ZSTD(1)),
    tx_bytes UInt64 CODEC(T64, ZSTD(1)),
    rx_bytes UInt64 CODEC(T64, ZSTD(1)),
    packets UInt64 CODEC(T64, ZSTD(1)),
    flows UInt64 CODEC(T64, ZSTD(1)),
    exporter LowCardinality(String) CODEC(ZSTD(1))
)
ENGINE = SummingMergeTree((tx_bytes, rx_bytes, packets, flows))
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), lan_ip, lan_host, lan_segment, peer_segment, proto, port, exporter, ts)
TTL ts + INTERVAL 365 DAY;

INSERT INTO netflow.flows_port_1h
SELECT
    toStartOfHour(time_received) AS ts,
    e.1 AS lan_ip, e.2 AS lan_host, e.3 AS lan_segment, e.4 AS peer_segment, proto,
    if(least(src_port, dst_port) >= 32768, 0, least(src_port, dst_port)) AS port,
    sumIf(bytes, e.5) AS tx_bytes, sumIf(bytes, NOT e.5) AS rx_bytes,
    sum(packets) AS packets, count() AS flows, exporter
FROM netflow.flows
ARRAY JOIN arrayFilter(x -> x.1 != '', [
    tuple(if(src_local, src_addr, ''), if(src_host != '', src_host, src_addr), src_segment, dst_segment, true),
    tuple(if(dst_local, dst_addr, ''), if(dst_host != '', dst_host, dst_addr), dst_segment, src_segment, false)
]) AS e
WHERE (SELECT count() FROM netflow.flows_port_1h) = 0
GROUP BY ts, lan_ip, lan_host, lan_segment, peer_segment, proto, port, exporter;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.flows_port_1h_mv TO netflow.flows_port_1h AS
SELECT toStartOfHour(time_received) AS ts FROM netflow.flows WHERE 0;
ALTER TABLE netflow.flows_port_1h_mv MODIFY QUERY
SELECT
    toStartOfHour(time_received) AS ts,
    e.1 AS lan_ip, e.2 AS lan_host, e.3 AS lan_segment, e.4 AS peer_segment, proto,
    if(least(src_port, dst_port) >= 32768, 0, least(src_port, dst_port)) AS port,
    sumIf(bytes, e.5) AS tx_bytes, sumIf(bytes, NOT e.5) AS rx_bytes,
    sum(packets) AS packets, count() AS flows, exporter
FROM netflow.flows
ARRAY JOIN arrayFilter(x -> x.1 != '', [
    tuple(if(src_local, src_addr, ''), if(src_host != '', src_host, src_addr), src_segment, dst_segment, true),
    tuple(if(dst_local, dst_addr, ''), if(dst_host != '', dst_host, dst_addr), dst_segment, src_segment, false)
]) AS e
GROUP BY ts, lan_ip, lan_host, lan_segment, peer_segment, proto, port, exporter;

-- pf blocks by rule (hourly). attempt: a connection attempt (not TCP, or a SYN without
-- ACK), the same test as ATTEMPT_SQL in the backend's queries/firewall.py.
CREATE TABLE IF NOT EXISTS netflow.fw_blocks_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    rule_nr UInt32 CODEC(ZSTD(1)),
    label LowCardinality(String) CODEC(ZSTD(1)),
    dir LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    src LowCardinality(String) CODEC(ZSTD(1)),
    src_host LowCardinality(String) CODEC(ZSTD(1)),
    src_segment LowCardinality(String) CODEC(ZSTD(1)),
    dst_segment LowCardinality(String) CODEC(ZSTD(1)),
    dst_as_org LowCardinality(String) CODEC(ZSTD(1)),
    dst_port UInt16 CODEC(ZSTD(1)),
    attempt UInt8 CODEC(ZSTD(1)),
    blocks UInt64 CODEC(T64, ZSTD(1)),
    dsts UInt64 CODEC(T64, ZSTD(1))  -- distinct destinations within the insert block (a lower bound once summed)
)
ENGINE = SummingMergeTree((blocks, dsts))
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), rule_nr, label, dir, proto, src, src_host, src_segment, dst_segment, dst_as_org, dst_port, attempt, ts)
TTL ts + INTERVAL 365 DAY;

INSERT INTO netflow.fw_blocks_1h
SELECT
    toStartOfHour(ts) AS ts, rule_nr, label, dir, proto, src, src_host, src_segment, dst_segment, dst_as_org, dst_port,
    toUInt8(proto != 'TCP' OR (position(tcp_flags, 'S') > 0 AND position(tcp_flags, 'A') = 0)) AS attempt,
    count() AS blocks, uniqExact(dst) AS dsts
FROM netflow.fw_blocks
WHERE (SELECT count() FROM netflow.fw_blocks_1h) = 0
GROUP BY ts, rule_nr, label, dir, proto, src, src_host, src_segment, dst_segment, dst_as_org, dst_port, attempt;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.fw_blocks_1h_mv TO netflow.fw_blocks_1h AS
SELECT toStartOfHour(ts) AS ts FROM netflow.fw_blocks WHERE 0;
ALTER TABLE netflow.fw_blocks_1h_mv MODIFY QUERY
SELECT
    toStartOfHour(ts) AS ts, rule_nr, label, dir, proto, src, src_host, src_segment, dst_segment, dst_as_org, dst_port,
    toUInt8(proto != 'TCP' OR (position(tcp_flags, 'S') > 0 AND position(tcp_flags, 'A') = 0)) AS attempt,
    count() AS blocks, uniqExact(dst) AS dsts
FROM netflow.fw_blocks
GROUP BY ts, rule_nr, label, dir, proto, src, src_host, src_segment, dst_segment, dst_as_org, dst_port, attempt;

-- DNS lookups by client and domain (hourly). dns_answers has a row per answer IP, and
-- one lookup's rows share a ts, so lookups counts distinct timestamps (dns-tail inserts a
-- lookup's answers together, so the per-block count sums correctly).
CREATE TABLE IF NOT EXISTS netflow.dns_queries_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    client LowCardinality(String) CODEC(ZSTD(1)),
    domain LowCardinality(String) CODEC(ZSTD(1)),
    lookups UInt64 CODEC(T64, ZSTD(1)),
    answers UInt64 CODEC(T64, ZSTD(1))
)
ENGINE = SummingMergeTree((lookups, answers))
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), client, domain, ts)
TTL ts + INTERVAL 365 DAY;

INSERT INTO netflow.dns_queries_1h
SELECT toStartOfHour(ts) AS ts, client, domain, uniqExact(ts) AS lookups, count() AS answers
FROM netflow.dns_answers
WHERE domain != '' AND (SELECT count() FROM netflow.dns_queries_1h) = 0
GROUP BY ts, client, domain;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.dns_queries_1h_mv TO netflow.dns_queries_1h AS
SELECT toStartOfHour(ts) AS ts FROM netflow.dns_answers WHERE 0;
ALTER TABLE netflow.dns_queries_1h_mv MODIFY QUERY
SELECT toStartOfHour(ts) AS ts, client, domain, uniqExact(ts) AS lookups, count() AS answers
FROM netflow.dns_answers
WHERE domain != ''
GROUP BY ts, client, domain;

-- TLS handshakes by client, fingerprint, version and server name (daily).
CREATE TABLE IF NOT EXISTS netflow.eve_tls_daily
(
    day Date CODEC(Delta, ZSTD(1)),
    src LowCardinality(String) CODEC(ZSTD(1)),
    ja4 LowCardinality(String) CODEC(ZSTD(1)),
    version LowCardinality(String) CODEC(ZSTD(1)),
    sni LowCardinality(String) CODEC(ZSTD(1)),
    dst_as_org LowCardinality(String) CODEC(ZSTD(1)),
    src_host SimpleAggregateFunction(anyLast, LowCardinality(String)) CODEC(ZSTD(1)),
    sessions SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    first SimpleAggregateFunction(min, DateTime('UTC')) CODEC(ZSTD(1)),
    last SimpleAggregateFunction(max, DateTime('UTC')) CODEC(ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (day, src, ja4, version, sni, dst_as_org)
TTL day + INTERVAL 365 DAY;

INSERT INTO netflow.eve_tls_daily
SELECT toDate(ts) AS day, src, ja4, version, sni, dst_as_org, anyLast(src_host), count(),
       toDateTime(min(ts), 'UTC'), toDateTime(max(ts), 'UTC')
FROM netflow.eve_tls
WHERE (SELECT count() FROM netflow.eve_tls_daily) = 0
GROUP BY day, src, ja4, version, sni, dst_as_org;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.eve_tls_daily_mv TO netflow.eve_tls_daily AS
SELECT toDate(ts) AS day FROM netflow.eve_tls WHERE 0;
ALTER TABLE netflow.eve_tls_daily_mv MODIFY QUERY
SELECT toDate(ts) AS day, src, ja4, version, sni, dst_as_org, anyLast(src_host) AS src_host, count() AS sessions,
       toDateTime(min(ts), 'UTC') AS first, toDateTime(max(ts), 'UTC') AS last
FROM netflow.eve_tls
GROUP BY day, src, ja4, version, sni, dst_as_org;

-- Pod connections leaving the cluster, by workload and destination (daily).
CREATE TABLE IF NOT EXISTS netflow.k8s_conns_daily
(
    day Date CODEC(Delta, ZSTD(1)),
    namespace LowCardinality(String) CODEC(ZSTD(1)),
    workload LowCardinality(String) CODEC(ZSTD(1)),
    verdict LowCardinality(String) CODEC(ZSTD(1)),
    drop_reason LowCardinality(String) CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    dst String CODEC(ZSTD(1)),
    dst_port UInt16 CODEC(ZSTD(1)),
    dst_host SimpleAggregateFunction(anyLast, LowCardinality(String)) CODEC(ZSTD(1)),
    dst_as_org SimpleAggregateFunction(anyLast, LowCardinality(String)) CODEC(ZSTD(1)),
    conns SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    first SimpleAggregateFunction(min, DateTime('UTC')) CODEC(ZSTD(1)),
    last SimpleAggregateFunction(max, DateTime('UTC')) CODEC(ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (day, namespace, workload, verdict, drop_reason, proto, dst, dst_port)
TTL day + INTERVAL 365 DAY;

INSERT INTO netflow.k8s_conns_daily
SELECT toDate(ts) AS day, namespace, workload, verdict, drop_reason, proto, dst, dst_port,
       anyLast(dst_host), anyLast(dst_as_org), count(), toDateTime(min(ts), 'UTC'), toDateTime(max(ts), 'UTC')
FROM netflow.k8s_conns
WHERE (SELECT count() FROM netflow.k8s_conns_daily) = 0
GROUP BY day, namespace, workload, verdict, drop_reason, proto, dst, dst_port;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.k8s_conns_daily_mv TO netflow.k8s_conns_daily AS
SELECT toDate(ts) AS day FROM netflow.k8s_conns WHERE 0;
ALTER TABLE netflow.k8s_conns_daily_mv MODIFY QUERY
SELECT toDate(ts) AS day, namespace, workload, verdict, drop_reason, proto, dst, dst_port,
       anyLast(dst_host) AS dst_host, anyLast(dst_as_org) AS dst_as_org, count() AS conns,
       toDateTime(min(ts), 'UTC') AS first, toDateTime(max(ts), 'UTC') AS last
FROM netflow.k8s_conns
GROUP BY day, namespace, workload, verdict, drop_reason, proto, dst, dst_port;

-- Per LAN host per day: internet bytes, flows, and distinct peers and domains, so pages
-- over long ranges read one row per host-day instead of 288 five-minute rows. Bytes are
-- internet-only: LAN<->LAN bytes are booked at both ends in flows_lan_5m and doubled by
-- the router's twin records. Fed from the two per-host rollups (an MV fires on inserts
-- into its source, including inserts made by another MV); each feeds its own columns and
-- leaves the rest empty, which merges away. Query with GROUP BY and the -Merge combinators.
CREATE TABLE IF NOT EXISTS netflow.host_daily_stats
(
    day Date CODEC(Delta, ZSTD(1)),
    lan_ip LowCardinality(String) CODEC(ZSTD(1)),
    lan_host SimpleAggregateFunction(anyLast, LowCardinality(String)) CODEC(ZSTD(1)),
    tx_bytes SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),   -- internet only
    rx_bytes SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),   -- internet only
    flows SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),      -- internet only
    lan_flows SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),  -- LAN peers (doubled, see above)
    peers AggregateFunction(uniq, String),           -- internet AS orgs
    lan_peers AggregateFunction(uniq, String),
    countries AggregateFunction(uniq, String),
    domains AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (day, lan_ip)
TTL day + INTERVAL 365 DAY;

INSERT INTO netflow.host_daily_stats (day, lan_ip, lan_host, tx_bytes, rx_bytes, flows, lan_flows, peers, lan_peers, countries)
SELECT toDate(ts) AS day, lan_ip, anyLast(lan_host),
       sumIf(tx_bytes, peer_country != ''), sumIf(rx_bytes, peer_country != ''),
       sumIf(flows, peer_country != ''), sumIf(flows, peer_country = ''),
       uniqStateIf(peer, peer_country != ''), uniqStateIf(peer, peer_country = ''), uniqStateIf(peer_country, peer_country != '')
FROM netflow.flows_lan_5m
WHERE (SELECT count() FROM netflow.host_daily_stats) = 0
GROUP BY day, lan_ip;

INSERT INTO netflow.host_daily_stats (day, lan_ip, lan_host, domains)
SELECT toDate(ts) AS day, lan_ip, anyLast(lan_host), uniqState(domain)
FROM netflow.flows_domain_5m
WHERE domain != '' AND lan_ip != ''
  AND (SELECT uniqMerge(domains) FROM netflow.host_daily_stats) = 0
GROUP BY day, lan_ip;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.host_daily_stats_lan_mv TO netflow.host_daily_stats AS
SELECT toDate(ts) AS day FROM netflow.flows_lan_5m WHERE 0;
ALTER TABLE netflow.host_daily_stats_lan_mv MODIFY QUERY
-- (source columns qualified: the aliases reuse their names)
SELECT toDate(ts) AS day, lan_ip, anyLast(f.lan_host) AS lan_host,
       sumIf(f.tx_bytes, peer_country != '') AS tx_bytes, sumIf(f.rx_bytes, peer_country != '') AS rx_bytes,
       sumIf(f.flows, peer_country != '') AS flows, sumIf(f.flows, peer_country = '') AS lan_flows,
       uniqStateIf(peer, peer_country != '') AS peers, uniqStateIf(peer, peer_country = '') AS lan_peers,
       uniqStateIf(peer_country, peer_country != '') AS countries
FROM netflow.flows_lan_5m AS f
GROUP BY day, lan_ip;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.host_daily_stats_domain_mv TO netflow.host_daily_stats AS
SELECT toDate(ts) AS day FROM netflow.flows_domain_5m WHERE 0;
ALTER TABLE netflow.host_daily_stats_domain_mv MODIFY QUERY
SELECT toDate(ts) AS day, lan_ip, anyLast(lan_host) AS lan_host, uniqState(domain) AS domains
FROM netflow.flows_domain_5m
WHERE domain != '' AND lan_ip != ''
GROUP BY day, lan_ip;

-- First and last time each LAN host reached each AS, for "new destination for this
-- host" (the per-host counterpart of dns_first_seen). Internet ends only.
CREATE TABLE IF NOT EXISTS netflow.lan_asn_first_seen
(
    lan_ip String,
    remote_asn UInt32,
    remote_as_org SimpleAggregateFunction(anyLast, LowCardinality(String)),
    first SimpleAggregateFunction(min, DateTime('UTC')),
    last SimpleAggregateFunction(max, DateTime('UTC'))
)
ENGINE = AggregatingMergeTree
ORDER BY (lan_ip, remote_asn)
TTL last + INTERVAL 365 DAY;

-- From the 30 days of raw flows. min/max would make a re-run harmless, but it scans
-- every flow, so it too only runs into an empty table.
INSERT INTO netflow.lan_asn_first_seen
SELECT
    if(src_local, src_addr, dst_addr) AS lan_ip,
    if(src_local, dst_asn, src_asn) AS remote_asn,
    anyLast(if(src_local, dst_as_org, src_as_org)),
    toDateTime(min(time_received), 'UTC'), toDateTime(max(time_received), 'UTC')
FROM netflow.flows
WHERE src_local != dst_local AND if(src_local, dst_asn, src_asn) != 0
  AND (SELECT count() FROM netflow.lan_asn_first_seen) = 0
GROUP BY lan_ip, remote_asn;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.lan_asn_first_seen_mv TO netflow.lan_asn_first_seen AS
SELECT '' AS lan_ip FROM netflow.flows WHERE 0;
ALTER TABLE netflow.lan_asn_first_seen_mv MODIFY QUERY
SELECT
    if(src_local, src_addr, dst_addr) AS lan_ip,
    if(src_local, dst_asn, src_asn) AS remote_asn,
    anyLast(if(src_local, dst_as_org, src_as_org)) AS remote_as_org,
    toDateTime(min(time_received), 'UTC') AS first,
    toDateTime(max(time_received), 'UTC') AS last
FROM netflow.flows
WHERE src_local != dst_local AND if(src_local, dst_asn, src_asn) != 0
GROUP BY lan_ip, remote_asn;
