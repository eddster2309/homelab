-- Traffic of pods that left the cluster (and Traefik's inbound), by workload (hourly,
-- 1y), for the netflowui workloads pages. The backend used to aggregate raw flows with
-- k8s_workload != '' (10M rows a week, no index help).
--
-- One row per workload, pod, direction, node and remote (address, port, proto) per
-- hour, from flows labelled with a workload. k8s_end is the pod's end: the source is a
-- k8s node or the Traefik VIP (src_host_kind IN ('k8s-node', 'k8s-vip')), so the row's
-- bytes are the pod's tx; the remote is the other end (app/queries/workloads.py
-- REMOTE*, NODE). node is the node's host name, node_addr its address (the pages
-- filter on it); on inbound rows (k8s_via = 'traefik') they are the VIP.
-- Distinct remotes are uniq(remote) over the rows, pods uniqExactIf(k8s_pod, ...).
--
-- Not an MV: k8s_workload is labelled late (the fixup in dns-tail), so dns-tail's
-- rollup_k8s inserts each 5-minute bucket once it is SETTLE minutes old. Several
-- inserts to one hourly row merge: AggregatingMergeTree with the counters as
-- SimpleAggregateFunction(sum), since a SummingMergeTree keeps the first value of its
-- other columns. last_seen is also dns-tail's cursor. On an empty table dns-tail
-- starts at the current hour; older history comes from clickhouse/backfill-rollups.sh,
-- one day at a time. About 100k rows a day.
CREATE TABLE IF NOT EXISTS netflow.flows_k8s_1h
(
    ts DateTime CODEC(Delta, ZSTD(1)),
    k8s_workload LowCardinality(String) CODEC(ZSTD(1)),
    k8s_via LowCardinality(String) CODEC(ZSTD(1)),   -- '' (Hubble's egress labels) or 'traefik'
    k8s_pod LowCardinality(String) CODEC(ZSTD(1)),
    k8s_end UInt8 CODEC(ZSTD(1)),                    -- 1: the pod sent these bytes
    node LowCardinality(String) CODEC(ZSTD(1)),
    node_addr LowCardinality(String) CODEC(ZSTD(1)),
    remote String CODEC(ZSTD(1)),
    remote_port UInt16 CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    remote_host SimpleAggregateFunction(anyLast, String) CODEC(ZSTD(1)),
    remote_org SimpleAggregateFunction(anyLast, String) CODEC(ZSTD(1)),
    remote_country SimpleAggregateFunction(anyLast, String) CODEC(ZSTD(1)),
    remote_local SimpleAggregateFunction(max, UInt8) CODEC(ZSTD(1)),
    domain SimpleAggregateFunction(max, String) CODEC(ZSTD(1)),   -- a name wins over ''
    bytes SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    flows SimpleAggregateFunction(sum, UInt64) CODEC(T64, ZSTD(1)),
    last_seen SimpleAggregateFunction(max, DateTime) CODEC(Delta, ZSTD(1))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (toStartOfDay(ts), k8s_workload, k8s_via, k8s_pod, k8s_end, node, node_addr, remote, remote_port, proto, ts)
TTL ts + INTERVAL 365 DAY;
