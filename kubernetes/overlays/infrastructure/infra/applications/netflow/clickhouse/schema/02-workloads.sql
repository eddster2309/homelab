-- Kubernetes workloads behind cluster egress, from Cilium's Hubble.
--
-- Pods leave the cluster masqueraded to their node's address, so OPNsense records
-- k8s-node-N:port -> remote. Masquerade keeps the pod's source port (checked on
-- Cilium 1.19), so a Hubble event for the pod and the NetFlow record for the node
-- share the 5-tuple (node_ip, src_port, dst, dst_port, proto). k8s_conn_dict looks it
-- up: flows_mv (03-flows.sql) and dns-tail's fixup fill flows.k8s_workload/k8s_pod.
-- Hubble has no byte counts: it names the pod, NetFlow still measures the traffic.
--
-- Cilium's dynamic exporter (cilium-helmchart-config.yaml) -> hubble-shipper (Vector,
-- ../../hubble/vector.yaml: one line per connection) -> Kafka topic hubble ->
-- k8s_conns_queue -> k8s_conns_mv -> k8s_conns.
-- Sorts before 03-flows.sql because flows_mv looks k8s_conn_dict up.
--
-- Also k8s_pods / k8s_pod_dict: which pod owns an address. Cilium's second exporter, `pods`,
-- logs Traefik's packets to its backends, which name the destination pod; hubble-shipper
-- keeps one line per pod per hour -> Kafka topic hubble-pods -> k8s_pods_queue -> k8s_pods_mv
-- -> k8s_pods. Traefik's access log has only the backend's ip:port, and 10-traefik.sql
-- turns that into a workload with k8s_pod_dict. Pods Traefik doesn't talk to aren't in it.

-- Recreated on every run (the Kafka engine can't ALTER) so batch settings apply; the MVs
-- are dropped first because ClickHouse refuses to drop a table a view reads from.
-- Consumption resumes from the consumer group's committed offsets.
DROP VIEW IF EXISTS netflow.k8s_conns_mv;
DROP TABLE IF EXISTS netflow.k8s_conns_queue;
CREATE TABLE netflow.k8s_conns_queue
(
    ts_ms UInt64,
    node String,                      -- short node name, k8s-node-2
    node_ip String,                   -- the node's InternalIP: what masquerade rewrites the source to
    pod_ip String,
    src_port UInt16,
    dst String,
    dst_port UInt16,
    proto String,                     -- TCP | UDP, as goflow2 spells it
    namespace String,
    pod String,
    workload String,                  -- owning workload (Deployment, StatefulSet, ...); the pod itself if it has none
    workload_kind String,
    verdict String,                   -- FORWARDED | DROPPED
    drop_reason String
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'netflow-kafka-bootstrap:9092',
    kafka_topic_list = 'hubble',
    kafka_group_name = 'clickhouse-hubble',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    kafka_flush_interval_ms = 15000,
    kafka_max_block_size = 65536,
    kafka_skip_broken_messages = 100,
    input_format_skip_unknown_fields = 1;

-- One row per pod connection that left the cluster (or was dropped on its way out).
-- Dropped ones never reach the network, so they have no flows: they're cluster-side
-- policy blocks, alongside pf's fw_blocks.
CREATE TABLE IF NOT EXISTS netflow.k8s_conns
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    node LowCardinality(String),
    node_ip LowCardinality(String),
    pod_ip String,
    src_port UInt16,
    dst String,
    dst_port UInt16,
    proto LowCardinality(String),
    namespace LowCardinality(String),
    pod String,
    workload LowCardinality(String),
    workload_kind LowCardinality(String),
    verdict LowCardinality(String),
    drop_reason LowCardinality(String),
    dst_host String,                  -- NetBox name of a LAN destination
    dst_as_org LowCardinality(String) -- internet destinations
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (namespace, workload, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- Recreated on every schema run so query changes apply; Kafka holds events meanwhile.
DROP VIEW IF EXISTS netflow.k8s_conns_mv;
CREATE MATERIALIZED VIEW netflow.k8s_conns_mv TO netflow.k8s_conns AS
SELECT
    fromUnixTimestamp64Milli(toInt64(ts_ms), 'UTC') AS ts,
    node, node_ip, pod_ip, src_port, dst, dst_port, proto,
    namespace, pod, workload, workload_kind, verdict, drop_reason,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(dst), '') AS dst_host,
    dictGet('netflow.geoip_asn', 'autonomous_system_organization', toIPv6OrDefault(dst)) AS dst_as_org
FROM netflow.k8s_conns_queue
WHERE node_ip != '';

-- Connections that went out, keyed as the node's NetFlow record has them. A 5-tuple
-- can recur within the day (port reuse), and the latest connection on it is the one
-- new flows belong to. workload and pod are "<namespace>/<name>".
CREATE OR REPLACE DICTIONARY netflow.k8s_conn_dict
(
    node_ip String,
    src_port UInt16,
    dst String,
    dst_port UInt16,
    proto String,
    workload String,
    pod String
)
PRIMARY KEY node_ip, src_port, dst, dst_port, proto
SOURCE(CLICKHOUSE(QUERY 'SELECT toString(node_ip) AS node_ip, src_port, dst, dst_port, toString(proto) AS proto, argMax(concat(namespace, ''/'', workload), ts) AS workload, argMax(concat(namespace, ''/'', pod), ts) AS pod FROM netflow.k8s_conns WHERE ts > now() - INTERVAL 1 DAY AND verdict = ''FORWARDED'' GROUP BY node_ip, src_port, dst, dst_port, proto'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);

-- Recreated on every run (the Kafka engine can't ALTER) so batch settings apply; the MVs
-- are dropped first because ClickHouse refuses to drop a table a view reads from.
-- Consumption resumes from the consumer group's committed offsets.
DROP VIEW IF EXISTS netflow.k8s_pods_mv;
DROP TABLE IF EXISTS netflow.k8s_pods_queue;
CREATE TABLE netflow.k8s_pods_queue
(
    ts_ms UInt64,
    node String,
    pod_ip String,
    namespace String,
    pod String,
    workload String,                  -- the pod itself if it has no owner
    workload_kind String
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'netflow-kafka-bootstrap:9092',
    kafka_topic_list = 'hubble-pods',
    kafka_group_name = 'clickhouse-hubble-pods',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    kafka_flush_interval_ms = 30000,
    kafka_max_block_size = 65536,
    kafka_skip_broken_messages = 100,
    input_format_skip_unknown_fields = 1;

-- One row per pod per hour while Traefik is talking to it.
CREATE TABLE IF NOT EXISTS netflow.k8s_pods
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    node LowCardinality(String),
    pod_ip String,
    namespace LowCardinality(String),
    pod String,
    workload LowCardinality(String),
    workload_kind LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (pod_ip, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;

DROP VIEW IF EXISTS netflow.k8s_pods_mv;
CREATE MATERIALIZED VIEW netflow.k8s_pods_mv TO netflow.k8s_pods AS
SELECT fromUnixTimestamp64Milli(toInt64(ts_ms), 'UTC') AS ts,
       node, pod_ip, namespace, pod, workload, workload_kind
FROM netflow.k8s_pods_queue
WHERE pod_ip != '';

-- Pod IP -> its workload and pod, "<namespace>/<name>". A pod IP is reused once the
-- pod is gone, so the latest pod on it wins. Some of Hubble's events for a pod lack its
-- owner, and the shipper then calls the pod its own workload (kind 'Pod'): for the same
-- pod, a sighting with a real owner wins over those.
CREATE OR REPLACE DICTIONARY netflow.k8s_pod_dict
(
    pod_ip String,
    workload String,
    pod String
)
PRIMARY KEY pod_ip
SOURCE(CLICKHOUSE(QUERY 'SELECT p.pod_ip AS pod_ip, argMax(concat(k.namespace, ''/'', k.workload), (k.workload_kind != ''Pod'', k.ts)) AS workload, any(p.pd) AS pod FROM (SELECT pod_ip, argMax(pod, ts) AS lp, argMax(concat(namespace, ''/'', pod), ts) AS pd FROM netflow.k8s_pods WHERE ts > now() - INTERVAL 1 DAY GROUP BY pod_ip) AS p INNER JOIN (SELECT pod_ip, pod, namespace, workload, workload_kind, ts FROM netflow.k8s_pods WHERE ts > now() - INTERVAL 1 DAY) AS k ON k.pod_ip = p.pod_ip AND k.pod = p.lp GROUP BY p.pod_ip'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);
