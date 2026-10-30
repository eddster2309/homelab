-- pf blocks from OPNsense's filterlog: remote syslog (TCP, RFC5424) -> eve-receiver
-- (Vector, ../../eve/vector.yaml 'fw': keeps block/reject, drops WAN-inbound) -> Kafka
-- topic fwlog -> fw_queue -> fw_blocks. Enriched once at insert, like flows.
--
-- ng_netflow taps the interface before pf, so a blocked packet still shows up as a flow.
-- This table is how the app tells them apart: it matches flows on the 5-tuple at query
-- time (a dictionary would race the flow export for short connections).

-- Recreated on every run (the Kafka engine can't ALTER) so batch settings apply; the MVs
-- are dropped first because ClickHouse refuses to drop a table a view reads from.
-- Consumption resumes from the consumer group's committed offsets.
DROP VIEW IF EXISTS netflow.fw_blocks_mv;
DROP TABLE IF EXISTS netflow.fw_queue;
CREATE TABLE netflow.fw_queue
(
    ts_ms UInt64,
    iface String,
    dir String,
    action String,
    reason String,
    rule_nr UInt32,
    label String,
    proto String,
    src_ip String,
    src_port UInt16,
    dst_ip String,
    dst_port UInt16,
    tcp_flags String,
    length UInt16
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'netflow-kafka-bootstrap:9092',
    kafka_topic_list = 'fwlog',
    kafka_group_name = 'clickhouse-fwlog',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    kafka_flush_interval_ms = 30000,
    kafka_max_block_size = 65536,
    kafka_skip_broken_messages = 100,
    input_format_skip_unknown_fields = 1;

-- One row per blocked packet (a SYN retried three times is three rows).
CREATE TABLE IF NOT EXISTS netflow.fw_blocks
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    iface LowCardinality(String),
    dir LowCardinality(String),
    action LowCardinality(String),
    reason LowCardinality(String),
    rule_nr UInt32,
    label LowCardinality(String),       -- the rule's label/tracker (its hash for automatic rules)
    proto LowCardinality(String),       -- TCP, UDP, ICMP… as in flows.proto
    src String,
    src_port UInt16,
    dst String,
    dst_port UInt16,
    tcp_flags LowCardinality(String),
    length UInt16,
    src_host String,                    -- NetBox names ('' if unknown)
    dst_host String,
    src_segment LowCardinality(String), -- as in flows: NetBox prefix segment or 'internet'
    dst_segment LowCardinality(String),
    dst_as_org LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (src, dst, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- Recreated on every schema run so query changes apply; Kafka holds events meanwhile.
DROP VIEW IF EXISTS netflow.fw_blocks_mv;
CREATE MATERIALIZED VIEW netflow.fw_blocks_mv TO netflow.fw_blocks AS
WITH
    toIPv6OrDefault(src_ip) AS s_ip,
    toIPv6OrDefault(dst_ip) AS d_ip,
    -- 'internet' exactly as flows_mv decides it: the address has a GeoIP country
    dictGet('netflow.geoip_city_blocks', 'geoname_id', s_ip) AS s_gid_city,
    if(s_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', s_ip), s_gid_city) AS s_gid,
    dictGet('netflow.geoip_city_blocks', 'geoname_id', d_ip) AS d_gid_city,
    if(d_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', d_ip), d_gid_city) AS d_gid
SELECT
    fromUnixTimestamp64Milli(toInt64(ts_ms), 'UTC') AS ts,
    iface,
    dir,
    action,
    reason,
    rule_nr,
    label,
    proto,
    src_ip AS src,
    src_port,
    dst_ip AS dst,
    dst_port,
    tcp_flags,
    length,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(src_ip), '') AS src_host,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(dst_ip), '') AS dst_host,
    if(dictGet('netflow.geoip_city_locations', 'country_iso_code', s_gid) != '', 'internet',
       dictGetOrDefault('netflow.nb_prefix_dict', 'segment', s_ip, '')) AS src_segment,
    if(dictGet('netflow.geoip_city_locations', 'country_iso_code', d_gid) != '', 'internet',
       dictGetOrDefault('netflow.nb_prefix_dict', 'segment', d_ip, '')) AS dst_segment,
    dictGet('netflow.geoip_asn', 'autonomous_system_organization', d_ip) AS dst_as_org
FROM netflow.fw_queue;
