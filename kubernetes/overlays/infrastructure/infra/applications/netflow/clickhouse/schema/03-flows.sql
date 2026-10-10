-- Kafka (goflow2 JSON) -> flows_queue -> flows_mv (GeoIP/ASN + NetBox enrichment) -> flows.
-- Enrichment happens once at insert, so rows keep the geo data and host names
-- current at the time (a DHCP address reused later keeps its old owner's name).
-- Private addresses miss the GeoIP dictionaries and get ''/0.

CREATE TABLE IF NOT EXISTS netflow.flows_queue
(
    type String,
    time_received_ns UInt64,
    time_flow_start_ns UInt64,
    time_flow_end_ns UInt64,
    sampler_address String,
    sampling_rate UInt64,
    bytes UInt64,
    packets UInt64,
    src_addr String,
    dst_addr String,
    src_net String,
    dst_net String,
    etype String,
    proto String,
    src_port UInt16,
    dst_port UInt16,
    in_if UInt32,
    out_if UInt32,
    tcp_flags UInt16,
    next_hop String
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'netflow-kafka-bootstrap:9092',
    kafka_topic_list = 'flows',
    kafka_group_name = 'clickhouse',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    kafka_skip_broken_messages = 100,
    input_format_skip_unknown_fields = 1;

CREATE TABLE IF NOT EXISTS netflow.flows
(
    time_received DateTime64(3) CODEC(Delta, ZSTD),
    time_flow_start DateTime64(3) CODEC(Delta, ZSTD),
    time_flow_end DateTime64(3) CODEC(Delta, ZSTD),
    type LowCardinality(String),
    sampler_address LowCardinality(String),
    sampling_rate UInt32,
    -- already multiplied by sampling_rate
    bytes UInt64,
    packets UInt64,
    src_addr String,
    dst_addr String,
    src_net String,
    dst_net String,
    etype LowCardinality(String),
    proto LowCardinality(String),
    src_port UInt16,
    dst_port UInt16,
    in_if UInt32,
    out_if UInt32,
    tcp_flags UInt16,
    next_hop String,

    src_country LowCardinality(String),
    src_country_name LowCardinality(String),
    src_city String,
    src_lat Float32,
    src_lon Float32,
    src_asn UInt32,
    src_as_org LowCardinality(String),

    dst_country LowCardinality(String),
    dst_country_name LowCardinality(String),
    dst_city String,
    dst_lat Float32,
    dst_lon Float32,
    dst_asn UInt32,
    dst_as_org LowCardinality(String),

    -- NetBox (02-netbox.sql). '' when NetBox doesn't know the address.
    src_host String,
    src_host_kind LowCardinality(String),
    src_segment LowCardinality(String),
    dst_host String,
    dst_host_kind LowCardinality(String),
    dst_segment LowCardinality(String),
    service LowCardinality(String),

    -- 02-intel.sql. domain may also be filled a few minutes late by the enricher's
    -- fixup (a flow can arrive before its DNS answer has been exported).
    domain String,                    -- name the client resolved to reach the server
    domain_names UInt16,              -- names the client had for that IP: 1 = certain, >1 = best guess, 0 = none
    threat LowCardinality(String),    -- threat lists the remote end is on
    remote_cloud LowCardinality(String)  -- "AWS CLOUDFRONT ap-southeast-2", "Microsoft 365 Exchange"
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(time_received)
ORDER BY time_received
TTL toDateTime(time_received) + INTERVAL 30 DAY;

-- Tables created before the NetBox columns existed
ALTER TABLE netflow.flows
    ADD COLUMN IF NOT EXISTS src_host String,
    ADD COLUMN IF NOT EXISTS src_host_kind LowCardinality(String),
    ADD COLUMN IF NOT EXISTS src_segment LowCardinality(String),
    ADD COLUMN IF NOT EXISTS dst_host String,
    ADD COLUMN IF NOT EXISTS dst_host_kind LowCardinality(String),
    ADD COLUMN IF NOT EXISTS dst_segment LowCardinality(String),
    ADD COLUMN IF NOT EXISTS service LowCardinality(String),
    ADD COLUMN IF NOT EXISTS domain String,
    ADD COLUMN IF NOT EXISTS domain_names UInt16,
    ADD COLUMN IF NOT EXISTS threat LowCardinality(String),
    ADD COLUMN IF NOT EXISTS remote_cloud LowCardinality(String);

-- Recreated on every schema run so query changes apply. Safe: while no MV is
-- attached the Kafka engine stops consuming and flows wait in the topic.
DROP VIEW IF EXISTS netflow.flows_mv;
CREATE MATERIALIZED VIEW netflow.flows_mv TO netflow.flows AS
WITH
    toIPv6OrDefault(src_addr) AS s_ip,
    toIPv6OrDefault(dst_addr) AS d_ip,
    -- fall back to the registered country for blocks with no city/geoname
    dictGet('netflow.geoip_city_blocks', 'geoname_id', s_ip) AS s_gid_city,
    if(s_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', s_ip), s_gid_city) AS s_gid,
    dictGet('netflow.geoip_city_blocks', 'geoname_id', d_ip) AS d_gid_city,
    if(d_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', d_ip), d_gid_city) AS d_gid,
    greatest(sampling_rate, 1) AS rate
SELECT
    fromUnixTimestamp64Nano(toInt64(time_received_ns)) AS time_received,
    fromUnixTimestamp64Nano(toInt64(time_flow_start_ns)) AS time_flow_start,
    fromUnixTimestamp64Nano(toInt64(time_flow_end_ns)) AS time_flow_end,
    type,
    sampler_address,
    sampling_rate,
    bytes * rate AS bytes,
    packets * rate AS packets,
    src_addr,
    dst_addr,
    src_net,
    dst_net,
    etype,
    proto,
    src_port,
    dst_port,
    in_if,
    out_if,
    tcp_flags,
    next_hop,

    dictGet('netflow.geoip_city_locations', 'country_iso_code', s_gid) AS src_country,
    dictGet('netflow.geoip_city_locations', 'country_name', s_gid) AS src_country_name,
    dictGet('netflow.geoip_city_locations', 'city_name', s_gid) AS src_city,
    dictGet('netflow.geoip_city_blocks', 'latitude', s_ip) AS src_lat,
    dictGet('netflow.geoip_city_blocks', 'longitude', s_ip) AS src_lon,
    dictGet('netflow.geoip_asn', 'autonomous_system_number', s_ip) AS src_asn,
    dictGet('netflow.geoip_asn', 'autonomous_system_organization', s_ip) AS src_as_org,

    dictGet('netflow.geoip_city_locations', 'country_iso_code', d_gid) AS dst_country,
    dictGet('netflow.geoip_city_locations', 'country_name', d_gid) AS dst_country_name,
    dictGet('netflow.geoip_city_locations', 'city_name', d_gid) AS dst_city,
    dictGet('netflow.geoip_city_blocks', 'latitude', d_ip) AS dst_lat,
    dictGet('netflow.geoip_city_blocks', 'longitude', d_ip) AS dst_lon,
    dictGet('netflow.geoip_asn', 'autonomous_system_number', d_ip) AS dst_asn,
    dictGet('netflow.geoip_asn', 'autonomous_system_organization', d_ip) AS dst_as_org,

    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(src_addr), '') AS src_host,
    dictGetOrDefault('netflow.nb_host_dict', 'kind', tuple(src_addr), '') AS src_host_kind,
    if(src_country != '', 'internet', dictGetOrDefault('netflow.nb_prefix_dict', 'segment', s_ip, '')) AS src_segment,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(dst_addr), '') AS dst_host,
    dictGetOrDefault('netflow.nb_host_dict', 'kind', tuple(dst_addr), '') AS dst_host_kind,
    if(dst_country != '', 'internet', dictGetOrDefault('netflow.nb_prefix_dict', 'segment', d_ip, '')) AS dst_segment,
    -- The service is on whichever end is listening: try dst:port, then src:port (return traffic)
    dictGetOrDefault('netflow.nb_service_dict', 'name', (dst_addr, proto, dst_port),
        dictGetOrDefault('netflow.nb_service_dict', 'name', (src_addr, proto, src_port), '')) AS service,
    -- 1. the connection's assigned name (src is the client, or dst is for return traffic)
    -- 2. provisional: the client's latest name for that IP (dns-tail replaces it once the connection is assigned)
    -- 3. anyone's latest name for the remote IP
    -- (MV output columns must all exist in flows, so domain and domain_names are two
    -- expressions with the same precedence rather than one tuple.)
    multiIf(
        dictHas('netflow.conn_domain_dict', (src_addr, src_port, dst_addr, dst_port, proto)),
            dictGet('netflow.conn_domain_dict', 'domain', (src_addr, src_port, dst_addr, dst_port, proto)),
        dictHas('netflow.conn_domain_dict', (dst_addr, dst_port, src_addr, src_port, proto)),
            dictGet('netflow.conn_domain_dict', 'domain', (dst_addr, dst_port, src_addr, src_port, proto)),
        dictHas('netflow.dns_pair_dict', (src_addr, dst_addr)), dictGet('netflow.dns_pair_dict', 'domain', (src_addr, dst_addr)),
        dictHas('netflow.dns_pair_dict', (dst_addr, src_addr)), dictGet('netflow.dns_pair_dict', 'domain', (dst_addr, src_addr)),
        dst_country != '' AND dictHas('netflow.dns_ip_dict', tuple(dst_addr)), dictGet('netflow.dns_ip_dict', 'domain', tuple(dst_addr)),
        src_country != '' AND dictHas('netflow.dns_ip_dict', tuple(src_addr)), dictGet('netflow.dns_ip_dict', 'domain', tuple(src_addr)),
        '') AS domain,
    multiIf(
        dictHas('netflow.conn_domain_dict', (src_addr, src_port, dst_addr, dst_port, proto)),
            dictGet('netflow.conn_domain_dict', 'names', (src_addr, src_port, dst_addr, dst_port, proto)),
        dictHas('netflow.conn_domain_dict', (dst_addr, dst_port, src_addr, src_port, proto)),
            dictGet('netflow.conn_domain_dict', 'names', (dst_addr, dst_port, src_addr, src_port, proto)),
        dictHas('netflow.dns_pair_dict', (src_addr, dst_addr)), dictGet('netflow.dns_pair_dict', 'names', (src_addr, dst_addr)),
        dictHas('netflow.dns_pair_dict', (dst_addr, src_addr)), dictGet('netflow.dns_pair_dict', 'names', (dst_addr, src_addr)),
        dst_country != '' AND dictHas('netflow.dns_ip_dict', tuple(dst_addr)), dictGet('netflow.dns_ip_dict', 'names', tuple(dst_addr)),
        src_country != '' AND dictHas('netflow.dns_ip_dict', tuple(src_addr)), dictGet('netflow.dns_ip_dict', 'names', tuple(src_addr)),
        toUInt16(0)) AS domain_names,
    arrayStringConcat(arrayFilter(x -> x != '', [
        dictGetOrDefault('netflow.intel_threat_dict', 'sources', s_ip, ''),
        dictGetOrDefault('netflow.intel_threat_dict', 'sources', d_ip, '')]), ',') AS threat,
    -- the internet end: cloud provider/service/region from published ranges
    if(dst_country = '' AND src_country = '', '', replaceRegexpAll(trimBoth(concat(
        dictGetOrDefault('netflow.intel_cloud_dict', 'provider', if(dst_country != '', d_ip, s_ip), ''), ' ',
        dictGetOrDefault('netflow.intel_cloud_dict', 'service', if(dst_country != '', d_ip, s_ip), ''), ' ',
        dictGetOrDefault('netflow.intel_cloud_dict', 'region', if(dst_country != '', d_ip, s_ip), ''))), '\\s+', ' ')) AS remote_cloud
FROM netflow.flows_queue;
