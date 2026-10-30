-- Kafka (goflow2 JSON) -> flows_queue -> flows_mv (GeoIP/ASN + NetBox enrichment) -> flows.
-- Enrichment happens once at insert, so rows keep the geo data and host names
-- current at the time (a DHCP address reused later keeps its old owner's name).
-- Private addresses miss the GeoIP dictionaries and get ''/0.

-- flows_mv and flows_queue are recreated on every schema run so column and query
-- changes apply (the Kafka engine can't ALTER). Safe: with no MV attached the
-- engine stops consuming, flows wait in the topic, and the new table resumes from
-- the 'clickhouse' consumer group's committed offsets.
DROP VIEW IF EXISTS netflow.flows_mv;
DROP TABLE IF EXISTS netflow.flows_queue;
CREATE TABLE netflow.flows_queue
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
    proto String,
    src_port UInt16,
    dst_port UInt16,
    in_if UInt32,
    out_if UInt32,
    tcp_flags UInt16,
    -- NetFlow v9 IN_BYTES/IN_PKTS, copied by goflow2's mapping file (goflow2-mapping.yaml).
    -- OPNsense's ng_netflow also sends OUT_BYTES/OUT_PKTS, always 0, and goflow2 writes
    -- IN_* and OUT_* into the same bytes/packets, so the zero wins. 0 for v5.
    in_bytes UInt64,
    in_packets UInt64
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'netflow-kafka-bootstrap:9092',
    kafka_topic_list = 'flows',
    kafka_group_name = 'clickhouse',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    -- One block a minute. At this rate the consumer drains the topic in seconds and
    -- flushes early, so the reschedule wait, not the flush interval, sets the batch
    -- size; at ~7 s every insert re-merged flows_5m and the other rollups (2026-10-28).
    kafka_flush_interval_ms = 60000,
    kafka_consumer_reschedule_ms = 60000,
    kafka_max_block_size = 65536,
    kafka_skip_broken_messages = 100,
    input_format_skip_unknown_fields = 1;

-- 2026-10-18: rebuilt for size (1.74 GiB for 41M rows, 45 B/row was mostly the
-- per-host columns compressing badly under ORDER BY time_received alone).
-- Low-cardinality columns are LowCardinality, narrow ints are narrow, every column
-- has an explicit codec, and the sort key groups rows by conversation so the host,
-- segment and geo columns compress as runs. src_net, dst_net, next_hop and etype
-- were dropped (only the retired Grafana dashboards read the first two). This only
-- applies to a fresh table; the live one was rebuilt by migrate-flows-v2.sh.
CREATE TABLE IF NOT EXISTS netflow.flows
(
    time_received DateTime64(3) CODEC(Delta, ZSTD),
    time_flow_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    time_flow_end DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    type LowCardinality(String) CODEC(ZSTD(1)),
    sampler_address LowCardinality(String) CODEC(ZSTD(1)),
    sampling_rate UInt32 CODEC(ZSTD(1)),
    -- already multiplied by sampling_rate
    bytes UInt64 CODEC(T64, ZSTD(1)),
    packets UInt64 CODEC(T64, ZSTD(1)),
    src_addr String CODEC(ZSTD(1)),
    dst_addr String CODEC(ZSTD(1)),
    proto LowCardinality(String) CODEC(ZSTD(1)),
    src_port UInt16 CODEC(ZSTD(1)),
    dst_port UInt16 CODEC(ZSTD(1)),
    in_if UInt16 CODEC(ZSTD(1)),
    out_if UInt16 CODEC(ZSTD(1)),
    tcp_flags UInt8 CODEC(ZSTD(1)),

    src_country LowCardinality(String) CODEC(ZSTD(1)),
    src_country_name LowCardinality(String) CODEC(ZSTD(1)),
    src_city LowCardinality(String) CODEC(ZSTD(1)),
    src_lat Float32 CODEC(ZSTD(1)),
    src_lon Float32 CODEC(ZSTD(1)),
    src_asn UInt32 CODEC(ZSTD(1)),
    src_as_org LowCardinality(String) CODEC(ZSTD(1)),

    dst_country LowCardinality(String) CODEC(ZSTD(1)),
    dst_country_name LowCardinality(String) CODEC(ZSTD(1)),
    dst_city LowCardinality(String) CODEC(ZSTD(1)),
    dst_lat Float32 CODEC(ZSTD(1)),
    dst_lon Float32 CODEC(ZSTD(1)),
    dst_asn UInt32 CODEC(ZSTD(1)),
    dst_as_org LowCardinality(String) CODEC(ZSTD(1)),

    -- NetBox (02-netbox.sql). '' when NetBox doesn't know the address.
    src_host LowCardinality(String) CODEC(ZSTD(1)),
    src_host_kind LowCardinality(String) CODEC(ZSTD(1)),
    src_segment LowCardinality(String) CODEC(ZSTD(1)),
    dst_host LowCardinality(String) CODEC(ZSTD(1)),
    dst_host_kind LowCardinality(String) CODEC(ZSTD(1)),
    dst_segment LowCardinality(String) CODEC(ZSTD(1)),
    service LowCardinality(String) CODEC(ZSTD(1)),

    -- 02-intel.sql. domain may also be filled a few minutes late by the enricher's
    -- fixup (a flow can arrive before its DNS answer has been exported).
    domain String CODEC(ZSTD(1)),                    -- name the client resolved to reach the server
    domain_names UInt16 CODEC(ZSTD(1)),              -- names the client had for that IP: 1 = certain, >1 = best guess, 0 = none
    threat LowCardinality(String) CODEC(ZSTD(1)),    -- threat lists the remote end is on
    remote_cloud LowCardinality(String) CODEC(ZSTD(1)),  -- "AWS CLOUDFRONT ap-southeast-2", "Microsoft 365 Exchange"

    -- 02-exporters.sql. exporter: the sensor that saw the flow (sampler_address if unlisted).
    -- It is the second sort key column, so its DEFAULT expression is evaluated at insert
    -- and the stored value is what orders the part.
    -- src/dst_local: the end is ours, i.e. GeoIP has no country for it, or it is one of
    -- the exporter hosts' own addresses in NetBox (edge01's public IP, the home WAN).
    exporter LowCardinality(String) DEFAULT dictGetOrDefault('netflow.exporter_dict', 'name', tuple(sampler_address), sampler_address) CODEC(ZSTD(1)),
    src_local UInt8 DEFAULT src_country = '',
    dst_local UInt8 DEFAULT dst_country = '',

    -- 02-workloads.sql. The pod behind a k8s node's end of the flow, "<namespace>/<name>",
    -- from Hubble; '' for everything else. Filled a few minutes late by dns-tail's fixup
    -- when the flow beats its Hubble event. Inbound flows to the Traefik VIP get the backend
    -- workload from Traefik's access log instead (02-traefik.sql); k8s_via says which.
    k8s_workload LowCardinality(String) CODEC(ZSTD(1)),
    k8s_pod LowCardinality(String) CODEC(ZSTD(1)),
    k8s_via LowCardinality(String) CODEC(ZSTD(1))    -- '' = Hubble (the pod behind the node's end), 'traefik' = the workload behind the VIP
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(time_received)
-- The hour prefix keeps time-range pruning working; within an hour, rows are
-- grouped by exporter and conversation (src/dst address), so the host, segment,
-- geo and port columns repeat in runs and compress far better than in arrival order.
ORDER BY (toStartOfHour(time_received), exporter, src_addr, dst_addr, time_received)
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
-- exporter, src/dst_local (2026-10-16). Rows from before then read the DEFAULTs:
-- every one came from OPNsense, and only GeoIP decided local.
ALTER TABLE netflow.flows
    ADD COLUMN IF NOT EXISTS exporter LowCardinality(String) DEFAULT dictGetOrDefault('netflow.exporter_dict', 'name', tuple(sampler_address), sampler_address),
    ADD COLUMN IF NOT EXISTS src_local UInt8 DEFAULT src_country = '',
    ADD COLUMN IF NOT EXISTS dst_local UInt8 DEFAULT dst_country = '';
-- k8s_workload, k8s_pod (2026-10-17)
ALTER TABLE netflow.flows
    ADD COLUMN IF NOT EXISTS k8s_workload LowCardinality(String),
    ADD COLUMN IF NOT EXISTS k8s_pod String;
-- k8s_via (2026-10-17)
ALTER TABLE netflow.flows
    ADD COLUMN IF NOT EXISTS k8s_via LowCardinality(String);
-- src_net, dst_net, next_hop, etype (2026-10-18): unused, so the live table loses them
-- even before it is rebuilt. Safe against flows_mv, which is dropped at the top of
-- this file and recreated below without them.
ALTER TABLE netflow.flows
    DROP COLUMN IF EXISTS src_net,
    DROP COLUMN IF EXISTS dst_net,
    DROP COLUMN IF EXISTS next_hop,
    DROP COLUMN IF EXISTS etype;
-- Skip indexes (2026-10-18) for the filters the sort key can't serve: the "either end"
-- address/ASN tests (src = X OR dst = X; the key only helps the src branch, so an OR
-- needs one index over both columns), and domain/workload equality. Measured on a day
-- of rows: a remote IP, an ASN, a domain or a workload sits in ~2-4 of ~150 granules,
-- a LAN host in ~24. New parts get them on insert; existing parts need
-- materialize-indexes.sh (hand-run, once).
ALTER TABLE netflow.flows
    ADD INDEX IF NOT EXISTS idx_addr (src_addr, dst_addr) TYPE bloom_filter(0.01) GRANULARITY 1,
    ADD INDEX IF NOT EXISTS idx_asn (src_asn, dst_asn) TYPE bloom_filter(0.01) GRANULARITY 1,
    ADD INDEX IF NOT EXISTS idx_domain domain TYPE bloom_filter(0.01) GRANULARITY 1,
    ADD INDEX IF NOT EXISTS idx_k8s_workload k8s_workload TYPE bloom_filter(0.01) GRANULARITY 1;

-- Dropped at the top of this file, with flows_queue.
CREATE MATERIALIZED VIEW netflow.flows_mv TO netflow.flows AS
WITH
    toIPv6OrDefault(src_addr) AS s_ip,
    toIPv6OrDefault(dst_addr) AS d_ip,
    -- fall back to the registered country for blocks with no city/geoname
    dictGet('netflow.geoip_city_blocks', 'geoname_id', s_ip) AS s_gid_city,
    if(s_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', s_ip), s_gid_city) AS s_gid,
    dictGet('netflow.geoip_city_blocks', 'geoname_id', d_ip) AS d_gid_city,
    if(d_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', d_ip), d_gid_city) AS d_gid,
    greatest(sampling_rate, 1) AS rate,
    -- The Traefik VIP's end of a flow (kind k8s-vip: the VIP also carries other services, so
    -- the name decides) and the workload behind it as (workload, pod): by the client's
    -- connection to :443, edge01's tunnel leg to :8443, or the VIP port of a TCP entrypoint.
    -- flows with the VIP as src are the replies.
    src_host_kind = 'k8s-vip' AND position(src_host, 'traefik/traefik') > 0 AS s_traefik,
    dst_host_kind = 'k8s-vip' AND position(dst_host, 'traefik/traefik') > 0 AS d_traefik,
    multiIf(
        proto = 'TCP' AND d_traefik AND dst_port = 443 AND dictHas('netflow.traefik_conn_dict', (src_addr, src_port)),
            dictGet('netflow.traefik_conn_dict', ('workload', 'pod'), (src_addr, src_port)),
        proto = 'TCP' AND s_traefik AND src_port = 443 AND dictHas('netflow.traefik_conn_dict', (dst_addr, dst_port)),
            dictGet('netflow.traefik_conn_dict', ('workload', 'pod'), (dst_addr, dst_port)),
        proto = 'TCP' AND d_traefik AND dst_port = 8443 AND dictHas('netflow.traefik_edge_conn_dict', (src_addr, src_port)),
            dictGet('netflow.traefik_edge_conn_dict', ('workload', 'pod'), (src_addr, src_port)),
        proto = 'TCP' AND s_traefik AND src_port = 8443 AND dictHas('netflow.traefik_edge_conn_dict', (dst_addr, dst_port)),
            dictGet('netflow.traefik_edge_conn_dict', ('workload', 'pod'), (dst_addr, dst_port)),
        proto = 'TCP' AND d_traefik AND dictHas('netflow.traefik_tcp_dict', tuple(dst_port)),
            tuple(dictGet('netflow.traefik_tcp_dict', 'workload', tuple(dst_port)), ''),
        proto = 'TCP' AND s_traefik AND dictHas('netflow.traefik_tcp_dict', tuple(src_port)),
            tuple(dictGet('netflow.traefik_tcp_dict', 'workload', tuple(src_port)), ''),
        tuple('', '')) AS traefik_wl
SELECT
    fromUnixTimestamp64Nano(toInt64(time_received_ns)) AS time_received,
    fromUnixTimestamp64Nano(toInt64(time_flow_start_ns)) AS time_flow_start,
    fromUnixTimestamp64Nano(toInt64(time_flow_end_ns)) AS time_flow_end,
    type,
    sampler_address,
    sampling_rate,
    -- greatest(): v9 from ng_netflow has bytes = 0 and the count in in_bytes (see flows_queue)
    greatest(bytes, in_bytes) * rate AS bytes,
    greatest(packets, in_packets) * rate AS packets,
    src_addr,
    dst_addr,
    proto,
    src_port,
    dst_port,
    toUInt16(in_if) AS in_if,
    toUInt16(out_if) AS out_if,
    toUInt8(tcp_flags) AS tcp_flags,

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
    -- an exporter's own public address gets the exporter's segment ('edge', 'wan')
    multiIf(src_country = '', dictGetOrDefault('netflow.nb_prefix_dict', 'segment', s_ip, ''),
        dictGetOrDefault('netflow.exporter_addr_dict', 'segment', tuple(src_addr), 'internet')) AS src_segment,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(dst_addr), '') AS dst_host,
    dictGetOrDefault('netflow.nb_host_dict', 'kind', tuple(dst_addr), '') AS dst_host_kind,
    multiIf(dst_country = '', dictGetOrDefault('netflow.nb_prefix_dict', 'segment', d_ip, ''),
        dictGetOrDefault('netflow.exporter_addr_dict', 'segment', tuple(dst_addr), 'internet')) AS dst_segment,
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
        NOT dst_local AND dictHas('netflow.dns_ip_dict', tuple(dst_addr)), dictGet('netflow.dns_ip_dict', 'domain', tuple(dst_addr)),
        NOT src_local AND dictHas('netflow.dns_ip_dict', tuple(src_addr)), dictGet('netflow.dns_ip_dict', 'domain', tuple(src_addr)),
        '') AS domain,
    multiIf(
        dictHas('netflow.conn_domain_dict', (src_addr, src_port, dst_addr, dst_port, proto)),
            dictGet('netflow.conn_domain_dict', 'names', (src_addr, src_port, dst_addr, dst_port, proto)),
        dictHas('netflow.conn_domain_dict', (dst_addr, dst_port, src_addr, src_port, proto)),
            dictGet('netflow.conn_domain_dict', 'names', (dst_addr, dst_port, src_addr, src_port, proto)),
        dictHas('netflow.dns_pair_dict', (src_addr, dst_addr)), dictGet('netflow.dns_pair_dict', 'names', (src_addr, dst_addr)),
        dictHas('netflow.dns_pair_dict', (dst_addr, src_addr)), dictGet('netflow.dns_pair_dict', 'names', (dst_addr, src_addr)),
        NOT dst_local AND dictHas('netflow.dns_ip_dict', tuple(dst_addr)), dictGet('netflow.dns_ip_dict', 'names', tuple(dst_addr)),
        NOT src_local AND dictHas('netflow.dns_ip_dict', tuple(src_addr)), dictGet('netflow.dns_ip_dict', 'names', tuple(src_addr)),
        toUInt16(0)) AS domain_names,
    arrayStringConcat(arrayFilter(x -> x != '', [
        dictGetOrDefault('netflow.intel_threat_dict', 'sources', s_ip, ''),
        dictGetOrDefault('netflow.intel_threat_dict', 'sources', d_ip, '')]), ',') AS threat,
    -- the internet end: cloud provider/service/region from published ranges
    if(dst_local AND src_local, '', replaceRegexpAll(trimBoth(concat(
        dictGetOrDefault('netflow.intel_cloud_dict', 'provider', if(NOT dst_local, d_ip, s_ip), ''), ' ',
        dictGetOrDefault('netflow.intel_cloud_dict', 'service', if(NOT dst_local, d_ip, s_ip), ''), ' ',
        dictGetOrDefault('netflow.intel_cloud_dict', 'region', if(NOT dst_local, d_ip, s_ip), ''))), '\\s+', ' ')) AS remote_cloud,
    dictGetOrDefault('netflow.exporter_dict', 'name', tuple(sampler_address), sampler_address) AS exporter,
    src_country = '' OR dictHas('netflow.exporter_addr_dict', tuple(src_addr)) AS src_local,
    dst_country = '' OR dictHas('netflow.exporter_addr_dict', tuple(dst_addr)) AS dst_local,
    -- the node is src for the pod's packets, dst for the replies
    multiIf(
        dictHas('netflow.k8s_conn_dict', (src_addr, src_port, dst_addr, dst_port, proto)),
            dictGet('netflow.k8s_conn_dict', 'workload', (src_addr, src_port, dst_addr, dst_port, proto)),
        dictHas('netflow.k8s_conn_dict', (dst_addr, dst_port, src_addr, src_port, proto)),
            dictGet('netflow.k8s_conn_dict', 'workload', (dst_addr, dst_port, src_addr, src_port, proto)),
        traefik_wl.1) AS k8s_workload,
    multiIf(
        dictHas('netflow.k8s_conn_dict', (src_addr, src_port, dst_addr, dst_port, proto)),
            dictGet('netflow.k8s_conn_dict', 'pod', (src_addr, src_port, dst_addr, dst_port, proto)),
        dictHas('netflow.k8s_conn_dict', (dst_addr, dst_port, src_addr, src_port, proto)),
            dictGet('netflow.k8s_conn_dict', 'pod', (dst_addr, dst_port, src_addr, src_port, proto)),
        traefik_wl.2) AS k8s_pod,
    multiIf(
        dictHas('netflow.k8s_conn_dict', (src_addr, src_port, dst_addr, dst_port, proto)), '',
        dictHas('netflow.k8s_conn_dict', (dst_addr, dst_port, src_addr, src_port, proto)), '',
        traefik_wl.1 != '', 'traefik',
        '') AS k8s_via
FROM netflow.flows_queue;
