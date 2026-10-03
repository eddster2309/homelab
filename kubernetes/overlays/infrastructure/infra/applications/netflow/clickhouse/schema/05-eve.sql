-- Suricata EVE from OPNsense's IDS: eve.json -> syslog-ng (raw lines, TCP) -> eve-receiver
-- (Vector, ../../eve/vector.yaml: keeps tls/http/alert, flattens) -> Kafka topic eve ->
-- eve_queue -> one MV per event type. Enriched once at insert, like flows.
--
-- The names Suricata sees on the wire (TLS SNI, HTTP Host) also go into conn_domains as
-- certain names (names = 1), so flows_mv, dns-tail's fixup and flows_domain_5m use them
-- in place of the DNS guess (conn_domain_dict prefers source != 'dns', 02-intel.sql).

CREATE TABLE IF NOT EXISTS netflow.eve_queue
(
    ts_ms UInt64,
    event_type String,
    in_iface String,
    src_ip String,
    src_port UInt16,
    dest_ip String,
    dest_port UInt16,
    proto String,
    app_proto String,
    sni String,
    version String,
    ja4 String,
    ja3 String,
    subject String,
    issuer String,
    not_after String,
    http_host String,
    http_url String,
    http_method String,
    http_user_agent String,
    http_status UInt16,
    alert_sid UInt32,
    alert_signature String,
    alert_category String,
    alert_severity UInt8,
    alert_action String
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = 'netflow-kafka-bootstrap:9092',
    kafka_topic_list = 'eve',
    kafka_group_name = 'clickhouse-eve',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    kafka_skip_broken_messages = 100,
    input_format_skip_unknown_fields = 1;

-- One row per TLS handshake. src is the client. subject/issuer/not_after are only
-- visible before TLS 1.3 (1.3 encrypts the certificate).
CREATE TABLE IF NOT EXISTS netflow.eve_tls
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    in_iface LowCardinality(String),
    src String,
    src_port UInt16,
    dst String,
    dst_port UInt16,
    proto LowCardinality(String),
    sni String,
    version LowCardinality(String),
    ja4 LowCardinality(String),
    ja3 LowCardinality(String),
    subject String,
    issuer LowCardinality(String),
    not_after String,
    src_host String,                  -- NetBox name of the client ('' if unknown)
    dst_host String,                  -- NetBox name of the server (LAN servers only)
    dst_as_org LowCardinality(String) -- internet servers
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (src, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- One row per plaintext HTTP request.
CREATE TABLE IF NOT EXISTS netflow.eve_http
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    src String,
    src_port UInt16,
    dst String,
    dst_port UInt16,
    host String,
    method LowCardinality(String),
    url String,
    user_agent LowCardinality(String),
    status UInt16,
    src_host String,
    dst_host String,
    dst_as_org LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (src, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- IDS alerts (only if rulesets are enabled in OPNsense).
CREATE TABLE IF NOT EXISTS netflow.eve_alert
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    src String,
    src_port UInt16,
    dst String,
    dst_port UInt16,
    proto LowCardinality(String),
    sid UInt32,
    signature String,
    category LowCardinality(String),
    severity UInt8,
    action LowCardinality(String),
    src_host String,
    dst_host String,
    src_as_org LowCardinality(String),
    dst_as_org LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY ts
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- Recreated on every schema run so query changes apply; Kafka holds events meanwhile.
DROP VIEW IF EXISTS netflow.eve_tls_mv;
CREATE MATERIALIZED VIEW netflow.eve_tls_mv TO netflow.eve_tls AS
SELECT
    fromUnixTimestamp64Milli(toInt64(ts_ms), 'UTC') AS ts,
    in_iface,
    src_ip AS src,
    src_port,
    dest_ip AS dst,
    dest_port AS dst_port,
    proto,
    sni,
    version,
    ja4,
    ja3,
    subject,
    issuer,
    not_after,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(src_ip), '') AS src_host,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(dest_ip), '') AS dst_host,
    dictGet('netflow.geoip_asn', 'autonomous_system_organization', toIPv6OrDefault(dest_ip)) AS dst_as_org
FROM netflow.eve_queue
WHERE event_type = 'tls';

DROP VIEW IF EXISTS netflow.eve_http_mv;
CREATE MATERIALIZED VIEW netflow.eve_http_mv TO netflow.eve_http AS
SELECT
    fromUnixTimestamp64Milli(toInt64(ts_ms), 'UTC') AS ts,
    src_ip AS src,
    src_port,
    dest_ip AS dst,
    dest_port AS dst_port,
    http_host AS host,
    http_method AS method,
    http_url AS url,
    http_user_agent AS user_agent,
    http_status AS status,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(src_ip), '') AS src_host,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(dest_ip), '') AS dst_host,
    dictGet('netflow.geoip_asn', 'autonomous_system_organization', toIPv6OrDefault(dest_ip)) AS dst_as_org
FROM netflow.eve_queue
WHERE event_type = 'http';

DROP VIEW IF EXISTS netflow.eve_alert_mv;
CREATE MATERIALIZED VIEW netflow.eve_alert_mv TO netflow.eve_alert AS
SELECT
    fromUnixTimestamp64Milli(toInt64(ts_ms), 'UTC') AS ts,
    src_ip AS src,
    src_port,
    dest_ip AS dst,
    dest_port AS dst_port,
    proto,
    alert_sid AS sid,
    alert_signature AS signature,
    alert_category AS category,
    alert_severity AS severity,
    alert_action AS action,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(src_ip), '') AS src_host,
    dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(dest_ip), '') AS dst_host,
    dictGet('netflow.geoip_asn', 'autonomous_system_organization', toIPv6OrDefault(src_ip)) AS src_as_org,
    dictGet('netflow.geoip_asn', 'autonomous_system_organization', toIPv6OrDefault(dest_ip)) AS dst_as_org
FROM netflow.eve_queue
WHERE event_type = 'alert';

-- Names seen on the wire -> conn_domains (certain: names = 1). These MVs fire on the
-- inserts eve_tls_mv / eve_http_mv make. IP literals in SNI/Host aren't names.
DROP VIEW IF EXISTS netflow.conn_domains_sni_mv;
CREATE MATERIALIZED VIEW netflow.conn_domains_sni_mv TO netflow.conn_domains AS
SELECT src AS client, src_port AS client_port, dst AS server, dst_port AS server_port, toString(proto) AS proto,
       ts AS started, sni AS domain, toUInt16(1) AS names, 'sni' AS source
FROM netflow.eve_tls
WHERE sni != '' AND NOT isIPv4String(sni) AND NOT isIPv6String(sni);

DROP VIEW IF EXISTS netflow.conn_domains_http_mv;
CREATE MATERIALIZED VIEW netflow.conn_domains_http_mv TO netflow.conn_domains AS
SELECT src AS client, src_port AS client_port, dst AS server, dst_port AS server_port, 'TCP' AS proto,
       ts AS started, host AS domain, toUInt16(1) AS names, 'http' AS source
FROM netflow.eve_http
WHERE host != '' AND NOT isIPv4String(host) AND NOT isIPv6String(host);
