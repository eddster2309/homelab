-- Enrichment data maintained by the netflow enricher (../../enrich):
--   dns_answers  <- dns-tail Deployment: Blocky query log (Loki) answer IPs
--   intel_*/port_names <- intel-update CronJob: threat lists, cloud ranges, IANA ports
-- intel/port tables are filled as <t>_new and EXCHANGEd in, like nb_*.

CREATE TABLE IF NOT EXISTS netflow.dns_answers
(
    ts DateTime64(3, 'UTC'),
    client String,                    -- IP that asked Blocky
    ip String,                        -- an A record in the answer
    domain String                     -- the name asked for (not the CNAME target)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (client, ip, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- (Source queries aggregate under other names in a subquery: 'argMax(domain) AS domain'
-- followed by uniqExact(domain) makes ClickHouse nest the alias in the aggregate.)
-- Last name each client resolved to each IP (past day), and how many different
-- names it resolved to that IP. Only a provisional label: a shared IP (CDN, the
-- Traefik VIP) has many names, and "latest" is often not the one in use. The
-- per-connection assignment below replaces it within a couple of minutes.
CREATE OR REPLACE DICTIONARY netflow.dns_pair_dict
(
    client String,
    ip String,
    domain String,
    names UInt16
)
PRIMARY KEY client, ip
SOURCE(CLICKHOUSE(QUERY 'SELECT client, ip, d AS domain, n AS names FROM (SELECT client, ip, argMax(domain, ts) AS d, toUInt16(uniqExact(domain)) AS n FROM netflow.dns_answers WHERE ts > now() - INTERVAL 1 DAY GROUP BY client, ip)'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 20 MAX 40);

-- Fallback: last name anyone resolved to an IP (a device reusing another's cache, DoH gaps).
CREATE OR REPLACE DICTIONARY netflow.dns_ip_dict
(
    ip String,
    domain String,
    names UInt16
)
PRIMARY KEY ip
SOURCE(CLICKHOUSE(QUERY 'SELECT ip, d AS domain, n AS names FROM (SELECT ip, argMax(domain, ts) AS d, toUInt16(uniqExact(domain)) AS n FROM netflow.dns_answers WHERE ts > now() - INTERVAL 1 DAY GROUP BY ip)'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 20 MAX 40);

-- One name per connection, chosen by dns-tail: the client's most recent lookup of
-- the server IP at or just before the connection started (ASOF match), kept for
-- every later record of the same connection, so a long stream isn't relabelled
-- when the device looks up another name on the same IP mid-stream.
-- names = distinct names the client had for that IP (1 = certain, >1 = best guess).
-- A name Suricata saw on the wire (TLS SNI / HTTP Host, source != 'dns') beats the DNS guess.
CREATE TABLE IF NOT EXISTS netflow.conn_domains
(
    client String,
    client_port UInt16,
    server String,
    server_port UInt16,
    proto LowCardinality(String),
    started DateTime64(3, 'UTC'),
    domain String,
    names UInt16,
    source LowCardinality(String) DEFAULT 'dns'   -- dns (ASOF guess, dns-tail) | sni | http (seen on the wire, 05-eve.sql)
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(started)
ORDER BY (client, client_port, server, server_port, proto)
TTL toDateTime(started) + INTERVAL 30 DAY;
ALTER TABLE netflow.conn_domains ADD COLUMN IF NOT EXISTS source LowCardinality(String) DEFAULT 'dns';

CREATE OR REPLACE DICTIONARY netflow.conn_domain_dict
(
    client String,
    client_port UInt16,
    server String,
    server_port UInt16,
    proto String,
    domain String,
    names UInt16
)
PRIMARY KEY client, client_port, server, server_port, proto
SOURCE(CLICKHOUSE(QUERY 'SELECT client, client_port, server, server_port, proto, d AS domain, n AS names FROM (SELECT client, client_port, server, server_port, toString(proto) AS proto, argMin(domain, (source = ''dns'', started)) AS d, argMin(names, (source = ''dns'', started)) AS n FROM netflow.conn_domains WHERE started > now() - INTERVAL 1 DAY GROUP BY client, client_port, server, server_port, proto)'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 20 MAX 40);

CREATE TABLE IF NOT EXISTS netflow.intel_threat
(
    network String,
    sources String,                   -- comma list: spamhaus-drop, feodo, tor-exit, crowdsec
    detail String
)
ENGINE = MergeTree ORDER BY network;
CREATE TABLE IF NOT EXISTS netflow.intel_threat_new AS netflow.intel_threat;

CREATE OR REPLACE DICTIONARY netflow.intel_threat_dict
(
    network String,
    sources String,
    detail String
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(DB 'netflow' TABLE 'intel_threat'))
LAYOUT(IP_TRIE)
LIFETIME(MIN 300 MAX 600);

CREATE TABLE IF NOT EXISTS netflow.intel_cloud
(
    network String,
    provider LowCardinality(String),  -- AWS, Google Cloud, Google, Cloudflare, GitHub, Microsoft 365
    service String,                   -- e.g. CLOUDFRONT, S3, Exchange, actions
    region String
)
ENGINE = MergeTree ORDER BY network;
CREATE TABLE IF NOT EXISTS netflow.intel_cloud_new AS netflow.intel_cloud;

CREATE OR REPLACE DICTIONARY netflow.intel_cloud_dict
(
    network String,
    provider String,
    service String,
    region String
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(DB 'netflow' TABLE 'intel_cloud'))
LAYOUT(IP_TRIE)
LIFETIME(MIN 300 MAX 600);

CREATE TABLE IF NOT EXISTS netflow.port_names
(
    proto LowCardinality(String),     -- TCP | UDP, matching flows.proto
    port UInt16,
    name String,
    description String
)
ENGINE = MergeTree ORDER BY (proto, port);
CREATE TABLE IF NOT EXISTS netflow.port_names_new AS netflow.port_names;

CREATE OR REPLACE DICTIONARY netflow.port_names_dict
(
    proto String,
    port UInt16,
    name String,
    description String
)
PRIMARY KEY proto, port
SOURCE(CLICKHOUSE(DB 'netflow' TABLE 'port_names'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 3600 MAX 7200);
