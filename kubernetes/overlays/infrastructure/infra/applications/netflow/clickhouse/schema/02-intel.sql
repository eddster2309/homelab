-- Enrichment data maintained by the netflow enricher (../../enrich):
--   dns_answers  <- dns-tail Deployment: Blocky query log (Loki) answer IPs
--   intel_*/port_names <- intel-update CronJob: threat lists, cloud ranges, IANA ports
-- intel/port tables are filled as <t>_new and EXCHANGEd in, like nb_*.

-- 2026-10-18: explicit codecs (46 MiB, ts alone was 35 MiB at 1.9x with no codec). Rows sort
-- by (client, ip, ts), so Delta on ts leaves small steps (11 MiB vs 18 MiB plain ZSTD(1) on a
-- sample; DoubleDelta and T64 were worse). domain is ~2k distinct per day, so LowCardinality
-- (1.5 MiB vs 7.4 MiB in the sample). client and ip are sort-key columns: their types can't
-- change in place, and as strings they're already small. The ALTERs below bring a live table
-- along: a codec-only MODIFY is metadata-only (new parts and merges use it, even for key
-- columns); domain's String -> LowCardinality is a column rewrite, cheap at this size.
CREATE TABLE IF NOT EXISTS netflow.dns_answers
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    client String,                    -- IP that asked Blocky
    ip String,                        -- an A record in the answer
    domain LowCardinality(String) CODEC(ZSTD(1))  -- the name asked for (not the CNAME target)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (client, ip, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;
ALTER TABLE netflow.dns_answers MODIFY COLUMN ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1));
ALTER TABLE netflow.dns_answers MODIFY COLUMN domain LowCardinality(String) CODEC(ZSTD(1));
-- Domain lookups (site and domain pages) can't use the (client, ip, ts) key; a name sits
-- in 1-4 of ~40 granules a day (2026-10-18). Existing parts: materialize-indexes.sh.
ALTER TABLE netflow.dns_answers
    ADD INDEX IF NOT EXISTS idx_domain domain TYPE bloom_filter(0.01) GRANULARITY 1;

-- First and last lookup of each name by each client (2026-10-18), for "first seen" on the
-- What's new and Domains pages, which otherwise group all of dns_answers by domain on
-- every load (9M rows -> ~18k here). Per client, not per name, so the app can still
-- leave out its own lookups: it reads the rows of its own hosts from dns_answers, where
-- it has the timestamps that exclusion needs. Kept a year like the rollups, so a name
-- looked up but never connected to stays known past dns_answers' 30 days.
CREATE TABLE IF NOT EXISTS netflow.dns_first_seen
(
    domain LowCardinality(String),
    client String,
    first SimpleAggregateFunction(min, DateTime('UTC')),
    last SimpleAggregateFunction(max, DateTime('UTC'))
)
ENGINE = AggregatingMergeTree
ORDER BY (domain, client)
TTL last + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.dns_first_seen_mv TO netflow.dns_first_seen AS
SELECT domain, client, toDateTime(min(ts), 'UTC') AS first, toDateTime(max(ts), 'UTC') AS last
FROM netflow.dns_answers WHERE domain != '' GROUP BY domain, client;

-- Backfill from what dns_answers still holds. It re-runs on every schema apply, which is
-- harmless (min/max, merged away) and cheap (~0.2 s), and it fills in anything inserted
-- before the MV existed.
INSERT INTO netflow.dns_first_seen
SELECT domain, client, toDateTime(min(ts), 'UTC'), toDateTime(max(ts), 'UTC')
FROM netflow.dns_answers WHERE domain != '' GROUP BY domain, client;

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
LIFETIME(MIN 60 MAX 120);

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
LIFETIME(MIN 60 MAX 120);

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
    started DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    domain LowCardinality(String) CODEC(ZSTD(1)),
    names UInt16,
    source LowCardinality(String) DEFAULT 'dns'   -- dns (ASOF guess, dns-tail) | sni | http (seen on the wire, 05-eve.sql) | edge (HAProxy on edge01, 09-edge.sql)
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(started)
ORDER BY (client, client_port, server, server_port, proto)
TTL toDateTime(started) + INTERVAL 30 DAY;
ALTER TABLE netflow.conn_domains ADD COLUMN IF NOT EXISTS source LowCardinality(String) DEFAULT 'dns';
-- 2026-10-18: explicit codecs (32 MiB; started was 1.6x). Rows sort by connection, not time,
-- so DoubleDelta (5.1 MiB) beat Delta (9.2 MiB) and plain ZSTD(1) (7.9 MiB) on a sample;
-- domain as LowCardinality is 1.2 MiB against 8.9 MiB. server and the other key columns keep
-- their types (can't ALTER a sort-key column's type). started is only in the partition key and
-- TTL, which allow a codec change; domain is a column rewrite, cheap here.
ALTER TABLE netflow.conn_domains MODIFY COLUMN started DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1));
ALTER TABLE netflow.conn_domains MODIFY COLUMN domain LowCardinality(String) CODEC(ZSTD(1));

-- Per connection: a name seen on the wire over a DNS guess, then the latest. A
-- 5-tuple can recur within the day (edge01's tunnel-leg source ports are reused),
-- and the latest session on it is the one new flows belong to.
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
SOURCE(CLICKHOUSE(QUERY 'SELECT client, client_port, server, server_port, proto, d AS domain, n AS names FROM (SELECT client, client_port, server, server_port, toString(proto) AS proto, argMax(domain, (source != ''dns'', started)) AS d, argMax(names, (source != ''dns'', started)) AS n FROM netflow.conn_domains WHERE started > now() - INTERVAL 1 DAY GROUP BY client, client_port, server, server_port, proto)'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);

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
