-- Device classification by netflowui's classifier (app/classify/ in homelab-network-ui),
-- written hourly: one row per LAN host with its class, score and evidence. Replaced
-- wholesale by each run (ReplacingMergeTree keeps the latest `updated` per lan_ip).
-- netflowui's intel writer user holds INSERT on this table (chi.yaml); the API reads it
-- through host_class_dict. source: rules | similarity | llm | unknown.

CREATE TABLE IF NOT EXISTS netflow.host_class
(
    lan_ip String CODEC(ZSTD(1)),
    mac String CODEC(ZSTD(1)),
    cls LowCardinality(String) CODEC(ZSTD(1)),
    score Float32 CODEC(ZSTD(1)),
    source LowCardinality(String) CODEC(ZSTD(1)),
    netbox_class LowCardinality(String) CODEC(ZSTD(1)),
    mismatch UInt8 CODEC(ZSTD(1)),
    evidence String CODEC(ZSTD(1)),      -- JSON array of the signals behind the class
    updated DateTime('UTC') CODEC(Delta, ZSTD(1))
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY lan_ip
TTL updated + INTERVAL 90 DAY;

-- lan_ip -> cls, score for the query bar's class: filter (dictGetOrDefault). FINAL so a
-- host re-classified before the merge reads its latest row; only hosts classified in
-- the last day (the classifier runs hourly), so ones it has stopped classifying (left
-- the network, or now excluded) drop out instead of matching for the table's 90 days.
CREATE OR REPLACE DICTIONARY netflow.host_class_dict
(
    lan_ip String,
    cls String,
    score Float32
)
PRIMARY KEY lan_ip
SOURCE(CLICKHOUSE(QUERY 'SELECT lan_ip, cls, score FROM netflow.host_class FINAL WHERE updated > now() - INTERVAL 1 DAY'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 300 MAX 600);
