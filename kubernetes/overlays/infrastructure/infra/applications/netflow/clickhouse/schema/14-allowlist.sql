-- Per-device allowlist decisions from netflowui (app/allowlist/): a user pins a
-- destination or port (always allowed), accepts a flagged one (added to the profile)
-- or removes either. One row per (lan_ip, dest, port); ReplacingMergeTree keeps the
-- latest `updated`, and the API reads with FINAL. A destination decision has port 0, a
-- port decision has dest ''. netflowui's intel writer user holds INSERT (chi.yaml).
-- action: pin | accept | remove. No TTL: decisions are kept until removed.

CREATE TABLE IF NOT EXISTS netflow.host_allowlist
(
    lan_ip String CODEC(ZSTD(1)),
    dest String CODEC(ZSTD(1)),
    port UInt16 CODEC(ZSTD(1)),
    action LowCardinality(String) CODEC(ZSTD(1)),
    updated DateTime('UTC') CODEC(Delta, ZSTD(1))
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY (lan_ip, dest, port);
