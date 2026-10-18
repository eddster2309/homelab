-- Blocked twins of the three rollups: the same rows, keys and enrichment as
-- flows_5m / flows_lan_5m / flows_domain_5m, but only for flows pf blocked (their
-- 5-tuple is a blocked connection attempt in fw_blocks, 06-fwlog.sql). A page shows
-- allowed traffic as rollup minus twin, or the blocked share next to the total.
--
-- Filled by dns-tail's rollup_blocked step (enrich/dns_tail.py), once per settled
-- 5-minute bucket, with flows_lan_5m_mv's / flows_5m_mv's / ROLLUP_SELECT's own
-- expressions, so the keys match row for row. Its cursor is fw_rollup_cursor.
-- Only buckets after the filterlog feed started have rows: earlier traffic is
-- simply "not known to be blocked".

CREATE TABLE IF NOT EXISTS netflow.flows_blocked_5m AS netflow.flows_5m;
CREATE TABLE IF NOT EXISTS netflow.flows_blocked_lan_5m AS netflow.flows_lan_5m;
CREATE TABLE IF NOT EXISTS netflow.flows_blocked_domain_5m AS netflow.flows_domain_5m;
-- The twins copy their rollup's definition (sort key, types, codecs), so they took
-- the 2026-10-18 rebuild of 04-rollup.sql the same way; the per-column ALTERs that
-- used to follow here were made obsolete by it.

-- One row per bucket rolled up; the next run starts after max(ts).
CREATE TABLE IF NOT EXISTS netflow.fw_rollup_cursor
(
    ts DateTime,
    done DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY ts
TTL ts + INTERVAL 30 DAY;
