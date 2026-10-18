-- Who each LAN address has been, and when. nb_hosts only holds NetBox as it is now:
-- once a DHCP lease is released (or a VM deleted) its address vanishes from every
-- lookup, and the UI can only call it unknown. This keeps the names, with the span
-- NetBox held each one, so an address can be shown as "was X until <date>". Leases
-- are reused, so the span matters: traffic after `until` is somebody else's.
--
-- A device is its NetBox object (`ref`, see nb_hosts), not its name: netbox-sync renames
-- devices in place, and a name can pass to another device (DHCP hostname clashes are
-- resolved per run). One row per (ip, ref, name, mac) after merges; query with GROUP BY
-- (or FINAL).

CREATE TABLE IF NOT EXISTS netflow.nb_host_history
(
    ip String,
    ref String,                       -- '' for a bare IP, and for the backfill below
    name String,
    mac String,
    kind SimpleAggregateFunction(anyLast, LowCardinality(String)),
    since SimpleAggregateFunction(min, DateTime('UTC')),
    until SimpleAggregateFunction(max, DateTime('UTC'))
)
ENGINE = AggregatingMergeTree
ORDER BY (ip, ref, name, mac);

-- Stamps every named address in NetBox each time netbox-sync's export could have
-- changed it (every 5 minutes), so `until` is within 5 minutes of its removal.
CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.nb_host_history_mv
REFRESH EVERY 5 MINUTE APPEND TO netflow.nb_host_history AS
SELECT ip, ref, name, mac, kind, now() AS since, now() AS until
FROM netflow.nb_hosts
WHERE name != '';

-- Backfill from the year of 5-minute rollups: lan_host is the NetBox name stamped at
-- ingest (the IP when there was none), so the span a name carried traffic is a lower
-- bound on the span NetBox held it. Flows have no ref or MAC, so these rows are only
-- tied to a device by name. min/max make re-running this harmless.
INSERT INTO netflow.nb_host_history
SELECT lan_ip AS ip, '' AS ref, lan_host AS name, '' AS mac, any(lan_kind) AS kind,
       min(ts) AS since, max(ts) AS until
FROM netflow.flows_lan_5m
WHERE lan_host != '' AND lan_host != lan_ip
GROUP BY lan_ip, lan_host;
