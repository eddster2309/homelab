-- LAN-to-LAN traffic by LAN host x domain (1y), and its blocked twin: the rows
-- flows_domain_5m / flows_blocked_domain_5m hold for internet traffic, for flows with a
-- domain whose two ends are both ours (a service on the LAN looked up by name). The
-- netflowui backend used to build these rows from 30 days of raw flows on every
-- request (LAN_DOMAIN_SQL in queries/domain_traffic.py); it reads these tables instead.
--
-- Same columns, sort key, engine and TTL as flows_domain_5m (they copy its definition,
-- as the other twins do). remote_org/country/cloud and threat are always ''. The client
-- is the side that isn't the server: the lower port of the two.
--
-- Not MVs: dns-tail's rollup_lan inserts each 5-minute bucket once it is SETTLE
-- minutes old, after the late domain fixup, so rows carry the final domain; its
-- rollup_blocked fills the twin from the same buckets and fw_rollup_cursor
-- (07-fw-rollup.sql). On an empty table dns-tail starts at the current hour; older
-- history comes from clickhouse/backfill-rollups.sh, one day at a time. About 32k rows
-- a week.
CREATE TABLE IF NOT EXISTS netflow.flows_lan_domain_5m AS netflow.flows_domain_5m;
CREATE TABLE IF NOT EXISTS netflow.flows_blocked_lan_domain_5m AS netflow.flows_domain_5m;
