#!/usr/bin/env bash
# One-off, hand-run: rebuild the live netflow.flows with the 2026-10-18 definition
# (new sort key, LowCardinality/narrow types, codecs; see schema/03-flows.sql).
# Run it once, after Flux has applied the new schema (the schema Job has already
# dropped src_net, dst_net, next_hop and etype from the live table, so both tables
# have the same columns to copy).
#
# Steps: create flows_v2 from the CREATE TABLE in 03-flows.sql, drop flows_mv (Kafka
# holds the flows meanwhile), copy one day-partition at a time and compare counts,
# swap the tables, then re-apply 03 and 04 to recreate flows_mv and re-bind the
# rollup MVs. The old table is left as flows_v2; it is never dropped here.
#
# Known loss: the enricher's late domain fixup (ALTER UPDATE on flows) that lands
# during the copy is lost for rows already copied, i.e. only the last few minutes'
# domains. Acceptable.
set -euo pipefail

SCHEMA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/schema"

# Print 03-flows.sql's CREATE TABLE for flows, renamed to flows_v2.
flows_v2_ddl() {
  awk '
    /^CREATE TABLE IF NOT EXISTS netflow\.flows$/ { on = 1 }
    on { print }
    on && !/^[[:space:]]*--/ && /;[[:space:]]*$/ { exit }
  ' "$SCHEMA_DIR/03-flows.sql" | sed 's/^CREATE TABLE IF NOT EXISTS netflow\.flows$/CREATE TABLE IF NOT EXISTS netflow.flows_v2/'
}

if [ "${1:-}" = "--print-ddl" ]; then
  flows_v2_ddl
  exit 0
fi

P="$(kubectl -n netflow get secret clickhouse-credentials -o jsonpath='{.data.admin_password}' | base64 -d)"

ch() {
  kubectl -n netflow exec -i chi-netflow-netflow-0-0-0 -c clickhouse -- \
    clickhouse-client -u admin --password "$P" "$@"
}

ddl="$(flows_v2_ddl)"
if ! grep -q 'netflow.flows_v2' <<<"$ddl"; then
  echo "could not extract the flows CREATE TABLE from 03-flows.sql" >&2
  exit 1
fi

echo "Creating netflow.flows_v2"
ch --multiquery <<<"$ddl"

echo "Dropping netflow.flows_mv (Kafka keeps the flows until it is recreated)"
ch -q "DROP VIEW IF EXISTS netflow.flows_mv"

cols="$(ch -q "SELECT arrayStringConcat(groupArray(name), ', ') FROM (SELECT name FROM system.columns WHERE database = 'netflow' AND table = 'flows_v2' ORDER BY position)")"

partitions="$(ch -q "SELECT DISTINCT partition FROM system.parts WHERE active AND database = 'netflow' AND table = 'flows' ORDER BY partition")"

for part in $partitions; do
  if ! [[ "$part" =~ ^[0-9]{8}$ ]]; then
    echo "unexpected partition id '$part'" >&2
    exit 1
  fi
  echo "Copying partition $part"
  ch -q "INSERT INTO netflow.flows_v2 ($cols) SELECT $cols FROM netflow.flows WHERE toYYYYMMDD(time_received) = $part"
  old="$(ch -q "SELECT count() FROM netflow.flows WHERE toYYYYMMDD(time_received) = $part")"
  new="$(ch -q "SELECT count() FROM netflow.flows_v2 WHERE toYYYYMMDD(time_received) = $part")"
  if [ "$old" != "$new" ]; then
    echo "count mismatch for $part: flows=$old flows_v2=$new; aborting (flows_mv is still dropped)" >&2
    exit 1
  fi
  echo "  $old rows"
done

echo "Swapping tables"
ch -q "EXCHANGE TABLES netflow.flows AND netflow.flows_v2"

echo "Re-applying 03-flows.sql (recreates flows_queue and flows_mv) and 04-rollup.sql (re-binds the rollup MVs)"
ch --multiquery < "$SCHEMA_DIR/03-flows.sql"
ch --multiquery < "$SCHEMA_DIR/04-rollup.sql"

echo
echo "Size, old (netflow.flows_v2) vs new (netflow.flows):"
ch --format PrettyCompact -q "
SELECT table, sum(rows) AS n, formatReadableSize(sum(bytes_on_disk)) AS on_disk,
       round(sum(bytes_on_disk) / n, 1) AS bytes_per_row
FROM system.parts
WHERE active AND database = 'netflow' AND table IN ('flows', 'flows_v2')
GROUP BY table ORDER BY table"

echo
echo "Check that flows are arriving, then drop the old copy yourself:"
echo "  DROP TABLE netflow.flows_v2 SYNC"
