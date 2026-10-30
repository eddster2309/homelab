#!/usr/bin/env bash
# One-off, hand-run: rebuild one netflow table with the definition in a schema file
# (new sort key, codecs, LowCardinality; see schema/04-rollup.sql, 2026-10-18).
# Run it after Flux has applied the new schema file (the schema Job only creates
# tables IF NOT EXISTS, so the live table keeps its old definition).
#
#   migrate-table.sh <table> <schema-file> [--drop-mv <mv>]... [--scale-down <deployment>]...
#                    [--reapply <file>]... [--print-ddl]
#
# <schema-file> is a path (or a bare name inside ./schema/) holding
# `CREATE TABLE IF NOT EXISTS netflow.<table>`; --reapply files (default: the
# schema file itself) are re-run after the swap through --multiquery.
#
# Steps
#  1. create netflow.<table>_v2 from that CREATE TABLE (renamed);
#  2. --scale-down: scale each deployment to 0 (original replicas restored on exit,
#     also on failure);
#  3. --drop-mv: DROP VIEW IF EXISTS (for Kafka-fed MVs, where the queue holds the
#     data meanwhile; the --reapply file must recreate them);
#  4. phase 1: copy rows with ts < C one month-partition at a time, where
#     C = toStartOfFiveMinutes(now() - 10 min), and compare per-partition sums of the
#     counter columns (not count(): SummingMergeTree merges rows; count() for any
#     other MergeTree) before moving on. Partitions may be monthly or daily.
#  5. EXCHANGE TABLES <table> AND <table>_v2 (atomic, by name);
#  6. phase 2: copy rows with ts >= C from the old table (now <table>_v2) into the new;
#  7. re-apply the schema (MODIFY QUERY re-binds MVs), print old vs new size. The old
#     copy is never dropped; the DROP command is printed.
#
# Why this is correct for MVs that read netflow.flows (flows_5m_mv, flows_lan_5m_mv)
# and are NOT dropped: an MV with TO <table> stores the target by name and resolves
# it on every insert, so before the swap it writes the old table and after the swap
# the new one. Nothing is copied twice and nothing is missed: phase 1 takes ts < C
# (the MV, 10+ minutes behind, only ever writes ts >= C, bar the odd Kafka straggler),
# the swap routes new MV output to the new table, and phase 2 takes everything the
# old table got for ts >= C up to the swap, which is static afterwards. Rows of one key
# landing in both tables is fine, SummingMergeTree sums them. After the swap the script
# waits and warns if the old table is still receiving rows (i.e. an MV still bound to
# it by UUID); if so, re-run the --reapply file / DROP and recreate the MV by hand,
# then re-copy ts >= C.
# For flows_domain_5m (not an MV) scale down dns-maint: the enricher resumes from
# max(ts) of the table, and would otherwise see an empty/short table mid-migration.
#
# Counters are summed by the columns the SummingMergeTree engine lists, read from
# the DDL itself.
set -euo pipefail

SCHEMA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/schema"

usage() {
  echo "usage: $0 <table> <schema-file> [--drop-mv <mv>]... [--scale-down <deployment>]... [--reapply <file>]... [--print-ddl]" >&2
  exit 2
}

[ $# -ge 2 ] || usage
TABLE="$1"; SCHEMA="$2"; shift 2
[[ "$TABLE" =~ ^[a-z0-9_]+$ ]] || { echo "bad table name '$TABLE'" >&2; exit 2; }
[ -f "$SCHEMA" ] || SCHEMA="$SCHEMA_DIR/$SCHEMA"
[ -f "$SCHEMA" ] || { echo "schema file not found: $SCHEMA" >&2; exit 2; }

MVS=(); DEPLOYS=(); REAPPLY=(); PRINT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --drop-mv) [ $# -ge 2 ] || usage; MVS+=("$2"); shift 2 ;;
    --scale-down) [ $# -ge 2 ] || usage; DEPLOYS+=("$2"); shift 2 ;;
    --reapply) [ $# -ge 2 ] || usage; f="$2"; [ -f "$f" ] || f="$SCHEMA_DIR/$f"; REAPPLY+=("$f"); shift 2 ;;
    --print-ddl) PRINT=1; shift ;;
    *) usage ;;
  esac
done
[ ${#REAPPLY[@]} -gt 0 ] || REAPPLY=("$SCHEMA")

# Print the CREATE TABLE for netflow.<table> up to its terminating ';' (a ';' inside a
# -- comment does not count), renamed to <table>_v2.
v2_ddl() {
  awk -v t="netflow.$TABLE" '
    $0 == "CREATE TABLE IF NOT EXISTS " t { on = 1; sub(t, t "_v2") }
    on { print }
    on { l = $0; sub(/--.*/, "", l); if (l ~ /;[[:space:]]*$/) exit }
  ' "$SCHEMA"
}

ddl="$(v2_ddl)"
if ! grep -q "netflow\.${TABLE}_v2" <<<"$ddl"; then
  echo "could not extract CREATE TABLE IF NOT EXISTS netflow.$TABLE from $SCHEMA" >&2
  exit 1
fi

if [ "$PRINT" = 1 ]; then
  echo "$ddl"
  exit 0
fi

# Columns the engine sums, e.g. SummingMergeTree((bytes, packets, flows)) -> bytes packets flows
sumcols="$(sed -n 's/^ENGINE = SummingMergeTree((\(.*\))).*/\1/p' <<<"$ddl" | tr -d ' ' | tr ',' ' ')"
# Any other MergeTree keeps every row, so a row count checks the copy.
if [ -n "$sumcols" ]; then
  sumexpr="$(for c in $sumcols; do printf 'sum(%s), ' "$c"; done | sed 's/, $//')"
else
  sumcols="rows"; sumexpr="count()"
fi
# Partition expression, e.g. toYYYYMM(ts) or toYYYYMMDD(ts); a partition id is its value
pexpr="$(sed -n 's/^PARTITION BY \(.*\)$/\1/p' <<<"$ddl")"
[ -n "$pexpr" ] || { echo "$TABLE has no PARTITION BY line" >&2; exit 1; }

P="$(kubectl -n netflow get secret clickhouse-credentials -o jsonpath='{.data.admin_password}' | base64 -d)"
ch() {
  kubectl -n netflow exec -i chi-netflow-netflow-0-0-0 -c clickhouse -- \
    clickhouse-client -u admin --password "$P" "$@"
}

declare -A ORIG
restore() {
  for d in "${!ORIG[@]}"; do
    echo "Restoring deploy/$d to ${ORIG[$d]} replicas"
    kubectl -n netflow scale "deploy/$d" --replicas="${ORIG[$d]}" || echo "FAILED to restore $d; scale it back by hand" >&2
  done
}
trap restore EXIT

for d in "${DEPLOYS[@]}"; do
  ORIG[$d]="$(kubectl -n netflow get "deploy/$d" -o jsonpath='{.spec.replicas}')"
  echo "Scaling deploy/$d ${ORIG[$d]} -> 0"
  kubectl -n netflow scale "deploy/$d" --replicas=0
done
if [ ${#DEPLOYS[@]} -gt 0 ]; then
  for d in "${DEPLOYS[@]}"; do kubectl -n netflow wait --for=delete pod -l "app=$d" --timeout=120s || true; done
fi

echo "Creating netflow.${TABLE}_v2"
ch --multiquery <<<"$ddl"
if [ "$(ch -q "SELECT count() FROM netflow.${TABLE}_v2")" != 0 ]; then
  echo "netflow.${TABLE}_v2 already holds rows (leftover from an earlier run?); drop it and retry" >&2
  exit 1
fi

for mv in "${MVS[@]}"; do
  echo "Dropping netflow.$mv (re-created by the re-applied schema)"
  ch -q "DROP VIEW IF EXISTS netflow.$mv"
done

cols="$(ch -q "SELECT arrayStringConcat(groupArray(name), ', ') FROM (SELECT name FROM system.columns WHERE database = 'netflow' AND table = '${TABLE}_v2' ORDER BY position)")"
oldcols="$(ch -q "SELECT arrayStringConcat(groupArray(name), ', ') FROM (SELECT name FROM system.columns WHERE database = 'netflow' AND table = '$TABLE' ORDER BY position)")"
if [ "$(tr ',' '\n' <<<"$cols" | tr -d ' ' | sort)" != "$(tr ',' '\n' <<<"$oldcols" | tr -d ' ' | sort)" ]; then
  echo "column sets differ: old=[$oldcols] new=[$cols]; aborting" >&2
  exit 1
fi

# Cut-off C: 10-15 minutes ago, a bucket boundary
C="$(ch -q "SELECT toUnixTimestamp(toStartOfFiveMinutes(now() - INTERVAL 10 MINUTE))")"
[[ "$C" =~ ^[0-9]+$ ]] || { echo "bad cut-off '$C'" >&2; exit 1; }
echo "Cut-off C = $(date -u -d "@$C" '+%F %T') UTC"

partitions="$(ch -q "SELECT DISTINCT partition FROM system.parts WHERE active AND database = 'netflow' AND table = '$TABLE' ORDER BY partition")"

for part in $partitions; do
  [[ "$part" =~ ^[0-9]{6,8}$ ]] || { echo "unexpected partition id '$part'" >&2; exit 1; }
  echo "Phase 1: partition $part (ts < C)"
  where="$pexpr = $part AND ts < toDateTime($C)"
  ch -q "INSERT INTO netflow.${TABLE}_v2 ($cols) SELECT $cols FROM netflow.$TABLE WHERE $where"
  old="$(ch -q "SELECT $sumexpr FROM netflow.$TABLE WHERE $where")"
  new="$(ch -q "SELECT $sumexpr FROM netflow.${TABLE}_v2 WHERE $where")"
  if [ "$old" != "$new" ]; then
    echo "sum mismatch for $part ($sumcols): old=[$old] new=[$new]; aborting, nothing swapped" >&2
    exit 1
  fi
  echo "  sums ($sumcols): $old"
done

echo "Swapping tables"
ch -q "EXCHANGE TABLES netflow.$TABLE AND netflow.${TABLE}_v2"

# From here netflow.$TABLE is the new table and netflow.${TABLE}_v2 the old one.
echo "Phase 2: ts >= C from the old table"
where="ts >= toDateTime($C)"
ch -q "INSERT INTO netflow.$TABLE ($cols) SELECT $cols FROM netflow.${TABLE}_v2 WHERE $where"
old="$(ch -q "SELECT $sumexpr FROM netflow.${TABLE}_v2 WHERE $where")"
echo "  old table sums ($sumcols) for ts >= C: $old"

for f in "${REAPPLY[@]}"; do
  echo "Re-applying $f"
  ch --multiquery < "$f"
done

if [ ${#MVS[@]} -eq 0 ]; then
  echo "Checking that the old table is no longer written to"
  before="$(ch -q "SELECT sum(rows) FROM system.parts WHERE active AND database = 'netflow' AND table = '${TABLE}_v2'")"
  sleep 20
  after="$(ch -q "SELECT sum(rows) FROM system.parts WHERE active AND database = 'netflow' AND table = '${TABLE}_v2'")"
  # Merges only shrink the row count; growth means new inserts
  if [ "$after" -gt "$before" ]; then
    echo "WARNING: netflow.${TABLE}_v2 (old) is still receiving rows ($before -> $after): an MV is still bound to it." >&2
    echo "Recreate the MV (DROP VIEW, re-apply the schema) and copy the rows it wrote with ts >= C into netflow.$TABLE by hand." >&2
  fi
fi

echo
echo "Size, old (netflow.${TABLE}_v2) vs new (netflow.$TABLE):"
ch --format PrettyCompact -q "
SELECT table, sum(rows) AS n, formatReadableSize(sum(bytes_on_disk)) AS on_disk,
       round(sum(bytes_on_disk) / n, 1) AS bytes_per_row
FROM system.parts
WHERE active AND database = 'netflow' AND table IN ('$TABLE', '${TABLE}_v2')
GROUP BY table ORDER BY table"

echo
echo "Check that data is still arriving, then drop the old copy yourself:"
echo "  DROP TABLE netflow.${TABLE}_v2 SYNC"
