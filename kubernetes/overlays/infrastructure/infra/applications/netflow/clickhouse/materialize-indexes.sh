#!/usr/bin/env bash
# One-off, hand-run: build the skip indexes added on 2026-10-18 (schema/03-flows.sql,
# schema/02-intel.sql) for parts written before them. Run it after Flux has applied the
# schema (the Job adds the indexes; new parts get them on insert). Without it the old
# parts just age out under the 30-day TTL, unindexed until then.
#
# Each MATERIALIZE INDEX is a mutation that rewrites only the index files, part by part,
# in the background; the script waits for each to finish and prints index sizes.
set -euo pipefail

NS=netflow
POD=chi-netflow-netflow-0-0-0
PW="$(kubectl -n "$NS" get secret clickhouse-credentials -o jsonpath='{.data.admin_password}' | base64 -d)"

ch() { kubectl -n "$NS" exec -i "$POD" -- clickhouse-client --user admin --password "$PW" -q "$1"; }

for spec in flows:idx_addr flows:idx_asn flows:idx_domain flows:idx_k8s_workload dns_answers:idx_domain; do
  table="${spec%%:*}"; index="${spec#*:}"
  if [ "$(ch "SELECT count() FROM system.data_skipping_indices WHERE database='netflow' AND table='$table' AND name='$index'")" != 1 ]; then
    echo "netflow.$table has no index $index yet; has the schema Job run?" >&2
    exit 1
  fi
  echo "materializing $table.$index"
  ch "ALTER TABLE netflow.$table MATERIALIZE INDEX $index SETTINGS mutations_sync = 1"
done

ch "SELECT table, name, type_full, formatReadableSize(data_compressed_bytes) AS size
    FROM system.data_skipping_indices WHERE database = 'netflow' ORDER BY table, name
    FORMAT PrettyCompactMonoBlock"
