#!/usr/bin/env bash
# One-off, hand-run: fill the rollups added in schema/16-lan-domain-rollup.sql,
# schema/17-k8s-rollup.sql and schema/19-security-rollups.sql with the history dns-tail
# doesn't write itself, one day at a time from the raw 30-day tables:
#
#   flows_lan_domain_5m           LAN-to-LAN flows with a domain (dns-tail rollup_lan)
#   flows_blocked_lan_domain_5m   the same, only flows pf blocked (rollup_blocked)
#   flows_k8s_1h                  flows labelled with a workload (rollup_k8s)
#   flows_seg_1h                  LAN segment pairs (rollup_seg)
#   flows_svc_1h                  flows to service ports (rollup_svc)
#   flows_wan_1h                  flows to the internet (rollup_wan)
#
# (fw_blocks_dst_1h, schema/18, and dns_pairs_1h, schema/19, backfill themselves in the
# schema Job.)
#
# Run it after Flux has applied the schema and the dns-tail image that fills these
# tables is running. dns-tail starts an empty table at the current hour (never at the
# start of the history); this script covers everything before the table's oldest row,
# newest day first, so a re-run (after a failure, or a second time) only does what is
# missing: a day's INSERT is one statement, and its window ends where the table's data
# begins (min(ts)), so no bucket is ever added twice. On a table with no rows it fills
# up to the newest settled bucket, so for an empty table run it while dns-tail is
# stopped, or before dns-tail has written its first rows; otherwise the buckets dns-tail
# writes meanwhile can be added twice.
#
#   backfill-rollups.sh [--dry-run] [--days N] [--table <name>]...
#
# --dry-run   print each table's windows and change nothing
# --days N    how far back to go (default 30, the raw flows' TTL)
# --table     only this table (repeatable); default: all six
#
# The SELECTs are copies of dns-tail's LAN_ROLLUP_SELECT / K8S_ROLLUP_SELECT / SEG, SVC, WAN_ROLLUP_SELECT / BLOCKED
# (netflowui services/dns-tail/dns_tail.py); keep them in step. Cost, measured as a
# SELECT over one day: LAN rollup ~1.3 CPU s, k8s ~2; the blocked twin more (~17 CPU s
# per week of raw flows); the three security tables ~25 + ~25 + ~17 CPU s per week of
# raw flows (about 5 CPU minutes for the 30 days; a day's INSERT takes 10-25 s wall).
# Each INSERT runs alone on the 2-CPU ClickHouse.
set -euo pipefail

NS=netflow
POD=chi-netflow-netflow-0-0-0
DRY=0
DAYS=30
TABLES=()

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --days) shift; DAYS="${1:?--days needs a number}" ;;
    --table) shift; TABLES+=("${1:?--table needs a name}") ;;
    *) echo "usage: $0 [--dry-run] [--days N] [--table <name>]..." >&2; exit 2 ;;
  esac
  shift
done
[[ "$DAYS" =~ ^[0-9]+$ ]] || { echo "--days must be a number" >&2; exit 2; }
[ ${#TABLES[@]} -gt 0 ] || TABLES=(flows_lan_domain_5m flows_blocked_lan_domain_5m flows_k8s_1h flows_seg_1h flows_svc_1h flows_wan_1h)
for t in "${TABLES[@]}"; do
  case "$t" in
    flows_lan_domain_5m | flows_blocked_lan_domain_5m | flows_k8s_1h | flows_seg_1h | flows_svc_1h | flows_wan_1h) ;;
    *) echo "unknown table '$t'" >&2; exit 2 ;;
  esac
done

PW="$(kubectl -n "$NS" get secret clickhouse-credentials -o jsonpath='{.data.admin_password}' | base64 -d)"
ch() { kubectl -n "$NS" exec -i "$POD" -- clickhouse-client --user admin --password "$PW" --max_execution_time=1800 -q "$1"; }

ROLLUP_COLUMNS="ts, lan_ip, lan_host, lan_segment, domain, domain_names, remote_org, remote_country, remote_cloud, threat, proto, tx_bytes, rx_bytes, flows, exporter"
K8S_COLUMNS="ts, k8s_workload, k8s_via, k8s_pod, k8s_end, node, node_addr, remote, remote_port, proto, remote_host, remote_org, remote_country, remote_local, domain, bytes, flows, last_seen"
SEG_COLUMNS="ts, client_segment, server_segment, client, client_host, server, server_host, port, proto, flows, blocked, bytes, last_seen"
SVC_COLUMNS="ts, dst_addr, dst_host, dst_segment, proto, dst_port, src_addr, src_segment, lt, src_country, src_as_org, flows, blocked, bytes, last_seen"
WAN_COLUMNS="ts, src_addr, src_host, src_segment, dst_addr, dst_host, dst_as_org, proto, dst_port, domain, flows, blocked, bytes, last_seen"

# @START@, @END@, @EXTRA@ and @BLOCKED@ are filled in by insert_sql.
LAN_SELECT="
SELECT toStartOfFiveMinutes(time_received) AS ts,
       if(dst_srv, src_addr, dst_addr) AS lan_ip,
       if(dst_srv, if(src_host != '', src_host, src_addr), if(dst_host != '', dst_host, dst_addr)) AS lan_host,
       if(dst_srv, src_segment, dst_segment) AS lan_segment,
       domain,
       max(domain_names) AS domain_names,
       '' AS remote_org, '' AS remote_country, '' AS remote_cloud, '' AS threat, proto,
       sumIf(bytes, dst_srv) AS tx_bytes,
       sumIf(bytes, NOT dst_srv) AS rx_bytes,
       count() AS flows,
       exporter
FROM (SELECT *, (NOT dst_local OR (src_local AND dst_port <= src_port)) AS dst_srv FROM netflow.flows
      WHERE time_received >= @START@ AND time_received < @END@ AND src_local AND dst_local AND domain != ''@EXTRA@)
GROUP BY ts, lan_ip, lan_host, lan_segment, domain, proto, exporter"

BLOCKED_COND="(src_addr, dst_addr, proto, if(proto IN ('TCP', 'UDP'), src_port, 0),
                  if(proto IN ('TCP', 'UDP'), dst_port, 0)) IN (
        SELECT src, dst, proto, src_port, dst_port FROM netflow.fw_blocks
        WHERE ts >= @START@ - INTERVAL 2 MINUTE AND ts < @END@ + INTERVAL 2 MINUTE
          AND (proto != 'TCP' OR (position(tcp_flags, 'S') > 0 AND position(tcp_flags, 'A') = 0)))"
BLOCKED_EXTRA=" AND $BLOCKED_COND"

K8S_SELECT="
SELECT toStartOfHour(time_received) AS ts, k8s_workload, k8s_via, k8s_pod, k8s_end,
       if(k8s_end, src_host, dst_host) AS node,
       if(k8s_end, src_addr, dst_addr) AS node_addr,
       if(k8s_end, dst_addr, src_addr) AS remote,
       if(k8s_end, dst_port, src_port) AS remote_port,
       proto,
       anyLast(if(k8s_end, dst_host, src_host)) AS remote_host,
       anyLast(if(k8s_end, dst_as_org, src_as_org)) AS remote_org,
       anyLast(if(k8s_end, dst_country, src_country)) AS remote_country,
       max(if(k8s_end, dst_local, src_local)) AS remote_local,
       max(domain) AS domain,
       sum(bytes) AS bytes,
       count() AS flows,
       max(time_received) AS last_seen
FROM (SELECT *, src_host_kind IN ('k8s-node', 'k8s-vip') AS k8s_end FROM netflow.flows
      WHERE time_received >= @START@ AND time_received < @END@ AND k8s_workload != '')
GROUP BY ts, k8s_workload, k8s_via, k8s_pod, k8s_end, node, node_addr, remote, remote_port, proto"

SEG_SELECT="
SELECT toStartOfHour(time_received) AS ts,
       if(fwd, src_segment, dst_segment) AS client_segment, if(fwd, dst_segment, src_segment) AS server_segment,
       if(fwd, src_addr, dst_addr) AS client, if(fwd, src_host, dst_host) AS client_host,
       if(fwd, dst_addr, src_addr) AS server, if(fwd, dst_host, src_host) AS server_host,
       least(src_port, dst_port) AS port, proto,
       count() AS flows, countIf(@BLOCKED@) AS blocked, sum(bytes) AS bytes,
       max(time_received) AS last_seen
FROM (SELECT *, dst_port <= src_port AS fwd FROM netflow.flows
      WHERE time_received >= @START@ AND time_received < @END@
        AND src_segment NOT IN ('', 'internet') AND dst_segment NOT IN ('', 'internet') AND src_segment != dst_segment)
GROUP BY ts, client_segment, server_segment, client, client_host, server, server_host, port, proto"

SVC_SELECT="
SELECT toStartOfHour(time_received) AS ts, dst_addr, dst_host, dst_segment, proto, dst_port, src_addr, src_segment,
       dst_port < src_port AS lt, src_country, src_as_org,
       count() AS flows, countIf(@BLOCKED@) AS blocked, sum(bytes) AS bytes,
       max(time_received) AS last_seen
FROM netflow.flows
WHERE time_received >= @START@ AND time_received < @END@ AND dst_segment NOT IN ('', 'internet')
  AND (dst_port <= src_port OR dictHas('netflow.nb_service_dict', (dst_addr, proto, dst_port)))
GROUP BY ts, dst_addr, dst_host, dst_segment, proto, dst_port, src_addr, src_segment, lt, src_country, src_as_org"

WAN_SELECT="
SELECT toStartOfHour(time_received) AS ts, src_addr, src_host, src_segment, dst_addr, dst_host, dst_as_org, proto,
       dst_port, domain,
       count() AS flows, countIf(@BLOCKED@) AS blocked, sum(bytes) AS bytes,
       max(time_received) AS last_seen
FROM netflow.flows
WHERE time_received >= @START@ AND time_received < @END@ AND dst_segment = 'internet'
GROUP BY ts, src_addr, src_host, src_segment, dst_addr, dst_host, dst_as_org, proto, dst_port, domain"

# insert_sql <table> <start epoch> <end epoch>
insert_sql() {
  local table="$1" s="toDateTime($2)" e="toDateTime($3)" sel cols extra=""
  case "$table" in
    flows_lan_domain_5m) sel="$LAN_SELECT"; cols="$ROLLUP_COLUMNS" ;;
    flows_blocked_lan_domain_5m) sel="$LAN_SELECT"; cols="$ROLLUP_COLUMNS"; extra="$BLOCKED_EXTRA" ;;
    flows_k8s_1h) sel="$K8S_SELECT"; cols="$K8S_COLUMNS" ;;
    flows_seg_1h) sel="$SEG_SELECT"; cols="$SEG_COLUMNS" ;;
    flows_svc_1h) sel="$SVC_SELECT"; cols="$SVC_COLUMNS" ;;
    flows_wan_1h) sel="$WAN_SELECT"; cols="$WAN_COLUMNS" ;;
  esac
  sel="${sel//@BLOCKED@/$BLOCKED_COND}"
  sel="${sel//@EXTRA@/$extra}"
  sel="${sel//@START@/$s}"
  sel="${sel//@END@/$e}"
  printf 'INSERT INTO netflow.%s (%s) %s' "$table" "$cols" "$sel"
}

fmt() { date -u -d "@$1" '+%F %T'; }

# The newest bucket that has settled (dns-tail's SETTLE, 10 minutes).
SETTLED="$(ch "SELECT toUnixTimestamp(toStartOfFiveMinutes(now() - INTERVAL 10 MINUTE))")"

for table in "${TABLES[@]}"; do
  if [ "$(ch "SELECT count() FROM system.tables WHERE database = 'netflow' AND name = '$table'")" != 1 ]; then
    echo "netflow.$table doesn't exist; has the schema Job run?" >&2
    exit 1
  fi
  # How far back there is anything to roll up: the raw tables' oldest row (for the
  # blocked twin the first pf block: nothing before it is blocked).
  if [ "$table" = flows_blocked_lan_domain_5m ]; then
    oldest="$(ch "SELECT toUnixTimestamp(toStartOfDay(min(ts))) FROM netflow.fw_blocks")"
  else
    oldest="$(ch "SELECT toUnixTimestamp(toStartOfDay(min(time_received))) FROM netflow.flows")"
  fi
  echo "== $table (raw data from $(fmt "$oldest") UTC, settled up to $(fmt "$SETTLED") UTC)"

  for n in $(seq 0 "$DAYS"); do
    # Day n back: [dstart, dend), from ClickHouse so the server's time zone and DST rule.
    read -r dstart dend <<<"$(ch "SELECT toUnixTimestamp(toStartOfDay(addDays(today(), -$n))), toUnixTimestamp(toStartOfDay(addDays(today(), -$n + 1)))")"
    if [ "$dend" -le "$oldest" ]; then
      echo "  no raw data before $(fmt "$dend") UTC; done"
      break
    fi
    # The table's data starts here (min(ts)); an empty one is filled up to the newest
    # settled bucket.
    first="$(ch "SELECT toUnixTimestamp(min(ts)) FROM netflow.$table")"
    [ "$first" != 0 ] || first="$SETTLED"
    end=$(( dend < first ? dend : first ))
    start=$(( dstart > oldest ? dstart : oldest ))
    if [ "$end" -le "$start" ]; then
      echo "  $(fmt "$dstart") UTC: already filled"
      continue
    fi
    echo "  $(fmt "$dstart") UTC: [$(fmt "$start"), $(fmt "$end"))"
    if [ "$DRY" != 1 ]; then
      ch "$(insert_sql "$table" "$start" "$end")"
    fi
  done

  if [ "$DRY" = 1 ]; then
    echo "  (dry run: nothing inserted; windows assume each day lands its rows)"
  else
    ch "SELECT '$table' AS table, count() AS \`rows\`, min(ts) AS first, max(ts) AS last FROM netflow.$table FORMAT PrettyCompactMonoBlock"
  fi
done
