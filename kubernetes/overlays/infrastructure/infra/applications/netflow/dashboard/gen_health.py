#!/usr/bin/env python3
"""Generates the netflow-pipeline Grafana dashboard: health of the NetFlow pipeline itself.

  python3 gen_health.py && gcx resources push -p netflow-pipeline.json

goflow2 -> Kafka -> ClickHouse, plus the enrichers (dns-tail, intel-update,
netbox-sync, geoipupdate). Everything is VictoriaMetrics except the dictionary
table, which only ClickHouse knows. Metric sources (see ../scrapes.yaml):
  goflow2_*                 goflow2 :8080
  kafka_consumergroup_*     Strimzi Kafka Exporter; kafka_server_* / kafka_log_* broker JMX
  chi_clickhouse_*          clickhouse-operator metrics-exporter (ServiceMonitor)
  dns_tail_*                dns-tail :9090
  vector_*                  eve-receiver :9598 (Suricata EVE from OPNsense)
  netflow_intel_*           pushed by intel-update each run
  kube_cronjob_* / kube_job_*  kube-state-metrics
"""
import json
import os

VM = {"type": "prometheus", "uid": "P4169E866C3094E38"}
CH = {"type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow"}

NS = 'namespace="netflow"'
CHI = 'chi="netflow"'
GROUP = 'consumergroup="clickhouse",topic="flows"'
EVE_GROUP = 'consumergroup="clickhouse-eve",topic="eve"'
ENRICH_JOBS = "intel-update|geoipupdate"

panels = []
_y = 0


def row(title, collapsed=False):
    global _y
    panels.append({"type": "row", "title": title, "collapsed": collapsed, "gridPos": {"x": 0, "y": _y, "w": 24, "h": 1},
                   "id": len(panels) + 1, "panels": []})
    _y += 1


def prom(expr, legend="", instant=False, fmt=None):
    t = {"datasource": VM, "expr": expr, "legendFormat": legend or "__auto", "range": not instant, "instant": instant}
    if fmt:
        t["format"] = fmt
    return t


def panel(title, type, x, w, h, targets, desc="", unit=None, options=None, fc=None, overrides=None, ds=VM):
    p = {"id": len(panels) + 1, "title": title, "type": type, "description": desc, "datasource": ds,
         "gridPos": {"x": x, "y": _y, "w": w, "h": h}, "targets": targets,
         "fieldConfig": {"defaults": {**(fc or {}), **({"unit": unit} if unit else {})}, "overrides": overrides or []},
         "options": options or {}}
    for i, t in enumerate(targets):
        t["refId"] = chr(ord("A") + i)
    panels.append(p)
    return p


def advance(h):
    global _y
    _y += h


def thresholds(*steps):
    """steps: base colour, then (value, colour) pairs."""
    return {"mode": "absolute", "steps": [{"color": steps[0], "value": None}] +
            [{"color": c, "value": v} for v, c in steps[1:]]}


STAT = {"colorMode": "background", "graphMode": "area", "justifyMode": "center", "textMode": "value",
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}


def stat(title, x, w, expr, unit, desc, th, decimals=None, mappings=None):
    fc = {"thresholds": th, "color": {"mode": "thresholds"}}
    if decimals is not None:
        fc["decimals"] = decimals
    if mappings:
        fc["mappings"] = mappings
    panel(title, "stat", x, w, 4, [prom(expr, instant=False)], desc, unit, STAT, fc)


TS_LEGEND = {"legend": {"displayMode": "list", "placement": "bottom", "calcs": []},
             "tooltip": {"mode": "multi", "sort": "desc"}}
TS_TABLE = {"legend": {"displayMode": "table", "placement": "right", "calcs": ["lastNotNull", "max"]},
            "tooltip": {"mode": "multi", "sort": "desc"}}


def ts(title, x, w, h, targets, unit, desc, legend=TS_LEGEND, fill=10, stack=False, fc_extra=None, overrides=None):
    fc = {"custom": {"drawStyle": "line", "fillOpacity": fill, "lineWidth": 1, "showPoints": "never",
                     "stacking": {"mode": "normal" if stack else "none", "group": "A"}, "spanNulls": False},
          "color": {"mode": "palette-classic"}, **(fc_extra or {})}
    return panel(title, "timeseries", x, w, h, targets, desc, unit, legend, fc, overrides)


# ============================================================== Overview
row("Overview")
stat("NetFlow in", 0, 4, "sum(rate(goflow2_flow_traffic_packets_total[5m]))", "pps",
     "UDP NetFlow packets goflow2 receives from OPNsense (REDACTED_IP:2055). 0 means the firewall export, the "
     "LoadBalancer IP or goflow2 is broken.", thresholds("red", (0.01, "green")), 2)
stat("Flows decoded", 4, 4, 'sum(rate(goflow2_flow_process_nf_flowset_total{type="DataFlowSet"}[5m]))', "ops",
     "Flow records per second goflow2 decodes and produces to Kafka (each NetFlow v5 packet carries up to 30).",
     thresholds("red", (0.01, "green")), 1)
stat("Consumer lag", 8, 4, f"sum(kafka_consumergroup_lag{{{GROUP}}})", "short",
     "Messages in topic 'flows' not yet read by ClickHouse (group 'clickhouse'). Grows when the flows_mv is "
     "detached or ClickHouse is down; Kafka keeps 24h / 5 GiB.",
     thresholds("green", (5000, "orange"), (50000, "red")), 0)
stat("Rows into ClickHouse", 12, 4, f"sum(rate(chi_clickhouse_event_KafkaRowsRead{{{CHI}}}[5m]))", "rowsps",
     "Rows the Kafka engine table (flows_queue) reads per second. Should track 'Flows decoded'.",
     thresholds("red", (0.01, "green")), 1)
stat("DNS answers lag", 16, 4, f"time() - max(dns_tail_cursor_timestamp_seconds{{{NS}}})", "s",
     "How far behind now dns-tail's Loki cursor is. Normal is POLL + LOKI_LAG (~45 s). Flows newer than this "
     "can't get a domain until the fixup runs.", thresholds("green", (180, "orange"), (900, "red")), 0)
stat("Intel data age", 20, 4,
     f'time() - max(kube_cronjob_status_last_successful_time{{{NS},cronjob="intel-update"}})', "s",
     "Since intel-update last succeeded (threat lists, cloud ranges, port names). Runs every 6h; a failed feed "
     "fails the run and keeps the old table.", thresholds("green", (7 * 3600, "orange"), (13 * 3600, "red")), 0)
advance(4)

ts("Pipeline throughput", 0, 12, 8, [
    prom('sum(rate(goflow2_flow_process_nf_flowset_total{type="DataFlowSet"}[$__rate_interval]))', "goflow2 decoded"),
    prom('sum(rate(kafka_server_brokertopicmetrics_messagesin_total{topic="flows"}[$__rate_interval]))', "Kafka messages in"),
    prom(f"sum(rate(chi_clickhouse_event_KafkaRowsRead{{{CHI}}}[$__rate_interval]))", "ClickHouse rows read"),
], "ops", "Flow records per second at each hop. The three lines should overlap; a gap shows where flows stop.",
    fill=0)
ts("Consumer lag", 12, 12, 8, [
    prom(f"sum(kafka_consumergroup_lag{{{GROUP}}})", "lag (messages)"),
], "short", "Kafka messages waiting for ClickHouse. Sawtooth up to a few thousand is normal (the Kafka engine "
    "flushes in blocks); a steady climb means ClickHouse isn't consuming.",
    fc_extra={"thresholds": thresholds("transparent", (50000, "red")),
              "custom": {"drawStyle": "line", "fillOpacity": 20, "lineWidth": 1, "showPoints": "never",
                         "thresholdsStyle": {"mode": "line+area"}, "spanNulls": False}})
advance(8)

# ============================================================== goflow2
row("goflow2")
ts("NetFlow packets by exporter", 0, 8, 7, [
    prom("sum by (remote_ip) (rate(goflow2_flow_traffic_packets_total[$__rate_interval]))", "{{remote_ip}}"),
], "pps", "UDP packets received, per exporting router.")
ts("Errors and drops", 8, 8, 7, [
    prom("sum(rate(goflow2_flow_decoder_error_total[$__rate_interval])) or vector(0)", "decode errors"),
    prom("sum(rate(goflow2_flow_process_nf_errors_total[$__rate_interval])) or vector(0)", "NetFlow errors"),
    prom("sum(rate(goflow2_flow_dropped_packets_total[$__rate_interval])) or vector(0)", "dropped (queue full)"),
], "pps", "Packets goflow2 couldn't decode or dropped because its queue was full. Flat zero is healthy; these "
    "series only exist after the first error.", fill=0)
ts("Decode time", 16, 8, 7, [
    prom("sum(rate(goflow2_flow_decoding_time_seconds_sum[$__rate_interval])) / sum(rate(goflow2_flow_decoding_time_seconds_count[$__rate_interval]))", "mean"),
    prom('max(goflow2_flow_decoding_time_seconds{quantile="0.5"})', "p50"),
], "s", "Time to decode one NetFlow packet. goflow2's p99 isn't shown: over a 10-minute summary window at "
    "~1 packet/s it is a single outlier.", fill=0)
advance(7)

# ============================================================== Kafka
row("Kafka")
stat("Broker up", 0, 4, f'sum(up{{{NS},pod=~"netflow-dual-.*"}})', "none",
     "The single KRaft controller+broker (netflow-dual-0) answering scrapes.", thresholds("red", (1, "green")), 0,
     [{"type": "value", "options": {"0": {"text": "DOWN"}, "1": {"text": "UP"}}}])
stat("Offline partitions", 4, 4, "sum(kafka_controller_kafkacontroller_offlinepartitionscount)", "none",
     "Partitions without a leader. Must be 0.", thresholds("green", (1, "red")), 0)
stat("Topic 'flows' size", 8, 4, 'sum(kafka_log_log_size{topic="flows"})', "bytes",
     "On-disk size of the buffer topic (zstd). Capped at 5 GiB / 24h by the KafkaTopic.",
     thresholds("green", (3 * 2**30, "orange"), (4.5 * 2**30, "red")), 1)
stat("Oldest unread", 12, 4,
     f"sum(kafka_consumergroup_lag{{{GROUP}}}) / clamp_min(sum(rate(kafka_topic_partition_current_offset{{topic=\"flows\"}}[15m])), 0.001)",
     "s", "Consumer lag expressed as time at the current produce rate. Must stay well under 24h (retention) or "
     "flows are lost.", thresholds("green", (600, "orange"), (6 * 3600, "red")), 0)
stat("Broker heap", 16, 4,
     f'sum(jvm_memory_used_bytes{{{NS},area="heap",pod=~"netflow-dual-.*"}}) / sum(jvm_memory_max_bytes{{{NS},area="heap",pod=~"netflow-dual-.*"}})',
     "percentunit", "JVM heap used / -Xmx (512 MiB).", thresholds("green", (0.8, "orange"), (0.95, "red")), 0)
stat("Volume used", 20, 4,
     f'max(kubelet_volume_stats_used_bytes{{{NS},persistentvolumeclaim=~"data-0-netflow-dual-.*"}} / kubelet_volume_stats_capacity_bytes{{{NS},persistentvolumeclaim=~"data-0-netflow-dual-.*"}})',
     "percentunit", "Broker Longhorn volume (20 Gi).", thresholds("green", (0.7, "orange"), (0.85, "red")), 0)
advance(4)
ts("Topic throughput", 0, 12, 7, [
    prom('sum(rate(kafka_server_brokertopicmetrics_bytesin_total{topic="flows"}[$__rate_interval]))', "in (goflow2)"),
    prom('sum(rate(kafka_server_brokertopicmetrics_bytesout_total{topic="flows"}[$__rate_interval]))', "out (ClickHouse)"),
], "Bps", "Compressed bytes produced to and fetched from 'flows'.", fill=0)
ts("Offsets", 12, 12, 7, [
    prom('sum(kafka_topic_partition_current_offset{topic="flows"})', "latest (produced)"),
    prom(f"sum(kafka_consumergroup_current_offset{{{GROUP}}})", "committed (clickhouse)"),
], "short", "Head of the topic vs ClickHouse's committed position; the gap is the lag.", fill=0)
advance(7)

# ============================================================== ClickHouse
row("ClickHouse")
stat("Server up", 0, 4, f"max(chi_clickhouse_metric_Uptime{{{CHI}}}) > bool 0", "none",
     "metrics-exporter can query the server.", thresholds("red", (1, "green")), 0,
     [{"type": "value", "options": {"0": {"text": "DOWN"}, "1": {"text": "UP"}}}])
stat("Kafka partitions", 4, 4, f"sum(chi_clickhouse_metric_KafkaAssignedPartitions{{{CHI}}})", "none",
     "Partitions of 'flows' assigned to the Kafka engine. 0 means flows_queue isn't consuming (MV dropped, broker "
     "down). (KafkaConsumersWithAssignment is not used: it dips to -1 between polls.)",
     thresholds("red", (1, "green")), 0)
stat("Failed queries", 8, 4, f"sum(increase(chi_clickhouse_event_FailedQuery{{{CHI}}}[1h])) or vector(0)", "short",
     "Failed queries in the last hour (dashboards, enrichers, schema Job).",
     thresholds("green", (1, "orange"), (50, "red")), 0)
stat("Memory", 12, 4, f"max(chi_clickhouse_metric_MemoryTracking{{{CHI}}})", "bytes",
     "Memory ClickHouse tracks (limit 4 GiB). About 750 MB is dictionaries, mostly GeoIP.",
     thresholds("green", (3 * 2**30, "orange"), (3.6 * 2**30, "red")), 1)
stat("Data on disk", 16, 4, f'sum(chi_clickhouse_table_parts_bytes{{{CHI},active="1"}})', "bytes",
     "Compressed size of every active part, all databases (netflow + system logs).",
     thresholds("green"), 1)
stat("Volume used", 20, 4,
     f'max(kubelet_volume_stats_used_bytes{{{NS},persistentvolumeclaim=~"data-chi-netflow-.*"}} / kubelet_volume_stats_capacity_bytes{{{NS},persistentvolumeclaim=~"data-chi-netflow-.*"}})',
     "percentunit", "ClickHouse Longhorn data volume (30 Gi).", thresholds("green", (0.7, "orange"), (0.85, "red")), 0)
advance(4)

table_opts = {"displayMode": "gradient", "orientation": "horizontal", "showUnfilled": True, "valueMode": "color",
              "namePlacement": "left", "sizing": "manual", "minVizHeight": 16, "maxVizHeight": 22,
              "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "legend": {"showLegend": False}}
panel("Table size on disk (netflow)", "bargauge", 0, 8, 10, [
    prom(f'sort_desc(sum by (table) (chi_clickhouse_table_parts_bytes{{{CHI},database="netflow",active="1",table!~".*_new"}}))',
         "{{table}}", instant=True),
], "Compressed bytes of active parts per table. flows is 30 d; the *_5m rollups keep 1 y.", "bytes", table_opts,
    {"color": {"mode": "continuous-BlPu"}, "decimals": 1})
panel("Rows (netflow)", "bargauge", 8, 8, 10, [
    prom(f'sort_desc(sum by (table) (chi_clickhouse_table_parts_rows{{{CHI},database="netflow",active="1",table!~".*_new"}}))',
         "{{table}}", instant=True),
], "Rows per table. nb_*, intel_* and port_names are replaced wholesale on each refresh.", "short", table_opts,
    {"color": {"mode": "continuous-BlPu"}, "decimals": 0})
panel("System log size", "bargauge", 16, 8, 10, [
    prom(f'sort_desc(sum by (table) (chi_clickhouse_table_parts_bytes{{{CHI},database="system",active="1"}}))',
         "{{table}}", instant=True),
], "ClickHouse's own system.*_log tables, 7-day TTL (chi.yaml). Should level off around 1-2 GB.", "bytes",
    table_opts, {"color": {"mode": "continuous-GrYlRd"}, "decimals": 1})
advance(10)

ts("netflow table growth", 0, 12, 8, [
    prom(f'sum by (table) (chi_clickhouse_table_parts_bytes{{{CHI},database="netflow",active="1",table=~"flows.*|dns_answers|eve_.*"}})',
         "{{table}}"),
], "bytes", "Size over time of the tables that grow. flows should plateau after 30 days.", legend=TS_TABLE, fill=0)
ts("Active parts per table", 12, 12, 8, [
    prom(f'topk(8, sum by (table) (chi_clickhouse_table_parts{{{CHI},active="1"}}))', "{{table}}"),
], "short", "Parts per table. Hundreds on one table means inserts are too small or merges are behind.",
    legend=TS_TABLE, fill=0)
advance(8)
ts("Inserts", 0, 8, 7, [
    prom(f"sum(rate(chi_clickhouse_event_InsertedRows{{{CHI}}}[$__rate_interval]))", "rows/s"),
], "rowsps", "All rows inserted (flows via the MV, rollups, enrichers, system logs).", fill=10)
ts("Queries", 8, 8, 7, [
    prom(f"sum(rate(chi_clickhouse_event_Query{{{CHI}}}[$__rate_interval]))", "queries/s"),
    prom(f"sum(rate(chi_clickhouse_event_FailedQuery{{{CHI}}}[$__rate_interval]))", "failed/s"),
], "qps", "", fill=0, overrides=[{"matcher": {"id": "byName", "options": "failed/s"},
                                  "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]}])
ts("Memory", 16, 8, 7, [
    prom(f"max(chi_clickhouse_metric_MemoryTracking{{{CHI}}})", "tracked"),
    prom(f"max(chi_clickhouse_metric_MemoryDictionaryBytesAllocated{{{CHI}}})", "dictionaries"),
], "bytes", "Container limit is 4 GiB.", fill=0)
advance(7)

panel("Dictionaries", "table", 0, 24, 13, [{
    "datasource": CH, "editorType": "sql", "format": 1, "queryType": "table",
    "rawSql": """SELECT name, status, element_count AS elements, bytes_allocated AS memory,
       last_successful_update_time AS last_update, loading_duration AS load_s, last_exception
FROM system.dictionaries WHERE database = 'netflow' ORDER BY name"""}],
    "Dictionaries flows_mv and the dashboards use (from ClickHouse, not VictoriaMetrics). status must be LOADED; "
    "last_exception explains a FAILED load.", ds=CH,
    options={"cellHeight": "sm", "showHeader": True, "footer": {"show": False}},
    overrides=[{"matcher": {"id": "byName", "options": "memory"}, "properties": [{"id": "unit", "value": "bytes"}]},
               {"matcher": {"id": "byName", "options": "load_s"}, "properties": [{"id": "unit", "value": "s"}, {"id": "decimals", "value": 2}]},
               {"matcher": {"id": "byName", "options": "status"}, "properties": [
                   {"id": "custom.cellOptions", "value": {"type": "color-background"}},
                   {"id": "mappings", "value": [
                       {"type": "value", "options": {"LOADED": {"color": "green", "index": 0}}},
                       {"type": "regex", "options": {"pattern": "FAILED.*", "result": {"color": "red", "index": 1}}},
                       {"type": "regex", "options": {"pattern": "LOADING.*|NOT_LOADED", "result": {"color": "orange", "index": 2}}}]}]},
               {"matcher": {"id": "byName", "options": "last_update"}, "properties": [{"id": "custom.width", "value": 180}]}])
advance(13)

# ============================================================== Enrichment
row("Enrichment")
stat("dns-tail rollup lag", 0, 4, f"time() - max(dns_tail_rollup_timestamp_seconds{{{NS}}})", "s",
     "flows_domain_5m is complete up to here. It trails by SETTLE (10 min) + one MAINT cycle (5 min) normally.",
     thresholds("green", (30 * 60, "orange"), (2 * 3600, "red")), 0)
stat("dns-tail errors (1h)", 4, 4, f"sum(increase(dns_tail_errors_total{{{NS}}}[1h]))", "short",
     "Failed poll/fixup/rollup steps in the last hour. Each step retries on the next loop.",
     thresholds("green", (1, "orange"), (10, "red")), 0)
stat("NetBox data age", 8, 4,
     'time() - max(kube_cronjob_status_last_successful_time{namespace="netbox",cronjob="netbox-sync"})', "s",
     "Since netbox-sync last succeeded (NetBox -> nb_* tables). Runs every 5 min.",
     thresholds("green", (20 * 60, "orange"), (3600, "red")), 0)
stat("GeoIP data age", 12, 4,
     f'time() - max(kube_cronjob_status_last_successful_time{{{NS},cronjob="geoipupdate"}})', "s",
     "Since the weekly MaxMind download (GeoLite2 City + ASN CSVs) last succeeded.", thresholds("green", (8 * 86400, "orange"), (15 * 86400, "red")), 0)
stat("Intel feeds OK", 16, 4,
     f"sum(last_over_time(netflow_intel_source_ok{{{NS}}}[7h])) / count(last_over_time(netflow_intel_source_ok{{{NS}}}[7h]))",
     "percentunit", "Share of intel-update sources (threat, cloud, IANA) that succeeded in the last run.",
     thresholds("red", (0.99, "green")), 0)
stat("Failed jobs (6h)", 20, 4,
     'count((kube_job_status_failed{namespace=~"netflow|netbox",job_name=~"(intel-update|geoipupdate|netbox-sync|clickhouse-schema).*"} > 0)'
     ' and on (namespace, job_name) (kube_job_created > time() - 6 * 3600)) or vector(0)',
     "short", "Enrichment/schema Jobs created in the last 6h that failed. A few netbox-sync failures while "
     "ClickHouse restarts are expected (its Service is headless, the name vanishes with the pod).",
     thresholds("green", (1, "red")), 0)
advance(4)

ts("DNS answers stored", 0, 8, 7, [
    prom(f"sum(rate(dns_tail_answers_stored_total{{{NS}}}[$__rate_interval]))", "answers/s"),
], "ops", "A records from Blocky's query log written to dns_answers.", fill=10)
ts("dns-tail step errors", 8, 8, 7, [
    prom(f"sum by (step) (increase(dns_tail_errors_total{{{NS}}}[$__rate_interval]))", "{{step}}"),
], "short", "poll = Loki/insert, fixup = late domain ALTER UPDATE, rollup = flows_domain_5m insert. Zero is healthy.",
    fill=0, stack=True)
ts("dns-tail lag", 16, 8, 7, [
    prom(f"time() - max(dns_tail_cursor_timestamp_seconds{{{NS}}})", "Loki cursor"),
    prom(f"time() - max(dns_tail_rollup_timestamp_seconds{{{NS}}})", "domain rollup"),
], "s", "Age of the newest stored DNS answer window and of the domain rollup.", fill=0)
advance(7)

panel("Intel feed entries (last run)", "bargauge", 0, 12, 9, [
    prom(f"sort_desc(last_over_time(netflow_intel_source_entries{{{NS}}}[7h]))", "{{list}} / {{source}}", instant=True),
], "Entries each feed returned on the last intel-update run. A feed missing here failed (see the table to the right).",
    "short", table_opts, {"color": {"mode": "continuous-BlPu"}, "decimals": 0})
panel("Enrichment jobs", "table", 12, 12, 9, [
    prom(f'time() - kube_cronjob_status_last_successful_time{{namespace=~"netflow|netbox",cronjob=~"{ENRICH_JOBS}|netbox-sync"}}',
         instant=True, fmt="table"),
    prom(f'time() - kube_cronjob_status_last_schedule_time{{namespace=~"netflow|netbox",cronjob=~"{ENRICH_JOBS}|netbox-sync"}}',
         instant=True, fmt="table"),
    prom(f'kube_cronjob_next_schedule_time{{namespace=~"netflow|netbox",cronjob=~"{ENRICH_JOBS}|netbox-sync"}} - time()',
         instant=True, fmt="table"),
], "CronJobs that feed the enrichment tables. 'since success' much larger than 'since scheduled' means recent runs "
   "failed.", options={"cellHeight": "sm", "showHeader": True, "footer": {"show": False}},
    unit="s", fc={"decimals": 0})
panels[-1]["transformations"] = [
    {"id": "merge", "options": {}},
    {"id": "organize", "options": {
        "excludeByName": {"Time": True, "__name__": True, "container": True, "endpoint": True, "instance": True,
                          "job": True, "service": True, "pod": True, "prometheus": True, "cluster": True},
        "renameByName": {"Value #A": "since success", "Value #B": "since scheduled", "Value #C": "next run in"},
        "indexByName": {"namespace": 0, "cronjob": 1, "Value #A": 2, "Value #B": 3, "Value #C": 4}}},
]
advance(9)

# ============================================================== Suricata EVE
row("Suricata EVE")
stat("EVE events in", 0, 4, f'sum(rate(vector_component_received_events_total{{{NS},component_id="eve_in"}}[5m]))', "ops",
     "Lines eve-receiver gets from OPNsense's syslog-ng (REDACTED_IP:5514/tcp), before filtering. 0 means Suricata, "
     "the syslog-ng drop-in or the LoadBalancer is broken.", thresholds("red", (0.001, "green")), 2)
stat("Kept for ClickHouse", 4, 4, f'sum(rate(vector_component_sent_events_total{{{NS},component_id="kafka"}}[5m]))', "ops",
     "tls/http/alert events produced to Kafka topic 'eve' after de-duplication.", thresholds("red", (0.001, "green")), 2)
stat("Receiver errors (1h)", 8, 4, f"sum(increase(vector_component_errors_total{{{NS},pod=~\"eve-receiver-.*\"}}[1h])) or vector(0)",
     "short", "Unparseable lines, Kafka send failures.", thresholds("green", (1, "orange"), (100, "red")), 0)
stat("EVE consumer lag", 12, 4, f"sum(kafka_consumergroup_lag{{{EVE_GROUP}}})", "short",
     "Events in topic 'eve' not yet read by ClickHouse (group 'clickhouse-eve').",
     thresholds("green", (2000, "orange"), (20000, "red")), 0)
panel("Since last TLS event", "stat", 16, 4, 4, [{
    "datasource": CH, "editorType": "sql", "format": 1, "queryType": "table",
    "rawSql": "SELECT dateDiff('second', max(ts), now()) AS age FROM netflow.eve_tls WHERE ts > now() - INTERVAL 1 DAY"}],
    "Age of the newest row in eve_tls (from ClickHouse). Minutes at most while anyone is browsing.", "s", STAT,
    {"thresholds": thresholds("green", (900, "orange"), (3600, "red")), "color": {"mode": "thresholds"}, "decimals": 0},
    ds=CH)
panel("Certain names (1h)", "stat", 20, 4, 4, [{
    "datasource": CH, "editorType": "sql", "format": 1, "queryType": "table",
    "rawSql": "SELECT countIf(source != 'dns') / count() AS share FROM netflow.conn_domains WHERE started > now() - INTERVAL 1 HOUR"}],
    "Share of named connections in the last hour whose name Suricata saw on the wire (TLS SNI / HTTP Host) rather "
    "than guessed from DNS. Bounded by the VLANs Suricata listens on.",
    "percentunit", STAT, {"thresholds": thresholds("orange", (0.5, "green")), "color": {"mode": "thresholds"}, "decimals": 1},
    ds=CH)
advance(4)
ts("EVE events", 0, 12, 7, [
    prom(f'sum(rate(vector_component_received_events_total{{{NS},component_id="eve_in"}}[$__rate_interval]))', "received"),
    prom(f'sum(rate(vector_component_sent_events_total{{{NS},component_id="kafka"}}[$__rate_interval]))', "to Kafka"),
    prom(f"sum(rate(kafka_server_brokertopicmetrics_messagesin_total{{topic=\"eve\"}}[$__rate_interval]))", "Kafka messages in"),
], "ops", "Received includes event types that are dropped (anomaly, drop, ssh); 'to Kafka' is what ClickHouse gets.",
    fill=0)
panel("Names by source (conn_domains)", "timeseries", 12, 12, 7, [{
    "datasource": CH, "editorType": "sql", "format": 0, "queryType": "timeseries",
    "rawSql": """SELECT $__timeInterval(started) AS time, source, count() AS connections
FROM netflow.conn_domains WHERE $__timeFilter(started) GROUP BY time, source ORDER BY time"""}],
    "Connections named per interval: sni/http = seen on the wire by Suricata, dns = dns-tail's ASOF guess (only for "
    "connections Suricata didn't name).", "short", TS_LEGEND,
    {"custom": {"drawStyle": "bars", "fillOpacity": 60, "lineWidth": 1, "showPoints": "never",
                "stacking": {"mode": "normal", "group": "A"}}, "color": {"mode": "palette-classic"}}, ds=CH)
advance(7)

dash = {
    "apiVersion": "dashboard.grafana.app/v1beta1",
    "kind": "Dashboard",
    "metadata": {"name": "netflow-pipeline"},
    "spec": {
        "title": "NetFlow Pipeline",
        "description": "Health of the netflow namespace: goflow2 -> Kafka -> ClickHouse, the enrichers and Suricata EVE. "
                       "Source: kubernetes/overlays/infrastructure/infra/applications/netflow/dashboard/gen_health.py",
        "tags": ["gcx", "netflow", "kafka", "clickhouse"],
        "timezone": "browser", "schemaVersion": 42, "refresh": "1m", "editable": True,
        "time": {"from": "now-6h", "to": "now"},
        "links": [{"title": "Home Network Traffic", "type": "link", "url": "/d/opnsense-netflow", "icon": "dashboard"}],
        "templating": {"list": []},
        "panels": panels,
    },
}
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netflow-pipeline.json")
json.dump(dash, open(out, "w"), indent=2)
print(out)
