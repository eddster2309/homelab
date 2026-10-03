"""NetFlow (ClickHouse): services LAN hosts answer on, for hosts nothing else describes.

A server answers from one fixed port to many different client ports; a client
does the opposite. So per (LAN address, proto, source port) over the window: at
least MIN_CLIENT_PORTS distinct peer ports, and the port below every one of them.
Only routed (inter-VLAN) traffic reaches NetFlow, so same-VLAN-only services stay
invisible.

The 7-day scan is too heavy for every 5-minute run: it runs in the first run of
each hour (FLOWS_EVERY_RUN=true forces it). Other runs leave c.flow_services as
None, and the reconciler then leaves flow-derived services alone.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import requests

from model import Collected, FlowService

WINDOW_DAYS = int(os.environ.get("FLOWS_WINDOW_DAYS", "7"))
MIN_CLIENT_PORTS = int(os.environ.get("FLOWS_MIN_CLIENT_PORTS", "5"))

# l4, not proto: ClickHouse resolves SELECT aliases inside WHERE, so aliasing the
# lower-cased protocol as "proto" would make proto IN ('TCP', 'UDP') never match.
QUERY = """
SELECT src_addr AS ip, lower(proto) AS l4, src_port AS port, uniqExact(dst_addr) AS clients,
       dictGetOrDefault('netflow.port_names_dict', 'name', tuple(proto, src_port), '') AS name
FROM netflow.flows
WHERE time_received > now() - INTERVAL {days} DAY
  AND src_country = '' AND proto IN ('TCP', 'UDP') AND src_port > 0 AND src_port < 32768
  AND (isIPAddressInRange(src_addr, 'REDACTED_IP/8') OR isIPAddressInRange(src_addr, 'REDACTED_IP/12')
       OR isIPAddressInRange(src_addr, 'REDACTED_IP/16'))
GROUP BY ip, proto, l4, port
HAVING uniqExact(dst_port) >= {min_ports} AND port < min(dst_port)
FORMAT JSONEachRow
"""


def collect(c: Collected) -> None:
    if os.environ.get("FLOWS_EVERY_RUN", "").lower() not in ("1", "true", "yes") \
            and datetime.now(timezone.utc).minute >= 5:
        return
    url = os.environ.get("CLICKHOUSE_URL", "http://clickhouse-netflow.netflow.svc:8123")
    r = requests.post(url, params={"query": QUERY.format(days=WINDOW_DAYS, min_ports=MIN_CLIENT_PORTS)},
                      headers={"X-ClickHouse-User": os.environ.get("CLICKHOUSE_USER", "netbox_sync"),
                               "X-ClickHouse-Key": os.environ["CLICKHOUSE_PASSWORD"]}, timeout=120)
    if r.status_code != 200:
        raise RuntimeError(f"ClickHouse: {r.status_code} {r.text[:300]}")
    c.flow_services = [FlowService(ip=d["ip"], proto=d["l4"], port=int(d["port"]), name=d["name"],
                                   clients=int(d["clients"]))
                       for d in map(json.loads, r.text.splitlines()) if d]
