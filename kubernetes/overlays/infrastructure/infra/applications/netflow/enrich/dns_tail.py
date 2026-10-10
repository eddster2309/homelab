"""dns-tail: Blocky's query log (in Loki) -> netflow.dns_answers, plus two follow-ups.

Every POLL seconds: pull new "query resolved ... answer=..." lines from Loki and
store one row per A record: (time, client, answer IP, name asked for).

Every MAINT seconds:
  - assign: each new connection (client, port, server, port, proto) gets ONE name:
    the client's lookup of that server IP at or just before the connection
    started (ASOF match), stored in conn_domains. The MV's own label is only
    provisional (the client's *latest* name for the IP), which is wrong for shared
    IPs such as CDNs or the Traefik VIP when the device looks up another name on
    the same IP mid-stream.
  - fixup: flows of the last FIXUP_WINDOW get their connection's name (and
    flows that beat their DNS answer get one at all).
  - rollup: 5-minute buckets older than SETTLE are aggregated into
    flows_domain_5m once, after assign + fixup have had their chance.

Prometheus metrics on :METRICS_PORT (scraped by the netflow VMPodScrape).
"""
from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests
from prometheus_client import Counter, Gauge, start_http_server

from chclient import ClickHouse

log = logging.getLogger("dns-tail")

LOKI = os.environ.get("LOKI_URL", "http://loki-gateway.monitoring.svc").rstrip("/")
TENANT = os.environ.get("LOKI_TENANT", "homelab")
QUERY = os.environ.get("LOKI_QUERY", '{unit="blocky.service"} |= "query resolved" |= "answer="')
POLL = int(os.environ.get("POLL_SECONDS", "30"))
MAINT = int(os.environ.get("MAINT_SECONDS", "120"))
ASSIGN_OVERLAP = int(os.environ.get("ASSIGN_OVERLAP_MINUTES", "15"))   # re-scan window for late flows
SKEW = int(os.environ.get("DNS_SKEW_SECONDS", "5"))       # Blocky log vs NetFlow clock/ordering slack
LAG = timedelta(seconds=int(os.environ.get("LOKI_LAG_SECONDS", "15")))     # let late log lines land
BACKFILL = timedelta(hours=float(os.environ.get("BACKFILL_HOURS", "24")))  # first start only
FIXUP_WINDOW = int(os.environ.get("FIXUP_MINUTES", "30"))
SETTLE = int(os.environ.get("SETTLE_MINUTES", "10"))
PAGE = 5000
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9090"))

STORED = Counter("dns_tail_answers_stored", "A records stored in netflow.dns_answers")
ERRORS = Counter("dns_tail_errors", "Failed steps", ["step"])
LAST_OK = Gauge("dns_tail_last_success_timestamp_seconds", "Last time each step succeeded", ["step"])
CURSOR = Gauge("dns_tail_cursor_timestamp_seconds", "Loki position: log lines before this are stored")
ROLLED = Gauge("dns_tail_rollup_timestamp_seconds", "flows_domain_5m is complete up to here")
for _step in ("poll", "assign", "fixup", "rollup"):
    ERRORS.labels(_step)

LINE = re.compile(r"\banswer=(?P<answer>.*?) client_ip=(?P<client>\S+) .*?\bquestion_name=(?P<q>\S+)")
A_REC = re.compile(r"\bA \((\d{1,3}(?:\.\d{1,3}){3})\)")
NULL_ANSWERS = {"REDACTED_IP"}       # Blocky's answer for blocked names: nothing is ever sent there

# Same precedence as the flows MV: the connection's assigned name, else the client's
# latest name for the IP, else anyone's. A (domain, names) tuple.
CONN_FWD = "(src_addr, src_port, dst_addr, dst_port, toString(proto))"
CONN_REV = "(dst_addr, dst_port, src_addr, src_port, toString(proto))"
DOMAIN_T = f"""multiIf(
    dictHas('netflow.conn_domain_dict', {CONN_FWD}), dictGet('netflow.conn_domain_dict', ('domain', 'names'), {CONN_FWD}),
    dictHas('netflow.conn_domain_dict', {CONN_REV}), dictGet('netflow.conn_domain_dict', ('domain', 'names'), {CONN_REV}),
    dictHas('netflow.dns_pair_dict', (src_addr, dst_addr)), dictGet('netflow.dns_pair_dict', ('domain', 'names'), (src_addr, dst_addr)),
    dictHas('netflow.dns_pair_dict', (dst_addr, src_addr)), dictGet('netflow.dns_pair_dict', ('domain', 'names'), (dst_addr, src_addr)),
    dst_country != '' AND dictHas('netflow.dns_ip_dict', tuple(dst_addr)), dictGet('netflow.dns_ip_dict', ('domain', 'names'), tuple(dst_addr)),
    src_country != '' AND dictHas('netflow.dns_ip_dict', tuple(src_addr)), dictGet('netflow.dns_ip_dict', ('domain', 'names'), tuple(src_addr)),
    tuple('', toUInt16(0)))"""

# New connections in [start, end): orient each flow so the side that did the DNS
# lookup is the client, take the connection's earliest record as its start, and
# pick the client's last lookup of the server IP at or before that (+SKEW).
# Connections Suricata already named from TLS SNI / HTTP Host (05-eve.sql) are skipped by
# the NOT IN below, and conn_domain_dict prefers those names over a later DNS guess anyway.
ASSIGN_SQL = """
INSERT INTO netflow.conn_domains (client, client_port, server, server_port, proto, started, domain, names)
WITH pairs AS (SELECT DISTINCT client, ip FROM netflow.dns_answers WHERE ts > {start} - INTERVAL 1 DAY AND ts < {end})
SELECT c.client, c.client_port, c.server, c.server_port, c.proto, c.started, d.domain, n.names
FROM (
    SELECT if(fwd, src_addr, dst_addr) AS client, if(fwd, src_port, dst_port) AS client_port,
           if(fwd, dst_addr, src_addr) AS server, if(fwd, dst_port, src_port) AS server_port,
           toString(proto) AS proto, toDateTime64(min(time_flow_start), 3, 'UTC') AS started
    FROM (SELECT *, (src_addr, dst_addr) IN pairs AS fwd, (dst_addr, src_addr) IN pairs AS rev
          FROM netflow.flows WHERE time_received >= {start} AND time_received < {end})
    WHERE fwd OR rev
    GROUP BY client, client_port, server, server_port, proto
) AS c
ASOF LEFT JOIN (
    SELECT client, ip, domain, ts - INTERVAL {skew} SECOND AS ts
    FROM netflow.dns_answers WHERE ts > {start} - INTERVAL 1 DAY AND ts < {end}
) AS d ON c.client = d.client AND c.server = d.ip AND c.started >= d.ts
LEFT JOIN (
    SELECT client, ip, toUInt16(uniqExact(domain)) AS names
    FROM netflow.dns_answers WHERE ts > {start} - INTERVAL 1 DAY AND ts < {end} GROUP BY client, ip
) AS n ON n.client = c.client AND n.ip = c.server
WHERE d.domain != ''
  AND (c.client, c.client_port, c.server, c.server_port, c.proto) NOT IN (
      SELECT client, client_port, server, server_port, proto FROM netflow.conn_domains
      WHERE started > {start} - INTERVAL 1 DAY)
"""

# INSERT ... SELECT matches by position: name the columns so table order doesn't matter.
ROLLUP_COLUMNS = ("ts, lan_ip, lan_host, lan_segment, domain, domain_names, remote_org, remote_country, remote_cloud, "
                  "threat, proto, tx_bytes, rx_bytes, flows")
ROLLUP_SELECT = """
SELECT toStartOfFiveMinutes(time_received) AS ts,
       if(remote_is_src, dst_addr, src_addr) AS lan_ip,
       if(remote_is_src, if(dst_host != '', dst_host, dst_addr), if(src_host != '', src_host, src_addr)) AS lan_host,
       if(remote_is_src, dst_segment, src_segment) AS lan_segment,
       domain,
       max(domain_names) AS domain_names,
       if(remote_is_src, src_as_org, dst_as_org) AS remote_org,
       if(remote_is_src, src_country, dst_country) AS remote_country,
       remote_cloud, threat, proto,
       sumIf(bytes, NOT remote_is_src) AS tx_bytes,
       sumIf(bytes, remote_is_src) AS rx_bytes,
       count() AS flows
FROM (SELECT *, dst_country = '' AND src_country != '' AS remote_is_src FROM netflow.flows
      WHERE time_received >= {start} AND time_received < {end} AND (src_country != '' OR dst_country != ''))
GROUP BY ts, lan_ip, lan_host, lan_segment, domain, remote_org, remote_country, remote_cloud, threat, proto"""


def parse(line: str) -> list[tuple[str, str, str]]:
    """-> [(client, ip, domain)] for each A record in a Blocky query-log line."""
    m = LINE.search(line)
    if not m:
        return []
    domain = m["q"].rstrip(".").lower()
    return [(m["client"], ip, domain) for ip in A_REC.findall(m["answer"]) if ip not in NULL_ANSWERS]


def _ns(dt: datetime) -> int:
    return int(dt.timestamp() * 1e9)


class Tailer:
    def __init__(self, ch: ClickHouse):
        self.ch = ch
        self.s = requests.Session()
        self.s.headers["X-Scope-OrgID"] = TENANT
        last = ch.scalar("SELECT toUnixTimestamp64Nano(max(ts)) FROM netflow.dns_answers WHERE ts > 0")
        self.cursor = int(last) + 1 if last not in ("", "0") else _ns(datetime.now(timezone.utc) - BACKFILL)
        CURSOR.set(self.cursor / 1e9)
        log.info("starting at %s", datetime.fromtimestamp(self.cursor / 1e9, timezone.utc).isoformat())

    def poll(self) -> int:
        """Fetch everything from the cursor up to now-LAG; returns rows stored."""
        end = _ns(datetime.now(timezone.utc) - LAG)
        stored = 0
        while self.cursor < end:
            r = self.s.get(f"{LOKI}/loki/api/v1/query_range", timeout=120, params={
                "query": QUERY, "start": self.cursor, "end": end, "limit": PAGE, "direction": "forward"})
            r.raise_for_status()
            entries = sorted((int(ts), line) for stream in r.json()["data"]["result"] for ts, line in stream["values"])
            rows = [{"ts": ts / 1e9, "client": c, "ip": ip, "domain": d}
                    for ts, line in entries for c, ip, d in parse(line)]
            self.ch.insert("netflow.dns_answers", rows)
            stored += len(rows)
            STORED.inc(len(rows))
            if len(entries) < PAGE:
                self.cursor = end
            else:
                # Full page: continue after the last timestamp. Lines sharing it at the page
                # boundary may be skipped; acceptable for a best-effort name lookup.
                self.cursor = entries[-1][0] + 1
            CURSOR.set(self.cursor / 1e9)
            if len(entries) < PAGE:
                break
        return stored

    def assign(self, start: str | None = None, end: str | None = None) -> None:
        """Name new connections. Default window: the last ASSIGN_OVERLAP minutes."""
        self.ch.q(ASSIGN_SQL.format(start=start or f"now() - INTERVAL {ASSIGN_OVERLAP} MINUTE",
                                    end=end or "now()", skew=SKEW))

    def fixup(self) -> None:
        """Relabel recent flows with their connection's name. Dictionaries reload every
        20-40 s, so connections assigned in this pass are applied on the next one."""
        now = datetime.now(timezone.utc)
        parts = sorted({(now - timedelta(minutes=FIXUP_WINDOW)).strftime("%Y%m%d"), now.strftime("%Y%m%d")})
        for part in parts:
            self.ch.q(f"""ALTER TABLE netflow.flows UPDATE domain = ({DOMAIN_T}).1, domain_names = ({DOMAIN_T}).2
                          IN PARTITION ID '{part}'
                          WHERE time_received > now() - INTERVAL {FIXUP_WINDOW} MINUTE
                            AND (domain, domain_names) != ({DOMAIN_T})""",
                      allow_nondeterministic_mutations=1, mutations_sync=1)

    def rollup(self) -> None:
        last = self.ch.scalar("SELECT toUnixTimestamp(max(ts)) FROM netflow.flows_domain_5m")
        settled = self.ch.scalar(f"SELECT toUnixTimestamp(toStartOfFiveMinutes(now() - INTERVAL {SETTLE} MINUTE))")
        if last in ("", "0"):
            # Empty table: roll up all history (make sure flows' domain/threat columns were
            # backfilled first if the table was just created)
            last_or_min = self.ch.scalar("SELECT toUnixTimestamp(toStartOfFiveMinutes(min(time_received))) FROM netflow.flows")
            start = int(last_or_min)
        else:
            start = int(last) + 300
        end = int(settled)
        if end <= start:
            ROLLED.set(start)
            return
        self.ch.q(f"INSERT INTO netflow.flows_domain_5m ({ROLLUP_COLUMNS}) " +
                  ROLLUP_SELECT.format(start=f"toDateTime({start})", end=f"toDateTime({end})"))
        ROLLED.set(end)
        log.info("rolled up %s .. %s", datetime.fromtimestamp(start, timezone.utc).strftime("%H:%M"),
                 datetime.fromtimestamp(end, timezone.utc).strftime("%H:%M"))


def step(name: str, fn):
    try:
        result = fn()
    except Exception:
        ERRORS.labels(name).inc()
        raise
    LAST_OK.labels(name).set_to_current_time()
    return result


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)-7s %(name)s %(message)s")
    start_http_server(METRICS_PORT)
    t = Tailer(ClickHouse())
    next_maint = 0.0
    while True:
        try:
            n = step("poll", t.poll)
            if n:
                log.info("stored %d answers", n)
            if time.monotonic() >= next_maint:
                step("assign", t.assign)
                step("fixup", t.fixup)
                step("rollup", t.rollup)
                next_maint = time.monotonic() + MAINT
        except Exception as e:  # keep tailing; the cursor only advances on success
            log.error("%s", e)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
