-- Inbound flows through Traefik, labelled with the backend Kubernetes workload.
--
-- Every service is reached through Traefik's VIP (NetBox: k8s-vip, REDACTED_IP), so
-- OPNsense records `client:port -> VIP:443` and nothing about which service it was.
-- Traefik's access log has the same client:port for each request, plus the service and
-- the backend pod's address (dns-tail reads it from Loki, 10-traefik.sql). These
-- dictionaries turn that into labels for flows:
--   traefik_conn_dict       client:port of a connection to websecure (:443)
--   traefik_edge_conn_dict  edge01's tunnel leg to websecure-pub (:8443): Traefik logs
--                           the internet client (PROXY protocol), OPNsense sees edge01's
--                           proxy_addr:proxy_port, and edge_sessions (09-edge.sql) links the two
--   traefik_tcp_dict        TCP entrypoints with no access log, by the VIP's port
-- flows_mv (03-flows.sql) and dns-tail's fixup fill flows.k8s_workload/k8s_pod and set
-- k8s_via = 'traefik'. Sorts before 03-flows.sql because flows_mv looks these up, which
-- is also why traefik_requests is created here (10-traefik.sql adds the queue and MV).
-- traefik_edge_conn_dict reads edge_sessions, created in 09: only on a first install does
-- a flow insert between the two files fail to load it, and Kafka redelivers that batch.
--
-- The workload a request is attributed to is its backend pod's workload; for a backend
-- that isn't a pod (Proxmox, Frigate, ... via an external Service) it is the Service,
-- "<svc_namespace>/<svc_name>". A connection carries several requests, and HTTP/2 can
-- carry several hosts: the workload with the most bytes wins, `names` counts them.

-- 2026-10-18: rebuilt for size (18 MiB for 3 days, ~180 MiB at the 30-day TTL). Sorted by
-- (hour, host, ts) instead of ts alone: every UI query is a time range (ts >= .. AND ts < ..),
-- so the hour prefix keeps range pruning, and host groups the per-host strings, backend and
-- user-agent columns into runs. Modest-cardinality strings are LowCardinality (per day: host
-- ~20, backend_pod/backend_addr ~50, client_host ~10, user_agent ~2.2k). logged takes Delta
-- and resp_bytes T64 (sample: 1.6 vs 2.3 MiB and 0.22 vs 0.34 MiB against plain ZSTD(1)); on
-- duration_ms plain ZSTD(1) beat Gorilla, FPC and ZSTD(3), so it stays at the default level.
-- Column types are unchanged for the UI (logged DateTime64(9), duration_ms Float32).
-- The sort key needs a table rebuild (migrate-table.sh); on the live table CREATE IF NOT
-- EXISTS does nothing, and the ALTERs below only update codecs/types in place.
CREATE TABLE IF NOT EXISTS netflow.traefik_requests
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),   -- request start (StartUTC)
    logged DateTime64(9, 'UTC') CODEC(Delta, ZSTD(1)),  -- Loki line time: dns-tail's cursor
    client String CODEC(ZSTD(1)),     -- the real client; for websecure-pub, via PROXY protocol
    client_port UInt16,
    entrypoint LowCardinality(String),    -- websecure (:443) | websecure-pub (:8443, edge01)
    host LowCardinality(String),      -- RequestHost
    router LowCardinality(String),
    svc_namespace LowCardinality(String), -- the Kubernetes Service; '' for a request no service handled
    svc_name LowCardinality(String),
    backend_addr LowCardinality(String),  -- the pod (or external host) Traefik forwarded to
    backend_port UInt16,
    status UInt16,                    -- DownstreamStatus
    req_bytes UInt64 CODEC(T64, ZSTD(1)),
    resp_bytes UInt64 CODEC(T64, ZSTD(1)),
    duration_ms Float32 CODEC(ZSTD(1)),
    protocol LowCardinality(String),  -- HTTP/1.1, HTTP/2.0
    user_agent LowCardinality(String),    -- request_User-Agent (the only header the access log keeps)
    tls_version LowCardinality(String),
    tls_cipher LowCardinality(String),
    client_user LowCardinality(String),   -- ClientUsername from basic auth; '' if none
    backend_workload LowCardinality(String),  -- k8s_pod_dict: "<namespace>/<workload>"; '' if backend_addr isn't a pod
    backend_pod LowCardinality(String),
    client_workload LowCardinality(String),   -- the same for a client that is a pod (dns-tail skips pods now, so rarely set)
    client_host LowCardinality(String),   -- NetBox name of a LAN client
    client_country LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (toStartOfHour(ts), host, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY;
-- In place on the live (old-key) table, and a no-op in effect on the rebuilt one. The
-- LowCardinality changes are column rewrites; host is in the new sort key, so it can only
-- change type in the rebuild (the old key is ts alone, where the ALTER is allowed).
ALTER TABLE netflow.traefik_requests MODIFY COLUMN logged DateTime64(9, 'UTC') CODEC(Delta, ZSTD(1));
ALTER TABLE netflow.traefik_requests MODIFY COLUMN req_bytes UInt64 CODEC(T64, ZSTD(1));
ALTER TABLE netflow.traefik_requests MODIFY COLUMN resp_bytes UInt64 CODEC(T64, ZSTD(1));
ALTER TABLE netflow.traefik_requests MODIFY COLUMN duration_ms Float32 CODEC(ZSTD(1));
ALTER TABLE netflow.traefik_requests MODIFY COLUMN client String CODEC(ZSTD(1));
ALTER TABLE netflow.traefik_requests MODIFY COLUMN host LowCardinality(String);
ALTER TABLE netflow.traefik_requests MODIFY COLUMN backend_addr LowCardinality(String);
ALTER TABLE netflow.traefik_requests MODIFY COLUMN backend_pod LowCardinality(String);
ALTER TABLE netflow.traefik_requests MODIFY COLUMN client_host LowCardinality(String);
ALTER TABLE netflow.traefik_requests MODIFY COLUMN user_agent LowCardinality(String);

-- Per client connection: one row per workload it reached, with the bytes both ways.
-- The three dictionaries below share it; the doubled quotes are for the QUERY string.
-- (The inner aliases differ from the table's columns so the outer WHERE/GROUP BY can't
-- pick up an aggregate.)
-- LAN clients reuse source ports within hours, so this one only looks at requests logged
-- in the last 2 hours: by log time, not start time, so a websocket that closes now (and
-- is only logged now) still names its connection.
CREATE OR REPLACE DICTIONARY netflow.traefik_conn_dict
(
    client String,
    client_port UInt16,
    workload String,                  -- "<namespace>/<workload>" with the most bytes on the connection
    pod String,                       -- the backend pod it last reached; '' if the backend wasn't a pod
    names UInt16                      -- workloads the connection reached (HTTP/2 reuse): 1 = certain
)
PRIMARY KEY client, client_port
SOURCE(CLICKHOUSE(QUERY 'SELECT client, client_port, argMax(wl, b) AS workload, argMax(pd, b) AS pod, toUInt16(count()) AS names FROM (SELECT client, client_port, if(notEmpty(backend_workload), backend_workload, if(empty(svc_name), svc_name, concat(svc_namespace, ''/'', svc_name))) AS wl, argMax(backend_pod, ts) AS pd, sum(req_bytes + resp_bytes) AS b FROM netflow.traefik_requests WHERE logged > now() - INTERVAL 2 HOUR AND entrypoint = ''websecure'' GROUP BY client, client_port, wl HAVING notEmpty(wl)) GROUP BY client, client_port'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);

-- The same for edge01's tunnel leg, keyed as OPNsense records it.
CREATE OR REPLACE DICTIONARY netflow.traefik_edge_conn_dict
(
    proxy_addr String,
    proxy_port UInt16,
    workload String,
    pod String,
    names UInt16
)
PRIMARY KEY proxy_addr, proxy_port
SOURCE(CLICKHOUSE(QUERY 'SELECT s.proxy_addr AS proxy_addr, s.proxy_port AS proxy_port, argMax(r.wl, r.b) AS workload, argMax(r.pd, r.b) AS pod, toUInt16(uniqExact(r.wl)) AS names FROM (SELECT client, client_port, if(notEmpty(backend_workload), backend_workload, if(empty(svc_name), svc_name, concat(svc_namespace, ''/'', svc_name))) AS wl, argMax(backend_pod, ts) AS pd, sum(req_bytes + resp_bytes) AS b FROM netflow.traefik_requests WHERE ts > now() - INTERVAL 1 DAY AND entrypoint = ''websecure-pub'' GROUP BY client, client_port, wl HAVING notEmpty(wl)) AS r INNER JOIN (SELECT client, client_port, proxy_addr, proxy_port FROM netflow.edge_sessions WHERE ts > now() - INTERVAL 1 DAY) AS s ON r.client = s.client AND r.client_port = s.client_port GROUP BY s.proxy_addr, s.proxy_port'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);

-- TCP entrypoints (traefik-patch.yaml) have no access log, so the VIP's port decides.
-- Replaced on every schema run, so this list is the source of truth: one row per
-- IngressRouteTCP (`kubectl get ingressroutetcp -A`), its Service resolved to the
-- workload behind it. frigate-rtsp (:8554) has none yet (Frigate is still behind
-- ingress-nginx); add it here when it's migrated.
CREATE TABLE IF NOT EXISTS netflow.traefik_tcp_routes
(
    exposed_port UInt16,              -- the VIP's port
    workload String                   -- "<namespace>/<workload>"
)
ENGINE = MergeTree ORDER BY exposed_port;
CREATE TABLE IF NOT EXISTS netflow.traefik_tcp_routes_new AS netflow.traefik_tcp_routes;

TRUNCATE TABLE netflow.traefik_tcp_routes_new;
INSERT INTO netflow.traefik_tcp_routes_new (exposed_port, workload) VALUES
    (222, 'gitlab/gitlab-gitlab-shell');   -- entrypoint gitlab-shell -> Service gitlab-gitlab-shell
EXCHANGE TABLES netflow.traefik_tcp_routes AND netflow.traefik_tcp_routes_new;

CREATE OR REPLACE DICTIONARY netflow.traefik_tcp_dict
(
    exposed_port UInt16,
    workload String
)
PRIMARY KEY exposed_port
SOURCE(CLICKHOUSE(DB 'netflow' TABLE 'traefik_tcp_routes'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);
