-- Requests Traefik served, from its JSON access log (Loki {namespace="traefik"}), which
-- dns-tail reads like edge01's HAProxy lines (09-edge.sql). One row per request.
--
-- dns-tail -> traefik_requests_queue (Null) -> traefik_requests_mv (pod, host and GeoIP
-- lookups) -> traefik_requests (02-traefik.sql, where its dictionaries are too).
-- Alloy drops metric/log ingest routed through Traefik on the way to Loki (traefik-patch.yaml),
-- but that is Alloy's own pushes, not Traefik's log of them: vmauth-ingest requests are in
-- Loki and so in here. A request no service handled (404, a cancelled one) has no service
-- or backend.

CREATE TABLE IF NOT EXISTS netflow.traefik_requests_queue
(
    ts DateTime64(3, 'UTC'),
    logged DateTime64(9, 'UTC'),
    client String,
    client_port UInt16,
    entrypoint String,
    host String,
    router String,
    svc_namespace String,
    svc_name String,
    backend_addr String,
    backend_port UInt16,
    status UInt16,
    req_bytes UInt64,
    resp_bytes UInt64,
    duration_ms Float32,
    protocol String,
    user_agent String,
    tls_version String,
    tls_cipher String,
    client_user String
)
ENGINE = Null;

-- Recreated on every run so query changes apply. A dns-tail insert while it's
-- missing is lost; the cursor has moved on by then, so keep this cheap to replace.
DROP VIEW IF EXISTS netflow.traefik_requests_mv;
CREATE MATERIALIZED VIEW netflow.traefik_requests_mv TO netflow.traefik_requests AS
WITH
    toIPv6OrDefault(client) AS c_ip,
    -- the registered country for blocks with no city, as in flows_mv
    dictGet('netflow.geoip_city_blocks', 'geoname_id', c_ip) AS c_gid_city,
    if(c_gid_city = 0, dictGet('netflow.geoip_city_blocks', 'registered_country_geoname_id', c_ip), c_gid_city) AS c_gid
SELECT ts, logged, client, client_port, entrypoint, host, router, svc_namespace, svc_name,
       backend_addr, backend_port, status, req_bytes, resp_bytes, duration_ms, protocol,
       user_agent, tls_version, tls_cipher, client_user,
       dictGetOrDefault('netflow.k8s_pod_dict', 'workload', tuple(backend_addr), '') AS backend_workload,
       dictGetOrDefault('netflow.k8s_pod_dict', 'pod', tuple(backend_addr), '') AS backend_pod,
       dictGetOrDefault('netflow.k8s_pod_dict', 'workload', tuple(client), '') AS client_workload,
       dictGetOrDefault('netflow.nb_host_dict', 'name', tuple(client), '') AS client_host,
       dictGet('netflow.geoip_city_locations', 'country_iso_code', c_gid) AS client_country
FROM netflow.traefik_requests_queue;
