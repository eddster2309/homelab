-- NetBox inventory, exported every 5 minutes by netbox-sync (netbox namespace).
-- netbox-sync fills <table>_new then EXCHANGEs it in, so the dictionaries never
-- load a half-written table. Rows reflect NetBox as it is, manual edits included.

CREATE TABLE IF NOT EXISTS netflow.nb_hosts
(
    ip String,
    name String,
    kind LowCardinality(String),      -- client|vm|lxc|k8s-node|k8s-vip|hypervisor|firewall|external-service|dns-only|...
    role LowCardinality(String),
    vendor String,
    mac String,
    cluster LowCardinality(String),
    fqdn String,
    status LowCardinality(String),
    tags Array(String),
    last_seen Nullable(DateTime64(0, 'UTC')),
    connection String                 -- Omada: switch port / Wi-Fi SSID @ AP
)
ENGINE = MergeTree ORDER BY ip;
CREATE TABLE IF NOT EXISTS netflow.nb_hosts_new AS netflow.nb_hosts;
ALTER TABLE netflow.nb_hosts ADD COLUMN IF NOT EXISTS connection String;
ALTER TABLE netflow.nb_hosts_new ADD COLUMN IF NOT EXISTS connection String;

CREATE TABLE IF NOT EXISTS netflow.nb_prefixes
(
    prefix String,
    segment String,                   -- short name, e.g. "users", "kubernetes", "cctv"
    vlan_vid UInt16,
    vlan_name String,
    role LowCardinality(String),
    site LowCardinality(String),
    via String                        -- OPNsense interface it's routed over, e.g. "INTER_WG_TO_CBR (wg1)"; '' for a local VLAN
)
ENGINE = MergeTree ORDER BY prefix;
-- via (2026-10-03)
ALTER TABLE netflow.nb_prefixes ADD COLUMN IF NOT EXISTS via String;
CREATE TABLE IF NOT EXISTS netflow.nb_prefixes_new AS netflow.nb_prefixes;
ALTER TABLE netflow.nb_prefixes_new ADD COLUMN IF NOT EXISTS via String;

CREATE TABLE IF NOT EXISTS netflow.nb_services
(
    ip String,
    proto LowCardinality(String),     -- TCP|UDP, matching flows.proto
    port UInt16,
    name String,                      -- e.g. "traefik/traefik websecure", "frigate"
    description String
)
ENGINE = MergeTree ORDER BY (ip, proto, port);
CREATE TABLE IF NOT EXISTS netflow.nb_services_new AS netflow.nb_services;

CREATE OR REPLACE DICTIONARY netflow.nb_host_dict
(
    ip String,
    name String,
    kind String,
    vendor String,
    fqdn String,
    connection String
)
PRIMARY KEY ip
SOURCE(CLICKHOUSE(DB 'netflow' TABLE 'nb_hosts'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);

CREATE OR REPLACE DICTIONARY netflow.nb_prefix_dict
(
    prefix String,
    segment String,
    vlan_vid UInt16,
    via String
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(DB 'netflow' TABLE 'nb_prefixes'))
LAYOUT(IP_TRIE)
LIFETIME(MIN 60 MAX 120);

CREATE OR REPLACE DICTIONARY netflow.nb_service_dict
(
    ip String,
    proto String,
    port UInt16,
    name String
)
PRIMARY KEY ip, proto, port
SOURCE(CLICKHOUSE(DB 'netflow' TABLE 'nb_services'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);
