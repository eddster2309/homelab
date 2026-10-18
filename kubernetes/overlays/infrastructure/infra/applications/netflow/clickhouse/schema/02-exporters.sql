-- Flow exporters (sensors), keyed on the address goflow2 reports as sampler_address.
-- Sorts before 03-flows.sql because flows_mv looks these dictionaries up.
--
-- host is the exporter's NetBox name: every address NetBox has for it (nb_hosts) counts
-- as the sensor's own, so its public addresses are local rather than internet
-- (src_local/dst_local on flows). No addresses are listed here; they follow NetBox.

CREATE TABLE IF NOT EXISTS netflow.exporters
(
    sampler_address String,
    name String,                      -- short name stored on flows.exporter, e.g. "opnsense", "edge01"
    host String,                      -- NetBox device/VM name (nb_hosts.name)
    role LowCardinality(String),      -- gateway: routes the LAN; edge: public front door (proxy)
    site LowCardinality(String),
    segment String                    -- src/dst_segment of the host's own public addresses
)
ENGINE = MergeTree ORDER BY sampler_address;
CREATE TABLE IF NOT EXISTS netflow.exporters_new AS netflow.exporters;

-- Replaced on every schema run, so this list is the source of truth.
-- edge01 exports over WireGuard, so it arrives from its tunnel address.
TRUNCATE TABLE netflow.exporters_new;
INSERT INTO netflow.exporters_new (sampler_address, name, host, role, site, segment) VALUES
    ('REDACTED_IP', 'opnsense', 'jack-cbr-fw01', 'gateway', 'jack-cbr', 'wan'),
    ('REDACTED_IP', 'edge01', 'edge01.internal', 'edge', 'binarylane', 'edge');
EXCHANGE TABLES netflow.exporters AND netflow.exporters_new;

CREATE OR REPLACE DICTIONARY netflow.exporter_dict
(
    sampler_address String,
    name String,
    host String,
    role String,
    site String,
    segment String
)
PRIMARY KEY sampler_address
SOURCE(CLICKHOUSE(DB 'netflow' TABLE 'exporters'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);

-- Each exporter's own addresses, from NetBox.
CREATE OR REPLACE DICTIONARY netflow.exporter_addr_dict
(
    ip String,
    exporter String,
    segment String
)
PRIMARY KEY ip
SOURCE(CLICKHOUSE(QUERY '
    SELECT h.ip AS ip, any(e.name) AS exporter, any(e.segment) AS segment
    FROM netflow.nb_hosts AS h
    INNER JOIN netflow.exporters AS e ON h.name = e.host
    GROUP BY h.ip'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 120);
