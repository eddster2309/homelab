-- MaxMind GeoLite2 CSVs written by the geoipupdate CronJob onto the geoip-db
-- PVC (mounted at user_files/geoip). Columns are declared in CSV file order.
-- FILE sources only reload when the file's mtime changes.

CREATE DATABASE IF NOT EXISTS netflow;

CREATE OR REPLACE DICTIONARY netflow.geoip_city_blocks
(
    network String,
    geoname_id UInt32,
    registered_country_geoname_id UInt32,
    represented_country_geoname_id UInt32,
    is_anonymous_proxy UInt8,
    is_satellite_provider UInt8,
    postal_code String,
    latitude Float32,
    longitude Float32,
    accuracy_radius UInt32,
    is_anycast UInt8
)
PRIMARY KEY network
SOURCE(FILE(path '/var/lib/clickhouse/user_files/geoip/city-blocks.csv' format 'CSVWithNames'))
LAYOUT(IP_TRIE)
LIFETIME(MIN 3600 MAX 7200);

CREATE OR REPLACE DICTIONARY netflow.geoip_city_locations
(
    geoname_id UInt32,
    locale_code String,
    continent_code String,
    continent_name String,
    country_iso_code String,
    country_name String,
    subdivision_1_iso_code String,
    subdivision_1_name String,
    subdivision_2_iso_code String,
    subdivision_2_name String,
    city_name String,
    metro_code String,
    time_zone String,
    is_in_european_union UInt8
)
PRIMARY KEY geoname_id
SOURCE(FILE(path '/var/lib/clickhouse/user_files/geoip/city-locations.csv' format 'CSVWithNames'))
LAYOUT(HASHED)
LIFETIME(MIN 3600 MAX 7200);

CREATE OR REPLACE DICTIONARY netflow.geoip_asn
(
    network String,
    autonomous_system_number UInt32,
    autonomous_system_organization String
)
PRIMARY KEY network
SOURCE(FILE(path '/var/lib/clickhouse/user_files/geoip/asn-blocks.csv' format 'CSVWithNames'))
LAYOUT(IP_TRIE)
LIFETIME(MIN 3600 MAX 7200);
