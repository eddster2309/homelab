-- Wi-Fi history from Omada, recorded by netflowui (app/omada/wifi_record.py): the
-- controller only knows the present, so each client's signal and each AP radio's
-- channel utilisation are sampled about once a minute. The "Wi-Fi experience" panel
-- on a host overlays them on its flows_lan_5m throughput.
-- netflowui's intel writer user holds INSERT on both tables (chi.yaml).
-- Unknown numbers are stored as 0 (no Wi-Fi reading is ever 0 dBm / 0 dB SNR).

-- One row per wireless client per sample. mac is 'aa:bb:cc:dd:ee:ff'.
CREATE TABLE IF NOT EXISTS netflow.wifi_client_samples
(
    ts DateTime('UTC') CODEC(Delta, ZSTD(1)),
    mac LowCardinality(String) CODEC(ZSTD(1)),     -- ~100
    ip LowCardinality(String) CODEC(ZSTD(1)),
    ap LowCardinality(String) CODEC(ZSTD(1)),      -- AP name as on the controller
    band LowCardinality(String) CODEC(ZSTD(1)),
    channel UInt16 CODEC(T64, ZSTD(1)),
    rssi Int16 CODEC(T64, ZSTD(1)),                -- dBm
    snr Int16 CODEC(T64, ZSTD(1)),                 -- dB
    rx_kbps UInt32 CODEC(T64, ZSTD(1)),            -- negotiated uplink rate
    tx_kbps UInt32 CODEC(T64, ZSTD(1))             -- negotiated downlink rate
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (mac, ts)
TTL ts + INTERVAL 90 DAY;

-- One row per AP radio per sample: how busy the channel is (%), this AP's own
-- traffic plus everything else it hears.
CREATE TABLE IF NOT EXISTS netflow.wifi_radio_samples
(
    ts DateTime('UTC') CODEC(Delta, ZSTD(1)),
    ap LowCardinality(String) CODEC(ZSTD(1)),      -- ~10
    band LowCardinality(String) CODEC(ZSTD(1)),
    channel UInt16 CODEC(T64, ZSTD(1)),
    util_pct UInt8 CODEC(T64, ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (ap, band, ts)
TTL ts + INTERVAL 90 DAY;
