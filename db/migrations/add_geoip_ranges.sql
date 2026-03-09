-- GeoIP IP ranges table
CREATE TABLE IF NOT EXISTS geoip_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country_code TEXT NOT NULL,
    country_name TEXT,
    ip_range TEXT NOT NULL,
    ip_version INTEGER NOT NULL DEFAULT 4,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(country_code, ip_range)
);

CREATE INDEX IF NOT EXISTS idx_geoip_country ON geoip_ranges(country_code);
CREATE INDEX IF NOT EXISTS idx_geoip_version ON geoip_ranges(ip_version);
