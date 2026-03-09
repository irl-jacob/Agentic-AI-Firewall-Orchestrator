-- Create active_configs table for tracking applied presets
CREATE TABLE IF NOT EXISTS active_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    preset_name TEXT NOT NULL,
    preset_version TEXT NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    applied_by TEXT DEFAULT 'system',
    snapshot_id INTEGER,
    rule_ids TEXT DEFAULT '[]',
    FOREIGN KEY (snapshot_id) REFERENCES rule_snapshots(id)
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_active_configs_applied_at ON active_configs(applied_at DESC);
