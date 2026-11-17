-- TriageKit update service. Older deployments also have licence tables from before 0.14; they are no longer used.
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')), licence_id TEXT, device_id TEXT, kind TEXT NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS releases (version TEXT PRIMARY KEY, channel TEXT NOT NULL DEFAULT 'beta', url TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER, notes TEXT, published TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')), manifest TEXT, signature TEXT);
