"""Base SQLite persistence connection, collation and table initialization."""
import sqlite3
import os
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = str(Path(__file__).resolve().parent.parent.parent.parent / "ip2domain.db")
DB_PATH = os.environ.get("IP2DOMAIN_DB_PATH", _DEFAULT_DB_PATH)

class BaseStorage:
    """Base SQLite manager initializing database connection, collation and tables."""
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        def natural_key(value):
            return [int(part) if part.isdigit() else part.casefold()
                    for part in re.split(r"(\d+)", str(value or "").strip())]
        def natural_compare(left, right):
            left_key, right_key = natural_key(left), natural_key(right)
            return (left_key > right_key) - (left_key < right_key)
        conn.create_collation("NATURAL_NOCASE", natural_compare)
        conn.create_function("CASEFOLD_CONTAINS", 2, lambda value, query:
                             int(str(query or "").casefold() in str(value or "").casefold()))
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verify INTEGER DEFAULT 0,
                    nmap INTEGER DEFAULT 0,
                    total_ips INTEGER DEFAULT 0,
                    total_domains INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'completed',
                    results_json TEXT,
                    graph_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS http_analysis (
                    target TEXT PRIMARY KEY,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    analysis_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vuln_analysis (
                    target TEXT PRIMARY KEY,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    analysis_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS node_positions (
                    node_id TEXT PRIMARY KEY,
                    x REAL NOT NULL,
                    y REAL NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS active_jobs (
                    job_id     TEXT PRIMARY KEY,
                    job_type   TEXT NOT NULL DEFAULT 'scan',
                    target     TEXT,
                    status     TEXT NOT NULL DEFAULT 'queued',
                    progress_pct INTEGER DEFAULT 0,
                    stage      TEXT,
                    error      TEXT,
                    meta_json  TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hidden_nodes (
                    node_id   TEXT PRIMARY KEY,
                    hidden_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS camera_devices (
                    target TEXT PRIMARY KEY,
                    hostname TEXT,
                    score INTEGER DEFAULT 0,
                    confidence TEXT,
                    device_json TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS strix_results (
                    ip TEXT PRIMARY KEY,
                    session_id TEXT,
                    probe_json TEXT,
                    streams_json TEXT NOT NULL,
                    is_garbage INTEGER DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS strix_scan_jobs (
                    job_id         TEXT PRIMARY KEY,
                    status         TEXT NOT NULL DEFAULT 'running',
                    targets_json   TEXT NOT NULL,
                    total_targets  INTEGER DEFAULT 0,
                    current_index  INTEGER DEFAULT 0,
                    current_ip     TEXT DEFAULT '',
                    progress_pct   INTEGER DEFAULT 0,
                    stage          TEXT DEFAULT '',
                    params_json    TEXT DEFAULT '{}',
                    logs_json      TEXT DEFAULT '[]',
                    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS centra_cameras (
                    camera_id TEXT PRIMARY KEY,
                    title TEXT,
                    camera_json TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS centra_geocode_cache (
                    address TEXT PRIMARY KEY,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS centra_scan_checks (
                    camera_id TEXT PRIMARY KEY,
                    camera_type TEXT NOT NULL,
                    building_id INTEGER NOT NULL,
                    entrance INTEGER NOT NULL,
                    found INTEGER NOT NULL DEFAULT 0,
                    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS centra_person_results (
                    camera_id TEXT PRIMARY KEY,
                    camera_type TEXT NOT NULL,
                    people_count INTEGER NOT NULL,
                    confidence REAL,
                    result_json TEXT NOT NULL,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS centra_reid_identities (
                    person_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    last_seen REAL NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS camera_catalog (
                    camera_uid TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    title TEXT NOT NULL DEFAULT '',
                    address TEXT NOT NULL DEFAULT '',
                    camera_type TEXT NOT NULL DEFAULT '',
                    available INTEGER NOT NULL DEFAULT 1,
                    latitude REAL,
                    longitude REAL,
                    camera_json TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(provider_id, external_id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_camera_catalog_provider_status
                ON camera_catalog(provider_id, available, camera_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_camera_catalog_title
                ON camera_catalog(title COLLATE NOCASE)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS camera_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    camera_uid TEXT NOT NULL,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_kind TEXT NOT NULL,
                    storage_key TEXT,
                    content_type TEXT,
                    byte_size INTEGER,
                    checksum TEXT,
                    status TEXT NOT NULL,
                    error TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(camera_uid) REFERENCES camera_catalog(camera_uid)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS camera_analysis_results (
                    result_id TEXT PRIMARY KEY,
                    camera_uid TEXT NOT NULL,
                    snapshot_id TEXT,
                    analysis_type TEXT NOT NULL,
                    model_name TEXT,
                    result_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(camera_uid) REFERENCES camera_catalog(camera_uid),
                    FOREIGN KEY(snapshot_id) REFERENCES camera_snapshots(snapshot_id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_centra_person_type_time
                ON centra_person_results(camera_type, detected_at DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_centra_checks_range
                ON centra_scan_checks(camera_type, building_id, entrance)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS remote_desktop_services (
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol_type TEXT NOT NULL,
                    service_json TEXT NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (target, port, protocol_type)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS go2rtc_camera_meta (
                    stream_name  TEXT PRIMARY KEY,
                    custom_title TEXT DEFAULT '',
                    group_ip     TEXT DEFAULT '',
                    group_name   TEXT DEFAULT '',
                    tags_json    TEXT DEFAULT '[]',
                    notes        TEXT DEFAULT '',
                    is_favorite  INTEGER DEFAULT 0,
                    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS go2rtc_group_meta (
                    group_ip     TEXT PRIMARY KEY,
                    custom_name  TEXT DEFAULT '',
                    tags_json    TEXT DEFAULT '[]',
                    notes        TEXT DEFAULT '',
                    is_favorite  INTEGER DEFAULT 0,
                    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS strix_scanned_cidrs (
                    cidr         TEXT PRIMARY KEY,
                    asn          TEXT DEFAULT '',
                    total_ips    INTEGER DEFAULT 0,
                    cameras_found INTEGER DEFAULT 0,
                    scanned_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            try:
                conn.execute("ALTER TABLE strix_results ADD COLUMN is_garbage INTEGER DEFAULT 0")
            except Exception:
                pass
            conn.commit()

        # Init v2 scanner tables (via mixin if available)
        if hasattr(self, "_init_v2_tables"):
            self._init_v2_tables()

