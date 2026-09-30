"""Durable SQLite work queue with expiring leases and fenced result commits."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from .checkpoints import CheckpointMixin, CHECKPOINT_SCHEMA
from .stage_queue import StageQueueMixin, STAGE_SCHEMA
from .endpoint_store import write_endpoint
from .graph_store import GraphRepositoryMixin

SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory_scans (
 id TEXT PRIMARY KEY, config TEXT NOT NULL, status TEXT NOT NULL,
 total_blocks INTEGER NOT NULL, total_endpoints INTEGER NOT NULL,
 cursor INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL, updated REAL NOT NULL,
 error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS inventory_work (
 scan_id TEXT NOT NULL, ordinal INTEGER NOT NULL, state TEXT NOT NULL,
 token TEXT NOT NULL, lease_until REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 1,
 PRIMARY KEY(scan_id, ordinal)
);
CREATE TABLE IF NOT EXISTS inventory_endpoints (
 scan_id TEXT NOT NULL, network_id TEXT NOT NULL, ip TEXT NOT NULL,
 transport TEXT NOT NULL, port INTEGER NOT NULL, hostname TEXT NOT NULL,
 state TEXT NOT NULL, document TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
 PRIMARY KEY(scan_id, network_id, ip, transport, port, hostname)
);
CREATE TABLE IF NOT EXISTS inventory_coverage (
 scan_id TEXT NOT NULL, ordinal INTEGER NOT NULL, counters TEXT NOT NULL,
 PRIMARY KEY(scan_id, ordinal)
);
CREATE INDEX IF NOT EXISTS inventory_endpoint_filter
 ON inventory_endpoints(scan_id, state, ip);
CREATE INDEX IF NOT EXISTS inventory_work_claim
 ON inventory_work(scan_id, state, lease_until);
"""


class InventoryRepository(CheckpointMixin, StageQueueMixin, GraphRepositoryMixin):
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.executescript(SCHEMA)
            db.executescript(CHECKPOINT_SCHEMA)
            db.executescript(STAGE_SCHEMA)
        self.migrate_graph()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, config, plan, exclusive=False):
        identifier, now = uuid.uuid4().hex, time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if exclusive and db.execute(
                "SELECT 1 FROM inventory_scans WHERE status IN ('queued','running') LIMIT 1"
            ).fetchone():
                raise ValueError("Resume or cancel the existing unfinished scan first")
            db.execute(
                "INSERT INTO inventory_scans(id,config,status,total_blocks,total_endpoints,created,updated) VALUES(?,?,?,?,?,?,?)",
                (identifier, json.dumps(config.to_dict()), "queued", plan.total, plan.endpoint_count, now, now),
            )
            from .graph_store import put
            from .evidence import identity
            put(db,identifier,'targets','',dict(id=identity(identifier,'targets'),input=config.targets,exclusions=config.exclusions,network_id=config.network_id,site_id=config.site_id,target_group=config.target_group,tags=config.tags,comments=config.comments))
        return identifier

    def get(self, identifier):
        with self.connect() as db:
            row = db.execute("SELECT * FROM inventory_scans WHERE id=?", (identifier,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["config"] = json.loads(result["config"])
            counters = {}
            completed = 0
            for item in db.execute("SELECT counters FROM inventory_coverage WHERE scan_id=?", (identifier,)):
                completed += 1
                for key, value in json.loads(item[0]).items():
                    counters[key] = counters.get(key, 0) + value
            result["completed_blocks"] = completed
            result["coverage"] = counters
            partial = {}
            for item in db.execute("SELECT counters FROM inventory_progress WHERE scan_id=?", (identifier,)):
                for key, value in json.loads(item[0]).items():
                    partial[key] = partial.get(key, 0) + value
            result["in_progress_coverage"] = partial
            result["stages"] = self.stage_stats(db, identifier)
            result["stages"]["discover"] = {
                "done": completed, "total": result["total_blocks"],
                "coverage": dict(counters), "in_progress_coverage": partial,
            }
            # Count final states once: closed TCP at discovery, open TCP/all UDP
            # at identification. Enrichment does not add to tested port counts.
            for key, value in result["stages"]["identify"]["coverage"].items():
                if key != "processed":
                    counters[key] = counters.get(key, 0) + value
            return result

    def list(self, limit=100):
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT id,status,total_blocks,total_endpoints,created,updated,error FROM inventory_scans ORDER BY created DESC LIMIT ?", (limit,),
            )]

    def transition(self, identifier, status, allowed, error=""):
        with self.connect() as db:
            placeholders = ",".join("?" for _ in allowed)
            return bool(db.execute(
                f"UPDATE inventory_scans SET status=?,updated=?,error=? WHERE id=? AND status IN ({placeholders})",
                (status, time.time(), error, identifier, *allowed),
            ).rowcount)

    def claim(self, identifier, lease_seconds, *, finalize=None):
        """SQLite serializes claim/cursor allocation across processes."""
        now, token = time.time(), uuid.uuid4().hex
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            scan = db.execute("SELECT * FROM inventory_scans WHERE id=?", (identifier,)).fetchone()
            if scan is None or scan["status"] != "running":
                return None
            expired = db.execute(
                "SELECT ordinal FROM inventory_work WHERE scan_id=? AND state='leased' AND lease_until<? ORDER BY ordinal LIMIT 1",
                (identifier, now),
            ).fetchone()
            if expired:
                ordinal = expired["ordinal"]
                db.execute(
                    "UPDATE inventory_work SET token=?,lease_until=?,attempts=attempts+1 WHERE scan_id=? AND ordinal=?",
                    (token, now + lease_seconds, identifier, ordinal),
                )
            elif scan["cursor"] < scan["total_blocks"]:
                ordinal = scan["cursor"]
                db.execute("UPDATE inventory_scans SET cursor=cursor+1 WHERE id=?", (identifier,))
                db.execute(
                    "INSERT INTO inventory_work(scan_id,ordinal,state,token,lease_until) VALUES(?,?,'leased',?,?)",
                    (identifier, ordinal, token, now + lease_seconds),
                )
            else:
                pending = db.execute(
                    "SELECT 1 FROM inventory_work WHERE scan_id=? AND state!='done' LIMIT 1", (identifier,),
                ).fetchone()
                staged = json.loads(scan["config"]).get("execution_mode") == "staged"
                if not pending and (finalize if finalize is not None else not staged):
                    db.execute("UPDATE inventory_scans SET status='completed',updated=? WHERE id=?", (now, identifier))
                return None
            return ordinal, token

    def save_endpoint(self, identifier, ordinal, token, document):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self._owns(db, identifier, ordinal, token):
                return False
            write_endpoint(db, identifier, document)
            return True

    @staticmethod
    def _owns(db, identifier, ordinal, token):
        return db.execute(
            """SELECT 1 FROM inventory_work w JOIN inventory_scans s ON s.id=w.scan_id
            WHERE w.scan_id=? AND w.ordinal=? AND w.token=? AND w.state='leased'
            AND w.lease_until>? AND s.status='running'""",
            (identifier, ordinal, token, time.time()),
        ).fetchone() is not None

    def finish(self, identifier, ordinal, token, counters, *, executor_token=None):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self._owns(db, identifier, ordinal, token):
                return False
            if executor_token is not None:
                from .stage_queue import executor_owns
                if not executor_owns(db, identifier, executor_token):
                    return False
            db.execute("UPDATE inventory_work SET state='done' WHERE scan_id=? AND ordinal=?", (identifier, ordinal))
            db.execute(
                "INSERT OR REPLACE INTO inventory_coverage VALUES(?,?,?)",
                (identifier, ordinal, json.dumps(counters)),
            )
            db.execute("DELETE FROM inventory_progress WHERE scan_id=? AND ordinal=?", (identifier, ordinal))
            db.execute("UPDATE inventory_scans SET updated=? WHERE id=?", (time.time(), identifier))
            return True

    def release(self, identifier, ordinal, token):
        with self.connect() as db:
            db.execute(
                "UPDATE inventory_work SET lease_until=0 WHERE scan_id=? AND ordinal=? AND token=? AND state='leased'",
                (identifier, ordinal, token),
            )

    def renew(self, identifier, ordinal, token, lease_seconds, *, executor_token=None):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if executor_token is not None:
                from .stage_queue import executor_owns
                if not executor_owns(db, identifier, executor_token):
                    return False
            return bool(db.execute(
                """UPDATE inventory_work SET lease_until=?
                WHERE scan_id=? AND ordinal=? AND token=? AND state='leased'
                AND lease_until>? AND EXISTS(
                    SELECT 1 FROM inventory_scans WHERE id=? AND status='running')""",
                (time.time() + lease_seconds, identifier, ordinal, token, time.time(), identifier),
            ).rowcount)

    def status(self, identifier):
        with self.connect() as db:
            row = db.execute("SELECT status FROM inventory_scans WHERE id=?", (identifier,)).fetchone()
            return row[0] if row else None

    def endpoints(self, identifier, limit=100, offset=0, state=None, protocol=None, category=None):
        where, params = ["scan_id=?"], [identifier]
        if state:
            where.append("state=?")
            params.append(state)
        if protocol:
            where.append("EXISTS(SELECT 1 FROM json_each(inventory_endpoints.document,'$.services') s WHERE json_extract(s.value,'$.protocol')=?)")
            params.append(protocol)
        if category:
            where.append("json_extract(inventory_endpoints.document,'$.device_info.category')=?")
            params.append(category)
        with self.connect() as db:
            query = "SELECT document,first_seen,last_seen FROM inventory_endpoints WHERE " + " AND ".join(where)
            rows = db.execute(query + " ORDER BY ip,transport,port,hostname LIMIT ? OFFSET ?", (*params, limit, offset))
            return [dict(json.loads(row["document"]), first_seen=row["first_seen"], last_seen=row["last_seen"]) for row in rows]
