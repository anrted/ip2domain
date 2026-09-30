"""Repository extension for incremental progress and fenced executor ownership."""
import json
import time
import uuid

CHECKPOINT_SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory_progress (
 scan_id TEXT NOT NULL, ordinal INTEGER NOT NULL, next_port INTEGER NOT NULL,
 counters TEXT NOT NULL, PRIMARY KEY(scan_id,ordinal)
);
CREATE TABLE IF NOT EXISTS inventory_executor (
 slot INTEGER PRIMARY KEY CHECK(slot=1), scan_id TEXT NOT NULL,
 token TEXT NOT NULL, lease_until REAL NOT NULL
);
"""


class CheckpointMixin:
    def acquire_executor(self, identifier, seconds=60):
        token, now = uuid.uuid4().hex, time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            owner = db.execute("SELECT * FROM inventory_executor WHERE slot=1").fetchone()
            if owner is not None and owner["lease_until"] > now:
                return None
            db.execute(
                "INSERT OR REPLACE INTO inventory_executor VALUES(1,?,?,?)",
                (identifier, token, now + seconds),
            )
        return token

    def renew_executor(self, identifier, token, seconds=60):
        with self.connect() as db:
            return bool(db.execute(
                "UPDATE inventory_executor SET lease_until=? WHERE slot=1 AND scan_id=? AND token=? AND lease_until>?",
                (time.time() + seconds, identifier, token, time.time()),
            ).rowcount)

    def release_executor(self, identifier, token):
        with self.connect() as db:
            db.execute("DELETE FROM inventory_executor WHERE slot=1 AND scan_id=? AND token=?", (identifier, token))

    def executor_transition(self, identifier, token, status, error=""):
        """A stale process cannot pause/error a scan resumed by a newer owner."""
        with self.connect() as db:
            return bool(db.execute(
                """UPDATE inventory_scans SET status=?,error=?,updated=? WHERE id=?
                AND status IN ('running','finalizing') AND EXISTS (
                    SELECT 1 FROM inventory_executor
                    WHERE slot=1 AND scan_id=? AND token=? AND lease_until>?
                )""",
                (status, error, time.time(), identifier, identifier, token, time.time()),
            ).rowcount)

    def progress(self, identifier, ordinal):
        with self.connect() as db:
            row = db.execute(
                "SELECT next_port,counters FROM inventory_progress WHERE scan_id=? AND ordinal=?",
                (identifier, ordinal),
            ).fetchone()
            return (row["next_port"], json.loads(row["counters"])) if row else (0, {})

    def advance(self, identifier, ordinal, token, next_port, counters):
        """A completed endpoint is never rescanned after its progress is committed."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self._owns(db, identifier, ordinal, token):
                return False
            db.execute(
                "INSERT OR REPLACE INTO inventory_progress VALUES(?,?,?,?)",
                (identifier, ordinal, next_port, json.dumps(counters)),
            )
            return True

    def active_scan(self, excluding=None):
        with self.connect() as db:
            row = db.execute(
                "SELECT id FROM inventory_scans WHERE status IN ('running','queued') AND id!=? LIMIT 1",
                (excluding or "",),
            ).fetchone()
            return row["id"] if row else None

    def resume(self, identifier):
        """A live executor cannot be hijacked by a second API process or CLI."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM inventory_executor WHERE lease_until>?", (time.time(),)).fetchone():
                return False
            if db.execute(
                "SELECT 1 FROM inventory_scans WHERE status IN ('queued','running') AND id!=?", (identifier,),
            ).fetchone():
                return False
            return bool(db.execute(
                """UPDATE inventory_scans SET status='queued',error='',updated=?
                WHERE id=? AND status IN ('paused','error','running','queued')""",
                (time.time(), identifier),
            ).rowcount)
