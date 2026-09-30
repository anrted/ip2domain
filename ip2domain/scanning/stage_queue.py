"""Durable endpoint stages: atomic handoffs, bounded backlog and fenced commits."""
from __future__ import annotations

import json
import time
import uuid

from .endpoint_store import write_endpoint

STAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory_stage_work (
 scan_id TEXT NOT NULL, ordinal INTEGER NOT NULL, port_index INTEGER NOT NULL,
 stage TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
 token TEXT NOT NULL DEFAULT '', executor_token TEXT NOT NULL DEFAULT '',
 lease_until REAL NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
 document TEXT NOT NULL, counters TEXT NOT NULL DEFAULT '{}',
 PRIMARY KEY(scan_id, ordinal, port_index, stage)
);
CREATE INDEX IF NOT EXISTS inventory_stage_claim
 ON inventory_stage_work(scan_id, stage, state, lease_until);
"""


def executor_owns(db, identifier, executor_token):
    return db.execute(
        """SELECT 1 FROM inventory_executor e JOIN inventory_scans s ON s.id=e.scan_id
        WHERE e.slot=1 AND e.scan_id=? AND e.token=? AND e.lease_until>?
        AND s.status='running'""", (identifier, executor_token, time.time()),
    ).fetchone() is not None


def stage_owns(db, identifier, claim, executor_token):
    return executor_owns(db, identifier, executor_token) and db.execute(
        """SELECT 1 FROM inventory_stage_work WHERE scan_id=? AND ordinal=?
        AND port_index=? AND stage=? AND token=? AND executor_token=?
        AND state='leased' AND lease_until>?""",
        (identifier, claim["ordinal"], claim["port_index"], claim["stage"],
         claim["token"], executor_token, time.time()),
    ).fetchone() is not None


def enqueue(db, identifier, ordinal, port_index, stage, document):
    if stage not in ("identify", "protocol", "endpoint", "enrich"):
        raise ValueError("unknown endpoint stage")
    db.execute(
        """INSERT OR IGNORE INTO inventory_stage_work
        (scan_id,ordinal,port_index,stage,document,counters) VALUES(?,?,?,?,?,?)""",
        (identifier, ordinal, port_index, stage, json.dumps(document),
         json.dumps({"_attempt_start": len(document["attempts"])})),
    )


class StageQueueMixin:
    def commit_discovery(self, identifier, ordinal, token, executor_token,
                         port_index, document, counters, next_stage, capacity, retain=False):
        """Checkpoint + endpoint + queue item are one transaction, not dual writes."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not executor_owns(db, identifier, executor_token) or not self._owns(db, identifier, ordinal, token):
                return "lost"
            if next_stage:
                pending = db.execute(
                    "SELECT COUNT(*) FROM inventory_stage_work WHERE scan_id=? AND state!='done'",
                    (identifier,),
                ).fetchone()[0]
                if pending >= capacity:
                    return "full"
            from .graph_store import record_host
            record_host(db,identifier,document)
            if document["state"] == "open" or document["services"] or retain:
                document = write_endpoint(db, identifier, document)
            if next_stage:
                enqueue(db, identifier, ordinal, port_index, next_stage, document)
            db.execute(
                "INSERT OR REPLACE INTO inventory_progress VALUES(?,?,?,?)",
                (identifier, ordinal, port_index + 1, json.dumps(counters)),
            )
            return "committed"

    def claim_stage(self, identifier, stage, executor_token, lease_seconds=60):
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not executor_owns(db, identifier, executor_token):
                return None
            row = db.execute(
                """SELECT * FROM inventory_stage_work WHERE scan_id=? AND stage=?
                AND (state='queued' OR (state='leased' AND lease_until<=?))
                ORDER BY ordinal,port_index LIMIT 1""",
                (identifier, stage, now),
            ).fetchone()
            if row is None:
                return None
            claim = dict(row)
            claim["token"] = uuid.uuid4().hex
            claim["document"] = json.loads(claim["document"])
            claim["counters"] = json.loads(claim["counters"])
            db.execute(
                """UPDATE inventory_stage_work SET state='leased',token=?,executor_token=?,
                lease_until=?,attempts=attempts+1
                WHERE scan_id=? AND ordinal=? AND port_index=? AND stage=?""",
                (claim["token"], executor_token, now + lease_seconds, identifier,
                 claim["ordinal"], claim["port_index"], stage),
            )
            return claim

    def renew_stage(self, identifier, claim, executor_token, lease_seconds=60):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not stage_owns(db, identifier, claim, executor_token):
                return False
            db.execute(
                """UPDATE inventory_stage_work SET lease_until=?
                WHERE scan_id=? AND ordinal=? AND port_index=? AND stage=?""",
                (time.time() + lease_seconds, identifier, claim["ordinal"], claim["port_index"], claim["stage"]),
            )
            return True

    def release_stage(self, identifier, claim, executor_token):
        with self.connect() as db:
            db.execute(
                """UPDATE inventory_stage_work SET state='queued',lease_until=0
                WHERE scan_id=? AND ordinal=? AND port_index=? AND stage=?
                AND token=? AND executor_token=? AND state='leased'""",
                (identifier, claim["ordinal"], claim["port_index"], claim["stage"], claim["token"], executor_token),
            )

    def save_stage(self, identifier, claim, executor_token, document, *, counters=None,
                   complete=False, next_stage=None, retain=False):
        """Persist each partial success; completing transfers its queue slot atomically."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not stage_owns(db, identifier, claim, executor_token):
                return False
            from .graph_store import record_host
            record_host(db,identifier,document)
            if document["state"] == "open" or document["services"] or retain:
                document = write_endpoint(db, identifier, document)
            db.execute(
                """UPDATE inventory_stage_work SET document=?,counters=COALESCE(?,counters),state=?
                WHERE scan_id=? AND ordinal=? AND port_index=? AND stage=?""",
                (json.dumps(document), json.dumps(counters) if counters is not None else ("{}" if complete else None),
                 "done" if complete else "leased",
                 identifier, claim["ordinal"], claim["port_index"], claim["stage"]),
            )
            if complete and next_stage:
                enqueue(db, identifier, claim["ordinal"], claim["port_index"], next_stage, document)
            return True

    def complete_if_drained(self, identifier, executor_token):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not executor_owns(db, identifier, executor_token):
                return False
            scan = db.execute("SELECT cursor,total_blocks FROM inventory_scans WHERE id=?", (identifier,)).fetchone()
            if scan["cursor"] < scan["total_blocks"]:
                return False
            for table in ("inventory_work", "inventory_stage_work"):
                if db.execute(f"SELECT 1 FROM {table} WHERE scan_id=? AND state!='done' LIMIT 1", (identifier,)).fetchone():
                    return False
            db.execute("UPDATE inventory_scans SET status='finalizing',updated=? WHERE id=?", (time.time(), identifier))
            return True

    @staticmethod
    def stage_stats(db, identifier):
        result = {name: {"queued": 0, "leased": 0, "done": 0, "coverage": {}} for name in ("identify", "protocol", "endpoint", "enrich")}
        for row in db.execute(
            "SELECT stage,state,COUNT(*) AS total FROM inventory_stage_work WHERE scan_id=? GROUP BY stage,state",
            (identifier,),
        ):
            result[row["stage"]][row["state"]] = row["total"]
        for row in db.execute(
            "SELECT stage,counters FROM inventory_stage_work WHERE scan_id=? AND state='done'", (identifier,),
        ):
            counters = result[row["stage"]]["coverage"]
            for key, value in json.loads(row["counters"]).items():
                counters[key] = counters.get(key, 0) + value
        return result
