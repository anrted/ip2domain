"""Transaction-local endpoint projection shared by all durable stages."""
import json
import time


def write_endpoint(db, identifier, document):
    key = (
        identifier, document["network_id"], document["ip"], document["transport"],
        document["port"], document["hostname"],
    )
    previous = db.execute(
        """SELECT document FROM inventory_endpoints WHERE scan_id=? AND network_id=?
        AND ip=? AND transport=? AND port=? AND hostname=?""", key,
    ).fetchone()
    from .evidence import sanitize_document
    document = sanitize_document(dict(document))
    if previous:
        previous = json.loads(previous["document"])
        # Partial retries must not erase already confirmed evidence. Attempts are
        # also retained, without duplicating identical diagnostics on every flush.
        for field in ("services", "classifications", "attempts", "evidence", "fingerprints", "endpoints", "streams", "channels", "authentication", "devices"):
            current = list(document.get(field, []))
            for item in previous.get(field, []):
                if item not in current:
                    current.append(item)
            document[field] = current
    now = time.time()
    db.execute(
        """INSERT INTO inventory_endpoints VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(scan_id,network_id,ip,transport,port,hostname)
        DO UPDATE SET state=excluded.state,document=excluded.document,last_seen=excluded.last_seen""",
        (*key, document["state"], json.dumps(document), now, now),
    )
    from .graph_store import project
    project(db, identifier, document)
    return document
