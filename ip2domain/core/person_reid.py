"""Short-lived anonymous appearance matching without face recognition."""

import os
import time
from pathlib import Path
from threading import Lock

import numpy as np
from PIL import Image


_lock = Lock()
_stateless_lock = Lock()
_gallery = {}
_next_id = 1


def _appearance_features(image: Image.Image, bbox) -> tuple:
    """Describe clothing colours in three body regions; deliberately skip the head."""
    x1, y1, x2, y2 = (int(round(value)) for value in bbox)
    if x2 - x1 < 8 or y2 - y1 < 16:
        return np.empty(0, dtype=np.float32), 0.0
    head_offset = int((y2 - y1) * 0.16)
    crop = image.crop((x1, min(y2, y1 + head_offset), x2, y2)).resize((32, 64))
    hsv = np.asarray(crop.convert("HSV"), dtype=np.uint8)
    colour_score = float(np.mean(hsv[..., 1])) / 255.0
    parts = []
    for region in np.array_split(hsv, 3, axis=0):
        for channel in range(3):
            hist, _ = np.histogram(region[..., channel], bins=16, range=(0, 256))
            parts.append(hist.astype(np.float32))
    vector = np.concatenate(parts)
    norm = float(np.linalg.norm(vector))
    return (vector / norm if norm else np.empty(0, dtype=np.float32), colour_score)


def _appearance_vector(image: Image.Image, bbox) -> np.ndarray:
    return _appearance_features(image, bbox)[0]


def _required_similarity(left_colour: float, right_colour: float) -> float:
    # IR/grayscale clothing has too little information for ordinary histogram
    # matching, so only an almost identical signature may reuse an ID.
    return 0.995 if min(left_colour, right_colour) < 0.08 else 0.985


def _purge(now: float, ttl: int) -> None:
    expired = [identity for identity, entry in _gallery.items()
               if now - entry["last_seen"] > ttl]
    for identity in expired:
        _gallery.pop(identity, None)


def assign_identities(image_path: Path, detections: list, camera_id: str,
                      threshold: float = 0.985) -> list:
    """Assign temporary IDs by cosine similarity of non-facial appearance vectors."""
    global _next_id
    ttl = max(300, min(86400, int(os.environ.get("IP2DOMAIN_CENTRA_REID_TTL", "7200"))))
    now = time.time()
    image = Image.open(image_path).convert("RGB")
    features = [_appearance_features(image, item["bbox"]) for item in detections]
    results, used = [], set()
    with _lock:
        _purge(now, ttl)
        for vector, colour_score in features:
            best_id, best_score = None, 0.0
            if vector.size:
                for identity, entry in _gallery.items():
                    if identity in used:
                        continue
                    if entry["vector"].shape != vector.shape:
                        continue
                    score = float(np.dot(vector, entry["vector"]))
                    required = max(threshold, _required_similarity(colour_score, entry.get("colour_score", 0.0)))
                    if score >= required and score > best_score:
                        best_id, best_score = identity, score
            matched = best_id is not None
            if not matched:
                best_id = f"person-{_next_id}"
                _next_id += 1
                best_score = 1.0
                observations = []
            else:
                observations = list(_gallery[best_id].get("observations", []))
                combined = _gallery[best_id]["vector"] * 0.7 + vector * 0.3
                combined_norm = float(np.linalg.norm(combined))
                vector = combined / combined_norm if combined_norm else vector
            observations.append({"camera_id": camera_id, "seen_at": now,
                                 "similarity": round(best_score, 3)})
            # Bound memory and avoid repeated entries for the same camera in a
            # single analysis period while retaining its latest timestamp.
            latest_by_camera = {item["camera_id"]: item for item in observations}
            observations = sorted(latest_by_camera.values(), key=lambda item: item["seen_at"])[-100:]
            _gallery[best_id] = {"vector": vector, "colour_score": colour_score,
                                 "last_seen": now, "camera_id": camera_id,
                                 "observations": observations}
            used.add(best_id)
            results.append({"person_id": best_id, "similarity": round(best_score, 3),
                            "matched": matched})
    return results


def reset_identities() -> None:
    global _next_id
    with _lock:
        _gallery.clear()
        _next_id = 1


def identity_count() -> int:
    with _lock:
        return len(_gallery)


def get_identity_observations(person_id: str) -> list:
    ttl = max(300, min(86400, int(os.environ.get("IP2DOMAIN_CENTRA_REID_TTL", "7200"))))
    now = time.time()
    with _lock:
        _purge(now, ttl)
        entry = _gallery.get(str(person_id or "").strip().lower())
        if not entry:
            return []
        return [dict(item) for item in entry.get("observations", [])
                if now - item["seen_at"] <= ttl]


def export_identity_states(person_ids=None) -> list:
    selected = set(person_ids or [])
    with _lock:
        states = []
        for person_id, entry in _gallery.items():
            if selected and person_id not in selected:
                continue
            states.append({
                "person_id": person_id,
                "vector": entry["vector"].tolist(),
                "colour_score": float(entry.get("colour_score", 0.0)),
                "last_seen": float(entry["last_seen"]),
                "camera_id": entry.get("camera_id", ""),
                "observations": list(entry.get("observations", [])),
            })
        return states


def restore_identity_states(states: list) -> int:
    global _next_id
    ttl = max(300, min(86400, int(os.environ.get("IP2DOMAIN_CENTRA_REID_TTL", "7200"))))
    now = time.time()
    restored = 0
    with _lock:
        for state in states:
            person_id = str(state.get("person_id") or "").lower()
            if not person_id.startswith("person-") or now - float(state.get("last_seen") or 0) > ttl:
                continue
            vector = np.asarray(state.get("vector") or [], dtype=np.float32)
            if not vector.size:
                continue
            _gallery[person_id] = {
                "vector": vector,
                "colour_score": float(state.get("colour_score") or 0),
                "last_seen": float(state["last_seen"]),
                "camera_id": state.get("camera_id", ""),
                "observations": list(state.get("observations") or []),
            }
            try:
                _next_id = max(_next_id, int(person_id.split("-", 1)[1]) + 1)
            except (ValueError, IndexError):
                pass
            restored += 1
    return restored


def assign_identities_stateless(image_path: Path, detections: list, camera_id: str,
                                states: list) -> tuple:
    """Match through a temporary gallery and release it before returning."""
    with _stateless_lock:
        reset_identities()
        restore_identity_states(states)
        identities = assign_identities(image_path, detections, camera_id)
        changed_ids = [item["person_id"] for item in identities]
        changed_states = export_identity_states(changed_ids)
        reset_identities()
        return identities, changed_states
