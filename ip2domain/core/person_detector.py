"""Lazy, CPU-only person detection for camera previews."""
from pathlib import Path
from threading import Lock
from typing import Optional

_session = None
_session_lock = Lock()


def available(model_path: Path) -> bool:
    if not model_path.is_file():
        return False
    try:
        import numpy  # noqa: F401
        import onnxruntime  # noqa: F401
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        return False


def _get_session(model_path: Path):
    global _session
    with _session_lock:
        if _session is None:
            import onnxruntime as ort
            options = ort.SessionOptions()
            options.intra_op_num_threads = 1
            options.inter_op_num_threads = 1
            _session = ort.InferenceSession(str(model_path), sess_options=options,
                                            providers=["CPUExecutionProvider"])
    return _session


def detect_people(image_path: Path, model_path: Path, confidence: float = 0.45,
                  iou_threshold: float = 0.45, count_confidence: float = 0.10) -> dict:
    """Return the number of people after class-specific non-maximum suppression."""
    import numpy as np
    from PIL import Image

    session = _get_session(model_path)
    image = Image.open(image_path).convert("RGB")
    width, height = image.size
    size = 640
    scale = min(size / width, size / height)
    resized = image.resize((max(1, int(width * scale)), max(1, int(height * scale))))
    canvas = Image.new("RGB", (size, size), (114, 114, 114))
    canvas.paste(resized, ((size - resized.width) // 2, (size - resized.height) // 2))
    tensor = np.asarray(canvas, dtype=np.float32).transpose(2, 0, 1)[None] / 255.0
    output = session.run(None, {session.get_inputs()[0].name: tensor})[0]
    predictions = output[0]
    scores = predictions[4]  # COCO class 0 (person).
    # Require one confident person to mark a camera positive, then use a more
    # sensitive threshold to count nearby/occluded people in the same scene.
    if float(np.max(scores)) < confidence:
        return {"count": 0, "confidence": None, "detections": []}
    selected = np.flatnonzero(scores >= min(confidence, count_confidence))
    if not selected.size:
        return {"count": 0, "confidence": None, "detections": []}

    boxes = predictions[:4, selected].T.astype(np.float32)
    person_scores = scores[selected].astype(np.float32)
    # YOLO emits centre-x, centre-y, width, height. Convert to corner boxes.
    corners = np.empty_like(boxes)
    corners[:, 0] = boxes[:, 0] - boxes[:, 2] / 2
    corners[:, 1] = boxes[:, 1] - boxes[:, 3] / 2
    corners[:, 2] = boxes[:, 0] + boxes[:, 2] / 2
    corners[:, 3] = boxes[:, 1] + boxes[:, 3] / 2

    order = person_scores.argsort()[::-1]
    keep = []
    while order.size:
        current = int(order[0])
        keep.append(current)
        if order.size == 1:
            break
        rest = order[1:]
        xx1 = np.maximum(corners[current, 0], corners[rest, 0])
        yy1 = np.maximum(corners[current, 1], corners[rest, 1])
        xx2 = np.minimum(corners[current, 2], corners[rest, 2])
        yy2 = np.minimum(corners[current, 3], corners[rest, 3])
        intersection = np.maximum(0, xx2 - xx1) * np.maximum(0, yy2 - yy1)
        current_area = max(0, corners[current, 2] - corners[current, 0]) * max(
            0, corners[current, 3] - corners[current, 1])
        rest_area = np.maximum(0, corners[rest, 2] - corners[rest, 0]) * np.maximum(
            0, corners[rest, 3] - corners[rest, 1])
        union = current_area + rest_area - intersection
        iou = np.divide(intersection, union, out=np.zeros_like(intersection), where=union > 0)
        order = rest[iou <= iou_threshold]
    offset_x = (size - resized.width) / 2
    offset_y = (size - resized.height) / 2
    detections = []
    for index in keep:
        x1, y1, x2, y2 = corners[index]
        detections.append({
            "confidence": float(person_scores[index]),
            "bbox": [
                max(0, min(width, (float(x1) - offset_x) / scale)),
                max(0, min(height, (float(y1) - offset_y) / scale)),
                max(0, min(width, (float(x2) - offset_x) / scale)),
                max(0, min(height, (float(y2) - offset_y) / scale)),
            ],
        })
    return {"count": len(detections), "confidence": float(person_scores[keep].max()),
            "detections": detections}


def detect_person(image_path: Path, model_path: Path, confidence: float = 0.45) -> Optional[float]:
    """Backward-compatible presence-only helper."""
    result = detect_people(image_path, model_path, confidence)
    return result["confidence"]
