"""Conservative explainable classification, separate from service discovery."""

DEVICE_TYPES = {
    "video": ["camera", "nvr", "dvr", "vms", "media_server", "anpr", "road_camera"],
    "voice": ["pbx", "ip_phone", "audio_recorder", "ip_audio", "intercom", "ptt"],
    "access": ["access_controller", "doorphone", "gate_controller", "parking", "traffic_controller"],
    "industrial": ["plc", "scada", "bms", "robot", "fire_panel", "elevator"],
    "energy": ["ups", "meter", "inverter", "ev_charger"],
    "iot": ["sensor", "smart_home", "telematics", "drone_station"],
    "network": ["radio_bridge", "wifi_ap", "router", "switch", "firewall", "satellite_terminal"],
    "workplace": ["nas", "printer", "mfp", "3d_printer", "kvm", "thin_client"],
    "specialized": ["pos", "payment_terminal", "information_terminal", "hotel_system", "laboratory", "medical"],
}
# Only explicit product signatures, never just a port or general-purpose protocol.
RULES = (
    ("audio_recorder", ("sprecord",), 0.95),
    ("pbx", ("asterisk", "freeswitch"), 0.9),
    ("vms", ("zoneminder", "milestone", "flussonic"), 0.9),
    ("nas", ("synology diskstation", "qnap nas", "truenas"), 0.9),
    ("3d_printer", ("octoprint",), 0.9),
)


def classify(observation):
    from .classification_catalog import SIGNATURE_RULES
    from .enrichment.device_endpoints import synthesize_device_endpoints

    observations = []
    text_corpus = []

    for service in observation.services:
        attributes = service.get("attributes", {})
        text = " ".join(str(attributes.get(k, "")) for k in ("product", "server", "banner", "model", "vendor")).lower()
        if text:
            text_corpus.append(text)

        for kind, signatures, confidence in RULES:
            for signature in signatures:
                if signature in text:
                    item = {
                        "kind": kind, "confidence": confidence, "rule_version": "1",
                        "evidence": [f"{service.get('protocol', '')}:product:{signature}"],
                    }
                    if item not in observations:
                        observations.append(item)

    full_text = " ".join(text_corpus)
    open_ports = (observation.port,) if getattr(observation, "port", None) else ()

    for rule in SIGNATURE_RULES:
        for sig in rule.signatures:
            if sig in full_text:
                item = {
                    "kind": rule.device_type,
                    "category": rule.category,
                    "vendor": rule.vendor,
                    "model": rule.model,
                    "confidence": rule.confidence,
                    "rule_version": "2",
                    "evidence": [f"catalog:{rule.vendor}:{sig}"],
                }
                if item not in observations:
                    observations.append(item)
                break

    observation.classifications = observations
    observation.device_info = synthesize_device_endpoints(observation)
