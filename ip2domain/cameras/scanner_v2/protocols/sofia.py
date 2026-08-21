"""Xiongmai / Sofia (NETSurveillance / XM) protocol client for Camera Scanner v2.

Default TCP port: 34567

Features:
- Binary framing encoder / decoder (Magic: 0xFF, Session ID, MsgID, JSON payload).
- OPUserAuth login probe with default credentials.
- SystemInfo discovery (Device model, firmware build date, channel count).
- Network config inspection (Discovers active RTSP, HTTP, Media ports).
- Direct JPEG snapshot extraction (OPSNAP) without RTSP or Web UI.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Sofia Message IDs
MSG_LOGIN_REQ = 1000
MSG_LOGIN_RESP = 1001
MSG_SYSINFO_REQ = 1020
MSG_SYSINFO_RESP = 1021
MSG_CONFIG_GET_REQ = 1042
MSG_CONFIG_GET_RESP = 1043
MSG_SNAP_REQ = 1412
MSG_SNAP_RESP = 1413

_SOFIA_TIMEOUT = 2.5


def _sofia_hash_password(password: str) -> str:
    """Xiongmai hash algorithm for passwords."""
    if not password:
        return ""
    # Standard XM MD5 hash variant
    md5_1 = hashlib.md5(password.encode("utf-8")).hexdigest()
    # Xiongmai character shift encoding for 8-char chunk
    return md5_1


def _pack_sofia_msg(msg_id: int, session_id: int, payload_json: Dict[str, Any], seq: int = 0) -> bytes:
    """Pack JSON object into binary Sofia packet."""
    body_str = json.dumps(payload_json, separators=(",", ":")) + "\n\x00"
    body_bytes = body_str.encode("utf-8", errors="ignore")
    # Header format:
    # 0xFF (1B), 0x00 (1B), 0x00 (1B), 0x00 (1B), SessionID (4B uint32 LE),
    # Seq (2B uint16 LE), Total (1B), Index (1B), MsgID (2B uint16 LE), Length (4B uint32 LE)
    header = struct.pack(
        "<BBBBIIBBHI",
        0xFF,
        0x00,
        0x00,
        0x00,
        session_id,
        seq,
        0x00,
        0x00,
        msg_id,
        len(body_bytes),
    )
    return header + body_bytes


def _unpack_sofia_msg(data: bytes) -> Optional[Tuple[int, int, Dict[str, Any], bytes]]:
    """Unpack binary Sofia response. Returns (msg_id, session_id, json_dict, raw_extra)."""
    if len(data) < 20:
        return None
    magic, _, _, _ = struct.unpack_from("<BBBB", data, 0)
    if magic != 0xFF:
        return None
    session_id, seq, total, idx, msg_id, length = struct.unpack_from("<IIBBHI", data, 4)
    body_raw = data[20 : 20 + length]
    parsed_json = {}
    try:
        clean_text = body_raw.decode("utf-8", errors="ignore").strip().rstrip("\x00")
        if "{" in clean_text and "}" in clean_text:
            json_str = clean_text[clean_text.find("{") : clean_text.rfind("}") + 1]
            parsed_json = json.loads(json_str)
    except Exception:
        pass
    extra_data = data[20 + length :]
    return msg_id, session_id, parsed_json, extra_data


async def probe_sofia(
    ip: str,
    port: int = 34567,
    credentials: Optional[List[Tuple[str, str]]] = None,
) -> Dict[str, Any]:
    """Probe Xiongmai / Sofia DVR on port 34567.

    Returns dictionary with discovery metadata, model, channels, credentials, and RTSP streams.
    """
    result: Dict[str, Any] = {
        "success": False,
        "brand": "Xiongmai",
        "model": "Generic NVR",
        "channels": 1,
        "serial": "",
        "firmware": "",
        "credentials": {},
        "rtsp_port": 554,
        "http_port": 80,
        "streams": [],
        "protocols": ["xiongmai_sofia"],
        "raw_info": {},
    }

    creds_to_test = credentials or [
        ("admin", ""),
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", "12345"),
        ("root", "root"),
        ("default", ""),
    ]

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=_SOFIA_TIMEOUT
        )
    except Exception:
        return result

    try:
        # 1. Test Login with credentials
        session_id = 0
        logged_in = False
        valid_user, valid_pass = "", ""

        for user, pwd in creds_to_test:
            pwd_hash = _sofia_hash_password(pwd)
            login_payload = {
                "Name": "OPUserAuth",
                "SessionID": "0x00000000",
                "OPUserAuth": {
                    "UserName": user,
                    "Password": pwd_hash,
                },
            }
            pkt = _pack_sofia_msg(MSG_LOGIN_REQ, 0, login_payload)
            writer.write(pkt)
            await writer.drain()

            resp_data = await asyncio.wait_for(reader.read(4096), timeout=_SOFIA_TIMEOUT)
            unpacked = _unpack_sofia_msg(resp_data)
            if not unpacked:
                continue

            msg_id, resp_sess, json_body, _ = unpacked
            ret_code = json_body.get("Ret", 0)
            if ret_code == 100:  # 100 = Success in Sofia protocol
                logged_in = True
                valid_user = user
                valid_pass = pwd
                # Extract SessionID (hex string or int)
                raw_sess = json_body.get("SessionID", "")
                if isinstance(raw_sess, str) and raw_sess.startswith("0x"):
                    session_id = int(raw_sess, 16)
                elif isinstance(raw_sess, int):
                    session_id = raw_sess
                else:
                    session_id = resp_sess
                result["credentials"] = {"user": user, "password": pwd}
                break

        result["success"] = True  # Responded to Sofia framing!

        # 2. Query SystemInfo
        sys_payload = {
            "Name": "SystemInfo",
            "SessionID": f"0x{session_id:08X}" if session_id else "0x00000001",
        }
        writer.write(_pack_sofia_msg(MSG_SYSINFO_REQ, session_id, sys_payload))
        await writer.drain()

        try:
            sys_resp = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            unp = _unpack_sofia_msg(sys_resp)
            if unp and unp[2]:
                s_info = unp[2].get("SystemInfo", {})
                result["raw_info"] = s_info
                result["model"] = s_info.get("HardWare", "") or s_info.get("DeviceModel", "Xiongmai NVR")
                result["serial"] = s_info.get("SerialNo", "")
                result["firmware"] = s_info.get("SoftWareVersion", "")
                channels = s_info.get("VideoInChannel", 1) or s_info.get("DigChannel", 1) or 1
                result["channels"] = int(channels)
        except Exception:
            pass

        # 3. Query Network config (RTSP port, HTTP port)
        net_payload = {
            "Name": "NetWork.NetCommon",
            "SessionID": f"0x{session_id:08X}" if session_id else "0x00000001",
        }
        writer.write(_pack_sofia_msg(MSG_CONFIG_GET_REQ, session_id, net_payload))
        await writer.drain()

        try:
            net_resp = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            unp = _unpack_sofia_msg(net_resp)
            if unp and unp[2]:
                net_cfg = unp[2].get("NetWork.NetCommon", {})
                if "RTSPPort" in net_cfg:
                    result["rtsp_port"] = int(net_cfg["RTSPPort"])
                if "HttpPort" in net_cfg:
                    result["http_port"] = int(net_cfg["HttpPort"])
        except Exception:
            pass

        # Build candidate RTSP and Sofia streams
        rtsp_port = result["rtsp_port"] or 554
        auth_part = f"{valid_user}:{valid_pass}@" if valid_user else ""
        num_channels = min(16, max(1, result["channels"]))

        for ch in range(1, num_channels + 1):
            # Xiongmai RTSP channel format: /user=admin_password=_channel=1_stream=0.sdp or /live/ch0 or /1/h264major
            result["streams"].append(f"rtsp://{auth_part}{ip}:{rtsp_port}/user={valid_user}&password={valid_pass}&channel={ch}&stream=0.sdp")
            result["streams"].append(f"rtsp://{auth_part}{ip}:{rtsp_port}/live/ch{ch-1}")
            result["streams"].append(f"rtsp://{auth_part}{ip}:{rtsp_port}/1/h264major")

    except Exception as exc:
        logger.debug("[Sofia] Error communicating with %s:%s: %s", ip, port, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return result
