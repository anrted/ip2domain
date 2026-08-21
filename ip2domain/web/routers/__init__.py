"""Web routers package."""
from ip2domain.web.routers.auth import router as auth_router
from ip2domain.web.routers.recon import router as recon_router
from ip2domain.web.routers.modules import router as modules_router
from ip2domain.web.routers.remote_desktop import router as remote_desktop_router
from ip2domain.web.routers.cameras import router as cameras_router
from ip2domain.web.routers.centra import router as centra_router
from ip2domain.web.routers.go2rtc import router as go2rtc_router
from ip2domain.web.routers.strix import router as strix_router
from ip2domain.web.routers.scanner_v2 import router as scanner_v2_router
from ip2domain.web.routers.city_ip import router as city_ip_router

__all__ = [
    "auth_router",
    "recon_router",
    "modules_router",
    "remote_desktop_router",
    "cameras_router",
    "centra_router",
    "go2rtc_router",
    "strix_router",
    "scanner_v2_router",
    "city_ip_router",
]
