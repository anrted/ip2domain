from .base import ProtocolPlugin
from ..detection.catalog import native_registry
class NativePlugin(ProtocolPlugin):
    name='native'
    @property
    def protocols(self):
        return tuple({p.name for p in native_registry().probes}-{'http','rtsp'})+('ssh','ftp','smtp','telnet','tls','Unknown')
