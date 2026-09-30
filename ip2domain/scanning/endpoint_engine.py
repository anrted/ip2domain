"""Lazy, ranked endpoint generation from data and protocol-discovered resources."""
from .fingerprint_engine import profiles


def rtsp_candidates(vendor='', channels=16, product='', model='', firmware='', derived=()):
    seen=set()
    for path in derived:
        if path not in seen: seen.add(path); yield dict(path=path,source='protocol',confidence=.95)
    catalog=list(profiles())
    catalog.sort(key=lambda p:(p['vendor'].lower()!=vendor.lower(),not p['vendor'].startswith('generic')))
    if vendor:
        matched=[p for p in catalog if p['vendor'].lower()==vendor.lower()]
        if matched:catalog=matched+[p for p in catalog if p['vendor'].startswith('generic')]
    # Channel-major order gives main and sub coverage before moving to the next camera.
    for channel in range(1,channels+1):
        for p in catalog:
            if p.get('models') and model and model not in p['models']:continue
            for stream in p['stream_patterns']['indices']:
                for template in p['rtsp_patterns']:
                    for codec in ('h264','h265') if '{codec}' in template else ('h264',):
                        path=template.format(channel=channel,stream=stream,stream1=stream+1,quality='main' if stream==0 else 'sub',codec=codec)
                        if path in seen:continue
                        seen.add(path)
                        yield dict(path=path,source='vendor-profile:'+p['vendor'],confidence=.7 if p['vendor'].lower()==vendor.lower() else .2,
                                   **({'channel':str(channel)} if '{channel' in template else {}),profile='main' if stream==0 else 'sub')
