"""Bounded, redacted response evidence with stable identities and raw digests."""
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def identity(*parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:24]


def clean_uri(value):
    try:
        u = urlsplit(value)
        host = u.hostname or ''
        if ':' in host: host = '[' + host + ']'
        if u.port: host += ':' + str(u.port)
        query = urlencode([(k, '[redacted]' if re.search('pass|token|secret|auth|key|session', k, re.I) else v)
                           for k,v in parse_qsl(u.query, keep_blank_values=True)])
        return urlunsplit((u.scheme, host if u.netloc else '', u.path, query, ''))
    except ValueError:
        return '[invalid-uri]'


def redact(value):
    value = re.sub(r'(?i)(authorization|proxy-authorization|set-cookie|cookie):[^\r\n]*', r'\1: [redacted]', str(value))
    value = re.sub(r'(?i)(password|passwd|token|secret|sessionid|api[_-]?key)(["\s:=]+)[^\s<>;,"\r\n]+', r'\1\2[redacted]', value)
    value = re.sub(r'(?:https?|rtsps?)://[^\s<>"\']+', lambda m: clean_uri(m[0]), value)
    return value


def capture(observation, kind, raw=b'', *, source='', weight=1.0, **metadata):
    if isinstance(raw, str): raw = raw.encode()
    for secret in getattr(observation,'_secrets',()):
        raw=raw.replace(secret.encode(),b'[redacted]')
    digest = hashlib.sha256(raw).hexdigest()
    item = dict(id=identity(observation.ip, observation.port, kind, source, digest), type=kind,
                source=source, weight=weight, sha256=digest, length=len(raw),
                sample=redact(raw[:8192].decode('utf-8','replace')), truncated=len(raw)>8192,
                **metadata)
    if not any(e['id']==item['id'] for e in observation.evidence): observation.evidence.append(item)
    return item['id']


def sanitize_document(value):
    """Last boundary for legacy documents and server-controlled nested metadata."""
    if isinstance(value,dict):
        return {k:sanitize_document(v) for k,v in value.items() if k.lower() not in
                ('password','passwd','credentials','_rtsp_credentials','authorization','proxy-authorization','cookie','set-cookie','access_token','refresh_token','secret')}
    if isinstance(value,(list,tuple)):return [sanitize_document(v) for v in value]
    if isinstance(value,str):return redact(value)
    return value
