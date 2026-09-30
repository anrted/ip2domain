"""Explicit scoped credentials only. Secrets stay in memory, never in ScanConfig."""
from dataclasses import dataclass, field
import base64
import hashlib
import re
import secrets
from urllib.request import parse_http_list, parse_keqv_list

@dataclass(frozen=True)
class Credential:
    id: str
    host: str
    protocol: str
    username: str = field(repr=False)
    password: str = field(repr=False)

class CredentialVault:
    def __init__(self, entries=()):
        self.entries = []
        for i,e in enumerate(entries):
            if not isinstance(e,dict) or set(e)-{'id','host','protocol','username','password'}:
                raise ValueError('invalid credential fields')
            if not all(isinstance(e.get(k),str) for k in ('host','protocol','username','password')):
                raise ValueError('credential needs explicit host, protocol, username and password')
            import ipaddress
            ipaddress.ip_address(e['host'])
            if any(c in e['username']+e['password'] for c in '\r\n\x00'):
                raise ValueError('credential contains control characters')
            if any(c.host==e['host'] and c.protocol==e['protocol'] for c in self.entries):
                raise ValueError('one credential per host/protocol; password spraying is not supported')
            self.entries.append(Credential(e.get('id',f'credential-{i+1}'),e['host'],e['protocol'],e['username'],e['password']))
        if len(self.entries)>256: raise ValueError('too many credentials')
    def get(self,host,protocol):
        return next((e for e in self.entries if e.host==host and e.protocol==protocol),None)
    def clear(self): self.entries.clear()


def mechanism(headers):
    challenge=headers.get('www-authenticate','')
    if challenge: return challenge.split()[0].lower()
    if 'set-cookie' in headers: return 'cookie/session'
    return 'none'


def authorization(challenge, credential, method, uri):
    if challenge.lower().startswith('basic '):
        return 'Basic '+base64.b64encode(f'{credential.username}:{credential.password}'.encode()).decode()
    if not challenge.lower().startswith('digest '): return None
    fields=parse_keqv_list(parse_http_list(challenge[7:]))
    algorithm=fields.get('algorithm','MD5')
    name={'md5':'md5','sha-256':'sha256','sha-512-256':'sha512_256'}.get(algorithm.lower().removesuffix('-sess'))
    if not name or not fields.get('nonce'): return None
    def h(s): return hashlib.new(name,s.encode()).hexdigest()
    def quote(s): return '"'+s.replace('\\','\\\\').replace('"','\\"')+'"'
    realm,nonce=fields.get('realm',''),fields['nonce']; cnonce=secrets.token_hex(16); nc='00000001'
    ha1=h(f'{credential.username}:{realm}:{credential.password}')
    if algorithm.lower().endswith('-sess'): ha1=h(f'{ha1}:{nonce}:{cnonce}')
    qops=[x.strip() for x in fields.get('qop','').split(',') if x.strip()]
    if qops and 'auth' not in qops: return None
    ha2=h(f'{method}:{uri}')
    response=h(f'{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}') if qops else h(f'{ha1}:{nonce}:{ha2}')
    result={'username':credential.username,'realm':realm,'nonce':nonce,'uri':uri,'response':response}
    if 'opaque' in fields: result['opaque']=fields['opaque']
    if fields.get('userhash')=='true': result['username']=h(f'{credential.username}:{realm}')
    parts=[f'{k}={quote(v)}' for k,v in result.items()]+['algorithm='+algorithm]
    if qops: parts+=['qop=auth','nc='+nc,'cnonce='+quote(cnonce)]
    elif algorithm.lower().endswith('-sess'): parts+=['cnonce='+quote(cnonce)]
    if fields.get('userhash')=='true':parts+=['userhash=true']
    return 'Digest '+', '.join(parts)
