"""Versioned JSON fingerprint providers; no vendor rules in pipeline code."""
from pathlib import Path
from functools import lru_cache
import json
from .evidence import identity

ROOT=Path(__file__).with_name('fingerprints')

@lru_cache(maxsize=8)
def profiles(root=str(ROOT)):
    return tuple(json.loads(p.read_text()) for p in sorted((Path(root)/'vendors').glob('*.json')))

@lru_cache(maxsize=8)
def signatures(root=str(ROOT)):
    result=[]
    for directory in ('products','models','firmware','services','protocols'):
        for p in sorted((Path(root)/directory).glob('*.json')):
            value=json.loads(p.read_text()); result.extend(value if isinstance(value,list) else [value])
    return tuple(result)


def fingerprint(observation, extra=()):
    corpus=' '.join(e.get('sample','') for e in observation.evidence).lower()
    corpus+=' '+json.dumps(observation.services).lower()
    for rule in (*signatures(),*extra):
        matches=[s for s in rule.get('contains',[]) if s.lower() in corpus]
        if not matches: continue
        evidence_ids=[e['id'] for e in observation.evidence if any(s.lower() in e.get('sample','').lower() for s in matches)]
        item={k:rule[k] for k in ('vendor','product','model','firmware','device_type','category','confidence') if k in rule}
        item.update(id=identity(rule['id'],observation.ip,observation.port),signature_id=rule['id'],version=rule['version'],evidence=evidence_ids)
        if item not in observation.fingerprints:observation.fingerprints.append(item)
    for profile in profiles():
        if any(s.lower() in corpus for s in profile['fingerprints']):
            item=dict(id=identity(profile['vendor'],observation.ip,observation.port),vendor=profile['vendor'],confidence=.85,
                      version=profile['version'],evidence=[e['id'] for e in observation.evidence if profile['vendor'].lower() in e.get('sample','').lower()])
            if item not in observation.fingerprints:observation.fingerprints.append(item)


def best(observation):
    result={}
    for fp in sorted(observation.fingerprints,key=lambda x:x.get('confidence',0)):
        result.update({k:v for k,v in fp.items() if k in ('vendor','product','model','firmware','device_type','confidence') and v})
    return result
