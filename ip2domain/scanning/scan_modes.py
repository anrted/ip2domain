"""Explicit scan depth and port presets. Port ranks are hints, never evidence."""
from pathlib import Path
import json

TOP10=(80,443,22,21,25,3389,110,445,139,143)
# Checked-in port frequencies can be refreshed independently of scanner code.
def top_ports(count):
    ports=json.loads(Path(__file__).with_name('fingerprints').joinpath('endpoints','top_tcp.json').read_text())['ports']
    return ','.join(map(str,ports[:count]))

def apply_mode(config):
    mode=config.mode.upper().replace(' ','_')
    if mode not in ('FAST','STANDARD','FULL','DEEP','VIDEO','VOIP','OT_SAFE'):raise ValueError('unknown scan mode')
    object.__setattr__(config,'mode',mode)
    from .policies import COMMON_TCP,CAMERA_PORTS_STR
    if config.tcp_ports==COMMON_TCP:
        ports={'FAST':top_ports(10),'STANDARD':top_ports(1000),'FULL':'1-65535','DEEP':'1-65535',
               'VIDEO':CAMERA_PORTS_STR,'VOIP':'80,443,5060,5061,8080','OT_SAFE':'80,443,102,502,2404,4840,20000,44818'}[mode]
        object.__setattr__(config,'tcp_ports',ports)
    if mode in ('FULL','DEEP','VIDEO','VOIP','OT_SAFE') and not config.udp_ports:
        object.__setattr__(config,'udp_ports',{'VIDEO':'3702,1900,5353','VOIP':'5060,4569','OT_SAFE':'47808,44818','FULL':'53,123,161,1900,3702,5353','DEEP':'53,123,161,1900,3702,5353'}[mode])
    object.__setattr__(config,'profile','deep_identification')
    # The operator still explicitly selects active_consent; mode never invents authorization.
    if mode in ('FULL','DEEP','VIDEO','VOIP','OT_SAFE'):object.__setattr__(config,'web_enrichment',True)
    if mode=='OT_SAFE':object.__setattr__(config,'industrial_consent',True)
