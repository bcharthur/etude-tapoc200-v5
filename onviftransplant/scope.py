from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json,re,subprocess

@dataclass(frozen=True)
class Scope:
    target_ip:str
    target_mac:str

def load_scope():
    try:
        from tapolab.config import load_scope as project_load_scope
        s=project_load_scope(); return Scope(str(s.target_ip),str(s.target_mac))
    except Exception: pass
    p=Path('config/scope.json')
    if not p.exists(): raise RuntimeError('Could not load config/scope.json')
    obj=json.loads(p.read_text(encoding='utf-8'))
    def find(o,names):
        if isinstance(o,dict):
            for k,v in o.items():
                if str(k).lower() in names and isinstance(v,str) and v: return v
            for v in o.values():
                h=find(v,names)
                if h:return h
        elif isinstance(o,list):
            for v in o:
                h=find(v,names)
                if h:return h
    ip=find(obj,{'target_ip','camera_ip','ip'}); mac=find(obj,{'target_mac','camera_mac','mac'})
    if not ip or not mac: raise RuntimeError('Missing target_ip/target_mac in scope')
    return Scope(ip,mac)

def normalized_mac(v): return v.replace(':','').replace('-','').upper()
def current_wifi_ssid():
    cp=subprocess.run(['netsh','wlan','show','interfaces'],capture_output=True,text=True,encoding='utf-8',errors='replace')
    for line in cp.stdout.splitlines():
        if re.match(r'\s*BSSID\s*:',line,re.I): continue
        m=re.match(r'\s*SSID\s*:\s*(.+?)\s*$',line,re.I)
        if m:return m.group(1).strip()
    return None

def expected_setup_ssid(scope): return 'Tapo_Cam_'+normalized_mac(scope.target_mac)[-4:]
def setup_gateway():
    ps='$ErrorActionPreference="Stop"; Get-NetIPConfiguration | Select-Object InterfaceAlias,@{N="IPv4DefaultGateway";E={@($_.IPv4DefaultGateway.NextHop)}} | ConvertTo-Json -Depth 4'
    cp=subprocess.run(['powershell','-NoProfile','-Command',ps],capture_output=True,text=True,encoding='utf-8',errors='replace')
    if cp.returncode!=0: raise RuntimeError(cp.stderr.strip() or 'Get-NetIPConfiguration failed')
    obj=json.loads(cp.stdout); rows=obj if isinstance(obj,list) else [obj]
    for row in rows:
        alias=str(row.get('InterfaceAlias') or '').lower()
        if not any(x in alias for x in ('wi-fi','wifi','wlan')): continue
        gws=row.get('IPv4DefaultGateway') or []
        if isinstance(gws,str):gws=[gws]
        for gw in gws:
            if gw and gw.startswith(('10.','172.','192.168.')): return gw
    raise RuntimeError('No private Wi-Fi gateway found')

def select_target(state):
    scope=load_scope()
    if state=='normal': return scope,scope.target_ip,{'state':'normal','scope_target_ip':scope.target_ip}
    if state=='setup':
        actual=current_wifi_ssid(); expected=expected_setup_ssid(scope)
        if not actual or actual.upper()!=expected.upper(): raise RuntimeError(f'Refusing SETUP test: connect to {expected!r}; current={actual!r}')
        ip=setup_gateway(); return scope,ip,{'state':'setup','actual_ssid':actual,'expected_ssid':expected,'gateway_target':ip}
    raise ValueError('state must be normal or setup')
