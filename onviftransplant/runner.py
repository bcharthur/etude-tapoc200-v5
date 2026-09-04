from __future__ import annotations
import time
from .evidence import EvidenceRun,sha256
from .http import post_xml
from .net import tcp_matrix,https_discover
from .oracle import classify,recovery_watch
from .scope import normalized_mac
from .soap import baseline_get_time,prefix_case,element_case,CONSERVATIVE_PREFIX,EXTENDED_PREFIX,CONSERVATIVE_ELEMENTS,EXTENDED_ELEMENTS

def verify_identity(scope,ip):
    if not tcp_matrix(ip).get('443'): raise RuntimeError(f'{ip}:443 is not reachable; cannot verify scoped camera')
    d=https_discover(ip);mac=str(((d.get('result') or {}).get('mac') or ''))
    if normalized_mac(mac)!=normalized_mac(scope.target_mac): raise RuntimeError(f'Refusing: discovered MAC {mac!r} != scoped MAC {scope.target_mac!r}')
    return d

def baseline(ip,paths=None):
    paths=paths or ['/onvif/device_service','/onvif/service'];body=baseline_get_time();return {p:post_xml(ip,p,body) for p in paths}

def choose_baseline_path(results):
    for path in ('/onvif/device_service','/onvif/service'):
        if (results.get(path) or {}).get('status_line') is not None:return path
    raise RuntimeError('Neither known ONVIF path produced an HTTP response; do not run mutation tests.')

def run_sweep(scope,ip,gate,axis,profile,evidence_base,delay,recovery_seconds):
    discovery=verify_identity(scope,ip);preflight=tcp_matrix(ip)
    if not preflight.get('2020'): raise RuntimeError('ONVIF :2020 is not reachable. Enable third_account first; no cases sent.')
    base=baseline(ip);path=choose_baseline_path(base);run=EvidenceRun(evidence_base,f'onvif-{axis}-{profile}')
    run.event('preflight',gate=gate,target_ip=ip,tcp=preflight,discovery=discovery,baseline=base,selected_path=path)
    if axis=='prefix': values=CONSERVATIVE_PREFIX if profile=='conservative' else EXTENDED_PREFIX; builder=prefix_case
    elif axis=='elements': values=CONSERVATIVE_ELEMENTS if profile=='conservative' else EXTENDED_ELEMENTS; builder=lambda n:element_case(n,100)
    else: raise ValueError('axis must be prefix or elements')
    cases=[];crash=None
    for i,value in enumerate(values,1):
        before=tcp_matrix(ip)
        if not before.get('2020'):
            crash={
                'before_case':value,
                'reason':'ONVIF unavailable before next testcase',
                'tcp':before,
            }
            run.event('stop',**crash)
            run.event(
                'recovery_watch',
                states=recovery_watch(ip,recovery_seconds,1.0),
            )
            break
        body=builder(value);h=sha256(body);run.event('case_start',index=i,axis=axis,value=value,body_len=len(body),body_sha256=h,tcp_before=before)
        started=time.monotonic();resp=post_xml(ip,path,body);elapsed=time.monotonic()-started;time.sleep(delay);after=tcp_matrix(ip);verdict=classify(before,after)
        row={'index':i,'axis':axis,'value':value,'body_len':len(body),'body_sha256':h,'request_result':resp,'elapsed_s':round(elapsed,4),'tcp_before':before,'tcp_after':after,'verdict':verdict}
        cases.append(row);run.event('case_result',**row)
        print(f'[{i}/{len(values)}] {axis}={value} body={len(body)}B status={resp.get("status_line")} verdict={verdict}',flush=True)
        if verdict!='ONVIF_STILL_REACHABLE':
            crash=row;run.event('crash_candidate',**row);run.event('recovery_watch',states=recovery_watch(ip,recovery_seconds,1.0));break
    summary={'scope_gate':gate,'target_ip':ip,'axis':axis,'profile':profile,'selected_onvif_path':path,'initial_tcp':preflight,'final_tcp':tcp_matrix(ip),'cases_sent':len(cases),'crash_candidate':crash,'evidence_dir':str(run.dir),'note':'Crash/memory-corruption oracle only. No code-execution payload, ROP chain, shellcode or persistence.'}
    run.finish(summary);return summary
