from __future__ import annotations
import time
from .net import tcp_matrix

def classify(before,after):
    if before.get('2020') and not after.get('2020'):
        if after.get('443') or after.get('8800'): return 'ONVIF_SERVICE_DOWN_DEVICE_STILL_REACHABLE'
        return 'MULTI_SERVICE_DOWN_POSSIBLE_REBOOT_OR_SYSTEM_CRASH'
    if after.get('2020'): return 'ONVIF_STILL_REACHABLE'
    return 'INCONCLUSIVE'

def recovery_watch(ip,seconds=60,interval=1.0):
    end=time.monotonic()+seconds;states=[];last=None
    while time.monotonic()<end:
        state=tcp_matrix(ip)
        if state!=last:
            states.append({'elapsed':round(seconds-max(0,end-time.monotonic()),3),'tcp':state});last=state
        if state.get('2020') and state.get('443'): break
        time.sleep(interval)
    return states
