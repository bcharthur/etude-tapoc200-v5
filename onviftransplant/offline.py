from __future__ import annotations
import hashlib
from pathlib import Path
ANCHORS=[b'CreateRules',b'SimpleItem',b'GetSystemDateAndTime',b'/onvif/service',b'/onvif/device_service',b'soap',b'ONVIF']
def index_binary(path):
    p=Path(path);data=p.read_bytes();hits={}
    for a in ANCHORS:
        offs=[];start=0
        while True:
            pos=data.find(a,start)
            if pos<0:break
            offs.append(pos);start=pos+1
            if len(offs)>=50:break
        if offs:hits[a.decode('ascii',errors='replace')]=offs
    return {'path':str(p),'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'anchor_hits':hits}
def compare(a,b):
    ia=index_binary(a);ib=index_binary(b);keys=sorted(set(ia['anchor_hits'])|set(ib['anchor_hits']))
    return {'a':ia,'b':ib,'anchors':{k:{'a':ia['anchor_hits'].get(k,[]),'b':ib['anchor_hits'].get(k,[])} for k in keys}}
