from __future__ import annotations
import socket

def post_xml(ip,path,body,timeout=3.0,max_response=131072):
    request=(f'POST {path} HTTP/1.1\r\nHost: {ip}:2020\r\nContent-Type: application/soap+xml; charset=utf-8\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body
    r={'request_len':len(request),'body_len':len(body),'status_line':None,'response_len':0,'response_preview':None,'exception':None}
    try:
        with socket.create_connection((ip,2020),timeout=timeout) as s:
            s.settimeout(timeout);s.sendall(request);data=bytearray()
            while len(data)<max_response:
                try:c=s.recv(min(8192,max_response-len(data)))
                except socket.timeout:break
                if not c:break
                data.extend(c)
        head,_,payload=bytes(data).partition(b'\r\n\r\n')
        if head:r['status_line']=head.split(b'\r\n',1)[0].decode('latin-1',errors='replace')
        r['response_len']=len(data);r['response_preview']=payload[:512].decode('utf-8',errors='replace')
    except Exception as e:r['exception']=f'{type(e).__name__}: {e}'
    return r
