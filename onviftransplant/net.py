from __future__ import annotations
import json,socket,ssl,time

def tcp_open(ip,port,timeout=.7):
    try:
        with socket.create_connection((ip,port),timeout=timeout): return True
    except OSError:return False

def tcp_matrix(ip): return {str(p):tcp_open(ip,p) for p in (443,554,2020,8800)}

def https_discover(ip,timeout=2.5):
    body=b'{"method":"login","params":{"sub_method":"discover"}}'
    req=(f'POST / HTTP/1.1\r\nHost: {ip}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    with socket.create_connection((ip,443),timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw,server_hostname=None) as s:
            s.sendall(req);data=bytearray()
            while len(data)<131072:
                try:c=s.recv(8192)
                except socket.timeout:break
                if not c:break
                data.extend(c)
    _,_,payload=bytes(data).partition(b'\r\n\r\n')
    try:return json.loads(payload.decode('utf-8',errors='replace'))
    except Exception:return {'parse_error':True,'body_preview':payload[:512].decode('utf-8',errors='replace')}
