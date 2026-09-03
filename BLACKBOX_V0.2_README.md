# Black-box v0.2 — Pre-auth state-machine mapping

Extract at project root and accept replacement of:

```text
blackboxlab\cli.py
```

New files:

```text
blackboxlab\rtsp_methods.py
blackboxlab\stream8800_v2.py
blackboxlab\https443_v2.py
```

No new Python dependency.

## What v0.1 established

### RTSP/554

Historical `localhost` / `127.0.0.1` URL regression is NOT reproduced:

```text
stream1 -> 401
stream2 -> 401
localhost variants -> 401
127.0.0.1 variants -> 401
```

### Streamd/8800

Confirmed:

```text
Server: Streamd
Digest
algorithm=MD5
qop=auth
encrypt_type=3
X-Preconn=1
X-Hb=5
```

Normal unauthenticated preview receives:

```text
401
Content-Length: 0
no media
```

### HTTPS/443

Pre-auth discovery works on `/` and `/app`:

```json
{
  "error_code": 0,
  "result": {
    "sub_method": "discover",
    "tpap": {
      "pake": [2],
      "tls": 1,
      "noc": 1,
      "port": 443
    }
  }
}
```

This is discovery/negotiation metadata, not an auth bypass by itself.

---

# New tests

## RTSP method matrix

```powershell
python .\blackbox.py rtsp-methods
```

Tests, without Authorization:

```text
OPTIONS
DESCRIBE
SETUP
PLAY
GET_PARAMETER
TEARDOWN
```

A 2xx on a non-public/stateful method is flagged for review.

## 8800 route/method matrix

```powershell
python .\blackbox.py 8800-routes
```

Tests bounded empty requests against:

```text
POST /stream
POST /
POST /app
POST /stream/
GET /stream
HEAD /stream
OPTIONS /stream
```

No credentials and zero request body.

## 8800 nonce profile

```powershell
python .\blackbox.py 8800-nonces --count 8
```

Measures:

```text
nonce uniqueness
opaque stability
realm
qop
algorithm
encrypt_type
X-Preconn
X-Hb
```

No Digest response is computed.

## HTTPS 443 oracle

```powershell
python .\blackbox.py 443-oracle
```

Compares:

```text
discover on /
discover on /app
discover on /stream
unknown method on /
unknown method on /app
empty multipleRequest on /
empty multipleRequest on /app
```

The aim is to map routing and error-code differences, not to authenticate.

## Full run

```powershell
python .\blackbox.py sweep-v2
```

Evidence:

```text
evidence\runs\<timestamp>\
├── blackbox-v0.2.json
└── manifest.json
```

No brute force, login completion, overflow, crash, reboot or reset.
