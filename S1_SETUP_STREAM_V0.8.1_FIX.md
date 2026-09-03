# S1 Setup Stream v0.8.1

## Why v0.8 saw exactly 74 bytes but no media

The multipart boundary parameter is:

```text
boundary=--client-stream-boundary--
```

In MIME multipart syntax, each actual delimiter on the wire is prefixed by
another `--`.

Therefore:

```text
boundary value:
--client-stream-boundary--

wire delimiter:
----client-stream-boundary--
```

v0.8 incorrectly sent only the boundary value as the wire delimiter.

Current go2rtc sends exactly:

```text
----client-stream-boundary--
Content-Type: application/json
Content-Length: ...

{"params":{"preview":...}}
```

Historical Tapo captures likewise show the first JSON response as roughly 74
bytes and carrying:

```json
{
  "type": "response",
  "seq": 1,
  "params": {
    "error_code": 0,
    "session_id": "..."
  }
}
```

followed by `video/mp2t`.

## Run

While still connected to your scoped `Tapo_Cam_XXXX`:

```powershell
python .\s1lab.py setup-stream-smoke
```

v0.8.1:
- fixes both client and device wire-boundary parsing;
- parses the session JSON first;
- reads at most 8 multipart parts;
- stops at the first video part;
- never saves media;
- tests only up to 256 KiB of the first video part;
- reports MPEG-TS sync spacing after decrypt.

Strong positive:

```text
session_response.error_code = 0
session_response.session_id != null
media_observed = true
decryptable_mpeg_ts_observed = true
```
