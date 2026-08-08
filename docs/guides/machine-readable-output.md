# Machine-readable output

Most query-style `pymobiledevice3` commands print JSON on stdout, ready for `jq` or any JSON
parser. This page documents the conventions that output follows so scripts can rely on them.

## Streams

- **stdout carries data.** JSON documents, NDJSON records, and text-mode data lines all go to
  stdout.
- **stderr carries diagnostics.** Logging, progress, and warnings never mix into the data
  stream. Redirect stderr away (`2>/dev/null`) without losing any data.

## Binary values

JSON has no binary type. Values that are `bytes` on the device (nonces, digests, keys,
certificates) are encoded as a single-key object tagged `$hex`:

```json
{
    "ApNonce": {
        "$hex": "a1b2c3d4"
    }
}
```

Decode with `bytes.fromhex` in Python, or in `jq` keep the hex string with `.ApNonce["$hex"]`.
A `$hex` object never has additional keys, so `isinstance(value, dict) and value.keys() == {"$hex"}`
is a reliable detector when round-tripping arbitrary output:

```python
def decode(obj):
    if isinstance(obj, dict):
        if obj.keys() == {"$hex"}:
            return bytes.fromhex(obj["$hex"])
        return {k: decode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decode(v) for v in obj]
    return obj
```

## Timestamps

Datetimes are ISO 8601 (`datetime.isoformat()`), e.g. `2026-08-08T12:00:00+03:00`. Values
without an explicit timezone are naive device- or host-local times.

## Streaming commands: NDJSON

Streaming commands print one compact JSON object per line (NDJSON) on stdout — nothing else
is written to stdout, so the stream can be piped directly:

```shell
pymobiledevice3 syslog live --format json -m kernel | jq .message
pymobiledevice3 diagnostics battery monitor | jq .CurrentCapacity
```

Streams whose records are structured data emit NDJSON always:

- `developer dvt graphics`
- `developer dvt energy`
- `developer dvt notifications`
- `developer dvt sysmon process monitor` (JSONL, optionally to a file via `--output`)
- `diagnostics battery monitor`
- `notification observe` / `notification observe-all`

Streams that also have a human-readable text rendering default to it and accept
`--format json`:

- `syslog live`
- `developer dvt oslog`
- `developer dvt netstat`
- `developer accessibility notifications`
- `crash watch`
