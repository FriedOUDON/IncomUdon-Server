# IncomUdon Relay Server

## Local run

```bash
go run ./main.go -port 50000
```

## No-crypto test mode

```bash
go run ./main.go -port 50000 -no-crypto
```

## Packet logging

```bash
go run ./main.go -port 50000 -log-packets
go run ./main.go -port 50000 -log-packets -log-audio
```

`-log-packets` includes codec config details (`codec_id`, `mode`, `pcm_only`) when `pktCodecConfig` is received.
The server also emits UDP packet-size monitor logs (`udp_size_warn`, `udp_fragment_risk`, `udp_size_stats`) to help detect fragmentation risk at high bitrates.

## Server-managed TX timeout

Set talk timeout by CLI flag:

```bash
go run ./main.go -port 50000 -talk-max-sec 60
```

Or by environment variable:

```bash
INCOMUDON_TALK_MAX_SEC=60 go run ./main.go -port 50000
```

Notes:
- `0` disables timeout.
- If both are set, `-talk-max-sec` takes precedence.
- On channel join, server sends this value to clients via `pktServerCfg` so clients can show remaining TX time.

## Docker build/run

```bash
docker build -t incomudon-relay . --no-cache
docker run --rm -p 50000:50000/udp incomudon-relay
```

```bash
docker run --rm -p 50000:50000/udp incomudon-relay -no-crypto
```
