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

## Docker build/run

```bash
docker build -t incomudon-relay .
docker run --rm -p 50000:50000/udp incomudon-relay
```

```bash
docker run --rm -p 50000:50000/udp incomudon-relay -no-crypto
```
