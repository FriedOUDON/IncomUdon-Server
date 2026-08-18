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

## Simultaneous transmit (multi-talk)

The relay remains the authority for PTT admission. Enable simultaneous transmit
and set the channel-wide talker limit with CLI flags:

```bash
go run ./main.go -port 50000 -multi-talk -max-active-talkers 2
```

Or use environment variables (CLI flags take precedence):

```bash
INCOMUDON_MULTI_TALK=true \
INCOMUDON_MAX_ACTIVE_TALKERS=2 \
go run ./main.go -port 50000
```

Notes:
- Multi-talk is disabled by default; disabled mode always permits one talker.
- The relay sends the enabled flag and maximum to each joining client via
  `pktServerCfg`.
- A late-joining client receives the current talkers' cached codec settings
  before their `TALK_GRANT` packets, so each stream starts with the correct
  decoder configuration.

## Docker Compose

Run these commands from the `server/` directory:

```bash
docker compose up --build -d
docker compose logs -f relay
```

Stop the relay with:

```bash
docker compose down
```

`compose.yaml` publishes UDP port `50000` by default and passes the relay's
server configuration through environment variables. Create a `.env` file next
to `compose.yaml` when persistent configuration is required; the available
keys and defaults are documented in `.env.example`.

For example, to allow two simultaneous transmitters and set a 60-second TX
timeout:

```bash
INCOMUDON_MULTI_TALK=true \
INCOMUDON_MAX_ACTIVE_TALKERS=2 \
INCOMUDON_TALK_MAX_SEC=60 \
docker compose up --build -d
```

## Docker (without Compose)

```bash
docker build -t incomudon-relay . --no-cache
docker run --rm -p 50000:50000/udp incomudon-relay
```

```bash
docker run --rm -p 50000:50000/udp incomudon-relay -no-crypto
```
