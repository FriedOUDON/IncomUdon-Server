# IncomUdon Relay Server

## Local run

```bash
go run . -port 50000
```

## No-crypto test mode

```bash
go run . -port 50000 -no-crypto
```

## Packet logging

```bash
go run . -port 50000 -log-packets
go run . -port 50000 -log-packets -log-audio
```

`-log-packets` includes codec config details (`codec_id`, `mode`, `pcm_only`) when `pktCodecConfig` is received.
Version 1 Relay traffic is limited to 1200-byte UDP datagrams. Oversize
datagrams are discarded before parsing or forwarding; packet logging emits
`udp_datagram_drop` for those drops and `udp_size_near_limit` for accepted
media close to the limit.

## Server-managed TX timeout

Set talk timeout by CLI flag:

```bash
go run . -port 50000 -talk-max-sec 60
```

Or by environment variable:

```bash
INCOMUDON_TALK_MAX_SEC=60 go run . -port 50000
```

Notes:
- `0` disables timeout.
- If both are set, `-talk-max-sec` takes precedence.
- On channel join, server sends this value to clients via `pktServerCfg` so clients can show remaining TX time.
- `TALK_RELEASE` carries the Version 1 release reason, including client PTT off,
  server timeout, membership timeout, client leave, and optional admission or
  preemption policy outcomes.

## Membership lease and keepalive

The Relay advertises an eight-byte `SERVER_CONFIG` after each successful JOIN.
It includes a per-membership snapshot of the normal talk limit, multi-talker
policy, membership lease, and idle keepalive interval.

```bash
INCOMUDON_MEMBERSHIP_LEASE_SEC=30 \
INCOMUDON_KEEPALIVE_INTERVAL_SEC=10 \
go run . -port 50000
```

Equivalent flags are `-membership-lease-sec` and `-keepalive-interval-sec`.
The lease must be `15..300` seconds and keepalive must be `1..floor(lease/3)`
seconds. Defaults are 30 and 10 seconds. Existing members retain the timing
snapshot accepted at JOIN; a later configuration change applies only to a new
JOIN.

Only accepted `KEEPALIVE`, `CODEC_CONFIG`, PTT control, and authorized active
`AUDIO`/`FEC` refresh membership. `PING`/`PONG` are RTT probes and never extend
the membership deadline. `-timeout` remains a deprecated whole-second alias
for `-membership-lease-sec`.

## Simultaneous transmit (multi-talk)

The relay remains the authority for PTT admission. Enable simultaneous transmit
and set the channel-wide talker limit with CLI flags:

```bash
go run . -port 50000 -multi-talk -max-active-talkers 2
```

Or use environment variables (CLI flags take precedence):

```bash
INCOMUDON_MULTI_TALK=true \
INCOMUDON_MAX_ACTIVE_TALKERS=2 \
go run . -port 50000
```

Notes:
- Multi-talk is disabled by default; disabled mode always permits one talker.
- `INCOMUDON_MAX_ACTIVE_TALKERS` and `-max-active-talkers` accept `1..16`.
- The relay sends the enabled flag and maximum to each joining client via
  `pktServerCfg`.
- A late-joining client receives the current talkers' cached codec settings
  before their `TALK_GRANT` packets, so each stream starts with the correct
  decoder configuration.

## Control Authentication v1

The relay supports the v0.7 Control Authentication v1 handshake and gates
AES-GCM v2 media on a verified, per-channel control session. It validates
authenticated `AUTH_HELLO` / `AUTH_CHALLENGE` / `JOIN` traffic, performs the
64-counter control replay check across provisional pre-JOIN state and the
joined session, caches only verified 19-byte `CODEC_CONFIG` payloads, and
re-signs Relay-generated control packets separately for every recipient.
Relay-generated packets use an independent fixed-header sequence space and a
non-wrapping Relay control nonce domain. Media remains end-to-end protected and
is forwarded byte-for-byte; the receiving client remains responsible for AEAD
authentication and media replay detection.

Configure it with these environment variables or their CLI equivalents:

```bash
INCOMUDON_CONTROL_AUTH_POLICY=required \
INCOMUDON_CONTROL_KEY_FILE=./control/control-keys.csv \
INCOMUDON_CONTROL_COOKIE_SECRET_FILE=./control/cookie.secret \
go run . -port 50000
```

`INCOMUDON_CONTROL_AUTH_POLICY` accepts:

- `off`: preserve no-crypto or legacy compatibility control behavior; AES-GCM
  v2 media is rejected.
- `optional`: require authentication only for channels listed in the key CSV.
- `required`: require authenticated control traffic and the AES-GCM v2 media
  profile for every channel. No-crypto and legacy-xor `CODEC_CONFIG` values are
  rejected even when their control HMAC is valid.

The key CSV is intentionally not stored in source control:

```csv
channel_id,key_id,control_key_base64
100,1,BASE64_ENCODED_32_BYTE_CONTROL_KEY
```

Each row contains a non-zero `key_id` and an exact 32-byte Base64-decoded
Control Authentication key. The value must be the channel's derived
`control_key` defined by the protocol; do not place the human channel password
in this file. The Relay-only cookie secret is at least 32 random bytes, either
raw or Base64 encoded. For example:

```bash
openssl rand -base64 32 > control/cookie.secret
```

For Docker Compose, place the files under `INCOMUDON_CONTROL_DATA_DIR`
(default `./control`) and use container paths in `.env`:

```dotenv
INCOMUDON_CONTROL_AUTH_POLICY=required
INCOMUDON_CONTROL_DATA_DIR=./control
INCOMUDON_CONTROL_KEY_FILE=/run/incomudon-control/control-keys.csv
INCOMUDON_CONTROL_COOKIE_SECRET_FILE=/run/incomudon-control/cookie.secret
```

`-no-crypto` cannot be combined with `required` policy. Endpoint-originated
packets with `sender_id = 0` are rejected before they can create membership,
talk, or authentication state; zero remains reserved for Relay/System packets.

## Directory Provisioning

For PSK-protected channel and speaker name provisioning to a PWA server, see
[directory.md](directory.md).

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
