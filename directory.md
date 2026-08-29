# Directory Provisioning

This document describes the optional PSK-protected directory publisher in the
Relay. It sends channel and speaker display names, plus a separate current
participant snapshot, to PWA servers over UDP. It does not send channel
passwords, audio, client session keys, or client endpoint addresses.

## Relay Configuration

Create `server/.env` beside `compose.yaml`. Directory mode is disabled unless
`INCOMUDON_DIRECTORY_ENABLED=true` is set. When it is disabled, incomplete
directory paths are ignored and do not prevent the Relay from starting.

```dotenv
# Host path mounted read-only at /run/incomudon-directory in the container.
INCOMUDON_DIRECTORY_ENABLED=true
INCOMUDON_DIRECTORY_DATA_DIR=./directory

# Required: paths inside the Relay container.
INCOMUDON_DIRECTORY_CHANNELS_CSV=/run/incomudon-directory/channels.csv
INCOMUDON_DIRECTORY_SPEAKERS_CSV=/run/incomudon-directory/speakers.csv
INCOMUDON_DIRECTORY_UDP_TARGET=192.168.1.50:51001
# Relay listener for authenticated on-demand pull requests from the PWA server.
INCOMUDON_DIRECTORY_UDP_LISTEN=:51000
INCOMUDON_DIRECTORY_PSK_FILE=/run/incomudon-directory/directory.psk

# Optional values shown with their defaults.
INCOMUDON_DIRECTORY_KEY_ID=pwa-1
INCOMUDON_DIRECTORY_PUBLISH_INTERVAL=30s
INCOMUDON_DIRECTORY_TTL=90s

# Optional, but strongly recommended when the PWA server has a stable address.
INCOMUDON_DIRECTORY_REQUEST_ALLOW_CIDRS=192.168.1.50/32

# Docker Compose port mapping only. These values are not read by the Relay.
# The host port is 51000. The PWA publishes its directory listener on 51001.
INCOMUDON_DIRECTORY_COMPOSE_UDP_HOST_PORT=51000
INCOMUDON_DIRECTORY_COMPOSE_UDP_LISTEN_PORT=51000
```

`INCOMUDON_DIRECTORY_DATA_DIR` is a host path. Docker Compose mounts it at
`/run/incomudon-directory` in the Relay container, so the CSV and PSK paths
must use that container path. Set `INCOMUDON_DIRECTORY_UDP_TARGET` to the PWA
server's private UDP listener address. `INCOMUDON_DIRECTORY_UDP_LISTEN` is a
separate Relay UDP port used only for authenticated pull requests; it is not
the Relay audio port. The `INCOMUDON_DIRECTORY_COMPOSE_UDP_*` variables are
used only by `compose.yaml` to publish that listener: the host port maps to
the container port. Keep the latter aligned with the port in
`INCOMUDON_DIRECTORY_UDP_LISTEN`. They are unnecessary when running the Relay
binary directly rather than through Docker Compose.

Keep the publish interval shorter than the TTL. The default `30s` interval and
`90s` TTL are recommended. The Relay reloads both CSV files and creates a
fresh participant snapshot at every publish interval, so valid CSV changes do
not require a Relay restart.

## Directory Files

The default layout is:

```text
server/
  .env
  directory/
    channels.csv
    speakers.csv
    directory.psk
```

`channels.csv` and `speakers.csv` are ignored by Git. Version-controlled
examples are available as `directory/channels.csv.example` and
`directory/speakers.csv.example`.

### channels.csv

Format: `channel_id,name`

```csv
# The header is optional.
channel_id,name
101,Operations
102,Maintenance
```

`channel_id` must be a unique integer from 1 through 4294967295.

### speakers.csv

Format: `channel_id,sender_id,name`

```csv
# The header is optional.
channel_id,sender_id,name
all,1001,Dispatch-1
101,1002,Field-Team-A
102,1001,Maintenance-Dispatch-1
102,2001,Maintenance-Lead
```

A numeric `channel_id` must exist in `channels.csv`. The `sender_id` must be an
integer from 1 through 4294967295.

Set `channel_id` to `all` to assign the name to that sender ID in every
configured channel. A concrete `channel_id` row for the same sender ID takes
precedence in that channel. In the example above, sender `1001` is named
`Dispatch-1` in channel `101` and `Maintenance-Dispatch-1` in channel `102`.

Duplicate `all/sender_id` pairs and duplicate numeric `channel_id/sender_id`
pairs are rejected. Blank rows and rows beginning with `#` are ignored. Names
must be valid UTF-8, non-empty, and at most 128 characters. After expanding
`all` rows, the directory supports at most 4096 speaker entries.

## PSK File

`directory.psk` must contain one base64url-encoded, random 32-byte key. Use a
key dedicated to directory provisioning; do not reuse an audio key or channel
password.

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' > directory.psk
chmod 600 directory.psk
```

Copy the exact same PSK file to the PWA server through a secure out-of-band
path. The PWA receiver's `INCOMUDON_DIRECTORY_KEY_ID` must equal
`INCOMUDON_DIRECTORY_KEY_ID` above.

## Security and Delivery

Each `snapshot`, `participants`, and pull `request` datagram is encrypted and
authenticated with AES-256-GCM. The Relay uses a fresh per-process epoch,
authenticated sequence numbers, and expiry metadata. The PWA rejects
malformed, expired, excessively long-lived, and replayed documents.

The `snapshot` document carries CSV-provisioned channel and speaker names. The
separate `participants` document contains only `channelId`, `senderId`,
`lastSeenAt`, and `talking`; it never contains an IP address or a secret. The
Relay publishes both documents at `INCOMUDON_DIRECTORY_PUBLISH_INTERVAL`.

For an immediate refresh, a PWA server sends an authenticated `request` to
`INCOMUDON_DIRECTORY_UDP_LISTEN`. After validating that request, the Relay
replies to the request source with fresh `snapshot` and `participants`
documents. This envelope contract is intentionally platform-neutral for the
future native client implementation.

Keep the PWA directory UDP port private. On the PWA server, configure a source
CIDR allowlist for the Relay address in addition to the PSK, and firewall the
port accordingly. One Relay process supports one directory UDP target; run a
separate Relay process when recipients require different PSKs.

Keep the Relay pull listener private as well. Configure
`INCOMUDON_DIRECTORY_REQUEST_ALLOW_CIDRS` for PWA server addresses whenever
possible, and do not reuse the directory PSK for audio encryption or channel
passwords.
