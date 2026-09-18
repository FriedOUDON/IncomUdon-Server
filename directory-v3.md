# Directory UDP v3 Relay Configuration

Directory UDP v3 is optional and disabled by default. When enabled, the Relay
serves only configured channels. It publishes static channel/speaker metadata
and current participants for the requested channel; it never publishes endpoint
addresses, channel credentials, media keys, or media payloads.

## Key Provisioning

The Relay key file is Relay-local and has this strict CSV format:

```text
channel_id,directory_channel_key_base64url
111,<canonical-unpadded-base64url-32-byte-key>
```

For each channel, credential provisioning derives the stored value as:

```text
directory_channel_key = HKDF-SHA-256(
    password_key,
    empty_salt,
    "incomudon-directory-channel-v3",
    32
)
```

Derive it in an offline trusted credential-management process, then provide only
the resulting 32-byte key to the Relay. Do not configure a raw passphrase,
random channel secret, or `password_key` in the Relay. The file uses canonical
unpadded Base64URL and is a secret because it can derive the v3 directional
Directory keys.

The Relay rejects an empty file, duplicate channel IDs, zero keys, noncanonical
Base64URL, a key with no matching metadata channel, and metadata with no key.

## Metadata

`channels.csv` has `channel_id,name`. `speakers.csv` has
`channel_id,sender_id,name`; its `channel_id` may be `all` for a sender-name
fallback. See the example files in this directory. Names are UTF-8 and limited
to 128 Unicode code points. The Relay loads all three files once at startup, so rotate a key
or update metadata by atomically replacing the file and restarting the Relay.

## Transport

Set `INCOMUDON_DIRECTORY_ENABLED=true` and select one transport:

```text
media-port    Default. IDP3 carrier on the ordinary Relay UDP port.
dedicated-udp Raw Directory JSON on INCOMUDON_DIRECTORY_DEDICATED_LISTEN.
```

`media-port` is normally preferred: clients use the active Relay host and port,
and Docker needs no additional port mapping. `dedicated-udp` is for deployments
that require network separation. Its listener and firewall/Docker UDP mapping
are explicit operator responsibilities.

Directory requests, registrations, and responses are bound to the selected
transport by AES-GCM AAD. Traffic replayed between the media port and a
dedicated listener therefore fails authentication.

## Runtime Limits

The Relay enforces the v3 1200-byte UDP cap, 64 active registrations, a
64-entry authenticated replay window per client direction/channel/epoch, and
at most 32 fragments per response. Metadata is limited to 256 channels and
4096 speaker rows; live participant responses are limited to 128 rows per
channel. Participant publications are sent every 30 seconds by default and
registrations expire after 90 seconds unless refreshed. Directory work uses
bounded queues and rate budgets; dropped Directory traffic is expected under
load and never delays audio or ordinary Relay control.
