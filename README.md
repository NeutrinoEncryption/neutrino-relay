# neutrino-relay

The zero-knowledge relay used by [Neutrino](https://neutrino.peretas.live) file transfers, by [Peretas Technologies](https://peretas.live).

Neutrino connects two computers directly whenever it can: first a direct QUIC connection, then coordinated NAT hole punching. The relay serves two purposes:
1. **Rendezvous.** It lets two peers find each other so they can attempt hole punching.
2. **Last-resort transport.** When no direct path exists, it carries their **end-to-end encrypted** stream.

This repository is the complete server, published so anyone can verify what it can and cannot see, and run their own.

## What the relay sees, and what it never sees

| Sees | Never sees |
|---|---|
| Client IP addresses, connection times, bytes forwarded | File contents or names (XChaCha20-Poly1305 end-to-end) |
| A 16-byte **ticket**: a keyed BLAKE3 hash of the session secret | The session code or its secret token |
| | Encryption keys (hybrid X25519 + ML-KEM-768, negotiated peer-to-peer *through* the relay) |

The relay doesn't store anything. It keeps no logs of tickets or payloads, and holds no state beyond the open connections.

## Protocol

WebSocket at `/v1/relay`. TLS is terminated by your reverse proxy.

1. The client sends one binary message: `[16-byte ticket][u32 BE length = 0]`.
2. The first two connections with the same ticket are paired. Each receives the same 20-byte envelope as a *pairing notice*.
3. From then on, every binary message is forwarded verbatim to the other peer. Clients wrap payloads as `[ticket][u32 BE len][ciphertext]`.

Limits: 4 MiB per message; 1 h to wait for a partner; 90 s idle (the relay pings every 25 s, and live clients answer); 2048 pending registrations; 4096 connections. A newer registration for the same ticket replaces a stale one.

## Run your own

```sh
cargo build --release
sudo install -m755 target/release/neutrino-relay /usr/local/bin/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin neutrino
sudo cp deploy/neutrino-relay.service /etc/systemd/system/ && sudo systemctl enable --now neutrino-relay
# nginx (TLS + WebSocket + per-IP limits): deploy/nginx.conf
# Optional STUN for public-address discovery (coturn, STUN only, no TURN relaying): deploy/turnserver.conf
```

`NEUTRINO_RELAY_BIND` (default `127.0.0.1:8787`) sets the listen address. Point clients at your relay with:

```sh
NEUTRINO_RELAY_URL=wss://relay.example.com/v1/relay neutrino send ./folder
```

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

Neutrino itself (the CLI and daemon) is proprietary. Only this relay and the [documentation](https://github.com/NeutrinoEncryption/documentation) are open source.
