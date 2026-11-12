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

The relay writes no persistent session data. It keeps no logs of tickets or payloads, and holds only in-memory connection, UDP allocation and rate-limit state.

## Protocol

WebSocket at `/v1/relay`. TLS is terminated by your reverse proxy.

1. The client sends one binary message: `[16-byte ticket][u32 BE length = 0]`.
2. The first two connections with the same ticket are paired. Each receives the same 20-byte envelope as a *pairing notice*.
3. From then on, every binary message is forwarded verbatim to the other peer. Clients wrap payloads as `[ticket][u32 BE len][ciphertext]`.

Limits: 4 MiB per message; 1 h to wait for a partner; 90 s idle (the relay pings every 25 s, and live clients answer); 2048 pending registrations; 4096 connections. A newer registration for the same ticket replaces a stale one.

## UDP protocol (raw QUIC relay)

UDP listens on `0.0.0.0:3479` by default, independently of WebSocket. It carries
end-to-end QUIC datagrams, preserving QUIC congestion control without TCP
head-of-line blocking. It does not terminate QUIC or inspect its ciphertext.

* Registration is **exactly 21 bytes**: ASCII `NRU1` (4 bytes), the keyed
  16-byte ticket (opaque bytes, no integer encoding), then one role byte: `0`
  for the initiating peer, `1` for its partner. Clients must agree on roles.
* The first registration waits silently. Two **distinct source IP:port addresses**
  with the same ticket and opposite roles pair. The relay sends each its own
  exact 21-byte registration as the pairing notice (including its own role).
  A repeated registration while pending has no response. Once paired, an exact
  repeat registration elicits a notice **only to its sender**, allowing retries
  after lost notices without repeatedly sending to the other peer.
* After pairing, every other datagram is forwarded **verbatim**, with no prefix,
  from the relay's UDP address to the partner. A source address identifies one
  allocation on this socket; it cannot register a different ticket or change
  roles until that allocation expires. Malformed/unknown traffic is dropped
  before pairing. An exact registration matching the current ticket and role is
  reserved control traffic even after pairing.
* NAT rebinding is not inferred from ciphertext. From its new UDP socket/address,
  a peer sends the same ticket and role. This replaces its old address immediately
  and returns a notice if paired; the partner continues using the same relay
  address. Old-address ciphertext is dropped. A stale client that knows the
  ticket can reclaim that role, so tickets must be unguessable secret-derived
  hashes, never public IDs. There is no additional identity authentication here;
  QUIC and application cryptography authenticate the peers. UDP source spoofing
  remains a risk: this is not a full TURN challenge/cookie protocol.
* Both peers must re-register following allocation expiry or a server restart.
  Retry registrations with backoff until notified. Keep active quiet sessions
  alive using end-to-end QUIC keepalives at an interval below 60 seconds.

Allocations (pending and paired) expire after **60 s without accepted traffic**
or **6 h from first registration**, even if busy; a same-role replacement never
extends that hard deadline. Cleanup runs every second and expired sources cannot
forward. There are at most **4096 allocations** (including pending), and at most
2048 pending by default. State and rate accounting are memory-only; no tickets,
addresses or payloads are logged. A single reusable 65,535-byte receive buffer
bounds payload memory; there is no application queue, retransmission or file buffering.

| Environment variable | Default | Meaning |
|---|---|---|
| `NEUTRINO_RELAY_UDP_BIND` | `0.0.0.0:3479` | UDP listen address |
| `NEUTRINO_RELAY_UDP_MAX_PENDING` | `2048` | Maximum pending tickets (also bounded by 4096 total) |
| `NEUTRINO_RELAY_UDP_IP_PPS` | `20000` | Ingress datagrams per source IP per second |
| `NEUTRINO_RELAY_UDP_IP_BPS` | `33554432` | Ingress payload bytes per source IP per second |
| `NEUTRINO_RELAY_UDP_TOTAL_BPS` | `134217728` | Total egress payload bytes per second, including notices |

Limits use one-second windows beginning with the first packet in each window;
short bursts across boundaries are possible. IP accounting includes rejected
packets that fit the budget and is bounded to 16,384 IPs (additional IPs are
silently dropped until entries expire). Zero limits deny traffic; invalid numeric
settings fail startup. Excess packets are dropped, leaving recovery and pacing
to QUIC. IP limits aggregate peers behind a shared NAT. Egress never exceeds
accepted raw ingress bytes plus notices: an unpaired address receives nothing
until pairing, and its initial notice is exactly its 21-byte registration size.
Retries send at most one equal-sized reply to their source; no response is sent
for malformed registrations. This bounds registration amplification to 1x
(payload bytes, excluding network headers); paired ciphertext forwarding is 1:1.

Open **UDP 3479** in the host firewall and provider firewall/security group.
nginx proxies WebSocket only; UDP goes directly to the relay process. This mode
is a minimal pairing relay, not interoperable with TURN clients.

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
