### [2026-11-12 15:35] Task: Raw UDP relay and production deployment
* `src/main.rs`: Run UDP mode alongside the unchanged WebSocket protocol.
* `src/udp.rs`: Add bounded pairing, raw forwarding, expiry/rate limits and unit tests.
* `tests/udp.rs`: Exercise two real UDP clients against a relay process.
* `README.md`: Specify wire format, limits, NAT rebinding, firewall and security bounds.
* `deploy/neutrino-relay.service`: Set UDP 3479 bind.
* `deploy/verify_udp.py`: Add external UDP/rebinding verification client.
* Monorepo `deploy/SERVER.md`: Record UDP port and multi-file deployment procedure.
* `AGENTS/updates/2026-11-12_UDP_RELAY.md`: Manifest and verification evidence.
* `AGENTS/changelogs/UDP_RELAY.md`: This file ledger.
