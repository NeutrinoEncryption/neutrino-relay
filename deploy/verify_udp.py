#!/usr/bin/env python3
"""Live check of a neutrino-relay UDP endpoint (protocol v2).

Verifies: return-path cookies (a cookie minted for another source, or a forged
cookie, allocates and forwards nothing), reply <= request before pairing,
pairing, verbatim forwarding in both directions, rebinding with the previous
secret, rejection of a replayed registration and a replayed rebind, and that the
stale source is dropped. A true IP-spoofed packet cannot be produced from user
space, so the spoof check sends registrations carrying cookies the sender never
received at its own address, which is strictly more than an off-path spoofer has.
"""
import argparse
import hashlib
import secrets
import socket


def silent(peer, label):
    peer.settimeout(0.7)
    try:
        data = peer.recv(65535)
    except (socket.timeout, ConnectionResetError):
        return
    finally:
        peer.settimeout(5)
    raise AssertionError(f"{label}: unexpected {len(data)}-byte datagram")


def hello(ticket, role, secret):
    """53 bytes: NRU2 | ticket(16) | role(1) | SHA-256(secret)(32)."""
    return b"NRU2" + ticket + bytes([role]) + hashlib.sha256(secret).digest()


def cookie(peer, hello_):
    peer.send(hello_)
    reply = peer.recv(65535)
    assert reply[:4] == b"NRC2" and len(reply) == 20, reply
    assert len(reply) <= len(hello_), "challenge larger than Hello"
    return reply[4:]


def signed(peer, ticket, role, secret, previous=b""):
    """Cookie round trip, then a 69-byte registration (85 with a previous secret)."""
    h = hello(ticket, role, secret)
    return h + cookie(peer, h) + previous


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=3479)
    args = parser.parse_args()
    ticket = secrets.token_bytes(16)
    s_a, s_b, s_a2 = (secrets.token_bytes(16) for _ in range(3))
    notice = b"NRA2" + ticket
    family = socket.getaddrinfo(args.host, args.port, type=socket.SOCK_DGRAM)[0]
    peers = [socket.socket(family[0], socket.SOCK_DGRAM) for _ in range(4)]
    a, b, moved, spoof = peers
    try:
        for peer in peers:
            peer.settimeout(5)
            peer.connect(family[4])

        h = hello(ticket, 0, s_a)
        cookie(spoof, h)
        for bad in (h[:52], h + b"\x00", h[:20] + b"\x02" + h[21:], b"NRU1" + h[4:21]):
            spoof.send(bad)
        silent(spoof, "malformed Hello")
        print("PASS: 20-byte challenge for a 53-byte Hello; malformed control ignored")

        captured = signed(a, ticket, 0, s_a)
        for forged in (captured[53:], bytes(16), secrets.token_bytes(16)):
            spoof.send(captured[:53] + forged)
        spoof.send(b"payload from an unvalidated source")
        silent(spoof, "spoofed registration")
        a.send(captured)
        silent(a, "pending registration")
        b.send(signed(b, ticket, 1, s_b))
        assert a.recv(65535) == notice + b"\x00"
        assert b.recv(65535) == notice + b"\x01"
        silent(spoof, "spoofed source after pairing")
        print("PASS: transplanted/forged cookies allocate nothing; "
              "validated peers paired (2 x 21-byte notices for a 69-byte request)")

        for size in (1, 1200, 4096):
            payload = secrets.token_bytes(size)
            a.send(payload)
            assert b.recv(65535) == payload
            b.send(payload)
            assert a.recv(65535) == payload
        print("PASS: 1, 1200 and 4096 bytes forwarded verbatim in both directions")

        moved.send(captured)
        moved.send(captured + s_a)
        silent(moved, "replayed registration")
        moved.send(signed(moved, ticket, 0, s_a))
        silent(moved, "fresh cookie without secret")
        moved.send(signed(moved, ticket, 0, s_a2, secrets.token_bytes(16)))
        silent(moved, "wrong secret")
        b.send(b"still original")
        assert a.recv(65535) == b"still original"
        print("PASS: replayed registration, and fresh cookie without the secret, cannot rebind")

        rebind = signed(moved, ticket, 0, s_a2, s_a)
        moved.send(rebind)
        assert moved.recv(65535) == notice + b"\x00"
        b.send(b"rebound ciphertext")
        assert moved.recv(65535) == b"rebound ciphertext"
        moved.send(b"from rebound")
        assert b.recv(65535) == b"from rebound"
        a.send(b"stale source")
        silent(b, "stale source")
        print("PASS: rebind with fresh cookie + previous secret; stale source dropped")

        spoof.send(rebind)
        spoof.send(signed(spoof, ticket, 0, s_a2, s_a))
        spoof.send(signed(spoof, ticket, 0, secrets.token_bytes(16), s_a))
        silent(spoof, "replayed rebind")
        a.send(signed(a, ticket, 0, secrets.token_bytes(16), s_a))
        silent(a, "old address with spent secret")
        b.send(b"replay rejected")
        assert moved.recv(65535) == b"replay rejected"
        print("PASS: replayed rebind (spent secret) rejected from any other address")
    finally:
        for peer in peers:
            peer.close()


if __name__ == "__main__":
    main()
