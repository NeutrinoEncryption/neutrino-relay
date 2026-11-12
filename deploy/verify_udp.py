#!/usr/bin/env python3
"""Verify public UDP pairing/forwarding without any Neutrino client dependencies."""
import argparse
import secrets
import socket

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("host")
parser.add_argument("--port", type=int, default=3479)
args = parser.parse_args()
ticket = secrets.token_bytes(16)
registration = b"NRU1" + ticket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
    for peer in (a, b):
        peer.settimeout(5)
        peer.connect((args.host, args.port))
    a.send(registration + b"\x00")
    b.send(registration + b"\x01")
    assert a.recv(65535) == registration + b"\x00", "incorrect role-0 notice"
    assert b.recv(65535) == registration + b"\x01", "incorrect role-1 notice"
    print("PASS: both UDP clients paired")
    for size in (1, 1200, 4096):
        payload = secrets.token_bytes(size)
        a.send(payload)
        assert b.recv(65535) == payload, "A -> B mismatch"
        b.send(payload)
        assert a.recv(65535) == payload, "B -> A mismatch"
        print(f"PASS: {size} bytes forwarded verbatim in both directions")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebound:
        rebound.settimeout(5)
        rebound.connect((args.host, args.port))
        rebound.send(registration + b"\x00")
        assert rebound.recv(65535) == registration + b"\x00"
        b.send(b"rebound ciphertext")
        assert rebound.recv(65535) == b"rebound ciphertext"
        a.send(b"stale source")
        b.settimeout(0.5)
        try:
            b.recv(65535)
        except socket.timeout:
            pass
        else:
            raise AssertionError("old source still forwards")
        print("PASS: NAT rebinding replaces old address; stale ciphertext dropped")
