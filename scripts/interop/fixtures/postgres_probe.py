#!/usr/bin/env python3
"""Prove a WarpTweet tunnel reaches loopback Postgres. No third-party modules."""
import socket
import struct
import sys


def startup(user: str, database: str) -> bytes:
    payload = b"\x00\x03\x00\x00"
    payload += b"user\x00" + user.encode() + b"\x00"
    payload += b"database\x00" + database.encode() + b"\x00"
    payload += b"\x00"
    return struct.pack("!I", len(payload) + 4) + payload


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: postgres_probe.py host:port user database", file=sys.stderr)
        return 64
    listen, user, database = sys.argv[1], sys.argv[2], sys.argv[3]
    host, port_s = listen.rsplit(":", 1)
    sock = socket.create_connection((host, int(port_s)), timeout=8)
    try:
        sock.sendall(startup(user, database))
        header = sock.recv(5)
        if len(header) < 5:
            print("postgres probe: short greeting", file=sys.stderr)
            return 1
        # Authentication* (R) or ErrorResponse (E) both prove we reached Postgres.
        if header[0:1] not in (b"R", b"E"):
            print("postgres probe: unexpected message %r" % header[0:1], file=sys.stderr)
            return 1
        print("postgres-interop-payload-v1")
        return 0
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
