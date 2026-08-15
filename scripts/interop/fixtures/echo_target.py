#!/usr/bin/env python3
"""Deterministic TCP echo fixture for WarpTweet interop Phase A.

Listens on 127.0.0.1:PORT, reads one connection, echoes all bytes until EOF,
then closes. Not a production service.
"""

from __future__ import annotations

import argparse
import socket
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="WarpTweet interop echo target")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--once", action="store_true", help="serve one connection and exit")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.listen(1)
    # Ready marker for orchestrator probes.
    print(f"echo-target ready {args.bind}:{args.port}", flush=True)

    while True:
        conn, _addr = sock.accept()
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        if args.once:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
