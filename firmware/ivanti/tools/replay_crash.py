#!/usr/bin/env python3
"""
Crash replay tool for IFT-TLS multi-packet fuzzing.

Prefix packets are read from strategy.txt (same format as the agent),
so switching targets only requires a different config file.

Usage:
  python3 replay_crash.py crash.bin
  python3 replay_crash.py -s config/strategy.txt crash.bin
  python3 replay_crash.py --single crash.bin
  python3 replay_crash.py --raw 00000a4c...
  python3 replay_crash.py -t 192.168.1.100 -p 1443 crash.bin
"""

import sys
import socket
import ssl
import struct
import argparse
import binascii


def load_strategy(path):
    """Parse agent strategy.txt, return list of (label, data) prefix packets."""
    prefixes = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            key, val = parts
            if key == "PREFIX_HEX":
                data = binascii.unhexlify(val)
                prefixes.append((f"PREFIX_HEX ({len(data)} bytes)", data))
            elif key == "PREFIX_FILE":
                with open(val, "rb") as pf:
                    data = pf.read()
                prefixes.append((f"PREFIX_FILE {val} ({len(data)} bytes)", data))
    return prefixes


def load_payload(args):
    if args.raw:
        return None, binascii.unhexlify(args.raw)
    with open(args.payload, "rb") as f:
        return args.payload, f.read()


def tls_connect(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if port == 443:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.connect((host, port))
    else:
        sock.connect((host, port))
        ssock = sock
    return ssock


def send_and_recv(ssock, data, label):
    print(f"[*] {label} ({len(data)} bytes)", end="")
    ssock.send(data)
    try:
        resp = ssock.recv(4096)
        print(f" -> {len(resp)} bytes")
        if resp:
            if len(resp) < 200:
                print(f"    {resp[:200]}")
            else:
                print(f"    {resp.hex()[:160]}...")
    except socket.timeout:
        print(" -> timeout")
    except Exception as e:
        print(f" -> {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE-2025-22457 Crash Replay")
    parser.add_argument("payload", nargs="?",
                        help="Crash payload file (kAFL corpus/crash/)")
    parser.add_argument("-s", "--strategy", default="config/strategy.txt",
                        help="Path to strategy.txt (default: config/strategy.txt)")
    parser.add_argument("--prefix", action="append", metavar="HEX", default=[],
                        help="Extra prefix hex (repeatable, sent before file prefixes)")
    parser.add_argument("-t", "--target", default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("-T", "--timeout", type=int, default=10)

    g = parser.add_mutually_exclusive_group()
    g.add_argument("--single", action="store_true",
                   help="Single-packet: crash payload only, no prefixes")
    g.add_argument("--raw", metavar="HEX",
                   help="Send raw hex instead of reading a file")

    args = parser.parse_args()

    if not args.payload and not args.raw:
        parser.error("must specify payload file or --raw HEX")

    # --- Load payload ---
    path, crash_data = load_payload(args)
    if path:
        print(f"[+] Payload: {path} ({len(crash_data)} bytes)")
    else:
        print(f"[+] Payload: raw hex ({len(crash_data)} bytes)")

    if len(crash_data) >= 4:
        ift_type = struct.unpack(">I", crash_data[:4])[0]
        print(f"[+] IFT type: 0x{ift_type:08X}")

    # --- Load prefix packets ---
    prefixes = [(f"--prefix #{i+1}", binascii.unhexlify(h))
                for i, h in enumerate(args.prefix)]

    if not args.single and not args.raw:
        try:
            file_prefixes = load_strategy(args.strategy)
            prefixes.extend(file_prefixes)
            print(f"[+] Loaded {len(file_prefixes)} prefixes from {args.strategy}")
        except FileNotFoundError:
            print(f"[!] Strategy not found: {args.strategy}, no prefixes loaded")

    # --- Connect and send ---
    ssock = tls_connect(args.target, args.port, args.timeout)
    print(f"[*] Connected to {args.target}:{args.port}")

    phase = 0
    for label, data in prefixes:
        phase += 1
        send_and_recv(ssock, data, f"Phase {phase}: {label}")

    # Final phase: crash payload
    phase += 1
    label = f"Phase {phase}: crash payload" if prefixes else "Crash payload"
    send_and_recv(ssock, crash_data, label)

    ssock.close()
    print("[+] Done")
