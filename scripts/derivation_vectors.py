#!/usr/bin/env python3
"""Independent reference implementation of tenant-pass password derivation.

This script deliberately shares no code with the Go implementation. It is
used to produce the test vectors in docs/en/derivation.md and
internal/rotation/rotation_test.go, so that a bug in the Go code cannot
silently "agree with itself".

Usage: python3 -I scripts/derivation_vectors.py
"""
import base64
import hashlib
import hmac
import struct


def lp(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">I", len(b)) + b


def account(store, node, name):
    return lp(store) + lp(node) + lp(name)


def offset(store, node, name, window_s):
    h = hashlib.sha256(b"tenant-pass/v1/offset" + account(store, node, name)).digest()
    return struct.unpack(">Q", h[:8])[0] % window_s


def derive(label, secret, key_id, store, node, name, n, window_s):
    msg = (label.encode() + account(store, node, name) + lp(key_id)
           + struct.pack(">Q", window_s) + struct.pack(">q", n))
    return hmac.new(secret, msg, hashlib.sha256).digest()


def password(secret, key_id, store, node, name, n, window_s):
    d = derive("tenant-pass/v1/password", secret, key_id, store, node, name, n, window_s)
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def scram_verifier(pw: str, salt: bytes, iterations=4096):
    salted = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda x: base64.b64encode(x).decode()
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


if __name__ == "__main__":
    secret = bytes(range(32))  # 00 01 02 ... 1f
    key_id = "k1"
    window = 900
    for store, node, name in [("postgres", "pg1", "t_acme"), ("mysql", "my1", "t_acme"), ("redis", "rd1", "t_acme")]:
        off = offset(store, node, name, window)
        t = 1793707200  # 2026-11-03T12:00:00Z
        n = (t - off) // window
        pw = password(secret, key_id, store, node, name, n, window)
        salt = derive("tenant-pass/v1/salt", secret, key_id, store, node, name, n, window)
        print(f"{store}/{node}/{name}: offset={off} n={n} start={n*window+off} password={pw}")
        print(f"  salt={salt.hex()}")
        if store == "postgres":
            print(f"  scram={scram_verifier(pw, salt[:16])}")
        if store == "redis":
            print(f"  acl_hash={hashlib.sha256(pw.encode()).hexdigest()}")
