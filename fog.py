#!/usr/bin/env python3
"""
fog.py

- Binds to UDP port 5005.
- Receives encrypted AES-GCM messages from edge scripts (pole1, pole2, pole3).
- Decrypts each message and prints the plaintext JSON (including pole_id).
"""

import socket
import json
from Crypto.Cipher import AES

# AES-GCM uses same 16-byte key as all edges:
KEY = b'0123456789abcdef'
BUFFER_SIZE = 4096  # should be large enough for nonce||tag||ciphertext

def decrypt_message(data):
    """
    Data format = nonce (16 bytes) || tag(16 bytes) || ciphertext
    Returns decrypted JSON object (as Python dict).
    """
    nonce = data[:16]
    tag   = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext.decode('utf-8'))

def run_fog():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 5005))
    print("[fog] Listening on UDP port 5005 for encrypted edge reports…")

    try:
        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            try:
                report = decrypt_message(data)
                pole = report.get("pole_id", "UNKNOWN")
                print(f"[fog] Received from {pole}: {report}")
            except Exception as e:
                print(f"[fog] Decryption or parsing error: {e}")
    except KeyboardInterrupt:
        print("\n[fog] Stopped by user.")
    finally:
        sock.close()

if __name__ == "__main__":
    run_fog() 