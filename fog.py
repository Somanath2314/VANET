#!/usr/bin/env python3
"""
fog.py:
  - Binds to UDP port 5005 
  - Receives encrypted reports from edge via UDP
  - Decrypts with AES-GCM (same key as edge.py)
  - Prints the JSON traffic counts to console
"""

import socket
import json
from Crypto.Cipher import AES

# Same 16-byte key as in edge.py
KEY = b'0123456789abcdef'

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

def decrypt_report(data):
    """
    Given data = nonce (16 bytes) || tag (16 bytes) || ciphertext,
    attempt to decrypt with AES-GCM and return the JSON string.
    """
    nonce = data[:16]
    tag   = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption/verification failed: {e}"

def print_traffic_status(report):
    """Print a formatted traffic status report"""
    print("\n" + "="*50)
    print(f"Time Step: {report['timestep']}")
    print("-"*50)
    print("Vehicle Counts:")
    print(f"  North: {report['north_count']}")
    print(f"  South: {report['south_count']}")
    print(f"  East:  {report['east_count']}")
    print(f"  West:  {report['west_count']}")
    print("-"*50)
    print(f"Current Phase: {report['current_phase']}")
    print("="*50 + "\n")

def run_fog():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Fog: Listening on UDP {UDP_IP}:{UDP_PORT} ...")
    print("Waiting for encrypted traffic data from edge...")

    while True:
        data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
        report_json = decrypt_report(data)
        try:
            report = json.loads(report_json)
            print_traffic_status(report)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON received: {report_json}")

if __name__ == "__main__":
    run_fog() 