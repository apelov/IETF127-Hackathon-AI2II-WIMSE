#!/usr/bin/env python3
"""Generate three negative mutant captures for observes_payment.py per AI2II Rule L4.

Mutants:
1. payment_unrelated.pcap: loopback traffic with no port 5070 payment exchange.
2. payment_request_only.pcap: valid payment request sent, but no 200 response from Northbank.
3. payment_tampered_digest.pcap: request sent without required WIMSE WIT / signature.
"""
import argparse
import pathlib
import struct
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
NEGATIVES_DIR = ROOT / "checkers" / "negatives"


def make_pcap(path: pathlib.Path, packets: list[tuple[int, int, int, int, int, bytes, float]], sport: int = 5070):
    global_hdr = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 0)
    raw_pkts = []
    t0 = time.time()
    for src_port, dst_port, seq, ack, flags, payload, dt in packets:
        src_ip = bytes((127, 0, 0, 1))
        dst_ip = bytes((127, 0, 0, 1))
        tcp_hdr = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, (5 << 4), flags, 65535, 0, 0)
        ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40 + len(payload), 0, 0x4000, 64, 6, 0, src_ip, dst_ip)
        frame = struct.pack('<I', 2) + ip_hdr + tcp_hdr + payload
        t = t0 + dt
        rec_hdr = struct.pack('<IIII', int(t), int((t % 1) * 1_000_000), len(frame), len(frame))
        raw_pkts.append(rec_hdr + frame)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(global_hdr + b"".join(raw_pkts))


def main():
    NEGATIVES_DIR.mkdir(parents=True, exist_ok=True)

    # 1. payment_unrelated.pcap: Port 49999 traffic only, no port 5070
    unrelated_pkts = [
        (41111, 49999, 100, 0, 0x02, b"", 0.001),
        (49999, 41111, 200, 101, 0x12, b"", 0.002),
        (41111, 49999, 101, 201, 0x10, b"", 0.003),
    ]
    make_pcap(NEGATIVES_DIR / "payment_unrelated.pcap", unrelated_pkts)

    # 2. payment_request_only.pcap: Port 5070 request, no response
    req_body = b'{"invoice":"4471","amount":4200,"currency":"USD","to":"supplier_acme_iban_xxx","ref":"7f3a21"}'
    req_headers = (
        b"POST /api/transfer HTTP/1.1\r\n"
        b"Host: 127.0.0.1:5070\r\n"
        b"Workload-Identity-Token: dummy.wit.jwt\r\n"
        b'Signature-Input: wimse=("@method" "@path" "@query" "workload-identity-token" "txn-token" "content-type" "content-digest");tag="wimse-workload-to-workload";wimse-aud="wimse://northbank.example/api/transfer"\r\n'
        b"Signature: wimse=:dGVzdHNpZw==:\r\n"
        b"Txn-Token: 7f3a21\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(req_body)).encode() + b"\r\n\r\n" + req_body
    )
    req_only_pkts = [
        (54321, 5070, 1000, 0, 0x02, b"", 0.001),
        (5070, 54321, 2000, 1001, 0x12, b"", 0.002),
        (54321, 5070, 1001, 2001, 0x10, b"", 0.003),
        (54321, 5070, 1001, 2001, 0x18, req_headers, 0.005),
        (5070, 54321, 2001, 1001 + len(req_headers), 0x10, b"", 0.006),
        # Connection reset without response
        (5070, 54321, 2001, 0, 0x04, b"", 0.007),
    ]
    make_pcap(NEGATIVES_DIR / "payment_request_only.pcap", req_only_pkts)

    # 3. payment_tampered_digest.pcap: Request missing WIT & Signature
    bad_req = (
        b"POST /api/transfer HTTP/1.1\r\n"
        b"Host: 127.0.0.1:5070\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(req_body)).encode() + b"\r\n\r\n" + req_body
    )
    bad_resp = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
    tampered_pkts = [
        (54321, 5070, 1000, 0, 0x02, b"", 0.001),
        (5070, 54321, 2000, 1001, 0x12, b"", 0.002),
        (54321, 5070, 1001, 2001, 0x10, b"", 0.003),
        (54321, 5070, 1001, 2001, 0x18, bad_req, 0.005),
        (5070, 54321, 2001, 1001 + len(bad_req), 0x10, b"", 0.006),
        (5070, 54321, 2001, 1001 + len(bad_req), 0x18, bad_resp, 0.008),
        (54321, 5070, 1001 + len(bad_req), 2001 + len(bad_resp), 0x10, b"", 0.009),
    ]
    make_pcap(NEGATIVES_DIR / "payment_tampered_digest.pcap", tampered_pkts)

    print("Created 3 negative mutants:")
    for name in ("payment_unrelated.pcap", "payment_request_only.pcap", "payment_tampered_digest.pcap"):
        sz = (NEGATIVES_DIR / name).stat().st_size
        print(f"  {name}: {sz} bytes")


if __name__ == "__main__":
    main()
