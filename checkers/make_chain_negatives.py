"""Derive three capture mutants from a valid multi-hop WIMSE chain run."""
import argparse
import pathlib
import struct
import subprocess
import time

HERE = pathlib.Path(__file__).parent
OUT = HERE / "negatives"


def add_leaked_txn(source: pathlib.Path, target: pathlib.Path):
    data = source.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1" or struct.unpack_from("<I", data, 20)[0] != 0:
        raise ValueError("expected little-endian classic pcap with DLT_NULL")
    # Build a synthetic HTTP request to port 5062 carrying a leaked Domain A Txn-Token
    # Header: {"alg":"ES256","typ":"txntoken+jwt"} -> eyJhbGciOiJFUzI1NiIsInR5cCI6InR4bnRva2VuK2p3dCJ9
    # Payload: {"aud":"maurice.ietf127.example","txn":"leaked"} -> eyJhdWQiOiJtYXVyaWNlLmlldGYxMjcuZXhhbXBsZSIsInR4biI6ImxlYWtlZCJ9
    leaked_jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6InR4bnRva2VuK2p3dCJ9.eyJhdWQiOiJtYXVyaWNlLmlldGYxMjcuZXhhbXBsZSIsInR4biI6ImxlYWtlZCJ9.c2ln"
    http_payload = (
        f"POST /research HTTP/1.1\r\n"
        f"Host: 127.0.0.1:5062\r\n"
        f"X-Test-Case: B_CHAIN\r\n"
        f"Txn-Token: {leaked_jwt}\r\n"
        f"Content-Length: 2\r\n\r\n{{}}"
    ).encode("ascii")
    source_ip = bytes((127, 0, 0, 1))
    dest_ip = source_ip
    total_len = 40 + len(http_payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0x4000, 64, 6, 0, source_ip, dest_ip)
    tcp = struct.pack("!HHIIHHHH", 41234, 5062, 1, 1, 0x5018, 65535, 0, 0)
    frame = struct.pack("<I", 2) + ip + tcp + http_payload
    now = time.time()
    record = struct.pack("<IIII", int(now), int((now % 1) * 1_000_000), len(frame), len(frame))
    target.write_bytes(data + record + frame)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=pathlib.Path)
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    subprocess.run(
        ["editcap", "-r", str(args.capture), str(OUT / "chain_unrelated.pcap"), "1-3"],
        check=True,
    )
    subprocess.run(
        [
            "tshark",
            "-r",
            str(args.capture),
            "-Y",
            "not (tcp.srcport in {5050,5051,5060,5061,5062,5063} and http.response)",
            "-w",
            str(OUT / "chain_request_only.pcap"),
        ],
        check=True,
    )
    add_leaked_txn(args.capture, OUT / "chain_leaked_txn.pcap")
    for name in ("chain_unrelated", "chain_request_only", "chain_leaked_txn"):
        print(name, (OUT / f"{name}.pcap").stat().st_size)


if __name__ == "__main__":
    main()
