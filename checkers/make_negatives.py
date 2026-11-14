"""Derive three capture mutants from a real WIMSE run (classic DLT_NULL pcap)."""
import argparse
import pathlib
import struct
import subprocess
import time

HERE = pathlib.Path(__file__).parent
OUT = HERE / "negatives"


def add_forbidden_fetch(source, target):
    data = source.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1" or struct.unpack_from("<I", data, 20)[0] != 0:
        raise ValueError("expected little-endian classic pcap with DLT_NULL")
    source_ip = bytes((127, 0, 0, 1))
    dest_ip = source_ip
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0, source_ip, dest_ip)
    tcp = struct.pack("!HHIIHHHH", 40000, 47999, 1, 0, 0x5002, 65535, 0, 0)
    frame = struct.pack("<I", 2) + ip + tcp
    now = time.time()
    record = struct.pack("<IIII", int(now), int((now % 1) * 1_000_000), len(frame), len(frame))
    target.write_bytes(data + record + frame)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=pathlib.Path)
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    subprocess.run(["editcap", "-r", str(args.capture), str(OUT / "unrelated.pcap"), "1-3"], check=True)
    subprocess.run(["tshark", "-r", str(args.capture), "-Y", "tcp.srcport != 5050",
                    "-w", str(OUT / "request_only.pcap")], check=True)
    add_forbidden_fetch(args.capture, OUT / "forbidden_fetch.pcap")
    for name in ("unrelated", "request_only", "forbidden_fetch"):
        print(name, (OUT / f"{name}.pcap").stat().st_size)


if __name__ == "__main__":
    main()
