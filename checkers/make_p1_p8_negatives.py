"""Derive three capture mutants from a live P2/P7/P8 run on port 5064."""
import argparse
import pathlib
import subprocess

HERE = pathlib.Path(__file__).parent
OUT = HERE / "negatives"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=pathlib.Path)
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    # 1. Unrelated / truncated 3-frame pcap
    subprocess.run(
        ["editcap", "-r", str(args.capture), str(OUT / "p1_p8_unrelated.pcap"), "1-3"],
        check=True,
    )
    # 2. Request-only (responses from port 5064 stripped)
    subprocess.run(
        [
            "tshark",
            "-r",
            str(args.capture),
            "-Y",
            "tcp.srcport != 5064",
            "-w",
            str(OUT / "p1_p8_request_only.pcap"),
        ],
        check=True,
    )
    # 3. Missing P2_before-effect case (first 20 frames only)
    subprocess.run(
        [
            "editcap",
            "-r",
            str(args.capture),
            str(OUT / "p1_p8_missing_before_effect.pcap"),
            "1-20",
        ],
        check=True,
    )
    for name in ("p1_p8_unrelated", "p1_p8_request_only", "p1_p8_missing_before_effect"):
        print(name, (OUT / f"{name}.pcap").stat().st_size)


if __name__ == "__main__":
    main()
