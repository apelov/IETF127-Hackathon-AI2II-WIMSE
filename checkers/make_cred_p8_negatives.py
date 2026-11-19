#!/usr/bin/env python3
"""Derive five capture mutants from a real cred-p8 capture (ports 5065, 5066, 5067).

Standard library only (no editcap or tshark). Every mutant is the real capture with packets removed
or with a same-length edit of one packet, so TCP sequence numbers stay consistent.

    python3 checkers/make_cred_p8_negatives.py <capture.pcap>

  cred_p8_unrelated.pcap        first three packets only
  cred_p8_request_only.pcap     every packet sent by a server port removed
  cred_p8_no_provider.pcap      every packet to or from the provider (:5067) removed
  cred_p8_mock_status.pcap      the refused use after revocation answered 403 instead of Cred's 401
                                (the fixed-answer mock's status)
  cred_p8_bearer_mismatch.pcap  the direct provider call presents a token other than the released one
"""
import argparse
import pathlib
import re

import cred_p8_dev as chk

OUT = pathlib.Path(__file__).parent / "negatives"


def write(name, header, records):
    path = OUT / name
    path.write_bytes(header + b"".join(h + p for h, p in records))
    print(name, path.stat().st_size)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=pathlib.Path)
    args = ap.parse_args()
    header, linktype, _, records = chk.read_pcap(args.capture)
    decoded = [chk.decode_tcp(linktype, p) for _, p in records]
    OUT.mkdir(exist_ok=True)

    write("cred_p8_unrelated.pcap", header, records[:3])
    write("cred_p8_request_only.pcap", header,
          [r for r, d in zip(records, decoded) if d is None or d[1] not in chk.SERVER_PORTS])
    write("cred_p8_no_provider.pcap", header,
          [r for r, d in zip(records, decoded) if d is None or chk.PORT_PROVIDER not in (d[1], d[3])])

    def edited(match, edit, what):
        out, hits = [], 0
        for (rec_hdr, pkt), d in zip(records, decoded):
            if d is not None and match(d):
                start, payload = d[6], d[7]
                new = edit(payload)
                assert len(new) == len(payload) and new != payload, what
                pkt = pkt[:start] + new + pkt[start + len(new):]
                hits += 1
            out.append((rec_hdr, pkt))
        if hits != 1:
            raise SystemExit(f"{what}: expected to edit exactly one packet, edited {hits}")
        return out

    write("cred_p8_mock_status.pcap", header, edited(
        lambda d: d[1] == chk.PORT_A and d[7].startswith(b"HTTP/1.1 401") and b'"delegation_revoked"' in d[7],
        lambda p: b"HTTP/1.1 403" + p[12:],
        "use-after-revoke response"))

    bearer = re.compile(rb"(?i)(authorization: Bearer )(\S)")
    write("cred_p8_bearer_mismatch.pcap", header, edited(
        lambda d: d[3] == chk.PORT_PROVIDER and b"P8CRED_revoked-after-token-released_direct-provider-call" in d[7]
        and bearer.search(d[7]) is not None,
        lambda p: bearer.sub(lambda m: m.group(1) + (b"X" if m.group(2) != b"X" else b"Y"), p, count=1),
        "direct provider call request"))


if __name__ == "__main__":
    main()
