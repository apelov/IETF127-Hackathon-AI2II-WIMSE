# WP05 — Independent Multi-Hop Capture Checker & Negatives

Tier: mini-code
Inputs: workpackages/README.md, workpackages/WP04-chain-driver-and-attacks.md, chain_cases.json

Create `checkers/observes_chain.py` and `checkers/make_chain_negatives.py` to independently verify a multi-hop `capture.pcap` across Domain A (`:5050`, `:5051`) and Domain B (`:5061`, `:5062`, `:5063`), and generate 3 negative captures.

> **AI2II Independence Rule (DESIGN.md §24.20 L4):**
> Run this Work Package using a **different model family** from the one that wrote `peers/chain_driver.py` (for example, run via `claude-or --model nvidia/nemotron-3-ultra-550b-a55b:free` or Gemini if Claude/Codex built WP04).

## Why

An AI2II `PASS` bundle requires an `observes_capture: true` checker from an independent model family that inspects the raw pcap via `tshark` (without reading driver/server logs) and rejects capture negatives.

Depends on: WP04.

## Deliverables

1. Create `checkers/observes_chain.py`:
   - Decodes HTTP on TCP ports `5050, 5051, 5061, 5062, 5063` via `tshark -r <pcap> -d tcp.port==5050,http -d tcp.port==5051,http -d tcp.port==5061,http -d tcp.port==5062,http -d tcp.port==5063,http -Y http -T json` using `object_pairs_hook` to preserve duplicate keys.
   - Groups HTTP request/response pairs per `tcp.stream` and maps them to cases via `X-Test-Case`.
   - Ignores untagged readiness probes (`GET /.well-known/wimse/jwks.json` or `GET /health`).
   - Checks for each case in `chain_cases.json`:
     - Every expected hop status code matches the captured HTTP response status.
     - **Cross-domain isolation check:** scans all HTTP requests to Domain B ports (`5061`, `5062`, `5063`); if any request to Domain B carries a `Txn-Token` header whose JWT payload has `"aud": "maurice.ietf127.example"` (i.e. a leaked Domain A Txn-Token), immediately records `FAIL: Domain A Txn-Token leaked to Domain B on stream <id>` and exits non-zero.
     - **End-to-end `txn` correlation check (`B_CHAIN`):** extracts the `txn` UUID from the `TTS-A`, `AS-A`, `AS-B`, `TTS-B`, and `File Tool` JSON bodies in `B_CHAIN` and verifies they are all identical non-empty strings.
   - Prints `SUMMARY cases=<N> errors=<E>` and exits `0` iff `errors == 0`.
2. Create `checkers/make_chain_negatives.py <valid_chain.pcap>` producing 3 negative pcaps in `checkers/negatives/`:
   - `chain_unrelated.pcap`: first 3 frames via `editcap -r <pcap> checkers/negatives/chain_unrelated.pcap 1-3`.
   - `chain_request_only.pcap`: responses stripped via `tshark -r <pcap> -Y "not (tcp.srcport in {5050,5051,5061,5062,5063} and http.response)" -w checkers/negatives/chain_request_only.pcap`.
   - `chain_leaked_txn.pcap`: appends a synthetic HTTP packet to port `5062` containing a `Txn-Token` header with `"aud": "maurice.ietf127.example"`, proving `observes_chain.py` catches a cross-domain Txn-Token leak.

## Owns (touch only these)

- `checkers/observes_chain.py` — independent multi-hop pcap checker.
- `checkers/make_chain_negatives.py` — generator for the 3 negative pcaps.
- `checkers/negatives/chain_unrelated.pcap`
- `checkers/negatives/chain_request_only.pcap`
- `checkers/negatives/chain_leaked_txn.pcap`

Do **not** modify any other files.

## Constraints / invariants

- Do not import anything from `peers/`.
- Always use `object_pairs_hook` when parsing `tshark -T json` output.
- Commit locally when `Verify:` passes; never push.

## Verification

Verify: .venv/bin/python checkers/observes_chain.py /tmp/wimse-chain.pcap && ! .venv/bin/python checkers/observes_chain.py checkers/negatives/chain_unrelated.pcap && ! .venv/bin/python checkers/observes_chain.py checkers/negatives/chain_request_only.pcap && ! .venv/bin/python checkers/observes_chain.py checkers/negatives/chain_leaked_txn.pcap
