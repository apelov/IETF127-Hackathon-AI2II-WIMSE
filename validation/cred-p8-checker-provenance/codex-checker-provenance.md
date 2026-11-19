Local paths redacted; no other change.
# Codex Cred P8 checker provenance

- Date `2026-11-18` (America/New_York)
- Model — Codex based on GPT-6; exact model ID not exposed by the runtime
- Installed ChatGPT macOS app version `26.1111.21308` (build `27194`), read from `/Applications/ChatGPT.app/Contents/Info.plist`
- SHA-256 of `checkers/observes_cred_p8.py` — `6facb48398e57f080f86051767d2fd969847cb91fd64f1d3be3dfa673c08cebd`

## Original prompt

```text
Write an independent capture checker for this repository. You are the sole author of its logic.\

Do NOT open or read: checkers/cred_p8_dev.py, checkers/cred_p8_assertions/, any existing\
checkers/observes_cred_p8.py, or validation/cred-p8-checker-provenance/. They are earlier\
attempts by other model families and reading them would break the independence rule.\

Read: workpackages/WP10-cred-p8-on-the-wire.md (sections "What runs" and "What the checker\
asserts"), cred_p8_cases.json, scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json,\
scenarios/p1_p8/cred-P8.manifest.json (reason_mapping and reason_mapping_note; the mapping is\
partial and token-not-released is the runner's name for 403 raw_token_disabled), and\
checkers/observes_p1_p8.py for how this repo calls tshark.\

Deliver one file, checkers/observes_cred_p8.py: takes a pcap path, uses tshark, checks the six\
assertions in WP10 from packets only, prints one line per assertion, exits 0 only if all hold,\
non-zero otherwise and on an empty or unreadable capture. Note that the permission grant\
(POST /admin/permissions on :5065 and :5066) carries no X-Test-Case header.\

Test it yourself with .venv/bin/python:\
\- must exit 0 on <scratch>/cred-p8.pcap\
\- must exit non-zero on each of checkers/negatives/cred_p8\_{unrelated,request_only,no_provider,mock_status,bearer_mismatch}.pcap,\
&#x20; each for its intended reason (mock_status: the refused use after revocation answered 403\
&#x20; instead of 401; bearer_mismatch: the direct provider call carries a token other than the one\
&#x20; released).\
Never edit a pcap or weaken an assertion to get a pass. If a mutant cannot be told apart from\
the real capture, say so.\

Do not touch any other file. Do not commit, push or open anything. When done, print a table of\
file, exit code and deciding line, and state your exact model name and version.
```

## Files read

- `workpackages/WP10-cred-p8-on-the-wire.md` (the “What runs” and “What the checker asserts” sections)
- `cred_p8_cases.json`
- `scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json`
- `scenarios/p1_p8/cred-P8.manifest.json` (`reason_mapping` and `reason_mapping_note` during authoring, `reason_mapping` at runtime)
- `checkers/observes_p1_p8.py`
- `<scratch>/cred-p8.pcap`
- `checkers/negatives/cred_p8_unrelated.pcap`
- `checkers/negatives/cred_p8_request_only.pcap`
- `checkers/negatives/cred_p8_no_provider.pcap`
- `checkers/negatives/cred_p8_mock_status.pcap`
- `checkers/negatives/cred_p8_bearer_mismatch.pcap`
- `<scratch>/wire-capture-probe.pcap` (zero-packet test)
- `checkers/observes_cred_p8.py` (newly authored file, executed and hashed after writing)
- `/Applications/ChatGPT.app/Contents/Info.plist` (app version and build fields)

## Final test results

Each run used `.venv/bin/python -B checkers/observes_cred_p8.py <capture>`. All six assertions passed on the reference capture.

| File | Exit code | Deciding line |
|---|---:|---|
| `cred-p8.pcap` | 0 | `PASS 6 provider requests and released bearer` |
| `cred_p8_unrelated.pcap` | 1 | `FAIL 2 tagged HTTP steps — no P8 step requests in capture` |
| `cred_p8_request_only.pcap` | 1 | `FAIL 2 tagged HTTP steps — P8CRED_no-delegation_use-without-delegation has no matched final HTTP response` |
| `cred_p8_no_provider.pcap` | 1 | `FAIL 6 provider requests and released bearer — provider saw 0 requests, expected 2` |
| `cred_p8_mock_status.pcap` | 1 | `FAIL 4 A revocation before use — A use after revocation returned HTTP 403, expected 401` |
| `cred_p8_bearer_mismatch.pcap` | 1 | `FAIL 6 provider requests and released bearer — direct provider bearer differs from the bearer released by configuration B` |
| `wire-capture-probe.pcap` (0 packets) | 1 | `FAIL 2 tagged HTTP steps — no P8 step requests in capture` |
| `/dev/null/cred-p8.pcap` (unreadable path) | 1 | `FAIL 1 read-only permission grants — capture unreadable or tshark failed to decode it` |
