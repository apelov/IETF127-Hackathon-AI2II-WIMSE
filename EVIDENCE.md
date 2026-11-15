# WIMSE Interop Evidence Catalog (`EVIDENCE.md`)

This catalog indexes every committed packet capture (`.pcap`), decision journal (`.jsonl`), partner trace manifest (`.json`), and AI2II verification bundle (`validation/bundle-*/`) in the repository, along with their exact SHA-256 digests and one-line inspection commands.

All artifacts listed below contain **zero private keys or secrets** (`"contains_secrets": false` in every `verdict.json`, verified by `./reproduce.sh`).

---

## 1. AI2II Verification Summary & Independent Reviews

Running `PYTHONPATH=. .venv/bin/python -m wire summarize validation` produces:

```text
PASS	inbound	458453327d36	validation/bundle-inbound/inbound
PASS	chain	8f8441e4af00	validation/bundle-chain/chain
PASS	payment	opena2a-wims	validation/bundle-payment/payment
```

| Cell | Verdict | Bundle Path | `verdict.json` SHA-256 | Independent Audit Report | Secrets Present? |
|---|---|---|---|---|---|
| `inbound` | **PASS** | [`validation/bundle-inbound/inbound/`](validation/bundle-inbound/inbound/) | `1d342023567c6f53994ebee7fd6a33225f4018782c840c6fcb14d36617caed2d` | [`validation/nemotron-review.md`](validation/nemotron-review.md) (`nvidia/nemotron-3-ultra-550b-a55b:free`) | `false` |
| `chain` | **PASS** | [`validation/bundle-chain/chain/`](validation/bundle-chain/chain/) | `937ea8a9728c6d35d79535eeab4603b97a269900a312dc75601e9b472f364d44` | [`validation/nemotron-p1-p8-review.md`](validation/nemotron-p1-p8-review.md) (`nvidia/nemotron-3-ultra-550b-a55b:free`) · [`validation/gemini-p1-p8-review.md`](validation/gemini-p1-p8-review.md) (`gemini-4-argon`) · [`validation/opus-chain-review.md`](validation/opus-chain-review.md) (`claude -p --model opus`) | `false` |
| `payment` | **PASS** | [`validation/bundle-payment/payment/`](validation/bundle-payment/payment/) | `adf295230ba85f27c9bc0a396775a629c86e0dbb568cbd37bc783003b903a8b7` | [`handover/aep/aep_verification_report.md`](handover/aep/aep_verification_report.md) (AEP Prototype Offline Verifier - Internal Simulation) · [`checkers/observes_payment.py`](checkers/observes_payment.py) (Independent L4 Wire Checker) | `false` |

---

## 2. Committed Packet Captures (`.pcap`)

### 2.1 Live Passing Captures

| Capture File | Cell / Scope | Total Packets | HTTP Messages | SHA-256 Digest | `tshark` / Wireshark Inspection Command |
|---|---|---:|---:|---|---|
| [`validation/bundle-inbound/inbound/capture.pcap`](validation/bundle-inbound/inbound/capture.pcap) | Suite 1: 34 WIMSE inbound cases (`A2–A13j`, `C2–C12b`, `IN4–IN15`) on loopback `:5050` & `:47999` | 536 | 72 | `85442bc4bb3051bcdcad88e63aebc0fb47502c062dac52c6c6da3cad344cad56` | `tshark -X lua_script:dissectors/wimse.lua -r validation/bundle-inbound/inbound/capture.pcap -Y http` |
| [`validation/bundle-chain/chain/capture.pcap`](validation/bundle-chain/chain/capture.pcap) | Suite 2 & 3: 19 3-agent cross-domain call-chain cases (`:5050–5063`) + 10 live `P2/P7/P8` cases (`:5064`) | 824 | 106 (53 exchanges; 104 with default `tshark -Y http`) | `fdad7743ec8a69288cef24bfccab1a2740a2f10e8b7063d2426fdbe067f2ca88` | `tshark -X lua_script:dissectors/wimse.lua -r validation/bundle-chain/chain/capture.pcap -Y 'wimse.test_case == "B_CHAIN"' -O wimse` |
| [`validation/bundle-payment/payment/capture.pcap`](validation/bundle-payment/payment/capture.pcap) (and [`handover/wimse_ai2ii/capture_scenario1.pcap`](handover/wimse_ai2ii/capture_scenario1.pcap)) | Suite 4: Harbor -> Northbank cross-domain WIMSE payment (`POST /api/transfer` on `:5070`) | 7 | 2 (1 full HTTP request/response exchange) | `5137fd90c2236088d563eb3d89ed89a65858f07249415c3ed8a38d90edbac3a5` | `tshark -r validation/bundle-payment/payment/capture.pcap -Y http` |

### 2.2 Negative Mutant Captures (Rejected by Independent Checkers)

Every independent checker is verified to exit non-zero on each of its negative PCAP mutants:

| Negative PCAP File | Target Checker | Mutation / Violation Tested | Total Packets | SHA-256 Digest |
|---|---|---|---:|---|
| [`checkers/negatives/unrelated.pcap`](checkers/negatives/unrelated.pcap) | `observes_wimse.py` | Non-WIMSE traffic (no WIMSE test cases present) | 3 | `812b677b805c51b9a40aae31b32d95c5d8b79bd18c523538244400dbb733c547` |
| [`checkers/negatives/request_only.pcap`](checkers/negatives/request_only.pcap) | `observes_wimse.py` | Client requests only (all server HTTP responses stripped) | 245 | `d49f72ef4103cd28d80e91a2436b609328827fdc45f8c33d7a2cbc7403090b8b` |
| [`checkers/negatives/forbidden_fetch.pcap`](checkers/negatives/forbidden_fetch.pcap) | `observes_wimse.py` | Contains forbidden outbound SSRF fetch to port `47999` during `C12`/`C12b` | 491 | `dd1d79aff9f43523f9e0d43afa832815ac5237db3375c8ca7e2fbd8669aab07d` |
| [`checkers/negatives/chain_unrelated.pcap`](checkers/negatives/chain_unrelated.pcap) | `observes_chain.py` | Non-WIMSE traffic (missing `B_CHAIN` and negative cases) | 3 | `269ec353898c3c9b2cf2a899da3b03cf55c347f11c47c069e5375426ebd214f0` |
| [`checkers/negatives/chain_request_only.pcap`](checkers/negatives/chain_request_only.pcap) | `observes_chain.py` | Request packets only (HTTP responses stripped across `:5050–5063`) | 522 | `ba162791ce3a5977e5cc481dd62861d56143fc9991799a0ded79f342ac044d91` |
| [`checkers/negatives/chain_leaked_txn.pcap`](checkers/negatives/chain_leaked_txn.pcap) | `observes_chain.py` | Domain A internal `Txn-Token` (`aud = "maurice.ietf127.example"`, `txn = "leaked"`) injected onto Domain B port `:5062` (`POST /research`, stream 41) during `B_CHAIN` | 563 | `9762aeb45ba25e6ff6aac692bf26ac1cfc0af6e20126cd1b5c73d9ff1b796c7e` |
| [`checkers/negatives/p1_p8_unrelated.pcap`](checkers/negatives/p1_p8_unrelated.pcap) | `observes_p1_p8.py` | Non-WIMSE traffic on loopback | 3 | `1281856404dbd4572ae0de3970160c91d5458493fa2239c7134f566e23c51fe3` |
| [`checkers/negatives/p1_p8_request_only.pcap`](checkers/negatives/p1_p8_request_only.pcap) | `observes_p1_p8.py` | `P2/P7/P8` requests on `:5064` with all HTTP responses stripped | 70 | `cb3bbef9651ff7199b3f9c3b317474aa218ffa78fb9f5d8034b35ebbdd5b5975` |
| [`checkers/negatives/p1_p8_missing_before_effect.pcap`](checkers/negatives/p1_p8_missing_before_effect.pcap) | `observes_p1_p8.py` | Truncated to frames 1–20 so `P2_before-effect` response and `P2_outside-made-up-proof` / `P2_outside-no-agent-answer` before-effect revocation checks are missing | 20 | `726aef5de0bbd2ed2730abe582719f7ae926ad0c74a54f3dde5b4b0c582f6913` |
| [`checkers/negatives/payment_unrelated.pcap`](checkers/negatives/payment_unrelated.pcap) | `observes_payment.py` | Non-payment traffic on loopback (no HTTP on port 5070) | 3 | `4d0fb85b5d12272031126f252573033c8396cb8eec4b6b35c3e3ae22973730ef` |
| [`checkers/negatives/payment_request_only.pcap`](checkers/negatives/payment_request_only.pcap) | `observes_payment.py` | Cross-domain payment request only; Northbank 200 OK settlement response stripped | 6 | `6a64f8737704ed12394cc58eb69e822dcdb3b2e66680dc1df1d8afb90b5ca745` |
| [`checkers/negatives/payment_tampered_digest.pcap`](checkers/negatives/payment_tampered_digest.pcap) | `observes_payment.py` | Request missing mandatory WIMSE WIT token and RFC 9421 signature | 7 | `d1615b5e927b7468aa67c346fa3dbff3489b69d085f5abcc785a933e44ddd920` |

---

## 3. Committed Decision Journals, Scenario Specs & Partner Traces

### 3.1 Runtime Decision Journals (`.jsonl`)

| File | Description | Lines | SHA-256 Digest |
|---|---|---:|---|
| [`validation/bundle-inbound/inbound/decision-journal.jsonl`](validation/bundle-inbound/inbound/decision-journal.jsonl) | AgentMaurice WIMSE inbound verifier decision journal across the 34 Suite 1 cases | 35 | `161c5d1658c6bca8827ee28fa786584e4e46172b9c0cea5eb2914772747e4b13` |
| [`validation/bundle-chain/chain/chain-journal.jsonl`](validation/bundle-chain/chain/chain-journal.jsonl) | Domain A + Domain B + `P2/P7/P8` structured decision journal across Suite 2 & Suite 3 | 38 | `77cb4ac70ce75d7091d11db541954ef13e1443a0a0a3016e7a8abd2fac47f974` |

### 3.2 Partner Scenario Definitions, Traces & Manifests (`scenarios/p1_p8/`)

For background context on how these partner artifacts were coordinated and cross-verified during the IETF 127 Hackathon, see [`scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md`](scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md).

| File | Partner / Source | Lines | SHA-256 Digest |
|---|---|---:|---|
| [`scenarios/p1_p8/P2-revocation-after-delegation-before-effect.json`](scenarios/p1_p8/P2-revocation-after-delegation-before-effect.json) | Iman Schrock, Ben Le (Redthread), Marc Miro (MintID) — `P2` v2 spec (`ietf127-wimse-scenario/1`) | — | `3a84a26c4e644e2cd04a7b7b6cfb75f1e65d0cd8eeb16783433d9cf619b21538` |
| [`scenarios/p1_p8/P7-approval-display-differs-from-the-executed-action.json`](scenarios/p1_p8/P7-approval-display-differs-from-the-executed-action.json) | Arun Thallapelly (OmniArx) — `P7` spec & Ed25519 vectors `V1`/`V4`/`V5`/`R2` | — | `3e6e023f0a9158fbdd0aefd14803b1bdba26f5393212ef8d7b0ba8c2c7c27370` |
| [`scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json`](scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json) | Kieran Sweeney (Cred) — `P8` spec (`token_released: false` vs `true`) | — | `1e1aa9ccffefe27ab1624198cbde7045c393b443e70417e198322f504e881cb8` |
| [`scenarios/p1_p8/redthread-local.manifest.json`](scenarios/p1_p8/redthread-local.manifest.json) | Ben Le (Redthread `v0.7.584`, simulated clock) — 22/22 case manifest for `P1–P6` | — | `1d2145bd44814b0645d39f55e55e1442ea11bd40da548b6a6f3aee4e2dd6d8df` |
| [`scenarios/p1_p8/redthread-P1-local.jsonl`](scenarios/p1_p8/redthread-P1-local.jsonl) | Redthread `P1` local trace (*Status unavailable*, simulated clock) | 9 | `8a296088ddc17d8255c6708075ea216c859ee53e2c9afa350a4708134046688a` |
| [`scenarios/p1_p8/redthread-P2-local.jsonl`](scenarios/p1_p8/redthread-P2-local.jsonl) | Redthread `P2` local trace (*Revocation after delegation, before effect*, simulated clock) | 122 | `3f4f9436ba1c1e01f5c7b47ad400ef9bfed36fa53a2f24495fa8f6174f4460f7` |
| [`scenarios/p1_p8/redthread-P3-local.jsonl`](scenarios/p1_p8/redthread-P3-local.jsonl) | Redthread `P3` local trace (*Delegation that widens*, simulated clock) | 6 | `00d23a57ef9542a5856de7aa419a600b18b12fbf1705817ff771d610c24cdae2` |
| [`scenarios/p1_p8/redthread-P4-local.jsonl`](scenarios/p1_p8/redthread-P4-local.jsonl) | Redthread `P4` local trace (*Cumulative limit across two services*, simulated clock) | 8 | `df75a31c1f23c4c1c8d3be234c44f16ed1c3acae3a0a6d27e8182ccd21435992` |
| [`scenarios/p1_p8/redthread-P5-local.jsonl`](scenarios/p1_p8/redthread-P5-local.jsonl) | Redthread `P5` local trace (*Request rewritten in transit*, simulated clock) | 4 | `4c67da7c46481542f0f8d48539db874aa96640f84670babf2eba668ab261abbf` |
| [`scenarios/p1_p8/redthread-P6-local.jsonl`](scenarios/p1_p8/redthread-P6-local.jsonl) | Redthread `P6` local trace (*Tool or build change between hops*, simulated clock) | 2 | `39d197814178be946754423de1d505086682cab2aba06058170b61385c94fe3e` |
| [`scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.manifest.json`](scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.manifest.json) | Marc Miro (MintID `public-v2026-11-11.1`) — Nov 14 testnet manifest | — | `ca1703c3e7c0c40c71d80d8be046d2c1ba3bd7f06e7d4f35d0ef4e4604100963` |
| [`scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.jsonl`](scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.jsonl) | MintID Nov 14 live testnet trace (`status_root_stale` + `holder_refresh` `credential_revoked` vs `sibling_control`) | 92 | `7090edc46994cbd039d281841043a68a41919188eb952a9b4da117b980182a32` |
| [`scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.manifest.json`](scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.manifest.json) | Ben Le (`v0.7.586`) + Marc Miro — recorded live sandbox negative control manifest (`15 Nov 2026 01:23 UTC`) | — | `4fe8b37ded9501f3a04857ed9637b6553a8de9f7767341f06ee06c35b04b28e2` |
| [`scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.jsonl`](scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.jsonl) | Redthread (`v0.7.586`) + MintID recorded live sandbox negative control JSONL (`proof_invalid`, `no-agent-answer`, run `15 Nov 2026 01:23 UTC`) | 4 | `1f038bbc79acd416915c0f9f6268634539c2ac54c6bdcc35041e6d6aefa1ef75` |

### 3.3 Unmodified Original Partner Archives (`scenarios/p1_p8/originals/`)

| Archive / File | Description | SHA-256 Digest |
|---|---|---|
| [`scenarios/p1_p8/originals/P2-revocation-after-delegation-before-effect-v1.json`](scenarios/p1_p8/originals/P2-revocation-after-delegation-before-effect-v1.json) | Initial `P2` v1 scenario JSON before the v2 MintID testnet update | `bdfaf486c5639addddc3c318aa6fd18f338bc5cdf27be5a87c630730aa261218` |
| [`scenarios/p1_p8/originals/redthread-p1-p6-local-runs.zip`](scenarios/p1_p8/originals/redthread-p1-p6-local-runs.zip) | Original ZIP bundle of Redthread `P1–P6` local runs (`v0.7.584`) | `b86918ac89f293305aae3e58824c2eaf76dc563078a22e925e98168a07a77739` |
| [`scenarios/p1_p8/originals/redthread-p2-mintid-sandbox.zip`](scenarios/p1_p8/originals/redthread-p2-mintid-sandbox.zip) | Original ZIP bundle of the Redthread + MintID sandbox integration (`v0.7.586`) | `415722e426dd56c054cae0b319243157a2dee8638348964d0b12b988f4e67a1a` |
