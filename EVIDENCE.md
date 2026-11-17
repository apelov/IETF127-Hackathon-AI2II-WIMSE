# WIMSE Interop Evidence Catalog (`EVIDENCE.md`)

This catalog indexes every committed packet capture (`.pcap`), decision journal (`.jsonl`), partner trace manifest (`.json`), and AI2II verification bundle (`validation/bundle-*/`) in the repository, along with their exact SHA-256 digests and one-line inspection commands.

All artifacts listed below contain **zero private keys or secrets** (`"contains_secrets": false` in every `verdict.json`, verified by `./reproduce.sh`).

---

## 1. AI2II Verification Summary & Independent Reviews

Running `PYTHONPATH=. .venv/bin/python -m wire summarize validation` produces:

```text
PASS	WIMSE	chain	bf10aed475bb	chain-stack@bf10aed475bb, wimse-chain-client@bf10aed475bb	all peers exited 0, capture non-empty, every checker passed and rejected its negatives	validation/bundle-chain/chain
PASS	WIMSE	inbound	bf10aed475bb	maurice@bf10aed475bb, wimse-client@bf10aed475bb	all peers exited 0, capture non-empty, every checker passed and rejected its negatives	validation/bundle-inbound/inbound
```

| Cell | Verdict | Bundle Path | `verdict.json` SHA-256 | Independent Audit Report | Secrets Present? |
|---|---|---|---|---|---|
| `inbound` | **PASS** | [`validation/bundle-inbound/inbound/`](validation/bundle-inbound/inbound/) | `18239c9ad11b568568b3a46ae6184ac425c7621a090c52006944b5694f061523` | [`validation/nemotron-review.md`](validation/nemotron-review.md) (`nvidia/nemotron-3-ultra-550b-a55b:free`) | `false` |
| `chain` | **PASS** | [`validation/bundle-chain/chain/`](validation/bundle-chain/chain/) | `c2264997e14c9a61623f7990f4a9634ff159e38a73a826eb75302437e87ea7de` | [`validation/nemotron-p1-p8-review.md`](validation/nemotron-p1-p8-review.md) (`nvidia/nemotron-3-ultra-550b-a55b:free`) · [`validation/gemini-p1-p8-review.md`](validation/gemini-p1-p8-review.md) (`gemini-4-argon`) · [`validation/opus-chain-review.md`](validation/opus-chain-review.md) (`claude -p --model opus`) | `false` |

---

## 2. Committed Packet Captures (`.pcap`)

### 2.1 Live Passing Captures

| Capture File | Cell / Scope | Total Packets | HTTP Messages | SHA-256 Digest | `tshark` / Wireshark Inspection Command |
|---|---|---:|---:|---|---|
| [`validation/bundle-inbound/inbound/capture.pcap`](validation/bundle-inbound/inbound/capture.pcap) | Suite 1: 34 WIMSE inbound cases (`A2–A13j`, `C2–C12b`, `IN4–IN15`) on loopback `:5050` & `:47999` | 540 | 72 | `b8508d5f1a3ba03dc8a73617fce8d6cb6c88c5f1593bed04536c2b4d78f15eab` | `tshark -X lua_script:dissectors/wimse.lua -r validation/bundle-inbound/inbound/capture.pcap -Y http` |
| [`validation/bundle-chain/chain/capture.pcap`](validation/bundle-chain/chain/capture.pcap) | Suite 2 & 3: 19 3-agent cross-domain call-chain cases (`:5050–5063`) + 10 `P2/P7/P8` loopback cases (`:5064`: 2 simulated, 2 replayed, 6 mocked) | 822 | 106 (53 exchanges) | `ac56bdb934f59b92b3ed2f60820c2b6251ff64c03e172b7f612d466067af8ad2` | `tshark -X lua_script:dissectors/wimse.lua -r validation/bundle-chain/chain/capture.pcap -Y 'wimse.test_case == "B_CHAIN"' -O wimse` |

### 2.2 Negative Mutant Captures (Rejected by Independent Checkers)

Every independent checker is verified to exit non-zero on each of its negative PCAP mutants: `wire run` re-checks this at every recording, and `./reproduce.sh` re-checks it on every run. The mutants were derived from earlier recordings of the same cells (the chain mutants from the `8f8441e` capture, except `chain_leaked_txn_body.pcap`, made from the capture in 2.1).

| Negative PCAP File | Target Checker | Mutation / Violation Tested | Total Packets | SHA-256 Digest |
|---|---|---|---:|---|
| [`checkers/negatives/unrelated.pcap`](checkers/negatives/unrelated.pcap) | `observes_wimse.py` | Non-WIMSE traffic (no WIMSE test cases present) | 3 | `812b677b805c51b9a40aae31b32d95c5d8b79bd18c523538244400dbb733c547` |
| [`checkers/negatives/request_only.pcap`](checkers/negatives/request_only.pcap) | `observes_wimse.py` | Client requests only (all server HTTP responses stripped) | 245 | `d49f72ef4103cd28d80e91a2436b609328827fdc45f8c33d7a2cbc7403090b8b` |
| [`checkers/negatives/forbidden_fetch.pcap`](checkers/negatives/forbidden_fetch.pcap) | `observes_wimse.py` | Contains forbidden outbound SSRF fetch to port `47999` during `C12`/`C12b` | 491 | `dd1d79aff9f43523f9e0d43afa832815ac5237db3375c8ca7e2fbd8669aab07d` |
| [`checkers/negatives/chain_unrelated.pcap`](checkers/negatives/chain_unrelated.pcap) | `observes_chain.py` | Non-WIMSE traffic (missing `B_CHAIN` and negative cases) | 3 | `0b85a5a7ac55505dfef4be1248455e17291fca83594e0313786d0c169850e456` |
| [`checkers/negatives/chain_request_only.pcap`](checkers/negatives/chain_request_only.pcap) | `observes_chain.py` | Request packets only (HTTP responses stripped across `:5050–5063`) | 781 | `01d3a553e97003f4a4a9c5d9105090d8ff581959108a4f1026cd467656410324` |
| [`checkers/negatives/chain_leaked_txn.pcap`](checkers/negatives/chain_leaked_txn.pcap) | `observes_chain.py` | Domain A internal `Txn-Token` (`aud = "maurice.ietf127.example"`, `txn = "leaked"`) injected onto Domain B port `:5062` (`POST /research`) during `B_CHAIN` | 825 | `5f086cb2f1d0a24614fb05a12e832ca1e33bc5c893ebdbb2a50e0a1684691e3c` |
| [`checkers/negatives/chain_leaked_txn_body.pcap`](checkers/negatives/chain_leaked_txn_body.pcap) | `observes_chain.py` | The same Domain A `Txn-Token` sent to `:5062` in an untagged request's JSON body (`subject_token`) instead of a header; only the body scan rejects it | 823 | `5aa5bd1a467c4f25a08d5a8e1e1288cbc6a0497aeda87d8ed50b054fb5b3a016` |
| [`checkers/negatives/chain_hop_flipped.pcap`](checkers/negatives/chain_hop_flipped.pcap) | `observes_chain.py` | One intermediate hop of `C7` (`:5061`) changed from `200` to `403`; the case's set of statuses is unchanged, so only the hop-by-hop comparison with `expected_hops` catches it | 824 | `92e6e2cfd875c824da5f0e29b7b1ce5fc843558e598167773199407d84340989` |
| [`checkers/negatives/p1_p8_unrelated.pcap`](checkers/negatives/p1_p8_unrelated.pcap) | `observes_p1_p8.py` | Non-WIMSE traffic on loopback | 3 | `1281856404dbd4572ae0de3970160c91d5458493fa2239c7134f566e23c51fe3` |
| [`checkers/negatives/p1_p8_request_only.pcap`](checkers/negatives/p1_p8_request_only.pcap) | `observes_p1_p8.py` | `P2/P7/P8` requests on `:5064` with all HTTP responses stripped | 70 | `cb3bbef9651ff7199b3f9c3b317474aa218ffa78fb9f5d8034b35ebbdd5b5975` |
| [`checkers/negatives/p1_p8_missing_before_effect.pcap`](checkers/negatives/p1_p8_missing_before_effect.pcap) | `observes_p1_p8.py` | Truncated to frames 1–20 so `P2_before-effect` response and `P2_outside-made-up-proof` / `P2_outside-no-agent-answer` before-effect revocation checks are missing | 20 | `726aef5de0bbd2ed2730abe582719f7ae926ad0c74a54f3dde5b4b0c582f6913` |

---

## 3. Committed Decision Journals, Scenario Specs & Partner Traces

### 3.1 Runtime Decision Journals (`.jsonl`)

| File | Description | Lines | SHA-256 Digest |
|---|---|---:|---|
| [`validation/bundle-inbound/inbound/decision-journal.jsonl`](validation/bundle-inbound/inbound/decision-journal.jsonl) | AgentMaurice WIMSE inbound verifier decision journal across the 34 Suite 1 cases | 35 | `2019fbd387b135f757752bee8ab698432af3033792a0f9611f547955fb6b8ff0` |
| [`validation/bundle-chain/chain/chain-journal.jsonl`](validation/bundle-chain/chain/chain-journal.jsonl) | Domain A + Domain B + `P2/P7/P8` structured decision journal across Suite 2 & Suite 3 | 38 | `1e60f6063db8a09efa1578f513541528f8a1852f79d36ad0009fbe220a6de285` |

### 3.2 Partner Scenario Definitions, Traces & Manifests (`scenarios/p1_p8/`)

For background context on how these partner artifacts were coordinated and cross-verified during the IETF 127 Hackathon, see [`scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md`](scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md).

| File | Partner / Source | Lines | SHA-256 Digest |
|---|---|---:|---|
| [`scenarios/p1_p8/P2-revocation-after-delegation-before-effect.json`](scenarios/p1_p8/P2-revocation-after-delegation-before-effect.json) | Iman Schrock, Ben Le (Redthread), Marc Miro (MintID) — `P2` v2 spec (`ietf127-wimse-scenario/1`) | — | `3a84a26c4e644e2cd04a7b7b6cfb75f1e65d0cd8eeb16783433d9cf619b21538` |
| [`scenarios/p1_p8/P7-approval-display-differs-from-the-executed-action.json`](scenarios/p1_p8/P7-approval-display-differs-from-the-executed-action.json) | Arun Thallapelly (OmniArx) — `P7` spec & Ed25519 vectors `V1`/`V4`/`V5`/`R2` | — | `3e6e023f0a9158fbdd0aefd14803b1bdba26f5393212ef8d7b0ba8c2c7c27370` |
| [`scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json`](scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json) | Kieran Sweeney (Cred) — `P8` spec (`token_released: false` vs `true`) | — | `1e1aa9ccffefe27ab1624198cbde7045c393b443e70417e198322f504e881cb8` |
| [`scenarios/p1_p8/P1-status-list-unreachable.json`](scenarios/p1_p8/P1-status-list-unreachable.json) | Ben Le (Redthread) — `P1` scenario definition (*Status list unreachable*, `ietf127-wimse-scenario/1`, 14 Nov 2026) | 97 | `0d0cb494bfbc0790019efef9a96692f95376b782f26d70a5a0b6b298804dd0bd` |
| [`scenarios/p1_p8/P3-delegation-that-widens.json`](scenarios/p1_p8/P3-delegation-that-widens.json) | Ben Le (Redthread) — `P3` scenario definition (*Delegation that widens*, `ietf127-wimse-scenario/1`, 14 Nov 2026) | 98 | `2377cdad5da8bb1131def4b5d51d093eebe66e3dc7979aa5b93b3c63ec1aa47d` |
| [`scenarios/p1_p8/P4-cumulative-limit-across-two-services.json`](scenarios/p1_p8/P4-cumulative-limit-across-two-services.json) | Ben Le (Redthread) — `P4` scenario definition (*Cumulative limit across two services*, `ietf127-wimse-scenario/1`, 14 Nov 2026) | 71 | `7c5fc7aaf111d3f17462bbf61a0b3a313d91e066620e38974eb2e8f38290916b` |
| [`scenarios/p1_p8/P5-request-rewritten-in-transit.json`](scenarios/p1_p8/P5-request-rewritten-in-transit.json) | Ben Le (Redthread) — `P5` scenario definition (*Request rewritten in transit*, `ietf127-wimse-scenario/1`, 14 Nov 2026) | 78 | `1f43f86d7f2c8cc1fd93222f23d29168960e95548fea093b1e446cacaadad533` |
| [`scenarios/p1_p8/P6-tool-description-or-build-changes-between-hops.json`](scenarios/p1_p8/P6-tool-description-or-build-changes-between-hops.json) | Ben Le (Redthread) — `P6` scenario definition (*Tool description or build changes between hops*, `ietf127-wimse-scenario/1`, 14 Nov 2026) | 62 | `cb5db97d24331faef25caf1b91ccb072a93a0585eace7c389666de70503e6714` |
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
| [`scenarios/p1_p8/cred-P8.manifest.json`](scenarios/p1_p8/cred-P8.manifest.json) | Cred (Kieran Sweeney) manifest for its own `P8` run (`cred-ninja/sdk` `83e9cec`, 15 Nov 2026; reason mapping, reproduction command) | 34 | `cd2e4839dbd1266a002b212b67e2c0308f28fdfa05d35c477fcf401cf86062fb` |
| [`scenarios/p1_p8/cred-P8.jsonl`](scenarios/p1_p8/cred-P8.jsonl) | Cred (Kieran Sweeney) own `P8` run, partner-attested, wall clock, local mock provider; not verified by `observes_p1_p8.py` | 11 | `b52794003e98d9e9bf6f9779080ad3af4d870d9a651a56872e1222523d7af7fc` |

### 3.3 Unmodified Original Partner Archives (`scenarios/p1_p8/originals/`)

| Archive / File | Description | SHA-256 Digest |
|---|---|---|
| [`scenarios/p1_p8/originals/P2-revocation-after-delegation-before-effect-v1.json`](scenarios/p1_p8/originals/P2-revocation-after-delegation-before-effect-v1.json) | Initial `P2` v1 scenario JSON before the v2 MintID testnet update | `bdfaf486c5639addddc3c318aa6fd18f338bc5cdf27be5a87c630730aa261218` |
| [`scenarios/p1_p8/originals/redthread-p1-p6-local-runs.zip`](scenarios/p1_p8/originals/redthread-p1-p6-local-runs.zip) | Original ZIP bundle of Redthread `P1–P6` local runs (`v0.7.584`) | `b86918ac89f293305aae3e58824c2eaf76dc563078a22e925e98168a07a77739` |
| [`scenarios/p1_p8/originals/redthread-p2-mintid-sandbox.zip`](scenarios/p1_p8/originals/redthread-p2-mintid-sandbox.zip) | Original ZIP bundle of the Redthread + MintID sandbox integration (`v0.7.586`) | `415722e426dd56c054cae0b319243157a2dee8638348964d0b12b988f4e67a1a` |
| [`scenarios/p1_p8/originals/ietf127-scenarios.zip`](scenarios/p1_p8/originals/ietf127-scenarios.zip) | Original ZIP from Ben Le, 14 Nov 2026: the eight scenario definitions `P1`–`P8` and a README (`P2`, `P7`, `P8` were later revised; the current versions are in `scenarios/p1_p8/`) | — | `112591867a0fd7eccf6db09ba2c3899db382c9e7cc9aa32ffc41c3e6c9c244cf` |
