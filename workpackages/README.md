# Multi-Agent WIMSE Interop — Work Package Plan (for Rung 0 / Mini-Code Models)

This directory contains self-contained Work Packages (`WP01`–`WP06`) to implement the full two-domain WIMSE + Txn-Token + Identity-Chaining interop scenario and attack suite from [hackathon-test-scenario.md](file:///Users/apelov/Code/AgentMaurice/wimse-interop/hackathon-test-scenario.md) and [maurice-demo-scenario-spec.md](file:///Users/apelov/Code/AgentMaurice/wimse-interop/maurice-demo-scenario-spec.md).

## Design Principles for Less Capable Models (`Tier: mini-code`)

Per `WP-template.md`:
> *"A `mini-code` package is not merely a shorter one. What defeats a small model is **open design decisions**, not line count, so it must have them already made: exact signatures and data shapes written out, tests supplied rather than specified, one or two owned files, and nothing left to invent."*

Therefore, every Work Package in `workpackages/`:
1. **Touches 1–2 disjoint files (`## Owns`)** so packages never conflict and never break the existing `inbound` PASS cell (`peers/driver.py`, `checkers/observes_wimse.py`, `cases.json`).
2. **Fixes all ports, URIs, JWT claims, and function signatures upfront.**
3. **Has a single deterministic `Verify:` one-liner** that runs in < 5 seconds without needing root or Docker.

---

## Fixed Architecture & Port Map (All Loopback `127.0.0.1`)

| Component | Trust Domain | Port / URL | Workload ID / `iss` / `aud` | Role |
| :--- | :--- | :--- | :--- | :--- |
| **Maurice** (existing) | Domain A (`maurice.ietf127.example`) | `127.0.0.1:5050` | `aud: http://maurice.ietf127.example:5050` | Existing Go binary (`bin/maurice`); validates WIT + HTTP-Sig / WPT (`wth`/`tth` binding) |
| **TTS-A** (`peers/domain_a.py`) | Domain A | `127.0.0.1:5051` (`POST /tts/token`) | `iss: http://maurice.ietf127.example:5051`, `aud: maurice.ietf127.example` | Issues Domain A `txntoken+jwt` (`txn`, `sub`, `scope`, `tctx`, `req_wl`) |
| **AS-A** (`peers/domain_a.py`) | Domain A | `127.0.0.1:5051` (`POST /oauth/token`) | `iss: http://maurice.ietf127.example:5051`, `aud: http://rich.ietf127.example:5061/oauth/token` | RFC 8693 Token Exchange: consumes Domain A `Txn-Token`, issues cross-domain `jwt-bearer` grant (`typ: jwt-chg+jwt`) so `Txn-Token` never leaves Domain A |
| **AS-B** (`peers/domain_b.py`) | Domain B (`rich.ietf127.example`) | `127.0.0.1:5061` (`POST /oauth/token`) | `iss: http://rich.ietf127.example:5061`, `aud: http://rich.ietf127.example:5060` | RFC 7523 JWT Bearer grant: verifies AS-A's grant (`aud == AS-B`), issues Domain B OAuth access token (`at+jwt`) carrying linked `txn` |
| **TTS-B** (`peers/domain_b.py`) | Domain B | `127.0.0.1:5061` (`POST /tts/token`) | `iss: http://rich.ietf127.example:5061`, `aud: rich.ietf127.example` | Issues Domain B `txntoken+jwt` from Domain B access token (for Agent 2) and narrowed replacement `txntoken+jwt` (for Agent 3) |
| **RICH Coordinator Agent (Agent 2)** (`peers/domain_b.py`) | Domain B | `127.0.0.1:5060` (`POST /coordinate`) | `wimse://rich.ietf127.example/agent/coordinator` | Verifies Agent 1's cross-domain `WIT + HTTP-Sig + Authorization: Bearer`, gets Domain B `Txn-Token` (`files:read files:list`) from TTS-B, delegates to Agent 3 (`:5062`) |
| **RICH Research Sub-Agent (Agent 3)** (`peers/domain_b.py`) | Domain B | `127.0.0.1:5062` (`POST /research`) | `wimse://rich.ietf127.example/agent/research` | Verifies Agent 2's `WIT + HTTP-Sig + Txn-Token` (or direct `Bearer` in targeted negative tests), exchanges for narrowed `Txn-Token` (`files:read`) at TTS-B, calls File Tool (`:5063`) |
| **File Tool** (`peers/domain_b.py`) | Domain B | `127.0.0.1:5063` (`POST /files/read`) | `wimse://rich.ietf127.example/tool/files` | Verifies caller's `WIT + proof + Txn-Token` (`tth` or covered `txn-token`), checks `delegation` (`required` vs `forbidden`), `scope` (`files:read`), `tctx.file` (`Q3.pdf` vs `salaries.xlsx`), and revocation list |
| **P2/P7/P8 Executor** (`peers/p2_p7_p8_executor.py`) | Domain B (`hop="E"`) | `127.0.0.1:5064` (`POST /p2/*`, `/p7/*`, `/p8/*`) | `ietf127-wimse-scenario/1` | Runs Redthread `ProtectedOperation` (`authorize` + `before-effect` + MintID outside hook), OmniArx `P7` (`V5` / `R2` at fixed clock `1800000000`), and Cred `P8` (`token_released` before vs after use) |

---

## Work Package DAG & Execution Order

```text
WP01 (Txn-Token & Chaining Crypto Primitives in peers/wimse.py + setup/gen_keys.py)
  ├──▶ WP02 (Domain A Services: TTS-A + AS-A in peers/domain_a.py)
  └──▶ WP03 (Domain B Services: AS-B + TTS-B + File Tool + RICH Agent in peers/domain_b.py)
         │
         ▼
       WP04 (End-to-End Chain & Attack Driver + Cases in chain_cases.json & peers/chain_driver.py)
         │
         ├──▶ WP05 (Independent Chain Capture Checker & Negatives in checkers/observes_chain.py)
         └──▶ WP07 (Extended Scenarios P1–P8: Redthread, MintID, OmniArx P7, Cred P8 + Independent Checker)
                │
                ▼
              WP06 (AI2II Manifest Integration: add `chain` and `p1-p8` cells to interop.yaml)
                │
                ▼
              WP08 (GitHub Publication: SCENARIOS_AND_AUTHORS.md, EVIDENCE.md, commit all PCAPs & bundles)
```

| WP | File | Tier | Depends On | Owns | Summary |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **[WP01](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP01-txn-and-chaining-primitives.md)** | `WP01-txn-and-chaining-primitives.md` | `mini-code` | — | `peers/wimse.py`, `setup/gen_keys.py` | Add `issue_txn_token()`, `issue_chain_grant()`, `issue_access_token()`, `verify_jws()`, and `verify_wimse_request()` helpers; generate `tts_a`, `as_a`, `as_b`, `tts_b`, `rich` keys. |
| **[WP02](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP02-domain-a-services.md)** | `WP02-domain-a-services.md` | `mini-code` | `WP01` | `peers/domain_a.py` | Implement Domain A HTTP server (`127.0.0.1:5051`) with `/tts/token` (issues `txntoken+jwt`, supports narrowing & bad-TTS test modes) and `/oauth/token` (RFC 8693 exchange to JWT grant for AS-B). |
| **[WP03](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP03-domain-b-services.md)** | `WP03-domain-b-services.md` | `mini-code` | `WP01` | `peers/domain_b.py` | Implement Domain B servers (`5061`, `5062`, `5063`): AS-B, TTS-B, File Tool (`Q3.pdf` with prompt injection text vs `salaries.xlsx`), and RICH Agent (credential isolation + kill-switch revocation endpoint). |
| **[WP04](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP04-chain-driver-and-attacks.md)** | `WP04-chain-driver-and-attacks.md` | `mini-code` | `WP02`, `WP03` | `chain_cases.json`, `peers/chain_driver.py` | Implement the driver that runs Normal Path (`B1–B8` including Maurice hop) and all negative/attack cases (`C5`, `C6`, `C7`, `C8`, `C9`, `C9b`, `C10`, `D1–D7`), writing unified `chain-journal.jsonl`. |
| **[WP05](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP05-chain-wire-checker.md)** | `WP05-chain-wire-checker.md` | `mini-code` | `WP04` | `checkers/observes_chain.py`, `checkers/make_chain_negatives.py` | Independent wire checker (must be run with a non-driver model family, e.g. Nemotron/Gemini) that inspects `capture.pcap` across ports `5050,5051,5061,5062,5063`, verifies Domain A `Txn-Token` never crosses to `:5061/:5062/:5063`, and rejects 3 negatives. |
| **[WP07](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP07-extended-scenarios-p1-p8.md)** | `WP07-extended-scenarios-p1-p8.md` | `mini-code` | `WP03`, `WP04` | `scenarios/p1_p8/**`, `peers/p2_p7_p8_executor.py`, `checkers/observes_p1_p8.py` | Integrate `P1–P8` (`ietf127-wimse-scenario/1`): Redthread `P1–P6` (22 cases, 120 s bound, `before-effect` 0 s / 51 s simulated), MintID `P2` (10 s proof, 185 s/245 s bounds, 13 Nov & 14 Nov traces + witness-refresh attribution), OmniArx `P7` (`V5` / `R2` at `1800000000`), Cred `P8` (`token_released` before vs after use), and an independent cross-family checker. |
| **[WP06](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP06-interop-manifest-cell.md)** | `WP06-interop-manifest-cell.md` | `mini-code` | `WP05`, `WP07` | `interop.yaml`, `setup/run_chain_servers.py` | Wire the `chain` and `p1-p8` cells into `interop.yaml` alongside `inbound` so `python -m wire run interop.yaml` produces full AI2II PASS bundles. |
| **[WP08](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP08-github-publication-and-evidence-docs.md)** | `WP08-github-publication-and-evidence-docs.md` | `mini-code` | `WP06`, `WP07` | `SCENARIOS_AND_AUTHORS.md`, `EVIDENCE.md`, `README.md`, `validation/**` | Document all scenarios, authors (Pelov, Schrock, Le/Redthread, Miro/MintID, Thallapelly/OmniArx, Sweeney/Cred), drafts, AI model families, and track all PCAPs, JSONL traces, and AI2II bundles in git for GitHub publication. |
| **[WP09](file:///Users/apelov/Code/IETF127-Hackathon/WIMSE/workpackages/WP09-live-emilia-and-mintid-testnet.md)** | `WP09-live-emilia-and-mintid-testnet.md` | `live-testnet` | `WP07`, `WP08` | `setup/clone_partners.sh`, `scenarios/p1_p8/mintid_outside.py`, `peers/domain_b.py` | **Future TODO:** Clone `emilia-protocol` + `mintid` (`deploy/networks.json` profile `testnet`: `issuer`, `verifier`, `relay`, `rpc.testnet.mintid.net:443`) to run `P1–P6` and positive/negative `P2` ZK non-revocation proofs live end-to-end. |
