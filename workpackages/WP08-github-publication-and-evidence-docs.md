# WP08 — Public GitHub Documentation, Author Attribution, and Evidence Catalog

Tier: mini-code
Inputs: workpackages/README.md, README.md, cases.json, chain_cases.json, scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md, scenarios/p1_p8/P2-revocation-after-delegation-before-effect.json, scenarios/p1_p8/P7-approval-display-differs-from-the-executed-action.json, scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json, scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.md

Create `SCENARIOS_AND_AUTHORS.md`, `EVIDENCE.md`, and update `README.md` and `.gitignore` so the repository is ready to publish to GitHub with complete author/implementation attribution, Internet-Draft citations, and all PCAPs, JSONL decision journals, and AI2II evidence bundles tracked in git.

## Why

The repository will be published to GitHub after the IETF 127 Hackathon as the public record of the WIMSE + OAuth + Agent Call-Chain interop. Every scenario, contributor, implementation, AI model family (builder vs. independent verifier), PCAP capture, and JSONL decision journal must be clearly documented, attributed, and committed to git (while ensuring no secret keys or credentials are ever committed, and `verdict.json` has `"contains_secrets": false`).

Depends on: WP06, WP07.

## Deliverables

1. **Create `SCENARIOS_AND_AUTHORS.md`** containing:
   - **Contributors & Implementations Table:**
     - **Alexander Pelov (IMT Atlantique / AgentMaurice):** Overall WIMSE interop architecture, AI2II evidence harness, Phase A/B/C multi-domain agent-chain & mid-transaction revocation scenario (`maurice-wimse-spec.md`, `maurice-demo-scenario-spec.md`, `hackathon-test-scenario.md`), RICH runtime (`rich.ietf127.example`), Maurice integration.
     - **Iman Schrock:** Before-effect revalidation test design (`P2` `before-effect`), cross-implementation scenario review and bound analysis (`P1–P8`).
     - **Ben Le (Redthread Security):** `draft-le-agent-passport` (`Chain Validation`, `Status and Revocation`, `Exposure After Revocation`), scenarios `P1–P6` (`ietf127-wimse-scenario/1`), Redthread verifier & `ProtectedOperation` executor (`v0.7.584` / `v0.7.586`, commits `a09a616`, `ac4d088`, `39f7531`, `358c1ad`), tool-digest pinning (`P6`), and MintID outside-verifier hook.
     - **Marc Miro (MintID):** MintID zero-knowledge non-revocation verifier (`mintid-testnet-3`, `public-v2026-11-11.1`, `proof-core 0.6.0`, `SPEC-1 v3.7`), 10 s presentation proof lifetime, 185 s issuer / 245 s holder / 395 s cascade revocation bounds, 13 Nov & 14 Nov live testnet traces, and the sibling witness-refresh control for revocation attribution.
     - **Arun Thallapelly (OmniArx):** `draft-thallapelly-oasnt-02` & `draft-thallapelly-oasnt-enforce-01`, scenario `P7` (*"Approval display differs from the executed action"*, vectors `V1`/`V4`/`V5`/`R2` at fixed clock `1800000000`).
     - **Kieran Sweeney (Cred):** `draft-sweeney-wimse-credential-delegation`, scenario `P8` (*"Final hop to a bearer-only third-party API"*, separating `revoked-between-authz-and-use` with `token_released: false` from `revoked-after-token-released` with `token_released: true`).
   - **Normative Internet-Drafts & RFCs Table:**
     - `draft-ietf-wimse-arch-08`, `draft-ietf-wimse-aims-01`, `draft-ietf-wimse-workload-creds-03`, `draft-ietf-wimse-wpt-02`, `draft-ietf-wimse-http-signature-08`, `draft-ietf-wimse-identifier-04`, `draft-ietf-oauth-transaction-tokens-11`, `draft-ietf-oauth-identity-chaining-17`, `draft-le-agent-passport`, `draft-thallapelly-oasnt-02`, `draft-thallapelly-oasnt-enforce-01`, `draft-sweeney-wimse-credential-delegation`, `RFC 9421`, `RFC 9530`, `RFC 9457`, `RFC 8693`, `RFC 7523`.
   - **AI Model Provenance & Independence Table (AI2II Rule L4):**
     - Lists each component (`peers/`, `scenarios/`, `checkers/`) with the exact AI model family that authored the implementation vs. the independent model family that authored/ran the capture checker.
   - **Complete Scenario Catalog:**
     - **Suite 1:** Phase A & C WIMSE Inbound Matrix against Maurice (34 cases: `A2–A13j`, `C2–C12b`, `IN4–IN15`).
     - **Suite 2:** Phase B & C Two-Domain Agent Call Chain (`B_CHAIN`, `C5–C10`, `D1–D7`).
     - **Suite 3:** Extended Scenarios `P1–P8` (`ietf127-wimse-scenario/1`: Redthread `P1–P6`, MintID `P2` testnet & sandbox runs, OmniArx `P7`, Cred `P8`).
2. **Create `EVIDENCE.md`** (generated/verified against the actual files in `validation/` and `scenarios/p1_p8/`):
   - Table of every committed `.pcap` file (`validation/bundle-*/**/capture.pcap` and `checkers/negatives/*.pcap`), its packet count, SHA-256 hash, and `tshark` one-liner to inspect it.
   - Table of every committed `.jsonl` decision journal and manifest (`decision-journal.jsonl`, `chain-journal.jsonl`, `redthread-P1..P6-local.jsonl`, `revocation-trace-testnet-20261114T104257Z.jsonl`, `redthread-P2-mintid-sandbox-negative.jsonl`), original partner archives in `scenarios/p1_p8/originals/`, and a link to `scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md` (which records the sanitized technical summary of the partner coordination emails without publishing raw private correspondence).
   - Output of `PYTHONPATH=../AI2II .venv/bin/python -m wire summarize validation`.
3. **Update `README.md`** to link prominently to `SCENARIOS_AND_AUTHORS.md`, `EVIDENCE.md`, and `VERIFY.md`, and ensure all PCAPs and evidence bundles in `validation/` and `scenarios/p1_p8/` are tracked in git (while `keys/*.pem`, `.venv/`, and `bin/maurice` remain git-ignored).

## Owns (touch only these)

- `SCENARIOS_AND_AUTHORS.md`
- `EVIDENCE.md`
- `README.md`
- `.gitignore`
- `validation/**` (committed evidence bundles, PCAPs, and journals)

## Constraints / invariants

- Never commit private keys (`keys/*.pem`) or any bundle with `"contains_secrets": true`.
- Every SHA-256 hash cited in `EVIDENCE.md` must match `shasum -a 256` on the committed file.
- Commit locally when `Verify:` passes; never push until the user explicitly requests `git push`.

## Verification

Verify: test -f SCENARIOS_AND_AUTHORS.md && test -f EVIDENCE.md && PYTHONPATH=../AI2II .venv/bin/python -m wire summarize validation
