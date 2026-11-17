# Post-hackathon analysis: the AI2II process on the WIMSE project

Scope: IETF 127 hackathon, 14-15 Nov 2026. Based on the full git history (23 commits on `main`), every document in the repo, the checkers, the evidence bundles and the five independent reviews.

## Status on 17 Nov 2026

This analysis describes the repository as it was on 15-16 Nov. Since then:

- Section 3, items 1 and 5: results are labelled by evidence class and never added across classes; the mocked and simulated cases are labelled as such.
- Item 2: both bundles were recorded again at `bf10aed`, and `env.json` no longer records absolute paths (Maurice's own log lines still name its home directory).
- Item 3: `interop.yaml` records who wrote each checker and peer. The checkers are attributed to Nemotron by the maintainer; the repository holds no transcript.
- Item 6: CI runs `./reproduce.sh` on every push and pull request.
- Item 8: Mistral F1 is fixed: `observes_chain.py` compares every hop with `expected_hops`, and the new mutant `chain_hop_flipped.pcap` proves it. `observes_live_partners.py` exits 1 when the testnet is unreachable.
- Absolute `file://` links were replaced with relative links.

## 0. Two framing corrections

- **AI2II is not in this repo.** It lives in the sibling project `../AI2II` (`DESIGN.md` §24.20). This repo used one part of it: the `wire/` evidence bundle plus the L4 rule that a checker's model family must differ from the peer's. The orchestrator, milestones, reviewer/verifier roles and human gates were not used.
- **P1-P8 are partner scenarios, not formal properties.** There are no formal proofs or model checks. The checks are tshark pcap checkers, SHA-256 manifests and Python asserts.

## 1. What actually happened

| When (14 Nov unless noted) | Commit | Event |
|---|---|---|
| 14:56 | `6ae2bc7` | Inbound harness for Maurice |
| 18:51 | `da67b0f` | WP01-WP07 plans written (27 files) |
| 18:53-19:32 | `f1c74f6` etc. | Evidence published, `wire/` vendored, Lua dissector |
| 20:07 | `4679466` | **All of WP01-WP07 implemented in one commit** (+4610 lines, 76 min after the plans) |
| 20:16 | `cd9cd3d` | Chain bundle and docs |
| 21:02 | `cbf669e` | Opus review and hardening |
| 21:58 | `fe15e70` | Gemini review and partner feedback |
| 15 Nov 09:43 | `9875bea` | Nemotron P1-P8 review |
| 15 Nov 12:49 | `64d3d24` | WP09 "live", Mistral hardening, payment spec |
| 15 Nov 13:22-13:39 | `57422f4`..`49d29ca` | Slide deck |

No reverts and no deletions. Docs and reports account for most of the line growth after the implementation commit.

## 2. What worked

1. **Evidence bundles with hashes and `reproduce.sh`.** Reviewers could re-run checks and tamper with bytes. Mistral did exactly that and found a real weakness.
2. **Mandatory negative mutants.** A checker that must reject unrelated and request-only traffic is a cheap guard against vacuous passes. It surfaced the subset-semantics gap (Mistral F1).
3. **Cross-model review, when the reviewer could execute.**
   - The Opus review re-dissected the pcap, ran its own crypto verification and checked 32 digests. It found the most valuable problems: doc-versus-wire mismatches (A1-A3), mutants not built from the committed capture (824 vs 563 packets), and 104 vs 106 HTTP messages.
   - Mistral Vibe ran `reproduce.sh` twice and flipped bytes in the pcap. Best method of the five.
4. **Work packages with owned files, exact signatures and a one-line `Verify:`.** They let a large implementation land in about an hour.
5. **The review → triage → harden loop.** Maintainer triage appended to each report, then a hardening commit. Findings fed back to partners (Redthread, Ben Le).

## 3. What did not work

1. **Claims outran evidence (the biggest problem).**
   - `TEST_RESULTS_SUMMARY.md` says "7/7 live testnet checks" and the deck says "Verified live". `checkers/observes_live_partners.py` does not support that:
     - Only 3 checks are real HTTP probes. Cases 3 and 4 (revoked/unrevoked) are hard-coded `CheckResult` lambdas. Cases 1 and 2 are mocks unless the verifier reports `synced`.
     - `errors` is set to 0 at line 57 and never incremented in `verify_live_endpoints`. With every endpoint down it prints `mode=SIMULATED` and exits 0.
     - `scenarios/p1_p8/mintid_outside.py` builds the proof payload from the witness hex, with no real prover.
   - WP09 is labelled "Future TODO" in `README.md` and the WP09 file, and PASS in the summary and deck.
   - There is no `live-partners` cell in `interop.yaml`, so this suite has no bundle and no mutants.
2. **The bundle is not tied to HEAD.** The chain verdict is pinned to `8f8441e`. Four later commits changed checkers and peers. `verify-bundle` proves integrity, not currency. `VERIFY.md` cites yet another commit than `verdict.json`.
3. **Checker independence is declared, not shown.** `interop.yaml` gives all three checkers `family: nvidia` (lines 50, 59, 68). Nothing in the repo shows Nemotron wrote `observes_chain.py` or `observes_p1_p8.py`. `VERIFY.md` says Nemotron could not execute in its last rounds and Claude ran the verifications. Opus finding A9 is still open. Prompts and transcripts were not kept.
4. **Reviewer noise was expensive.** Nemotron's P1-P8 review had roughly one real finding for four false ones. Its headline "High" finding was rejected, it cited the wrong audit year, and "Wait, let me re-examine" is left in the body. The maintainer paid the triage cost.
5. **Hand-maintained numbers drift.** 85 vs 92 vs "32/32" cases, 104 vs 106 messages, and a stale README status section across five documents.
6. **No tests and no CI.** The only gate is a manually run script. P7 digests are placeholders, P2 "outside" cases are replayed recordings, and P1/P3-P6 are partner traces that this repo only hashes.
7. **The work-package discipline slipped.** Packages say "commit when Verify passes", but WP01-WP07 went in one commit with no per-package record. `WP-template.md` is cited but missing. A 1,491-line generated WP09 spec was committed unedited, and links are absolute `file://` paths.
8. **Findings were not tracked to closure.** Still open: Mistral F1 (`observes_chain.py:300`, `issubset`), Opus A9, B7, C1-C7 (token services that mint without authenticating the caller, `test_mode` accepted from request bodies, shared agent keys), Nemotron CHK-2 to CHK-6.
9. **Branch hygiene.** The Mistral review on `main` describes `bundle-payment` and `observes_payment.py`, which exist only on `feature/opena2a-wimse-aep`.
10. **No threat model, decision log, traceability matrix or retrospective.** P1-P8 traceability exists only as prose tables.

## 4. What looks useless or low value

| Item | Why | Suggestion |
|---|---|---|
| Four overlapping summary docs (README, TEST_RESULTS_SUMMARY, SCENARIOS_AND_AUTHORS, EVIDENCE) | Restate the same counts by hand, and are the source of the drift | Generate one from `verdict.json` |
| `checkers/wire.py` | Same-family dev checker, superseded | Delete |
| `WP09-architecture-nemotron.md` | Unedited generated spec beside a shorter WP09 | Delete or move out of the repo |
| Free-tier, non-executing reviewers as a gate | Cost more triage than they returned | Keep only reviewers that can run commands |
| "mini-code tier" label | Nothing enforces it | Drop or enforce |
| Slide generator (471 lines) for 2 slides | Output is hand-checked anyway | Generate numbers from verdicts, or build slides by hand |
| `scenarios/p1_p8/originals/*.zip` next to extracted copies | Duplicate | Keep one |
| 10 MB of pcaps for a loopback demo | Heavy for the value | Keep hashes plus one reference capture |
| `.ruff_cache`, `.DS_Store`, Office lock file | Clutter | Already ignored |

## 5. What to add, in priority order

1. **Generated claims and a drift gate.** Every number or PASS in docs and slides comes from verdicts. A `reproduce.sh --fresh` fails on drift and on bundle commit ≠ HEAD.
2. **A claim taxonomy per case:** `observed-on-wire | replayed-recording | simulated | mocked | partner-attested`. Summaries and slides print the breakdown, not one pass count. This alone would have prevented the WP09 overclaim.
3. **Checker honesty tests.** Every checker must exit non-zero when its target is unreachable and must fail its own mutants, enforced in CI. Fix `observes_live_partners.py` first.
4. **Provenance records.** Per artifact: model, prompt, tool access, transcript hash. Make the L4 family check verify author against checker instead of comparing declared strings.
5. **A reviewer protocol.** Each finding needs a reproducible command and its output. Severity must cite evidence. The triage table (accepted/rejected/why) becomes a committed file.
6. **Unit tests and CI.** Cover the WP01 token helpers and wire the executor's 10-case self-test into pytest and GitHub Actions.
7. **A traceability matrix.** P1-P8 → spec clause → peer code → checker assertion → bundle path.
8. **A findings register, threat model and ADR-lite decision log.** Owner and status per finding, so reviews do not lose items.
9. **Per-WP commits** with the `Verify:` output recorded, and the WP template kept in the repo.
10. **Scripted mutants** generated from the committed capture (closes B7).
11. **Repeat runs.** At least 3 per cell, with the unsigned `X-Test-Case` caveat documented.
12. **A scope freeze before slides**, with slides generated from verdicts.

## 6. Verdict

The core idea holds up: an evidence bundle, a checker that must fail its negatives, and hashed reproduction. Reviews that executed things found real bugs.

The process checked the wire. It did not check the claims made about the wire. Most defects in this repo are in the human-facing layer: counts, labels, the "live" claim, and an independence rule nobody could verify. Items 1-3 in §5 close most of that gap for the least work.

## Appendix: key references

`validation/opus-chain-review.md`, `validation/mistral-vibe-review.md`, `validation/nemotron-p1-p8-review.md`, `validation/gemini-p1-p8-review.md`, `checkers/observes_live_partners.py`, `checkers/observes_chain.py:300`, `scenarios/p1_p8/mintid_outside.py`, `interop.yaml`, `VERIFY.md`, `TEST_RESULTS_SUMMARY.md`, `workpackages/README.md`, `../AI2II/DESIGN.md` §24.20.
