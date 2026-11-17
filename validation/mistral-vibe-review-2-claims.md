<!-- Mistral Vibe, headless (`vibe --prompt-file`), run 17 Nov 2026 on a separate checkout of ae228cc. Report as written. -->

# Review 2 of 2 — claims, attribution and documents (commit `ae228cc`)

## Findings

**F1 — high — EVIDENCE.md lists wrong SHA-256 digests (and packet counts) for three chain negative mutants at HEAD.**
`EVIDENCE.md:43-45`. Commit `ae228cc` regenerated `chain_unrelated.pcap`, `chain_request_only.pcap`, `chain_leaked_txn.pcap` (`git show --stat ae228cc`: "chain_leaked_txn.pcap | Bin 110345 -> 148354 bytes" etc.) but did not touch `EVIDENCE.md` (`git log --oneline -- EVIDENCE.md` stops at `899f343`).
Command and output:
```
$ sha256sum checkers/negatives/chain_*.pcap
0b85a5a7ac55...  chain_unrelated.pcap     (EVIDENCE.md:43 claims 269ec353...)
01d3a553e970...  chain_request_only.pcap  (EVIDENCE.md:44 claims ba162791...)
5f086cb2f1d0...  chain_leaked_txn.pcap     (EVIDENCE.md:45 claims 9762aeb4...)
$ tshark -r checkers/negatives/chain_request_only.pcap 2>/dev/null | wc -l   → 781  (doc: 522)
$ tshark -r checkers/negatives/chain_leaked_txn.pcap  2>/dev/null | wc -l   → 825  (doc: 563)
```
The claimed digests still match the *copies inside* `validation/bundle-chain/chain/inputs/...` (recorded at `8f8441e`, before the regeneration), so the doc describes files that no longer exist at HEAD. Why it matters: EVIDENCE.md's core promise is "Exact SHA-256 digests"; a reader who runs `sha256sum` per the catalog gets mismatches on 3 of 9 listed mutants, and `reproduce.sh`'s checks run against the new files the doc doesn't describe.

**F2 — high — README headline "85/85 passing cases" sums different evidence classes, against the repo's own rule.**
`README.md:7`: "(**85/85 passing cases + 9/9 rejected negative PCAP mutants**)". 85 = 34 inbound + 19 chain + 10 loopback `:5064` (2 simulated + 2 replayed + **6 mocked**) + 22 recorded Redthread traces (not executed here). `CONTRIBUTING.md` ("How results are labelled") states "results of different classes are never added together", and `TEST_RESULTS_SUMMARY.md:14` says the earlier summed figure "mixed these classes and is retired" — yet the README index still publishes such a sum, counting mocked and not-executed cases as "passing". The "9/9" is also stale (F3).

**F3 — medium — the 10th negative mutant is missing from the docs and the mutant counts are stale.**
`checkers/negatives/` contains 10 pcaps; `chain_hop_flipped.pcap` (added in `ae228cc`, 824 packets, sha256 `92e6e2cf...`) appears in `interop.yaml` (observes-chain negatives) and `reproduce.sh` but in **no** document: `grep -n hop_flipped EVIDENCE.md README.md TEST_RESULTS_SUMMARY.md` → no matches. `README.md:22` says "all 9 negative mutant PCAP rejections", `README.md:99` lists "all 6 negative mutants" for the chain cell (omits `chain_hop_flipped.pcap`), and `TEST_RESULTS_SUMMARY.md:8` says Suite 2 rejected "**3 / 3** negative PCAP mutants" (it is 4/4 at HEAD). Why it matters: the headline negative-control count a reader relies on is wrong after `ae228cc`.

**F4 — medium — SCENARIOS_AND_AUTHORS.md cites three spec files that do not exist.**
`SCENARIOS_AND_AUTHORS.md:13` lists `specs/maurice-wimse-spec.md`, `specs/maurice-demo-scenario-spec.md`, `specs/hackathon-test-scenario.md` as Alexander Pelov's specifications. `specs/` contains only `OPENA2A_WIMSE_AEP_SPEC.md` and `SETUP_PARALLEL_PROJECT.md`; `workpackages/README.md` itself says those documents are "not in this repository". Verified: script over all backticked `specs/...` refs → 3 MISSING-REF. Why it matters: the contributor table points readers at paths that 404.

**F5 — medium — the Suite 1 case catalog contradicts `cases.json`.**
`SCENARIOS_AND_AUTHORS.md:64-69` and `TEST_RESULTS_SUMMARY.md:7`. `cases.json` has 34 cases with IDs `A2,A3,A4,A5,A6a,A6b,A12a-d,A13a-j,C2,C3,C4,C4b,C11,C12,C12b,IN4,IN6,IN10-IN13,IN15`. The docs' table uses IDs that don't exist (`A6`, `A7`–`A12`, `A13`, `IN5`, `IN7`–`IN9`, `IN14`) and wrong outcomes: e.g. doc says "`C2`, `C3`, `C4` | WIT Revocation Lifecycle | `200 OK` before revocation (`C2`)..." but `cases.json` has `C2 | genuine WIT, request signed with another key → 400 proof-invalid`, `C3 | replay → 200 then 400 replay`, `C4/C4b | audience-mismatch → 400`; doc says "`C11` key-compromised `401`" but `cases.json` `C11 | WIT from an issuer not in trust → 400 untrusted-trust-domain`; doc "`IN4`–`IN15` ... `200 OK` within ±30 s" but `IN4 | expired WIT → 400 wit-expired`. Command: `python3 -c` dump of `cases.json` ids/titles/expects (output above). Why it matters: a reader cannot map the documented test names to the actual tested cases; several described behaviors (WIT revocation lifecycle in Suite 1) are not what the data says was tested.

**F6 — medium — PARTNER_COORDINATION_SUMMARY's MintID measurement table contradicts the committed trace; WP07 repeats it and cites a 13 Nov trace that is not in the repo.**
`scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md:88-92` vs `scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.jsonl` (last row `results`) and `.md`. Recomputed from the jsonl:
- issuer: t0 = 10:43:25.128Z, last_ok +19.7 s, first_no +23.1 s — doc claims t_revoke `10:42:59.092Z`, last accepted `17.1 s` (23.1 s refusal matches).
- kill_switch: t0 = 10:44:00.599Z, last_ok +14.5 s, first_no +17.1 s — doc claims `10:43:37.547Z`, last accepted `11.1 s`.
- cascade rows swapped: doc line 91 assigns `cascade_agent_1` 34.8/40.8 s, but the jsonl has `cascade_agent_1` +185.9/+189.1 s and `cascade_agent_2` +34.8/+40.8 s.
Bounds (185/245/395 s), the 13.9 s dual-origin delta, and 10 s proof lifetime do match. `workpackages/WP07-extended-scenarios-p1-p8.md:14` repeats the mismatched figures as "14 Nov testnet trace" and cites "13 Nov one-run figures (issuer: 19.7/25.2, holder: 14.6/17.1)" — no 13 Nov trace file exists in the repo (only `revocation-trace-testnet-20261114T104257Z.*`); `workpackages/README.md:60` and `WP08:21` also say "13 Nov & 14 Nov traces". Why it matters: this is the partner-facing sanitized summary; its numbers don't match the hashed artifact it points to.

**F7 — medium — model-provenance contradictions between SCENARIOS_AND_AUTHORS, interop.yaml, VERIFY.md and the reviews.**
- `SCENARIOS_AND_AUTHORS.md:49` says the inbound peers (`bin/maurice` + `peers/driver.py`, `peers/wimse.py`) were authored by "**Anthropic Claude Opus 4.6** + human authors". `interop.yaml:16,24` declares `family: unknown-maurice` and `family: openai`, and its header comment says the client adapter "was written mainly with **OpenAI Codex**; later edits ... by Anthropic Claude"; `VERIFY.md` says the same ("Maurice's provenance is unknown"; "Driver edits not written by Codex ... Claude wrote two changes").
- `SCENARIOS_AND_AUTHORS.md:49` gives two checker model IDs, `nvidia/llama-3.1-nemotron-ultra-253b-v1` / `nvidia/nemotron-3-ultra-550b-a55b:free`; only the latter is attested anywhere (`validation/nemotron-review.md`); the former appears nowhere else. Opus review item A9 asked to reconcile this — still unreconciled. `SCENARIOS_AND_AUTHORS.md:50` also says "Claude Opus 5.5 / **Sonnet 5.5**" — no Sonnet model is named anywhere (`grep -ri sonnet` → only that line); `opus-chain-review.md:5` says `claude-opus-5-5-high`.
- `validation/gemini-p1-p8-review.md:3` claims the "Anthropic Claude family ... authored Redthread's `v0.7.584`/`v0.7.586` verifier, `run_local.py`" — contradicts Ben Le / Redthread Security authorship stated in every other document.
- `interop.yaml` header discloses "Later edits to observes_chain.py / observes_p1_p8.py: Claude Opus (cbf669e, ...), Gemini (fe15e70)" while still declaring `family: nvidia` for all three checkers (lines 54/63/73) — `SCENARIOS_AND_AUTHORS.md:50` presents the chain checkers as purely Nemotron-audited. (Related known issue: `VERIFY.md` says Nemotron could not execute in its last rounds and Claude ran the verifications; `POST_HACKATHON_ANALYSIS.md` §3.3 already flags "declared, not shown".)
Why it matters: AI2II Rule L4 separation is the repo's central provenance claim; the documents disagree on which family wrote the peer under test and which wrote the checkers.

**F8 — medium — NOTICE does not cover one partner-provided file.**
`NOTICE:23,26` lists `scenarios/p1_p8/originals/redthread-*.zip` and `originals/ietf127-scenarios.zip`, but not `scenarios/p1_p8/originals/P2-revocation-after-delegation-before-effect-v1.json`, which `EVIDENCE.md:93` calls an "Unmodified Original Partner Archive" (initial P2 v1 from the partner). Every other partner-contributed file under `scenarios/p1_p8/` is covered (checked file-by-file against NOTICE globs). No partner file carries an Apache/MIT/copyright header (`grep -rli "apache|MIT license|copyright" scenarios/` → none), and `LICENSE-APACHE`/`LICENSE-MIT` are the standard texts scoped to Alexander Pelov's work — so nothing partner-owned is offered under Apache-2.0/MIT; the gap is only the NOTICE entry.

**F9 — medium — slide generator text overstates and mismatches the docs.**
`setup/generate_powerpoint.py` (text only, per scope):
- line ~175: "**4 Independent AI Family Audits**: Full code and PCAP verification by Claude Opus, Gemini, NVIDIA Nemotron, and Mistral Vibe." — `VERIFY.md` records that Nemotron "could not execute commands in its sandbox in its last three rounds. Claude ran every verification"; `validation/mistral-vibe-review.md` describes commit `3d4fab4`, which is **not** an ancestor of `main` (`git merge-base --is-ancestor 3d4fab4 main` → no; it describes `bundle-payment`/`observes_payment.py`, which exist only on `feature/opena2a-wimse-aep`).
- lines 240-247 scoreboard: omits the 4 P2 `:5064` loopback cases (2 simulated + 2 replayed) that README counts; shows only "Suite 3: P7/P8 on :5064 … 6 MOCKED" and "Suite 4 … 3/3 ✅ PASS".
- lines 355-390: trust domains "Domain A (**harbor.example**)" / "Domain B (rich.example)" — the repo's domains are `maurice.ietf127.example` / `rich.ietf127.example` (SCENARIOS §2, workpackages/README); `harbor.example` belongs to the OpenA2A payment spec (`specs/OPENA2A_WIMSE_AEP_SPEC.md`). Draft names `draft-ietf-wimse-s2s-protocol`, `draft-ietf-wimse-workload-identity-bcp`, `draft-mintid-zk-credentials` (lines 356,362,370,384) appear nowhere in the repo's normative list.
- line 269: "100% REPRODUCIBLE IN 1 COMMAND" — `reproduce.sh` verifies committed evidence and "does not re-run peers" (`TEST_RESULTS_SUMMARY.md:14`).
- Slide 1 architecture (User → Agent 1: Maurice → Token Authority → …, "9-HOP") implies Maurice forwards the chain; per accepted opus finding A2, hops 2/3/5 are sent by the driver workload `wimse://peer.ietf127.example/client` and Maurice runs a side workflow. The SCENARIOS diagram was corrected; the slide was not.

**F10 — low — "18 RFCs & Internet-Drafts" is 17.**
`TEST_RESULTS_SUMMARY.md:14`, `setup/generate_powerpoint.py:158,461`. Counting the documents in the normative table (`SCENARIOS_AND_AUTHORS.md` §2, same list in `WP08:21`): 8 `draft-ietf-wimse/oauth` + `draft-le-agent-passport` + 2 `draft-thallapelly-*` + `draft-sweeney-*` + RFC 9421, 9530, 9457, 8693, 7523 = **17**.

**F11 — low — VERIFY.md inconsistencies still open.**
`VERIFY.md:9`: "verdict PASS at commit `801b463`" — both `verdict.json` files record `4584533…` (inbound) and `8f8441e…` (chain); `801b463` exists in history but is not the bundle commit (already noted in `POST_HACKATHON_ANALYSIS.md` §3.2; still unfixed). `VERIFY.md:25` calls `validation/bundle-inbound/inbound/` "git-ignored" — it is tracked (`git ls-files validation/` lists it; `git check-ignore` → not ignored).

**F12 — low — EVIDENCE.md "104 with default `tshark -Y http`" does not reproduce.**
`EVIDENCE.md:31` (chain capture row: "106 (53 exchanges; 104 with default `tshark -Y http`)"). Measured on tshark 4.6.9: `tshark -r validation/bundle-chain/chain/capture.pcap -Y http | wc -l` → **106** (53 requests + 53 responses); also 106 with the Lua dissector. The headline 106 is correct; only the parenthetical is wrong.

**F13 — low — EVIDENCE.md claims to index "every … partner trace manifest (.json)" but omits one.**
`redthread-P2-local.manifest.json` (24 lines, sha256 `d59d59eb…`, listed in `PARTNER_COORDINATION_SUMMARY.md` §6) has no row in `EVIDENCE.md` §3.2 (`grep -n redthread-P2-local.manifest EVIDENCE.md` → none).

**F14 — low — TEST_RESULTS_SUMMARY's Suite 2 flow misstates who calls whom.**
`TEST_RESULTS_SUMMARY.md:8`: "9-hop … (`User -> TTS-A -> Maurice -> AS-A -> AS-B -> Agent 2 -> …`)" — per accepted opus finding A2, the driver (not Maurice) sends hops 2, 3 and 5; the corrected `SCENARIOS_AND_AUTHORS.md` diagram shows this, the summary row does not.

**F15 — low — POST_HACKATHON_ANALYSIS contains stale or wrong specifics.**
Line 3: "23 commits on `main`" — `git rev-list --count main` = **31** now (24 even at the doc's own commit `0f3f9af`). Line 62 names `WP09-architecture-nemotron.md` — exists on no branch (`git log --all -- workpackages/WP09-architecture-nemotron.md` empty). Line 65: "Slide generator (471 lines)" — `wc -l setup/generate_powerpoint.py` = 472. Line 67: "10 MB of pcaps" — `find validation checkers -name '*.pcap' | xargs du -ch` = **1.3M** total. Lines 7/93 reference `../AI2II/DESIGN.md` §24.20 — not present in this checkout (`ls ../AI2II` → no). (Verified correct in the same doc: `da67b0f` = 27 files, `4679466` = +4610 lines, "76 min", all cited commit IDs exist, 5 review files, `feature/opena2a-wimse-aep` exists.)

**F16 — low — workpackages/README internal slips.**
Line 3: "Work Packages (`WP01`–`WP06`)" though WP01–WP09 exist. Line 7 cites `WP-template.md`, which is not in the repo (known, still open per `POST_HACKATHON_ANALYSIS.md` §3.7).

**F17 — low — "hashes sent" vs "not received" for Redthread.**
`workpackages/WP09-live-redthread-and-mintid-testnet.md:24`: "the file hashes Ben Le **sent** on 15 Nov 17:59 UTC (not yet in this repo)" vs `TEST_RESULTS_SUMMARY.md:22`: "have **not been received**".

**Still-open items from earlier reviews (checked, not closed):** Mistral F1 (`issubset` at `observes_chain.py`) is **closed** at `ae228cc` (B_CHAIN now requires all-200); opus A6's 104-vs-106 is fixed in the headline number but the "104 with default" parenthetical remains (F12); opus A9 (reconcile the two Nemotron model IDs) still open (F7); `VERIFY.md` commit mismatch still open (F11); `mistral-vibe-review.md` still describes the non-`main` tree `3d4fab4` (documented in `POST_HACKATHON_ANALYSIS.md` §3.9, file unchanged); `nemotron-p1-p8-review.md:14` still says "Audit Date: 2025-11-15" (its own triage says 2026).

## Table of findings

| # | Severity | Location | Issue |
|---|---|---|---|
| F1 | high | `EVIDENCE.md:43-45` | SHA-256 digests + packet counts stale for 3 chain mutants regenerated in `ae228cc` (verified by `sha256sum`/`tshark`) |
| F2 | high | `README.md:7` | "85/85 passing cases" sums mixed evidence classes (incl. 6 mocked, 22 not-executed traces), violating CONTRIBUTING's own rule; "9/9" stale |
| F3 | medium | `EVIDENCE.md` §2.2, `README.md:22,99`, `TEST_RESULTS_SUMMARY.md:8` | 10th mutant `chain_hop_flipped.pcap` undocumented; counts say 9/9 and 3/3, actual 10/10 and 4/4 |
| F4 | medium | `SCENARIOS_AND_AUTHORS.md:13` | cites 3 nonexistent files under `specs/` |
| F5 | medium | `SCENARIOS_AND_AUTHORS.md:64-69`, `TEST_RESULTS_SUMMARY.md:7` | Suite 1 catalog IDs/outcomes contradict `cases.json` |
| F6 | medium | `PARTNER_COORDINATION_SUMMARY.md:88-92`, `WP07:14` | MintID t_revoke/last-accept values and cascade agent rows contradict the committed jsonl; "13 Nov trace" absent |
| F7 | medium | `SCENARIOS_AND_AUTHORS.md:49-50`, `interop.yaml:16,24,54-73`, `VERIFY.md`, `gemini-p1-p8-review.md:3` | model-provenance contradictions (peer family, dual Nemotron IDs, "Sonnet 5.5", Redthread authorship claim, later same-family checker edits) |
| F8 | medium | `NOTICE:23,26` vs `EVIDENCE.md:93` | partner original `originals/P2-...-v1.json` not listed in NOTICE |
| F9 | medium | `setup/generate_powerpoint.py:175,240-247,269,355-390` | "full PCAP verification by Nemotron" overstated; scoreboard omits P2 :5064 cases; `harbor.example` domains and unlisted draft names; "100% reproducible"; stale 9-hop flow |
| F10 | low | `TEST_RESULTS_SUMMARY.md:14`, `generate_powerpoint.py:158,461` | "18 RFCs & Internet-Drafts" — countable list has 17 |
| F11 | low | `VERIFY.md:9,25` | commit `801b463` vs verdict `4584533…`; bundle called "git-ignored" but is tracked |
| F12 | low | `EVIDENCE.md:31` | "104 with default tshark -Y http" — measured 106 (tshark 4.6.9) |
| F13 | low | `EVIDENCE.md` §3.2 | `redthread-P2-local.manifest.json` missing despite "every manifest" claim |
| F14 | low | `TEST_RESULTS_SUMMARY.md:8` | 9-hop flow shows Maurice as forwarder; wire shows driver sends hops 2/3/5 |
| F15 | low | `POST_HACKATHON_ANALYSIS.md:3,62,65,67,7,93` | 23 commits (31), nonexistent WP09-architecture file, 471 (472) lines, 10 MB (1.3 MB) pcaps, `../AI2II` absent |
| F16 | low | `workpackages/README.md:3,7` | "WP01–WP06" (WP01–09 exist); `WP-template.md` cited but missing |
| F17 | low | `WP09:24` vs `TEST_RESULTS_SUMMARY.md:22` | Redthread hashes "sent" vs "not received" |

## Checked and found correct

- **Counts:** `cases.json` = 34 cases (35 steps), `chain_cases.json` = 19 cases — match README/TEST_RESULTS_SUMMARY/SCENARIOS. Redthread traces: 5+2+6+3+4+2 = 22 cases, `redthread-local.manifest.json` has 22 results all `match:true`, `clock:"simulated"`, version `0.7.584`. All JSONL/JSON line counts in EVIDENCE §3 (35, 38, 9, 122, 6, 8, 4, 2, 92, 4, 34, 11; specs 97/98/71/78/62) match `wc`/splitlines. `chain-journal.jsonl` lines 34–36 match the D5/D6 references in SCENARIOS.
- **Hashes/sizes:** every SHA-256 and byte size in `PARTNER_COORDINATION_SUMMARY.md` §6 (24 active files + 4 originals) matches; every EVIDENCE.md digest matches **except** the three in F1; both `verdict.json` hashes match EVIDENCE §1; `contains_secrets:false` in both verdicts; both bundle `SHA256SUMS` verify (13/13 inbound, 17/17 chain); verdict commits `458453327d36…`/`8f8441e4af00…` match the README/EVIDENCE PASS lines; maurice binary hash `36f92fe8…` is consistent across `verdict.json`, VERIFY.md, README (the binary itself is not in the repo — unverifiable, but internally consistent).
- **Packet/HTTP counts:** 536 / 824 packets and 72 / 106 HTTP messages (53+53) for the two live captures match EVIDENCE; the six unchanged mutants' packet counts (3, 245, 491, 3, 70, 20) match.
- **Evidence classes:** every Suite-3/Suite-4 row in TEST_RESULTS_SUMMARY carries explicit classes (simulated, replayed, mocked, partner-attested, partner-reported/record-pending) and does not sum them; Jacob Stewart's external matrix is explicitly excluded from totals; the 17 Nov Redthread run is labeled partner-reported with "record pending" everywhere it appears; Suite 4 correctly says there is no `live-partners` cell in `interop.yaml` (true) and that only 3 probes are live (matches `observes_live_partners.py`).
- **Attribution:** no Redthread repository URL anywhere (grep over all docs/code: none); Iman Schrock credited "test design only, no EMILIA runtime" consistently in SCENARIOS, NOTICE, WP09, TEST_RESULTS_SUMMARY; OmniArx→P7, Cred→P8 (`cred-ninja/sdk` `83e9cec…`, run `2026-11-15T18:40:42Z`, 11 lines, manifest hash matches file), MintID sandbox attribution and versions (`0.7.584` traces / `0.7.586` sandbox / `0.7.591`+`3a6560c` draft / `0.7.592` 17 Nov run; MintID tags `public-v2026-11-13.1` checkout vs `public-v2026-11-11.1` services) are consistent across docs and manifests; scenario JSONs name their proposers correctly.
- **Licensing:** LICENSE-APACHE is the unmodified Apache-2.0 text, LICENSE-MIT is Alexander Pelov's; no partner file in `scenarios/` carries any license/copyright header; NOTICE covers all partner files except the one gap in F8.
- **Links:** all relative Markdown links in every `.md` resolve (script over all files: 0 broken); no `file://` or `/Users/…` paths remain in `workpackages/` or `specs/` (fixed in `ae228cc`); external URLs (project GitHub, agentmaurice.ai, mintid.net) could not be checked offline — unverified, not counted as findings.
- **Other verified claims:** the sandbox zip truncation note is accurate (`unzip -t` → "missing 864 bytes in zipfile", doc says 864); `reproduce.sh` does offer `--live`/`--live-testnet` as the slide claims; `feature/opena2a-wimse-aep` branch exists; POST_HACKATHON's `da67b0f`=27 files, `4679466`=+4610 lines, 76-minute gap, and all cited commit IDs check out.

## Maintainer triage (17 Nov 2026)

Several findings describe `ae228cc` and were already fixed in `73cd9e0` (recorded again, docs updated) while the review ran.

| # | Decision | Change |
|---|---|---|
| F1 | already fixed in `73cd9e0` | mutant digests and packet counts updated; mutants now 11 (`chain_leaked_txn_body.pcap` added after the code review) |
| F2 | already fixed in `73cd9e0` | README no longer adds classes together |
| F3 | already fixed in `73cd9e0` | every mutant listed; counts updated |
| F4 | accepted | the three AgentMaurice specs are named as documents outside this repository |
| F5 | accepted | the Suite 1 catalog in `SCENARIOS_AND_AUTHORS.md` is now generated from `cases.json` (one row per case and step); the Suite 1 row in `TEST_RESULTS_SUMMARY.md` names the real cases |
| F6 | accepted | the MintID table in `PARTNER_COORDINATION_SUMMARY.md` is rebuilt from the trace's `results` row (the issuer and kill-switch `t0` and last-acceptance values were wrong, the cascade agents were swapped, and a "principal" row had no source in the trace); WP07, WP08 and the workpackages README label the 13 Nov figures as reported by email |
| F7 | accepted | `SCENARIOS_AND_AUTHORS.md` now agrees with `interop.yaml` and `VERIFY.md` (Maurice provenance unknown; client adapter mainly Codex; checkers by Nemotron, later edited by Claude and Gemini, so separation is partial); the unattested Nemotron model id and "Sonnet 5.5" removed; maintainer notes added to `gemini-p1-p8-review.md` (Redthread's model family is not recorded here) and `nemotron-p1-p8-review.md` (date) |
| F8 | accepted | `NOTICE` lists `originals/P2-revocation-after-delegation-before-effect-v1.json` |
| F9 | accepted (most already fixed) | deck: real domains and draft names from the normative list, no "100% reproducible", the P2 `:5064` cases have their own row, the architecture strip shows the client workload making the calls, Maurice's row describes Suite 1 |
| F10 | accepted | 17 documents, not 18 |
| F11 | accepted | `VERIFY.md` cites `bf10aed`; the bundle is described as committed |
| F12 | already fixed in `73cd9e0` | |
| F13 | accepted | `redthread-P2-local.manifest.json` added to `EVIDENCE.md` |
| F14 | accepted | Suite 2 row describes who calls whom |
| F15 | partly accepted | 10 MB corrected to 1.3 MB; the WP09 file is described as never committed; the commit and line counts describe the state when the analysis was written and are covered by its dated status note |
| F16 | accepted | WP range and the template reference corrected |
| F17 | accepted | WP09 now says the hashes were mentioned, not received |
