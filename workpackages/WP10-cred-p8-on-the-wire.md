# WP10: Scenario P8 answered by real Cred, on the wire

Status: the earlier branch recorded **PASS, observed-on-wire**, with 148 packets,
12 tagged steps, all six checker assertions passed and all five mutants rejected.
This clean-history branch must record a new bundle from its first commit, verify it outside
the checkout, then copy the unmodified PASS bundle into the repository. The bundle's `env.json`
and `verdict.json` identify the exact clean source commit and observed counts.
The original mocked and partner-attested rows remain separate and unchanged.

Draft: `draft-sweeney-wimse-credential-delegation-02`, *Credential Delegation Protocol for AI
Agents in Multi-System Environments*.

Inputs: `CONTRIBUTING.md`, `interop.yaml`, `wire/`, `scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json`, `scenarios/p1_p8/cred-P8.jsonl`, `scenarios/p1_p8/cred-P8.manifest.json`

## Why

`TEST_RESULTS_SUMMARY.md` lists P8 twice: four mocked loopback cases (`impl: p8-fixed-answer-mock`,
403 for every refusal) and Cred's own run (partner-attested, different statuses, not verified by
`observes_p1_p8.py`). This package puts Cred's own code on loopback ports inside a `wire` capture, so
a capture checker can verify Cred's real answers. The mock on `:5064` and the partner record stay as
they are.

## What runs

| Port | What | Code |
|---|---|---|
| `127.0.0.1:5065` | Cred, configuration A: WIMSE (WIT + WPT or HTTP signature), required Txn-Tokens, brokered handles only | Cred (`cred-ninja/sdk`, `hackathon/ietf127`, commit in `cred_p8_cases.json`) |
| `127.0.0.1:5066` | Cred, configuration B: deprecated `allowRawTokens`, no Txn-Tokens, read-only connection | Cred, same commit |
| `127.0.0.1:5067` | Bearer-only provider: accepts any bearer token, no introspection, no revocation | mock in `peers/cred_p8/serve.mjs` (same behaviour as Cred's `scripts/hackathon/lib/mock-provider.mjs`, on a fixed port) |

`peers/cred_p8/serve.mjs` starts the three through Cred's hackathon helper
(`scripts/hackathon/lib/cred.mjs`). `peers/cred_p8/driver.mjs` sends the steps with Cred's hackathon
client (`scripts/hackathon/lib/client.mjs`) and tags each request with `X-Test-Case: P8CRED_<case>_<step>`.
Nothing in the Cred checkout is modified.

Steps and expected answers are in `cred_p8_cases.json`: the eleven steps of `cred-P8.jsonl` plus one
control, `write-under-read/read-allowed` (a read under the read-only grant succeeds and Cred calls
the provider once), so that "no provider traffic during a refusal" is a real observation.

| Step | Port | Cred answers | Scenario reason |
|---|---|---|---|
| no-delegation / use-without-delegation | 5065 | 401 `invalid_token` | no-delegation |
| no-delegation / ask-for-delegation | 5065 | 403 `permission_required` | no-delegation |
| write-under-read / delegate-read | 5065 | 200 | ok |
| write-under-read / read-allowed (control) | 5065 | 200, one provider call | ok |
| write-under-read / write | 5065 | 403 `scope_insufficient` | scope-exceeded |
| revoked-between-authz-and-use / delegate-read | 5065 | 200 | ok |
| revoked-between-authz-and-use / revoke | 5065 | 200 | ok |
| revoked-between-authz-and-use / use-after-revoke | 5065 | 401 `delegation_revoked` | status-revoked |
| revoked-after-token-released / ask-for-bearer-token | 5065 | 403 `raw_token_disabled` | (runner's name: token-not-released) |
| revoked-after-token-released / release-bearer-token | 5066 | 200 with the provider bearer token | token-released |
| revoked-after-token-released / revoke | 5066 | 200 | token-released |
| revoked-after-token-released / direct-provider-call | 5067 | 200 from the provider | token-released |

## Files

- `cred_p8_cases.json`: steps, ports, expected status and Cred error per step, pinned Cred commit.
- `peers/cred_p8/serve.mjs`, `peers/cred_p8/driver.mjs`: launcher and driver.
- `setup/check_cred_p8_env.py`, `setup/check_cred_p8_ready.py`: environment and readiness checks.
- `interop.cred-p8.yaml`: the `cred-p8` cell. It is a separate manifest because `env_checks` apply to
  every cell of a manifest, and the `inbound` and `chain` cells must not need node or a Cred checkout.
- `checkers/observes_cred_p8.py`: independent OpenAI checker (see "Rule L4").
- `validation/cred-p8-checker-provenance/`: two path-redacted historical verification records and
  the concise Arete summary identifying the externally retained full archive.
- `checkers/cred_p8_dev.py`: original Claude development checker, imported only by the mutant generator.
- `checkers/make_cred_p8_negatives.py`: derives five mutants from a real capture.
- `reproduce.sh`: runs the checker and the mutants when `validation/bundle-cred-p8/` is committed.

## Prepare and run

```sh
git clone -b hackathon/ietf127 https://github.com/cred-ninja/sdk.git external/cred
git -C external/cred checkout "$(python3 -c 'import json;print(json.load(open("cred_p8_cases.json"))["cred"]["commit"])')"
(cd external/cred && npm ci && npm run build)
.venv/bin/python setup/check_cred_p8_env.py
```

First run, to obtain a capture for the mutants (needs tcpdump, tshark and Node 22; ports 5065 to
5067 free). Use `lo0` on macOS and `lo` on Linux. This recording used unprivileged tcpdump after
Kieran assigned this user's BPF device ownership for the session; that permission resets at reboot.
No `wire` code change was needed: it already resolves `loopback` to `lo0` on macOS. Set `TMPDIR`
to your scratch directory and ensure capture permission is available before starting:

```sh
CAPTURE="$TMPDIR/cred-p8.pcap"
tcpdump -i lo0 -n -U -w "$CAPTURE" -- "tcp port 5065 or tcp port 5066 or tcp port 5067" &
node peers/cred_p8/serve.mjs --cred external/cred &
node peers/cred_p8/driver.mjs
# stop both, then:
.venv/bin/python checkers/observes_cred_p8.py "$CAPTURE"
.venv/bin/python checkers/make_cred_p8_negatives.py "$CAPTURE"
git add checkers/negatives/cred_p8_*.pcap && git commit
```

Then the cell, on a clean tree:

```sh
OUT="$TMPDIR/cred-p8-wire-bundle"
PYTHONPATH=. .venv/bin/python -m wire run interop.cred-p8.yaml --cell cred-p8 --out "$OUT"
PYTHONPATH=. .venv/bin/python -m wire verify-bundle "$OUT/cred-p8"
# Only after both commands exit 0 and verdict.json says PASS:
mkdir -p validation/bundle-cred-p8
cp -R "$OUT/cred-p8" validation/bundle-cred-p8/
```

## What the checker asserts

From the packets alone (it does not read the driver's journal):

1. The only permission each Cred server is given before the steps is `calendar.readonly`.
2. Every step is on the wire once, on its port, with the status and `{error}` code above.
3. Cred's codes map to the scenario reasons through `reason_mapping` in `cred-P8.manifest.json`, and
   those are the reasons the P8 scenario file expects.
4. revoked-between-authz-and-use: the revocation names the delegation that was granted and is
   answered 200 before the use, and the refused use presents that same Delegation Token.
5. Configuration A never sends the provider bearer token towards the agent (the token is learned
   from Cred's own provider call during the control read).
6. The provider sees exactly two requests: Cred's call inside the allowed read, and the agent's
   direct call after revocation, with exactly the bearer token configuration B released.

Mutants: `cred_p8_unrelated`, `cred_p8_request_only`, `cred_p8_no_provider`, `cred_p8_mock_status`
(the refused use answered 403, the mock's status, instead of Cred's 401), `cred_p8_bearer_mismatch`.

## Rule L4

Cred was written mainly with Anthropic Claude, with occasional edits by OpenAI Codex.
Anthropic Claude wrote the launcher, driver, mutant generator and original development
checker. Only the mutant generator imports the development checker.

OpenAI Codex wrote `checkers/observes_cred_p8.py` without reading Cred's source or any
earlier checker. Both `cred-p8-stack` and `cred-p8-client` declare peer family
`anthropic+openai`. The packet checker declares `openai`. Because OpenAI appears on
both sides, the family separation is partial.

Codex based on GPT-6; exact model ID not exposed by the runtime

The checker prompt, files read, original test results and source digest are in
`validation/cred-p8-checker-provenance/codex-checker-provenance.md`. Hermes reran the
saved checker without modifying it. The checker uses packet evidence decoded by tshark.

### Failed Arete attempt retained

The earlier Nous Research Arete 27B attempt is closed as failed: nine code-and-test rounds,
including the three-round extension, never passed the real capture. Nonzero mutant exits in that
attempt did not establish discrimination. No further Arete repair cycle is authorized or running.
All raw prompts, replies, streams, failures, modules and stop reports are retained outside
Git by Kieran Sweeney. `validation/cred-p8-checker-provenance/arete-attempt-summary.md` records
the seven setup failures, nine code-and-test rounds, final failure and archive identity.
The raw attempt is not active code and is not included in this branch's history.
The two other kept provenance documents are historical records from the earlier branch;
only their local scratch paths are redacted. The fresh bundle is this branch's recording evidence.

### CI

`git diff origin/main -- .github/workflows/reproduce.yml` is empty. The prior proposed CI change
was reverted. Existing CI already installs tshark and runs `./reproduce.sh`, which checks the
committed Cred capture and all five mutants. CI does not need Node or a Cred checkout for these
offline checks and does not rerun the peers.

## Site and decks

Regeneration was attempted with the existing task `.venv`. `setup/build_site.py` and
`setup/generate_test_catalog.py` exited 1 with `ModuleNotFoundError: No module named 'lxml'`.
`setup/generate_wg_deck.py`, `setup/generate_session_deck.py` and `setup/generate_powerpoint.py`
exited 1 with `ModuleNotFoundError: No module named 'pptx'`. As authorized, the site, generators
and committed decks are left unchanged. They do not yet display this additional observed-on-wire
cell; the new result is in the Markdown result tables and the verified bundle. No session deck
was overwritten with `--force`.

## Verification and clean-history rebuild

The unchanged replacement passed the preliminary capture and rejected all five mutants for
their intended reasons. The historical command table is kept in
`validation/cred-p8-checker-provenance/hermes-resume-verification.md`; its raw logs and the full
failed attempt are externally archived. The checker source SHA-256 is unchanged.

Commit the cell, peers, cases, checker, helper, mutant generator, mutants, slim provenance,
this work package and reproduction wiring first. On that clean commit, record outside the
checkout and run `wire verify-bundle`. Copy the complete bundle without editing any generated
pcap, verdict or checksum; commit it only on PASS. Then update result rows and recompute the
new bundle's EVIDENCE.md digests. `./reproduce.sh` must exit 0 at the final clean commit.
`wire/` and `.github/workflows/reproduce.yml` are unchanged.

Do not use sudo. A capture permission failure is a stop-and-report condition.
