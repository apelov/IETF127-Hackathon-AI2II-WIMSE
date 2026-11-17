# Verification handoff: WIMSE inbound harness (2026-11-14)

Purpose: let a fresh Claude session (or a human) independently check the claims below.
Do not trust this file. Re-run the commands and read the evidence.

## Claims

1. `peers/driver.py` passes all 34 cases in `cases.json` against a local Maurice.
2. The AI2II cell `inbound` has verdict PASS at commit `bf10aed` with a clean tree (recorded again on 17 Nov 2026; first recorded at `801b463`).
3. `checkers/observes_wimse.py` is an independent checker. Nemotron Ultra wrote it via `claude-or`. It
   accepts a real capture (34 cases, 0 errors) and rejects all three negatives.
4. The Maurice binary under test is `bin/maurice`, sha256 `36f92fe85b5b8ad3675cdf84800dcb0ae22507523ee6e9e9f679b69e1603c695`.

## Layout

| Path | Role |
|---|---|
| `cases.json` | Expected outcomes (status, problem type, challenge, journal reason) |
| `peers/driver.py`, `peers/wimse.py` | Client adapter; checks status, journal entry, no-fetch of C12/C12b URL |
| `checkers/wire.py` | Same-family dev checker, **not** the independent one |
| `checkers/observes_wimse.py` | Independent checker (Nemotron) |
| `checkers/make_negatives.py`, `checkers/negatives/*.pcap` | Capture mutants: unrelated, request_only, forbidden_fetch |
| `setup/` | Keys, config patch, build, env check, run, ready check |
| `interop.yaml` | AI2II manifest |
| `validation/bundle-inbound/inbound/` | Evidence bundle from the PASS run (committed) |

## Re-run (needs port 5050 free, tree committed; run outside any sandbox)

```sh
git status --short                       # must be empty for dirty=false
lsof -nP -iTCP:5050 -sTCP:LISTEN         # must print nothing
rm -rf validation/bundle-inbound
PYTHONPATH=. .venv/bin/python -m wire run interop.yaml --cell inbound --out validation/bundle-inbound
PYTHONPATH=. .venv/bin/python -m wire verify-bundle validation/bundle-inbound/inbound
PYTHONPATH=. .venv/bin/python -m wire validate-checkers interop.yaml
```

Offline checks on the saved evidence:

```sh
B=validation/bundle-inbound/inbound
python3 checkers/observes_wimse.py $B/capture.pcap | tail -1         # SUMMARY cases=34 errors=0
for n in forbidden_fetch request_only unrelated; do
  python3 checkers/observes_wimse.py checkers/negatives/$n.pcap >/dev/null; echo $n $?   # each nonzero
done
grep -E '"(verdict|commit|dirty)"' $B/verdict.json
shasum -a 256 bin/maurice
```

## What to scrutinise

- **Independence.** Maurice's provenance is unknown. The checker (Nemotron) differs from the adapter family.
  Nemotron could not execute commands in its sandbox in its last three rounds. Claude ran every
  verification after each of its edits. Read the `git log -p -- checkers/observes_wimse.py` history.
- **Driver edits not written by Codex.** Claude wrote two changes: the `journal_entry` fallback, which matches
  `mixed-credentials` entries that lack `wit_sha256`, and the A6b rewrite. The A6b rewrite sends a valid WIT +
  WPT plus `Authorization: Bearer` via `extra_headers`. The `interop.yaml` header comment records both
  OpenAI Codex and Anthropic Claude for the client adapter.
- **A6b may be weak.** The driver accepts any unfingerprinted `mixed-credentials` entry in the journal window.
  This is sound only for a single-client run. A6b's expectation allows status 400 or 401.
- **Journal matching.** Maurice journals mixed-credential rejections with empty `peer_id`, `wit_jti` and
  `wit_sha256`. Confirm that this is intended behaviour and not a Maurice bug worth reporting.
- **`under_test: true` on `wimse-client`** in `interop.yaml`. Check it against the AI2II design.
- **Checker strictness.** It now ignores requests with no `X-Test-Case` that are not POSTs to the executions
  route (the harness's JWKS readiness probe). Check this cannot hide a real untagged test request.
- **Negatives.** `forbidden_fetch` is a synthetic TCP connection to port 47999 added to a real capture.
  Check that it is a fair mutant.
- **Single run.** There is no repeat run for flakiness.
- **`X-Test-Case` is unsigned,** so the checker is valid only for a controlled single-client capture.

## Environment notes

- Earlier a Maurice (PID 20525) occupied port 5050. It was killed, not restarted.
- The runner needs unsandboxed execution (tcpdump, ports). `.git` writes were blocked under the sandbox.
- The `~/.maurice/one/config/standalone.yaml` file was patched by `setup/patch_config.py`, with a backup next to it.
