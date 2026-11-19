Local paths redacted; no other change.
# Hermes verification after replacement authorization

OpenAI authored the active checker, `checkers/observes_cred_p8.py`:
Codex based on GPT-6; exact model ID not exposed by the runtime

The authoring record is `codex-checker-provenance.md`. Hermes did not edit the checker.
Its SHA-256 remained `6facb48398e57f080f86051767d2fd969847cb91fd64f1d3be3dfa673c08cebd`.
The failed Arete attempt remains closed: nine code-and-test rounds, never passed the real capture.
Its records are unchanged, with the final source modules archived under `failed-arete/`.
Historical paths in earlier records describe the attempt at the time, not current wiring.

## Runtime and scope

- Python 3.12.16; Node v22.23.5; tshark 4.6.9; unprivileged tcpdump on macOS lo0.
- Cred commit `83e9cecfebebff653b35e1aa9fef83749e603a01`, clean.
- Successful recording source commit `986d165db2fd54f74e7548421c254c9725854862`, clean.
- Capture publication of ephemeral test tokens was authorized. No private signing keys or production credentials are included.
- Ports 5065, 5066 and 5067 had no listening servers after the run. The task-specific server state directory no longer existed.
- No sudo, push, remote tag, fork, pull request or message was issued.

## Commands and outcomes

The capture and mutant command was `.venv/bin/python -B checkers/observes_cred_p8.py <capture>`.
Full preliminary results are in `hermes-codex-validation-1.json`.

| Input | Exit | Deciding diagnostic |
|---|---:|---|
| Preliminary real capture | 0 | PASS 6 provider requests and released bearer; all six assertions passed |
| cred_p8_unrelated.pcap | 1 | FAIL 2 tagged HTTP steps: no P8 step requests in capture |
| cred_p8_request_only.pcap | 1 | FAIL 2 tagged HTTP steps: first step has no matched final HTTP response |
| cred_p8_no_provider.pcap | 1 | FAIL 6 provider requests and released bearer: provider saw 0 requests, expected 2 |
| cred_p8_mock_status.pcap | 1 | FAIL 4 A revocation before use: A use after revocation returned HTTP 403, expected 401 |
| cred_p8_bearer_mismatch.pcap | 1 | FAIL 6 provider requests and released bearer: direct provider bearer differs from the bearer released by configuration B |
| Empty capture | 1 | FAIL 2 tagged HTTP steps: no P8 step requests in capture |
| Unreadable path | 1 | FAIL 1 read-only permission grants: capture unreadable or tshark failed to decode it |

These results match the Codex authoring table. The committed bundle's checker log independently records the passing fresh capture and intended mutant diagnostics.

1. `wire run interop.cred-p8.yaml --cell cred-p8 --out validation/bundle-cred-p8`, through `.venv/bin/python -m wire` with `PYTHONPATH=.`: first attempt exited 3, `BLOCKED: cred-p8: experiment directory has uncommitted or untracked changes`. The env check created its own untracked output log before the cleanliness check. It did not start capture. That generated attempt is retained outside the repository at `<scratch>/wire-blocked-codex-1/`.
2. The same command with only the generated output directory locally excluded exited 0, `PASS: cred-p8: all peers exited 0, capture non-empty, every checker passed and rejected its negatives`. The local exclude did not hide source changes. It was removed after the verified bundle was committed. No capture permission error occurred and no wire code was changed.
3. `PYTHONPATH=. .venv/bin/python -m wire verify-bundle validation/bundle-cred-p8/cred-p8` exited 0, `OK`. The generated verdict was PASS, both peers exited 0, and both repositories were recorded clean. Only then was the bundle committed as `014a229`.
4. `./reproduce.sh` after the bundle commit exited 0, `=== ALL REPRODUCIBILITY CHECKS PASSED ===`. The original checkers reported 34, 19 and 10 cases with zero errors; the additional Cred checker passed six assertions and rejected five mutants.
5. A fresh detached baseline worktree at `origin/main`, `622ef5a953fa1deed2818e9bd3e8cb538b782b14`, with a real Python 3.12 virtual environment, ran untouched `./reproduce.sh` in this session: exit 0, 34/19/10 cases, zero errors. An initial baseline preflight found that a temporary `.venv` symlink was untracked; no reproduction was run in that state. It was replaced with a task-local virtual environment, and cleanliness was confirmed before reproduction.
6. All 51 EVIDENCE.md artifact digest rows were recomputed and matched, including the existing artifacts. The new capture has 148 packets, 30 HTTP messages (15 requests and 15 responses), 12 tagged requests and zero kernel drops.
7. `.github/workflows/reproduce.yml` has an empty diff against origin/main. The old change was already reverted. Existing CI installs tshark and runs `./reproduce.sh`, sufficient for offline verification of this cell without Node or a Cred checkout.

The current bundle is distinct from the preliminary capture used to derive the five committed mutants. No pcap, verdict or generated checksum file was hand-edited.

## Site/deck regeneration exceptions

All attempts used the existing task `.venv`:

| Generator | Exit | Diagnostic |
|---|---:|---|
| setup/build_site.py | 1 | ModuleNotFoundError: No module named 'lxml' |
| setup/generate_test_catalog.py | 1 | ModuleNotFoundError: No module named 'lxml' |
| setup/generate_wg_deck.py | 1 | ModuleNotFoundError: No module named 'pptx' |
| setup/generate_session_deck.py | 1 | ModuleNotFoundError: No module named 'pptx' |
| setup/generate_powerpoint.py | 1 | ModuleNotFoundError: No module named 'pptx' |

As expressly authorized, the site, generators and committed decks remain unchanged. They do not display the additional observed-on-wire cell yet. No `--force` overwrite of the hand-edited session deck was attempted.

Command logs are retained under `<scratch>/`: `wire-run-codex-1.log`, `wire-run-codex-2.log`, `reproduce-codex-bundle-1.log`, `baseline-reproduce-codex-1.log`, `hermes-codex-failclosed-1.json`, and each generator's `<name>-codex-1.log`. The committed bundle holds the capture, environment, journals, checker output and generated digests.
