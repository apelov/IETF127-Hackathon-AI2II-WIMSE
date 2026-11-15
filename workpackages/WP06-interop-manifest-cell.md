# WP06 — Wire `chain` Cell into `interop.yaml`

Tier: mini-code
Inputs: workpackages/README.md, workpackages/WP05-chain-wire-checker.md, interop.yaml, setup/run_server.py, setup/check_ready.py

Add `setup/run_chain_servers.py`, `setup/check_chain_ready.py`, and the `chain` cell to `interop.yaml` so `python -m wire run interop.yaml --cell chain --out validation/bundle-chain` runs Maurice + Domain A + Domain B + the chain driver + the independent checker and produces an AI2II `PASS` bundle.

## Why

To produce verifiable AI2II wire evidence for the multi-agent scenario without breaking the existing `inbound` cell, `interop.yaml` needs a second cell (`chain`) that starts Maurice (`:5050`) plus the Domain A (`:5051`) and Domain B (`:5061`, `:5062`, `:5063`) services, captures all loopback ports (`5050, 5051, 5061, 5062, 5063, 47999`), runs `peers/chain_driver.py --with-maurice`, and validates the capture with `checkers/observes_chain.py` and its 3 negative captures.

Depends on: WP05.

## Deliverables

1. Create `setup/run_chain_servers.py`:
   - Starts `domain_a` (`:5051`) and `domain_b` (`:5061`, `:5062`, `:5063`) in background daemon threads, and then runs `bin/maurice serve --runtime-config ~/.maurice/one/config/standalone.yaml` as a foreground child process if `bin/maurice` and `~/.maurice/one/config/standalone.yaml` exist, OR falls back to a built-in Python `:5050` WIMSE responder (`domain_a.start_maurice_fallback_on_5050()`) when cloned on a machine without `maurice` installed (forwarding `SIGTERM`/`SIGINT` so when AI2II stops the server process group, all ports close cleanly).
2. Create `setup/check_chain_ready.py`:
   - Checks that `http://127.0.0.1:5050/.well-known/wimse/jwks.json` returns `200` AND TCP ports `5051`, `5061`, `5062`, `5063` accept connections on `127.0.0.1`. Exits `0` when all are ready, else `1`.
3. Update `interop.yaml`:
   - Update `capture.filter` to `"tcp port 5050 or tcp port 5051 or tcp port 5061 or tcp port 5062 or tcp port 5063 or tcp port 47999"` (this is a superset of the original filter, so `inbound` remains 100% compatible).
   - Add peers `chain-stack` (runs `setup/run_chain_servers.py`, ready `setup/check_chain_ready.py`, `binaries: [bin/maurice]`) and `wimse-chain-client` (runs `.venv/bin/python peers/chain_driver.py --with-maurice --journal-out {bundle}/chain-journal.jsonl`).
   - Add checker `observes-chain` (`observes_capture: true`, `command: .venv/bin/python checkers/observes_chain.py {capture}`, with the 3 `chain_*.pcap` negatives).
   - Add cell `chain` (`server: chain-stack`, `clients: [wimse-chain-client]`, `checkers: [observes-chain]`, `timeout_s: 120`).

## Owns (touch only these)

- `setup/run_chain_servers.py`
- `setup/check_chain_ready.py`
- `interop.yaml`

Do **not** modify `peers/driver.py`, `checkers/observes_wimse.py`, or `cases.json`.

## Constraints / invariants

- Both `validate-checkers` and `wire run` for `--cell inbound` and `--cell chain` must pass with a clean git tree (`dirty: false`).
- Commit locally before running `wire run` so AI2II sees a clean git worktree; never push.

## Verification

Verify: PYTHONPATH=. .venv/bin/python -m wire validate-checkers interop.yaml && rm -rf validation/bundle-chain && PYTHONPATH=. .venv/bin/python -m wire run interop.yaml --cell chain --out validation/bundle-chain && PYTHONPATH=. .venv/bin/python -m wire verify-bundle validation/bundle-chain/chain
