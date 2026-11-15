# WIMSE inbound interop harness

This harness sends 34 WIMSE inbound cases to a local Maurice instance. `cases.json` is
the expected outcome for both the client driver and the packet checker. The keys in
`keys/` are throwaway test keys and are ignored by Git.

## Setup

Requirements: Python 3 with `cryptography`, `tshark`, and a Maurice instance with
the target agent and workflow in `setup/target.json`.

```sh
python3 setup/gen_keys.py
python3 setup/patch_config.py
# Restart Maurice after patching its config.
```

`patch_config.py` backs up the existing `~/.maurice/one/config/standalone.yaml`
before replacing its trailing `wimse:` block. Inspect the generated configuration
before restarting. The server must load the patched trust entries and grants; otherwise
even valid cases fail with `untrusted-trust-domain`.

## Run

Start a capture before the driver and stop it after the driver exits:

```sh
tcpdump -i lo0 -s 0 -U -w /tmp/wimse.pcap 'tcp port 5050 or tcp port 47999'
python3 peers/driver.py
python3 checkers/wire.py /tmp/wimse.pcap
```

The driver checks HTTP status, problem type, authentication challenge, the matching
Maurice decision journal entry, and that the attacker URL in C12/C12b was not fetched.
It exits nonzero if any case differs. For a subset, pass comma-separated IDs to
`--cases` on both commands. The packet checker checks that each declared case has
the expected number of HTTP request/response pairs, route, status, problem type,
and challenge. It does not read the driver or Maurice journal. Since the case tag
is an unsigned test header, the checker is suitable only for this controlled
single-client capture.

The checker here was written by the same model family as the harness. It is a
development aid, **not** the independent checker required for an AI2II PASS bundle.
An independent checker needs an author from a different model family, a capture
from a passing run, and negative captures that it demonstrably rejects.

## Current local state (2026-11-14)

AI2II cell `inbound` **PASS** at commit `801b463` (clean tree): the driver passed 34/34
cases against `bin/maurice` (sha256 `36f92fe8...`), the independent checker
`checkers/observes_wimse.py` (Nemotron Ultra) reported 0 errors on the run's capture, and
it rejects all three negatives. Evidence: `validation/bundle-inbound/inbound/`.

```sh
PYTHONPATH=../AI2II .venv/bin/python -m wire run interop.yaml --cell inbound --out validation/bundle-inbound
```

Port 5050 must be free (stop any running Maurice) and the tree must be committed.
Maurice journals mixed-credential rejections (A6a/A6b) without a WIT fingerprint, so the
driver matches those entries by reason within the request's journal window.
