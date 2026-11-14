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

Maurice PID 83273 started at 12:15, before `standalone.yaml` was patched at 12:38.
The A2/A4/A5 baseline returned `untrusted-trust-domain` rather than the expected
outcomes. Restart that instance to load the test trust configuration, then rerun
the full driver and capture checker. No full-suite verdict has been recorded yet.
