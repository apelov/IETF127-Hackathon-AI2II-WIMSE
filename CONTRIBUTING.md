# Contributing

Pull requests are welcome: results from your own implementation, corrections to how your work is
described, new scenarios, and fixes to the harness or checkers. Fork the repository, push a branch,
and open a pull request against `main`.

Every pull request runs `./reproduce.sh` on GitHub (`.github/workflows/reproduce.yml`). It checks
the evidence bundles, runs the packet checkers on the committed captures with their negative
mutants, and verifies the digests of every partner manifest. It does not re-run any
implementation.

## Contributing a result from your implementation

Add two files to `scenarios/p1_p8/`, named after your implementation and the scenario:

- `<impl>-<scenario>.jsonl`: one JSON object per decision, in the `ietf127-wimse-scenario/1`
  format (`scenario`, `case`, `impl`, `decision`, `reason`, `effect`, and `clock`).
- `<impl>-<scenario>.manifest.json`: how the run was made, with at least:

```json
{
  "scenario": "P8",
  "format": "ietf127-wimse-scenario/1",
  "impl": "cred",
  "repository": "https://... (or \"none\" if not public yet)",
  "commit": "full commit hash of the code that ran",
  "run_at_utc": "2026-11-15T18:40:42Z",
  "clock": "wall | simulated",
  "reproduce": "the exact commands that produced the JSONL",
  "files": {
    "<impl>-<scenario>.jsonl": {"sha256": "<sha256 of the file>", "lines": 11}
  }
}
```

`./reproduce.sh` verifies the digest and line count of every manifest in this format, so a later
edit to your JSONL fails the check. `scenarios/p1_p8/cred-P8.manifest.json` is a complete example.

Say in the manifest anything that limits what the run shows, for example a mock provider, a
simulated clock, or cases that were not run. Results contributed this way are listed as
**partner-attested** in `TEST_RESULTS_SUMMARY.md`: they are your run, recorded and hashed here, not
re-executed by this repository.

## How results are labelled

Every result in `TEST_RESULTS_SUMMARY.md` carries one of these classes, and results of different
classes are never added together:

| Class | Meaning |
|---|---|
| observed-on-wire | in a committed capture and checked by an independent checker |
| simulated | run here against a simulated verifier or a fake clock |
| replayed-recording | recorded earlier and replayed into a capture |
| mocked | answered by fixed responses in this repository; says nothing about your implementation |
| partner-attested | your own run, recorded and hashed here |
| not-run | planned, not executed |

If a row describes your implementation with the wrong class, a pull request or an issue that
corrects it is the fastest fix.

## Credit and naming

- Tell us how you and your implementation should be named: person, affiliation, project, version
  and commit. We use exactly that, and nothing else.
- We do not link a repository for you unless you ask us to.
- Before results are presented (slides, mailing list, IETF session), every named party is asked to
  confirm their rows.

## Licence

- Code and documents written for this repository are available under Apache-2.0 or MIT, at your
  option (`LICENSE-APACHE`, `LICENSE-MIT`). A contribution to them is made under the same terms.
- Traces, manifests and other material that you provide from your own implementation stay under
  your terms. Add an entry for them to the "Third-party contributions" section of `NOTICE`, naming
  the files and their owner. If you offered the material to the working group as an IETF
  Contribution (BCP 78, BCP 79), say so there.

## Do not commit

- Private keys or credentials (`keys/` is generated locally by `setup/gen_keys.py` and ignored).
- Local paths, user names or host names in new files.
- Material you do not have the right to share.
