# Run the inbound cases against your own implementation

`peers/driver.py` sends 34 requests (35 steps) to a WIMSE-verifying HTTP server and compares each
answer with `cases.json`. By default it targets AgentMaurice. This page says how to point it at
your own server instead.

What the driver tests: a server that accepts a POST carrying a Workload Identity Token (WIT) and
either a WIMSE HTTP message signature (draft-ietf-wimse-http-signature-08) or a Workload Proof
Token (draft-ietf-wimse-wpt-02), and rejects the broken variants. It tests inbound verification
only.

## 1. Configure your server

The driver signs with throwaway test keys. Generate them once:

```
python setup/gen_keys.py          # writes keys/ (ignored by git)
```

Then make your server accept, and only accept, this setup:

| Setting | Value |
|---|---|
| Trust domain | `peer.ietf127.example` |
| Trust anchor (JWKS) | `keys/peer.jwks.json`: one ES256 key, `kid` `peer-1`. This is the issuer of every WIT the driver sends. Load the file you generated on the machine that runs the driver; keys differ per machine |
| Issuer allowlist for that trust domain | `http://peer.ietf127.example` (the `iss` of the WITs). Needed for IN6, C12 |
| Second trust domain (only for C12b) | `lax.ietf127.example`, same JWKS, no issuer allowlist |
| Audience | the string you put in `audience` (section 2); the default is the `base` URL. The signature parameter `wimse-aud` must equal it exactly (C4, C4b) |
| Grants (who may call the endpoint) | `wimse://peer.ietf127.example/client`, `wimse://peer.ietf127.example/a~b`, `wimse://peer.ietf127.example/a/b`. Nothing else, so `.../ungranted` is refused (IN15) |
| Route | any path that accepts `POST` with a JSON body; set it in `route` |

`setup/patch_config.py` writes the same settings into Maurice's configuration, if you want a
reference.

Behaviour the cases expect:

- a valid request returns 200;
- `wimse-sign-response` in the signature returns 501 with problem type `wimse-signed-response-unsupported` unless you implement response signing;
- every failed signed request returns 400 with problem type `https://iana.org/assignments/http-problem-types#wimse-signature-invalid` and the same body whatever the reason (draft-ietf-wimse-http-signature-08 section 3.6);
- an authenticated but ungranted workload returns 403.

Hostname: the driver connects to `base`. `audience` is only a string in the signature, so you do not
need `maurice.ietf127.example` in `/etc/hosts`. Run against `http://127.0.0.1:8080` and set
`audience` to whatever your server has configured.

Case C12 and C12b put an attacker URL in the WIT `iss` and require that your server does not fetch
it. The driver listens on `127.0.0.1:47999` for that. Your server must run on the same host (or
otherwise reach the driver's `127.0.0.1:47999`) for the check to mean anything.

## 2. Write `target.json`

Copy `setup/target.json` and edit it. Pass it with `--target`. Fields:

| Field | Required | Default | Meaning |
|---|---|---|---|
| `base` | yes | none | `http://host[:port]`. Plain http only; no path, no trailing slash. The driver connects here |
| `route` | no | `/api/v2/agents/{agent}/workflows/{workflow}/executions` (Maurice) | Path template starting with `/`. May use `{agent}`, `{workflow}` (or any other field of this file) |
| `audience` | no | the value of `base` | String the requests are bound to (`wimse-aud`, WPT `aud`) |
| `agent`, `workflow` | only if `route` uses them | none | Values for the route template |
| `journal` | no | `true` | Read Maurice's decision journal. Set `false` for any server that is not Maurice (same as `--wire-only`) |
| keys starting with `_` | no | | Comments, ignored |

Unknown fields, a missing `base`, `https://`, a path in `base`, a route without a leading `/` or a
route that uses a field you did not set all stop the run with a message that names the problem.

Example for a server on port 8080:

```json
{
  "base": "http://127.0.0.1:8080",
  "route": "/v1/run",
  "audience": "http://127.0.0.1:8080",
  "journal": false
}
```

## 3. Run it

```
python peers/driver.py --target mine.json                 # all 34 cases
python peers/driver.py --target mine.json --only draft    # only cases the drafts decide
python peers/driver.py --target mine.json --cases A2,A13a,IN10
python peers/driver.py --base http://127.0.0.1:8080 --route /v1/run --wire-only
```

Command-line `--base`, `--route`, `--audience`, `--wire-only` override the file. With no arguments
the driver behaves as before: Maurice, journal on. `--journal-out` needs the journal and cannot be
combined with `--wire-only`.

Do not use the default target unless AgentMaurice is the thing under test: it reads
`~/.maurice/one/logs/wimse-decisions.jsonl` and sends to Maurice's port.

## 4. Read the output

```
CASE A2 [IN-1] PASS :: WIT + HTTP-sig, granted workload :: step=1 status=200 want=[200] type=- reason-skipped ok
CLASS A2 draft
CASE A5 [IN-3] PASS :: WIT without proof :: step=1 status=401 ... reason-skipped matched=primary(401, wpt-02) ok
CLASS A5 draft (wpt-02 SHOULD 401; conflicts with http-signature-08, ...)
CASE IN6 [IN-6] FAIL :: WIT iss not in allowlist :: step=1 status=200 want=[400] ... MISMATCH
CLASS IN6 needs your policy (see guide): issuer allowlist: ...
SUMMARY total=34 failed=2 ['IN6', 'IN13']
BREAKDOWN failed_draft=['IN13'] failed_needs_policy=['IN6']
SKIPPED decision-journal reason comparison on 32 step(s): ...
```

- `step=... status=... want=[...]` is the HTTP status; `type=` is the RFC 9457 problem type.
- `reason-skipped` marks a step where `cases.json` names an internal reject reason that only
  Maurice's journal can show. In wire-only mode that comparison is not made. Passing means the
  status and problem type match; it does not show that your server rejected for the intended reason.
- `CLASS` says whether the outcome comes from the drafts (`draft`) or from your policy
  (`needs your policy`). The classification table is `cases_applicability.json`; `cases.json` is not
  changed.
- Cases that need your policy: IN6, C12, C12b (issuer allowlist), A13i, A13j, IN15 (grants; A13i and
  A13j also need the grants for `a~b` and `a/b`). Expect failures on these until you implement that
  policy; they are not a verdict on draft conformance.
- A5 and IN13 expect 401 with `WWW-Authenticate: WPT`, which follows draft-ietf-wimse-wpt-02
  section 2.1 (SHOULD). draft-ietf-wimse-http-signature-08 section 3.6 says 400
  `wimse-signature-invalid` and calls 401 NOT RECOMMENDED. The two drafts disagree. In `--wire-only`
  mode only, a 400 with that problem type is also accepted for these two cases, and the line says
  `matched=primary(401, wpt-02)` or `matched=alternative(400 wimse-signature-invalid, http-signature-08)`.
  In journal mode (Maurice) only 401 is accepted.
- The exit code is 0 only if every selected case passed.

## 5. Capture a PCAP and check it

The checker `checkers/observes_wimse.py` reads a capture with `tshark` and re-checks status, problem
type and `WWW-Authenticate` per case from the wire, plus that nothing connected to port 47999.

Minimum steps (loopback, tcpdump started before the driver and stopped after it):

```
tcpdump -i lo0 -n -U --immediate-mode -w mine.pcap 'tcp port 8080 or tcp port 47999'   # Linux: -i lo, usually with sudo
python peers/driver.py --target mine.json --only draft
# stop tcpdump (Ctrl-C), then
tshark -r mine.pcap -d tcp.port==8080,http -Y http.request     # sanity check: one line per request
```

Limit of the checker as committed: it decodes only TCP port **5050** and accepts only the route
`/api/v2/agents/{agent}/workflows/{workflow}/executions`. A server on another port or route is not
decodable by it without a change to the checker. Today you can either run your server on port 5050
with that route (not on the machine where AgentMaurice runs), or send the capture and the driver
output as evidence without the checker verdict. The checker also rejects requests for cases that
you did not name with `--cases`, so pass it the same list you ran.

## 6. Submit results

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). In short: open a pull request against `main`; say how
you and your implementation should be named, with version and commit; say what limits the run (for
example `--wire-only`, or policy cases not implemented). Results are labelled by class there;
results from your own run are `partner-attested`. There is no committed place yet for inbound-driver
results from other implementations: put the driver output (and capture, if you made one) in the pull
request or an issue and a maintainer will decide where it goes.

## Limits

- The two-domain chain (`B_CHAIN`, `peers/chain_driver.py`) is not re-targetable yet. Only the
  inbound driver is.
- The P1 to P8 scenarios are not run by this driver. They are contributed as partner records under
  `scenarios/p1_p8/` (see `CONTRIBUTING.md`).
- Wire-only mode does not check the reason a request was rejected.
- Only plain `http://` targets are supported.

## What was and was not tested

Tested here against `tests/stub_server.py` (a small stdlib server that reuses `peers/wimse.py`),
never against Maurice or any other real implementation: the config loader and its error messages,
the default target values, `--wire-only`, `--only draft`, the 401/400 alternative for A5, and a
tcpdump capture on loopback that `tshark` decodes. The checker was run on that capture only after a
scratch copy had its port changed from 5050 to the stub's port. Not tested: this guide's server
settings table against any implementation other than the stub, the route and audience settings against
Maurice, the capture commands on Linux, and the `--journal-out` path.

Run the tests: `python -m unittest discover -s tests -v`.
