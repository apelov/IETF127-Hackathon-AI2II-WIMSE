"""Live negative control for the combined P2 run: Redthread's executor takes a fresh-proof decision from MintID's sandbox
verifier (https://verifier.testnet.mintid.net, contract v1) immediately before the effect. With no MintID agent
credential the agent side cannot produce a valid proof, so the verifier must refuse and the operation must not run.
Two cases: a proof the verifier cannot accept (a made-up envelope) and no answer at all. Our own verifier and the
delegation chain run on the simulated clock (tests/atpp_world.py); the call to the sandbox verifier is real and its time
is recorded in `utc`. The positive case needs MintID's published agent client and sandbox credentials, run by whoever
holds them with `answer` replaced.

    python3 docs/hackathon/ietf127/run_mintid_sandbox.py [verifier-origin]
"""
import datetime
import json
import pathlib
import re
import sys
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT / "app"), str(ROOT / "tests")]

import mintid_outside  # noqa: E402
import protected_op  # noqa: E402
import rp_policy as rp  # noqa: E402
from atpp_world import GOOD_TRANSPORT  # noqa: E402
from test_atpp_delegation import _signed, two_hop  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://verifier.testnet.mintid.net"
POLICY = [{"claim": "unexpired", "value": True}]
lines = []


def stamp(inner):
    def decide(req, txn):
        d = inner(req, txn)
        d["utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return d
    return decide


def made_up(ch):                                  # an envelope no verifier can accept
    return {"proof_hex": "00", "issuer_id": "00" * 32, "status_root": "00" * 32, "claimed_predicates": ["unexpired"]}


def run(case, answer, txn):
    n, a, b, root, child = two_hop()
    ran = []
    op = protected_op.ProtectedOperation(n.verifier(), lambda req: ran.append(1) or "done", lines.append, case=case,
                                         outside=stamp(mintid_outside.outside(BASE, answer, POLICY)))
    r = op.run(_signed(n, b, [root, child], [a]), rp.HIGH, GOOD_TRANSPORT, txn, tool="list_orders")
    return {"effect": r["effect"], "operation_ran": bool(ran), "outside": r.get("outside")}


results = {"made-up-proof": run("outside-made-up-proof", made_up, "mi-1"),
           "no-agent-answer": run("outside-no-agent-answer", lambda ch: None, "mi-2")}
build = json.loads(urllib.request.urlopen(BASE + "/v1/build-info", timeout=10).read())
out = HERE / "runs"
out.mkdir(exist_ok=True)
(out / "redthread-P2-mintid-sandbox-negative.jsonl").write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in lines))
version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
(out / "redthread-P2-mintid-sandbox-negative.manifest.json").write_text(json.dumps({
    "format": "ietf127-wimse-scenario/1", "scenario": "P2", "impl": "redthread", "version": version,
    "verifier": BASE, "verifier_release": build.get("release"), "verifier_spec": build.get("spec_revision"),
    "clock": "own verifier simulated; sandbox call real (see utc)", "results": results, "lines": len(lines),
    "positive_case": "not run: needs the MintID agent client and sandbox credentials"}, indent=2) + "\n")
print(json.dumps(results))
