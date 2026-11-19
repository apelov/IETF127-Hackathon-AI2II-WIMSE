"""Environment check for the cred-p8 cell: a built Cred checkout at the pinned commit, and node.

The checkout lives in external/cred (git-ignored). Prepare it with the commands in
workpackages/WP10-cred-p8-on-the-wire.md.
"""
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = json.loads((ROOT / "cred_p8_cases.json").read_text())["cred"]
cred = ROOT / spec["checkout"]

problems = []
if shutil.which("node") is None:
    problems.append("node is not on PATH")
if not (cred / "scripts/hackathon/lib/cred.mjs").is_file():
    problems.append(f"no Cred checkout at {spec['checkout']} ({spec['repository']}, branch {spec['branch']})")
else:
    head = subprocess.run(["git", "-C", str(cred), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != spec["commit"]:
        problems.append(f"{spec['checkout']} is at {head or 'no commit'}, expected {spec['commit']}")
    dirty = subprocess.run(["git", "-C", str(cred), "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    if dirty:
        problems.append(f"{spec['checkout']} has uncommitted changes")
    for dist in ("packages/server/dist/index.js", "packages/sdk/dist/esm/index.js"):
        if not (cred / dist).is_file():
            problems.append(f"Cred is not built ({dist} missing): run npm ci && npm run build in {spec['checkout']}")
for p in problems:
    print(f"cred-p8 env: {p}", file=sys.stderr)
if not problems:
    print(f"cred-p8 env: ok, Cred {spec['commit'][:12]} built in {spec['checkout']}")
sys.exit(1 if problems else 0)
