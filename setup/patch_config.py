"""Rewrite the trailing `wimse:` block of Maurice's standalone.yaml for the hackathon (backup first).

Usage: python3 setup/patch_config.py [--config PATH]   then restart `maurice serve`.
"""
import argparse, json, pathlib, re, shutil, time

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
t = json.loads((HERE / "target.json").read_text())
ap = argparse.ArgumentParser()
ap.add_argument("--config", default=str(pathlib.Path.home() / ".maurice/one/config/standalone.yaml"))
ap.add_argument("--trust-domain", help="existing instance trust domain; never change an established one")
ap.add_argument("--issuer-iss", help="existing instance issuer URL")
args = ap.parse_args()
cfg = pathlib.Path(args.config)
text = cfg.read_text()
head, sep, old = text.partition("\nwimse:\n")
assert sep, "no wimse: block found"
domain_match = re.search(r"^  trust_domain:\s*(\S+)\s*$", old, re.M)
issuer_match = re.search(r"^  issuer:\s*\n    iss:\s*(\S+)\s*$", old, re.M)
domain = args.trust_domain or (domain_match.group(1) if domain_match else None)
issuer = args.issuer_iss or (issuer_match.group(1) if issuer_match else None)
assert domain and issuer, "existing trust_domain and issuer.iss required"
shutil.copy(cfg, f"{cfg}.bak-{time.strftime('%Y%m%dT%H%M%S')}")
H = "workload:wimse://peer.ietf127.example"
grants = "".join(
    f'      - {{holder: "{H}{p}", agent: {t["agent"]}, workflow: {t["workflow"]}}}\n'
    for p in ("/client", "/a~b", "/a/b")
)
block = f"""
wimse:
  enabled: true
  trust_domain: {domain}
  issuer:
    iss: {issuer}
  inbound:
    audiences:
      - http://maurice.ietf127.example:5050
      - http://127.0.0.1:5050
    grants:
{grants}  trust:
    - trust_domain: peer.ietf127.example
      issuers: [http://peer.ietf127.example]
      jwks_file: {ROOT}/keys/peer.jwks.json
    - trust_domain: lax.ietf127.example
      jwks_file: {ROOT}/keys/peer.jwks.json
"""
cfg.write_text(head + "\n" + block.lstrip("\n"))
print("patched", cfg)
