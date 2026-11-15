"""Create throwaway test issuers: `peer` (trusted by Maurice) and `rogue` (not in trust:).

Writes keys/<name>.pem (private) and keys/<name>.jwks.json (public). Test keys only.
"""
import json, pathlib, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "peers"))
from wimse import jwk_from_public

KEYS = pathlib.Path(__file__).parent.parent / "keys"
KEYS.mkdir(exist_ok=True)
for name in ("peer", "rogue", "tts_a", "as_a", "as_b", "tts_b", "rich"):
    pem = KEYS / f"{name}.pem"
    if pem.exists():
        continue
    k = ec.generate_private_key(ec.SECP256R1())
    pem.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    jwk = jwk_from_public(k.public_key(), kid=f"{name}-1")
    (KEYS / f"{name}.jwks.json").write_text(json.dumps({"keys": [jwk]}, indent=2))
    print("created", name)
