"""Check fixed local prerequisites before AI2II starts capture or peers."""
import json
import pathlib
import shutil
import socket
import sys

import yaml

root = pathlib.Path(__file__).resolve().parent.parent
target = json.loads((root / "setup/target.json").read_text())
config_path = pathlib.Path.home() / ".maurice/one/config/standalone.yaml"
try:
    config = yaml.safe_load(config_path.read_text())
    wimse = config["wimse"]
    assert wimse["enabled"] is True
    assert target["base"] in wimse["inbound"]["audiences"]
    assert any(t["trust_domain"] == "peer.ietf127.example" for t in wimse["trust"])
    assert any(g["holder"] == "workload:wimse://peer.ietf127.example/client"
               for g in wimse["inbound"]["grants"])
    assert (root / "keys/peer.pem").is_file()
    assert (root / "keys/peer.jwks.json").is_file()
    assert shutil.which("maurice")
    assert shutil.which("tshark")
    assert socket.gethostbyname("maurice.ietf127.example") == "127.0.0.1"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 5050))
except (OSError, KeyError, TypeError, AssertionError, yaml.YAMLError) as exc:
    print(f"WIMSE environment unavailable: {exc or type(exc).__name__}", file=sys.stderr)
    raise SystemExit(1)
print("WIMSE local prerequisites ready; port 5050 is free")
