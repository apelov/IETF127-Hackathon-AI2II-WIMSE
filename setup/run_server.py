"""Start the captured Maurice binary with this machine's prepared test config."""
import os
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent
binary = root / "bin/maurice"
config = pathlib.Path.home() / ".maurice/one/config/standalone.yaml"
os.execv(binary, [str(binary), "serve", "--runtime-config", str(config)])
