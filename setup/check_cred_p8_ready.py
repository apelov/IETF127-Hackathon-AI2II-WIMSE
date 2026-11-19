"""Return success when the cred-p8 stack has written its state file and listens on :5065, :5066, :5067."""
import os
import pathlib
import socket
import tempfile

state = pathlib.Path(os.environ.get("CRED_P8_STATE") or pathlib.Path(tempfile.gettempdir()) / "ietf127-cred-p8-state")
if not (state / "state.json").is_file():
    raise SystemExit(1)
try:
    for port in (5065, 5066, 5067):
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
except OSError:
    raise SystemExit(1)
