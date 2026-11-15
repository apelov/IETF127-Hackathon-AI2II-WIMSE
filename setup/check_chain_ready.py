"""Return success when Maurice (:5050) and all Domain A/B/Executor ports (:5051, :5060..5064) are ready."""
import socket
import urllib.error
import urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:5050/.well-known/wimse/jwks.json", timeout=2) as response:
        if response.status != 200:
            raise SystemExit(1)
    for port in (5051, 5060, 5061, 5062, 5063, 5064):
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
except (OSError, urllib.error.URLError):
    raise SystemExit(1)
