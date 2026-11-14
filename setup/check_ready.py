"""Return success when Maurice's WIMSE JWKS endpoint is ready."""
import urllib.error
import urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:5050/.well-known/wimse/jwks.json", timeout=2) as response:
        if response.status != 200:
            raise SystemExit(1)
except (OSError, urllib.error.URLError):
    raise SystemExit(1)
