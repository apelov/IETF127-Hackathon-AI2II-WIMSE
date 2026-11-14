"""Minimal WIMSE peer toolkit for the interop harness: WIT issuing, WPT, RFC 9421 HTTP signatures.

Written for testing: every function takes the knobs needed to build a *bad* request on purpose.
Test keys only. Drafts: CREDS-03 (WIT), WPT-02, HTTPSIG-08, RFC 9421, RFC 9530.
"""
import base64, hashlib, http.client, json, os, time, urllib.parse
from dataclasses import dataclass, field
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

TAG = "wimse-workload-to-workload"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_from_public(pub, kid=None, alg=None) -> dict:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        n = pub.public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
        jwk["alg"] = alg or "ES256"
    else:
        from cryptography.hazmat.primitives import serialization
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw), "alg": alg or "Ed25519"}
    if kid:
        jwk["kid"] = kid
    return jwk


def raw_sign(key, data: bytes) -> bytes:
    """ES256 as r||s (JWS / RFC 9421), Ed25519 raw."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return key.sign(data)


def new_workload_key(kind="ES256"):
    return ec.generate_private_key(ec.SECP256R1()) if kind == "ES256" else ed25519.Ed25519PrivateKey.generate()


def jwt(header: dict, claims: dict, key) -> str:
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    c = b64u(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{c}.{b64u(raw_sign(key, f'{h}.{c}'.encode()))}"


def issue_wit(issuer_key, *, kid, iss, sub, workload_pub_jwk, ttl=3600, now=None, header_extra=None, claims_extra=None, drop=()):
    now = int(now if now is not None else time.time())
    header = {"alg": "ES256", "kid": kid, "typ": "wit+jwt"} | (header_extra or {})
    claims = {"iss": iss, "sub": sub, "iat": now, "exp": now + ttl, "jti": b64u(os.urandom(16)), "cnf": {"jwk": workload_pub_jwk}}
    claims |= claims_extra or {}
    for d in drop:
        claims.pop(d, None)
    return jwt(header, claims, issuer_key)


def issue_wpt(wkey, *, wit, alg, aud, lifetime=60, now=None, txn_token=None, claims_extra=None, drop=()):
    now = int(now if now is not None else time.time())
    claims = {"aud": aud, "exp": now + lifetime, "jti": b64u(os.urandom(16)), "wth": b64u(hashlib.sha256(wit.encode()).digest())}
    if txn_token:
        claims["tth"] = b64u(hashlib.sha256(txn_token.encode()).digest())
    claims |= claims_extra or {}
    for d in drop:
        claims.pop(d, None)
    return jwt({"alg": alg, "typ": "wpt+jwt"}, claims, wkey)


@dataclass
class Req:
    """A fully built request: replayable byte for byte."""
    method: str
    url: str
    headers: dict
    body: bytes = b""
    extra_headers: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Resp:
    status: int
    headers: dict
    body: bytes

    @property
    def problem_type(self):
        try:
            return json.loads(self.body).get("type", "")
        except Exception:
            return ""


def _sig_params(components, created, expires, nonce, tag, aud, sign_response, extra_params, keyid_param):
    inner = " ".join(f'"{c}"' for c in components)
    p = f"({inner});created={created};expires={expires}"
    if nonce is not None:
        p += f';nonce="{nonce}"'
    if tag is not None:
        p += f';tag="{tag}"'
    if aud is not None:
        p += f';wimse-aud="{aud}"'
    if sign_response:
        p += ";wimse-sign-response"
    if keyid_param:
        p += f';keyid="{keyid_param}"'
    for k, v in extra_params:
        p += f";{k}={v}"
    return p


def _base(components, values, params):
    lines = [f'"{c}": {values[c]}' for c in components]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode()


def http_sig(method, url, body: bytes, wit, wkey, *, aud, headers=None, content_type="application/json",
             lifetime=60, now=None, nonce="auto", tag=TAG, sign_response=False, keyid_param=None,
             extra_params=(), extra_signature=False, drop_components=(), tamper_digest=False):
    """Build a signed Req per HTTPSIG-08 / RFC 9421. Covered components in spec order."""
    u = urllib.parse.urlsplit(url)
    headers = dict(headers or {})
    headers["Workload-Identity-Token"] = wit
    if body:
        headers["Content-Type"] = content_type
        digest = f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"
        headers["Content-Digest"] = digest
    lower = {k.lower(): v for k, v in headers.items()}
    comps = ["@method", "@path", "@query"]
    if body:
        comps += ["content-type", "content-digest"]
    for opt in ("authorization", "txn-token"):
        if opt in lower:
            comps.append(opt)
    comps.append("workload-identity-token")
    comps = [c for c in comps if c not in drop_components]
    values = {"@method": method, "@path": u.path, "@query": "?" + u.query, **lower}
    now = int(now if now is not None else time.time())
    nonce = b64u(os.urandom(16)) if nonce == "auto" else nonce
    params = _sig_params(comps, now, now + lifetime, nonce, tag, aud, sign_response, extra_params, keyid_param)
    sig = raw_sign(wkey, _base(comps, values, params))
    members_in, members_sig = [f"wimse={params}"], [f"wimse=:{base64.b64encode(sig).decode()}:"]
    if extra_signature:
        params2 = _sig_params(comps, now, now + lifetime, b64u(os.urandom(16)), tag, aud, False, (), None)
        sig2 = raw_sign(wkey, _base(comps, values, params2))
        members_in.append(f"second={params2}")
        members_sig.append(f"second=:{base64.b64encode(sig2).decode()}:")
    headers["Signature-Input"] = ", ".join(members_in)
    headers["Signature"] = ", ".join(members_sig)
    if tamper_digest:  # body changed after signing
        body = body + b" "
    return Req(method, url, headers, body)


def wpt_request(method, url, body: bytes, wit, wkey, *, aud, alg, headers=None, content_type="application/json", **wpt_kw):
    headers = dict(headers or {})
    headers["Workload-Identity-Token"] = wit
    headers["Authorization"] = "WPT " + issue_wpt(wkey, wit=wit, alg=alg, aud=aud, **wpt_kw)
    if body:
        headers["Content-Type"] = content_type
    return Req(method, url, headers, body)


def send(req: Req, case=None, timeout=15) -> Resp:
    u = urllib.parse.urlsplit(req.url)
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    headers = dict(req.headers)
    if case:
        headers["X-Test-Case"] = case  # not signed; lets the checker pair requests with cases
    path = u.path + ("?" + u.query if u.query else "")
    if req.extra_headers:
        c.putrequest(req.method, path)
        if req.body:
            headers.setdefault("Content-Length", str(len(req.body)))
        for name, value in [*headers.items(), *req.extra_headers]:
            c.putheader(name, value)
        c.endheaders(req.body or None)
    else:
        c.request(req.method, path, body=req.body or None, headers=headers)
    r = c.getresponse()
    out = Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, r.read())
    c.close()
    return out
