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


# --- OAuth message formats (RFC 8693, RFC 7523, RFC 6749; txn-tokens-11 s11, identity-chaining-17 s2) ---

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TT_TXN = "urn:ietf:params:oauth:token-type:txn_token"
TT_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TT_JWT = "urn:ietf:params:oauth:token-type:jwt"
TT_UNSIGNED_JSON = "urn:ietf:params:oauth:token-type:unsigned_json"
FORM_CT = "application/x-www-form-urlencoded"


def form_encode(params: dict) -> bytes:
    """application/x-www-form-urlencoded body; None values are left out."""
    return urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}).encode("ascii")


def form_decode(raw: bytes) -> dict | None:
    """Parse a form body. None when malformed or when a parameter appears twice (RFC 6749 s3.2)."""
    try:
        pairs = urllib.parse.parse_qsl(raw.decode("utf-8"), keep_blank_values=True, strict_parsing=bool(raw))
    except ValueError:
        return None
    out: dict = {}
    for k, v in pairs:
        if k in out:
            return None
        out[k] = v
    return out


def txn_token_request(*, audience: str, scope: str, subject_token: str, subject_token_type: str,
                      request_context: dict | None = None, request_details: dict | None = None) -> bytes:
    """Body of a Txn-Token request (txn-tokens-11 s11.1, Figure 5)."""
    return form_encode({
        "grant_type": GRANT_TOKEN_EXCHANGE,
        "requested_token_type": TT_TXN,
        "audience": audience,
        "scope": scope,
        "subject_token": subject_token,
        "subject_token_type": subject_token_type,
        "request_context": json.dumps(request_context) if request_context is not None else None,
        "request_details": json.dumps(request_details) if request_details is not None else None,
    })


def chain_exchange_request(*, subject_token: str, resource: str | None = None, audience: str | None = None,
                           scope: str | None = None, subject_token_type: str = TT_TXN) -> bytes:
    """Body of the token exchange at the trust domain A AS (identity-chaining-17 s2.3.1, RFC 8693 s2.1)."""
    return form_encode({
        "grant_type": GRANT_TOKEN_EXCHANGE,
        "subject_token": subject_token,
        "subject_token_type": subject_token_type,
        "resource": resource,
        "audience": audience,
        "scope": scope,
    })


def jwt_bearer_request(assertion: str, scope: str | None = None) -> bytes:
    """Body of the access token request at the trust domain B AS (RFC 7523 s2.1, identity-chaining-17 s2.4.1)."""
    return form_encode({"grant_type": GRANT_JWT_BEARER, "assertion": assertion, "scope": scope})


WIMSE_SIGNATURE_INVALID = "https://iana.org/assignments/http-problem-types#wimse-signature-invalid"


def auth_failure_body(status: int) -> tuple[str, dict]:
    """(content type, body) of a refused authentication at a resource server.

    http-signature-08 s3.6: 400 with the problem type wimse-signature-invalid, and the response MUST NOT distinguish
    which check failed. The body depends on the status only, never on the cause (the cause goes to the journal).
    401 is what the WPT scheme (wpt-02 s2.1) and a request with no proof at all get: a bare problem, with the
    WWW-Authenticate header set by the caller.
    """
    if status == 400:
        return "application/problem+json", {"type": WIMSE_SIGNATURE_INVALID, "title": "Bad Request", "status": 400}
    return "application/problem+json", {"type": "about:blank", "title": "Unauthorized", "status": status}


class OAuthError(Exception):
    """An RFC 6749 s5.2 error: JSON body {"error": code}, status 400 unless the code says otherwise.

    `cause` is the precise reason for the journal; it is never sent.
    """

    def __init__(self, error: str, status: int = 400, cause: str | None = None):
        super().__init__(error)
        self.error = error
        self.status = status
        self.cause = cause or error


def parse_txn_token_request(raw: bytes, content_type: str, trust_domain: str) -> dict:
    """Validate a Txn-Token request (txn-tokens-11 s11.1) and return its parameters.

    request_context and request_details are parsed to dicts (or None when absent).
    """
    if content_type.split(";")[0].strip().lower() != FORM_CT:
        raise OAuthError("invalid_request")
    f = form_decode(raw)
    if f is None:
        raise OAuthError("invalid_request")
    if f.get("grant_type") != GRANT_TOKEN_EXCHANGE:
        raise OAuthError("unsupported_grant_type")
    if f.get("requested_token_type") != TT_TXN or not f.get("subject_token") or not f.get("subject_token_type"):
        raise OAuthError("invalid_request")
    if f.get("audience") != trust_domain:
        raise OAuthError("invalid_target")  # RFC 8693 s2.2.2
    for name in ("request_context", "request_details"):
        if name in f:
            try:
                val = json.loads(f[name])
            except ValueError:
                raise OAuthError("invalid_request") from None
            if not isinstance(val, dict):
                raise OAuthError("invalid_request")
            f[name] = val
        else:
            f[name] = None
    return f


def txn_token_response(token: str) -> dict:
    """Txn-Token response (txn-tokens-11 s11.4): no refresh_token."""
    return {"access_token": token, "issued_token_type": TT_TXN, "token_type": "N_A"}


# --- WP01: Txn-Token, Identity-Chaining, and Verification Primitives ---

def parse_jwt(token: str) -> tuple[dict, dict, bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
        raise ValueError("jwt-malformed")
    try:
        header = json.loads(b64u_dec(parts[0]).decode("utf-8"))
        claims = json.loads(b64u_dec(parts[1]).decode("utf-8"))
        sig = b64u_dec(parts[2])
    except Exception as exc:
        raise ValueError("jwt-malformed") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("jwt-malformed")
    return header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), sig


def _pub_from_jwk(pub_jwk: dict):
    kty = pub_jwk.get("kty")
    if kty == "EC" and pub_jwk.get("crv") == "P-256":
        x = int.from_bytes(b64u_dec(pub_jwk["x"]), "big")
        y = int.from_bytes(b64u_dec(pub_jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if kty == "OKP" and pub_jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(b64u_dec(pub_jwk["x"]))
    raise ValueError("unsupported-jwk")


def verify_raw_sig(pub_jwk: dict, data: bytes, sig: bytes) -> bool:
    try:
        pub = _pub_from_jwk(pub_jwk)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            if len(sig) != 64:
                return False
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            der = encode_dss_signature(r, s)
            pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
            return True
        pub.verify(sig, data)
        return True
    except Exception:
        return False


def verify_jwt(token: str, jwks: dict, *, expected_typ: str | None = None,
               expected_aud: str | None = None, now: int | None = None) -> dict:
    header, claims, signing_input, sig = parse_jwt(token)
    alg = header.get("alg")
    if alg not in ("ES256", "EdDSA", "Ed25519"):
        raise ValueError("alg-unsupported")
    if expected_typ is not None and header.get("typ") != expected_typ:
        raise ValueError("typ-mismatch")
    keys = jwks.get("keys", []) if "keys" in jwks else [jwks]
    kid = header.get("kid")
    candidates = [k for k in keys if not kid or k.get("kid") == kid] or keys
    if not any(verify_raw_sig(k, signing_input, sig) for k in candidates):
        raise ValueError("sig-invalid")
    now = int(now if now is not None else time.time())
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp <= now:
        raise ValueError("token-expired")
    iat = claims.get("iat")
    if iat is not None and (not isinstance(iat, (int, float)) or iat > now + 60):
        raise ValueError("iat-invalid")
    if expected_aud is not None:
        aud = claims.get("aud")
        ok = (aud == expected_aud) if isinstance(aud, str) else (isinstance(aud, list) and expected_aud in aud)
        if not ok:
            raise ValueError("aud-mismatch")
    return claims


def issue_txn_token(tts_key, *, kid: str, iss: str, aud: str, txn: str, sub: str,
                    scope: str, req_wl: str, tctx: dict | None = None, rctx: dict | None = None, ttl: int = 120,
                    now: int | None = None, typ: str = "txntoken+jwt", drop: tuple = ()) -> str:
    now = int(now if now is not None else time.time())
    header = {"alg": "ES256", "kid": kid, "typ": typ}
    claims = {
        "iss": iss,
        "aud": aud,
        "txn": txn,
        "sub": sub,
        "scope": scope,
        "req_wl": req_wl,
        "iat": now,
        "exp": now + ttl,
        "tctx": tctx if tctx is not None else {},
    }
    if rctx is not None:
        claims["rctx"] = rctx
    for d in drop:
        claims.pop(d, None)
    return jwt(header, claims, tts_key)


def issue_chain_grant(as_a_key, *, kid: str, iss: str, aud: str, sub: str, scope: str,
                      txn: str, tctx: dict | None = None, ttl: int = 60, now: int | None = None,
                      client_id: str | None = None) -> str:
    now = int(now if now is not None else time.time())
    header = {"alg": "ES256", "kid": kid, "typ": "jwt-chg+jwt"}
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "scope": scope,
        "txn": txn,
        "tctx": tctx if tctx is not None else {},
        "iat": now,
        "exp": now + ttl,
        "jti": b64u(os.urandom(16)),
    }
    if client_id is not None:
        claims["client_id"] = client_id  # the workload AS-A authenticated: RFC 8693 client, carried to AS-B
    return jwt(header, claims, as_a_key)


def issue_access_token(as_b_key, *, kid: str, iss: str, aud: str | list[str], sub: str, scope: str,
                       txn: str, tctx: dict | None = None, ttl: int = 120, now: int | None = None,
                       client_id: str | None = None) -> str:
    """RFC 9068 s2.2: iss, exp, aud, sub, client_id, iat, jti are required; txn/tctx/scope are ours."""
    now = int(now if now is not None else time.time())
    header = {"alg": "ES256", "kid": kid, "typ": "at+jwt"}
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "scope": scope,
        "txn": txn,
        "tctx": tctx if tctx is not None else {},
        "iat": now,
        "exp": now + ttl,
        "jti": b64u(os.urandom(16)),
    }
    if client_id is not None:
        claims["client_id"] = client_id
    return jwt(header, claims, as_b_key)


def _valid_wimse_id(sub: str) -> str | None:
    if not isinstance(sub, str) or not sub.startswith("wimse://"):
        return None
    u = urllib.parse.urlsplit(sub)
    if u.scheme != "wimse" or not u.hostname or u.port is not None or u.username or u.password or u.query or u.fragment:
        return None
    if not u.path or u.path == "/":
        return None
    raw_lower = u.path.lower()
    if "/./" in raw_lower or "/../" in raw_lower or raw_lower.endswith("/.") or raw_lower.endswith("/..") or "%2e" in raw_lower or "%2f" in raw_lower:
        return None
    return u.hostname.lower()


def verify_wimse_proof(method: str, path_and_query: str, headers: dict[str, str], body: bytes,
                       trust_jwks: dict[str, dict], *, expected_aud: str,
                       seen_nonces: set[str] | None = None, now: int | None = None) -> tuple[bool, int, str, dict | None]:
    now = int(now if now is not None else time.time())
    lower = {k.lower(): v for k, v in headers.items()}
    wit = lower.get("workload-identity-token")
    if not wit:
        return False, 401, "proof-missing", None
    try:
        _, unverified_claims, _, _ = parse_jwt(wit)
    except ValueError:
        return False, 400, "wit-invalid", None
    sub = unverified_claims.get("sub", "")
    td = _valid_wimse_id(sub)
    if not td:
        return False, 400, "identifier-invalid", None
    if td not in trust_jwks:
        return False, 400, "untrusted-trust-domain", None
    try:
        wit_claims = verify_jwt(wit, trust_jwks[td], expected_typ="wit+jwt", now=now)
    except ValueError as exc:
        return False, 400, str(exc), None
    cnf_jwk = (wit_claims.get("cnf") or {}).get("jwk")
    if not isinstance(cnf_jwk, dict):
        return False, 400, "cnf-missing", None

    has_sig = "signature-input" in lower and "signature" in lower
    auth_hdr = lower.get("authorization", "")
    has_wpt = auth_hdr.lower().startswith("wpt ")

    if not has_sig and not has_wpt:
        return False, 401, "proof-missing", None

    if has_sig:
        sig_in = lower["signature-input"]
        sig_val = lower["signature"]
        if "," in sig_in and sig_in.count(f'tag="{TAG}"') > 1:
            return False, 400, "multiple-wimse-signatures", None
        if ";" not in sig_in or "=" not in sig_in:
            return False, 400, "proof-invalid", None
        label, params = sig_in.split("=", 1)
        label = label.strip()
        if ";keyid=" in params or f'tag="{TAG}"' not in params or ";wimse-sign-response" in params:
            return False, 400, "proof-invalid", None
        if f';wimse-aud="{expected_aud}"' not in params:
            return False, 400, "aud-mismatch", None
        comp_part = params.split(")", 1)[0].lstrip("(")
        comps = [c.strip('"') for c in comp_part.split() if c.strip('"')]
        for req_c in ("@method", "@path", "@query", "workload-identity-token"):
            if req_c not in comps:
                return False, 400, "proof-invalid", None
        if "txn-token" in lower and "txn-token" not in comps:
            return False, 400, "proof-invalid", None
        if body:
            expected_digest = f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"
            if lower.get("content-digest") != expected_digest or "content-digest" not in comps:
                return False, 400, "digest-mismatch", None
        import re
        m_nonce = re.search(r';nonce="([^"]+)"', params)
        if m_nonce and seen_nonces is not None:
            nonce = m_nonce.group(1)
            if nonce in seen_nonces:
                return False, 400, "replay", None
            seen_nonces.add(nonce)
        u = urllib.parse.urlsplit(path_and_query)
        values = {"@method": method.upper(), "@path": u.path, "@query": "?" + u.query, **lower}
        try:
            base_bytes = _base(comps, values, params)
            m_sig = re.search(rf"{re.escape(label)}=:([A-Za-z0-9+/=]+):", sig_val)
            if not m_sig:
                return False, 400, "proof-invalid", None
            raw_s = base64.b64decode(m_sig.group(1))
        except Exception:
            return False, 400, "proof-invalid", None
        if not verify_raw_sig(cnf_jwk, base_bytes, raw_s):
            return False, 400, "proof-invalid", None
        return True, 200, "accept", {"peer_id": sub, "wit_claims": wit_claims, "mechanism": "http-sig"}

    # WPT verification
    wpt_token = auth_hdr[4:].strip()
    try:
        wpt_hdr, wpt_claims, _, _ = parse_jwt(wpt_token)
        cnf_alg = cnf_jwk.get("alg")
        wpt_alg = wpt_hdr.get("alg")
        # wpt-02 s2: the WPT alg MUST match the alg of the jwk in cnf; "Ed25519" and "EdDSA" are different strings
        if cnf_alg and wpt_alg != cnf_alg:
            return False, 401, "alg-mismatch", None
        verify_jwt(wpt_token, cnf_jwk, expected_typ="wpt+jwt", expected_aud=expected_aud, now=now)
    except ValueError:
        return False, 401, "proof-invalid", None
    expected_wth = b64u(hashlib.sha256(wit.encode()).digest())
    if wpt_claims.get("wth") != expected_wth:
        return False, 401, "proof-invalid", None
    if "txn-token" in lower:
        expected_tth = b64u(hashlib.sha256(lower["txn-token"].encode()).digest())
        if wpt_claims.get("tth") != expected_tth:
            return False, 401, "proof-invalid", None
    if seen_nonces is not None and wpt_claims.get("jti"):
        jti = wpt_claims["jti"]
        if jti in seen_nonces:
            return False, 401, "replay", None
        seen_nonces.add(jti)
    return True, 200, "accept", {"peer_id": sub, "wit_claims": wit_claims, "mechanism": "wpt"}

