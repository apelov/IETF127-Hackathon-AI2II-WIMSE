# External review, 2026-11-14

Reviewer: `claude-or` with OpenRouter model
`nvidia/nemotron-3-ultra-550b-a55b:free`. It read `README.md`, `cases.json`,
`peers/driver.py`, `peers/wimse.py`, `setup/patch_config.py`, and
`checkers/wire.py`. The review was advisory; findings were checked against
the captured HTTP exchange and the cited protocol documents before edits.

## Accepted and fixed

- IN13 used an EC workload key while claiming `EdDSA` in the WPT header. It
  now uses an Ed25519 key and deliberately varies only the WIT `cnf.jwk.alg`
  (`Ed25519`) versus WPT JOSE `alg` (`EdDSA`). The generated JWTs were
  inspected locally. [WPT-02](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-wimse-wpt-02.html)
  requires a string-equal match.
- The attacker URL sink now sends an explicit HTTP 404 so a mistaken fetch
  terminates promptly and remains detectable by its hit counter.

## Rejected after verification

- The review called `"@query": "?"` for a request without a query a critical
  signature bug. [RFC 9421 section 2.2.7](https://datatracker.ietf.org/doc/html/rfc9421#section-2.2.7)
  explicitly specifies `?` in that case. The generator is correct.
- The checker reads `http.www_authenticate`, a dedicated TShark field. The
  review overlooked that field. `tshark -G fields` confirms it exists; a 401
  capture is still needed to exercise that branch end to end.
- C3 sends its second request only after checking the first. The journal
  offset is taken immediately before each request, so the first decision
  cannot be mistaken for the second.
- `Content-Digest` is required by the HTTP signature profile when a body is
  present. [WPT-02](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-wimse-wpt-02.html)
  defines a different proof and does not require that header.

Other suggestions (the SSRF issuer URL shape, optional `iat`, and the specific
Maurice response for signed-response requests) were not supported as
correctness defects by the cited drafts or by the test's stated purpose.

This review does not replace an independently authored capture checker for an
AI2II PASS bundle.
