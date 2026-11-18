"""Chain cases whose behaviour in chain_cases.json is ahead of the committed capture.

The peers were brought in line with the drafts (authenticated Txn-Token requests, form-encoded OAuth messages, no
request-controlled fault injection, authenticated /admin/revoke, authentication failures that do not name the failed
check, RFC 6749 s5.2 token-endpoint errors). The committed capture
(validation/bundle-chain/chain/capture.pcap) was recorded before that and may not be edited. Until it is re-recorded
with the live stack, the cases below are tolerated as follows, by checkers/observes_chain.py and setup/build_site.py:

  * not in the capture            -> skipped, reported as PENDING;
  * in the capture with the hops that chain_cases.json lists as "legacy_expected_hops" -> held to the LEGACY expectations
    ("legacy_expected_hops", "legacy_expected_statuses", "legacy_expected_reason": the same hop, status and reason checks,
    with the old values), not exempted from them, and reported as PENDING;
  * in the capture with the NEW expected_hops, or any other hops that are not the legacy ones -> FAIL.

The last rule is the point: a re-recorded capture must make the checkers fail until the case is removed from this
list, so the list cannot go stale. After re-recording, empty it (and drop "legacy_expected_hops" from chain_cases.json).
Nothing else is tolerated. A pending case is never validated against the new behaviour, so observes_chain.py ends with a
loud "N cases NOT validated against the new behaviour (pending re-record)" line (stdout and stderr) and a
pending_not_validated=N figure in its SUMMARY: a run with pending cases is not a clean pass of the new behaviour.
"""

PENDING_RERECORD: list[str] = []  # emptied after the chain was re-recorded with the corrected peers and the real Maurice (18 Nov 2026)


def check_list(cases: dict) -> None:
    unknown = [c for c in PENDING_RERECORD if c not in cases]
    if unknown:
        raise SystemExit(f"PENDING_RERECORD names cases that are not in chain_cases.json: {unknown}")


def classify(cid: str, observed_hops: list | None, spec: dict) -> str:
    """'ok' (not pending, caller compares), 'pending' (tolerated), or an error message (fail loudly)."""
    if cid not in PENDING_RERECORD:
        return "ok"
    if not observed_hops:
        return "pending"
    if observed_hops == spec["expected_hops"]:
        return (f"{cid} is in PENDING_RERECORD but the capture already shows the new behaviour {observed_hops}: "
                "remove it from checkers/pending_rerecord.py PENDING_RERECORD")
    if observed_hops == spec.get("legacy_expected_hops"):
        return "pending"
    return f"{cid}: hops {observed_hops} are neither expected_hops {spec['expected_hops']} nor the legacy {spec.get('legacy_expected_hops')}"
