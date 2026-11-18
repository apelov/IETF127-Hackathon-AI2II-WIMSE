"""Regression tests for the chain peers. They need no Maurice and never touch :5050.

Starts TTS-A/AS-A on :5051 and Domain B on :5060-:5063 in this process and runs every case of
peers/chain_driver.py without the Maurice hop. If one of those ports is already taken (for example by a running
chain stack) the tests are skipped rather than disturbing whatever listens there.

    .venv/bin/python -m unittest discover -s tests -v
"""
import json
import pathlib
import socket
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "peers"))
sys.path.insert(0, str(ROOT))

import chain_driver as cd
import domain_a
import domain_b
import wimse as w

PORTS = (5051, 5060, 5061, 5062, 5063)


def _busy(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


class ChainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        busy = [p for p in PORTS if _busy(p)]
        if busy:
            raise unittest.SkipTest(f"ports in use, not starting the peers: {busy}")
        cls.srv_a = domain_a.start_in_thread(5051)
        cls.srvs_b = domain_b.start_all_in_threads()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "srv_a", None):
            cls.srv_a.shutdown()
            cls.srv_a.server_close()
            domain_b.shutdown_all(cls.srvs_b)

    def run_case(self, cid):
        ok, notes, _ = cd.RUNNERS[cid](False)
        self.assertTrue(ok, f"{cid}: {notes}")

    def test_every_case_passes(self):
        for cid in cd.RUNNERS:
            with self.subTest(case=cid):
                self.run_case(cid)

    def test_chain_cases_cover_every_runner(self):
        self.assertEqual(set(cd.RUNNERS), set(cd.CASES))

    def test_no_test_mode_in_requests(self):
        """A test_mode member in a request changes nothing: it is not read."""
        wkey = w.new_workload_key("ES256")
        form = cd.new_txn_form("files:read") + b"&test_mode=widen_scope"
        r = cd.safe_send(cd.signed_form(cd.TTS_A_URL, form, cd.peer_wit(wkey), wkey, cd.TTS_A_PROOF_AUD), case="UT")
        self.assertEqual(r.status, 200)
        self.assertEqual(cd.claims_of(json.loads(r.body)["access_token"])["scope"], "files:read")

    def test_replacement_keeps_txn_sub_aud(self):
        wkey = w.new_workload_key("ES256")
        wit = cd.peer_wit(wkey)
        r1 = cd.safe_send(cd.signed_form(cd.TTS_A_URL, cd.new_txn_form("files:read files:list"), wit, wkey,
                                         cd.TTS_A_PROOF_AUD), case="UT")
        orig = json.loads(r1.body)["access_token"]
        r2 = cd.safe_send(cd.signed_form(cd.TTS_A_URL, cd.replace_form(orig, "files:read"), wit, wkey,
                                         cd.TTS_A_PROOF_AUD), case="UT")
        self.assertEqual(r2.status, 200)
        a, b = cd.claims_of(orig), cd.claims_of(json.loads(r2.body)["access_token"])
        for k in ("txn", "sub", "aud"):
            self.assertEqual(a[k], b[k])
        self.assertEqual(b["scope"], "files:read")

    def test_json_body_is_refused_by_the_tts(self):
        """The Txn-Token request is a form (s11.1); the old JSON body is not accepted."""
        wkey = w.new_workload_key("ES256")
        body = json.dumps({"sub": "user:alice", "scope": "files:read"}).encode()
        req = w.http_sig("POST", cd.TTS_A_URL, body, cd.peer_wit(wkey), wkey, aud=cd.TTS_A_PROOF_AUD)
        r = cd.safe_send(req, case="UT")
        self.assertEqual(r.status, 400)
        self.assertEqual(json.loads(r.body)["error"], "invalid_request")

    def test_forged_proofs_are_one_error(self):
        """Every authentication failure at the TTS looks the same in the body."""
        wkey = w.new_workload_key("ES256")
        bodies = set()
        for tamper in (False, True):
            req = w.http_sig("POST", cd.TTS_A_URL, cd.new_txn_form("files:read"), cd.peer_wit(wkey), wkey,
                             aud=cd.TTS_A_PROOF_AUD, content_type=w.FORM_CT, tamper_digest=tamper)
            r = cd.safe_send(req, case="UT")
            bodies.add((r.status == 200, r.body if r.status != 200 else b""))
        failed = [b for ok, b in bodies if not ok]
        self.assertEqual(failed, [b'{"error": "invalid_client"}'])


    def test_authentication_failures_do_not_name_the_failed_check(self):
        """http-signature-08 s3.6: every 400 from a failed authentication has one body, whatever check failed."""
        causes = {
            "digest": {"tamper_digest": True},
            "audience": {"aud_override": "http://rich.ietf127.example:9999"},
            "component": {"drop_components": ("@query",)},
            "keyid": {"keyid_param": "k1"},
            "nonce-less tag": {"tag": "some-other-tag"},
        }
        wkey = w.new_workload_key("ES256")
        targets = {  # url, audience the peer expects, WIT
            "file-tool": ("http://127.0.0.1:5063/files/read", cd.FILE_AUD, cd.rich_wit(cd.RESEARCH_KEY, cd.RESEARCH_ID), cd.RESEARCH_KEY),
            "coordinator": ("http://127.0.0.1:5060/coordinate", "http://rich.ietf127.example:5060", cd.peer_wit(wkey), wkey),
            "research": ("http://127.0.0.1:5062/research", "http://rich.ietf127.example:5062", cd.rich_wit(cd.COORD_KEY, cd.COORDINATOR_ID), cd.COORD_KEY),
            "tts-a": (cd.TTS_A_URL, cd.TTS_A_PROOF_AUD, cd.peer_wit(wkey), wkey),
            "tts-b": (cd.TTS_B_URL, "http://rich.ietf127.example:5061", cd.rich_wit(cd.COORD_KEY, cd.COORDINATOR_ID), cd.COORD_KEY),
            "as-a": ("http://127.0.0.1:5051/oauth/token", cd.TTS_A_PROOF_AUD, cd.peer_wit(wkey), wkey),
        }
        for name, (url, aud, wit, key) in targets.items():
            seen = {}
            for cause, kw in causes.items():
                kw = dict(kw)
                req_aud = kw.pop("aud_override", aud)
                req = w.http_sig("POST", url, b"a=b", wit, key, aud=req_aud, content_type=w.FORM_CT, **kw)
                r = cd.safe_send(req, case="UT")
                seen[cause] = (r.status, r.headers.get("content-type"), r.body)
            self.assertEqual({v[0] for v in seen.values()}, {400}, f"{name}: {seen}")
            self.assertEqual(len(set(seen.values())), 1, f"{name} body differs by cause: {seen}")

    def test_no_proof_and_wpt_failures_share_their_bodies_too(self):
        wit = cd.rich_wit(cd.RESEARCH_KEY, cd.RESEARCH_ID)
        tok = w.issue_txn_token(cd.TTS_B_KEY, kid="tts_b-1", iss="http://rich.ietf127.example:5061", aud="rich.ietf127.example",
                                txn="t", sub="user:alice", scope="files:read", req_wl=cd.RESEARCH_ID, tctx={"file": "Q3.pdf"})
        no_proof = cd.safe_send(w.Req("POST", "http://127.0.0.1:5063/files/read", {"Content-Type": "application/json"}, b"{}"), case="UT")
        bad_wpt = cd.safe_send(w.wpt_request("POST", "http://127.0.0.1:5063/files/read", b"{}", wit, cd.RESEARCH_KEY,
                                             aud=cd.FILE_AUD, alg="ES256", headers={"Txn-Token": tok}, txn_token=tok,
                                             claims_extra={"tth": "wrong"}), case="UT")
        self.assertEqual((no_proof.status, bad_wpt.status), (401, 401))
        self.assertEqual(no_proof.body, bad_wpt.body)

    def test_token_endpoint_errors_are_rfc6749(self):
        """RFC 6749 s5.2 / RFC 7523 s3.1: 400 and an error code at AS-B; no custom reason member."""
        def asb(body):
            return cd.safe_send(w.Req("POST", "http://127.0.0.1:5061/oauth/token", {"Content-Type": w.FORM_CT}, body), case="UT")
        at = w.issue_access_token(cd.AS_B_KEY, kid="as_b-1", iss="x", aud="y", sub="s", scope="files:read", txn="t")
        for body, error in (
            (w.jwt_bearer_request(at), "invalid_grant"),  # an access token is not a grant (RFC 7523 s3.1)
            (w.jwt_bearer_request("not-a-jwt"), "invalid_grant"),
            (w.form_encode({"grant_type": w.GRANT_JWT_BEARER}), "invalid_request"),
            (w.form_encode({"grant_type": "password", "assertion": at}), "unsupported_grant_type"),
            (b"%%%", "invalid_request"),
        ):
            r = asb(body)
            self.assertEqual((r.status, json.loads(r.body)), (400, {"error": error}), body)
        r = cd.safe_send(w.Req("POST", "http://127.0.0.1:5061/oauth/token", {"Content-Type": "application/json"},
                               json.dumps({"assertion": at}).encode()), case="UT")
        self.assertEqual((r.status, json.loads(r.body)), (400, {"error": "invalid_request"}))


class WptAlgTest(unittest.TestCase):
    """wpt-02 s2: the alg of the WPT MUST match the alg of the jwk in cnf; Ed25519 and EdDSA are not interchangeable."""

    def _verify(self, wpt_alg):
        issuer = w.new_workload_key("ES256")
        trust = {"t.example": {"keys": [w.jwk_from_public(issuer.public_key(), kid="i-1")]}}
        wkey = w.new_workload_key("Ed25519")
        wit = w.issue_wit(issuer, kid="i-1", iss="http://t.example", sub="wimse://t.example/w",
                          workload_pub_jwk=w.jwk_from_public(wkey.public_key()))  # cnf alg "Ed25519"
        req = w.wpt_request("POST", "http://127.0.0.1:1/x", b"{}", wit, wkey, aud="http://t.example", alg=wpt_alg)
        return w.verify_wimse_proof("POST", "/x", req.headers, req.body, trust, expected_aud="http://t.example")

    def test_same_alg_is_accepted(self):
        self.assertEqual(self._verify("Ed25519")[:3], (True, 200, "accept"))

    def test_eddsa_against_ed25519_cnf_is_refused(self):
        self.assertEqual(self._verify("EdDSA")[:3], (False, 401, "alg-mismatch"))

    def test_es256_against_ed25519_cnf_is_refused(self):
        self.assertEqual(self._verify("ES256")[:3], (False, 401, "alg-mismatch"))


if __name__ == "__main__":
    unittest.main()
