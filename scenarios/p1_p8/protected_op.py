"""The enforcing side of a protected operation: authorise, then re-check just before the operation takes effect,
and run it only if that check still allows the request (IETF 127 scenario P2, "before-effect"; draft-le-agent-passport
"Exposure After Revocation").

The verifier decides; this connects its decision to the operation and records whether the operation ran. Each step
writes one log line in the scenario format (docs/hackathon/ietf127, `ietf127-wimse-scenario/1`), so a run can be
compared with other implementations.

Run `python3 app/protected_op.py` for a self-check."""


class ProtectedOperation:
    """`verifier`: an atpp_verify.Verifier. `operation(req)` performs the effect and returns its result. `log(line)`
    receives one dict per step. `revoked_at`: when the revocation under test was recorded at the issuer, if any, so
    lines carry `t_since_revocation_ms`."""

    def __init__(self, verifier, operation, log, scenario="P2", case="", impl="redthread", hop="E", domain="B"):
        self.v, self.operation, self.log = verifier, operation, log
        self.base = {"scenario": scenario, "case": case, "impl": impl, "hop": hop, "domain": domain}
        self.revoked_at = None

    def _line(self, check, r, effect, txn_id):
        now = self.v.now()
        line = dict(self.base, txn_id=txn_id, check=check, decision=r["decision"],
                    reason=",".join(r["reasons"]) or "ok", effect=effect, ts=now, bound_s=r["exposure"])
        if self.revoked_at is not None:
            line["t_since_revocation_ms"] = int(round((now - self.revoked_at) * 1000))
        self.log(line)

    def run(self, req, value, transport, txn_id, before_effect=None, **kw):
        """Authorise `req`, call `before_effect()` (where a test changes the world: the window between authorisation
        and effect), re-check with every status fetched fresh, and perform the operation only if both allowed.
        Returns {"effect": "ran"|"none", "result", "authorize", "before_effect"}."""
        a = self.v.verify(req, value, transport, **kw)
        if a["decision"] != "allow":
            self._line("authorize", a, "none", txn_id)
            return {"effect": "none", "result": None, "authorize": a, "before_effect": None}
        self._line("authorize", a, "pending", txn_id)
        if before_effect:
            before_effect()
        b = self.v.verify(req, value, transport, revalidate=True, **kw)
        if b["decision"] != "allow":
            self._line("before-effect", b, "none", txn_id)
            return {"effect": "none", "result": None, "authorize": a, "before_effect": b}
        result = self.operation(req)
        self._line("before-effect", b, "ran", txn_id)
        return {"effect": "ran", "result": result, "authorize": a, "before_effect": b}


def demo():
    class V:                                     # a verifier that allows once, then sees the revocation
        calls = []

        def now(self):
            return 100.0

        def verify(self, req, value, transport, revalidate=False, **kw):
            self.calls.append(revalidate)
            ok = not revalidate
            return {"decision": "allow" if ok else "deny", "reasons": [] if ok else ["revoked"], "exposure": 120}
    ran, lines = [], []
    op = ProtectedOperation(V(), lambda req: ran.append(req), lines.append, case="before-effect")
    op.revoked_at = 99.5
    r = op.run({}, "high", {}, "t1")
    assert r["effect"] == "none" and ran == [] and V.calls == [False, True]
    assert [x["check"] for x in lines] == ["authorize", "before-effect"] and lines[1]["reason"] == "revoked"
    assert lines[1]["t_since_revocation_ms"] == 500
    print("protected_op self-check ok")


if __name__ == "__main__":
    demo()
