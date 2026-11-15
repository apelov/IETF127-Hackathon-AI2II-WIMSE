"""The enforcing side of a protected operation: authorise, then re-check just before the operation takes effect,
and run it only if that check still allows the request (IETF 127 scenario P2, "before-effect"; draft-le-agent-passport
"Exposure After Revocation").

The verifier decides; this connects its decision to the operation and records whether the operation ran. Each step
writes one log line in the scenario format (docs/hackathon/ietf127, `ietf127-wimse-scenario/1`), so a run can be
compared with other implementations.

Run `python3 scenarios/p1_p8/protected_op.py` for a self-check.
"""
import inspect


class ProtectedOperation:
    """`verifier`: an atpp_verify.Verifier or mock verifier.
    `op` / `operation(req)`: performs the effect and returns its result.
    `log(line)`: receives one dict per step.
    `outside`: optional callable for outside verifiers (e.g., MintID).
    `revoked_at`: when the revocation under test was recorded at the issuer, if any,
    so lines carry `t_since_revocation_ms`.
    """

    def __init__(
        self,
        verifier,
        operation=None,
        log=None,
        scenario="P2",
        case="before-effect",
        impl="redthread",
        hop="E",
        domain="B",
        outside=None,
        op=None,
    ):
        if op is not None and operation is None:
            operation = op
        self.v = verifier
        self.verifier = verifier
        self.operation = operation
        self.op = operation
        self.log = log or (lambda line: None)
        self.outside = outside
        self.base = {
            "scenario": scenario,
            "case": case,
            "impl": impl,
            "hop": hop,
            "domain": domain,
        }
        self.revoked_at = None

    def _line(self, check, r, effect, txn_id, extra=None):
        if hasattr(self.v, "now") and callable(self.v.now):
            now = self.v.now()
        elif hasattr(self, "ts") and self.ts is not None:
            now = self.ts
        else:
            now = 0
        decision = r["decision"] if isinstance(r, dict) and "decision" in r else ("allow" if r else "deny")
        if isinstance(r, dict):
            reasons = r.get("reasons")
            if isinstance(reasons, list):
                reason = ",".join(reasons) or "ok"
            else:
                reason = r.get("reason", "ok" if decision == "allow" else "deny")
            bound = r.get("exposure", r.get("bound_s", 120))
        else:
            reason = "ok" if decision == "allow" else "deny"
            bound = 120
        line = dict(
            self.base,
            txn_id=txn_id,
            check=check,
            decision=decision,
            reason=reason,
            effect=effect,
            ts=now,
            bound_s=bound,
        )
        if self.revoked_at is not None:
            line["t_since_revocation_ms"] = int(round((now - self.revoked_at) * 1000))
        if extra:
            line.update(extra)
        self.log(line)
        return line

    def run(
        self,
        *args,
        txn_id="1",
        domain=None,
        hop=None,
        scenario=None,
        case=None,
        value="high",
        before_effect=None,
        **kw,
    ):
        """Authorise `req`, call `before_effect()` (where a test changes the world: the window between
        authorisation and effect), re-check with every status fetched fresh (or via `outside`), and
        perform the operation only if both allowed.
        Returns a dict describing the decision, effect, and result.
        """
        if domain is not None:
            self.base["domain"] = domain
        if hop is not None:
            self.base["hop"] = hop
        if scenario is not None:
            self.base["scenario"] = scenario
        if case is not None:
            self.base["case"] = case

        chain = None
        transport = {}
        if len(args) == 0:
            req = {}
        elif len(args) == 1:
            req = args[0]
        elif len(args) == 2:
            if isinstance(args[1], (dict, list)):
                chain, req = args[0], args[1]
            else:
                req, value = args[0], args[1]
        elif len(args) == 3:
            req, value, transport = args[0], args[1], args[2]
        else:
            req, value, transport = args[0], args[1], args[2]
            if txn_id == "1":
                txn_id = args[3]

        if hasattr(self.verifier, "verify"):
            sig = inspect.signature(self.verifier.verify)
            if "chain" in sig.parameters and chain is not None:
                a = self.verifier.verify(chain, req, value=value, **kw)
            else:
                a = self.verifier.verify(req, value, transport, **kw)
        elif callable(self.verifier):
            try:
                a = self.verifier(req, value, transport, **kw)
            except TypeError:
                try:
                    a = self.verifier(req)
                except TypeError:
                    a = self.verifier()
        else:
            a = {"decision": "allow", "reasons": [], "exposure": 120}

        if isinstance(a, bool):
            a = {"decision": "allow" if a else "deny", "reasons": [] if a else ["denied"], "exposure": 120}

        if a.get("decision") != "allow":
            self._line("authorize", a, "none", txn_id)
            return {
                "decision": a.get("decision", "deny"),
                "reason": ",".join(a.get("reasons", [])) or a.get("reason", "deny"),
                "effect": "none",
                "operation_ran": False,
                "result": None,
                "authorize": a,
                "before_effect": None,
            }

        self._line("authorize", a, "pending", txn_id)

        if before_effect is not None and callable(before_effect):
            before_effect()

        if self.outside is not None:
            try:
                res = self.outside()
            except TypeError:
                res = self.outside(req, txn_id)
            if isinstance(res, tuple) and len(res) == 3:
                ok, reason, extra = res
            elif isinstance(res, dict):
                ok = res.get("decision") == "allow" or res.get("accepted") is True or res.get("ok") is True
                reason = res.get("reason") or res.get("error") or ("ok" if ok else "deny")
                extra = {k: v for k, v in res.items() if k not in ("decision", "reason", "effect", "ok")}
            else:
                ok = bool(res)
                reason = "ok" if ok else "deny"
                extra = {}

            extra_dict = dict(extra) if extra else {}
            now = self.v.now() if hasattr(self.v, "now") and callable(self.v.now) else 1000000
            log_line = dict(
                self.base,
                txn_id=txn_id,
                check="outside-verifier",
                decision="allow" if ok else "deny",
                reason=reason,
                effect="ran" if ok else "none",
                ts=now,
            )
            if self.revoked_at is not None:
                log_line["t_since_revocation_ms"] = int(round((now - self.revoked_at) * 1000))
            if extra_dict:
                log_line.update(extra_dict)
            self.log(log_line)

            op_fn = self.op or self.operation
            if ok:
                result = op_fn(req) if op_fn else None
                ret = {
                    "decision": "allow",
                    "reason": reason,
                    "effect": "ran",
                    "operation_ran": True,
                    "result": result,
                    **extra_dict,
                }
                ret["outside"] = {"decision": "allow", "reason": reason, **extra_dict}
                return ret
            else:
                ret = {
                    "decision": "deny",
                    "reason": reason,
                    "effect": "none",
                    "operation_ran": False,
                    "result": None,
                    **extra_dict,
                }
                ret["outside"] = {"decision": "deny", "reason": reason, **extra_dict}
                return ret

        if hasattr(self.verifier, "verify"):
            sig = inspect.signature(self.verifier.verify)
            if "chain" in sig.parameters and chain is not None:
                b = self.verifier.verify(chain, req, value=value, revalidate=True, **kw)
            else:
                b = self.verifier.verify(req, value, transport, revalidate=True, **kw)
        elif callable(self.verifier):
            try:
                b = self.verifier(req, value, transport, revalidate=True, **kw)
            except TypeError:
                try:
                    b = self.verifier(req, revalidate=True)
                except TypeError:
                    b = self.verifier()
        else:
            b = {"decision": "allow", "reasons": [], "exposure": 120}

        if isinstance(b, bool):
            b = {"decision": "allow" if b else "deny", "reasons": [] if b else ["denied"], "exposure": 120}

        if b.get("decision") != "allow":
            self._line("before-effect", b, "none", txn_id)
            return {
                "decision": b.get("decision", "deny"),
                "reason": ",".join(b.get("reasons", [])) or b.get("reason", "deny"),
                "effect": "none",
                "operation_ran": False,
                "result": None,
                "authorize": a,
                "before_effect": b,
            }

        op_fn = self.op or self.operation
        result = op_fn(req) if op_fn else None
        self._line("before-effect", b, "ran", txn_id)
        return {
            "decision": "allow",
            "reason": "ok",
            "effect": "ran",
            "operation_ran": True,
            "result": result,
            "authorize": a,
            "before_effect": b,
        }


def demo():
    class V:  # a verifier that allows once, then sees the revocation
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
