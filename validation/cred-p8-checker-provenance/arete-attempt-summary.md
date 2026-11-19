Local paths redacted; no other change.
# Failed Arete checker attempt

Model id: `nousresearch_arete-27b`; maker: Nous Research.
Base model: `Qwen/Qwen3.8-27B` (Alibaba); family: `alibaba-qwen+nousresearch`.
GGUF: `NousResearch_Arete-27B-IQ4_XS.gguf` (bartowski IQ4_XS).
LM Studio version: `0.4.26+4`.
The attempt is closed as failed; it never passed the real capture.
Setup failures are separate from the nine code-and-test rounds.

| Phase | Outcome |
|---|---|
| Setup 1 | Generation tool timeout. |
| Setup 2 | Generation canceled to switch to streaming. |
| Setup 3 | Reasoning-only output exhausted the output cap. |
| Setup 4 | Assertion request 1 of 6 exhausted the output cap. |
| Setup 5 | SDK preflight failed; larger context refused by memory guardrail. |
| Setup 6 | SDK template disconnected again; local rendering workaround verified. |
| Setup 7 | One-shot assembly exhausted the output cap with thinking off. |
| Code-and-test 1 | Real capture exit 2: spec file missing at module-relative path. |
| Code-and-test 2 | Real capture exit 2: same spec-path failure. |
| Code-and-test 3 | Real capture exit 1: permission grant not observed. |
| Code-and-test 4 | Real capture exit 1: permission grant not observed. |
| Code-and-test 5 | Real capture exit 1: permission grant not observed. |
| Code-and-test 6 | Real capture exit 1: permission grant not observed. |
| Code-and-test 7 | Real capture exit 1: permission grant not observed. |
| Code-and-test 8 | Real capture exit 1: permission grant not observed. |
| Code-and-test 9 | Real capture exit 1: permission grant not observed. |

Final failure line: `assertion1: no /admin/permissions grant observed on Cred port 5065`.
The grant is in the capture; parser and partial reason-mapping failures remained.
Nonzero mutant exits did not establish discrimination while the real capture failed.

Archive file: `cred-p8-checker-provenance.tar.gz`.
Archive size: `1355692` bytes.
Archive SHA-256: `bf54274a1c0c22f7c5c94f95263dda9dda88e1a21d12395300d26f9fa57de996`.
raw prompts, replies and streams are retained by Kieran Sweeney and available on request
