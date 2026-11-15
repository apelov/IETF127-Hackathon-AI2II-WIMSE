# Revocation trace — testnet — 2026-11-14T10:42:57.756Z

Chain `mintid-testnet-3`, issuer `7bf0b103ee565ba9…`, verifier `e8bc2290520bb2ee…`. Raw events: `revocation-trace-testnet-20261114T104257Z.jsonl`. Decision log: not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD).

## Authority evidence

| Field | Value |
|---|---|
| Source | the issuer's status root on chain `mintid-testnet-3`, read by the verifier with an ics23 proof against the node's committed app hash at each decision (R15) |
| Trace ran from | public checkout `dca3d605b7a1d559ef74c444498552f64c9c8285` (read from the public project's release tag); source revision `82c455ed09f8a99142117378a345a392d031f7dc` (the commit checked out); release `public-v2026-11-13.1` |
| Revision | verifier `89d6af3f4612` (public-v2026-11-11.1), issuer `89d6af3f4612` (public-v2026-11-11.1); verifier engine `proof-core 0.6.0`, SDK 0.9.0, SPEC-1 v3.7 |
| Issuer signing key | `ce96f48eae90d5fb…` (a key id, not a revision) |
| Status/root | before: epoch 32817, finalized height 460843; after: epoch 32827, finalized height 460983 |
| Observation time | before 2026-11-14T10:42:58.000Z; after 2026-11-14T10:47:53.000Z (verifier `/v1/status`) |
| Actual age | before 17 s; after 12 s |
| Deployed freshness limit | 180 s maximum root age (heartbeat 30 s; verifier height lag 100 blocks; K = 5 s) |
| Check performed | condition 5: the proof is verified against the issuer definition (BBS key + accumulator) the newest *provable* finalized root anchors; condition 7: the presented root is the current root, or a ring entry inside its validity window, superseded within the height lag and followed by no emergency root; chain unreadable → refuse |

Presentation lifetime: 10 s (R14) — bounds replay, not revocation; a separate field from the revocation latency below.

Claim policy (every challenge; SHA-256 with the issuer policy `bb83d24e40d8627dc0fba3ff51967d0ee5040d51112d73b207f05439272aa364`): `human_backed = True`, `pairwise_pseudonym` (this verifier), `assurance_grade >= A2`, `counterparty_includes = eip155:8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`, `delegated_scope_includes = payments.initiate`, `category_in = mcc:5812`, `geo_in = iso3166-1:ES`, `transaction_limit >=` 5 USDC (5000000, exponent 6), `unexpired = True`, `credential_active = True`; no key-custody floor: the trace measures revocation propagation, not custody, and an agent minted without key-attestation evidence is appraised `software`.

## Temporal revocation

| Path | Trigger time (t0) | Authority evidence consulted at the denial | Last accepted action | Required deny point (bound) | First observed denial | Root carrying the revocation |
|---|---|---|---|---|---|---|
| issuer | 2026-11-14T10:43:25.128Z — the issuer's removal of the agent (revoke response) | current root epoch 32819 (finalized height 460872, generated 2026-11-14T10:43:41.000Z) | 2026-11-14T10:43:44.852Z (+19.7 s) | t0 + 185 s (t0 + A + K) = 2026-11-14T10:46:30.128Z | 2026-11-14T10:43:48.276Z (+23.1 s), `status_root_stale` | epoch 32819, finalized height 460872 at 2026-11-14T10:43:41.455Z |
| kill_switch | 2026-11-14T10:44:00.599Z — the recording of the nullifier on chain (block time of the relay's tx) | current root epoch 32820 (finalized height 460886, generated 2026-11-14T10:44:11.000Z) | 2026-11-14T10:44:15.147Z (+14.5 s) | t0 + 245 s (t0 + G + A + K) = 2026-11-14T10:48:05.599Z | 2026-11-14T10:44:17.665Z (+17.1 s), `status_root_stale` | epoch 32820, finalized height 460886 at 2026-11-14T10:44:11.207Z |
| cascade (cascade_agent_1) | 2026-11-14T10:44:41.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 32827 (finalized height 460983, generated 2026-11-14T10:47:41.000Z) | 2026-11-14T10:47:46.945Z (+185.9 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-11-14T10:51:16.000Z | 2026-11-14T10:47:50.063Z (+189.1 s), `status_root_stale` | trigger root epoch 32821, finalized height 460898 at 2026-11-14T10:44:40.937Z |
| cascade (cascade_agent_2) | 2026-11-14T10:44:41.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 32822 (finalized height 460912, generated 2026-11-14T10:45:11.000Z) | 2026-11-14T10:45:15.787Z (+34.8 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-11-14T10:51:16.000Z | 2026-11-14T10:45:21.763Z (+40.8 s), `status_root_stale` | trigger root epoch 32821, finalized height 460898 at 2026-11-14T10:44:40.937Z |

## Measured deny point per path

| Path | First observed denial − t0 | Bound | Within the bound |
|---|---|---|---|
| issuer | 23.1 s, `status_root_stale`, confirmed `status_root_stale` | 185 s | yes |
| kill_switch | 17.1 s, `status_root_stale`, confirmed `status_root_stale` | 245 s | yes |
| cascade/cascade_agent_1 | 189.1 s, `status_root_stale`, confirmed `status_root_stale` | 395 s | yes |
| cascade/cascade_agent_2 | 40.8 s, `status_root_stale`, confirmed `status_root_stale` | 395 s | yes |

Times are wall-clock UTC of this machine; a root's "finalized at" is the CometBFT block time (BFT time), which trails wall-clock by up to about one block, so it can read earlier than the root's own `generated_at`. Each forced attempt takes about a second (proof + verdict), which is the granularity of the measured points.

## Refusals set aside (not the denial point)

A denial point is a refusal the revocation explains (`status_root_stale`, `credential_revoked`), confirmed by a second attempt made at once and refused the same way. Any other refusal — such as `deadline_exceeded`, a validation that outlived the 10 s presentation lifetime — is recorded as an attempt and the trace keeps forcing; so is a refusal the second attempt does not confirm. Times are seconds after the path's t0.

- **issuer**: none.
- **issuer control (never revoked)**: none.
- **kill_switch**: none.
- **cascade (cascade_agent_1)**: none.
- **cascade (cascade_agent_2)**: none.

## Decision-log lines (R18 fixed-slot records)

| Path | Decision | Verifier answer | Decision-log line |
|---|---|---|---|
| issuer last accepted | 2026-11-14T10:43:44.852Z | `accepted` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| issuer first refused | 2026-11-14T10:43:48.276Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| kill_switch last accepted | 2026-11-14T10:44:15.147Z | `accepted` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| kill_switch first refused | 2026-11-14T10:44:17.665Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_1 last accepted | 2026-11-14T10:47:46.945Z | `accepted` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_1 first refused | 2026-11-14T10:47:50.063Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_2 last accepted | 2026-11-14T10:45:15.787Z | `accepted` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_2 first refused | 2026-11-14T10:45:21.763Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |

## Control (issuer path): a sibling agent that is not revoked

The sibling forced a proof over the witness it held at the trigger, never refreshing: last accepted 2026-11-14T10:43:42.149Z, first refused 2026-11-14T10:43:47.367Z `status_root_stale`; after refreshing its witness it was `accepted`.

## Attribution

The verifier's record shows the root a decision rested on; revocation is shown by the failed witness refresh.

A first refusal marks when a root newer than the agent's witness became provable to the verifier, which a never-revoked agent forcing an old witness meets too. A revoked agent cannot obtain a newer witness; a live one can, and is accepted again. Times are seconds after the path's t0.

| Path | Revoked agent | First refused | Witness refresh |
|---|---|---|---|
| issuer | `agent_issuer` | +23.1 s `status_root_stale` | refused +3.1 s, `credential_revoked` |
| kill_switch | `agent_kill_switch` | +17.1 s `status_root_stale` | refused +11.8 s, `credential_revoked` |
| cascade (cascade_agent_1) | `cascade_agent_1` | +189.1 s `status_root_stale` | refused +183.3 s, `credential_revoked` |
| cascade (cascade_agent_2) | `cascade_agent_2` | +40.8 s `status_root_stale` | refused +32.0 s, `credential_revoked` |

Control on the issuer path (`sibling_control`, never revoked, forcing the witness it held at the trigger): refused +22.2 s `status_root_stale`; its witness refresh: a newer witness obtained +26.0 s; after the refresh accepted +28.9 s `accepted`.

## Rule

- **issuer**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **issuer control (never revoked)**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **kill_switch**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **cascade (cascade_agent_1)**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **cascade (cascade_agent_2)**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.

