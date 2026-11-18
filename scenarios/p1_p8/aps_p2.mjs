// APS run of IETF 127 hackathon scenario P2 (revocation after delegation, before effect).
// Uses agent-passport-system@8.1.1, draft-pidlisnyi-aps record types:
// aps:authority-delegation:v1 and aps:authority-revocation:v1.
// Writes one JSON object per decision to stdout (ietf127-wimse-scenario/1).
// Keys are generated fresh on every run and never written anywhere.
import {
  generateKeyPair,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  verifyAuthorityDelegationChain,
  InMemoryAuthorityRevocationStore,
  recordAuthorityRevocation,
  issueAuthorityRevocation,
  createAuthorityRevocationResolver,
} from 'agent-passport-system'
import { randomBytes } from 'node:crypto'
import { performance } from 'node:perf_hooks'

const SCOPE = 'payments:transfer' // E's protected, high value operation
const ts = (ms) => new Date(ms).toISOString() // canonical UTC millisecond timestamp
const nonce = () => randomBytes(16).toString('hex')

function party(did) {
  const k = generateKeyPair()
  return { did, vm: `${did}#key-1`, pub: k.publicKey, priv: k.privateKey }
}

function authority(scope, notBefore, notAfter, remaining) {
  return {
    scope: { profile: 'aps-hierarchical-v1', grants: [scope] },
    spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100000', cumulative: '100000' },
    depth: { remaining },
    time: { not_before: notBefore, not_after: notAfter },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1', required: [] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'irreversible' },
  }
}

// Root receipt: issuer (domain A authority) -> agent A. Child receipt: agent A -> agent B.
function setup() {
  const issuer = party('did:example:issuer.domain-a')
  const a = party('did:example:agent-a.domain-a')
  const b = party('did:example:agent-b.domain-b')
  const keys = new Map([[issuer.vm, issuer.pub], [a.vm, a.pub], [b.vm, b.pub]])
  const resolveVerificationKey = (_c, vm) => keys.get(vm) ?? null
  const t = Date.now()
  const root = issueAuthorityDelegation({
    record_type: 'aps:authority-delegation:v1', version: '1.0', parent_delegation_id: null,
    issuer: issuer.did, subject: a.did, verification_method: issuer.vm,
    issued_at: ts(t - 2000), nonce: nonce(),
    authority: authority(SCOPE, ts(t - 2000), ts(t + 3600000), 2),
  }, issuer.priv)
  const child = issueSubAuthorityDelegation(root, {
    record_type: 'aps:authority-delegation:v1', version: '1.0', parent_delegation_id: root.delegation_id,
    issuer: a.did, subject: b.did, verification_method: a.vm,
    issued_at: ts(t - 1000), nonce: nonce(),
    authority: authority(SCOPE, ts(t - 1000), ts(t + 1800000), 1),
  }, a.priv, { now: ts(t), resolveVerificationKey, resolveRevocation: () => 'active' })
  // E's revocation store. E tracks both records, so absence of a revocation reads as active.
  const store = new InMemoryAuthorityRevocationStore()
  store.track(root.delegation_id)
  store.track(child.delegation_id)
  return { issuer, root, child, store, resolveVerificationKey }
}

// E's check: verify the whole chain at the current wall clock time, then the scope.
function check(env) {
  const r = verifyAuthorityDelegationChain([env.root, env.child], {
    now: ts(Date.now()),
    resolveVerificationKey: env.resolveVerificationKey,
    trustRoot: (c) => c.delegation_id === env.root.delegation_id,
    resolveRevocation: createAuthorityRevocationResolver(env.store, { resolveVerificationKey: env.resolveVerificationKey }),
  })
  const code = r.failures?.[0]?.code ?? null
  if (r.state === 'valid') {
    const grants = env.child.authority.scope.grants
    return grants.includes(SCOPE) ? { decision: 'allow', reason: 'ok', aps_state: r.state, aps_code: null }
      : { decision: 'deny', reason: 'scope-exceeded', aps_state: r.state, aps_code: 'SCOPE' }
  }
  const reason = code === 'REVOKED' ? 'status-revoked'
    : code === 'REVOCATION_UNKNOWN' ? 'status-unavailable' : `aps:${code}`
  return { decision: 'deny', reason, aps_state: r.state, aps_code: code }
}

// The issuer of A's root receipt revokes it, and E records the signed revocation.
function revokeRoot(env) {
  const rec = issueAuthorityRevocation(env.root, {
    now: ts(Date.now()), revoker: env.issuer.did, verification_method: env.issuer.vm,
    reason_code: 'key_compromise', nonce: nonce(),
  }, env.issuer.priv)
  const out = recordAuthorityRevocation(env.store, env.root, rec, { resolveVerificationKey: env.resolveVerificationKey })
  if (!out || out.recorded !== true) throw new Error('revocation was not recorded: ' + JSON.stringify(out))
  return { rec, t0: performance.now() }
}

const lines = []
let effects = 0
const protectedOp = () => { effects += 1 }
// The effect field is what the protected operation's counter shows, read after the
// decision is acted on, not a value derived from the decision.
function act(d) {
  const before = effects
  if (d.decision === 'allow') protectedOp()
  return effects > before ? 'ran' : 'none'
}
function log(c, txn, check_, d, expected, extra = {}) {
  lines.push({
    scenario: 'P2', case: c, impl: 'aps', hop: 'E', domain: 'B', txn_id: txn,
    check: check_, decision: d.decision, reason: d.reason, effect: extra.effect,
    expected_decision: expected?.decision ?? null, expected_reason: expected?.reason ?? null,
    aps_state: d.aps_state, aps_code: d.aps_code,
    t_since_revocation_ms: extra.t ?? null, bound_s: null, clock: 'wall', ts: Date.now(),
  })
}
const EXPECT = { decision: 'deny', reason: 'status-revoked' }

// Case revoke-upstream: B's call succeeds once, A's root receipt is revoked, B calls again.
{
  const env = setup()
  let d = check(env)
  log('revoke-upstream', 'ru-0', 'authorize', d, { decision: 'allow', reason: 'ok' }, { effect: act(d) })
  const { t0 } = revokeRoot(env)
  d = check(env)
  const t = Math.round((performance.now() - t0) * 1000) / 1000
  log('revoke-upstream', 'ru-1', 'authorize', d, EXPECT, { effect: act(d), t })
}

// Case before-effect: E authorizes, A's root receipt is revoked, E checks again before effect.
{
  const env = setup()
  let d = check(env)
  log('before-effect', 'be-0', 'authorize', d, { decision: 'allow', reason: 'ok' }, { effect: 'pending' })
  const { t0 } = revokeRoot(env)
  d = check(env)
  const t = Math.round((performance.now() - t0) * 1000) / 1000
  log('before-effect', 'be-0', 'before-effect', d, EXPECT, { effect: act(d), t })
}

for (const l of lines) process.stdout.write(JSON.stringify(l) + '\n')
process.stderr.write(`protected operation ran ${effects} time(s)\n`)
