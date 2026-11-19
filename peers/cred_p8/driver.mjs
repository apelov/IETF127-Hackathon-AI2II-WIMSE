#!/usr/bin/env node
// Scenario P8 driver: an agent in trust domain B sends the P8 steps to the two
// Cred servers started by serve.mjs and, for the last step, to the provider.
//
// The requests (WIT + WPT, WIT + HTTP signature, Txn-Token, DPoP-bound
// Delegation Token) are built by Cred's own hackathon client
// (scripts/hackathon/lib/client.mjs) and SDK. This file only orders the steps,
// tags each request with X-Test-Case (unsigned, for the capture checker),
// compares each answer with cred_p8_cases.json and writes a journal in the
// ietf127-wimse-scenario/1 format.
//
//   node peers/cred_p8/driver.mjs --cred <cred checkout> [--state <dir>] [--journal-out <file>]
//
// Exit status 0 only when every step matched.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const arg = (name, dflt) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? dflt : process.argv[i + 1];
};
const credDir = path.resolve(arg('--cred', path.join(root, 'external/cred')));
const stateDir = path.resolve(arg('--state', process.env.CRED_P8_STATE ?? path.join(os.tmpdir(), 'ietf127-cred-p8-state')));
const journalOut = arg('--journal-out', null);

const spec = JSON.parse(fs.readFileSync(path.join(root, 'cred_p8_cases.json'), 'utf8'));
const expected = new Map(spec.steps.map((s) => [`${s.case}/${s.step}`, s]));
const state = JSON.parse(fs.readFileSync(path.join(stateDir, 'state.json'), 'utf8'));

const lib = (f) => import(pathToFileURL(path.join(credDir, 'scripts/hackathon/lib', f)).href);
const { es256Jws } = await lib('issuers.mjs');
const { loadPackages } = await lib('cred.mjs');
const { agentClient } = await lib('client.mjs');
const { server: cred, sdk } = await loadPackages();
const credCommit = spawnSync('git', ['-C', credDir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();

// Every request this process sends carries the tag of the step in progress.
let tag = null;
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init = {}) => {
  const headers = new Headers(init.headers ?? {});
  if (tag) headers.set('X-Test-Case', tag);
  return realFetch(input, { ...init, headers });
};

const privateKey = (jwk) => crypto.createPrivateKey({ key: jwk, format: 'jwk' });
const workload = (name) => {
  const w = state.workloads[name];
  return { subject: w.subject, wit: w.wit, privateKey: privateKey(w.privateKeyJwk) };
};
const ttsKey = privateKey(state.tts.privateKeyJwk);
// Same claims as Cred's hackathon Txn-Token Service (scripts/hackathon/lib/issuers.mjs).
const txnToken = (txn, claims = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return es256Jws({ alg: 'ES256', kid: state.tts.kid, typ: 'txntoken+jwt' }, {
    iat: now, exp: now + 300, aud: state.tts.aud, txn, sub: 'user:alice',
    scope: 'calendar.read', req_wl: `gateway.${state.tts.aud}`, ...claims,
  }, ttsKey);
};
const client = (cfg, name) => agentClient({
  baseUrl: state[cfg].baseUrl, workload: workload(name), sdk, cred,
  agent: { did: state[cfg].agents[name].did, identity: sdk.importAgentIdentity(state[cfg].agents[name].identity) },
});
const revoke = (cfg, jti) => fetch(`${state[cfg].baseUrl}/api/v1/delegations/${jti}?user_id=alice`, {
  method: 'DELETE', headers: { authorization: `Bearer ${state[cfg].agentToken}` },
});
const jtiOf = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()).jti;
const errOf = (r) => (r && typeof r.body === 'object' && r.body ? (r.body.error ?? null) : null);

const CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
const lines = [];
let failures = 0;

/** Run one step under its tag and compare the answer with cred_p8_cases.json. */
async function step(caseName, stepName, txnId, scopes, run) {
  const exp = expected.get(`${caseName}/${stepName}`);
  if (!exp) throw new Error(`step not in cred_p8_cases.json: ${caseName}/${stepName}`);
  tag = exp.id;
  let res;
  try {
    res = await run();
  } finally {
    tag = null;
  }
  const status = res.status;
  const credError = errOf(res);
  const ok = status === exp.status && credError === exp.cred_error;
  if (!ok) failures += 1;
  lines.push({
    scenario: 'P8', case: caseName, impl: 'cred', hop: 'E', domain: 'B', txn_id: txnId,
    decision: exp.decision, reason: exp.reason, ts: Math.floor(Date.now() / 1000),
    provider: 'google', scopes_requested: scopes, token_released: exp.token_released,
    cred_config: exp.config, step: stepName, test_case: exp.id, http_status: status, cred_reason: credError,
    expected_http_status: exp.status, expected_cred_reason: exp.cred_error, match: ok,
    clock: 'wall', cred_commit: credCommit,
  });
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${exp.id} HTTP ${status} cred=${credError ?? '-'} (expected ${exp.status} ${exp.cred_error ?? '-'})`);
  return res;
}
const jsonRes = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });

// Configuration A.
{
  const planner = client('A', 'planner');
  const stranger = client('A', 'no-delegation');
  const READ = ['calendar.readonly'];

  let id = `txn-${crypto.randomUUID()}`;
  await step('no-delegation', 'use-without-delegation', id, READ,
    () => stranger.sendUse(stranger.buildUse(null, { url: CALENDAR, method: 'GET' }, txnToken(id))));
  await step('no-delegation', 'ask-for-delegation', id, READ,
    () => stranger.delegateWithWpt({ user_id: 'alice', scopes: READ }, txnToken(id)));

  id = `txn-${crypto.randomUUID()}`;
  let d = await step('write-under-read', 'delegate-read', id, READ,
    () => planner.delegateWithWpt({ user_id: 'alice', scopes: READ }, txnToken(id)));
  let token = d.body?.access_token;
  await step('write-under-read', 'read-allowed', id, READ,
    () => planner.sendUse(planner.buildUse(token, { url: CALENDAR, method: 'GET' }, txnToken(id))));
  await step('write-under-read', 'write', id, ['calendar.readonly', 'calendar.events'],
    () => planner.sendUse(planner.buildUse(token, { url: CALENDAR, method: 'POST', body: { summary: 'not allowed' } }, txnToken(id, { scope: 'calendar.read calendar.write' }))));

  id = `txn-${crypto.randomUUID()}`;
  d = await step('revoked-between-authz-and-use', 'delegate-read', id, READ,
    () => planner.delegateWithWpt({ user_id: 'alice', scopes: READ }, txnToken(id)));
  token = d.body?.access_token;
  await step('revoked-between-authz-and-use', 'revoke', id, READ,
    async () => jsonRes(await revoke('A', jtiOf(token))));
  await step('revoked-between-authz-and-use', 'use-after-revoke', id, READ,
    () => planner.sendUse(planner.buildUse(token, { url: CALENDAR, method: 'GET' }, txnToken(id))));

  id = `txn-${crypto.randomUUID()}`;
  await step('revoked-after-token-released', 'ask-for-bearer-token', id, READ,
    () => planner.delegateWithWpt({ user_id: 'alice', scopes: READ, token_format: 'raw' }, txnToken(id)));
}

// Configuration B: the only Cred path that hands the provider bearer token to the agent.
{
  const planner = client('B', 'planner');
  const READ = ['calendar.readonly'];
  const id = `txn-${crypto.randomUUID()}`;
  const raw = await step('revoked-after-token-released', 'release-bearer-token', id, READ,
    () => planner.delegateWithWpt({ user_id: 'alice', scopes: READ, token_format: 'raw' }, undefined));
  const bearer = raw.body?.access_token;
  const delegationId = raw.body?.delegation_id ?? raw.body?.jti ?? null;
  if (typeof bearer !== 'string' || !delegationId) {
    console.log('FAIL release-bearer-token: no bearer token or delegation id in the answer; remaining steps not run');
    failures += 1;
  } else {
    await step('revoked-after-token-released', 'revoke', id, READ,
      async () => jsonRes(await revoke('B', delegationId)));
    // The agent now calls the provider directly with the bearer token it holds.
    await step('revoked-after-token-released', 'direct-provider-call', id, READ,
      async () => jsonRes(await fetch(`${state.provider_url}/calendar/v3/calendars/primary/events`, { headers: { authorization: `Bearer ${bearer}` } })));
  }
}

if (lines.length !== spec.steps.length) {
  console.log(`FAIL ran ${lines.length} steps, cred_p8_cases.json has ${spec.steps.length}`);
  failures += 1;
}
if (journalOut) {
  fs.mkdirSync(path.dirname(path.resolve(journalOut)), { recursive: true });
  fs.writeFileSync(journalOut, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
}
console.log(`SUMMARY steps=${lines.length} failures=${failures} cred_commit=${credCommit}`);
process.exit(failures ? 1 : 0);
