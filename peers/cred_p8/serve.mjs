#!/usr/bin/env node
// Scenario P8 with real Cred on the wire (ietf127-wimse-scenario/1).
//
// Starts, on fixed loopback ports so the harness capture can see them:
//   :5065  Cred, configuration A (WIMSE, required Txn-Tokens, brokered handles only)
//   :5066  Cred, configuration B (deprecated allowRawTokens, no Txn-Tokens, read-only connection)
//   :5067  a bearer-only provider mock (accepts any bearer token, cannot introspect or revoke)
//
// The two Cred servers are Cred's own code, started through Cred's hackathon
// helper (scripts/hackathon/lib/cred.mjs) from a built checkout of
// cred-ninja/sdk. Nothing in that checkout is modified. Only this file and
// driver.mjs belong to the harness. The provider is a mock written here, with
// the same behaviour as Cred's scripts/hackathon/lib/mock-provider.mjs but on
// a fixed port; Cred's calls to https://www.googleapis.com are redirected to it
// in this process, the way Cred's own mock does it.
//
//   node peers/cred_p8/serve.mjs --cred <cred checkout> [--state <dir>]
//
// Keys and tokens for the driver are written to <state>/state.json (mode 0600),
// outside the repository and outside the evidence bundle. They are generated
// at each start and are test material only.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const arg = (name, dflt) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? dflt : process.argv[i + 1];
};
const credDir = path.resolve(arg('--cred', '.'));
const stateDir = path.resolve(arg('--state', process.env.CRED_P8_STATE ?? path.join(os.tmpdir(), 'ietf127-cred-p8-state')));
const HOST = '127.0.0.1';
const PORTS = { A: 5065, B: 5066, provider: 5067 };
const TD_B = 'domain-b.example';

const lib = (f) => import(pathToFileURL(path.join(credDir, 'scripts/hackathon/lib', f)).href);
const { witIssuer } = await lib('issuers.mjs');
const { startCred } = await lib('cred.mjs');

fs.rmSync(stateDir, { recursive: true, force: true });
fs.mkdirSync(path.join(stateDir, 'trust'), { recursive: true, mode: 0o700 });

// Bearer-only provider: any bearer token is accepted; there is no introspection and no revocation.
let providerCalls = 0;
const provider = http.createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    providerCalls += 1;
    const send = (status, obj) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(obj));
    if (!(req.headers.authorization ?? '').startsWith('Bearer ')) return send(401, { error: 'unauthorized' });
    if (!req.url.startsWith('/calendar/v3/calendars/primary/events')) return send(404, { error: 'not_found' });
    if (req.method === 'GET') return send(200, { kind: 'calendar#events', items: [{ id: 'evt1', summary: 'IETF 127 hackathon' }] });
    if (req.method === 'POST') return send(200, { id: 'evt2', status: 'confirmed' });
    return send(404, { error: 'not_found' });
  });
});
await new Promise((r) => provider.listen(PORTS.provider, HOST, r));
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  const g = 'https://www.googleapis.com';
  return url.startsWith(`${g}/`) ? realFetch(`http://${HOST}:${PORTS.provider}${url.slice(g.length)}`, init) : realFetch(input, init);
};

// Trust domain B: one WIT issuer, two workloads, one Txn-Token Service key.
const trustDir = path.join(stateDir, 'trust');
const issuerB = witIssuer(TD_B, trustDir);
const planner = issuerB.workload('/ns/agents/sa/planner');
const stranger = issuerB.workload('/ns/agents/sa/no-delegation');
const tts = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ttsKid = `${TD_B}-tts-1`;
const ttsJwks = path.join(trustDir, `${TD_B}.txn-jwks.json`);
fs.writeFileSync(ttsJwks, JSON.stringify({ keys: [{ ...tts.publicKey.export({ format: 'jwk' }), kid: ttsKid, use: 'sig', alg: 'ES256' }] }, null, 2));

const base = (port) => ({
  host: HOST,
  port,
  trustDomains: { [TD_B]: { witBundle: issuerB.bundlePath, keyUse: 'wit-svid' } },
  user: 'alice',
  agents: [
    { name: 'planner', workload: planner.subject, allowedScopes: ['calendar.readonly'] },
    { name: 'no-delegation', workload: stranger.subject },
  ],
});
const credA = await startCred({
  ...base(PORTS.A),
  txnTokens: {
    [TD_B]: {
      aud: TD_B, jwks: ttsJwks, keyUse: 'sig',
      userSubject: { claim: 'sub', pattern: '^user:([a-z0-9._-]{1,64})$' },
      scopeMap: { google: { 'calendar.read': ['calendar.readonly'], 'calendar.write': ['calendar.events'] } },
    },
  },
  connectionScopes: ['calendar.readonly', 'calendar.events'],
}, { stateDir: path.join(stateDir, 'cred-a') });
const credB = await startCred({
  ...base(PORTS.B),
  connectionScopes: ['calendar.readonly'],
}, { stateDir: path.join(stateDir, 'cred-b'), serverOptions: { allowRawTokens: true } });

const jwk = (k) => k.export({ format: 'jwk' });
const agentsOf = (c) => Object.fromEntries(Object.values(c.agents).map((a) => [a.name, { did: a.did, identity: a.identity.export() }]));
const state = {
  trust_domain: TD_B,
  provider_url: `http://${HOST}:${PORTS.provider}`,
  workloads: {
    planner: { subject: planner.subject, wit: planner.wit, privateKeyJwk: jwk(planner.privateKey) },
    'no-delegation': { subject: stranger.subject, wit: stranger.wit, privateKeyJwk: jwk(stranger.privateKey) },
  },
  tts: { aud: TD_B, kid: ttsKid, privateKeyJwk: jwk(tts.privateKey) },
  A: { baseUrl: credA.baseUrl, agentToken: credA.agentToken, agents: agentsOf(credA) },
  B: { baseUrl: credB.baseUrl, agentToken: credB.agentToken, agents: agentsOf(credB) },
};
fs.writeFileSync(path.join(stateDir, 'state.json'), JSON.stringify(state), { mode: 0o600 });

console.log(`cred-p8-stack: Cred A ${credA.baseUrl} (WIMSE, Txn-Tokens required, handles only)`);
console.log(`cred-p8-stack: Cred B ${credB.baseUrl} (allowRawTokens)`);
console.log(`cred-p8-stack: bearer-only provider mock http://${HOST}:${PORTS.provider}`);
console.log(`cred-p8-stack: cred checkout ${path.basename(credDir)}, node ${process.version}`);

let stopping = false;
const stop = async () => {
  if (stopping) return;
  stopping = true;
  console.log(`cred-p8-stack: stopping, provider calls received: ${providerCalls}`);
  await credA.close();
  await credB.close();
  provider.closeAllConnections();
  await new Promise((r) => provider.close(r));
  fs.rmSync(stateDir, { recursive: true, force: true });
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
