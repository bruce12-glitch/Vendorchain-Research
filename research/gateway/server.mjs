import * as grpc from '@grpc/grpc-js';
import { connect, signers } from '@hyperledger/fabric-gateway';
import { createPrivateKey, createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { commitRecord } from './commit.mjs';

function required(name) { if (!process.env[name]) throw new Error(`${name} is required`); return process.env[name]; }
const endpoint = required('FABRIC_PEER_ENDPOINT');
const client = new grpc.Client(endpoint, grpc.credentials.createSsl(readFileSync(required('FABRIC_TLS_CERT'))),
  { 'grpc.ssl_target_name_override': required('FABRIC_PEER_HOST_ALIAS') });
const gateway = connect({ client, identity: { mspId: required('FABRIC_MSP_ID'), credentials: readFileSync(required('FABRIC_ID_CERT')) },
  signer: signers.newPrivateKeySigner(createPrivateKey(readFileSync(required('FABRIC_ID_KEY')))),
  evaluateOptions: () => ({ deadline: Date.now()+30000 }), endorseOptions: () => ({ deadline: Date.now()+60000 }),
  submitOptions: () => ({ deadline: Date.now()+60000 }), commitStatusOptions: () => ({ deadline: Date.now()+120000 }) });
const contract = gateway.getNetwork(process.env.FABRIC_CHANNEL || 'vendorchain').getContract('vendorchain');
if (process.argv[2] === 'register-key') {
  const key = JSON.parse(readFileSync(process.argv[3]));
  await contract.submitTransaction('RegisterWorkerKey', key.keyID, key.publicKey, String(key.notBefore), String(key.notAfter));
  gateway.close(); client.close();
} else {
  const secret = required('GATEWAY_TOKEN');
  if (secret.length < 32) throw new Error('GATEWAY_TOKEN must be at least 32 characters');
  const hash = s => createHash('sha256').update(s).digest();
  const server = createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (!timingSafeEqual(hash(req.headers.authorization || ''), hash('Bearer '+secret))) { res.writeHead(401).end('{}'); return; }
    if (req.method !== 'POST' || req.url !== '/records') { res.writeHead(404).end('{}'); return; }
    try {
      let bytes = 0; const chunks = [];
      for await (const chunk of req) { bytes += chunk.length; if (bytes > 20000) throw new Error('payload too large'); chunks.push(chunk); }
      const result = await commitRecord(contract, JSON.parse(Buffer.concat(chunks).toString()));
      res.writeHead(200).end(JSON.stringify(result));
    } catch {
      res.writeHead(503).end(JSON.stringify({ error: 'commit unconfirmed; reconcile the durable outbox' }));
    }
  });
  server.requestTimeout = 150000;
  server.headersTimeout = 10000;
  server.listen(Number(process.env.GATEWAY_PORT || 8091), '127.0.0.1');
  const stop = () => server.close(() => { gateway.close(); client.close(); });
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}
