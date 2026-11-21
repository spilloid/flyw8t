import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { fork, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { publicRelay, supportOrigin, udpTurn } from './public-connection.mjs';

const iceTag = servers => 'data-ice="' + JSON.stringify(servers).replaceAll('"', '&quot;') + '"';
const relay = {urls:['stun:example.test','turn:relay.example.test:3500?transport=udp'], username:'u', credential:'p'};

test('only a manually selected HTTPS console origin receives the invitation', () => {
  assert.equal(supportOrigin('https://Example.test:8461/'), 'https://example.test:8461');
  for (const bad of [null,'file:///a','http://example.test','https://x@other.test','https://example.test/s',
    'https://example.test/#x','https://example.test?x','https://example.test\\@other.test']) {
    assert.throws(() => supportOrigin(bad));
  }
});

test('selects authenticated UDP TURN and the corresponding local interface', async () => {
  const server = '198.51.100.7';
  const resolve = async host => { assert.equal(host,'relay.example.test'); return {address:server}; };
  const route = async (host,port) => { assert.equal(host,server); assert.equal(port,3500); return '10.0.0.2'; };
  assert.deepEqual(await publicRelay(iceTag([relay]),resolve,route),
    {bind:'10.0.0.2', server, allocation:server, port:3500, username:'u', credential:'p'});
  for (const urls of ['turns:x','stun:x','turn:host:0','turn:host?transport=tcp','turn:user@host','turn:x:65536']) {
    assert.throws(() => udpTurn(iceTag([{...relay,urls}])));
  }
  assert.throws(() => udpTurn(iceTag([{...relay,credential:''}])));
  for (const bad of ['0.0.0.0','127.0.0.1','169.254.169.254','239.0.0.1','255.255.255.255','::1']) {
    await assert.rejects(publicRelay(iceTag([relay]),async () => ({address:bad}),route));
    await assert.rejects(publicRelay(iceTag([relay]),resolve,async () => bad));
  }
});

test('portable foreground participant authenticates HTTPS and WSS and fences actions by tab and source', {timeout:20000}, async t => {
  const dir = mkdtempSync(join(tmpdir(),'flyw8t-public-participant-'));
  t.after(() => rmSync(dir, {recursive:true,force:true}));
  const key=join(dir,'key.pem'),cert=join(dir,'cert.pem');
  const openssl = process.env.OPENSSL_BIN ?? (process.platform === 'win32' ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl');
  const make=spawnSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-addext',
    'subjectAltName=IP:127.0.0.1','-days','1','-keyout',key,'-out',cert],{stdio:'ignore',windowsHide:true});
  assert.equal(make.status,0,'OpenSSL is required for the real HTTPS/WSS participant test');
  const cookie='__Host-flyw8t_support='+'x'.repeat(43);
  let upstream, mode='0', code, upgrade;
  const session=randomUUID(), seenSockets=new Set();
  const server=createServer({key:readFileSync(key),cert:readFileSync(cert)},async (req,res) => {
    if (req.method === 'POST' && req.url === '/s') {
      const parts=[]; for await (const part of req) parts.push(part);
      code=new URLSearchParams(Buffer.concat(parts).toString()).get('code');
      if (req.headers.origin !== upstream) { res.writeHead(403).end(); return; }
      res.writeHead(303,{Location:'/s/session','Set-Cookie':cookie+'; Path=/; Secure; HttpOnly; SameSite=Lax'}).end();
    } else if (req.url === '/s/session' && req.headers.cookie === cookie) {
      const ice=iceTag([{...relay,urls:'turn:10.12.34.56:3478?transport=udp'}]);
      res.end('<div id="support" data-session="'+session+'" data-role="participant" data-control="'+mode+'" data-state="authorizing" '+ice+'></div><p>Requested by Pat (support), as known to Example.</p>');
    } else res.writeHead(403).end();
  });
  server.on('connection',socket => {seenSockets.add(socket); socket.on('close',() => seenSockets.delete(socket));});
  server.on('upgrade',(req,socket) => {
    upgrade=[req.url,req.headers.origin,req.headers.cookie];
    const accept=createHash('sha1').update(req.headers['sec-websocket-key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');
    const state=Buffer.from(JSON.stringify({type:'state',state:'authorizing',peer_present:true}));
    socket.write(Buffer.concat([Buffer.from([0x81,state.length]),state]));
  });
  server.listen(0,'127.0.0.1'); await once(server,'listening');
  upstream='https://127.0.0.1:'+server.address().port;
  t.after(() => {for (const socket of seenSockets) socket.destroy(); server.close();});
  const worker=fork(new URL('./companion.mjs',import.meta.url),[process.execPath],
    {stdio:['ignore','ignore','inherit','ipc'],env:{...process.env,NODE_EXTRA_CA_CERTS:cert},execArgv:[]});
  t.after(() => { if (worker.connected) worker.disconnect(); worker.kill(); });
  const [ready]=await once(worker,'message');
  const local=ready.origin, tab='c'.repeat(32);
  async function api(path,data,owner=tab,origin=local) {
    const response=await fetch(local+'/api/'+path,{method:data?'POST':'GET',
      headers:{Origin:origin,'X-Flyw8t-Trial':'1','X-Flyw8t-Tab':owner,'Content-Type':'application/json'},body:data&&JSON.stringify(data)});
    return {status:response.status,...await response.json()};
  }
  const invitation={origin:upstream,code:'012345678'};
  assert.equal((await api('status')).state,'idle');
  assert.equal((await api('join',invitation,tab,'https://other.test')).status,403);
  assert.equal((await api('join',{...invitation,origin:upstream+'/s'})).status,400);
  mode='1';
  assert.match((await api('join',invitation)).message,/view-only/);
  assert.deepEqual(upgrade,['/api/support/participant/ws',upstream,cookie]);
  mode='0'; await api('join',invitation);
  let state;
  for (let i=0;i<100;i++) {
    state=await api('status');
    if (state.state==='authorizing' || state.state==='error') break;
    await delay(20);
  }
  assert.equal(state.state,'authorizing',state.message);
  assert.equal(code,invitation.code);
  assert.match(state.technician,/Requested by Pat/);
  assert.equal((await api('status',undefined,'b'.repeat(32))).technician,undefined);
  assert.equal((await api('approve',{source:'chart'})).status,409);
  assert.equal((await api('approve',{source:'picker'},'b'.repeat(32))).status,409);
  assert.equal((await api('decline',{})).state,'ended');
  assert.equal((await api('approve',{source:'picker'})).status,409);
});
