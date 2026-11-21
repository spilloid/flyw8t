import http from 'node:http';
import { readFileSync, accessSync } from 'node:fs';
import { htmlText, secureParticipantCookie, waitForViewerRelay } from './participant-transport.mjs';
import { publicConnection } from './public-connection.mjs';
import { nativeParticipant } from './native-participant.mjs';

let origin;
const [pickerBinary, ...extra] = process.argv.slice(2);
if (!pickerBinary || extra.length) throw Error('Expected the Windows participant executable.');
accessSync(pickerBinary);
const files = new Map([
  ['/', ['participant.html','text/html; charset=utf-8']],
  ['/participant-ui.js', ['participant-ui.js','text/javascript; charset=utf-8']],
  ['/participant-ui.css', ['participant-ui.css','text/css; charset=utf-8']],
].map(([path,[file,type]]) => [path,{type,body:readFileSync(new URL(file,import.meta.url))}]));
const issue = (code,message) => Object.assign(Error(message),{code});
let current;
const active = s => current === s && !['ended','error'].includes(s.state);
const send = (s,message) => {
  if (s.socket?.readyState !== WebSocket.OPEN) throw issue(409,'The support server is disconnected.');
  s.socket.send(JSON.stringify(message));
};
function status(tab) {
  return sessionStatus(tab);
}
function sessionStatus(tab) {
  const s = current;
  if (s && s.tab!==tab && active(s)) return {state:'idle',busy:true,message:'Another tab owns the current session.'};
  if (!s || s.tab!==tab) return {state:'idle'};
  return {state:s.state, technician:s.technician, message:s.message, peerPresent:s.peerPresent,
    source:s.source, sas:s.state==='sharing'?s.native?.code:undefined};
}
function finish(s,state,message,notify) {
  if (!active(s)) return;
  // Fence queued events and revoke the private native pipe before other work.
  s.state=state;
  s.message=message;
  s.native?.stop();
  s.viewerRelay?.cancel();
  if (s.native) s.draining = s.native.dispose().catch(() => {});
  s.abort.abort();
  if (notify && s.socket?.readyState===WebSocket.OPEN) {
    try {send(s,notify);} catch {}
  }
  if (s.socket && s.socket.readyState<WebSocket.CLOSING) s.socket.close();

}

async function signal(s,msg) {
  if (!active(s)) return;
  if (msg.type==='ended') {
    const failed=msg.state==='connection_failed';
    finish(s,failed?'error':'ended',failed?'The video connection failed.':msg.state==='rejected'?'Sharing was declined.':'The support session ended.');
  } else if (msg.type==='error') {
    finish(s,'error','The support server declined the request.',{type:'end'});
  } else if (msg.type==='state') {
    s.peerPresent=msg.peer_present===true;
    s.upstream=msg.state;
    if (!s.approved && msg.state==='authorizing') {
      s.state='authorizing';
      s.message='Review the technician and choose what to share.';
    }
  } else if (msg.type==='signal' && s.approved && s.upstream==='connecting') {
    if (typeof msg.data?.commit==='string' && !s.native && /^[a-f0-9]{64}$/.test(msg.data.commit)) {
      s.native=nativeParticipant(pickerBinary,s.session,s.relay);
      s.stage='native-offer';
      const offer=await s.native.offer(s.session,msg.data.commit);
      if (!active(s)) return;
      s.viewerRelay=waitForViewerRelay(s.relay.allocation, () => finish(s,'error',
        'The technician’s browser did not reach the configured UDP video relay. Check its network route.',{type:'media',state:'failed'}));
      s.message='Waiting for the technician’s browser to reach the video relay.';
      send(s,{type:'signal',data:{sdp:offer,relayOnly:true}});
      void s.native.closed.then(()=>{
        if (!active(s)) return;
        if (s.native.endMessage) finish(s,'ended',s.native.endMessage,{type:'end'});
        else finish(s,'error',s.native.failureMessage ?? 'The native source ended before the support session was closed.',{type:'media',state:'failed'});
      }).catch(()=>finish(s,'error','Windows could not start the native source.',{type:'end'}));
    } else if (s.viewerRelay && !s.answered && (msg.data?.sdp?.type==='answer' || msg.data?.candidate)) {
      const answer=s.viewerRelay.receive(msg.data);
      if(!answer) return;
      s.answered=true;
      s.stage='native-answer';
      s.message='Choose a window or screen in the Windows picker.';
      await s.native.answer(answer);
      if (!active(s)) return;
      if (!s.native.sent || !s.native.code) throw Error('Missing native session evidence');
      send(s,{type:'media',state:'connected'});
      s.state='sharing';
      s.stage='sharing';
      s.message='Sharing with the technician. You can stop at any time.';
    }
  }
}

async function join(s,code) {
  const serverOrigin=s.connection.origin;
  const request=s.connection.request;
  s.stage='support-binding';
  const params={redirect:'manual',signal:AbortSignal.any([s.abort.signal,AbortSignal.timeout(10000)])};
  const bound=await request(serverOrigin+'/s',{...params,method:'POST',headers:{
    Origin:serverOrigin,'Content-Type':'application/x-www-form-urlencoded'
  },body:new URLSearchParams({code})});
  if (bound.status!==303 || bound.headers.get('location')!=='/s/session') {
    await bound.body?.cancel();
    throw issue(400,bound.status===429?'The support server limited code attempts. Try again later.':'The invitation expired, was used, or is invalid.');
  }
  const setCookies = bound.headers.getSetCookie();
  const cookie=secureParticipantCookie(setCookies);
  await bound.body?.cancel();
  if (!cookie) throw issue(502,'The support server did not bind the participant.');
  s.stage='consent-page';
  const response=await request(serverOrigin+'/s/session',{...params,headers:{Cookie:cookie}});
  if (!response.ok) {
    await response.body?.cancel();
    throw issue(502,'The consent page is unavailable.');
  }
  const chunks=[];
  let length=0;
  for await (const chunk of response.body) {
    length+=chunk.length;
    if (length>262144) throw issue(502,'The consent page is too large.');
    chunks.push(chunk);
  }
  const page=Buffer.concat(chunks).toString('utf8');
  // Match the actual server-rendered consent contract and refuse a changed shape.
  const tag=page.match(/<div\b[^>]*\bid="support"[^>]*>/i)?.[0] || '';
  const session=tag.match(/\bdata-session="([a-f0-9-]{36})"/)?.[1];
  if (!session || !tag.includes('data-role="participant"') || !tag.includes('data-state="authorizing"')) {
    throw issue(409,'This participant needs a new view-only invitation.');
  }
  const control = tag.match(/\bdata-control="([01])"/)?.[1];
  if (!control) throw issue(409,'This participant needs a new view-only invitation.');
  const who=page.match(/<p>(Requested by [^<]+)<\/p>/)?.[1];
  if (!who || who.length>1024) throw issue(502,'Technician identity could not be read from the consent page.');
  if (!active(s)) return;
  s.session=session;
  // The name can contain the same prose as the server's attribution. Display
  // the whole paragraph, with exactly one entity decode for UI textContent.
  s.technician = htmlText(who);
  // Install signaling handlers immediately after opening the socket. Relay DNS and
  // route selection may take longer than the server's initial authorization message.
  let relayError;
  if (control === '0') {
    s.stage='relay-policy';
    try { s.relay=await s.connection.relay(tag); }
    catch { relayError='This deployment needs an authenticated single-address IPv4 UDP video relay.'; }
    if (!active(s)) return;
  }
  const socket=s.connection.socket(cookie);
  s.socket=socket;
  if (control === '1' || relayError) {
    // Binding spends the invitation. Tell its technician that this participant
    // ended it, without ever approving or connecting a capture source.
    const message = relayError ?? 'This participant needs a new view-only invitation. Ask the technician to choose View screen.';
    await new Promise(resolve => {
      const settle = () => {
        clearTimeout(timeout);
        finish(s,'error',message,{type:'end'});
        resolve();
      };
      const timeout = setTimeout(settle,5000);
      socket.onopen = socket.onclose = socket.onerror = settle;
    });
    return;
  }
  s.stage='support-signaling';
  socket.onmessage=event=>{
    if (!active(s)) return;
    try { void signal(s,JSON.parse(event.data)).catch(error=>{
      const message=error.code==='RELAY_UNREACHABLE'
        ? 'The video relay did not answer over UDP. Ask the technician to check the network route.'
        : s.native?.failureMessage ?? 'The native video connection could not be verified or started.';
      finish(s,'error',message,{type:'end'});
    }); }
    catch { finish(s,'error','Invalid support message.',{type:'end'}); }
  };
  socket.onerror=socket.onclose=()=>finish(s,'error','The support server disconnected. Sharing stopped.');
}

const lease=setInterval(()=>{
  if(current && active(current) && Date.now()-current.lastSeen>10000)
    finish(current,'ended','The participant tab disconnected. Sharing stopped.',{type:'end'});
},500);
lease.unref();
async function body(req) {
  let n=0; const chunks=[];
  for await(const chunk of req) {n+=chunk.length;if(n>1024) throw issue(413,'Request too large.');chunks.push(chunk);}
  try {const value=JSON.parse(Buffer.concat(chunks).toString('utf8')); if(!value || typeof value!=='object' || Array.isArray(value)) throw Error(); return value;}
  catch {throw issue(400,'Invalid request.');}
}
const server=http.createServer(async(req,res)=>{
  const reply=(code,data,type='application/json')=>{
    res.writeHead(code,{'Content-Type':type,'Cache-Control':'no-store','Referrer-Policy':'no-referrer',
      'X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"});
    res.end(type==='application/json'?JSON.stringify(data):data);
  };
  try {
    if('http://'+req.headers.host!==origin) throw issue(403,'Invalid host.');
    const file=files.get(req.url);
    if(req.method==='GET' && file) return reply(200,file.body,file.type);
    const tab=req.headers['x-flyw8t-tab'];
    if(typeof tab!=='string' || !/^[a-f0-9]{32}$/.test(tab)) throw issue(403,'Open the local participant page.');
    if(req.method==='GET' && req.url==='/api/status') {
      if(current?.tab===tab) current.lastSeen=Date.now();
      return reply(200,status(tab));
    }
    if(req.method!=='POST' || req.headers.origin!==origin || req.headers['x-flyw8t-trial']!=='1' ||
       req.headers['content-type']!=='application/json') throw issue(403,'Use the local participant page.');
    const msg=await body(req);
    if(req.url==='/api/join') {
      if(current && active(current)) throw issue(409,'A session is already joined.');
      if (typeof msg.code!=='string' || !/^\d{9}$/.test(msg.code)) throw issue(400,'Enter the nine-digit invitation code.');
      if (Object.keys(msg).length!==2) throw issue(400,'Enter the console address and invitation code.');
      let connection;
      try { connection=await publicConnection(msg.origin); }
      catch { throw issue(400,'Enter the HTTPS address of your Flyw8t console.'); }
      if (current && active(current)) throw issue(409,'A session is already joined.');
      const s = {
        connection,
        tab, abort:new AbortController(), lastSeen:Date.now(), state:'connecting',
        message:'Checking your invitation.', draining:current?.draining,stage:'join',
      };
      current = s;
      try {
        await s.draining;
        if(active(s)) await join(s,msg.code);
      } catch(e) {
        finish(s,'error',e.code===400 || e.code===409 || e.code===502?e.message:'Could not reach the support server. Check the address, network, and HTTPS certificate.');
      }
      return reply(200,status(tab));
    }
    const s=current;
    if(!s || s.tab!==tab || !active(s)) throw issue(409,'This tab has no active session.');
    s.lastSeen=Date.now();
    if(req.url==='/api/approve') {
      if(s.state!=='authorizing' || s.approved || msg.source!=='picker')
        throw issue(409,'Select an available source for a view-only invitation first.');
      s.source=msg.source; s.approved=true; s.state='connecting';
      s.message='Connecting to the technician.';
      send(s,{type:'approve'});
    } else if(req.url==='/api/decline') {
      if(s.state!=='authorizing') throw issue(409,'There is no invitation to decline.');
      finish(s,'ended','You declined the invitation.',{type:'decline'});
    } else if(req.url==='/api/end') {
      finish(s,'ended','You ended the session.',{type:'end'});
    } else throw issue(404,'Unknown action.');
    reply(200,status(tab));
  } catch(error) {
    const known=[400,403,404,409,413,502].includes(error.code);
    reply(known?error.code:500,{error:known?error.message:'The participant request failed.'});
  }
});
server.requestTimeout=10000;
server.headersTimeout=10000;
server.listen(0,'127.0.0.1',()=>{
  origin='http://127.0.0.1:'+server.address().port;
  console.log('Local participant ready at '+origin);
  if(process.connected) process.send?.({type:'participant-ready',origin},()=>{});
});
function shutdown() {
  if(current) finish(current,'ended','The local participant closed.',{type:'end'});
  server.close();
  server.closeAllConnections();
}
for(const sig of ['SIGINT','SIGTERM']) process.on(sig,shutdown);
if (process.connected) process.once('disconnect',shutdown);
