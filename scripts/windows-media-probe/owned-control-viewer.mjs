// The launcher binds these functions to its one top-level loopback document.
const $ = id => document.getElementById(id);
const board = $('board');
const positions = Array.from({length:32}, () => board.appendChild(document.createElement('span')));
const hex = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2,'0')).join('');
const digest = t => crypto.subtle.digest('SHA-256',new TextEncoder().encode(t));
let pc, channel, activation, verified = false, closed = false, seq = 0, heldKey, dragging = false, lastCell = '';
function end(detail) {
  if (closed) return;
  closed = true;
  activation = undefined;
  pc?.close();
  $('status').textContent = detail;
  window.closeBoard().catch(() => {});
}
function send(event) {
  if (!activation || !verified || closed || channel?.readyState !== 'open') return;
  if (channel.bufferedAmount > 4096) { end('Session ended because input was delayed.'); return; }
  try { channel.send(JSON.stringify({scope:'owned_board',activation,seq:++seq,event})); }
  catch { end('The session disconnected.'); }
}
function cell(e) {
  const rect = board.getBoundingClientRect();
  const x = Math.floor((e.clientX-rect.left)*8/rect.width);
  const y = Math.floor((e.clientY-rect.top)*4/rect.height);
  return x>=0 && y>=0 && x<8 && y<4 ? {x,y} : null;
}
board.onpointermove = e => {
  const p = cell(e);
  if (!p || !activation || lastCell === p.x+','+p.y) return;
  lastCell = p.x+','+p.y;
  send({kind:'move',...p});
};
board.onpointerdown = e => {
  const p = cell(e);
  if (!p || !activation || dragging || !e.isPrimary || e.button !== 0) return;
  board.focus();
  board.setPointerCapture(e.pointerId);
  dragging = true;
  send({kind:'button',...p,down:true});
};
board.onpointerup = e => {
  if (!dragging || !e.isPrimary) return;
  dragging = false;
  const p = cell(e);
  if (!p) { end('Pointer left the practice board.'); return; }
  send({kind:'button',...p,down:false});
};
board.onpointercancel = () => { if (dragging) end('Pointer interrupted.'); };
board.onkeydown = e => {
  if (!activation || e.ctrlKey || e.altKey || e.metaKey || !(e.key === 'Backspace' || /^[ -~]$/.test(e.key))) return;
  e.preventDefault();
  if (e.repeat || heldKey) return;
  heldKey = {code:e.code,key:e.key};
  send({kind:'key',key:e.key,down:true});
};
board.onkeyup = e => {
  if (heldKey?.code !== e.code) return;
  e.preventDefault();
  send({kind:'key',key:heldKey.key,down:false});
  heldKey = undefined;
};
board.onblur = () => { if (heldKey || dragging) end('Input focus was lost with a key or button held.'); };
$('end').onclick = () => end('Session ended.');
addEventListener('pagehide', () => end('Session ended.'));
async function start() {
  const cert = await RTCPeerConnection.generateCertificate({name:'ECDSA',namedCurve:'P-256'});
  const fp = cert.getFingerprints().find(v => v.algorithm === 'sha-256').value.replaceAll(':','').toLowerCase();
  const session = await window.boardSession();
  const commit = hex(await digest('flyw8t-sas-commit-v1|'+session+'|'+fp));
  pc = new RTCPeerConnection({certificates:[cert],iceServers:[]});
  pc.onconnectionstatechange = () => {
    if (['closed','disconnected','failed'].includes(pc.connectionState)) end('Session disconnected.');
  };
  pc.ondatachannel = async ({channel:incoming}) => {
    try {
      if (channel || incoming.label !== 'flyw8t.owned-board.v2' || !incoming.ordered ||
          incoming.maxRetransmits != null || incoming.maxPacketLifeTime != null) throw Error();
      channel = incoming;
      channel.onclose = () => end('Session ended.');
      channel.onerror = () => end('The control channel closed.');
      channel.onmessage = ({data}) => {
        if (closed) return;
        let state;
        try { state = JSON.parse(data); } catch { end('Invalid board state.'); return; }
        if (state?.phase === 'active' && typeof state.activation === 'string' &&
            /^[a-f0-9]{64}$/.test(state.activation) && (!activation || activation === state.activation)) {
          activation = state.activation;
        } else if (state?.phase !== 'waiting' || activation || Object.hasOwn(state, 'activation')) {
          end('Board authorization ended.');
          return;
        }
        $('status').textContent = activation ? 'You control the practice board.' : 'Waiting for the participant to click Allow.';
        $('typed').textContent = state.text;
        positions.forEach((el,i) => {
          el.textContent = i === state.y*8+state.x ? '●' : '';
          el.toggleAttribute('data-marked',!!state.marked && i === state.marked[1]*8+state.marked[0]);
        });
      };
      const certs = pc.sctp?.transport?.getRemoteCertificates?.();
      if (!certs?.[0]) throw Error();
      const remote = hex(await crypto.subtle.digest('SHA-256',certs[0]));
      const code = (new DataView(await digest('flyw8t-sas-v1|'+session+'|'+fp+'|'+remote)).getUint32(0)%1000000).toString().padStart(6,'0');
      if (closed) return;
      $('code').textContent = code;
      verified = true;
    } catch { end('The browser could not verify the control connection.'); }
  };
  const offer = await window.boardOffer(commit);
  if (offer.type !== 'offer' || !/^m=application .* UDP\/DTLS\/SCTP webrtc-datachannel\r?$/m.test(offer.sdp) ||
      offer.sdp.match(/^m=/gm)?.length !== 1) throw Error();
  await pc.setRemoteDescription(offer);
  await pc.setLocalDescription(await pc.createAnswer());
  if (pc.iceGatheringState !== 'complete') await new Promise(resolve => {
    pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') resolve(); };
  });
  const answer = pc.localDescription.toJSON();
  answer.sdp = answer.sdp.split('\r\n').filter(v => !v.startsWith('a=candidate:') || v.split(/\s+/)[4] === '127.0.0.1').join('\r\n');
  await window.boardAnswer(answer);
}
start().catch(() => end('Could not establish the practice session.'));
