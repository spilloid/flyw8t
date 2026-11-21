'use strict';
const tab = crypto.randomUUID().replaceAll('-', '');
const byId = id => document.getElementById(id);
let phase = 'idle';
let busy = false;
let polling = false;
let generation = 0;
let ownsSession = false;
let actionError = '';

async function request(action, body) {
  const options = {headers:{'X-Flyw8t-Tab':tab},cache:'no-store',signal:AbortSignal.timeout(10000)};
  if (body !== undefined) {
    options.method = 'POST';
    options.headers['X-Flyw8t-Trial'] = '1';
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  const response = await fetch('/api/' + action, options);
  const data = await response.json();
  if (!response.ok) throw Error(data.error || data.message || 'The local app could not complete the request.');
  return data;
}

function render(state) {
  const next = state.busy ? 'busy' : state.state;
  if (next !== phase) actionError = '';
  phase = next;
  const pairing = ['idle','ended','error'].includes(phase);
  const authorizing = phase === 'authorizing';
  const active = phase === 'connecting' || phase === 'sharing';
  ownsSession = active || authorizing;
  byId('pair').hidden = !pairing;
  byId('approve').hidden = !authorizing;
  byId('live').hidden = !active;
  byId('who').textContent = state.technician || 'The technician';
  byId('verification').hidden = !active || !state.sas;
  byId('sas').textContent = active && state.sas ? String(state.sas).replace(/^(\d{3})(\d{3})$/,'$1 $2') : '';
  const defaultStatus = {idle:'Ready',authorizing:'Waiting for your choice.',connecting:'Connecting to the technician…',sharing:'Sharing with the technician.',ended:'Session ended.',error:'This session could not continue.',busy:'Another tab is using the local participant app.'};
  byId('status').textContent = actionError || state.message || defaultStatus[phase] || 'Waiting for the support server…';
  document.body.dataset.state = phase;
}

async function poll() {
  if (busy || polling) return;
  polling = true;
  const ticket = generation;
  try {
    const state = await request('status');
    if (ticket === generation) render(state);
  } catch {
    if (ticket === generation) byId('status').textContent = 'Connection to the local participant app lost.';
  } finally {polling=false;}
}

async function act(action, body) {
  if (busy) return;
  actionError = '';
  busy = true; generation++;
  document.querySelectorAll('button').forEach(b=>b.disabled=true);
  try {
    const state = await request(action,body);
    if (state.state) render(state);
    if (action==='join') byId('code').value='';
  } catch (error) {actionError=error.message; byId('status').textContent=actionError; return;}
  finally {busy=false; document.querySelectorAll('button').forEach(b=>b.disabled=false);}
  await poll();
}
byId('invite').onsubmit = e => {
  e.preventDefault(); const code = byId('code').value.replace(/[ -]/g,'');
  if (!/^\d{9}$/.test(code)) {actionError='Enter all nine digits.'; byId('status').textContent=actionError; return;}
  void act('join',{code,origin:byId('origin').value.trim()});
};
byId('code').oninput = () => { actionError=''; };
byId('choose').onclick = () => void act('approve',{source:'picker'});
byId('decline').onclick = () => void act('decline',{});
byId('end').onclick = () => void act('end',{});
window.addEventListener('pagehide',()=>{
  if (ownsSession) fetch('/api/end',{method:'POST',headers:{'X-Flyw8t-Tab':tab,'X-Flyw8t-Trial':'1','Content-Type':'application/json'},body:'{}',keepalive:true}).catch(()=>{});
});
poll(); setInterval(poll,1000);
