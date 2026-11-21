import assert from 'node:assert/strict';
import test from 'node:test';
import { selectedEndMessage } from './native-participant.mjs';
import { waitForViewerRelay } from './participant-transport.mjs';
import {setTimeout as delay} from 'node:timers/promises';

const selection = {selected:true, verified:true, sent:false, noSelection:false, code:0, signal:null};

test('a verified picker can close before or after the first sample', () => {
  assert.equal(selectedEndMessage(selection), 'No window or screen was shared.');
  assert.equal(selectedEndMessage({...selection, code:1, noSelection:true}), 'No window or screen was shared.');
  assert.equal(selectedEndMessage({...selection, sent:true}), 'Windows stopped sharing.');
});

const answer = {type:'answer',sdp:'v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 102\r\na=mid:0\r\n'};
const candidate = {candidate:'candidate:1 1 UDP 1 192.0.2.1 40000 typ relay',sdpMid:'0',sdpMLineIndex:0};

test('a browser answer with no matching relay candidate times out and late ICE stays fenced', async () => {
  let expired = 0;
  const wait = waitForViewerRelay('192.0.2.1',() => expired++,10);
  assert.equal(wait.receive({sdp:answer}), undefined);
  assert.equal(wait.receive({candidate:{...candidate,candidate:candidate.candidate.replace('192.0.2.1','192.0.2.2')}}),undefined);
  await delay(25);
  assert.equal(expired,1);
  assert.equal(wait.receive({candidate}),undefined);
});

test('a matched candidate or local Stop cancels the relay deadline', async () => {
  let expired = 0;
  const matched = waitForViewerRelay('192.0.2.1', () => expired++,10);
  assert.equal(matched.receive({candidate}),undefined);
  assert.ok(matched.receive({sdp:answer}));
  const stopped = waitForViewerRelay('192.0.2.1', () => expired++,10);
  stopped.cancel();
  assert.equal(stopped.receive({candidate}),undefined);
  await delay(25);
  assert.equal(expired,0);
});

test('an unverified peer, chart exit, signal, or unexpected source error stays a failure', () => {
  for (const change of [
    {verified:false}, {selected:false}, {signal:'SIGTERM'}, {code:1},
    {code:1, sent:true, noSelection:true}, {code:2, noSelection:true},
  ]) assert.equal(selectedEndMessage({...selection, ...change}), undefined);
});
