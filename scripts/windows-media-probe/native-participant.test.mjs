import assert from 'node:assert/strict';
import test from 'node:test';
import { selectedEndMessage } from './native-participant.mjs';

const selection = {selected:true, verified:true, sent:false, noSelection:false, code:0, signal:null};

test('a verified picker can close before or after the first sample', () => {
  assert.equal(selectedEndMessage(selection), 'No window or screen was shared.');
  assert.equal(selectedEndMessage({...selection, code:1, noSelection:true}), 'No window or screen was shared.');
  assert.equal(selectedEndMessage({...selection, sent:true}), 'Windows stopped sharing.');
});

test('an unverified peer, chart exit, signal, or unexpected source error stays a failure', () => {
  for (const change of [
    {verified:false}, {selected:false}, {signal:'SIGTERM'}, {code:1},
    {code:1, sent:true, noSelection:true}, {code:2, noSelection:true},
  ]) assert.equal(selectedEndMessage({...selection, ...change}), undefined);
});
