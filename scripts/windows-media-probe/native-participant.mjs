import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';

export function selectedEndMessage({selected, verified, sent, noSelection, code, signal}) {
  if (!selected || !verified || signal) return undefined;
  if (code === 0) return sent ? 'Windows stopped sharing.' : 'No window or screen was shared.';
  if (code === 1 && noSelection && !sent) return 'No window or screen was shared.';
}

export function nativeParticipant(binary, session, relay) {
  if (!relay) throw Error('Choose a window using an authenticated relay.');
  const marker = 'selected-surface';
  let child, closed, verifiedCode, sent = false, forced = false, stopped = false;
  let reachedLimit = false, failureMessage;
  let offered = false, noSelection = false, relayUnreachable = false;
  function stop() {
    stopped = true;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    child.stdin.end();
  }
  async function dispose() {
    stop();
    if (closed && await Promise.race([closed.then(() => false), delay(2000, true)])) {
      forced = true;
      child.kill();
      await closed;
    }
  }
  return {
    get started() {return !!child;},
    get code() {return verifiedCode;},
    get sent() {return sent;},
    get stopped() {return stopped;},
    get closed() {return closed;},
    get forced() {return forced;},
    get failureMessage() {return failureMessage;},
    get endMessage() {
      if (reachedLimit && verifiedCode && child?.exitCode === 0) return "This beta session reached its two-minute sharing limit.";
      return selectedEndMessage({
        selected:true, verified:!!verifiedCode, sent, noSelection,
        code:child?.exitCode, signal:child?.signalCode,
      });
    },
    async offer(id, commit) {
      assert.equal(id, session);
      assert.ok(!child && !stopped && /^[0-9a-f]{64}$/.test(commit), 'unexpected session commitment');
      child = spawn(binary, ['--selected-window-attended-relay'], {stdio:['pipe','pipe','pipe'], windowsHide:true, timeout:180_000});
      closed = once(child, 'close');
      closed.catch(() => {});
      child.stdin.on('error', () => {});
      const lines = createInterface({input:child.stdout});
      const offer = new Promise((resolve, reject) => {
        lines.on('line', line => {
          try {
            const msg = JSON.parse(line);
            if (!offered) {
              assert.equal(msg.type, 'offer');
              const sections = msg.sdp.split(/\r?\n/);
              assert.equal(sections.filter(s => s.startsWith('m=')).length, 1);
              assert.ok(sections.some(s => s.startsWith('m=video ')));
              const candidates = sections.filter(s => s.startsWith('a=candidate:'));
              assert.ok(candidates.length && candidates.every(s => {
                const fields=s.split(/\s+/);
                return fields[2]?.toLowerCase()==='udp' && fields[4]===relay.allocation && fields[6]==='typ' && fields[7]==='relay';
              }));
              offered = true;
              resolve(msg);
            } else if (msg.type === 'peer_verified' && /^\d{6}$/.test(msg.sas)) {
              verifiedCode = msg.sas;
            }
          } catch { reject(Error('Invalid native participant response')); stop(); }
        });
        closed.then(() => {
          const error=Error('Native sender ended before its offer');
          if (relayUnreachable) error.code='RELAY_UNREACHABLE';
          reject(error);
        }, reject);
      });
      createInterface({input:child.stderr}).on('line', line => {
        if (line === 'Error: "UDP relay did not answer before the allocation deadline"')
          relayUnreachable = true;
        if (line === 'Selected-surface sharing time limit reached.') reachedLimit = true;
        if (line === 'Error: "the verified video transport disconnected"')
          failureMessage = 'The video connection to the technician disconnected. Sharing stopped.';
        if (line === 'Error: "the technician DTLS connection did not complete"')
          failureMessage = 'Both peers reached the relay, but the secure video connection did not complete.';
        if (line === 'First ' + marker + ' access unit sent.') sent = true;
        if (line === 'Error: "no desktop or window was selected"') noSelection = true;
      });
      child.stdin.write(JSON.stringify({session, commit}) + '\n');
      child.stdin.write(JSON.stringify(relay)+'\n');
      return offer;
    },
    async answer(msg) {
      assert.ok(child && offered && !stopped && msg.type === 'answer' && msg.sdp.length < 65536);
      const sdp = msg.sdp;
      child.stdin.write(JSON.stringify({type:'answer', sdp}) + '\n');
      const deadline = Date.now() + 120000;
      // The certificate result and sample marker travel on different pipes.
      while ((!sent || !verifiedCode) && !stopped && child.exitCode === null && child.signalCode === null && Date.now() < deadline) {
        await delay(20);
      }
      if (child.exitCode !== null || child.signalCode !== null) await closed;
      assert.ok(sent && verifiedCode && !stopped, 'native sender did not send a verified video sample');
    },
    stop, dispose,
  };
}
