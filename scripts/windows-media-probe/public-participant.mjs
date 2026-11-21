import { accessSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { supportOrigin } from './public-connection.mjs';
import { secureParticipantCookie } from './participant-transport.mjs';
import { nativeParticipant } from './native-participant.mjs';

const here = file => fileURLToPath(new URL(file, import.meta.url));
const binary = here('../native/flyw8t-participant.exe');
const args = process.argv.slice(2);

for (const file of ['companion.mjs','participant.html','participant-ui.css','participant-ui.js']) accessSync(here(file));
accessSync(binary);
const transport = await import('undici');
if (typeof transport.WebSocket !== 'function' || typeof transport.fetch !== 'function' ||
    typeof nativeParticipant !== 'function' || typeof secureParticipantCookie !== 'function' ||
    supportOrigin('https://localhost/') !== 'https://localhost') throw Error('The participant package is incomplete.');

if (args.length === 1 && args[0] === '--check') {
  console.log('Windows participant package ready.');
} else if (args.length || process.platform !== 'win32') {
  throw Error('Run the Windows participant from its extracted folder.');
} else {
  const worker = spawn(process.execPath, ['--use-system-ca', here('companion.mjs'), binary],
    {stdio:['ignore','inherit','inherit','ipc']});
  worker.on('message', message => {
    if (message?.type !== 'participant-ready' || !/^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(message.origin)) return;
    // The local service sends ready only after an exclusive loopback bind.
    const browser = spawn('explorer.exe', [message.origin], {stdio:'ignore', windowsHide:true});
    browser.on('error', () => console.log('Open ' + message.origin + ' on this PC.'));
  });
  worker.on('error', () => { console.error('Windows could not start the participant.'); process.exitCode = 1; });
  worker.on('exit', code => { process.exitCode = code ?? 1; });
  for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => {
    if (worker.connected) worker.disconnect();
  });
}
