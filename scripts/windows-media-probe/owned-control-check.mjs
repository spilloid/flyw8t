import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const cwd = fileURLToPath(new URL('.',import.meta.url));
function artifact(task) {
  const args = [task,'--locked','--example','owned-control','--features','owned-board','--message-format=json'];
  const built = spawnSync('cargo',args,{cwd,encoding:'utf8',stdio:['ignore','pipe','inherit'],maxBuffer:32*1024*1024});
  if (built.error) throw built.error;
  let executable;
  for (const line of built.stdout.split(/\r?\n/)) {
    if (!line.startsWith('{')) { if (line) console.log(line); continue; }
    const row = JSON.parse(line);
    if (row.reason === 'compiler-message') process.stderr.write(row.message.rendered ?? '');
    if (row.reason === 'compiler-artifact' && row.target.name === 'owned-control' &&
        row.profile.test === (task === 'test') && row.executable) executable = row.executable;
  }
  assert.equal(built.status,0,'cargo '+task+' failed');
  assert.ok(executable,'cargo did not report its '+task+' executable');
  return executable;
}
const program = artifact('build');
const test = artifact('test');
const check = spawnSync(process.execPath,['owned-control.mjs',program,'--check',test],{cwd,stdio:'inherit'});
if (check.error) throw check.error;
process.exitCode = check.status ?? 1;
