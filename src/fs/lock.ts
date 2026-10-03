/** Same-host, local-filesystem locks. Never execute a transaction without a lock. */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { BridgeError } from '../errors.js';
export function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (e) { return (e as NodeJS.ErrnoException).code !== 'ESRCH'; }
}
export function withFileLock<T>(target: string, fn: () => T, timeoutMs = 10_000): T {
  const dir = `${target}.lock`;
  const owner = crypto.randomUUID();
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      fs.mkdirSync(dir);
      try { fs.writeFileSync(path.join(dir, 'owner.json'), JSON.stringify({ pid: process.pid, owner })); }
      catch (e) { fs.rmSync(dir, { recursive: true, force: true }); throw e; }
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      const reaper=dir+'.reap';let reaping=false;
      try {
        fs.mkdirSync(reaper);reaping=true;
        const file = path.join(dir, 'owner.json');
        if (fs.existsSync(file)) {
          const record = JSON.parse(fs.readFileSync(file, 'utf8')) as { pid: number };
          if (Number.isInteger(record.pid) && record.pid > 0 && !processAlive(record.pid)) fs.rmSync(dir, { recursive: true, force: true });
        } else if (Date.now() - fs.statSync(dir).mtimeMs > 15_000) fs.rmSync(dir, { recursive: true, force: true });
      } catch { /* Unknown ownership: fail closed. */ }
      finally {if(reaping)fs.rmSync(reaper,{recursive:true,force:true});}

      if (Date.now() >= deadline) throw new BridgeError('LOCK_TIMEOUT', `Timed out locking ${target}; no changes were written.`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  try { return fn(); }
  finally {
    const record = JSON.parse(fs.readFileSync(path.join(dir, 'owner.json'), 'utf8')) as { owner: string };
    if (record.owner === owner) fs.rmSync(dir, { recursive: true, force: true });
  }
}
