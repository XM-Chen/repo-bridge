import crypto from 'node:crypto';
import { currentPrincipal, currentSession, runWithContext } from '../context.js';
import { BridgeError } from '../errors.js';
import { spawnArgv, formatExecResult, smartTruncate, type ExecOptions } from '../exec/runner.js';
import { redact } from '../security/secrets.js';
import { registry, type Workspace } from '../workspace/registry.js';
import { activeJob, getJob, owner, records, transaction, updateJob, type Job } from './store.js';
import { fingerprint } from './verification.js';
const running = new Map<string, {
    abort: AbortController;
    done: Promise<void>;
}>();
let stopping = false;
const boundedWait = (seconds: number) => {
    if (!Number.isFinite(seconds) || seconds < 0 || seconds > 30)
        throw new BridgeError('INVALID_ARGUMENT', 'wait_seconds must be between 0 and 30.');
    return seconds * 1000;
};
export async function waitJob(id: string, seconds = 0): Promise<Job> {
    const until = Date.now() + boundedWait(seconds);
    let j = getJob(id);
    while (activeJob(j) && Date.now() < until) {
        await new Promise(r => setTimeout(r, Math.min(100, until - Date.now())));
        j = getJob(id);
    }
    return j;
}
export async function launchJob(w: Workspace, argv: string[], opts: ExecOptions, extra: {
    wait?: number;
    key?: string;
    kind?: Job['kind'];
    target?: string;
    signature: unknown;
}): Promise<Job> {
    boundedWait(extra.wait ?? 5);
    if (stopping)
        throw new BridgeError('NOT_STARTED', 'Service is shutting down; command not started.');
    if (extra.key && (extra.key.length > 200 || !extra.key.trim()))
        throw new BridgeError('INVALID_ARGUMENT', 'idempotency_key must be nonempty and at most 200 characters.');
    const principal = currentPrincipal();
    const sid = currentSession();
    const signature = crypto.createHash('sha256').update(JSON.stringify({ argv, cwd: opts.cwd, timeout: opts.timeoutMs, workspace: w.id, session: sid, kind: extra.kind, target: extra.target, args: extra.signature })).digest('hex');
    const result = transaction(s => {
        if (extra.key) {
            const prior = s.jobs.find(j => j.principal === principal && j.key === extra.key);
            if (prior) {
                if (prior.signature !== signature)
                    throw new BridgeError('IDEMPOTENCY_CONFLICT', 'Key already used with different arguments.');
                return { job: prior, existing: true };
            }
        }
        if (sid && !s.sessions.some(rec => rec.id === sid && rec.status === 'open' && rec.principal === principal))
            throw new BridgeError('SESSION_CLOSED', 'Session closed before Job acceptance.');
        if (s.busy?.some(b => b.workspace === w.id))
            throw new BridgeError('NOT_STARTED', 'Workspace checkout/lifecycle operation is in progress; command not started.');
        const live = s.jobs.filter(activeJob);
        if (live.length >= 4 || live.some(j => j.workspace === w.id))
            throw new BridgeError('NOT_STARTED', 'Concurrency limit reached; command has not started. Retry after a Job finishes.');
        const job: Job = { id: crypto.randomUUID(), principal, workspace: w.id, root: w.root, ...(sid ? { session: sid } : {}), ownerPid: process.pid, owner, state: 'running', command: redact(argv.join(' ')), cwd: opts.cwd, startedAt: new Date().toISOString(), signature, ...(extra.key ? { key: extra.key } : {}), ...(extra.kind ? { kind: extra.kind } : {}), ...(extra.target ? { target: redact(extra.target) } : {}), log: '', truncated: false };
        s.jobs.push(job);
        return { job, existing: false };
    });
    if (!result.existing) {
        const abort = new AbortController();
        const done = Promise.resolve().then(() => runWithContext({ principal, ...(sid ? { session: sid } : {}) }, async () => {
            let pending = '';
            let pendingBytes = 0;
            let full = false;
            let spawned = false;
            const flush = () => { if (!pending && !full)
                return; const chunk = pending; pending = ''; pendingBytes = 0; updateJob(result.job.id, j => { const left = 1024 * 1024 - Buffer.byteLength(j.log); const buf = Buffer.from(chunk); let end=Math.max(0,Math.min(left,buf.length));while(end>0&&end<buf.length&&(buf[end]!&0xc0)===0x80)end--;j.log += buf.subarray(0,end).toString('utf8'); j.truncated ||= full || buf.length > left; }); };
            let observedResult: Awaited<ReturnType<typeof spawnArgv>> | undefined;
            const poll = setInterval(() => { try {
                flush();
                const j = records().jobs.find(j => j.id === result.job.id);
                if (j?.cancelRequested)
                    abort.abort();
            }
            catch {
                abort.abort();
            } }, 200);
            try {
                if (extra.kind)
                    updateJob(result.job.id, j => { j.before = undefined; });
                const before = extra.kind ? await fingerprint(w.root) : undefined;
                if (before)
                    updateJob(result.job.id, j => { j.before = before; });
                const r = await spawnArgv(argv, { ...opts, signal: abort.signal, onSpawn: () => { spawned = true; }, maxOutputBytes: Math.min(opts.maxOutputBytes, 1024 * 1024), onOutput: text => { const size = Buffer.byteLength(text); if (pendingBytes + size <= 1024 * 1024) {
                        pending += text;
                        pendingBytes += size;
                    }
                    else
                        full = true; } });
                observedResult = r;
                flush();
                const after = extra.kind ? await fingerprint(w.root) : undefined;
                updateJob(result.job.id, j => { j.result = { ...r, command: redact(r.command) }; j.state = r.timedOut ? 'timed_out' : abort.signal.aborted ? 'cancelled' : 'completed'; j.endedAt = new Date().toISOString(); if (after)
                    j.after = after; });
                try {
                    registry().recordCommand(w.id, { command: redact(r.command), cwd: opts.cwd, exitCode: r.exitCode, durationMs: r.durationMs, at: new Date().toISOString() });
                }
                catch { /* Job result is authoritative even if legacy history fails. */ }
            }
            catch (e) {
                try {
                    try {
                        flush();
                    }
                    catch { /* still attempt final state */ }
                    updateJob(result.job.id, j => { j.state = observedResult ? (observedResult.timedOut ? 'timed_out' : abort.signal.aborted ? 'cancelled' : 'completed') : spawned ? 'outcome_unknown' : 'not_started'; if (observedResult)
                        j.result = { ...observedResult, command: redact(observedResult.command) }; j.error = redact((e as Error).message); j.endedAt = new Date().toISOString(); });
                }
                catch { /* Leave unknown on owner failure. */ }
            }
            finally {
                clearInterval(poll);
                running.delete(result.job.id);
            }
        }));
        running.set(result.job.id, { abort, done });
    }
    return waitJob(result.job.id, extra.wait ?? 5);
}
export function jobView(j: Job): object {
    const { log: _log, ...record } = j;
    return { ...record, log_bytes: Buffer.byteLength(j.log), ...(j.result ? { result: { ...j.result, stdout: smartTruncate(j.result.stdout, 60000).text, stderr: smartTruncate(j.result.stderr, 30000).text } } : {}) };
}
export function jobResult(j: Job): {
    text: string;
    data: object;
} {
    const failures = j.result && !j.result.ok ? `${j.result.stdout}\n${j.result.stderr}`.split('\n').filter(l => /FAIL|error|AssertionError|exception/i.test(l)).slice(0, 25) : [];
    return { text: `job_id: ${j.id}\nstate: ${j.state}\n${j.result ? formatExecResult({ ...j.result, stdout: smartTruncate(j.result.stdout, 60000).text, stderr: smartTruncate(j.result.stderr, 30000).text }) : j.error ?? 'Command accepted. Query job_status / job_log for progress.'}${failures.length ? '\nFAILURE LINES (extracted)\n' + failures.join('\n') : ''}`, data: jobView(j) };
}
export async function cancelJob(id: string): Promise<Job> {
    const j = getJob(id);
    if (!activeJob(j))
        return j;
    updateJob(id, j => { j.cancelRequested = true; });
    running.get(id)?.abort.abort();
    return waitJob(id, 30);
}
export async function shutdownJobs(): Promise<void> {
    stopping = true;
    for (const [id, h] of running) {
        h.abort.abort();
        try {
            updateJob(id, j => { j.cancelRequested = true; });
        }
        catch { /* termination takes precedence over record failure */ }
    }
    await Promise.all([...running.values()].map(h => h.done));
}
