import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { loadConfig } from '../config.js';
import { currentPrincipal, currentSession } from '../context.js';
import { BridgeError } from '../errors.js';
import { readState, transact } from '../fs/state.js';
import { processAlive } from '../fs/lock.js';
import { registry, type Workspace } from '../workspace/registry.js';
import { redact } from '../security/secrets.js';
import type { ExecResult } from '../exec/runner.js';
import type { Fingerprint } from './verification.js';
export interface Session {
    id: string;
    principal: string;
    workspace: string;
    root: string;
    title?: string;
    status: 'open' | 'closed';
    startedAt: string;
    closedAt?: string;
    operations: Operation[];
}
export interface Operation {
    tool: string;
    at: string;
    paths: string[];
}
export type JobState = 'running' | 'completed' | 'cancelled' | 'timed_out' | 'not_started' | 'outcome_unknown';
export interface Job {
    id: string;
    principal: string;
    workspace: string;
    root: string;
    session?: string;
    ownerPid: number;
    owner: string;
    state: JobState;
    command: string;
    cwd: string;
    startedAt: string;
    endedAt?: string;
    key?: string;
    signature: string;
    cancelRequested?: boolean;
    result?: ExecResult;
    error?: string;
    log: string;
    truncated: boolean;
    kind?: 'build' | 'test' | 'lint';
    target?: string;
    before?: Fingerprint;
    after?: Fingerprint;
}
interface State {
    busy?: Array<{
        workspace: string;
        owner: string;
        pid: number;
        token: string;
    }>;
    version: 1;
    sessions: Session[];
    jobs: Job[];
    operations: Record<string, Operation[]>;
}
const empty = (): State => ({ version: 1, sessions: [], jobs: [], operations: {} });
const valid = (s: State) => !!s && s.version === 1 && Array.isArray(s.sessions) && s.sessions.every(rec => rec && typeof rec.id === 'string' && typeof rec.principal === 'string' && typeof rec.workspace === 'string' && typeof rec.root === 'string' && ['open', 'closed'].includes(rec.status) && Array.isArray(rec.operations)) && Array.isArray(s.jobs) && s.jobs.every(j => j && typeof j.id === 'string' && typeof j.principal === 'string' && typeof j.workspace === 'string' && typeof j.root === 'string' && typeof j.log === 'string' && typeof j.ownerPid === 'number' && ['running', 'completed', 'cancelled', 'timed_out', 'not_started', 'outcome_unknown'].includes(j.state)) && !!s.operations && typeof s.operations === 'object';
const file = () => path.join(loadConfig().dataDir, 'runtime', 'records.json');
export const owner = crypto.randomUUID();
export const activeJob = (j: Job) => j.state === 'running';
function reconcile(s: State): void {
    s.busy = (s.busy ?? []).filter(b => processAlive(b.pid));
    for (const j of s.jobs)
        if (activeJob(j) && !processAlive(j.ownerPid)) {
            j.state = 'outcome_unknown';
            j.endedAt = new Date().toISOString();
            j.error = 'Owner process exited; execution outcome is unknown. No automatic retry.';
        }
    const terminal = s.jobs.filter(j => !activeJob(j)).sort((a, b) => (b.endedAt ?? b.startedAt).localeCompare(a.endedAt ?? a.startedAt));
    const keep = new Set(terminal.filter(j => Date.now() - Date.parse(j.endedAt ?? j.startedAt) < 7 * 86400000).slice(0, 100).map(j => j.id));
    s.jobs = s.jobs.filter(j => activeJob(j) || keep.has(j.id));
}
export function records(): State { const s = readState(file(), empty, valid); reconcile(s); return s; }
export function transaction<R>(fn: (s: State) => R): R { return transact(file(), empty, valid, s => { reconcile(s); return fn(s); }); }
export function authorize(record: {
    principal: string;
    workspace: string;
    root: string;
}): Workspace {
    if (record.principal !== currentPrincipal())
        throw new BridgeError('PERMISSION_DENIED', 'This record belongs to another caller.');
    const w = registry().require(record.workspace);
    if (fs.realpathSync(w.root) !== record.root)
        throw new BridgeError('PERMISSION_DENIED', 'Workspace root no longer matches the recorded root.');
    return w;
}
export function session(id: string, allowClosed = false): Session {
    const s = records().sessions.find(s => s.id === id);
    if (!s)
        throw new BridgeError('SESSION_NOT_FOUND', 'Session not found.');
    authorize(s);
    if (!allowClosed && s.status !== 'open')
        throw new BridgeError('SESSION_CLOSED', 'Session is closed. Start a new session.');
    return s;
}
export function startSession(w: Workspace, title?: string): Session {
    const s: Session = { id: crypto.randomUUID(), principal: currentPrincipal(), workspace: w.id, root: fs.realpathSync(w.root), ...(title ? { title: title.slice(0, 200) } : {}), status: 'open', startedAt: new Date().toISOString(), operations: [] };
    transaction(state => {
        if (state.sessions.length >= 1000)
            throw new BridgeError('RECORD_LIMIT', 'Session history is full (1000); archive the runtime records before creating more.');
        state.sessions.push(s);
    });
    return s;
}
export function assertIdle(workspace: string): void {
    if (records().jobs.some(j => j.workspace === workspace && activeJob(j)))
        throw new BridgeError('WORKSPACE_BUSY', 'Workspace has a running Job; wait for it or cancel it before changing checkout or closing it.');
}
export function recordOperation(w: Workspace, tool: string, paths: string[]): void {
    const sid = currentSession();
    const op: Operation = { tool, paths: paths.map(p => redact(p).slice(0, 4096)).slice(0, 100), at: new Date().toISOString() };
    transaction(s => {
        if (sid) {
            const found = s.sessions.find(s => s.id === sid);
            if (found) {
                found.operations.push(op);
                found.operations = found.operations.slice(-1000);
            }
        }
        else {
            const key = `${currentPrincipal()}:${w.id}`;
            s.operations[key] = [...(s.operations[key] ?? []), op].slice(-1000);
        }
    });
}
export function getJob(id: string): Job {
    const j = records().jobs.find(j => j.id === id);
    if (!j)
        throw new BridgeError('JOB_NOT_FOUND', 'Job not found or retention expired.');
    authorize(j);
    if (j.session)
        session(j.session, true);
    return j;
}
export function updateJob(id: string, fn: (j: Job) => void): void { transaction(s => { const j = s.jobs.find(j => j.id === id); if (j)
    fn(j); }); }
/** Reserve checkout/lifecycle mutations across bridges without holding a file lock across awaits. */
export function reserveWorkspace(workspace: string): () => void {
    const token = crypto.randomUUID();
    transaction(s => {
        if (s.jobs.some(j => j.workspace === workspace && activeJob(j)) || s.busy?.some(b => b.workspace === workspace))
            throw new BridgeError('WORKSPACE_BUSY', 'Workspace is running a Job or checkout/lifecycle operation.');
        (s.busy ??= []).push({ workspace, owner, pid: process.pid, token });
    });
    return () => transaction(s => { s.busy = (s.busy ?? []).filter(b => b.token !== token); });
}
