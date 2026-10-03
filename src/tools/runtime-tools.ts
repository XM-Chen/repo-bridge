import { currentPrincipal } from '../context.js';
import { BridgeError } from '../errors.js';
import { registry } from '../workspace/registry.js';
import { activeJob, authorize, getJob, records, session, startSession, transaction } from '../runtime/store.js';
import { cancelJob, jobResult, jobView, waitJob } from '../runtime/jobs.js';
import { type ToolDef } from './types.js';
const str = { type: 'string' };
const def = (name: string, description: string, properties: Record<string, unknown>, required: string[], handler: ToolDef['handler']): ToolDef => ({ name, description, capability: 'read', inputSchema: { type: 'object', properties, required }, handler });
export const runtimeTools: ToolDef[] = [
    def('session_start', 'Start an explicit caller-owned session bound to a workspace.', { workspace: str, title: str }, ['workspace'], async (a) => { const s = startSession(registry().require(a.str('workspace')), a.optStr('title')); return { text: `session_id: ${s.id}\nworkspace: ${s.workspace}\nstatus: ${s.status}`, data: s }; }),
    def('session_list', 'List your sessions; history is retained after close.', { workspace: str, status: { type: 'string', enum: ['open', 'closed'] } }, [], async (a) => {
        const w = a.optStr('workspace') ? registry().require(a.str('workspace')) : undefined;
        const list = records().sessions.filter(s => s.principal === currentPrincipal() && (!w || s.workspace === w.id) && (!a.optStr('status') || s.status === a.str('status'))).filter(s => { try {
            authorize(s);
            return true;
        }
        catch {
            return false;
        } });
        return { text: list.map(s => `${s.id} ${s.status} ${s.title ?? ''} ${s.workspace}`).join('\n') || 'No sessions.', data: { sessions: list } };
    }),
    def('session_info', 'Session details, operation history and Jobs with typed validation evidence.', { session_id: str }, ['session_id'], async (a) => { const s = session(a.str('session_id'), true); const jobs = records().jobs.filter(j => j.session === s.id); return { text: `session_id: ${s.id}\nstatus: ${s.status}\noperations: ${s.operations.length}\nJobs: ${jobs.map(j => `${j.id} ${j.state}`).join(', ') || 'none'}`, data: { ...s, jobs: jobs.map(jobView) } }; }),
    def('session_close', 'Close a session; refuses while it has running Jobs.', { session_id: str }, ['session_id'], async (a) => { const s = session(a.str('session_id')); transaction(state => { if (state.jobs.some(j => j.session === s.id && activeJob(j)))
        throw new BridgeError('SESSION_BUSY', 'Cancel or wait for running Jobs first.'); const rec = state.sessions.find(x => x.id === s.id)!; rec.status = 'closed'; rec.closedAt = new Date().toISOString(); }); return `closed session ${s.id}`; }),
    def('job_list', 'Find your Jobs after reconnecting. Filter by workspace or session.', { workspace: str, session_id: str }, [], async (a) => { const w = a.optStr('workspace') ? registry().require(a.str('workspace')) : undefined; const sid = a.optStr('session_id'); if (sid)
        session(sid, true); const list = records().jobs.filter(j => j.principal === currentPrincipal() && (!w || j.workspace === w.id) && (!sid || j.session === sid)).filter(j => { try {
        authorize(j);
        return true;
    }
    catch {
        return false;
    } }); return { text: list.map(j => `${j.id} ${j.state} ${j.command}`).join('\n') || 'No Jobs.', data: { jobs: list.map(j => ({ job_id: j.id, workspace: j.workspace, session_id: j.session, state: j.state, command: j.command, started_at: j.startedAt, ended_at: j.endedAt, exit_code: j.result?.exitCode ?? null })) } }; }),
    def('job_status', 'Query a caller-owned Job or wait up to 30 seconds for its completion.', { job_id: str, wait_seconds: { type: 'number', minimum: 0, maximum: 30 } }, ['job_id'], async (a) => jobResult(await waitJob(a.str('job_id'), a.num('wait_seconds', 0)))),
    def('job_log', 'Read bounded incremental redacted output. Cursor is a UTF-8 byte offset.', { job_id: str, cursor: { type: 'integer', minimum: 0 }, max_bytes: { type: 'integer', minimum: 1, maximum: 131072 } }, ['job_id'], async (a) => {
        const j = getJob(a.str('job_id'));
        const buf = Buffer.from(j.log);
        const cursor = a.num('cursor', 0);
        const max = a.num('max_bytes', 65536);
        if (!Number.isInteger(cursor) || cursor < 0 || cursor > buf.length || !Number.isInteger(max) || max < 1 || max > 131072)
            throw new BridgeError('INVALID_ARGUMENT', 'Invalid cursor/max_bytes.');
        let end = Math.min(buf.length, cursor + max);
        while (end > cursor && end < buf.length && (buf[end]! & 0xc0) === 0x80)
            end--;
        if (cursor < buf.length && (buf[cursor]! & 0xc0) === 0x80)
            throw new BridgeError('INVALID_ARGUMENT', 'Cursor must be a UTF-8 boundary.');
        const text = buf.subarray(cursor, end).toString('utf8');
        return { text: `cursor: ${cursor} → ${end}; truncated: ${j.truncated}; more: ${end < buf.length}\n${text}`, data: { job_id: j.id, text, cursor, next_cursor: end, truncated: j.truncated, more: end < buf.length, state: j.state } };
    }),
    { ...def('job_cancel', 'Request process-tree termination; cancelled is reported only after confirmed exit.', { job_id: str }, ['job_id'], async (a) => jobResult(await cancelJob(a.str('job_id')))), capability: 'exec', sideEffecting: true },
];
