import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { resetConfigForTests, loadConfig } from '../config.js';
import { resetRegistryForTests, registry } from '../workspace/registry.js';
import { currentPrincipal, runWithContext } from '../context.js';
import { callTool, toolManifest } from '../tools/index.js';
import { readFile, writeFile, editFile } from '../fs/ops.js';
import { withFileLock } from '../fs/lock.js';
import { atomicWriteFileSync } from '../fs/atomic.js';
import { records, transaction } from '../runtime/store.js';
import { getJob } from '../runtime/store.js';
import { shutdownJobs } from '../runtime/jobs.js';
import { fingerprint } from '../runtime/verification.js';
import { parseCommand } from '../security/commands.js';
import { doctor } from '../doctor.js';
import { OAuthStore } from '../auth/oauth-store.js';
let base: string;
let root: string;
let other: string;
let workspace: string;
const oldEnv = { ...process.env };
const dist = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const git = (args: string[], cwd = root) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const data = (r: Awaited<ReturnType<typeof callTool>>) => r.structuredContent?.data as Record<string, unknown>;
const ok = async (name: string, args: Record<string, unknown> = {}) => { let r = await callTool(name, { workspace, ...args }); if (name.startsWith('run_') && args.wait_seconds !== 0 && data(r)?.state === 'running')
    r = await callTool('job_status', { job_id: data(r).id, wait_seconds: 30 }); assert.equal(r.isError, false, r.text); assert.equal(r.structuredContent?.text, r.text); return r; };
beforeEach(() => {
    base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'bridge-reliable-')));
    root = path.join(base, 'repo');
    other = path.join(base, 'other');
    fs.mkdirSync(root);
    fs.mkdirSync(other);
    Object.assign(process.env, { REPO_BRIDGE_MODE: 'stdio', REPO_BRIDGE_DATA_DIR: path.join(base, 'data'), REPO_BRIDGE_WORKSPACES: `app=${root};other=${other}`, REPO_BRIDGE_PERMISSION: 'full', REPO_BRIDGE_LOG_LEVEL: 'error' });
    delete process.env.REPO_BRIDGE_AUTH;
    delete process.env.REPO_BRIDGE_TOKEN;
    delete process.env.REPO_BRIDGE_ALLOW_NO_AUTH;
    resetConfigForTests();
    resetRegistryForTests();
    workspace = registry().openLocal('app').id;
    registry().openLocal('other');
    fs.writeFileSync(path.join(root, 'a.txt'), 'a\n');
    fs.writeFileSync(path.join(root, 'b.txt'), 'b\n');
    git(['init', '-b', 'feature']);
    git(['config', 'user.name', 'Fixture']);
    git(['config', 'user.email', 'fixture@example.test']);
    git(['add', '.']);
    git(['commit', '-m', 'base']);
});
afterEach(() => { resetConfigForTests(); resetRegistryForTests(); for (const k of Object.keys(process.env))
    if (!(k in oldEnv))
        delete process.env[k]; Object.assign(process.env, oldEnv); });
test('configuration parsing and doctor never create missing directories', async () => {
    const missing = path.join(base, 'missing-data');
    process.env.REPO_BRIDGE_DATA_DIR = missing;
    resetConfigForTests();
    loadConfig();
    assert.equal(fs.existsSync(missing), false);
    const r = await doctor();
    assert.equal(r.exitCode, 1);
    assert.ok(r.checks.find(c => c.id === 'directory.data' && !c.ok));
    assert.equal(fs.existsSync(missing), false);
});
test('doctor distinguishes invalid config and unreachable service without writes', async () => {
    const snapshot = fs.readdirSync(base);
    const r = await doctor('http://127.0.0.1:1');
    assert.equal(r.exitCode, 1);
    assert.ok(r.checks.some(c => c.id === 'service.health' && !c.ok));
    assert.deepEqual(fs.readdirSync(base), snapshot);
    process.env.REPO_BRIDGE_PERMISSION = 'invalid';
    resetConfigForTests();
    assert.equal((await doctor()).checks[0]!.id, 'config');
});
test('corrupt workspace, OAuth and runtime files are preserved and fail closed', () => {
    const state = path.join(base, 'data', 'state.json');
    fs.writeFileSync(state, '{broken');
    resetRegistryForTests();
    assert.throws(() => registry(), /preserved/);
    assert.equal(fs.readFileSync(state, 'utf8'), '{broken');
    const auth = path.join(base, 'data', 'oauth.json');
    fs.writeFileSync(auth, 'oops');
    assert.throws(() => new OAuthStore(path.dirname(auth)), /preserved/);
    assert.equal(fs.readFileSync(auth, 'utf8'), 'oops');
    const runtime = path.join(base, 'data', 'runtime', 'records.json');
    fs.mkdirSync(path.dirname(runtime));
    fs.writeFileSync(runtime, 'bad');
    assert.throws(() => records(), /preserved/);
    assert.equal(fs.readFileSync(runtime, 'utf8'), 'bad');
});
test('live owner lock is never stolen by age and timeout does not invoke callback', () => {
    const target = path.join(base, 'target');
    fs.mkdirSync(target + '.lock');
    fs.writeFileSync(path.join(target + '.lock', 'owner.json'), JSON.stringify({ pid: process.pid, owner: 'test' }));
    const old = new Date(0);
    fs.utimesSync(target + '.lock', old, old);
    let called = false;
    assert.throws(() => withFileLock(target, () => { called = true; }, 70), /Timed out/);
    assert.equal(called, false);
    assert.ok(fs.existsSync(target + '.lock'));
});
test('full revision is identical for ranges; missing/stale revisions cannot overwrite', () => {
    const version = readFile(root, 'a.txt').revision;
    assert.equal(readFile(root, 'a.txt', { startLine: 1, endLine: 1 }).revision, version);
    assert.throws(() => writeFile(root, 'a.txt', 'new', 'overwrite'), /expected_revision/);
    fs.writeFileSync(path.join(root, 'a.txt'), 'external');
    assert.throws(() => writeFile(root, 'a.txt', 'new', 'overwrite', version), /version/);
    assert.throws(() => editFile(root, 'a.txt', [{ oldString: 'external', newString: 'new' }], version), /version/);
    assert.equal(fs.readFileSync(path.join(root, 'a.txt'), 'utf8'), 'external');
});
test('atomic replacement failure preserves original and removes its temporary file', () => {
    const target = path.join(base, 'destination');
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, 'keep'), 'original');
    assert.throws(() => atomicWriteFileSync(target, 'new'));
    assert.equal(fs.readFileSync(path.join(target, 'keep'), 'utf8'), 'original');
    assert.equal(fs.readdirSync(base).some(n => n.endsWith('.tmp')), false);
});
test('generic Git reads have a narrow parameter grammar and every mutation is refused', () => {
    const p = { extraAllowed: [], denied: [], allowShell: false };
    for (const cmd of ['git status --short', 'git diff --stat', 'git log --oneline -5', 'git show HEAD:a.txt', 'git branch --list'])
        assert.doesNotThrow(() => parseCommand(cmd, p));
    for (const cmd of ['git add .', 'git commit -m x', 'git push', 'git -C elsewhere status', 'git -c alias.foo=status foo', 'git status --config-env=a=b', 'git diff --output=escape', 'git diff --ext-diff', 'git show --textconv HEAD:a.txt', 'git branch new', 'git branch -D old', 'git log --exec=x', 'git alias', 'git --git-dir=else status', 'git diff --no-index a.txt b.txt'])
        assert.throws(() => parseCommand(cmd, p), /not supported/);
});
test('explicit targets, foreign sessions, mismatched targets and closed sessions are refused', async () => {
    const s1 = data(await ok('session_start'));
    const s2 = data(await ok('session_start', { workspace: 'other' }));
    assert.equal((await callTool('write_file', { path: 'new.txt', content: 'wrong' })).isError, true);
    const mismatch = await callTool('write_file', { workspace, session_id: s2.id, path: 'new.txt', content: 'wrong' });
    assert.match(mismatch.text, /SESSION_MISMATCH/);
    assert.equal(fs.existsSync(path.join(root, 'new.txt')), false);
    await ok('write_file', { session_id: s1.id, path: 'new.txt', content: 'one' });
    await ok('write_file', { workspace: 'other', session_id: s2.id, path: 'new.txt', content: 'two' });
    assert.equal(fs.readFileSync(path.join(root, 'new.txt'), 'utf8'), 'one');
    assert.equal(fs.readFileSync(path.join(other, 'new.txt'), 'utf8'), 'two');
    await runWithContext({ principal: 'foreign' }, async () => assert.equal((await callTool('session_info', { session_id: s1.id })).isError, true));
    const info = data(await ok('session_info', { session_id: s1.id }));
    assert.equal((info.operations as unknown[]).length, 1);
    await ok('session_close', { session_id: s1.id });
    assert.equal((await callTool('read_file', { session_id: s1.id, path: 'a.txt' })).isError, true);
});
test('read_files has independent failures, shared budget and the same credential protections', async () => {
    const r = data(await ok('read_files', { files: [{ path: 'a.txt' }, { path: '.env' }, { path: '../outside' }], max_bytes: 1024 }));
    const files = r.files as Record<string, unknown>[];
    assert.equal(files.length, 3);
    assert.equal(files[0]!.revision, readFile(root, 'a.txt').revision);
    assert.ok(files[1]!.error);
    assert.ok(files[2]!.error);
    assert.equal((await callTool('read_files', { workspace, files: Array(9).fill({ path: 'a.txt' }) })).isError, true);
});
test('exact commit preserves unrelated staging and reports the published commit ID', async () => {
    fs.writeFileSync(path.join(root, 'a.txt'), 'selected\n');
    fs.writeFileSync(path.join(root, 'b.txt'), 'unrelated\n');
    git(['add', 'b.txt']);
    const old = git(['rev-parse', 'HEAD']).trim();
    const r = data(await ok('git_commit', { message: 'selected', paths: ['a.txt'], expected_head: old }));
    assert.match(String(r.commit_id), /^[a-f0-9]{40}$/);
    assert.equal(git(['show', 'HEAD:a.txt']), 'selected\n');
    assert.equal(git(['show', 'HEAD:b.txt']), 'b\n');
    assert.equal(git(['diff', '--cached', '--name-only']).trim(), 'b.txt');
});
test('partially staged selection and stale HEAD stop before changing HEAD/index', async () => {
    fs.writeFileSync(path.join(root, 'a.txt'), 'staged\n');
    git(['add', 'a.txt']);
    fs.writeFileSync(path.join(root, 'a.txt'), 'unstaged\n');
    const old = git(['rev-parse', 'HEAD']).trim();
    const index = fs.readFileSync(path.join(root, '.git', 'index'));
    assert.match((await callTool('git_commit', { workspace, message: 'bad', paths: ['a.txt'], expected_head: old })).text, /partially staged/);
    assert.equal(git(['rev-parse', 'HEAD']).trim(), old);
    assert.deepEqual(fs.readFileSync(path.join(root, '.git', 'index')), index);
    assert.match((await callTool('git_commit', { workspace, message: 'bad', paths: ['a.txt'], expected_head: '0'.repeat(40) })).text, /HEAD changed/);
});
test('commit supports deletion and literal special filenames', async () => {
    const name = 'odd [name] space.txt';
    fs.writeFileSync(path.join(root, name), 'new');
    fs.rmSync(path.join(root, 'a.txt'));
    const old = git(['rev-parse', 'HEAD']).trim();
    await ok('git_commit', { message: 'files', paths: ['a.txt', name], expected_head: old });
    assert.equal(git(['show', `HEAD:${name}`]), 'new');
    assert.equal(git(['ls-tree', '--name-only', 'HEAD']).includes('a.txt'), false);
});
function hook(name: string, contents: string): void { const file = path.join(root, '.git', 'hooks', name); fs.writeFileSync(file, '#!/bin/sh\n' + contents + '\n'); fs.chmodSync(file, 0o755); }
test('commit hooks may modify messages but file/tree changes or hook failure stop publication', async () => {
    const old = git(['rev-parse', 'HEAD']).trim();
    fs.writeFileSync(path.join(root, 'a.txt'), 'new');
    hook('commit-msg', 'echo "hook message" > "$1"');
    const r = await ok('git_commit', { message: 'input', paths: ['a.txt'], expected_head: old });
    assert.ok(data(r).commit_id);
    assert.equal(git(['log', '-1', '--format=%s']).trim(), 'hook message');
    fs.writeFileSync(path.join(root, 'a.txt'), 'next');
    const next = git(['rev-parse', 'HEAD']).trim();
    hook('pre-commit', 'echo "hook edit" > a.txt');
    assert.match((await callTool('git_commit', { workspace, message: 'blocked', paths: ['a.txt'], expected_head: next })).text, /changed files/);
    assert.equal(git(['rev-parse', 'HEAD']).trim(), next);
    assert.equal(fs.readFileSync(path.join(root, 'a.txt'), 'utf8').trim(), 'hook edit');
    hook('pre-commit', 'exit 1');
    assert.match((await callTool('git_commit', { workspace, message: 'blocked', paths: ['a.txt'], expected_head: next })).text, /pre-commit failed/);
});
test('hook HEAD races do not overwrite a competing commit', async () => {
    const old = git(['rev-parse', 'HEAD']).trim();
    fs.writeFileSync(path.join(root, 'a.txt'), 'new');
    hook('pre-commit', 'git -c core.hooksPath=/dev/null commit --allow-empty -m competing');
    const r = await callTool('git_commit', { workspace, message: 'ours', paths: ['a.txt'], expected_head: old });
    assert.equal(r.isError, true);
    assert.equal(git(['log', '-1', '--format=%s']).trim(), 'competing');
});
test('short Jobs preserve nonzero exit semantics and typed validation invalidates on external edits', async () => {
    const r = await ok('run_tests', { command: 'node -e "console.log(42)"' });
    const j = data(r);
    assert.equal(j.state, 'completed');
    assert.equal((j.result as Record<string, unknown>).exitCode, 0);
    let evidence = data(await ok('report_changes')).verification as Record<string, unknown>[];
    assert.equal(evidence[0]!.current_code, 'observed_match');
    fs.writeFileSync(path.join(root, 'a.txt'), 'external');
    evidence = data(await ok('report_changes')).verification as Record<string, unknown>[];
    assert.equal(evidence[0]!.current_code, 'unproven');
    const failed = await ok('run_tests', { command: 'node -e "process.exit(3)"' });
    assert.equal((data(failed).result as Record<string, unknown>).exitCode, 3);
});
test('during-run edits and incomplete scans never prove current validation', async () => {
    const r = await ok('run_tests', { command: `node -e "require('fs').writeFileSync('a.txt','changed')"` });
    const j = data(r);
    assert.notEqual((j.before as Record<string, unknown>).digest, (j.after as Record<string, unknown>).digest);
    const evidence = data(await ok('report_changes')).verification as Record<string, unknown>[];
    assert.equal(evidence[0]!.current_code, 'unproven');
    fs.writeFileSync(path.join(root, 'huge.bin'), Buffer.alloc(100 * 1024 * 1024 + 1));
    const f = await fingerprint(root);
    assert.equal(f.complete, false);
    assert.match(f.reason ?? '', /limit/);
});
test('long Jobs survive response loss, replay idempotently, refuse mismatched replay and block checkout/session close', async () => {
    const s = data(await ok('session_start'));
    const args = { session_id: s.id, command: 'node -e "setTimeout(()=>console.log(42),800)"', wait_seconds: 0, idempotency_key: 'long' };
    const r = data(await ok('run_command', args));
    assert.equal(r.state, 'running');
    const replay = data(await ok('run_command', args));
    assert.equal(replay.id, r.id);
    assert.match((await callTool('run_command', { workspace, ...args, command: 'node -e "console.log(1)"' })).text, /IDEMPOTENCY_CONFLICT/);
    assert.match((await callTool('git_branch', { workspace, name: 'blocked', create: true })).text, /WORKSPACE_BUSY/);
    assert.match((await callTool('session_close', { session_id: s.id })).text, /SESSION_BUSY/);
    assert.match((await callTool('workspace_close', { workspace })).text, /WORKSPACE_BUSY/);
    assert.match((await callTool('run_command', { workspace, command: 'node -e "console.log(1)"' })).text, /NOT_STARTED/);
    const final = data(await ok('job_status', { job_id: r.id, wait_seconds: 5 }));
    assert.equal(final.state, 'completed');
    assert.equal((data(await ok('job_log', { job_id: r.id }))).text, '42\n');
});
test('split chunks and multiline credentials are redacted before logs or final output persist', async () => {
    const code = `process.stdout.write('ghp_12345678');setTimeout(()=>{console.log('901234567890');console.log('-----BEGIN PRIVATE KEY-----');console.log('hidden-value');console.log('-----END PRIVATE KEY-----');console.log('API_TOKEN=');console.log('multiline-secret')},100)`;
    fs.writeFileSync(path.join(root, 'secret.cjs'), code);
    const j = data(await ok('run_command', { command: 'node secret.cjs' }));
    const serialized = JSON.stringify(records());
    assert.equal(serialized.includes('ghp_12345678901234567890'), false);
    assert.equal(getJob(String(j.id)).log.includes('hidden-value'), false);
    assert.equal(String(j.log).includes('multiline-secret'), false);
    assert.equal(JSON.stringify(j.result).includes('hidden-value'), false);
});
test('timeout and cancellation wait for real process tree termination', async () => {
    const timed = data(await ok('run_command', { command: 'node -e "setTimeout(()=>{},10000)"', timeout_seconds: 1 }));
    assert.equal(timed.state, 'timed_out');
    const script = path.join(root, 'tree.cjs');
    fs.writeFileSync(script, `const c=require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)']);console.log(c.pid);setInterval(()=>{},1000)`);
    const j = data(await ok('run_command', { command: 'node tree.cjs', wait_seconds: 0 }));
    await new Promise(r => setTimeout(r, 500));
    const log = data(await ok('job_log', { job_id: j.id }));
    const pid = Number(String(log.text).trim());
    assert.ok(pid > 0);
    const cancelled = data(await ok('job_cancel', { job_id: j.id }));
    assert.equal(cancelled.state, 'cancelled');
    assert.throws(() => process.kill(pid, 0));
});
test('logs are capped and log cursors accurately report remaining output', async () => {
    const initial = data(await ok('run_command', { command: `node -e "for(let i=0;i<40000;i++)console.log('abcdefghijklmnopqrstuvwxyz0123456789')"`, wait_seconds: 0 }));
    const j = data(await ok('job_status', { job_id: initial.id, wait_seconds: 30 }));
    assert.ok(Buffer.byteLength(String(j.log)) <= 1024 * 1024);
    assert.equal(getJob(String(j.id)).truncated, true);
    const r = data(await ok('job_log', { job_id: j.id, max_bytes: 1024 }));
    assert.equal(r.next_cursor, 1024);
    assert.equal(r.more, true);
});
function childScript(code: string): Promise<string> { return new Promise((resolve, reject) => { const c = spawn(process.execPath, ['--input-type=module', '-e', code], { env: { ...process.env }, stdio: ['ignore', 'pipe', 'pipe'] }); let out = ''; let err = ''; c.stdout.on('data', b => out += b); c.stderr.on('data', b => err += b); c.on('error', reject); c.on('close', code => code === 0 ? resolve(out) : reject(new Error(err || out))); }); }
const moduleUrl = (rel: string) => JSON.stringify(pathToFileURL(path.join(dist, rel)).href);
test('cross-process querying/cancellation notifies the owning bridge', async () => {
    const j = data(await ok('run_command', { command: 'node -e "setInterval(()=>{},1000)"', wait_seconds: 0 }));
    const code = `const {callTool}=await import(${moduleUrl('tools/index.js')});const r=await callTool('job_cancel',{job_id:${JSON.stringify(j.id)}});console.log(JSON.stringify(r));`;
    const text = await childScript(code);
    assert.match(text, /cancelled/);
    assert.equal(data(await ok('job_status', { job_id: j.id })).state, 'cancelled');
});
test('two bridge processes competing to overwrite one revision preserve one winner', async () => {
    const rev = readFile(root, 'a.txt').revision;
    const script = (content: string) => `const {writeFile}=await import(${moduleUrl('fs/ops.js')});try {writeFile(${JSON.stringify(root)},'a.txt',${JSON.stringify(content)},'overwrite',${JSON.stringify(rev)});console.log('won')}catch(e){console.log(e.code)}`;
    const results = await Promise.all([childScript(script('one')), childScript(script('two'))]);
    assert.equal(results.filter(r => r.includes('won')).length, 1);
    assert.equal(results.filter(r => r.includes('REVISION_CONFLICT')).length, 1);
});
test('abrupt owner death leaves unknown records without adoption or automatic rerun', async () => {
    const file = path.join(root, 'marker');
    const code = `const {callTool}=await import(${moduleUrl('tools/index.js')});const r=await callTool('run_command',{workspace:${JSON.stringify(workspace)},command:'node -e "console.log(1)"',wait_seconds:0});console.log(JSON.stringify(r));process.exit(0);`;
    const text = await childScript(code);
    const j = JSON.parse(text.trim()).structuredContent.data;
    const result = data(await ok('job_status', { job_id: j.id }));
    assert.equal(result.state, 'outcome_unknown');
    assert.equal(fs.existsSync(file), false);
});
test('global concurrency limit is shared across bridges and never starts rejected commands', async () => {
    transaction(s => { for (let i = 0; i < 4; i++)
        s.jobs.push({ id: `fixture-${i}`, principal: currentPrincipal(), workspace: `different-${i}`, root, ownerPid: process.pid, owner: 'fixture', state: 'running', command: 'fixture', cwd: root, startedAt: new Date().toISOString(), signature: 'fixture', log: '', truncated: false }); });
    const r = await callTool('run_command', { workspace, command: 'node -e "require(\'fs\').writeFileSync(\'rejected\',\'bad\')"' });
    assert.match(r.text, /NOT_STARTED/);
    assert.equal(fs.existsSync(path.join(root, 'rejected')), false);
});
test('every tool publishes a matching structured envelope schema and annotations', async () => {
    for (const t of toolManifest()) {
        assert.deepEqual(t.outputSchema.required, ['text', 'status']);
        assert.equal(typeof t.annotations, 'object');
    }
    const r = await callTool('unknown', {});
    assert.equal(r.structuredContent?.status, 'not_started');
    assert.equal(r.structuredContent?.text, r.text);
});
test('graceful Job manager shutdown confirms cancellation before returning', async () => {
    const j = data(await ok('run_command', { command: 'node -e "setInterval(()=>{},1000)"', wait_seconds: 0 }));
    await shutdownJobs();
    assert.equal(data(await ok('job_status', { job_id: j.id })).state, 'cancelled');
});
test('permission tightening rejects generic/dedicated writes and protected commits before any operation', async () => {
    const old = git(['rev-parse', 'HEAD']).trim();
    fs.writeFileSync(path.join(root, 'a.txt'), 'new');
    process.env.REPO_BRIDGE_PERMISSION = 'edit';
    resetConfigForTests();
    assert.equal((await callTool('git_commit', { workspace, message: 'bad', paths: ['a.txt'], expected_head: old })).isError, true);
    assert.equal((await callTool('run_command', { workspace, command: 'git add .' })).isError, true);
    assert.equal(git(['diff', '--cached', '--name-only']).trim(), '');
    assert.equal(git(['rev-parse', 'HEAD']).trim(), old);
    assert.equal((await callTool('repo_open_remote', { repository: path.join(base, 'never-cloned') })).isError, true);
    process.env.REPO_BRIDGE_PERMISSION = 'full';
    resetConfigForTests();
    git(['branch', '-m', 'main']);
    assert.match((await callTool('git_commit', { workspace, message: 'bad', paths: ['a.txt'], expected_head: old })).text, /PROTECTED_BRANCH/);
    assert.equal(git(['rev-parse', 'HEAD']).trim(), old);
});
test('post-publication index failure returns the commit ID and prevents duplicate-commit guidance', async () => {
    fs.writeFileSync(path.join(root, 'a.txt'), 'new');
    const old = git(['rev-parse', 'HEAD']).trim();
    const rename = fs.renameSync;
    fs.renameSync = ((src: fs.PathLike, dest: fs.PathLike) => { if (String(dest) === path.join(root, '.git', 'index'))
        throw new Error('simulated index replacement failure'); return rename(src, dest); }) as typeof fs.renameSync;
    let r;
    try {
        r = await ok('git_commit', { message: 'published', paths: ['a.txt'], expected_head: old });
    }
    finally {
        fs.renameSync = rename;
    }
    assert.equal(data(r).commit_id, git(['rev-parse', 'HEAD']).trim());
    assert.notEqual(data(r).commit_id, old);
    assert.match(r.text, /Do not repeat git_commit/);
    assert.match(r.text, /reconcile/);
});
test('post-commit hook failure retains the successful commit and its recovery information', async () => {
    fs.writeFileSync(path.join(root, 'a.txt'), 'new');
    hook('post-commit', 'exit 1');
    const r = await ok('git_commit', { message: 'published', paths: ['a.txt'], expected_head: git(['rev-parse', 'HEAD']).trim() });
    assert.equal(data(r).commit_id, git(['rev-parse', 'HEAD']).trim());
    assert.match(r.text, /post-commit failed/);
});
test('doctor probes health/OAuth/challenges without registering a client or writing files', async () => {
    const visited: string[] = [];
    const server = createServer((req, res) => { visited.push(`${req.method} ${req.url}`); res.setHeader('Content-Type', 'application/json'); if (req.url === '/health') {
        res.end('{"status":"ok"}');
    }
    else if (req.url === '/mcp') {
        res.statusCode = 401;
        res.setHeader('WWW-Authenticate', 'Bearer resource_metadata="/metadata"');
        res.end('{}');
    }
    else if (req.url === '/.well-known/oauth-protected-resource') {
        res.end('{"authorization_servers":["https://test"]}');
    }
    else if (req.url === '/.well-known/oauth-authorization-server') {
        res.end('{"authorization_endpoint":"https://test/auth","token_endpoint":"https://test/token"}');
    }
    else {
        res.statusCode = 404;
        res.end('{}');
    } });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    process.env.REPO_BRIDGE_AUTH = 'oauth';
    process.env.REPO_BRIDGE_TOKEN = 'test-passphrase-0123456789';
    resetConfigForTests();
    const snapshot = fs.readdirSync(path.join(base, 'data'));
    try {
        const r = await doctor(`http://127.0.0.1:${(server.address() as {
            port: number;
        }).port}`);
        assert.ok(r.checks.find(c => c.id === 'service.health')?.ok);
        assert.ok(r.checks.find(c => c.id === 'service.auth_challenge')?.ok);
        assert.ok(r.checks.find(c => c.id === 'service.oauth.resource')?.ok);
        assert.ok(r.checks.find(c => c.id === 'service.oauth.authorization')?.ok);
        assert.deepEqual(fs.readdirSync(path.join(base, 'data')), snapshot);
        assert.ok(visited.every(v => v.startsWith('GET ')));
        assert.ok(!visited.some(v => v.includes('register')));
    }
    finally {
        await new Promise<void>(r => server.close(() => r()));
    }
});

test('real stdio service EOF gracefully terminates its accepted Job and saves the outcome', async () => {
    fs.writeFileSync(path.join(root, 'shutdown.cjs'), `console.log(process.pid);setInterval(()=>{},1000)`);
    const child = spawn(process.execPath, [path.join(dist, 'index.js'), '--stdio'], { env: { ...process.env }, stdio: ['pipe', 'pipe', 'pipe'] });
    const responses = new Map<number, (value: Record<string, unknown>) => void>();
    let buffer = '';
    child.stdout.on('data', chunk => {
        buffer += String(chunk);
        for (;;) {
            const newline = buffer.indexOf('\n');
            if (newline < 0) break;
            const line = buffer.slice(0, newline); buffer = buffer.slice(newline + 1);
            const value = JSON.parse(line) as Record<string, unknown>;
            if (typeof value.id === 'number') responses.get(value.id)?.(value);
        }
    });
    let requestId = 0;
    const request = (method: string, params: object): Promise<Record<string, unknown>> => new Promise((resolve, reject) => {
        const id = ++requestId;
        const timer = setTimeout(() => reject(new Error('stdio response timed out')), 15000);
        responses.set(id, value => { clearTimeout(timer); resolve(value); });
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
    const exit = new Promise<void>(resolve => child.once('exit', () => resolve()));
    try {
        await request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'shutdown-test', version: '2.0.0' } });
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
        const response = await request('tools/call', { name: 'run_command', arguments: { workspace, command: 'node shutdown.cjs', wait_seconds: 0 } });
        const result = response.result as { structuredContent: { data: { id: string; state: string } } };
        const jobId = result.structuredContent.data.id;
        assert.equal(result.structuredContent.data.state, 'running');
        await new Promise(resolve => setTimeout(resolve, 500));
        const pid = Number(getJob(jobId).log.trim()); assert.ok(pid > 0);
        child.stdin.end();
        await Promise.race([exit, new Promise<never>((_, reject) => { const timer = setTimeout(() => reject(new Error('shutdown did not finish')), 10000); timer.unref(); })]);
        assert.equal(getJob(jobId).state, 'cancelled'); assert.throws(() => process.kill(pid, 0));
    } finally { child.kill(); }
});
