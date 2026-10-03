import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { git, assertNotProtected } from './git.js';
import { loadConfig } from '../config.js';
import { BridgeError } from '../errors.js';
import { resolvePath } from '../security/paths.js';
import { fingerprint } from '../runtime/verification.js';
import { assertIdle } from '../runtime/store.js';
import type { Workspace } from '../workspace/registry.js';
import { allows } from '../security/permissions.js';
export function gitWritePolicy(remote = false, branch?: string): void {
    const cfg = loadConfig();
    if (!allows(cfg.permission, remote ? 'git_remote' : 'git_local'))
        throw new BridgeError('PERMISSION_DENIED', `Git ${remote ? 'remote' : 'local'} mutation requires ${remote ? 'full' : 'develop'} permission.`);
    if (branch)
        assertNotProtected(branch, 'modify');
}
const digest = (buf: Buffer) => crypto.createHash('sha256').update(buf).digest('hex');
export async function exactCommit(w: Workspace, paths: string[], expected: string, message: string): Promise<{
    commit_id: string;
    branch: string;
    paths: string[];
    recovery?: string;
}> {
    gitWritePolicy();
    assertIdle(w.id);
    if (!paths.length || paths.some(p => !p.trim()))
        throw new BridgeError('INVALID_ARGUMENT', 'git_commit requires nonempty paths and expected_head from git_status.');
    if (!/^[a-f0-9]{40,64}$/.test(expected))
        throw new BridgeError('INVALID_ARGUMENT', 'expected_head must be the full HEAD object ID from git_status.');
    const names = [...new Set(paths.map(p => { const checked = resolvePath(w.root, p); const lexical = path.resolve(w.root, p); const r = { abs: lexical, rel: path.relative(w.root, lexical).split(path.sep).join('/') }; if (checked.rel === '.' || r.rel.startsWith('.git/') || fs.existsSync(r.abs) && !fs.lstatSync(r.abs).isFile() && !fs.lstatSync(r.abs).isSymbolicLink())
            throw new BridgeError('INVALID_ARGUMENT', 'Commit paths must name individual files.'); return r.rel; }))];
    const literal = names.map(p => `:(literal)${p}`);
    const ref = (await git(w.root, ['symbolic-ref', '-q', 'HEAD'])).stdout.trim();
    if (!ref.startsWith('refs/heads/'))
        throw new BridgeError('GIT_ERROR', 'Detached HEAD cannot be committed by this tool.');
    const branch = ref.slice(11);
    gitWritePolicy(false, branch);
    const head = () => git(w.root, ['rev-parse', 'HEAD']);
    if ((await head()).stdout.trim() !== expected)
        throw new BridgeError('GIT_ERROR', 'HEAD changed. Re-read git_status and review the diff.');
    const indexPath = path.resolve(w.root, (await git(w.root, ['rev-parse', '--git-path', 'index'])).stdout.trim());
    const snapshot = fs.existsSync(indexPath) ? fs.readFileSync(indexPath) : Buffer.alloc(0);
    for (const name of names) {
        const staged = await git(w.root, ['diff', '--cached', '--quiet', expected, '--', `:(literal)${name}`], { allowFail: true });
        const unstaged = await git(w.root, ['diff', '--quiet', '--', `:(literal)${name}`], { allowFail: true });
        if (staged.exitCode === 1 && unstaged.exitCode === 1)
            throw new BridgeError('GIT_ERROR', `Selected file ${name} is partially staged; inspect and decide its version in a terminal first.`);
        if ((staged.exitCode !== 0 && staged.exitCode !== 1) || (unstaged.exitCode !== 0 && unstaged.exitCode !== 1))
            throw new BridgeError('GIT_ERROR', 'Cannot inspect selected file staging.');
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-bridge-commit-'));
    const tempIndex = path.join(dir, 'index');
    const messageFile = path.join(dir, 'message');
    let commit = '';
    let advanced = false;
    let realLock: number | undefined;
    let indexLockOwned = false;
    const env = { GIT_INDEX_FILE: tempIndex };
    const cfg = loadConfig();
    const config = [`user.name=${cfg.git.authorName}`, `user.email=${cfg.git.authorEmail}`];
    try {
        await git(w.root, ['read-tree', expected], { env });
        await git(w.root, ['add', '-A', '--', ...literal], { env });
        const tree = (await git(w.root, ['write-tree'], { env })).stdout.trim();
        const oldTree = (await git(w.root, ['rev-parse', `${expected}^{tree}`])).stdout.trim();
        if (tree === oldTree)
            throw new BridgeError('GIT_ERROR', 'Requested paths have no changes to commit.');
        const selectedWorktree=await git(w.root,['diff','--quiet','--',...literal],{env,allowFail:true});
        if(selectedWorktree.exitCode!==0)throw new BridgeError('GIT_ERROR','Selected files changed while staging. Re-read and review before committing.');
        const observed = await fingerprint(w.root);
        if (!observed.complete)
            throw new BridgeError('GIT_ERROR', 'Cannot completely observe hook effects; reduce repository scan size before committing.', { hint: observed.reason });
        fs.writeFileSync(messageFile, cfg.git.commitTrailer ? `${message}\n\n${cfg.git.commitTrailer}\n` : `${message}\n`);
        for (const [hook, args] of [['pre-commit', []], ['prepare-commit-msg', [messageFile, 'message']], ['commit-msg', [messageFile]]] as Array<[
            string,
            string[]
        ]>) {
            const r = await git(w.root, ['hook', 'run', '--ignore-missing', hook, ...(args.length ? ['--', ...args] : [])], { env, config, allowFail: true });
            if (!r.ok)
                throw new BridgeError('GIT_ERROR', `${hook} failed: ${(r.stderr || r.stdout).trim()}`, { hint: 'Hook/user file changes are preserved; inspect them before retrying.' });
        }
        const after = await fingerprint(w.root);
        if (!after.complete || after.digest !== observed.digest || (await git(w.root, ['write-tree'], { env })).stdout.trim() !== tree)
            throw new BridgeError('GIT_ERROR', 'Hooks or concurrent edits changed files/index/tree. Changes preserved; re-read and review before committing.');
        if (!fs.readFileSync(messageFile, 'utf8').trim())
            throw new BridgeError('GIT_ERROR', 'Hook produced an empty commit message.');
        commit = (await git(w.root, ['commit-tree', tree, '-p', expected, '-F', messageFile], { env, config })).stdout.trim();
        // Hold the real index lock only for final publication, never while hooks execute.
        realLock = fs.openSync(`${indexPath}.lock`, 'wx');
        indexLockOwned = true;
        const current = fs.existsSync(indexPath) ? fs.readFileSync(indexPath) : Buffer.alloc(0);
        if (digest(current) !== digest(snapshot))
            throw new BridgeError('GIT_ERROR', 'Real index changed concurrently. Candidate not published; review staging.');
        if ((await git(w.root, ['symbolic-ref', '-q', 'HEAD'])).stdout.trim() !== ref || (await head()).stdout.trim() !== expected)
            throw new BridgeError('GIT_ERROR', 'Branch/HEAD changed concurrently; candidate not published.');
        const reconcile = path.join(dir, 'real-index');
        if (snapshot.length)
            fs.writeFileSync(reconcile, snapshot);
        else
            await git(w.root, ['read-tree', expected], { env: { GIT_INDEX_FILE: reconcile } });
        await git(w.root, ['reset', '-q', commit, '--', ...literal], { env: { GIT_INDEX_FILE: reconcile } });
        const finalWorktree=await git(w.root,['diff','--quiet','--',...literal],{env,allowFail:true});
        if(finalWorktree.exitCode!==0)throw new BridgeError('GIT_ERROR','Selected files changed before publication; candidate not published.');
        // Conditional ref update prevents overwriting a competing commit.
        await git(w.root, ['update-ref', '-m', `commit: ${message.split('\n')[0]}`, ref, commit, expected]);
        advanced = true;
        fs.writeFileSync(realLock, fs.readFileSync(reconcile));
        fs.closeSync(realLock);
        realLock = undefined;
        fs.renameSync(`${indexPath}.lock`, indexPath);
        indexLockOwned = false;
        const post = await git(w.root, ['hook', 'run', '--ignore-missing', 'post-commit'], { config, allowFail: true });
        return { commit_id: commit, branch, paths: names, ...(!post.ok ? { recovery: `Commit succeeded; post-commit failed: ${post.stderr}. Do not repeat git_commit.` } : {}) };
    }
    catch (e) {
        if (advanced)
            return { commit_id: commit, branch, paths: names, recovery: `Branch already updated. Do not repeat git_commit. Inspect git_status; reconcile selected index entries with git reset ${commit} -- <selected paths> in a terminal. Error: ${(e as Error).message}` };
        throw e;
    }
    finally {
        try { if (realLock !== undefined) fs.closeSync(realLock); } catch { /* Preserve the published outcome. */ }
        // Only remove a lock acquired by this operation.
        try { if (indexLockOwned) fs.rmSync(`${indexPath}.lock`, { force: true }); } catch { /* Operator can remove leftover owned lock after inspection. */ }
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* Temporary cleanup must not hide commit identity. */ }
    }
}
