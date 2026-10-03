import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { git, isGitRepo } from '../git/git.js';
import { isInside, resolvePath, ALWAYS_SKIP_DIRS } from '../security/paths.js';
import { isSecretPath } from '../security/secrets.js';
import { GitIgnore } from '../fs/gitignore.js';
export interface Fingerprint {
    digest: string;
    complete: boolean;
    reason?: string;
    head: string;
    files: number;
    bytes: number;
    scope: string;
}
export async function fingerprint(root: string, scope = '.'): Promise<Fingerprint> {
    const started = Date.now();
    let complete = true;
    let reason: string | undefined;
    let head = '';
    let files = 0;
    let bytes = 0;
    const hash = crypto.createHash('sha256');
    const observed: Array<{
        abs: string;
        size: number;
        mtime: number;
        ctime: number;
    }> = [];
    try {
        const base = resolvePath(root, scope, { mustExist: true, allowSecrets: true }).abs;
        let names: string[] = [];
        let statusBefore = '';
        if (isGitRepo(root)) {
            const opts = { allowFail: true, timeoutMs: 1500, maxOutputBytes: 4 * 1024 * 1024 };
            const h = await git(root, ['rev-parse', 'HEAD'], opts);
            head = h.stdout.trim();
            const st = await git(root, ['status', '--porcelain=v2', '-z', '--untracked-files=all'], opts);
            statusBefore = st.stdout;
            const ls = await git(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], opts);
            if (!ls.ok || ls.truncated || st.truncated || !st.ok) {
                complete = false;
                reason = 'Git enumeration incomplete';
            }
            names = [...new Set(ls.stdout.split('\0').filter(Boolean))].sort();
            hash.update(head).update(statusBefore);
        }
        else {
            const ig = new GitIgnore().addDirectories(ALWAYS_SKIP_DIRS);
            try {
                ig.add(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'));
            }
            catch { /* absent */ }
            const stack = [root];
            while (stack.length && names.length <= 10000 && Date.now() - started < 5000) {
                for (const e of fs.readdirSync(stack.pop()!, { withFileTypes: true })) {
                    const abs = path.join(e.parentPath, e.name);
                    const rel = path.relative(root, abs).split(path.sep).join('/');
                    if (ig.ignores(rel + (e.isDirectory() ? '/' : '')) || isSecretPath(rel))
                        continue;
                    if (e.isDirectory())
                        stack.push(abs);
                    else
                        names.push(rel);
                }
            }
            if (stack.length) {
                complete = false;
                reason = 'Enumeration resource limit';
            }
            names.sort();
        }
        for (const name of names) {
            if (!isInside(base, path.resolve(root, name)) || isSecretPath(name))
                continue;
            if (files >= 10000 || bytes >= 100 * 1024 * 1024 || Date.now() - started >= 5000) {
                complete = false;
                reason = 'Scan resource limit';
                break;
            }
            const abs = path.resolve(root, name);
            try {resolvePath(root,name,{mustExist:false});}catch(e){if((e as {code?:string}).code==='SECRET_BLOCKED')continue;complete=false;reason='Protected or outside path';continue;}
            try {
                const st = fs.lstatSync(abs);
                hash.update(name).update(String(st.mode));
                if (st.isSymbolicLink()) {
                    hash.update('link').update(fs.readlinkSync(abs));
                    files++;
                    continue;
                }
                if (!st.isFile() || !isInside(root, fs.realpathSync(abs))) {
                    complete = false;
                    reason = 'Unsupported or outside file';
                    continue;
                }
                if (bytes + st.size > 100 * 1024 * 1024) {
                    complete = false;
                    reason = 'Content resource limit';
                    break;
                }
                const buf = fs.readFileSync(abs);
                const after = fs.statSync(abs);
                if (st.size !== after.size || st.mtimeMs !== after.mtimeMs || st.ctimeMs !== after.ctimeMs) {
                    complete = false;
                    reason = 'File changed during scan';
                }
                hash.update('file').update(crypto.createHash('sha256').update(buf).digest());
                files++;
                bytes += buf.length;
                observed.push({ abs, size: after.size, mtime: after.mtimeMs, ctime: after.ctimeMs });
            }
            catch (e) {
                if ((e as NodeJS.ErrnoException).code === 'ENOENT')
                    hash.update(name).update('missing');
                else {
                    complete = false;
                    reason = 'Unreadable file';
                }
            }
        }
        for (const f of observed) {
            try {
                const st = fs.statSync(f.abs);
                if (st.size !== f.size || st.mtimeMs !== f.mtime || st.ctimeMs !== f.ctime) {
                    complete = false;
                    reason = 'Files changed during scan';
                }
            }
            catch {
                complete = false;
                reason = 'Files changed during scan';
            }
        }
        if (isGitRepo(root)) {
            const h = await git(root, ['rev-parse', 'HEAD'], { allowFail: true, timeoutMs: 1000 });
            const st = await git(root, ['status', '--porcelain=v2', '-z', '--untracked-files=all'], { allowFail: true, timeoutMs: 1000, maxOutputBytes: 4 * 1024 * 1024 });
            if (h.stdout.trim() !== head || st.stdout !== statusBefore || st.truncated) {
                complete = false;
                reason = 'Git changed during scan';
            }
        }
        if (Date.now() - started > 5000) {
            complete = false;
            reason = 'Scan time limit';
        }
    }
    catch (e) {
        complete = false;
        reason = (e as Error).message;
    }
    return { digest: hash.digest('hex'), complete, ...(reason ? { reason } : {}), head, files, bytes, scope };
}
