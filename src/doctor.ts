import fs from 'node:fs';
import path from 'node:path';
import { loadConfig } from './config.js';
import { which, spawnArgv } from './exec/runner.js';
import { detectProject } from './workspace/detect.js';
export interface DoctorCheck {
    id: string;
    ok: boolean;
    blocking: boolean;
    problem: string;
    impact: string;
    next_step: string;
}
export async function doctor(url?: string): Promise<{
    exitCode: number;
    checks: DoctorCheck[];
}> {
    const checks: DoctorCheck[] = [];
    const add = (id: string, ok: boolean, problem: string, impact: string, next_step: string, blocking = true) => checks.push({ id, ok, blocking, problem: ok ? 'OK' : problem, impact: ok ? 'Ready' : impact, next_step: ok ? 'None' : next_step });
    let cfg;
    try {
        cfg = loadConfig();
        add('config', true, '', '', '');
    }
    catch (e) {
        add('config', false, (e as Error).message, 'Service configuration cannot load.', 'Correct the named environment variable; run doctor again.');
        return { exitCode: 1, checks };
    }
    try {
        add('node', Number(process.versions.node.split('.')[0]) >= 22, `Node ${process.version} is unsupported.`, 'Runtime may fail.', 'Install Node 22 or 24.');
        const git = which('git', process.cwd());
        const version = git ? await spawnArgv(['git', '--version'], { cwd: process.cwd(), timeoutMs: 3000, maxOutputBytes: 2000 }) : undefined;
        add('git', !!version?.ok, 'Git is missing or does not execute.', 'Git tools cannot run.', 'Install Git and add it to the service account PATH.');
        for (const [i, w] of cfg.workspaceRoots.entries()) {
            const present = fs.existsSync(w.path) && fs.statSync(w.path).isDirectory();
            add(`workspace.${i}.exists`, present, `Workspace missing: ${w.alias} (${w.path}).`, 'Workspace cannot be opened.', 'Restore the directory or correct REPO_BRIDGE_WORKSPACES.');
            if (present) {
                const profile = detectProject(w.path);
                const bins = [...new Set([...profile.build, ...profile.test, ...profile.lint].map(c => c.command.trim().split(/\s/)[0]!))];
                for (const bin of bins)
                    add(`workspace.${i}.tool.${bin}`, !!which(bin, w.path), `Required executable missing: ${bin}.`, 'Detected project checks cannot run.', 'Install its toolchain and expose it in the service account PATH.');
            }
        }
        for (const [name, dir] of [['data', cfg.dataDir], ['managed', cfg.managedRoot]] as const) {
            let ok = false;
            try {
                ok = fs.statSync(dir).isDirectory();
                fs.accessSync(dir, fs.constants.R_OK | fs.constants.W_OK);
            }
            catch { ok = false; }
            add(`directory.${name}`, ok, `Directory missing or inaccessible: ${dir}.`, 'State or managed clones cannot be stored.', 'Create the directory outside doctor and grant the service account read/write access.');
        }
        const stateFile = path.join(cfg.dataDir, 'state.json');
        if (cfg.auth.mode === 'oauth')
            add('auth.public_url', !!cfg.auth.publicUrl && cfg.auth.publicUrl.startsWith('https://'), 'OAuth public URL is missing or not HTTPS.', 'Public discovery relies on forwarded request headers and may advertise the wrong origin.', 'Set REPO_BRIDGE_PUBLIC_URL to the public HTTPS origin.', false);
        if (fs.existsSync(stateFile)) {
            let ok = false;
            try {
                const s = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
                ok = [1, 2].includes(s.version) && Array.isArray(s.workspaces);
            }
            catch { /*report*/ }
            add('state.workspace', ok, 'Workspace state is corrupt.', 'Startup/state writes are blocked to preserve the original.', 'Stop all bridges, back up the file and restore a known-good copy.');
        }
        const target = url ?? (cfg.mode === 'stdio' ? undefined : cfg.auth.publicUrl || `http://${cfg.host === '::1' ? '[::1]' : cfg.host}:${cfg.port}`);
        if (target) {
            const base = new URL(target);
            if (!['http:', 'https:'].includes(base.protocol))
                throw new Error('Doctor URL must be http(s).');
            const probe = async (p: string) => { try {
                return await fetch(new URL(p, base), { signal: AbortSignal.timeout(3000), redirect: 'error' });
            }
            catch {
                return undefined;
            } };
            const health = await probe('/health');
            add('service.health', health?.status === 200, 'Health endpoint unreachable or unhealthy.', 'Local service readiness not confirmed.', 'Check the configured URL, service process, bind address, firewall and reverse proxy.');
            const challenge = await probe('/mcp');
            const challengeOk = cfg.auth.mode === 'none' ? !!challenge && challenge.status !== 401 : challenge?.status === 401 && (cfg.auth.mode === 'path-token' || !!challenge.headers.get('www-authenticate'));
            add('service.auth_challenge', challengeOk, 'Authentication challenge does not match configuration.', 'Clients may fail authentication/discovery.', 'Check REPO_BRIDGE_AUTH and reverse proxy Authorization/WWW-Authenticate handling.');
            if (cfg.auth.mode === 'oauth') {
                for (const [id, p] of [['resource', '/.well-known/oauth-protected-resource'], ['authorization', '/.well-known/oauth-authorization-server']] as const) {
                    const r = await probe(p);
                    let ok = false;
                    try {
                        const data = await r?.json() as Record<string, unknown> | undefined;
                        ok = r?.status === 200 && !!data && (id === 'resource' ? Array.isArray(data.authorization_servers) : typeof data.authorization_endpoint === 'string' && typeof data.token_endpoint === 'string');
                    }
                    catch { /*report*/ }
                    add(`service.oauth.${id}`, ok, 'OAuth discovery metadata is missing or invalid.', 'ChatGPT discovery may fail.', 'Set a reachable public URL and route /.well-known and /oauth through the proxy.');
                }
            }
        }
        else
            add('service.health', true, '', '', '', false);
        add('chatgpt.e2e', true, '', '', '', false);
        checks[checks.length - 1]!.impact = 'Local probes do not confirm a real ChatGPT end-to-end connection.';
        return { exitCode: checks.some(c => !c.ok && c.blocking) ? 1 : 0, checks };
    }
    catch (e) {
        add('doctor.internal', false, (e as Error).message, 'Diagnosis itself could not finish.', 'Check the URL/input and filesystem errors; rerun doctor.');
        return { exitCode: 2, checks };
    }
}
export async function runDoctor(argv: string[]): Promise<number> {
    const index = argv.indexOf('--url');
    if (index >= 0 && !argv[index + 1]) {
        process.stderr.write('--url needs a URL\n');
        return 2;
    }
    const report = await doctor(index >= 0 ? argv[index + 1] : undefined);
    process.stdout.write(argv.includes('--json') ? JSON.stringify(report) + '\n' : report.checks.map(c => `${c.ok ? 'OK' : 'ISSUE'} ${c.id}: ${c.problem}\n  Impact: ${c.impact}\n  Next: ${c.next_step}`).join('\n') + '\n');
    return report.exitCode;
}
