/**
 * Introspection tools.
 *
 * bridge_status lets the model discover its own limits instead of discovering
 * them by hitting an error mid-task; report_changes produces the end-of-task
 * summary a reviewer actually needs (what changed, what was verified, what is
 * still open) from recorded facts rather than from the model's recollection.
 */
import { records, session } from '../runtime/store.js';
import { fingerprint } from '../runtime/verification.js';
import { currentPrincipal, currentSession } from '../context.js';
import { loadConfig, describeLevel } from '../config.js';
import { describeAuthMode } from '../auth/index.js';
import { allowedCommands } from '../security/commands.js';
import { capabilityMatrix } from '../security/permissions.js';
import { forgeConfigured } from '../forge/forge.js';
import { currentBranch, getStatus, isGitRepo, log as gitLog, git } from '../git/git.js';
import { registry } from '../workspace/registry.js';
import { block, bullets, join, kv, type ToolDef } from './types.js';

export const statusTools: ToolDef[] = [
  {
    name: 'bridge_status',
    description:
      'What this bridge is allowed to do: permission level, which capabilities are enabled, which executables may run, timeouts and output limits, protected branches, and whether GitHub/GitLab tokens are configured. Check this when a tool is refused, or before planning work that needs to push.',
    capability: 'read',
    inputSchema: { type: 'object', properties: {} },
    handler: async () => {
      const cfg = loadConfig();
      const reg = registry();
      const active = reg.active();
      const caps = capabilityMatrix(cfg.permission);

      return join(
        block('PERMISSION', [
          `level: ${cfg.permission}`,
          describeLevel(cfg.permission),
          ...Object.entries(caps).map(([k, v]) => `${v ? '✓' : '✗'} ${k}`),
        ]),
        block('ACTIVE WORKSPACE', [
          ...(active
            ? kv({ alias: active.alias, root: active.root, kind: active.kind, task: active.task })
            : ['none — call workspace_open or repo_open_remote']),
        ]),
        block('EXECUTION', [
          ...kv({
            shell: cfg.exec.allowShell ? 'enabled (operator override)' : 'disabled — commands run as argv, no pipes/&&/redirects',
            timeout: `${Math.round(cfg.exec.timeoutMs / 1000)}s`,
            max_output: `${Math.round(cfg.exec.maxOutputBytes / 1024)} KB per stream (error lines preserved when truncated)`,
            denied: cfg.exec.deniedCommands,
          }),
          `allowed executables: ${allowedCommands({
            extraAllowed: cfg.exec.extraAllowedCommands,
            denied: cfg.exec.deniedCommands,
            allowShell: cfg.exec.allowShell,
          }).join(' ')}`,
        ]),
        block('TRANSPORT & AUTH', [
          ...kv({
            mode: cfg.mode,
            authentication: cfg.mode === 'stdio' ? 'stdio — inherited from the host process' : describeAuthMode(),
          }),
          'Authentication decides who may connect. It does NOT affect the permission level above.',
        ]),
        block('GIT & FORGE', [
          ...kv({
            protected_branches: cfg.git.protectedBranches,
            commit_author: `${cfg.git.authorName} <${cfg.git.authorEmail}>`,
            github_token: forgeConfigured('github') ? 'configured' : 'not configured',
            gitlab_token: forgeConfigured('gitlab') ? 'configured' : 'not configured',
          }),
        ]),
        block('SAFETY', [
          'Credential files (.env, *.pem, ~/.ssh, cloud config) are never returned by read/search tools.',
          'Paths are confined to the active workspace; symlinks leaving it are not followed.',
          'Destructive commands (force push, reset --hard, recursive delete, publish, prune) require confirm=true.',
          'Secrets are redacted from command output and logs.',
        ]),
      );
    },
  },

  {
    name: 'report_changes',
    description:
      'Summarise everything done in this workspace: files changed (with per-file line counts from git), commands run and whether they passed, git operations, current branch and commit state. Use this to write an accurate final report instead of relying on memory — and to see what is still uncommitted.',
    capability: 'read',
    inputSchema: {
      type: 'object',
      properties: {
        workspace: { type: 'string', description: 'Workspace alias or ID. Reads may use the active workspace; mutations/execution require workspace or session_id.' },
        against: { type: 'string', description: 'Compare against this ref for the file summary (e.g. "develop"). Default: HEAD (uncommitted changes only).' },
      },
    },
    handler: async (args) => {
      const reg = registry();
      const w = reg.require(args.optStr('workspace'));
      const legacy=reg.changeLog(w.id);
      const sid=currentSession();const state=records();
      const ops=sid?session(sid).operations:state.operations[`${currentPrincipal()}:${w.id}`]??[];
      const files: typeof legacy.files={};
      for(const op of ops) for(const p of op.paths) files[p]={action:op.tool==='delete_path'?'deleted':op.tool==='move_path'?'moved':'modified',count:(files[p]?.count??0)+1,lastAt:op.at};
      const changeLog={...legacy,files,...(sid?{startedAt:session(sid).startedAt}:{}),commands:[] as typeof legacy.commands,git:legacy.git};
      const against = args.optStr('against');

      let gitSection = '';
      if (isGitRepo(w.root)) {
        const status = await getStatus(w.root);
        const branch = await currentBranch(w.root);
        const stat = await git(w.root, ['diff', '--stat', against ? `${against}...HEAD` : 'HEAD'], { allowFail: true });
        const commits = against ? await gitLog(w.root, 20, `${against}..HEAD`) : [];

        gitSection = join(
          block('GIT', [
            ...kv({
              branch,
              upstream: status.upstream,
              ahead: status.ahead || undefined,
              working_tree: status.clean ? 'clean (everything committed)' : 'has uncommitted changes',
            }),
          ]),
          stat.stdout.trim() ? block(`CHANGED FILES (vs ${against ?? 'HEAD'})`, stat.stdout.trim().split('\n')) : '',
          commits.length ? block('COMMITS ON THIS BRANCH', bullets(commits.map((c) => `${c.shortHash} ${c.subject}`), 20)) : '',
          !status.clean
            ? block('STILL UNCOMMITTED', bullets([
                ...status.staged.map((f) => `staged   ${f.path}`),
                ...status.unstaged.map((f) => `modified ${f.path}`),
                ...status.untracked.map((p) => `new      ${p}`),
              ], 40))
            : '',
        );
      }

      const commands = legacy.commands;
      const jobs=records().jobs.filter(j=>j.workspace===w.id && j.principal===currentPrincipal() && (!currentSession() || j.session===currentSession()));
      const current=await fingerprint(w.root);
      const verification=jobs.filter(j=>j.kind).map(j=>({
        job_id:j.id,kind:j.kind,command:j.command,target:j.target??'full command scope',state:j.state,exit_code:j.result?.exitCode??null,
        historical:j.state==='completed'&&j.result?.exitCode===0?'passed':j.state==='completed'?'failed':j.state,
        current_code:j.state==='completed'&&j.result?.exitCode===0 && j.before?.complete && j.after?.complete && current.complete && j.before.digest===j.after.digest && j.after.digest===current.digest?'observed_match':'unproven',
        started_at:j.startedAt,ended_at:j.endedAt,reason:current.reason??j.after?.reason??j.before?.reason
      }));

      return {data:{verification,current_fingerprint:current,session_id:currentSession(),workspace:w.id},text:join(
        block('OPERATION HISTORY', kv({
          workspace: w.alias,
          root: w.root,
          task: w.task,
          started: changeLog.startedAt,
          files_touched_by_bridge: Object.keys(changeLog.files).length,
        })),
        Object.keys(changeLog.files).length
          ? block('FILES RECORDED FOR THIS TARGET', bullets(Object.entries(changeLog.files).map(([p, c]) => `${c.action.padEnd(8)} ${p}${c.count > 1 ? ` (${c.count} edits)` : ''}`), 60))
          : '',
        gitSection,
        verification.length
          ? block('VERIFICATION EVIDENCE', bullets(verification.map(c=>`historical: ${c.historical}; current code: ${c.current_code} — ${c.kind} ${c.command} (exit ${c.exit_code})`), 20))
          : block('VERIFICATION RUN', ['none — legacy commands are history only; no typed validation evidence']),
        commands.length
          ? block('LEGACY WORKSPACE COMMAND HISTORY (no inferred session ownership)', bullets(commands.slice(-20).map((c) => `${c.exitCode === 0 ? 'ok  ' : `exit ${c.exitCode}`} ${c.command}`), 20))
          : '',
        changeLog.git.length ? block('LEGACY WORKSPACE GIT HISTORY (no inferred session ownership)', bullets(changeLog.git.map((g) => `${g.op}: ${g.detail}`), 20)) : '',
        'observed_match compares recorded source observations only; it does not prove environment, dependencies or transient changes. Legacy workspace logs have no session owner.',
      ) };
    },
  },
];
