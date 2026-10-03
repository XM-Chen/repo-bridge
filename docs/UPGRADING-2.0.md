# 2.0 upgrade and calling migration

This upgrade preserves the TypeScript runtime, single service deployment, existing tool names and labelled text. Tool results additionally include `structuredContent` (`text`, `status`, optional `data`/`error`) and matching MCP output schemas/annotations. Command failures retain `isError=false` when the command actually ran; inspect `data.result.exitCode`, `data.state` and the envelope status. Admission/policy/argument failures have `isError=true`, status `not_started`. An interrupted owner leaves `outcome_unknown`; never automatically retry a mutation based on an unknown result.

## Upgrade procedure

1. Stop every old bridge process sharing the installation data directory.
2. Back up the full data directory, including `state.json`, `oauth.json` and legacy `sessions/` logs.
3. Install/build the new code and run `repo-bridge doctor --json` using the service account environment. Doctor does not create directories, register OAuth clients, modify configuration or launch a service. Create missing directories manually.
4. Start the new version using the existing deployment configuration, then validate a real connector flow separately. Doctor is a local readiness probe, not a ChatGPT end-to-end test.

Old workspace and OAuth formats remain readable. Legacy workspace logs retain their historical role; they do not prove session ownership or code validation. New explicit sessions, workspace operation records, Jobs and typed evidence live in `runtime/records.json`. Corrupt files fail closed and remain untouched for recovery. Do not run old/new versions against the same data directory.

Shared state locks support multiple bridge processes on one host with a local filesystem. Live process locks are never stolen by age; acquisition timeout reports failure. This does not promise NAS, NFS, Synology synchronization or cross-machine lock semantics. Put runtime data on a host-local disk even when source repositories are on synchronized storage.

## Explicit targeting

Reads may still use the current caller's active workspace. Writes, execution, Git mutations and workspace close require an explicit `workspace` or `session_id`. Local opening and remote cloning use their own required target parameters. Sessions bind the caller, workspace ID and canonical root. IDs do not grant authority; each access checks ownership and current configured root permissions. Supplying both selectors requires the same workspace. A closed session remains readable via `session_info`, but cannot accept new operations. A running Job prevents closing its session/workspace, deleting a clone or changing checkout state.

Old: `edit_file({path:"src/a.ts",edits:[...]})`

New: `session_start({workspace:"app",title:"Fix parser"})`, then `edit_file({session_id:"<id>",path:"src/a.ts",expected_revision:"<revision>",edits:[...]})`.

Explicit workspace-only calls are supported and recorded as workspace operations; no session is guessed from tokens, requests or recent workspace use.

## File versions

`read_file` returns `data.revision`, a SHA-256 digest of the entire file bytes, including for partial line reads. Existing-file `write_file` in overwrite/append mode requires `expected_revision`; new-file creation still requires absence. `edit_file` accepts an optional version and otherwise retains unique exact anchor checks. The bridge serializes same-file writes across local processes and rechecks source before publication. Atomic replacement does not provide full transaction isolation against external editors; re-read after any conflict. `read_files` reads at most eight known paths/ranges, shares a maximum 120,000-byte content budget, and returns independent item failures with the same protections/revisions.

## Git migration

`git_status` returns `data.head`. `git_commit` requires nonempty individual `paths` and `expected_head`:

```json
{"workspace":"app","message":"Fix parser","paths":["src/parser.ts","test/parser.test.ts"],"expected_head":"<full HEAD from git_status>"}
```

The temporary index starts from the expected HEAD and includes only those paths. Other staged entries stay staged. A selected partially staged file is refused. Pre-commit, prepare-commit-msg and commit-msg run on the temporary index; message edits are preserved, file/tree changes and failures stop publication for reinspection. HEAD/branch checks and a conditional ref update prevent overwriting a competing commit. Post-commit runs after success. Files changed by hooks or users are never automatically rolled back. A failure after branch publication returns `commit_id` and recovery instructions: inspect/reconcile the index, do not repeat the commit.

Generic Git supports strictly validated `status`, `diff`, `log`, `show`, and branch listing. Global configuration/repository flags, aliases, writing commands and external-program flags are refused, with dedicated-tool guidance. Unsupported Git mutations, including rebase continuation, are manual terminal operations. Dedicated tools, remote cloning (now requires `full`) and PR automatic push share the Git policy. Managed clone deletion requires write permission and `confirm=true`.

Interpreters, package managers, hooks and build scripts remain trusted code with the service account's host privileges. These policies are not an operating-system sandbox and cannot stop a trusted script from invoking Git or reading the host. Use container/OS isolation for that boundary.

## Jobs and verification

Execution tools add `wait_seconds` (default 5, range 0–30) and optional `idempotency_key` (at most 200 characters). A still-running command returns `job_id`. `job_list` recovers caller-owned tasks; `job_status` waits at most 30 seconds; `job_log` reads UTF-8 byte cursors with explicit truncation/remaining information; `job_cancel` requests process-tree termination and reports cancelled only after exit. A retained key with identical execution parameters returns the original Job; a different command/context fails. Maximum four active Jobs across shared state, one per workspace; excess is rejected before starting, without a queue. Existing configured execution timeout remains (default ten minutes).

HTTP/MCP disconnect does not cancel accepted tasks. stdio requires the bridge to remain alive. Graceful service shutdown stops admission, kills owned trees, waits and saves final records. Restart does not adopt processes or rerun tasks. Abrupt exits may leave unknown results. Cross-process cancellation signals the live owner through shared state; it never kills a PID from disk alone. Logs are redacted before persistence/output, bounded to 1 MiB per Job; completed records are retained at most seven days and 100 Jobs. Sessions are bounded to 1,000 records, with 1,000 recent operations each; archive a backed-up runtime store offline when full. Active tasks are never history-pruned.

`run_tests`, `run_build`, and `run_lint` record typed evidence: resolved command, cwd, selector, start/end, exit and before/after source observations. Fingerprints include HEAD, Git state, tracked/nonignored new files with path/type/content, excluding credentials and outside links. Limits: 10,000 files, 100 MiB, five seconds per observation; incomplete scans do not prevent checks, but cannot prove current validation. Selector scope is recorded; fingerprints conservatively observe the whole workspace, so unrelated source changes may invalidate a local test result. `report_changes` separates historical pass/fail from `observed_match`/`unproven` for current code. Equality only compares observations; dependencies, environment and every transient change during execution are not proven.

Typical flow: start session → read revisions → edit → launch background test → reconnect → query Job/log → inspect validation evidence → exact commit → dedicated push → report. Any external edit or HEAD change requires renewed validation before claiming current source passed.

## Doctor

`repo-bridge doctor [--json] [--url URL]` checks configuration, Node/Git, workspaces, detected toolchains, directory permissions and a configured/local service. URL probes inspect `/health`, the authentication challenge, and OAuth discovery when configured, without client registration. Human output gives problem, impact and next step; JSON check IDs are stable (`config`, `node`, `git`, `directory.data`, `service.health`, `service.auth_challenge`, `service.oauth.resource`, etc.). Exit 0: no blocking issues; 1: readiness/configuration issues; 2: diagnosis could not finish.

No UI, LSP, remote runner, managed worktree, interactive terminal, cross-file transactions, package release, deployment or existing-service restart is included in this upgrade.
