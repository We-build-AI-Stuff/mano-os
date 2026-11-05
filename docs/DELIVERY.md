# Delivery ledger — mano-OS v2.1

Updated 2026-11-05. This is the delivery status against the unchanged
[original specification](spec-v2.1.md), not a new or reduced project scope.
The specification is byte-identical to the supplied README; SHA-256:
`6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace`.

Private desktop integration is under development on `feat/task-private-desktop`.
Its [capability and verification boundary](private-desktop.md) distinguish local
contract checks from the pending native GUI exercise. Browser, Writer and full
MVP acceptance remain open.

## What is delivered today

The main branch contains a Debian security/runtime prototype, a native prompt,
scoped broker permissions, isolated execution, durable state and recorded task
fixtures. An unsigned runtime package can be built and exercised in a disposable
Debian VM using [operations](operations.md). Live AI-driven everyday workflows,
the integrated MVP and a signed installable OS have not been accepted.

A passing component test, source file or CI job is evidence for its stated scope.
None alone closes a phase or proves the requested version complete.

| Track | Visible state | Completion boundary |
| --- | --- | --- |
| Audited runtime baseline | `7f255805d3b1d6c1f7b5485f1b2ea4e6db7a79f6`, including merged PR148 | Native result viewer and recorded-project download verified at their indexed revisions; full version incomplete |
| Workspace evidence | [Published evidence index](phase-1-workspace-evidence.md), [run 41871350554](https://github.com/We-build-AI-Stuff/mano-os/actions/runs/41871350554) | Downloaded source/log hashes and action/artifact bindings checked; Phase 1 measurements and the later full cross-app MVP remain open |
| Package apply | [PR #134](https://github.com/We-build-AI-Stuff/mano-os/pull/134), 191 changed files and 28,977 additions at audit time | Unmerged; source/runtime and publication integrity still incomplete |
| Latest package lab evidence | [Run 41794862656](https://github.com/We-build-AI-Stuff/mano-os/actions/runs/41794862656), head `9d8c491` | All three CI jobs and 46 external staging checks passed; specific held-file evidence, not phase completion |
| Unpushed package experiments | Kernel-event collector/parser drafts remain in the original local checkout | Not included in main or the accepted CI head |

## Next delivery milestone

**Complete Phase 1 measurements against its evidenced native mock-project exit
demonstration.** The installed workspace create/test journey and its recorded
correction are published and inspected. Use the existing broker, sandbox, prompt,
workflow and journal before expanding later-phase package experiments. A
deterministic run remains labeled recorded/mock and does not establish live-model
or authenticated delegate success.

The lab now exports the finished recorded project, original captured test logs,
correction diff and identity/hash manifest. See [the workspace demonstration](workspace-demo.md)
for download, inspection and disposable-runner reproduction. Native acceptance of
the export must be checked on the revision being reviewed; source presence alone
does not close this milestone.

The [published Phase 1 evidence index](phase-1-workspace-evidence.md) now records
the inspected main `63da53f` download and PR148 native viewer, with their exact CI
runs, archive hashes, original actions and eight-item requirement audit. It separates
the mock-agent addition project from the later recorded correction fixture. The
download contains a one-file correction diff. Section 14 requires per-phase task
success/bypass/intervention, elapsed/cost, idle/peak RAM, OOM recovery and regression
measurements with honest scope and unknowns; that Phase 1 reporting remains
incomplete. The complete workspace diff and original task trace remain required
for Section 14's first cross-app MVP, alongside its browser/report evidence. They
are not new prerequisites for the minimal Phase 1 mock-project exit demonstration.

The specification explicitly includes a mock model in Phase 1. Credit valid recorded
evidence within that scope, and do not rerun or rebuild a completed fixture merely
to create activity. Live AI-driven product acceptance remains a separate outstanding
requirement; proceed through the original phase ordering. Provider credentials/configuration stay operator-controlled; this
ledger authorizes no credential probing or paid calls.

PR #134 remains preserved and unmerged for the Phase 5 package/system-helper
requirement. Its genuine defects remain blockers for that operation. Shared-runtime
security defects also block any earlier milestone they actually affect. Existing
security assertions and all required CI remain in force. The full package capability
and all other original requirements remain part of the requested version.

The CI security job now renders existing journey observations in the GitHub Actions
summary, including missing evidence and remaining release gates. To reproduce the
read-only summary after collecting an artifact:

```sh
python3 scripts/delivery_summary.py --evidence evidence --revision FULL_TESTED_COMMIT
```

## Numbered build/test requirements

These 53 rows preserve every numbered build/test item in phases 0–7. A statement
that a prototype component exists is not a completion checkmark. The phase exit
criteria below remain separate requirements.

### Phase 0 — Feasibility & security architecture spike

Architecture GO for Phase 1 development; physical acceptance remains open. [Existing implementation notes](architecture/0008-phase0-original-spec-audit.md).

| ID | Original build/test requirement | Current evidence or remaining gap |
| --- | --- | --- |
| P0-1 | Debian 13 minimal VM (8 GB max), btrfs root and security-update baseline; verify patched bubblewrap. | CI VM/btrfs/recovery evidence; no physical install claim. |
| P0-2 | Minimal prompt-only Sway user session; no conventional desktop shell. | Native prompt and authenticated rescue TTY in CI; physical display acceptance open. |
| P0-3 | Separate headless Sway instance, independent runtime dir and service identity; launch Chromium + LibreOffice and validate screenshot and basic input. | Isolated Sway, Chromium and Writer fixtures in CI. |
| P0-4 | Explicitly enable accessibility; inspect AT-SPI tree, exercise a named action and verify Wayland coordinate mapping. | Named accessibility action and scale-aware visible-control fixtures. |
| P0-5 | Restrict compositor privileged protocol access to intended services; test untrusted XWayland and Wayland clients. | Wayland privileged-global and task-private XWayland negatives. |
| P0-6 | **Approval spoof attack:** attempt to click/type into human approval from CLI, injected GUI events, virtual-keyboard path and socket abuse. Must fail. | OS-authenticated fallback and spoof negatives; real physical provenance remains unmeasured. |
| P0-7 | **Input/stop test:** physically request stop while core is frozen; tasks must terminate without Python cooperation. Deny `/dev/input` and `/dev/uinput` to untrusted tasks. | Native watchdog/TTY Stop with frozen services; physical-key acceptance remains open. |
| P0-8 | Check no inherited user D-Bus, Wayland/X11, SSH/gpg, PipeWire or systemd-control sockets. | Inherited environment/FD and host IPC denial fixtures. |
| P0-9 | Evaluate Snapper snapshot/restore and terminal rescue on btrfs. | Snapshot restore and recovered-root boot fixtures. |
| P0-10 | Record idle RAM, session memory, app start, process limits, log evidence and compatibility problems; do not invent numbers. | Lab measurements and compatibility findings; required product metrics remain open. |

### Phase 1 — Trusted broker, sandbox runner and minimal agent

Native mock/recorded demonstrations inspected; complete phase acceptance remains
open. [Evidence and eight-item audit](phase-1-workspace-evidence.md).

| ID | Original build/test requirement | Current evidence or remaining gap |
| --- | --- | --- |
| P1-1 | Define typed broker request/result/grant schema and distinct user/service identities. | Typed protocols, broker peer identity and separate service/task identities exist. |
| P1-2 | Implement broker-owned policy, secure grants and action journal (`intent → executing → done/failed/unknown`). | Broker grants, approvals and action journal exist; full product acceptance remains open. |
| P1-3 | Implement per-task bubblewrap sandbox with filesystem restrictions, no inherited IPC, cgroup and seccomp/Landlock tests. | Native sandbox, cgroups and filesystem/syscall/IPC negative fixtures exist. |
| P1-4 | Build supervised, Auto and Full Access policy **profiles** (initial small scope, then expand later). | Workspace permission profiles and native PAM/GUI permission proposal flow exist. |
| P1-5 | Implement isolated terminal adapter and minimal model adapter / LangGraph `AgentRuntime`. | Native LangGraph mock-project and installed planner/core fixtures inspected; live-provider acceptance is a separate product gap. |
| P1-6 | Implement prompt bar and broker-driven approval UI. | Native prompt, broker status/permissions and verified-snapshot viewer have CI evidence; submission alone does not execute a task. |
| P1-7 | Build golden-task tests, mock model, recorded traces/replay, malicious shell attempts and CI gating. | Reproducible source/log/action and negative evidence published; per-phase metrics remain incomplete. The broader red-team corpus belongs to Phase 2. |
| P1-8 | Implement stop/revoke end-to-end and verify unknown-effect recovery. | Native Stop/revoke and unknown-state handling exist; integrated phase exit evidence remains open. |

### Phase 2 — Developer tool workflows and independent coding adapters

Recorded developer workflow and isolated adapters; authenticated coding gate open. [Existing implementation notes](architecture/0096-isolated-coding-delegates.md).

| ID | Original build/test requirement | Current evidence or remaining gap |
| --- | --- | --- |
| P2-1 | PTY and long-running process supervision, logs, environment and package-plan adapters. | PTY supervision, captured output and package forecasts exist. |
| P2-2 | Antigravity headless adapter with per-task synthetic home/settings; verify soft-denial exit-0 case. | Pinned Antigravity adapter has offline isolation/configuration contracts; authenticated coding not accepted. |
| P2-3 | Second adapter (Claude Code or Codex) with same contract, version pinning and replayable traces. | Pinned Codex adapter shares contract; authenticated coding and live denial behavior not accepted. |
| P2-4 | Git workspace snapshots, test/fix loops and structured artifacts. | Recorded fail/fix/pass workflow, artifact verification and workspace checkpoints exist. |
| P2-5 | MCP sandbox runner and minimal tool discovery. | Sandboxed MCP discovery/inspection exists; complete integration acceptance remains open. |
| P2-6 | Red-team corpus: prompt-injection repos, typosquatted dependencies, malicious MCP servers, malicious scripts. | [Four named attack fixtures](phase-2-redteam-corpus.md) cover repository instructions, a local deceptive dependency hook, shell and the existing native MCP case. Changed-revision native acceptance is pending; no live-model resistance claim. |

### Phase 3 — Linux GUI/browser control; ship runtime MVP

Unsigned runtime package and isolated application fixtures; integrated MVP gate open. [Existing implementation notes](architecture/0088-clean-debian-package-reboot.md).

| ID | Original build/test requirement | Current evidence or remaining gap |
| --- | --- | --- |
| P3-1 | Headless session management and GUI-only sandbox policy. | Isolated session and GUI fixture infrastructure exists. |
| P3-2 | D-Bus/AT-SPI adapters, window geometry and screenshots. | Accessibility, geometry and screenshots have CI fixture evidence. |
| P3-3 | Controlled keyboard/mouse input only to agent session; no human focus stealing. | Agent-only input and human-focus canary have CI fixture evidence; physical input remains open. |
| P3-4 | Playwright launches system Chromium using local transport; distinct browser profiles. | System Chromium/Playwright fixture exists; full agent-driven workflow acceptance remains open. |
| P3-5 | Browser compatibility tests for each pinned version, including security setting checks. | Pinned-browser fixture contracts exist; release compatibility acceptance remains open. |
| P3-6 | LibreOffice tasks (open, edit, save, export) and screenshot/vision privacy controls. | Writer save/export fixtures exist; integrated user task and privacy acceptance remain open. |
| P3-7 | Trusted approval surface, synthetic-input attack recheck, independent compositor-level/TTY stop path. | Native approvals and Stop have VM evidence; physical trigger acceptance remains open. |
| P3-8 | Package runnable **`mano-runtime` v0.x `.deb`** for stock Debian + Sway. | Unsigned mano-runtime prototype package has clean-Debian/reboot fixtures; runtime MVP gate remains open. |

### Phase 4 — Durable multi-app workflows and control SDK

Durable state, controller, artifacts and scoped SDK components; full workflow gate open. [Existing implementation notes](architecture/0076-durable-controller-cycles.md).

| ID | Original build/test requirement | Current evidence or remaining gap |
| --- | --- | --- |
| P4-1 | Typed SDK, full capability registry and provider-agnostic tool adapters. | Typed operation adapters and discovery exist; full public capability registry acceptance remains open. |
| P4-2 | Dependency-aware workflow execution, task queues, retries and timeouts. | Bounded controller and recorded workflow sequencing exist; general multi-app orchestration remains open. |
| P4-3 | Broker journal reconciliation for `unknown` actions and idempotent replay rules. | Journal reconciliation and no-effect replay fixtures exist; full workflow restart gate remains open. |
| P4-4 | Searchable artifacts, model context compaction and token/cost budgets. | Artifact custody and budget components exist; complete search/context compaction acceptance remains open. |
| P4-5 | Connector authorization and provenance/taint-aware exfiltration guardrails. | Disclosure/egress and feedback approval components exist; complete connector provenance/exfiltration acceptance remains open. |

### Phase 5 — Broader autonomy, hardware and OS operations

Package planning/recovery components; package apply unfinished in PR #134. [Existing implementation notes](architecture/0103-approved-package-forecasts.md).

| ID | Original build/test requirement | Current evidence or remaining gap |
| --- | --- | --- |
| P5-1 | Wider, time-bounded Auto and Full Access grants with host data restrictions retained. | Bounded workspace profiles exist; broader grants remain restricted pending acceptance. |
| P5-2 | Broker-performed credentialed Git/API operations; no plain secrets to agents. | Provider credential custody/egress components exist; credentialed Git/API product workflows not accepted. |
| P5-3 | Narrow package/system helper, btrfs/Snapper actions and documented restore. | Forecast, review and recovery components merged; apply/runtime integrity remains unfinished in PR #134. |
| P5-4 | Device discovery, serial read, GPU/system APIs and safe hardware operation envelopes. | No accepted device/serial/GPU hardware workflow established by this audit. |
| P5-5 | VM lab mode for deliberately broad experiments and physical safety stop tests. | Disposable VM lab exists; physical hardware safety stop acceptance remains open. |

### Phase 6 — Optimize for 8 GB, harden and expand compatibility

VM resource/negative tests; physical 8 GB acceptance open. [Existing implementation notes](operations.md).

| ID | Original build/test requirement | Current evidence or remaining gap |
| --- | --- | --- |
| P6-1 | zram and OOM containment tuning; task priority and execution concurrency caps. | VM cgroup/OOM isolation evidence exists; target-hardware tuning acceptance remains open. |
| P6-2 | Cold boot, idle, browser and code-build memory traces on physical 8 GB test systems. | Physical 8 GB cold-boot/idle/browser/build traces missing. |
| P6-3 | Desktop/XWayland/GUI application compatibility matrix and fallback policies. | Pinned application fixture contracts exist; release compatibility matrix incomplete. |
| P6-4 | Security fuzzing, IPC-failure, dependency-update and crash recovery tests. | Negative/crash/IPC tests exist; complete hardening and dependency-update acceptance incomplete. |
| P6-5 | CLI/coding-agent/Chromium version contract tests in release pipeline. | CI version checks exist; complete release pipeline acceptance incomplete. |

### Phase 7 — Bootable mano-OS distribution

Development runtime package; signed installable distribution not accepted. [Existing implementation notes](architecture/0087-prototype-runtime-package.md).

| ID | Original build/test requirement | Current evidence or remaining gap |
| --- | --- | --- |
| P7-1 | Build custom Debian-based image with `live-build` or `mkosi` (tool decision by experiment). | No accepted custom installable OS image established by this audit. |
| P7-2 | Pin build inputs including base repository snapshot; retain security-update mechanism. | Current CI bootstraps from a current Debian cloud image; fully pinned release inputs/signature verification incomplete. |
| P7-3 | Configure prompt-first boot, login, compositor isolation, services and user onboarding. | Prototype Sway/runtime setup exists; distribution onboarding/boot acceptance incomplete. |
| P7-4 | Provide AI API configuration, user policy setup, mode selection and hardware diagnostics. | Native provider setup and permission controls exist; complete installer configuration/hardware diagnostics incomplete. |
| P7-5 | Provide signed packages/image, update/rollback and recovery boot option. | Runtime package is unsigned; signed image/package/update/recovery acceptance incomplete. |
| P7-6 | Fresh install smoke tests in a VM and on one 8 GB physical machine. | Clean-Debian runtime fixture exists; fresh OS-image VM and physical installation acceptance incomplete. |

## Original phase exit criteria

| Phase | Required exit | Acceptance today |
| --- | --- | --- |
| 0 | Isolation, approval protection, trusted Stop, headless GUI; revise architecture if they fail | Lab GO for Phase 1 development, using the documented OS-authenticated fallback; no production or physical guarantee |
| 1 | Agent creates/tests a workspace project; protected policy/host writes fail at OS boundary | Native mock-project and protected-policy exit demonstration evidenced; Section 14's per-phase reporting remains incomplete |
| 2 | Coding job → tests → correction → verified result; malicious delegate leaves policy/settings unchanged | Recorded correction and offline adapter fixtures; authenticated delegate gate remains open |
| 3 | Build website → tests → Chromium verification → summary, plus Writer; approval/user-session attacks fail | Individual browser/Writer/runtime fixtures; integrated MVP gate remains open |
| 4 | Restart core without repeating completed effects; reconcile unknown effects; show accurate status | Components/fixtures present; full multi-app restart gate remains open |
| 5 | Granted sensor read and system operation; off-scope credential/device/persistence changes fail | Package/helper work incomplete; hardware and credentialed workflows not accepted |
| 6 | Responsive real 8 GB laptop, isolated OOM and protected user/broker | Physical acceptance missing |
| 7 | Fresh OS install boots to prompt, runs authorized CLI/GUI, reliably stops work and survives updates | Signed image/fresh install/update acceptance missing |

Phase 8 remains optional after the stable baseline. Physical testing is deferred
while CI VM work proceeds; it has not been waived.

## Section 14: golden tasks and measurements

| Required verification | Current boundary |
| --- | --- |
| Correct basic file/CLI artifact | Recorded workspace fixture evidence; full user journey remains to be accepted |
| Workspace escape denied | Native sandbox negative fixtures; repeat relevant tests for changed profiles |
| Protected policy/journal/config unchanged | Existing integrity/negative fixtures; applies to every effectful milestone |
| Malicious MCP/injected prompt cannot gain secrets/authority | Scoped MCP/denial fixtures; full corpus acceptance remains open |
| Agent cannot operate authentic approval | Native PAM and isolated-session fixtures; physical provenance unmeasured |
| Independent Stop under hung core | Native VM/TTY fixtures; physical trigger acceptance open |
| Chromium without open CDP port, working locators | Pinned application fixtures; integrated task gate open |
| Correct LibreOffice output, no focus hijack | Writer/isolation fixtures; integrated task gate open |
| Unknown remote effect checked rather than blindly replayed | Journal/replay components; accepted real connector workflow missing |
| Agent OOM isolated from human session | VM fixtures; target-hardware measurements open |
| Credentialed API without secret in agent env/logs | Provider custody components; accepted credentialed product workflow open |
| Reproducible package/application compatibility matrix | Individual pinned fixtures; complete release matrix missing |

Publish each phase's verified task success rate, policy bypass rate, interventions,
elapsed time, task/model cost, idle/peak RAM, OOM recovery time and regression count.
Existing VM observations cover only their fixtures. No product-wide success rate,
physical performance or live-model cost is claimed by this audit. Missing values
remain null rather than estimates.

The first full MVP still requires the original request: create a small API and
website, run tests, verify its primary UI in Chromium, generate a report and show
the result. Retain workspace diff, test/build logs, browser trace, report, broker
journal, cgroup limits and human-input isolation evidence. A recorded terminal test
alone cannot close this MVP.

## Section 16: definition of done for each delivery PR

Every issue still needs documented-environment execution; positive and relevant
negative tests; real end-to-end evidence where appropriate; broker-grant/journal
verification for effects; measured memory/compatibility impact; and reproducibility
without relying on assistant assertions. Use one testable issue at a time, retain
protocol/version contracts, document rollback and limitations, and merge only after
all required CI passes on the exact final head with the current base.

## Evidence provenance and limits

This is a source/evidence audit by the implementing assistant, not an independent
security assessment. Phase 0's latest retained `architecture-audit.json` says
`go-for-phase1-development` and `production_execution_authorized: false`; its audit
code and ADR0008 are unchanged between the audited main and package branch.
Historical NO-GO entries in the phase-0 log describe earlier checkpoints.

Main/source references were inspected on 2026-11-04. Package-branch results are
explicitly labeled; none imply that PR #134 is merged. CI artifacts expire after
seven days, so preserve required evidence before relying on older download links.
Do not treat a future stale snapshot of this file as current GitHub status.
