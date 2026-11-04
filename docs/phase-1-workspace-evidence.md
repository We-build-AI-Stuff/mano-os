# Phase 1 workspace demonstration: evidence and remaining acceptance

Audited 2026-11-04 against the unchanged [v2.1 specification](spec-v2.1.md).
The downloadable recorded project and native result viewer have been exercised and
inspected. Full Phase 1 acceptance and the complete v2.1 product remain open.
This is an evidence review by the implementing assistant, not an independent
security assessment.

## Accepted revisions and downloads

| Demonstration | Source and CI | Collected evidence |
| --- | --- | --- |
| Downloadable recorded project | Main `63da53fe9dbfb828a7257133df3182760c1b9664`; [run 41871350554](https://github.com/We-build-AI-Stuff/mano-os/actions/runs/41871350554), quality/security-lab/merge-gate succeeded | [Artifact 13347110077](https://github.com/We-build-AI-Stuff/mano-os/actions/runs/41871350554/artifacts/13347110077), 12,221,352 bytes |
| Native verified-result viewer | [PR #148](https://github.com/We-build-AI-Stuff/mano-os/pull/148), head `f1a764fddf49f67abf4b9a3021c0c30ed7af29ce`; [run 41871505838](https://github.com/We-build-AI-Stuff/mano-os/actions/runs/41871505838), all three jobs and CodeRabbit succeeded | [Artifact 13345538223](https://github.com/We-build-AI-Stuff/mano-os/actions/runs/41871505838/artifacts/13345538223), 12,318,392 bytes; `live-verified-result.png` and `live-human-permissions.json` |

The viewer run tested synthetic merge
`e417b99a7b5533dd47f9fff935443e2f01e7fb45`, with parents `63da53f` and `f1a764f`.
Merged main `7f255805d3b1d6c1f7b5485f1b2ea4e6db7a79f6` has that same source tree,
`b268755de162b8655f0b39114e5c6e14a7d4438a`. A subsequent main workflow is a
separate run; the PR result must not be represented as its conclusion.

The downloaded ZIP SHA-256 values were checked before inspection:

```text
13347110077 a6037e79e4e26be9e1a3ca48c1860155527f988ead8b978e0ddfbe8b1271bc20
13345538223 40c0083ed61688775d6aa98989d9785430fec7dcefe372c785192103c69ac8fc
```

Artifacts expire under the workflow's seven-day retention policy. The source and
[reproduction instructions](workspace-demo.md) remain in Git; an expired artifact
does not establish a result on another revision. These are CI evidence downloads,
not a signed OS release.

## What actually ran

The broker-service fixture first submits the native human request **“Create and
test a small addition project”**. The installed LangGraph core uses an explicit
mock model to create `calc.py` and its unit test through an approved isolated
terminal action. The native fixture requires the test to pass, prevents replay
from overwriting a canary, and checks the declared exact-file artifact separately.
`mock_agent_golden_project_tests`, `mock_agent_replay_no_effect` and the verifier
checks in `broker-service.json` describe that scope.

The later recorded developer workflow uses the same task/workspace for a separate
four-step test/fix demonstration. It does not claim that a live model converted
the addition request into these steps or devised the correction:

| Step | Actual result | Original action on main `63da53f` |
| --- | --- | --- |
| Publish initial `workflow_answer.py` | `answer()` returns 0; 27-byte publication receipt | `23f80e5a7d99f3d832539d914b571ccc` |
| Run the recorded test | Exit 1; stderr `FAIL expected 42 got 0` | `f2716bebcf1a9ab13686d413b357655a` |
| Publish the recorded correction | `answer()` returns 42; 28-byte publication receipt | `479ee96a92e66875d30d446fde4c57b6` |
| Run the final test and verify its artifact | Exit 0; stdout `PASS`; exact-file snapshot checked separately | `cfe723cb3f52b14da97d113f2cd66120` |

All four effects require separate native PAM approvals. Task
`45e633f88137547bb3c70fb7610a914a`, workflow
`460ef9cea416a5b0921a7cbe198dba02` and final artifact
`2883613f3e996a850270073e0ba7ae4c` bind the exported observations. These IDs identify
this run; they are not reusable authority.

The inspected `developer-project/` files include final source, original captured
stdout/stderr, `correction.diff`, the recorded definition and identity/hash manifest.
Every exported file's size/hash matched its manifest; command logs matched their
original captured metadata; the final source matched the artifact identity/hash.
The supplied convenience unit test also passed after downloading and inspecting
the source. That local test does not reproduce the original native environment.

The diff compares recorded initial source with the captured final source. It is
not a complete before/after inventory of the shared task workspace. The exported
snapshot precedes a deliberate replay-canary modification; it does not describe
later live workspace contents. Original capture metadata is retained unchanged;
the broker's checked artifact references establish verification.

The viewer demonstration is a separate task in the same PR run. The production
prompt opens a native broker-backed preview of `gui-result.txt`, containing
`Verified GUI result` and a newline (20 bytes). Its actual screenshot was inspected
and matched its recorded image hash. The fixture separately approves a Supervised
profile and exact effect, verifies the captured file, and restores its original
bounded Auto profile through fresh PAM before later package tests continue.

## Original Phase 1 requirements

All report paths below refer to the collected run artifact. Component reports
have their own scope labels; a primitive probe alone does not establish integrated
runtime acceptance.

| Original item | Evidence inspected | Remaining boundary |
| --- | --- | --- |
| P1-1: typed requests/results/grants and identities | Typed protocol source; `broker-ipc.json` peer/caller negatives; `workspaces.json` distinct identities and cross-workspace kernel denials | Protocol/identity fixtures, not a general product completion claim |
| P1-2: broker policy, grants and action journal | `broker-service.json` native PAM, argument binding, durable terminal outcomes and original workflow action observations | Complete source/journal export for the whole human task remains open |
| P1-3: sandbox, filesystem/IPC/cgroup/seccomp/Landlock | Integrated broker-service kernel denials; `fd-sandbox.json` descriptor, IPC, syscall and Landlock primitive checks | The FD primitive report explicitly excludes broker integration; use the broker-service fixture for integrated claims |
| P1-4: initial Supervised/Auto/Full Access profiles | Broker-service profile count/expiry/exact-grant and protected-policy kernel negatives; native GUI/PAM profile workflow | Workspace scope only; broader later-phase autonomy is not accepted |
| P1-5: terminal, minimal model adapter and LangGraph core | Native mock-agent golden project, installed core/broker-planner entrypoints and SQLite reopening | Phase 1 explicitly permits a mock model; accepted live-agent operation remains a broader product gap |
| P1-6: prompt and broker-driven approval surface | `human-prompt.json`, native transport/PAM checks and real `live-human-permissions.json` viewer flow | Submission remains intent; controller/provider configuration is separate. Physical input acceptance remains deferred |
| P1-7: golden/mock/trace/replay/negative tests and CI | Four-step exported definition/logs, same-action replay canary, protected-policy negatives and successful exact-revision CI | Full workspace change inventory and broader task/corpus metrics remain open |
| P1-8: Stop/revoke and unknown-effect recovery | `recorded_developer_native_stop_restart_no_follow_on_effect`, frozen-service/native Stop, durable unknown/restart and revoked-profile checks in broker-service report | Native VM fixtures; physical trigger and broader workflow/release acceptance remain open |

The original exit condition has concrete native mock-project and OS-boundary
negative evidence. This report credits that demonstration while retaining the
missing aggregate evidence and original phase/product scope.

## Measurements and next work

| Observation | Actual value and scope |
| --- | --- |
| Recorded workflow elapsed time | 35.62486908 seconds on main `63da53f`, from registration through the verified workflow result, including synthetic CI approval interaction; excludes later export/replay/Stop stages |
| Broker service limits | 128 MiB memory, 16 tasks and 20% CPU, observed by the native service fixture; limits are not peak usage |
| Workflow peak RAM | `null`; not measured |
| Physical input provenance / physical 8 GB performance | `null`; not measured |
| Live-model success, model cost and product-wide success/bypass rates | Not established; no provider disclosure occurs in this recorded workflow |

`resources.json` contains separate VM-primitives/UI observations and explicitly
states that the production core/broker are absent from that measurement scope.
Do not use those values as the memory footprint of this installed workflow.

The remaining workspace milestone needs a complete before/after change inventory
and original task trace, plus appropriately scoped resource and task/corpus metrics.
Those gaps must be filled rather than converting this one-file diff or fixture
result into full Phase 1 acceptance. Do not rebuild this accepted fixture solely
to create activity. Live AI, authenticated coding delegates, integrated browser/
Writer workflows, full recovery/autonomy, package apply, hardware, physical 8 GB
testing and signed installation retain their original later acceptance gates.
