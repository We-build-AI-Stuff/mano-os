# Inspect the recorded workspace project

The disposable Debian lab creates a Python project, observes a failed test,
publishes a correction, runs a passing test and verifies a sealed source snapshot.
Four separate native PAM approvals authorize its four effects. The plans are
recorded: this demonstrates the broker/core/executor workflow without an AI
provider call. It does not demonstrate that a live model devised the correction.

## Get a run's result

Open the repository's **Actions → CI** and select a completed run for the revision
being reviewed. Check its conclusion and download its `phase0-REVISION` artifact.
An artifact can also come from a failed run; inspect the run and reports before
treating any contained result as accepted. The bundle is produced by the lab after
the recorded workflow reaches its verified snapshot, before its replay canary.

With GitHub CLI, replace `RUN_ID` and `REVISION` with that run's exact values:

```sh
gh run view RUN_ID --repo We-build-AI-Stuff/mano-os
gh run download RUN_ID --repo We-build-AI-Stuff/mano-os \
  --name phase0-REVISION --dir mano-evidence
```

The `developer-project/` directory contains:

| File | Meaning |
| --- | --- |
| `workflow_answer.py` | Final source bytes read from the broker-held artifact, compared with the original exact-file predicate |
| `failed-test.stdout`, `failed-test.stderr` | Captured output of the actual failing command, read through the task-scoped broker reader |
| `passed-test.stdout`, `passed-test.stderr` | Captured output of the actual passing command, through the same reader |
| `correction.diff` | Recorded initial source versus captured final source; this covers that file, not every file in the shared fixture workspace |
| `manifest.json` | Tested revision, original human prompt, task/resource/workflow IDs, recorded definition, original action observations, artifact metadata, approval IDs and file hashes |
| `test_workflow_answer.py` | Convenience test supplied for inspecting the downloaded project; the exact original command is retained in `manifest.json` |

After inspecting the source and convenience test, run it in a scratch directory:

```sh
cd mano-evidence/developer-project
python3 -m unittest -v
```

That local result checks the downloaded project. It does not reproduce native PAM,
the broker isolation, Stop or the original executor environment.

The original failed test reports `FAIL expected 42 got 0` and exit 1. The correction
changes `answer()` from returning 0 to returning 42; the final command prints
`PASS` and exits 0. The separate exact-file predicate checks the captured source.
Publication and command exit alone do not mark the human goal complete.

## Reproduce the native journey

Use the checked-in **CI** workflow on an explicitly disposable Ubuntu 24.04 runner.
Its security job installs VM tooling and invokes:

```sh
MANO_DISPOSABLE_CI=1 bash scripts/run_vm_lab.sh
```

This is a CI runner invocation, not a setup command for a personal computer. The
script creates disposable Debian VMs and runs the existing golden-project,
recorded correction, approval, protected-policy and Stop/recovery fixtures. Its
tracked source is transferred into the guest and installed there. Do not rerun a
completed run merely because a local observation timed out.

Use `broker-service.json` alongside the bundle. Its `terminal_execution` section
contains `recorded_developer_workflow_witness`,
`recorded_developer_native_stop_restart_no_follow_on_effect` and
`full_workspace_profile_protected_policy_kernel_denial`. The witness checks that
reopening the recorded workflow does not overwrite a changed replay canary. The
exported source is the earlier verified snapshot; it is not a claim about later
workspace contents. Existing native assertions remain required.

The manifest records workflow elapsed seconds. Peak workflow RAM, physical input
provenance and live-model success remain unmeasured (`null`). Full Phase 1 and
v2.1 acceptance still require the remaining evidence in [DELIVERY.md](DELIVERY.md).
