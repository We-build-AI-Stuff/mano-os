## Local aggregate declaration/resource hardening (not pushed)

Baseline trigger acquisition now caps the complete reference set at 4 MiB and
4096 decoded directives in addition to per-file quotas. Excess declared byte
size is rejected before invoking the owned-baseline reader for that file. Two
regressions cover aggregate byte exhaustion and aggregate directive exhaustion.
The independent reader recomputes the same aggregate bounds. Unqualified log
package lookup now uses one name index while retaining ambiguity rejection.

781 local tests: 726 passed, 55 skipped. Ruff, compilation and diff checks pass.
These changes remain local alongside the linkage/sequence/time-window follow-ups.
Current remote run 40286784670 still validates 8f77c70, with quality successful
and the VM security job in progress. Its acceptance uses NINE flags; the later
local source requires TWELVE. No protection, probe or artifact was removed.

## Local UTC execution-window binding (not pushed)

package_log_time.bind_controller_window checks nonempty preserved log append
against actual controller realtime/monotonic nanosecond samples around the fixed
worker run. Same boot, positive bounded integer samples, at most 60 seconds and
at most two seconds wall/monotonic drift are required. UTC event seconds must
fall in the inclusive start/end second buckets and never decrease. The worker
and dpkg receive TZ=UTC0 explicitly; both environment witnesses are recorded.
This is controller-relative containment, not an external time authority or a
proof of trigger arguments, script effects or log mutation permission.

779 local tests: 724 passed, 55 skipped. Ruff, compilation and diff checks pass.
An independent implementation recomputed a SYNTHETIC two-event clock fixture
and rejected seven altered reports. No native clock samples have been acquired
by this source yet. Future fresh source acceptance needs TWELVE options, adding
--log-time-window after --log-sequence. Current remote 8f77c70/run40286784670
still needs NINE; it has no linkage, sequence or time-window guard. Keep all three
local follow-ups unpushed until current run and its evidence are accepted.

## Local supported event-sequence follow-up (not pushed)

package_log_sequence.require_sequence now requires one startup, complete ordered
unpack/configure for every approved new package, and pending/processing/settled
trigger cycles. Empty, truncated, repeated or overlapping actions, uncaused
trigger processing and decreasing timestamp text fail. Dependency order, actual
trigger arguments, clock timezone/window, maintainer effects and log authority
remain separate and unverified. Unsupported state patterns require an explicit
extension rather than permissive fallback.

773 local tests: 718 passed, 55 skipped. Ruff, compile and diff checks pass.
The accepted fc81e10 native suffix matches 21 events and two trigger cycles;
an independent implementation recomputed that sequence and rejected six altered
reports. This is LOCAL source against native bytes, not a new-source VM run.
The CI-only probe now includes dpkg_log_sequence. Later fresh acceptance must
use ELEVEN options, adding --log-sequence after --trigger-linkage. Current remote
8f77c70 source still uses only nine options. Its run 40286784670 remains live,
quality succeeded and security-lab is executing the VM step. Preserve that run.

## Local trigger-linkage follow-up (not pushed)

Remote 8f77c70efeb254cc28d0e627bb6abb9c382a0d48 remains under native CI run
40286784670. Quality succeeded; security-lab was verified in progress on the real
Debian VM probe step. Watch session 1886 is live. Do not replace this run merely
because a polling interval expires. Current run acceptance needs nine options,
without --trigger-linkage, because remote source does not contain this follow-up.

The local guard recomputes package log scope, authenticated candidate payload and
control validation, baseline declaration byte binding, and archive declaration
parsing. Every referenced trigger package must have at least one declared
interest linked to a lexical authenticated payload path or an explicit activation
in the approved new-package closure. Unsupported dynamic dpkg-trigger calls cannot
satisfy this guard. It does not prove actual postinst trigger arguments, event
order, script effects or execution authority. All corresponding flags remain false.
A future production policy must cover those requirements separately.

The parser now rejects non-ASCII trigger names, matching upstream's printable
7-bit naming rule. Upstream trigger specification blob
1d185aa132f132cd5d742ce436bfce40a83c39d6 was acquired as text only, SHA256
3283d48c0ecb80b5621aaccc02d9ee49e62b6737f64fc6d27830531185b75172.
766 local tests: 711 passed, 55 skipped. Ruff, compilation and diff checks pass.
An independent implementation recomputed two links on a SYNTHETIC fixture and
rejected four altered reports. This is not native linkage evidence. Once current
remote source is accepted, the follow-up needs fresh CI and all ten acceptance
options, adding --trigger-linkage after --trigger-declarations.

# mano-OS continuation

## Objective and execution rules

The original v2.1 phases 0–7 remain ACTIVE and incomplete; Phase 8 is optional.
The frozen specification SHA256 is
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Repository: We-build-AI-Stuff/mano-os. PR #134 is the only open implementation PR.
Its base was verified as 65fdfc02e3dbb18f791a92374a24690ae4e1ba87.

Use merge commits only after current-base, exact-head ALL CI and relevant real
security/artifact/GUI evidence pass. Admin human-review override is authorized;
failed CI, protection or evidence bypass is not. Assess CodeRabbit findings:
fix valid issues, or explain concretely why a finding does not apply. All five
current review threads were verified resolved. Do not request human reviews or
notify reviewers; the user arranges them. No proactive subagents or other-chat
messages. Root/Linux/VM/AppArmor execution stays in disposable Debian CI, never
on the Mac. No paid providers, key/auth experiments, or local VM/model downloads.
Never silently delete data. Warn below 20 GiB free or above 90 percent usage;
stop large downloads below 10 GiB. The agent has no /compact invocation tool.

## Latest independently accepted native evidence

Head fc81e1076719a5b578f701ecebb462209e5890d9, full retry run 40283471563:
quality 121441694142, security-lab 121441693697 and merge-gate 121449324163
all succeeded. Artifact 12634355338 is 22,982,680 bytes, SHA256
f455bf0d86a62744abcbf5c504e758ee0d420c3acf7b9d2674042b877c21f66e.
The local pr134-log-decoding-retry-security.zip matches the server digest.

Independent acceptance passed 54 hash checks, 45 required flags and all prior
package/PAM/Stop/recovery/ELF/staging/tree/closure/control/list/database/accounting
and log-observation checks, plus recomputation of all 21 decoded event frames.
The strict mutation guard accounted for 55 of 66 differences and rejected 11
unresolved effects. This is expected rejection evidence, not complete mutation
approval. All six fresh GUI originals and four numeric crops were visually
inspected; full pending/effective values 900 before and 120 after are readable.
Receipt: outputs/acceptance-pr134-log-decoding-retry/inspection.json, relative to
the task root (the repository is under work/mano-os). Physical provenance is null.

The initial run 40282316047 failed before VM probes during an official Debian APT
download connection reset. The failed artifact 12632218896 and raw log are
preserved; SHA256
8fc69f2978e8db093988deb41c1778c031a74cc993ac9da28ee7c11bee7a4075.
The full retry used unchanged source; no checks or artifacts were removed.
Download session 53381 and acceptance session 23824 completed successfully.

## Follow-up prepared for fresh CI

Commit b0f79d8 recomputes log package identity/version scope from both complete
package databases and the authenticated new-package plan. Existing packages may
only appear as unchanged-version trigger references; other actions fail. This
does not approve their execution, ordering, timestamps or filesystem effects.

Commit a84905a binds bounded trigger declarations to exact archive control member
bytes and fixed baseline dpkg info paths. The baseline filename comes from the
actual installed database, including Multi-Arch: same. Root ownership, mode 0644,
one link, empty xattrs and matching tree size/SHA are required. Missing baseline
packages or files remain explicit unavailable sources. Declarations alone do not
grant trigger authority. Actual baseline libc-bin/man-db bytes still need fresh
CI acquisition at this follow-up source. Never substitute guessed declarations.

758 local tests passed with 55 platform skips (703 executed successfully).
Ruff from .venv/bin/ruff, compilation and git diff --check pass. System Python
has no Ruff; use the existing environment. The independent declaration reader
checked actual accepted31 archive controls plus a SYNTHETIC baseline fixture and
rejected five altered reports. The scope reader checked saved native inputs and
rejected six alterations. Neither check proves new native execution.

The next head must pass fresh CI and full acceptance with NINE wrapper options:
--payload-closure --control-metadata --file-lists --database-files
--change-accounting --log-observation --log-decoding --log-scope
--trigger-declarations. The accepted fc81e10 source uses only the first seven.
Use outputs/run_pr134_acceptance.py and download_ci_artifact.py from repository
cwd, passing the exact run/head/stem. Inspect fresh six originals/four crops and
write their bound receipt before claiming acceptance. Detailed CI handles belong
in task-root outputs/CONTINUATION.md.

## Remaining implementation and version requirements

Bind trigger interests/activation to authenticated payload and named declarations,
then enforce event sequence, timezone/window and whole-log mutation policy. Log
syntax and identity matching alone are not authority. Validate loader-cache,
aux-cache, controller mountpoint and parent mutations rather than approving names.

Production staging still needs the native guard, PAM, Stop, sealed archive,
deadline/boot/generation bindings and complete trusted runtime/ELF/plugin/loader
immutability. Coherent activation, crash/Stop/ENOSPC/recovery, no replay, complete
conffile/generated-state/service/account/upgrade/removal policies, broad package
compatibility and full catalog/tool-registry reprobe remain incomplete. Existing
live apply does not establish full privileged runtime closure. No merge yet.

The original provider/model repair/coding/apps/connectors/profiles, physical input
and 8 GiB performance, signed OS installation/update/recovery and release gates
remain active. Physical tests were deferred by continuing in CI, not waived.
The Root tree collector is trusted TCB with SYS_ADMIN for xattrs, not an adversarial
sandbox. The .snapshots subtree exclusion is explicit; the independent reader does
not reacquire the actual filesystem. This fixture is not general package coverage.

## Disk and unrelated files

Last disk check: approximately 23.5 GiB free, 89 percent usage. No data was deleted.
Preserve these unrelated untracked duplicates:
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py
