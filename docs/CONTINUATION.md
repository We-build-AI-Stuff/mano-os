# mano-OS continuation

## Goal and execution rules

Original v2.1 phases 0–7 remain ACTIVE/incomplete; Phase 8 is optional. Frozen
specification SHA256:
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Repo We-build-AI-Stuff/mano-os; PR #134 is the current implementation PR.
Main/base remains 65fdfc02e3dbb18f791a92374a24690ae4e1ba87, verified this turn.
Use merge commits only after exact final head/current base ALL CI and relevant
security/artifact/GUI acceptance. Admin human-review override is authorized;
failed CI, branch-protection or evidence bypass is not. Evaluate CodeRabbit:
fix valid findings or explain concretely why they do not apply before merging.
Five previous threads were resolved; refresh reviews before any merge.

No human review requests/notifications, proactive subagents or other-chat messages.
Root/Linux/VM/AppArmor execution stays in disposable Debian CI, never this Mac.
No local VM/model downloads, paid-provider/key/auth experiments or silent deletion.
Warn below 20 GiB free or above 90 percent usage; stop large downloads below 10 GiB.
No agent /compact tool exists; never claim invoking it. Keep continuation current.

## Latest fully accepted native evidence

Head 8f77c70efeb254cc28d0e627bb6abb9c382a0d48, run 40286784670 ALL3SUCCESS:
security 121452205200, quality 121452205604, merge-gate 121459292079.
Artifact 12635203732: 22,934,745 bytes, SHA256
98f9f84b79478a82f28132f864bd4191db34028ef0a5991a0052183f7e8a571a.
Downloaded ZIP matches GitHub's digest. Independent acceptance passed 54 hash
checks, all 45 flags and the full package/PAM/Stop/recovery/ELF/staging chain,
including payload/control/lists/database/accounting/log bytes, 21 event frames,
20 package event identity/version matches and exact trigger declaration binding.
The strict guard still rejects 11 unresolved effects among 66 differences.

One new archive trigger file and both actual baseline trigger files were bound.
libc-bin.triggers is 440 bytes, SHA256
c3d6b5df131336e54c31dc5687929467de7abea5c5798e3d6a6b2a64ef971fd4;
man-db.triggers is 383 bytes, SHA256
0a0a9141e038168b0a6d0978584b1d74c1805d5004b5be2b07f1be1ddb886c44.
They declare ldconfig interest-await and six man-directory interest-noawait
paths respectively. These are now acquired bytes, not guesses from tree hashes.
All six fresh originals and four numeric crops were actually inspected. Full
900/120 values are readable. Bound receipt, relative to task-root outputs:
acceptance-pr134-trigger-declarations/inspection.json. Physical provenance null.
Download session 36717 and acceptance 47436 exited 0; old watcher 1886 exited 0.

## Follow-up batch awaiting its own native acceptance

Local commits after 8f77c70:
- 778e807: recomputed trigger declaration/activation source linkage.
- 76074eb: supported complete new-install and settled-trigger event sequences.
- 69cde5f: fixed worker/dpkg TZ=UTC0 and controller boot/realtime/monotonic window.
- 6e949ce: aggregate baseline declarations <=4 MiB/4096 directives and indexed names.
- 6b95aa4: mask only existing fixed private-state directories; reject aliases/parents.

783 local tests completed: 728 passed, 55 skipped. Existing .venv/bin/ruff,
compilation, embedded worker compilation and git diff --check pass. No Root or VM
execution occurred on the Mac. Local linkage and sequence implementations also
matched the newly accepted native inputs: two declaration links, 21 event frames
and two trigger cycles. Independent readers reproduced them. This is local source
on native inputs, not native execution of the new source.

The acquired declarations support libc-bin via libncurses6 activate-noawait
ldconfig, and man-db via sl's lexical /usr/share/man payload path. Actual postinst
trigger arguments and maintainer effects remain unverified, so linkage grants no
execution or publication authority. The sequence profile is explicit and rejects
unsupported/missing/overlapping state changes. It does not verify dependency order.
Clock binding requires actual controller samples, same boot, <=60-second duration,
<=2-second wall/monotonic drift and UTC event-second containment; external absolute
time authority remains false. No native samples exist for this new source yet.

Historical trees prove bubblewrap created absent var/lib/mano-provider and changed
var/lib timestamps. The new setup leaves absent private targets absent, while
masking existing directories. The independent reader requires exact masks and
unchanged private subtrees. The old native creation is correctly rejected; that
historical effect is not retrospectively approved. Synthetic mask/time tests are
not new native evidence.

## Exact acceptance for the follow-up source

After its fresh CI is terminal and all three jobs succeed, download the exact
head/run artifact and run outputs/run_pr134_acceptance.py from repository cwd
with THIRTEEN options:
--payload-closure --control-metadata --file-lists --database-files
--change-accounting --log-observation --log-decoding --log-scope
--trigger-declarations --trigger-linkage --log-sequence --log-time-window
--private-state-masks

Current accepted 8f77c70 uses only the first NINE options. Never apply newer gates
to source that lacks them. Inspect six fresh originals/four crops and bind their
hashes in a new receipt before GUI acceptance. Exact current head/run/session
handles belong in task-root outputs/CONTINUATION.md. Preserve failed evidence.

## Remaining version and merge requirements

Actual trigger argument/activation policy, dependency order, cache/aux-cache/log
and other unlisted mutations need complete validation. Production staging must
bind native PAM/Stop, sealed archives, deadline/boot/generation and full trusted
runtime/ELF/plugin/loader immutability. Complete conffile/generated-state/account/
service/upgrade/removal policies, protected-runtime updates, coherent activation,
crash/Stop/ENOSPC/recovery/no replay, broad package compatibility and full registry
reprobe remain unfinished. Existing live apply lacks complete privileged runtime
closure. No merge or candidate publication/boot activation is authorized yet.

All original provider/model repair/coding/apps/connectors/profiles, physical input
and 8 GiB performance, signed OS installation/update/recovery and release gates
remain active. Physical tests were deferred by continuing in CI, not waived.
The tree collector is trusted Root TCB with SYS_ADMIN for xattrs, not an adversarial
sandbox. The .snapshots exclusion remains explicit; independent acceptance does
not reacquire the filesystem. The fixed fixture is not general package coverage.

## Disk and unrelated files

Last approximately 23.5 GiB free, 89 percent usage. No data deleted. Preserve:
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py
