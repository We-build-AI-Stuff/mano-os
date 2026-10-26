## Local bounded loader-cache observation (not pushed)

package_loader_cache observes glibc new-format 1.1 little-endian caches with zero
hwcap/OS-version fields and an optional opaque generator extension. It bounds
raw bytes, entry counts, string offsets/termination and expanded strings, checks
reserved bytes and extension ranges, preserves suffix-shared C strings, and
rejects unsupported formats/metadata. Library flags remain uninterpreted; no
library is opened or loaded. Fixed etc/ld.so.cache bytes must match Root 0644/
one-link/xattr-free baseline and candidate tree entries.

798 local tests: 743 passed, 55 skipped. Nine cache tests cover malformed headers,
pointers, strings, extensions, quota, C-string termination and metadata/byte binding.
Ruff/compile/diff pass. The local decoder on accepted ef19cf4 native bytes reads
568 before/573 after entries; five additions include four ncurses-family libraries
and the unapproved synthetic fixture. An independent implementation reproduces
both tables and rejects seven altered reports. This is LOCAL source against native
input, not new-source native execution. The cache and library effects stay blocked.

Pinned reference: glibc-2.41 dl-cache.h Git blob
0ee6571315630fb8156d633c48c86b1086dbcd43, SHA256
d82003ce9e95ffb9fe685426e7591784d9296b2e7fbfa2a519168c5884b5d881.
The CI-only probe now emits loader_cache_observation alongside the unchanged
ldconfig diagnostic. Future source acceptance adds --loader-cache after --exec-trace
(FIFTEEN options). Current remote 2011fdd run uses fourteen; it cannot prove this
observer or the local inherited-descriptor guard. Keep both follow-ups local until
that run's source and artifact are accepted.

## Local inherited-descriptor check (not pushed)

The worker now enumerates its actual /proc/self/fd before invoking any package.
Only descriptors 0/1/2 are permitted. An already-closed enumeration descriptor is
ignored only on EBADF; other errors or any live extra descriptor abort. The worker
reports its empty nonstdio_fds and inherited_fd_scope_verified=True, and the
controller checks them. This snapshot does not prove every later descriptor or
all execution coverage.

Execution-trace observation schema 1.1 identifies this additional requirement.
The independent reader requires both worker facts for 1.1; archived schema 1.0
remains readable but explicitly returns inherited-descriptor verification false.
The number of acceptance flags remains fourteen. Current remote 2011fdd/run
40325437426 uses schema 1.0 and cannot prove this local check. Keep it unpushed
until that run's source and artifacts are accepted.

789 local tests: 734 passed, 55 skipped. Two additional tests execute only the
isolated helper AST against mocked descriptor operations, without Linux/Root calls
on the Mac. Independent SYNTHETIC selfcheck rejects unexpected live descriptors
and false verification, and does not upgrade legacy evidence. No native descriptor
census exists for this source yet. Trace arguments/contents/coverage/authority
remain unverified; the full original goal remains active.

# mano-OS continuation

## Objective and rules

Original v2.1 phases 0–7 remain ACTIVE/incomplete; Phase 8 is optional. Frozen
specification SHA256:
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Repo We-build-AI-Stuff/mano-os, PR #134. Last verified main/base:
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Refresh before any merge.
Merge commits only after exact final head/current base ALL CI plus required
security/artifact/GUI acceptance. Human-review admin override is authorized;
failed-CI/protection/evidence bypass is not. Assess CodeRabbit findings: fix valid
issues or explain concretely why inapplicable. Five prior threads were resolved;
refresh reviews before merge. No reviewer notifications or review requests.

Root/Linux/VM/AppArmor/tracer execution stays in disposable Debian CI, never Mac.
No proactive subagents, other-chat messages, paid-provider/key/auth experiments,
local VM/model downloads or silent deletion. Warn below 20 GiB or above 90 percent;
stop large downloads below 10 GiB. No agent /compact tool exists; never claim using
it. Keep this file current. Preserve the three unrelated untracked duplicate files.

## Latest fully accepted native source

Head ef19cf4adc34787a61e283a0802febde1457cea3, CI 40321845193 ALL3SUCCESS:
security 121568468226, quality 121568468448, merge-gate 121577494621.
Artifact 12650077946: 22,961,675 bytes, SHA256
08f5e6ed3ab673b8ff5c39004877a60a3935ba6ec7d0ab8803a13bcf2d241e17.
ZIP bytes match GitHub's digest. Full independent 54-hash/45-flag acceptance and
all package/PAM/Stop/recovery/ELF/staging gates passed, including all thirteen
current optional gates. Download 57632 and acceptance 83756 exited 0. Old watcher
14849 exited 0. Same slow download was retained; scoped network evidence showed
14 MB received before completion. No duplicate or observation-timeout restart.

Native declaration linkage: two referenced baseline packages and two supported
activation sources. Native sequence: 21 event frames and two complete trigger
cycles. Controller-relative UTC containment recomputed over 649000902 monotonic
nanoseconds. This is one bounded fixture observation, not a performance benchmark
or an external absolute-time authority. Actual postinst arguments remain unverified.
Existing /var/lib/mano-broker was masked and both captured private entries remained
unchanged; absent provider state remained absent. The strict guard accounts for
55 of 64 differences and rejects nine unresolved effects. No publication authority.

All six fresh GUI originals and four numeric crops were actually inspected;
full pending/effective 900/120 values are readable. Receipt under task-root outputs:
acceptance-pr134-combined-log-guards/inspection.json. Physical provenance null.
Earlier native 8f77c70 declaration evidence and failed bootstrap evidence remain
preserved in prior artifacts and Git/architecture history.

## Trace capture follow-up needs its own native evidence

Implementation commit 69b19f15ddb94736a4d814127e5b1ad601ab4742 adds CI-only
strace to collect execve/execveat bytes outside the candidate namespace. It follows
forks, emits hex strings, kills tracees on tracer exit and never uses syscall-count
detachment. The raw target is precreated Root 0600 inside the new controller BASE
mode-0700 directory hidden behind the candidate's snapshot mask. The unit keeps
memory/task/runtime limits and adds a 16 MiB file-size ceiling, also checked through
the actual worker resource limit. Existing worker capability checks remain intact.

Successful trace observation requires stable regular Root 0600/one-link metadata,
nonempty bytes below the quota and exact hash/size. Raw bytes and actual utility
version are SHA-bound artifacts. Failed runs retain bounded partial bytes with
worker_failed metadata and cannot satisfy acceptance. The tracer is trusted Root
inspection TCB, not a sandbox. CLONE_UNTRACED and other coverage limitations remain
explicit: all_execs_observed, arguments_decoded, script_contents_at_exec_verified,
trigger_authority_verified and publication_authorized all remain false.

787 local tests: 732 passed, 55 skipped. Ruff from .venv/bin/ruff, compilation,
embedded fixed worker compilation, shell syntax and diff checks pass. Mocked FD/
command tests and the independent opaque-byte selfcheck are SYNTHETIC, not Root
or tracer execution on this Mac. The new source needs its own native run. Do not
infer a parser or callback policy from guessed trace syntax; inspect actual data.

## Acceptance and continuation

Exact new source/run/session IDs belong in task-root outputs/CONTINUATION.md.
After its fresh CI is terminal and all three jobs succeed, use the exact source
head with download_ci_artifact.py and run_pr134_acceptance.py from repository cwd.
The trace source requires FOURTEEN options:
--payload-closure --control-metadata --file-lists --database-files
--change-accounting --log-observation --log-decoding --log-scope
--trigger-declarations --trigger-linkage --log-sequence --log-time-window
--private-state-masks --exec-trace

Accepted ef19cf4 uses only the first THIRTEEN; it has no tracer. Inspect six fresh
originals and four numeric crops and bind their hashes in a new receipt before GUI
acceptance. Preserve failure custody; a polling timeout does not stop a live job.
System Python has no Ruff; use the existing environment.

## Remaining full version and merge requirements

Actual trigger argument/activation policy, dependency ordering and complete
cache/aux-cache/log/unlisted mutation validators remain. Production staging must
bind native PAM/Stop, sealed archives and deadline/boot/generation to complete
trusted runtime/ELF/plugin/loader immutability. Complete conffile/generated-state/
account/service/upgrade/removal policies, protected-runtime updates, coherent
activation, crash/Stop/ENOSPC/recovery/no replay, broad package compatibility and
full catalog/tool-registry reprobe remain unfinished. Existing live apply lacks
complete privileged runtime closure. No merge, publication or boot activation yet.

All original provider/model repair/coding/apps/connectors/profiles/hardware,
physical input and 8 GiB performance, signed OS installation/update/recovery and
release gates remain active. Physical tests were deferred by continuing in CI,
not waived. The tree collector is trusted Root TCB with SYS_ADMIN xattr visibility,
not an adversarial sandbox. The .snapshots exclusion is explicit; independent
acceptance does not reacquire the actual filesystem. The fixture is not general
package compatibility evidence.

## Disk and unrelated files

Disk fell near 20.1 GiB/90 percent; user was warned. Most recent check recovered
to about 21 GiB free, still near 90 percent. Recheck before downloads; no data was
deleted. Preserve unrelated untracked files:
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py
