# mano-OS continuation

## Objective and rules

Original v2.1 phases 0–7 remain ACTIVE/incomplete; Phase 8 is optional. Frozen
specification SHA256:
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Repo We-build-AI-Stuff/mano-os, PR #134. Last verified main/base:
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Refresh before merge. Merge commits
only after exact final head/current base ALL CI and required real security/
artifact/GUI evidence. Human-review admin override is authorized; failed-CI,
protection or evidence bypass is not. Evaluate CodeRabbit: fix valid findings or
explain concretely why inapplicable. Five previous threads were resolved; refresh
before merge. No human review requests/notifications or other-chat messages.

No proactive subagents. Root/Linux/VM/AppArmor/tracer execution stays in disposable
Debian CI, never Mac. No local VM/model downloads, paid-provider/key/auth experiments
or silent deletion. Warn below 20 GiB free or above 90 percent; stop large downloads
below 10 GiB. No agent /compact tool exists; never claim invoking it.

## Latest fully accepted native source

Head 2011fddef433a894e8e04d8dc4efb4f01f1f5f54, run 40325437426 ALL3SUCCESS:
quality 121580809296, security 121580809790, merge-gate 121591898434.
Artifact 12651604704: 22,991,681 bytes, SHA256
0bf8fd352f1e0c71d85b4dcb50afd93a1927d6bf0cff6cc92f08df7361be14f3.
ZIP matches GitHub's digest. Independent 54-hash/45-flag acceptance and the full
package/PAM/Stop/recovery/ELF/staging chain passed all fourteen options.

The independent verifier initially omitted the two trace assets from its exact
manifest set. It was corrected to add only staged-exec-trace.txt and
staged-strace-version.txt when trace acceptance is requested. Exact set equality,
all hashes and every preceding gate remain required; the same unchanged artifact
then passed. No CI rerun or probe bypass. The initial full local log was overwritten
by the wrapper; an accurate record from observed tool output is retained as
pr134-exec-trace-initial-manifest-failure.json. The wrapper now rotates existing
acceptance logs before retry, preventing this recurrence.

Native raw trace: 15,864 bytes, 29 lines, SHA256
6cacfecc59faf8360c9a4bbaee5bbd2f800d6aac0539f17fa6c943ed7f037899;
actual strace version 6.13. Stable Root 0600/one-link metadata and byte/hash custody
passed. It shows libc-bin.postinst triggered ldconfig and man-db.postinst triggered
/usr/share/man. These are manual raw observations, not a formal argument decoder
or callback authority proof. Schema 1.0 explicitly has no inherited-FD verification.
All-exec coverage, script bytes at exec, argument decoding and authority stay false.

The strict guard still accounts for 55 of 64 differences and rejects nine unknown
effects. No publication. Six fresh originals and four numeric crops were actually
inspected; full 900/120 values are visible. Receipt under task-root outputs:
acceptance-pr134-exec-trace/inspection.json. Physical provenance null. Download
75193 and full acceptance 40478 exited 0; old watcher 60189 exited 0. Earlier
accepted sources and failed bootstrap custody remain in prior artifacts/history.

## Follow-ups need their own native source run

4339994 adds the worker's /proc/self/fd snapshot before dpkg: only 0/1/2 permitted;
closed enumeration entries ignored only on EBADF; live extras or other errors fail.
The controller requires empty nonstdio_fds and inherited_fd_scope_verified=True.
Trace schema 1.1 identifies this check. Independent acceptance requires its worker
facts for 1.1, while old 1.0 remains readable with explicit FD verification false.
This snapshot does not prove all subsequent descriptors or trace coverage.

80d3fbd adds bounded loader-cache decoding and fixed cache/tree byte binding.
Supported profile: glibc new 1.1 little endian, zero hwcap/OS-version fields,
optional opaque generator. Raw bytes, counts, string expansion and extension
ranges are bounded; suffix-shared strings are valid. No referenced library is
opened/loaded. Flags, search order, generator identity, unused bytes, library
objects, regeneration and mutation authority remain unverified. Existing ldconfig
diagnostics remain separate. Strict accounting does not approve the changed cache.

798 local tests: 743 passed, 55 skipped. Ruff from .venv/bin/ruff, compilation and
diff checks pass. The local decoder and independent reader reproduced 568/573
entries from accepted ef19cf4 native bytes and rejected seven altered reports.
Five additions are form/menu/ncurses/panel and the unapproved synthetic fixture.
This is local source on native inputs, not new-source VM execution. Mocked FD tests
and synthetic FD-reader checks similarly do not prove a native descriptor census.
Pinned glibc-2.41 header: Git blob 0ee6571315630fb8156d633c48c86b1086dbcd43,
SHA256 d82003ce9e95ffb9fe685426e7591784d9296b2e7fbfa2a519168c5884b5d881.

## Exact acceptance and next work

Current exact source/run/session handles belong in task-root outputs/CONTINUATION.md.
After the follow-up run is terminal and all three jobs succeed, download its exact
artifact and use run_pr134_acceptance.py from repository cwd with FIFTEEN options:
--payload-closure --control-metadata --file-lists --database-files
--change-accounting --log-observation --log-decoding --log-scope
--trigger-declarations --trigger-linkage --log-sequence --log-time-window
--private-state-masks --exec-trace --loader-cache

Accepted 2011fdd uses only the first FOURTEEN; it has no descriptor check or cache
observer. Never promote an older schema/source to stronger verification. Inspect
six fresh originals/four crops and write their bound receipt before GUI acceptance.
The actual trace is preserved as pr134-2011fdd-exec-trace.txt. Next implement a
bounded strict trace decoder using that native form; do not execute trace content.
Then bind actual callback names to declarations/activation and script provenance.

## Remaining complete-version and merge requirements

Actual trigger argument/activation policy, dependency order, complete cache/aux-
cache/log/unlisted mutation validation remain. Production staging must bind native
PAM/Stop, sealed archives, deadlines/boot/generation and full trusted runtime/ELF/
plugin/loader immutability. Complete conffile/generated-state/account/service/
upgrade/removal policies, protected-runtime updates, coherent activation, crash/
Stop/ENOSPC/recovery/no replay, broad package compatibility and full registry
reprobe remain unfinished. Existing live apply lacks complete privileged runtime
closure. No merge, publication or boot activation yet.

All original provider/model repair/coding/apps/connectors/profiles/hardware,
physical input and 8 GiB performance, signed OS installation/update/recovery and
release gates remain active. Physical tests were deferred by continuing in CI,
not waived. Root collectors/tracer are trusted inspection TCB, not adversarial
sandbox proof. The .snapshots exclusion is explicit; independent acceptance does
not reacquire the actual filesystem. The fixture is not general compatibility.

## Disk and preservation

Disk fell near 20.1 GiB/90 percent and the user was warned. Latest about 21.3 GiB,
still near 90 percent; no data deleted. Recheck before downloads. Preserve unrelated
untracked duplicates:
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py
