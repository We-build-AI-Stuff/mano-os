# mano-OS continuation — full goal remains active

Updated 2026-10-29. Original v2.1 phases 0–7 are ACTIVE/incomplete; Phase 8 is
optional. Specification: docs/spec-v2.1.md, SHA256
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Do not redefine completion around a prototype, CI slice or the checks below.

## Repository and latest accepted source

We-build-AI-Stuff/mano-os; PR #134; branch feat/approved-package-apply.
Accepted head ab85fb7a7bcd9a3f2cd6d58489967091a98522db, base
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Tested merge
c0966a68bd8fce3066b571f54f98f3d15d90c6ea has exactly those parents;
sixteen runtime/probe/native/workflow source files match the head.

CI run 40802181056 ALL THREE SUCCESS:
- quality 123212611617: 906 tests, one Mac-specific skip; strict native guard
  compilation and wrong-user/arbitrary-command refusals passed.
- security-lab 123212611801; merge-gate 123220553066.
- Artifact 12867512215: 24,887,122 bytes, SHA256
  5fe4de70f6e39d700b051b549bd2475e344a20fdbf38c6a8cbc5ad9d1e83dee5.
- Fixed observer exec 75723 COMPLETED ZERO. Do not restart it. All 27 staging
  gates plus the prior 54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed.
- Six fresh UI originals and eight crops/contact sheet ACTUALLY viewed; 15-PNG
  receipt: task outputs/acceptance-pr134-man-input-policy/inspection.json.
  Full 900/120 values are legible; pending/effective numeric pixels identical.
  Headless only; physical input provenance remains null.

Exact proof/logs in task outputs: pr134-ab85fb7-native27-proof.json,
pr134-ab85fb7-{quality,security}-completed-job.log, quality-proof.json,
pr134-man-input-policy-{security-acceptance,continuation}.log and artifact
metadata/ZIP. Prior native26 head3729ef2/run40700950648 is historical evidence.
All older detailed continuation files are archived under task outputs and Git.

## What native27 actually demonstrated

Fixed cache guard requires UID6/GID12, empty groups, NNP1 and all five capability
sets ZERO. Debian kernel reported Landlock ABI6. Positive-before/denied-after
file read/write and temporary executable controls passed, as did cache writes,
namespace/identity syscall denials and restriction inheritance after child exec.
The fixed mandb runs against baseline programs/config and candidate manuals,
read-only, in private namespaces and an empty independent 16 MiB cache.

Control and restricted runs use separate caches and drained domains. Their
complete logical maps match: 28 indexes, 4,862 records. The test-owned control
fixture retained its bytes and metadata. Both raw bundles even share SHA256
69f955da6fe2785499506a785144fa747b4b37df917a5223080a5ed8ee8a422f.
Each contains 1,040,384 database bytes. All five changed candidate indexes
match fresh records. Canonical output is 670,720 bytes; all 4,515 primary records
bind observed source metadata. Input trees and live inputs stayed unchanged.
These are fixed CI observations, not complete source semantics or publication.

The setup-only capability ceiling includes NET_ADMIN for private loopback.
Bubblewrap drops it before setpriv clears groups and every capability set.
Existing general task guard and production package executor are unchanged.
Production securebits43 UID-drop compatibility is still unfinished; CI profile11
is separate evidence. Native27 does not fix that production gap.

## Prepared source-metadata integration, not yet native28 accepted

Feature commits 6b3b507,263d6f1,d7e2527 follow accepted head ab85fb7. Before the
next push refresh base/reviews/disk; next exact-head CI and gate28 are required.

Canonical derivation now takes baseline_tree and emits two additional artifacts:
staged-man-source-links.json and staged-man-virtual-targets.json. The source
walker respects path order (link/.. must follow the link first), real/owned
parents and cycle/depth/path/report limits. It binds an opaque terminal file
hash without opening those paths or interpreting source bytes.

Runtime metadata models candidate /usr/share/man over a baseline root. Exact
root-owned absolute /etc/alternatives selectors require trusted baseline parents
and candidate-selector equality, and must return into manuals. Generic external
or unsupported relative selectors remain unbound. Selector/manual hops share
one depth limit. No filesystem permission or native guard is broadened.

Two independent implementations agree on all 4,515 primary chains, including
62 alternatives selectors, and all 248 virtual target chains in ACTUAL retained
native26 and native27 inputs. Virtual pointer names remain inert base64 data.
Metadata matching alone cannot count as a target chain unless its primary
runtime chain also binds. Alias declarations/includes/descriptions/filter
semantics, generated state and publication all remain FALSE.

Local integration independently reconstructs all five artifacts exactly,
8,330,674 combined bytes, within the 32 MiB budget. Existing three native27
canonical artifacts and summary are unchanged by the optional extension.
Focused suite: 90 tests, 89 pass and one Linux-only skip; repo lint/diff pass.
Ten altered integrated-evidence cases reject, including false authority and
terminal-hash forgery with rebound artifact hash. Fifteen selector fixtures
agree; source-link boundary tests include cycles, escapes and link/.. handling.
Evidence: task outputs/pr134-man-source-metadata-native{26,27}-*selfcheck.json
and pr134-man-runtime-source-links-native26-*selfcheck.json.

New explicit --man-source-metadata is gate28 and requires all earlier 27 gates.
All 27 omitted dependencies reject. The gate27 path retains its original
canonical checker. Independent checker: task outputs/accept_man_source_metadata.py.
Next staging artifact count55. Local/data-only results are not fresh native28 CI.

## Current implementation boundaries and rejected effects

Accounting is still 107/125; 18 effects are UNAPPROVED:
etc, etc/ld.so.cache, usr/local/lib, its two synthetic fixture libraries,
usr/share/.mano-staged-ci-control, var/cache/ldconfig and aux-cache,
new de.UTF-8/ja.UTF-8 man-cache locale/cat6/index paths, modified root/de/ja
indexes, and var/log/dpkg.log. Never whitelist synthetic negatives to finish.
No candidate is published, installed as a generation or selected for boot.

Trusted tracer retains bounded exec/exit frames; fixed callback identities,
arguments and normal zero exits are checked. Full execution coverage, caller
ancestry/credentials, script bytes at exec and effect authority stay unverified.
Root tree collectors/tracer are inspection TCB, not adversarial confinement
proof. .snapshots exclusion is explicit; independent readers do not reacquire
filesystem contents. Fixed fixture compatibility is not general compatibility.

Pure Python decodes active GDBM records and complete deterministic encoding,
parses man-db 2.5.0 frames/references and computes source metadata. No native
DB library reads staged data on Mac/Root. Native Linux quality DB tests use
only self-created synthetic files. Research source archives were read as data,
matched HTTPS DSC hashes; PGP signatures were not verified or code executed.

Earlier failed runs d356534/40693734664 (loopback setup) and
f49cc1d/40697287147 (strace result padding) remain failed custody. The padding
fixture is tests/fixtures/exec-trace-f49cc1d-aligned-resume.txt; bounded literal
spaces preserve argument/return/PID checks. Later green CI does not rewrite
those failed outcomes. All old logs/artifacts are retained.

## All acceptance dependencies

Native27 uses the first27; new source requires ALL28:
--payload-closure --control-metadata --file-lists --database-files
--change-accounting --log-observation --log-decoding --log-scope
--trigger-declarations --trigger-linkage --log-sequence --log-time-window
--private-state-masks --exec-trace --loader-cache --exec-decoding
--command-diagnostics --uid-drop-comparison --compatible-stage
--process-outcomes --trigger-arguments --cache-tag-metadata
--man-cache-bytes --gdbm-decoding --man-regeneration --man-canonical
--man-input-policy --man-source-metadata

Use task outputs/run_pr134_acceptance.py from repository cwd. Each option has
an explicit artifact set; never promote an old schema to stronger proof.
Every new source needs current-base/exact-head CI, real artifacts, independent
acceptance and fresh actual UI inspection/receipt before any merge decision.

## Full remaining goal and merge rules

Finish callback script/caller/activation authority, dependency order, complete
manual source/include/link/description/filter/cache/tag and loader/ELF/search/
aux-cache/log/unlisted-mutation policy. Production staging must bind native
PAM/Stop, sealed archives, deadlines/boot/generation and complete privileged
runtime/plugin/loader immutability, including protected updates. Complete
conffile/account/service/upgrade/removal policies, broad package compatibility,
full registry reprobe, coherent activation and crash/Stop/ENOSPC/recovery/no
replay remain unfinished.

All original provider/model repair/coding/apps/connectors/profiles/hardware,
physical input and 8 GiB performance, signed OS installation/update/recovery/
release gates remain. Physical tests were deferred by continuing in CI, not
waived. Full original phases0–7 stay active. Green prototype CI is not completion.

Merge commits only after current-base/exact-head ALL CI, real security/artifact/
UI evidence and genuine review blockers resolved. Admin human-review override
is authorized; failed CI/protection/evidence bypass is not. Evaluate CodeRabbit
findings on merit: fix valid ones, or post a concrete reason for dismissal before
an otherwise eligible merge. Latest refresh: five threads, all resolved.
No reviewer notifications/requests, proactive subagents, other-chat messages or
paid-provider/key/auth experiments. No new merge is authorized by this document.

## Mac safety, disk and preservation

Root/Linux/VM probes ONLY disposable Debian CI. Ordinary unprivileged portable
Python/file/data analysis is allowed Mac. Never run native DB readers on staged
bytes there. Keep VM images/models off Mac; no silent user-data deletion.
Disk last43 GiBfree/79%; warn <20 GiB or >90%, stop large downloads <10 GiB.
Preserve unrelated duplicate files (do not stage/delete):
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py

Full local discovery previously blocked in shared dependency/pyc filesystem
reads. Do not delete caches, reinstall or infer test assertion failures from
observation timeouts. Focused portable checks work; completed exact-head quality
logs are full-suite authority. Retain diagnostics and resume confirmed handles.

No agent /compact tool exists; do not claim one was invoked. Keep continuation
compact and preserve older records via task-output archives/Git history.
