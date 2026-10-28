# mano-OS continuation — current state and full scope

Updated 2026-10-28. Full original v2.1 phases 0–7 remain ACTIVE/incomplete;
Phase 8 is optional. Frozen requirements: docs/spec-v2.1.md, SHA256
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Never redefine completion around the prototype/CI evidence below.

## Current checkout, CI and next action

- Repository: We-build-AI-Stuff/mano-os, PR #134, feat/approved-package-apply.
- Remote head: 3729ef2afe04c7fadeb17483cea2f4942d4bfea7.
- Local implementation head: d121ce5 (virtual metadata helper, not pushed).
- Base last verified: 65fdfc02e3dbb18f791a92374a24690ae4e1ba87.
- Run 40700950648: quality 122860281543 SUCCESS, 895 tests with one Mac-specific
  skip; recorded alignment regression and both native GNU DBM crosschecks pass.
- Security job 122860282032 is still live. Current fresh regeneration, loopback
  fix, canonical integration, merge-gate, artifact acceptance and UI are pending.
- Exact-run one-shot: task outputs/continue_pr134_canonical_cache.py, local exec
  session 1966; log pr134-canonical-cache-continuation.log. One transient API
  error was observed; it retries the SAME run. Re-poll the same live handle.
- It saves failed-run custody only on failure; on ALL3SUCCESS checks artifact
  digest, tested merge base/head parents, thirteen runtime/probe source files
  and all TWENTY-SIX acceptance options. It never reruns CI, merges or blesses UI.
- Artifact stem: pr134-man-canonical-security (or -canonical-failed-security).
- Do not push while the current run is live: workflow cancels earlier runs.
  A timeout/API error is not terminal. A missing handle requires API/log checks.
- After success, inspect actual raw and derived cache artifacts independently,
  then view six fresh UI originals and eight crops/contact sheet. Write a new
  exact-head/run/artifact/digest 15-image receipt. Never reuse an older receipt.

Task-root outputs/CONTINUATION.md holds local handles and last observation times.
The full older continuation files are preserved in outputs/continuation-*-archive-*.md;
Git history and docs/architecture/0117-staged-package-feasibility.md retain history.
No agent /compact tool exists; never claim one was invoked. Keep this file compact.

## Latest fully accepted native evidence

Head d59f36e9948e754b86e9fb87fdbdd5db9b85c864 / run 40621100477 passed all three
jobs: quality 122595065461 (855 tests), security 122595065099, gate 122601841693.
Artifact 12788132725: 23,612,862 bytes, SHA256
33a18552aca152a9199c58ae90cd1050a24904e31fde2782b48482c97f85447e.
Tested merge 7c91eaf297157758222b19b2bad80aad99e48aeb has expected base/head
parents and five matching source files. All 24 staging options and prior complete
54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed independent acceptance.
Six originals/eight crops/contact sheet were actually viewed; receipt in task
outputs/acceptance-pr134-gdbm-decoding/inspection.json binds all 15 PNGs. Full
900/120 values are readable; physical input provenance is null (headless only).

Native accounting is 107/125, with 18 effects UNAPPROVED: etc, etc/ld.so.cache,
usr/local/lib plus the two synthetic library names, usr/share/.mano-staged-ci-control,
var/cache/ldconfig and aux-cache, new de.UTF-8/ja.UTF-8 man-cache directories/cat6/
indexes, modified root/de/ja indexes, and var/log/dpkg.log. Keep the negative guard;
never whitelist synthetic canary/library effects to claim completion.

## Two failed follow-ups — not acceptance

- d356534 / run 40693734664: quality passed 864 tests; security 122834882711 and
  gate 122844329045 failed before man worker start. Bubblewrap could not initialize
  private loopback; missing setup NET_ADMIN is the likely cause. Artifact
  12819527130, 3,555,571 bytes, SHA256
  17fdde931c4ed63f4b7ffd2718c9bfb7a1fec1afaa2b6dc5a19fbd1dce7c64ed.
- f49cc1d / run 40697287147: quality passed 888 tests; security 122847338031 and
  gate 122857057502 failed BEFORE regeneration. Trace parser rejected normal
  result-column padding on resumed PID 7892, entry 12/completion 14. Artifact
  12821036891, 2,909,581 bytes, SHA256
  c98ec01331b7079eaf538e3697c443609de12455d43ae93066bb11ad3f4d3f25.

Both exact logs, failed artifacts and proofs remain under task outputs. The
recorded 16,829-byte trace is tests/fixtures/exec-trace-f49cc1d-aligned-resume.txt.
Both decoders agree locally on 62 lines, 30 calls, 31 terminal events. Parser now
allows only 1–64 literal spaces at the return separator, keeping all argument,
PID/resume, exact return and resource checks. Failed runs remain failed.

## Current implementation and evidence limits

CI staging clones an immutable baseline and writable unpublished candidate. The
trusted tracer preserves bounded exec/exit frames. Callback arguments and normal
zero exits are checked, but complete coverage, ancestry, credentials at each exec,
script bytes at exec and activation/effect authority remain unproved.

Fresh-cache experiment uses read-only baseline tools/config, read-only candidate
/usr/share/man, and an empty independent 16 MiB tmpfs. Setup alone receives
NET_ADMIN; bubblewrap drops it before setpriv clears groups and all capability sets.
The UID 6/GID 12 worker guard requires all five capability sets to be exactly zero.
Tree/raw database/failure witnesses are retained before later checks. This complete
current experiment has not passed native security yet. Production securebits stay
43; CI staging uses separately tested 11 under 0xdb/NNP/private namespaces. The
production keep-caps compatibility gap is not fixed by changing this experiment.

Pure Python decodes retained GDBM active records, builds complete deterministic
standard GDBM bytes, parses man-db 2.5.0 frames and resolves internal multi-keys.
No native database library reads staged data on Mac. Linux quality native tests
read/update only self-created synthetic files (including canonical empty/single/
max-frame/split fixtures); this is narrower than native staged-cache acceptance.

Current source adds three derived artifacts: staged-man-canonical-bytes.json,
staged-man-canonical-frames.json and staged-man-canonical-sources.json. Raw files
remain separate. Caps: 64 databases, 8 MiB raw/canonical totals, 65,536 records,
16 MiB/report, 32 MiB combined. Every derived byte/report is independently rebuilt.
All source/include/description/filter and generated-state/publication flags stay
false. Old retained native24 local integration: 5 databases, 3,881 records,
622,592 input bytes, 514,560 canonical bytes, 3,247,294 artifact bytes. Fourteen
altered claims/artifacts reject. This is not current fresh-generation evidence.

Primary metadata locally binds all 3,606 candidate A/B records; baseline has six
missing primary sources (3,596/3,602 bind). Links use their own lstat timestamps.
The 224 virtual C aliases remain source-declaration-unverified. New unused local
package_man_virtual_metadata resolves their pointers to unique A/B records in the
same index with exact name/section/extension/compression/filter/time and bound
primary metadata. Both implementations match all 224 on old retained data; seven
mismatch cases agree as unresolved. It never treats aliases/pointers as paths.
This helper is NOT wired or pushed and does not change current gate26 verification.
Local focused suite: 152 tests, 143 pass, nine Linux-only skips. Lint/diff pass.

Research GNU GDBM 1.24/man-db 2.13.1 source tarballs were read as data, matched to
HTTPS DSC size/SHA; PGP signatures were not verified. Never build/execute them
or present research provenance as production admission.

## Current acceptance options

Native24 uses first 24; current source requires ALL 26, in order of dependency:

--payload-closure --control-metadata --file-lists --database-files
--change-accounting --log-observation --log-decoding --log-scope
--trigger-declarations --trigger-linkage --log-sequence --log-time-window
--private-state-masks --exec-trace --loader-cache --exec-decoding
--command-diagnostics --uid-drop-comparison --compatible-stage
--process-outcomes --trigger-arguments --cache-tag-metadata
--man-cache-bytes --gdbm-decoding --man-regeneration --man-canonical

Use task outputs/run_pr134_acceptance.py from repository cwd. Fixed artifact
names differ by explicit option. Never promote an older schema to stronger proof.

## Full remaining scope and merge rules

Finish callback script/caller/activation authority, dependency ordering, complete
manual source/include/link/description/filter/cache/tag/loader/aux-cache/log and
unlisted-mutation policy. Production staging must bind native PAM/Stop, sealed
archives, deadlines/boot/generation and full privileged runtime ELF/plugin/loader
immutability, including protected updates. Complete conffile/account/service/
upgrade/removal policies, broad package compatibility/full registry reprobe,
coherent activation, crash/Stop/ENOSPC/recovery/no replay remain unfinished.

All original provider/model repair/coding/apps/connectors/profiles/hardware,
physical input and 8 GiB performance, signed OS install/update/recovery/release
gates remain. Physical tests were deferred by continuing in CI, not waived.
The Root collectors/tracer are trusted inspection TCB, not adversarial confinement
proof. .snapshots exclusion is explicit; independent acceptance does not reacquire
actual filesystem contents. Fixed fixtures are not general compatibility evidence.

Merge commits only after current-base/exact-final-head ALL CI, real artifact/
security/UI evidence and review findings are addressed. Human-review admin
override is authorized; failed CI/protection/evidence bypass is not. Assess
CodeRabbit findings on merit: fix genuine issues or post a concrete reason when
incorrect/inapplicable/stale/already fixed. Last pre-push check: five resolved
threads; refresh before later pushes/merges. No reviewer notifications/requests,
proactive subagents, other-chat messages, paid-provider/key/auth experiments.

## Host safety and preservation

Root/Linux/VM work ONLY in disposable Debian CI; never on the Mac. Ordinary
unprivileged portable Python/file/data checks are allowed. Never use a native
DB library on untrusted staged bytes on Mac. No local VM/model downloads.
Disk last ~48 GiB free / 76% used. Warn below 20 GiB or above 90%; stop new large
downloads below 10 GiB. Never silently delete user data. No data was deleted.
Preserve unrelated untracked duplicates:
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py

Local full discovery previously blocked in kernel reads of shared dependency
files/pyc; do not retry full imports, reinstall dependencies or delete caches on
a timeout. Focused portable checks work; exact-head completed CI logs are full
suite evidence. Saved diagnostic samples/logs remain under task outputs.
