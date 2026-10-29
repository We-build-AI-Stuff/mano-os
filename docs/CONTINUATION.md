# mano-OS continuation — current state and full scope

Updated 2026-10-29. Full original v2.1 phases 0–7 remain ACTIVE/incomplete;
Phase 8 is optional. Frozen requirements: docs/spec-v2.1.md, SHA256
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Never redefine completion around the prototype/CI evidence below.

## Prepared paired input-policy experiment — native verification pending

The new fixed CI-only `native/mano_man_cache_guard.c` requires UID 6/GID 12,
empty groups, NNP and zero capability sets. Landlock ABI 5+ limits readable
inputs and writable cache/tmp trees; seccomp denies privilege/namespace changes
and network socket families. It reports positive-before/negative-after file and
temporary-executable controls, plus inherited restrictions after child exec.
The existing general task guard and production package executor are unchanged.

The controller now runs an unrestricted comparison and the restricted generator
against the same immutable inputs in separate empty 16 MiB caches. Both process
domains must drain. A public test-owned control file must retain its bytes and
metadata. Both complete logical index maps must match; the control is never a
fallback or publication authority. Source, binary, both raw worker reports,
both tree/byte witnesses and the policy-pair report are retained and hashed.

Local checks: 73 focused tests, 72 passed and one Linux-native-only skip;
repository lint and diff whitespace checks passed. Native C compilation and
successful kernel enforcement have NOT been tested on this Mac. Independent
acceptance adds explicit option 27, `--man-input-policy`, depending on all prior
26 options. The new checker and its CLI wiring still need native artifacts. Eleven
altered-evidence self-checks reject, including a record change with rebound hashes. No new native run has been accepted. Last accepted evidence
below remains the previous source, not proof for these new changes.

## Baseline alternatives metadata binding prepared locally

The optional runtime-overlay source-link profile now checks both complete tree
digests, uses candidate /usr/share/man with baseline ancestor metadata, and binds
only exact root-owned absolute /etc/alternatives selectors with trusted baseline
parents. Each selector must match its candidate counterpart and return inside
manuals; generic external files, changed selectors, cycles, unsafe parents and
unsupported relative selectors remain unbound. Combined manual/selector hops
share the depth limit. No filesystem permissions or native guards are changed.

Both independent data-only walkers now agree on all 4,515/4,515 primary chains
using retained native26 metadata, including all 62 selectors, plus 15 selector
fixtures. Evidence: task outputs/pr134-man-runtime-source-links-native26-
{local,independent-selfcheck}.json. Full roff include/alias/description/filter
semantics and production authority remain unverified. The helper is unused,
local and unpushed while native27 runs. Focused suite: 87 tests, 86 pass and one
Linux-only skip; repo lint/diff pass. Do not confuse this local analysis with
native validation of the helper or new artifacts for the running source.

## Local source-link follow-up, not part of the running CI head

New unused `package_man_source_links` walks observed symlinks component by
component inside the manual tree, enforcing ownership, real parent directories,
cycle/depth/path/report limits and a terminal regular-file metadata/content hash.
It never opens those paths or interprets source content. A second implementation
agrees on all 4,515 primary sources in accepted native26 data and 13 adversarial
cases. 4,453 bind; 62 leave the manual hierarchy through /etc/alternatives.
Do not permit arbitrary external targets. The next graph design must bind the
immutable baseline alternatives selectors actually visible to the worker, since
only candidate /usr/share/man is overlaid. Full includes/alias declarations,
descriptions/filter semantics and publication remain unverified.

Local focused suite now runs 83 tests, 82 pass and one Linux-native-only skip;
repository lint/diff checks pass. Evidence lives in task outputs under
pr134-man-source-links-native26-{local,unresolved,independent-selfcheck}.json.
The running CI remains head ab85fb7, run 40802181056; its quality job succeeded
with 906 tests (one skip), security job 123212611801 is running as of 01:53 UTC.
One-shot exec 75723 is live; do not restart it without checking its handle.

## Current checkout and accepted native evidence

- Repository: We-build-AI-Stuff/mano-os, PR #134, feat/approved-package-apply.
- Remote accepted head: 3729ef2afe04c7fadeb17483cea2f4942d4bfea7.
- Local implementation d121ce5 adds an unused virtual metadata helper; local
  16341a4 condenses continuation history. Neither is pushed yet.
- Base last verified: 65fdfc02e3dbb18f791a92374a24690ae4e1ba87.
- Run 40700950648 ALL3SUCCESS: quality 122860281543 (895 tests, one Mac-specific
  skip), security 122860282032, merge-gate 122873536590.
- Artifact 12822079446: 24,521,872 bytes, SHA256
  277e10de15f373f613cdacc893bb042bc2dba07effa1bca59dae6edebd18e292.
- Tested merge 5737edb307d7a906815bee3dee4526812586a421 has expected base/head
  parents and thirteen identical runtime/probe source files.
- One-shot local exec 1966 exited ZERO. All 26 staging options and prior complete
  54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed independent acceptance.
- Six fresh originals and eight crops/contact sheet were ACTUALLY viewed. Exact
  15-PNG receipt: task outputs/acceptance-pr134-man-canonical/inspection.json.
  Full 900/120 limits are visible; numeric regions are identical between pending
  and effective. Physical provenance stays null (headless only).
- Raw job logs/proof: outputs/pr134-3729ef2-{quality,security}-completed-job.log,
  quality-proof.json and native26-proof.json. Do not restart the completed watcher.

The fresh generator ran as UID [6,6,6], GID [12,12,12], groups [], NNP 1 and
all five capability sets ZERO in private namespaces. It completed normally with
bounded output and unchanged input trees. Fresh output: 28 databases / 1,040,384
raw bytes. All five changed candidate indexes equal fresh logical records.
Canonical output: 670,720 bytes, 4,862 records; all 4,515 primary records bind to
observed source metadata. The 248 virtual/cat records still lack source-declaration/
include/link/description/filter proof. Canonical artifact sizes: bytes 894,882;
frames 1,921,997; source diagnostics 1,267,778. No authority follows from these facts.

Accounting remains 107/125 with 18 UNAPPROVED effects: etc/ld.so.cache and its
parent, usr/local/lib and two synthetic library names, synthetic canary,
var/cache/ldconfig/aux-cache and its parent, new de.UTF-8/ja.UTF-8 man-cache
locale/cat6/index paths, modified root/de/ja indexes, and var/log/dpkg.log.
Keep the strict negative guard; never whitelist synthetic effects to finish.

The unused local virtual helper was now checked against ACTUAL accepted native26
canonical artifacts. Both implementations agree on all 248 unique metadata-bound
targets across 28 indexes. Evidence: pr134-virtual-metadata-native26-selfcheck.json.
This is local derived analysis, not native execution of that helper or proof of
source alias declarations. Decide next integration/stronger input confinement
without changing that scope or weakening existing gates. No CI run is live now;
refresh remote/base/reviews and disk before the next push. No merge/publication.

Earlier native24 d59f36e / run 40621100477 remains historical accepted evidence:
artifact 12788132725, 23,612,862 bytes, SHA256
33a18552aca152a9199c58ae90cd1050a24904e31fde2782b48482c97f85447e,
24 options, 855 quality tests and a separate 15-PNG UI receipt. Do not mix sources.

Task-root outputs/CONTINUATION.md holds operational pointers. Full older records
are in outputs/continuation-*-archive-*.md, Git history and ADR 0117. No agent
/compact tool exists; never claim one was invoked. Keep this file compact.

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
Tree/raw database/failure witnesses are retained before later checks. The current experiment passed native security; complete source/read authority
and adversarial confinement are still not proved. Production securebits stay
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
altered claims/artifacts reject. Those old-data numbers are historical; current fresh native26 counts are above.

Primary metadata locally binds all 3,606 candidate A/B records; baseline has six
missing primary sources (3,596/3,602 bind). Links use their own lstat timestamps.
The 224 virtual C aliases remain source-declaration-unverified. New unused local
package_man_virtual_metadata resolves their pointers to unique A/B records in the
same index with exact name/section/extension/compression/filter/time and bound
primary metadata. Both implementations matched all 224 on old retained data and all 248 on accepted
native26 data; seven
mismatch cases agree as unresolved. It never treats aliases/pointers as paths.
The virtual helper is now pushed with ab85fb7, but remains unwired and does not
change the source-declaration evidence boundary.
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
Disk last 43 GiB free / 79% used. Warn below 20 GiB or above 90%; stop new large
downloads below 10 GiB. Never silently delete user data. No data was deleted.
Preserve unrelated untracked duplicates:
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py

Local full discovery previously blocked in kernel reads of shared dependency
files/pyc; do not retry full imports, reinstall dependencies or delete caches on
a timeout. Focused portable checks work; exact-head completed CI logs are full
suite evidence. Saved diagnostic samples/logs remain under task outputs.
