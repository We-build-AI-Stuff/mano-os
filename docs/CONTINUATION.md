# mano-OS continuation — original full version remains active

Updated 2026-11-03. Original v2.1 phases 0–7 are ACTIVE/incomplete; Phase 8 is
optional. Specification docs/spec-v2.1.md SHA256:
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
A prototype, CI slice or the gates below cannot substitute for the full version.

## Latest accepted native 39: real production UID delegation

Head 4f2efdb949fb993d14a6aad2627b0b737d36ffb8, base
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Run 41578405862 ALL THREE SUCCESS:
quality 125727242736 (1,050 tests / one skip), security 125727242962,
merge-gate 125734599484. Artifact 13205431852 / 47,920,131 bytes / SHA256
3fd9ae9224c1e11b5c5ef438266b6051d4d22e43d29e924010bfdcbc1b3ab330.
Tested merge 92cbd1e22da6e28d035a3f34dca84b3bd55d5e0c has exact parents
and 54 matching relevant sources. Collector session 61602 TERMINAL EXIT ZERO;
do not restart. All 39 staging/identity gates and the previous
54-hash/45-flag/PAM/Stop/recovery/package/ELF chain independently pass.
Six fresh UI originals and eight crops were actually viewed. The 15-PNG receipt
confirms full 900/120 values and identical pending/effective numeric regions.
Physical input provenance and peak memory remain null.
Proof: task outputs/pr134-4f2efdb-native39-proof.json; receipt:
outputs/acceptance-pr134-identity-delegation/inspection.json.

Native guard 11 removes only KEEP_CAPS_LOCKED; six capabilities (0xdb), NOROOT,
normal-UID-fixup locks, NNP/seccomp/AppArmor/namespaces/Stop remain. This changes
retention semantics; it is not bit-for-bit policy equivalence or isolation of
mutually hostile members of one authorized package task (ADR 0118).
Fixed setpriv delegation before APT effects independently verifies UID 6/6/6,
GID 12/12/12, groups [12], E/P/Amb zero, I/B 219, profile 11/NNP/seccomp/enforced
AppArmor/private namespaces, unchanged child state and three EPERM restoration
results. Actual setup/public-cowsay/installed-runtime-sl preflight latencies are
154,418,281 / 104,640,441 / 104,843,326 ns. Parent state retention is checked by
the immutable worker. Arbitrary maintainer effects and full closure stay unverified.

## Current native-40 run and test portability correction

Pushed head c2b1eea938d69e2afe7932ffb1bfa507bd2d0560 / run 41581232470:
quality 125736312185 FAILED (1,061 tests, five failures / one skip). All five
failures occur in fixed-corpus fixture reconstruction before traversal assertions.
CI uses Python 3.11; its gzip.compress(mtime=0) fast path delegates the OS-header
byte to zlib, unlike the newer canonical-255 behavior. A portable literal-only
reproducer differs from the frozen fixture at byte 9 alone (OS metadata).
The correction uses gzip.GzipFile with explicit empty filename, mtime 0 and
compression level 9; its WHOLE output matches the frozen fixture exactly.
No native input/fixture/hash, traversal check, grant or runtime code changes.
The 11 focused trace/graph tests and lint/diff pass locally after correction.
Diagnosis/raw quality log retained in task outputs/pr134-c2b1eea-quality-failure-diagnosis.json
and pr134-c2b1eea-quality-failed-raw.log. Fresh CI remains mandatory.

Security job 125736312293 and collector session 99577 were confirmed LIVE; the
collector follows the SAME run and will retain failed-run artifact custody after
terminal failure. Do not restart it. DO NOT PUSH the correction while this run is
active: workflow concurrency cancel-in-progress=true would cancel the real lab
and lose its completed evidence. Prepare the correction locally, wait for terminal
custody, then push and start a fresh exact-head all-40 run. Failed quality remains
failed even if the lab succeeds. No native-40 acceptance or merge is authorized.

## Next change: fixed native conformance and every primary source context

The pending source change compares the actual confined mandb diagnostics with
conditional source models for all 13 fixed corpus cases. Native traversal,
hardlink versus symlink-to-hardlink, gzip/xz precedence, original-directory
recursion, nine/ten-hop limit, missing source, cycles, comments/blank lines and
attached .so behavior match accepted native-38 raw data. Unknown/ambiguous cached
invocations and conflicting explicit outcomes fail closed. Root commands/grants/
configuration/resource limits remain unchanged. The controller adds a bounded
model/comparison packet after domain drain, to the existing Root report.

Original native-38 raw stderr (17,244 bytes) plus inventory is retained in
39,333-byte tests/fixtures/man-native-reference-3882227.json, SHA256:
1509e49b227dfaa01b1937951d11e17c9ca8400b4f9368f3d076196d0fec96c5.
Its source is accepted head 388222738e93795e3ac916af0ab20edde6b5b7ca /
run 41574997328 / artifact 13204530619, SHA256:
434d977d23f95263b3eace3beceb8ee9492aa3d0ccad39c3543a752bef0bd4ff.
That run passed all 38 earlier gates, 1,038 quality tests / one skip, exact merge
23ed1d029439ddee5292d8006b90e6ef39365398 / 47 source comparisons and fresh UI.
Native-38 invocation alone was not full source semantics or publication authority.

The same next change derives a conditional leading-source graph for EVERY primary
canonical record, using bound source metadata, verified leading classifications
and measured compression order. Accepted native-38 data: 4,515 primary records /
4,515 distinct contexts all terminate; a separate reader replays every traversal.
The 248 virtual/cat records are explicitly excluded and still need separate policy.
Compact graph 14,494,016 bytes; embedded graph plus source hash 15,063,104 bytes.
The existing Root report embeds it; no 65th artifact. A FULL 32 MiB graph reserve
plus the unchanged 1 MiB reference reserve is charged against the ORIGINAL
200 MB envelope: prototype charge 176,202,092 bytes. Fixed-reference joint evidence
is 293,856 bytes within its existing 1 MiB reserve. Per-input/record/context/byte
limits are enforced. Unknown/unresolved graphs remain incomplete and fail acceptance.

New gate --man-reference-conformance defaults false, requires all 39 previous
gates, and requires both independent fixed native conformance and complete primary
context replay. Old receipts lack its witnesses and cannot be promoted. Next
collector must compare 59 sources (previous 54 + trace module/test/native fixture
+ source-graph module/test), exact merge parents and all 40 gates. Fresh CI,
artifact acceptance and ACTUAL UI viewing/receipt are required before any merge.
Local validation: 92 focused portable tests, 11 independent new reader groups,
repo-wide ruff and diff PASS. Only two own small literal strings are compressed
in portable tests. No staged data is inflated and no native Linux program runs
on Mac. Offline proofs in task outputs/pr134-native38-reference-conformance-offline.json,
pr134-native38-primary-source-graph-offline-proof.json and
pr134-native38-primary-source-graph-independent-proof.json are NOT new native acceptance.

## Failed custody and regression history

Failed native-37 head 108986db0209febaa071540545d06275a42b8736 /
run 41569202382 remains FAILED: security 125697904443, merge 125703884976;
quality 125697904733 passed 1,023 tests / one skip. Artifact 13201845054 /
2,893,794 bytes / SHA256 61401ce827d2551393f9da88b9532f999e3b7c13122135d2ca206a6abc56c133.
Kernel observations disproved the original saved-Root ambient-clear expectation;
corrected native-37 head 0e34f312618e5e95e5597e9fd3abed758b798aa7 /
run 41571884425 passed. Exact regression:
tests/fixtures/uid-drop-linux-saved-root-v1.json SHA256
d1f7773368ff9bda1310a8000b4ebada3a3e3e5163c60b900186ae392524aa66.
All 43/11 controls, including negative locked-43 setpriv conflict and saved-UID0
counterexamples, remain. Complete drop loses capabilities; retaining saved Root
or permitted bits within a task cannot establish hostile-child isolation.
Failed native-35 runs 41490850832 and 41506696335 and older failed framing/trace
runs remain failed, with custody preserved. No later green run rewrites them.
Detailed previous notes are in Git history and task outputs/
CONTINUATION-repo-before-source-graph-20261103.md; do not delete evidence.

## Full remaining goal and merge conditions

Finish callback/script/caller/activation/dependency authority; complete source/
include/link/alias/NAME/filter/cache/tag semantics, loader/ELF/search/aux-cache/log/
unlisted mutation policy and privileged runtime immutability including protected
updates. Coherent production staging/activation/crash/Stop/ENOSPC/recovery/no replay,
conffiles/accounts/services/upgrades/removal/broad package compatibility and full
registry reprobe remain. 107/125 effects accounted; 18 negative canaries rejected.
Conditional primary leading-source coverage is NOT full roff/namespace/source-graph,
virtual alias/description/filter/generated-state, mutation or publication validation.
Those wider flags stay FALSE and remain mandatory.

All original provider/model repair/coding/apps/connectors/profiles/hardware,
physical input/8 GiB performance, signed OS installation/update/recovery and release
requirements remain. Physical tests were deferred by continuing in CI, not waived.
PR134 is NOT merge eligible until its remaining genuine security gates are complete.
Merge commits ONLY current base/exact final head ALL CI + real security/artifact/UI
acceptance and genuine defects resolved. Admin human-review override is authorized;
failed CI/protection/evidence bypass is not. CodeRabbit findings: fix genuine ones,
or explain concretely in PR before an otherwise eligible merge. Latest refresh:
five threads, all resolved. No reviewer requests/notifications, proactive subagents,
other-chat messages/new chats, new automations or paid-provider/key/auth experiments.

## Mac safety, disk and context

Root/Linux/native DB parsing/staged inflation/VM probes ONLY disposable Debian CI.
Portable unprivileged Python, metadata and byte analysis is allowed Mac. No local
VM/model downloads or silent data deletion. Disk about 22 GiB free / 88 percent
used; warn <20 GiB or >=90 percent, stop new large downloads <10 GiB.
Preserve unrelated untracked duplicates (never stage/delete):
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py
No agent /compact tool exists; do not claim invocation. Keep this note compact;
preserve older detail in Git history and task-output archives.
