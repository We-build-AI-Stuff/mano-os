# mano-OS continuation — original full version ACTIVE/incomplete

Updated 2026-11-04. Original v2.1 phases 0–7 remain incomplete; Phase 8 optional.
Specification docs/spec-v2.1.md SHA256:
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
A passing prototype/CI slice cannot substitute for the full version.

## Latest accepted native43 — confirmed executable-mapping gap

Head7039597ce9123c6af054dda6bdb9eeb72920e649/base65fdfc02e3dbb18f791a92374a24690ae4e1ba87.
Run41773655848 ALL3SUCCESS: quality126388903454(1096tests/oneskip),
security126388903597,merge126395384448. Collector46304 TERMINAL0; do not restart.
Artifact13296643097/49502219B/SHA2abbce8d32aa93d20ed6463360ca052b77aa4eb29e7a0c75e7080e1c91602bd4.
Testedmerged980134daa1aa87873d06e861cb4a6141b1dd4b9 exactparents/68matching sources.
ALL43 independent gates plus previouschain PASS. Fresh sixUI originals/eightcrops
ACTUALLY viewed; full900/120 and identical numericpixels. Proof in task outputs:
pr134-7039597-native43-proof.json; receiptacceptance-pr134-man-mapping-controls/inspection.json.

Actual kernel6.12.115+deb13.1-cloud-amd64/LandlockABI6: BOTH workers still allow
postguard temporaryRX/privateRWX, anonymousRWX and RW-to-RX. Temporary program
launch is denied. Seven before/after observations all succeed witherrno0; raw976B
packetSHA1f0cec3bbc5290448ce83a04899deae40c9ef655cb769a59c260b98a3bfa4b63.
Diagnostic mappings never jumped into; existing positive trusted true-copy exec ran.
PairedRootsummary3443B/full16KiBreserve,64artifacts/charged176358516Bwithin200MB.
Source identity checks and all13nativecases/4515primarycontexts stillpass;
248virtual/catexcluded. Physicalinput/peakRAMnull; allauth/fullruntime/loader/
generatedstate/publication flagsFALSE. Accepted DIAGNOSTIC evidence is not a fix.
Gapreceipt pr134-native43-executable-mapping-gap.json. No CI/collector live now.

## Current executable-memory enforcement implementation — NOT native-accepted

New fixed --mandb-enforced mode in native/mano_man_cache_guard.c applies a second
seccomp filter in the actual process before execl(mandb), retaining legacy v3 roles.
New v4 guard checks exact enforcing AppArmor context before Landlock; full UID6/
GID12/groups/caps/NNP checks remain. The fixed profile is loaded only by the guarded
CI Root controller; aa-exec transition follows complete setpriv drop and precedes
Python. Control worker remains baseline. No native Linux action ran on Mac.

Canaries retain all seven mapping cases before/after, require temporary file mmap
permission denials, and enforce anonymous RWX/RW-to-RX denials. Additional checks:
baseline private RWX, anonymous RX, pkey_mprotect EXEC, personality, memfd_create,
shmget/shmat, userfaultfd and uselib must return EPERM. Child SELF exec repeats all
postfilter controls while the own temporary probe still exists. Diagnostic mmap
addresses are never jumped into. Fixed mandb exec inherits filters/profile.
package_man_execmem.py validates exact bounded witness schema, strict types,
all positives/denials and false authority claims. Controller source-binds profile,
checks actual worker context and actual guard header, retains raw worker evidence.
New Root report field man_execmem_enforcement embeds profile bytes + proof <=16KiB;
FULL additional16KiB reserve charged to ORIGINAL200MB, still64named artifacts.
Existing 70s/256MiB/32task limits and all prior controls remain unchanged.

Local focused tests:229run/4Linuxskips;10new synthetic validation/wiring groups pass.
Full local suite interrupted during optional langchain/urllib3 import (KeyboardInterrupt;
not a pass); log outputs/pr134-execmem-full-local-tests.log. Native compile/CI
still require current verification. New code
is NOT accepted as a mitigation until disposable native CI and independent44th
reader/CLI/source-parent/budget/actual UI evidence pass. Independent readers still
need explicit new gate: reconstruct worker execmem preflight/hash and fixed argv,
select v4 ONLY for actual mandb, independently parse all new native controls and
bind profile/parser/source/binary/report/budget; preserve all earlier43 gates.
Do not run previous43 collector against new output or claim green CI is acceptance.

interpreter/ELF/GNUstack/READ_IMPLIES_EXEC across exec/loader/plugin/source semantics
and production protectedupdates remain requirements. No fullclosure claim from
memory policy alone. Diskwarning18GiBfree/91% communicated. Three unrelated files
with names ending ' 2' remain untracked and must not be staged or deleted.

## Latest accepted native42 — named source identities

Head17c022e1fb22fe11a681b454f6ca8f05baf8b8b9/base65fdfc02e3dbb18f791a92374a24690ae4e1ba87.
Run41769328482 ALL3SUCCESS: quality126375064452(1090tests/oneskip),
security126375064634,merge126382658769. Collector17517 TERMINAL EXIT0; do not restart.
Artifact13295191227/49492006B/SHA934b8cecf51b4003ac2488b4cc534e2033493707b33bc8e8367cb5eec24d5d8b.
Testedmergeb96a109c6ebec84a9f4b81f61ed560b5bc4b9db6 exactparents/66matching sources.
ALL42 independent gates plus earlier54hash/45flag/PAM/Stop/recovery/package/ELFchain
PASS. Six fresh UI originals/eight crops ACTUALLY viewed, full900/120 values visible,
pending/effective numeric pixels identical. Proofoutputs/pr134-17c022e-native42-proof.json;
receiptoutputs/acceptance-pr134-man-runtime-origin/inspection.json. Global UI receipts updated.
Both worker pairs match all10 held source objects (8baseline/2injected), Rootbefore/
after unchanged. Actual FDs use Btrfs devices0:56 baseline/0:48 injected in both.
Source packet9313B within full64KiB reserve,64artifacts, charged176330164B within
original200MB. Worker15638B.13native fixedcases/4515primarycontexts terminal,
248virtual/catexcluded. Graph15063104B/reference293856B. Authentication/fullruntime/
loader/generatedstate/publication FALSE; physicalinput andpeakRAM null.
No native43 mapping evidence, Root/runtime integration or mitigation accepted yet.

## Latest accepted native41

PR134 OPEN, branch feat/approved-package-apply. Committed/pushed head
956eb07c0c1fb02c4262485eed08f5d135100a11; base
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Run41587601147 ALL THREE SUCCESS:
quality125756623752 (1078 tests / one skip), security125756623432,
merge-gate125764270263. Artifact13209138971 /49503579 bytes /SHA256
588c11075094aa3119dfd7e9c8532853634e0e2043e2a877eed23ca495526586.
Tested merge f7b7425e6738c89168b1e8175f1a1ba3a4565a41 has exact parents and
63 matching relevant sources. Collector session5847 TERMINAL EXIT0; do not restart.
ALL41 independent gates plus the earlier54-hash/45-flag/PAM/Stop/recovery/package/
ELF chain pass. Six fresh originals and eight crops actually viewed: full900/120
values visible, pending/effective numeric pixels identical. Proof in task outputs:
pr134-956eb07-native41-proof.json; 15-PNG inspection receipt:
acceptance-pr134-man-runtime-view/inspection.json. Global UI receipts updated.

Both dropped workers report28 kernel mounts and ten named readonly code/config
objects. Actual Btrfs mount device0:26 differs from baseline FD subvolume0:55 and
injected helper FD subvolume0:49; per-FD mount IDs bind the correct VFS view.
No false superblock-device equality is required. Named mount protection passes;
filesystem object origin, complete runtime closure, loader selection, generated
state, changes/publication authorization remain FALSE. Physical input/peak RAM null.
All13 fixed native reference cases and4515 primary conditional source contexts
match;248 virtual/cat records excluded. Embedded graph15063104B/reference293856B;
64 artifacts, charged aggregate176247018B within original200MB, including full
32MiB graph +1MiB reference reserves. Wider semantic flags remain false.

## Source identity implementation — accepted in native42 above

Accepted17c wires package_man_runtime_origin.py into both existing CI
manual-generation workers and the Root controller. Holds ten O_PATH/NOFOLLOW/
CLOEXEC source FDs across each worker domain, compares before/after/child exact
bounded fstat values from the same FD used for the readonly mount witness. Eight
sources belong to the immutable baseline, two to private injected artifacts.
Only the fixed serializer is embedded in the child; no Root traversal/capture API.
Fixed serializer/module hashes and strict mount/identity field agreement required.
Snapshot readonly uses existing Btrfs property-get; worker VFS readonly is separate.
Failure/timeout raw diagnostics retain source witnesses, missing exit code stays
null and no drain/success is invented. Root native capture has NOT run on Mac.

The two pairs are embedded under64KiB; full reserve charged against ORIGINAL200MB,
still64 artifacts. No privilege, command authority, namespace or resource ceiling
changes. Independent output reader accept_man_runtime_origin.py plus default-false
--man-runtime-origin gate require all41 earlier gates and exact independent worker
reconstruction. New reader imports no producers/native APIs. Old41 receipts refuse
new42 contract; all authentication/full closure/loader/generated-state/publication
flags remain false. Source identity equality alone cannot authenticate an interpreter.

The 17c change passed fresh native42 CI, all42 gates,66source comparisons and
actual UI viewing as recorded above. Portable tests alone were not acceptance.

## Executable-mapping implementation — accepted diagnostic above

Native optional --mapping-controls retains all v3 UID/cap/NNP/Landlock/seccomp,
positive/negative temporary-launch and inherited-child controls. Seven before/
after cases: baseline read/RX, copied temporary ELF read/RX/privateRWX, anonymous
RWX and RW-to-RX mprotect. Diagnostic mappings are never jumped into; the existing
positive trusted true-copy exec remains. Default v3 modes/output unchanged.
The controller now requests the bounded5s probe in BOTH existing workers before
mandb, with source identity mode and original70s/256MiB/32task limits unchanged.
Failure/incomplete output retained in private diagnostics and generation refuses.

Root checks canonical bounded byte streams/counts/hashes, zero typed exit and
complete capture, strict4KiB packet/14outcomes and real permission errnos; ENOMEM
is not a denial. Native reports kernel release, matched with controller and both
workers. Root paired report binds parser/native source/binary, capped16KiB; full
new reserve charged original200MB alongside32MiB graph/1MiB reference/64KiB source
reserves, still64 artifacts. Independent --man-mapping-controls defaultsfalse,
requiresall42 and exact source reconstruction/raw-packet/source/binary/kernel/
summary/aggregate verification. Tests refuse source substitution, truncation,
numeric aliases, missing positives/duplicate fields, unexpected errors or promoted
claims. All complete-runtime/loader/generated-state/publication flags remainfalse.

Local143 focused producer tests/one Linux skip,20 independent reader groups,
repo lint/diff PASS. Python worker compiled only; Linux C uncompiled/unexecuted on
Mac. Fresh native43 CI needs68source comparisons (66 +parser/test), exact parents,
all43 gates and fresh actual UI. Current accepted42 remains17c above; this next
code is uncommitted/unaccepted. Primary pinned Linux6.12 audit URLs/hashes in task
outputs/man-runtime-executable-mapping-review.json are context, not VM proof.
After real outcomes, select/test required mitigation before any full-runtime claim.

## Preserved accepted and failed history

Accepted native40:40edb0b/run41583761347/artifact13207698039, all3CI/all40/freshUI;
proof pr134-40edb0b-native40-proof.json. Collector28546 terminal0.
Failed c2b1eea/run41581232470 remains FAILED (five Python3.11 gzip fixture-header
failures); custody artifact13206881174/SHA39cf3db639f019a0844ed70a8f7d5d80204ea70a493c6c4fae0e73726066f834.
Collector99577 terminal1. Fixed GzipFile preserves whole frozen fixture bytes;
no fixtures or checks skipped/changed. Accepted39:4f2efdb/run41578405862 retains
production securebits11 task ceiling, complete UID delegation, restoration denials,
PAM/Stop/packaged workflows and actual UI. ADR0118 records measured preflight times.
Failed saved-Root expectation108986d/run41569202382 remains failed; exact native
regression and both43/11 positive/negative controls preserved. Corrected37 and38
accepted in earlier proofs. Older failed35/framing/trace runs also remain failed.
Details preserved in Git history and task-output continuation archives, including
CONTINUATION-repo-before-native41-20261104.md. Never rewrite failed runs as accepted.

## Full remaining goal and merge conditions

Finish callback/script/caller/activation/dependency authority; complete source/
include/link/alias/NAME/filter/cache/tag semantics, loader/ELF/search/aux-cache/log/
unlisted mutation policy and privileged runtime immutability INCLUDING protected
updates. Production staging/activation/crash/Stop/ENOSPC/recovery/no replay,
conffiles/accounts/services/upgrades/removal/broad compatibility and full registry
reprobe remain.107/125 effects accounted;18 negative canaries rejected. Conditional
primary-source coverage is not complete roff/source/virtual alias/description/
filter/generated-state, mutation or publication validation; those gates remain.

All original provider/model repair/coding/apps/connectors/profiles/hardware,
physical input/8GiB performance, signed OS install/update/recovery/release and
Section14 metrics/MVP/Section16 Definition of Done remain mandatory. Physical
tests deferred by continuing in CI, not waived. PR134 is not merge eligible merely
because CI is green. Merge commits only with current base/exact final head ALL CI,
real security/artifact/UI acceptance and genuine defects resolved. Admin human
review override authorized; failed-CI/protection/evidence bypass is not. Assess
CodeRabbit on merit: fix genuine findings, otherwise explain concretely in PR
before an eligible merge. Latest refresh: five threads, all resolved. No reviewer
requests/notifications, proactive subagents, other chats/new chats/automations or
paid-provider/key/auth experiments.

## Mac safety, disk and context

Root/Linux/native DB/staged inflation/VM operations ONLY disposable Debian CI.
Portable unprivileged Python, metadata/byte/mock tests allowed Mac. No local VM or
model downloads; never silently delete user data. Latest disk about18GiB free/91%
used: WARNING communicated. Warn<20GiB or>=90%; stop large downloads<10GiB.
Preserve unrelated untracked duplicates, never stage/delete:
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py
No agent /compact tool exists; do not claim invocation. Keep notes compact and
preserve historical detail in archives/Git rather than dropping requirements.
