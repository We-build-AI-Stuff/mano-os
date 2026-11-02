# mano-OS continuation — full goal remains active

Updated 2026-11-02. Original v2.1 phases 0–7 are ACTIVE/incomplete; Phase 8 is
optional. Specification: docs/spec-v2.1.md, SHA256
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Do not redefine completion around a prototype, CI slice or the checks below.

## Accepted native34: bound static compression configuration

The staging probe now retains the fixed baseline libman library as opaque bytes,
freezes a Root-owned 0444 single-link copy, checks the stored copy before decoding,
and binds its content/metadata to both retained trees. Fixed selector and parent
ownership, permissions, searchability and unchanged candidate library metadata are
required. The pure static decoder never loads the ELF file or executes its stored
program strings. One artifact is added (expected 64), within the unchanged
64-artifact/200 MB budget. Gzip content protocol v2, native permissions and resource
limits stay unchanged.

A separate ELF reader recomputes the complete configuration and metadata binding.
The new `--man-compression-table` gate depends on all previous 33 gates and checks
fixed-file custody plus the decoder's exact tested Git hash. Seven producer test
groups and four independent test groups cover byte/range/relocation corruption,
changed files/selectors/parents, false configuration and custody claims. Both
readers agree on synthetic fixtures and the exact library bytes matching accepted
native33 baseline metadata. Native34 is accepted at head 01259c9fff6312201527e10353aa861084bc9534, base
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Run 41394879221 passed all three jobs:
quality 125113940407 (984 tests, one platform skip), security 125113940731 and
merge-gate 125120820408. Artifact 13119498820 is 47,855,661 bytes, SHA256
 ae29d77ac3c2755e34a68e6066c90954a2503adde9612c7d92cafc5ba8d28d2c.
Tested merge 62546e1ab5c9719df4295ed8f6f1c6437a467da5 has exact base/head
parents and 26 matching relevant sources. Collector 67531 exited zero after all
34 staging gates plus the earlier 54-hash/45-flag/PAM/Stop/recovery/package/ELF
chain. It is terminal; do not restart. Six fresh UI originals and eight crops
were actually viewed; the 15-PNG receipt confirms full 900/120 values and matching
pending/effective numeric regions. Physical input provenance remains null.
Full proof: task outputs/pr134-01259c9-native34-proof.json. There are exactly
64 staging artifacts / 141,542,331 uncompressed bytes. The captured 282,912-byte
library matches the earlier reference's SHA256
 e1119194250c85d02f1c7328b332ee93a7cfe7212e1903b7bb146aa5229d60da.
Its nine configured suffixes are independently bound to the native capture. Runtime loader selection, helper search paths, target resolution, full
source semantics, generated-state validity and publication stay false.

## Latest repeated native34 acceptance: conditional lookup preparation

Head 6e4c47bcc97dc173c5307e54d16e1136b18d4800 is accepted for the existing
34 gates at base 65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Run 41484827812
passed quality 125413460826 (1,010 tests / one skip), security 125413460191
and merge-gate 125427392007. Artifact 13162264557 is 47,894,166 bytes, SHA256
58ab23cfc356cdd6be9eaee2b1f3492b8b6eaf3a0d02e3ca847f30e2ef32deb5.
Tested merge 12fe1b506de96ce151e1e258be6510b9154ed3c3 has exact base/head
parents and 30 relevant matching sources. Collector 29400 exited zero after
ALL34 and the prior 54-hash/45-flag/PAM/Stop/recovery/package/ELF chain.
All six fresh UI originals and eight crops were viewed; the 15-PNG receipt
confirms full 900/120 values. Physical provenance remains null. There are 64
staging artifacts / 141,546,110 uncompressed bytes. Proof and receipt are in
task outputs/pr134-6e4c47b-native34-proof.json and
outputs/acceptance-pr134-reference-lookup/inspection.json. All five review
threads were freshly read and remain resolved. This does not complete PR134's
remaining privileged package policy or the full original version.

## Native fixture gate35 preparation

The next preparation adds an exact, Root-owned read-only request for a fresh
source-content process after the real content domain drains. It probes only fixed
synthetic cache paths: 40 stat/lstat queries and nine selection cases. It opens no
actual source captures, parses no compressed data and executes no man-db library.
Native C grants and guard profile remain unchanged; only the fixed request mount
source changes, with a shorter 30-second service deadline. Root creates fixtures
and checks exact node types/owners/modes/bytes/targets/child sets plus inode/device/
timestamp identity before and after domain drain.

The bounded raw capture, fixture inventory and normalized metadata tree are
embedded in the existing Root report. No 65th file is added. A full 1 MiB reserve
for this evidence is charged against the unchanged 200 MB aggregate envelope.
Bounded raw capture is preserved in existing CI stderr before parsing or failure
cleanup. An independent reader imports no producer modules, checks the fixed
inventory and witness identities/errors, and replays traversal independently.
`--man-reference-fixtures` requires all 34 prior gates. Actual accepted native34
evidence remains accepted by its old contract and is rejected by the new gate
because fixture evidence is absent. These new fixtures have only mocked local
coverage until the next exact-head disposable Debian run. They do not establish
whole source-namespace, native caller, hardlink, source semantics or publication
authority; all those claims remain false.
Six producer/controller test groups and three independent fixture test groups
cover packet dispatch, unchanged sandbox grants, report bounds, unsafe controller
contexts, crossed identities/errors/order and false authority. The combined
focused portable suite passes 82 tests with one Linux-only skip on Mac. Lint and
diff checks pass; this is local preparation, not native35 acceptance.

## Conditional lookup preparation

`package_man_reference_lookup.py` models one-hop selection over frozen retained
metadata for UID6/GID12, using a supplied compression order. It follows symlinks
before processing `..`, applies directory search permissions, tries the root
before the original page directory, and stops at the first successful stat even
for a directory. It distinguishes proven absence/access failures from unknown
scope, ACLs, protected-symlink policy and resource limits. It opens no host paths.
The known overlay uses candidate manuals and baseline ancestors/alternatives.
The recursive driver additionally models initial lstat-based hardlink selection,
keeps the original directory through later requests, and enforces ten source
inspections. It assumes all three link flags and independently bound plaintext
classifications. Directory read permission is required before choosing a hardlink
alias; file read permission is required before inspecting content. Unsupported
initial nonregular hardlinks, security attributes and missing content stay unknown.
This is a conditional metadata model, not native namespace or caller equivalence.

Sixteen synthetic tests cover precedence, fallback, locale context, nested original
context, symlink/parent ordering, cycles, dangling links, nonregular poisoning,
DAC classes, directory/trailing-slash rules, unknown attributes/scope, literal
operands and immutable snapshots. A data-only experiment over native34's actual
retained library, trees and text selects captured regular targets for all 14
indexed relative contexts; those targets have no further leading requests. The
unchanged unindexed missing reference remains unresolved. Results are in task
outputs/pr134-native34-conditional-reference-lookup-experiment.json. No native
lookup or complete graph authority has been gained. Nine additional synthetic
chain tests cover retained original-directory context, nine versus ten hops,
cycles, hardlinks, initial symlink behavior, read permissions, missing/nonregular
content and false evidence. The 56 focused lookup/chain/classifier/configuration/
source-link tests pass locally; their committed code is included in the accepted
1,010-test quality run.

A reproducible pure-byte experiment in task outputs/experiment_man_reference_chain.py
checks the accepted native34 ZIP hash and recomputes every retained leading-request
classification from frozen expanded bytes without inflation. The conditional driver
reaches a terminal source in all 4,515 distinct observed primary-page contexts,
using each retained index's locale context. Fourteen need relative-reference lookup;
no actual initial hardlink selection is exercised. Full result digest and nontrivial
chains are in outputs/pr134-native34-conditional-source-chain-experiment.json.
Native caller flags/stat behavior, kernel namespace equivalence, source semantics,
generated-state validity and publication remain unverified/false.

The separate task-output reader now independently replays all 4,515 conditional
reports, with nine synthetic test groups. Native fixtures and caller semantics
remain required before claiming actual source resolution. The
64-artifact cap must stay; enrich/version existing evidence rather than add a
65th file. All original requirements remain active.

`test_package_man_reference_linux.py` adds self-created filesystem fixtures for
disposable unprivileged Linux CI only. It compares 34 stat/lstat traversals and
nine first-existing selection cases to actual kernel results and inode identity:
symlink-before-parent, absolute links mapped into the fixture, loops, dangling
links, missing paths, ENAMETOOLONG, trailing slashes, search-denied directories,
unreadable files, literal operands, compression order and nonregular poisoning.
Ownership is mapped to modeled UID6/GID12; this does not prove actual source-domain
credentials/mounts, native man-db behavior or hardlink semantics. The test is
correctly skipped on Mac and actually ran successfully in the accepted Linux
quality job above.

## Accepted native33: initial source-request evidence

A pure-data transformation now validates retained binary framing, complete ordered
names, compressed/expanded hashes, native decoder witnesses and capture/manifest
bindings before classifying every initial request. It opens no operand paths and
performs no inflation. The CI staging probe retains a bounded canonical
`staged-man-leading-requests.json` artifact with per-file byte evidence and source
program/classifier hashes. This adds one artifact (expected 63); the unchanged
64-artifact/200 MB global limit still applies. No native worker permission or
resource limit changes are needed.

The independent gate uses a separate byte classifier and the existing independent
binary reader, recomputes every per-file record and exact canonical artifact, and
checks Root summary/provenance hashes. `--man-leading-requests` depends on all
32 earlier gates. Malformed text, crossed input/capture bindings, byte mutations,
false length/hash relabeling, incomplete maps and invented authority are rejected.
Five new repository tests and three independent gate tests pass synthetically;
157 focused checks passed with three Linux-specific skips. On actual retained
native32 plaintext, the new producer equals the previous independent inventory:
3,202 files, 3,187 without leading requests, 15 relative requests, zero unsupported.
Native33 is accepted at head cd25b88d0a4de63146d8e875e7e26c40bc5bca93, base
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Run 41390687327 passed all three jobs:
quality 125101182897 (977 tests, one platform skip), security 125101182965 and
merge-gate 125107900877. Artifact 13117613609 is 47,760,553 bytes, SHA256
ad3b7124777cddc3352b694f2fa97f3c98a03e8a1ca2e3401453aa903c754ed0.
Tested merge e7041f2755e9d29a63c9ea4c42c7380f45337c10 has exact base/head
parents and 25 matching relevant sources. Collector 96203 exited zero after all
33 staging gates plus the prior 54-hash/45-flag/PAM/Stop/recovery/package/ELF
acceptance. It is terminal; do not restart. Six fresh UI originals and all eight
crops were actually viewed; the 15-PNG receipt confirms full 900/120 values and
matching pending/effective numeric regions. Physical input provenance is null.
Full proof: task outputs/pr134-cd25b88-native33-proof.json. The initial-request
artifact is 3,584,161 bytes, SHA256
2f0977a675399b3f9940897681d286602bf53dc593e34b00571033373f4737f4.
There are 63 staging artifacts / 141,256,353 uncompressed bytes. The retained
library hash also matches the local reference bytes used by the unused decoder
below. All 3,202 per-file leading records match the historical native32 inventory.
Exactly 14 indexed relative contexts occur in the root index; the fifteenth
relative source is unindexed and unchanged from baseline. Its root/original-dir
candidates are absent in both snapshots. These remain lookup observations, with
full runtime equivalence and target authority unproven.
Reference resolution, full include graphs, alias/name/description/filter semantics,
generated-state validity and publication remain false. All original requirements
remain active.

## Local compression-table preparation, not part of native33

An unused pure-byte ELF64/x86-64 decoder is prepared in
`package_man_compression_table.py`. It never loads a library or executes its
program strings. It requires one defined global `comp_list` object, file-backed
segment/section agreement, bounded symbol/relocation tables, direct relative
pointer relocations, read-only strings, unique bounded extensions and a final
null sentinel. Five synthetic test groups cover malformed headers/ranges/symbols,
relocation changes, extra writes into the table, missing sentinels, duplicate
extensions and resource ceilings. This is not wired into native capture or gates.

A 1,469,060-byte public Debian package was read as data to obtain only
`libman-2.13.1.so`. Its 282,912 bytes exactly match the accepted native32 baseline
SHA256 e1119194250c85d02f1c7328b332ee93a7cfe7212e1903b7bb146aa5229d60da.
No archive paths were extracted and no native library code or manual gzip was
executed/inflated. The package signature is not claimed; the extracted library
is bound by the independently accepted baseline file hash. The decoder finds
configured extensions gz,z,Z,bz2,xz,lzma,lz,zst,zstd in that library's static data.
Runtime symbol selection, helper search paths and execution authority stay false.
Task outputs contain the reference-byte proof and static-table inventory/prototype.
The next custody step can retain this fixed baseline library as one binary
artifact (the 64th staged artifact), without changing the gzip content protocol or
adding native worker permissions. Keep the global file/byte limits enforced.

Retained index/link metadata shows exactly 14 primary contexts whose captured
source has a leading relative request, all in the root index; no locale fallback
is needed for those observed contexts. The fifteenth relative request belongs to
unchanged, unindexed man7/man.7.gz and references absent man7/groff_man.7. These
are data inventories, not complete runtime/source-graph or publication proof.

## Accepted native32: bounded decoded-source custody

The content worker now has explicit `man-source-gzip-content-v2` output and writes
one fixed exclusive nofollow/CLOEXEC 0600 binary under its private cache. Canonical
records bind manifest SHA, compressed SHA, expanded SHA and exact expanded bytes;
each record is written only after GNU output equality. It streams one file at a
time, bounds expansion at 8 MiB/file and 64 MiB total, file count at 8192, names at
4 MiB total and binary size at 72 MiB. Failed writes cannot later finish a bundle.

The Root controller waits for domain drain, verifies UID6/GID12/mode0600/nlink1,
copies bounded data to a fixed exclusive Root-owned file, verifies stable source
FD identity and freezes the copy 0444 before inspecting report metadata. A fixed
service stop precedes acquisition of partial output on launch failure. Content-only
tmpfs grows from 16 to 128 MiB; file-size limit grows from 2 to 72 MiB. Other roles
retain their limits; 256 MiB memory, 32 tasks and 190-second runtime stay enforced.
The overall 64-artifact/200,000,000-byte uncompressed budget is checked by the
producer too. No path text is executed or used to open a source include.

Independent task-output reader uses its own bounded binary parser, with no
producer import or inflation. It checks order, counts, exact bytes and both native
decoder hashes. New `--man-expanded-inputs` gate depends on all prior 31 gates;
legacy discard-only evidence retains its original validation. Protocol selection
is bound to the exact tested Git worker, not a self-reported profile. Synthetic
tests cover corruption, truncation, count/length inflation, false hash relabeling,
cross-binding, partial writes and reads, and missing records. Synthetic GNU/native
witnesses are fabricated fixtures and prove no Linux controls.

Native32 is now accepted at head 0359534610ab64603d780540e009fb4542c32de5, base
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Run 40907659099 passed all three jobs:
quality 123566730299 (972 tests, one platform skip), security 123566730904 and
merge-gate 123581536444. Artifact 12912654941 is 47,445,957 bytes, SHA256
2cd89ec03c99994a528ffd7b0648f8ef582c027a47cd4f0c77efa8fd8d7ca2b7.
Tested merge dd651fad860dfd7f745d38e6b029ef233a794db9 has exact parents and
23 matching relevant source files. All 32 independent staging gates and prior
54-hash/45-flag/PAM/Stop/recovery/package/ELF checks passed. Collector 78300 is
no longer present; its final record confirms independent acceptance exit zero.
Do not restart it. Six fresh UI originals and all eight crops were actually
viewed; the 15-PNG receipt is in task outputs/acceptance-pr134-man-expanded-inputs.
Full 900/120 values are visible and pending/effective numeric regions match.
Physical input provenance remains null.

The binary retains 35,074,232 expanded bytes across 3,202 files; its size is
35,386,688 bytes and SHA256
881631fc0754bdff1dcaca2c64ca66f89b706f8300d9201428c38981f8818a55.
Independent acceptance reacquires the actual text without repeating inflation.
There are 62 staging artifacts / 137,661,623 uncompressed bytes. The actual
content worker completed under unchanged 256 MiB/32-task/190-second limits;
peak memory was not measured. Guard, source identity, domain drain, control,
runtime/input hashes and frozen output checks passed. Full proof is in task
outputs/pr134-0359534-native32-proof.json; completed job logs are preserved.

A follow-up pure-data inventory inspected the retained text with two separate
leading-request algorithms: all 3,202 agreed, no unsupported cases, 3,187 had
no leading .so request and 15 had relative requests. This opens no source paths,
repeats no staged gzip inflation and proves no target resolution, full include
graph, alias declarations, descriptions, filters or generated-state authority.
Per-file evidence is in task outputs/pr134-native32-leading-request-inspection.json.
The next step is to bind these initial requests into the retained evidence, then
resolve references against exact observed metadata and deployed compression
precedence. Never treat this initial-request classifier as a full roff parser.

Full source semantics/runtime closure and publication remain false. Accounting
remains 107/125 with 18 rejected effects; no merge or activation. All original
version requirements remain outstanding. Native31 below is historical evidence.

## Historical native31: complete observed regular manual-file coverage

PR #134, branch feat/approved-package-apply; repository We-build-AI-Stuff/mano-os.
Accepted head 33460b89ac766ee1829f0bd69bb476aec58ee1be, current base
65fdfc02e3dbb18f791a92374a24690ae4e1ba87. Tested merge
b251fbd0b637cc34d631a269a12c2f7d1d44a3ad has exact parents and 23 matching sources.
Run 40897545136 ALL THREE SUCCESS: quality 123530664567 (960 tests, one platform
skip), security 123530665039, merge-gate 123544814352. Artifact 12909612532 is
37,829,297 bytes, SHA256
fe8a485a694b54d11a8ee98920a7ecc93e7a54d54fd8faddd3ccb227aa04b7cb.
Collector 32845 TERMINAL EXIT ZERO; do not restart. All 31 staging gates plus the
prior 54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed. Six fresh UI
originals and eight crops/contact sheet were actually viewed; 15-PNG receipt in
task outputs/acceptance-pr134-man-input-coverage/inspection.json binds full
900/120 values and matching pending/effective number regions. Headless only;
physical provenance remains null. Full proof pr134-33460b8-native31-proof.json,
completed quality/security logs, metadata/ZIP and acceptance/collector logs retained.

The opaque source protocol v2 explicitly covers every observed regular file
under the manual root and records the indexed subset separately. Actual capture:
3,202 files / 11,609,535 compressed bytes, including 3,198 indexed files and four
additional files. Descriptor-relative nofollow reads check seven stat fields and
content hashes. Raw opaque capture is 15,579,213 bytes. Fixed content role
compares zlib/GNU gzip output on every file: 3,202 members / 35,074,232 expanded
bytes match. Raw content frame is 5,586,740 bytes. Profile v3, ABI6, UID6/GID12,
empty groups, zero capabilities, NNP, controls/drain/input-tree rechecks pass.
Independent coverage binds the observed inventory and both capture domains.
61 staged artifacts total 122,529,948 uncompressed bytes. Expanded bytes are
still discarded in this accepted version. Independent acceptance does not
reinflate real gzip or reacquire expanded source bytes on Root/Mac.

Old native30 remains accepted under its original 30-gate semantics and is rejected
by the v2 coverage gate, even after profile/hash relabeling. Old native29 guard-v2
source-v1 evidence still validates. No source/roff/include/name/description/filter
semantics, complete readable namespace/runtime closure, generated-state validity
or publication authority is granted. Accounting remains 107/125 with 18 rejected
effects. Do not whitelist intentional negatives. No merge or activation.

## Initial source-request inspection boundary

The leading-source helper remains unwired into the native capture/probe. It has
five synthetic tests and now agrees with a separate byte-only implementation on
all native32 retained sources. It opens no paths and grants no graph/publication
authority. Exact-version reference notes are in task outputs/
man-db-2.13.1-source-semantics-review.md. Native32 custody is implemented and
accepted above; source-reference resolution and full NAME/filter semantics remain.

## Accepted streaming controller output bounds

Local content collection now enforces stdout/stderr limits while reading with
nonblocking pipes, rather than collecting unlimited bytes before checking size.
The deadline includes an exited launcher whose descendant keeps a pipe open,
and a launcher that closes both pipes but remains alive. Failure kills the
launcher process group, retains bounded partial diagnostics and stops the fixed
systemd service to cover its separate process domain. The final worker report
budget includes its trailing newline. Portable self-created process fixtures
cover stdout/stderr overflow, normal nonzero exit, closed pipes and inherited
pipes. Sixteen focused tests pass with two Linux-only skips; lint/diff pass.
These changes passed the fresh native30 run above; the earlier failed run remains historical.

## First content CI: failed overall, successful VM report retained

Revision 37159961d71ebf5dc5fadc0fe95cab56fdc6b5e9, run 40884679399:
quality job 123485106826 compiled the native guard with strict warnings and ran
951 tests. One test failed because GNU gzip rejects zero padding between two
members with status 2 and partial output, while Python accepts that compatibility
extension. The fixed content worker already rejects every nonzero GNU status,
truncated output or byte disagreement. Correct the synthetic crosscheck to
record this incompatibility and verify the content worker rejects it; do not
accept status 2 or silently strip padding. The Linux correction passed the subsequent accepted quality runs.
Full quality log is retained in task outputs/pr134-3715996-quality-completed-job.log.
Security job 123485106169 passed; quality and merge-gate failed. Observer 34188
terminated with failed-run custody and no acceptance attempted. Artifact
12902529879 is 37,786,282 bytes, SHA256
52d75c7cf9b1d110f973886ea295764e6cfeade4d7582b83b97d3d4f68da2768.
Its raw report records 3,198 files/members, 35,024,800 expanded bytes and both
decoders equal. Profile v3/source-content, Landlock ABI 6, UID 6/GID 12, empty
groups, zero capabilities, NNP and inherited controls are reported. Builtin
zlib binds /usr/bin/python3.13. Domain drain/control preservation are reported;
61 staged artifacts total 122,392,075 uncompressed bytes. This is diagnostic
inspection of a failed run, not independent acceptance. Full closure,
generated-state validity and publication authority remain false. The correction
and streaming limits passed the fresh exact-head run above. No merge.

## Accepted content scope and limits

The source-content role in guard profile v3 compares bounded zlib expansion
against fixed /usr/bin/gzip -cd on stdin and discards expanded bytes. Header
names/comments remain inert. Immutable support files and exact input/runtime
hashes bind the report. Content has 190s/256MiB/32tasks, per-file 10s and 8MiB,
aggregate 64MiB/16384 members and a 16MiB report ceiling. Other roles retain
their budgets. The content gate depends on all 29 prior gates. Independent
acceptance binds compressed framing and native comparison evidence without
repeating real inflation on Root/Mac. Semantics and publication remain false.

## Opaque source-byte capture accepted in native29

The new package_man_source_bytes module prepares an exact terminal-file manifest
from recomputed cache/source chains, then a fixed Linux UID6/GID12/empty-groups
worker reads opaque bytes through descriptor-relative nofollow paths. It checks
seven stat fields before/after and content hashes. It does not decompress,
interpret or execute manual bytes. Manifest is Root-owned mode0444/nlink1;
source root/parents must be trusted real directories. FIFO/symlink escapes and
changed metadata/content are rejected. Bounds:8192 files,1MiB/file,16MiB total,
4MiB manifest and24MiB output. Native27 metadata yields3198 terminal files,
11,596,108 requested bytes and a1,047,431-byte manifest; no source files were
read on Mac. A second implementation reconstructs that manifest exactly.

Cache guard profilev2 adds only the fixed --source-bytes entrypoint and a role
field (mandb or source-bytes). Only that role gains read access to two fixed
Root-owned /run files; arbitrary commands/paths are not accepted. Normal cache
controls and the existing task/production guards remain unchanged. Source role
uses its own70s/256MiB/32-task domain and fresh private16MiB cache, preventing
control probes from changing the retained regenerated-cache tree. Program,
manifest and raw guard+capture frame are retained before validation, including
bounded failure stdout/stderr. Staging rechecks inputs afterwards as before.

Independent gate29 --man-source-bytes requires all earlier28 gates and adds
three fixed artifacts (total58). It recomputes the manifest from raw cache and
observed layers, checks exact Git program/native-source provenance, fixed-role
native controls, exact hashes/counts/canonical base64 and nonauthority flags.
Guard schema v1/v2 is selected by tested Git C source, never by worker claims;
the old native27 v1 artifact was reaccepted. All28 omitted-dependency cases
reject; the gate28 path is unchanged. Two capture validators agree and reject
12 synthetic altered captures. Local focused104 tests:103 pass/one Linux skip;
Python repo lint/diff pass. C profilev2 compiled under strict warnings. Native29 executed the source reader
as UID6/GID12/groups empty with all capability sets zero and Landlock ABI6.
It captured3198 files/11,596,108 bytes; all stat fields and hashes matched.
Capture frame is15,561,203 bytes; source domain drained and control unchanged.
Artifact uncompressed total116,798,944 stays below the unchanged200MB cap.
The reader reports stat-fields verification, not complete xattr metadata proof.
All includes/alias/description/filter semantics and publication remain false.

## Guard and cache controls carried through native28

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

## Source-metadata integration accepted in native28

Feature commits 6b3b507,263d6f1,d7e2527 are included in accepted head 3a03c71.
Native28 emitted all five artifacts; independent acceptance and UI receipt passed.

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
Native28 staging artifact count55. The fresh native artifacts now corroborate
the local data-only checks; source semantics and publication remain unverified.

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

Native35 requires ALL35; subsequent source-custody gates must retain them:
--payload-closure --control-metadata --file-lists --database-files
--change-accounting --log-observation --log-decoding --log-scope
--trigger-declarations --trigger-linkage --log-sequence --log-time-window
--private-state-masks --exec-trace --loader-cache --exec-decoding
--command-diagnostics --uid-drop-comparison --compatible-stage
--process-outcomes --trigger-arguments --cache-tag-metadata
--man-cache-bytes --gdbm-decoding --man-regeneration --man-canonical
--man-input-policy --man-source-metadata --man-source-bytes --man-source-content --man-input-coverage
--man-expanded-inputs --man-leading-requests --man-compression-table --man-reference-fixtures

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
Disk last 25 GiB free/88%; warn <20 GiB or >90%, stop large downloads <10 GiB.
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
