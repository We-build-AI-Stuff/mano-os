## Failed fresh-cache launch retained; corrected setup and source metadata prepared

Run 40693734664 at d356534fe5ef9de7b3c62cc6605d74217b434cbb is terminal FAILURE.
Quality 122834883195 passed 864 tests (one Mac-specific skip); security 122834882711
and merge-gate 122844329045 failed. The one-shot 22196 exited nonzero after
retaining failed-run custody only. Artifact 12819527130 is 3,555,571 bytes, SHA256
17fdde931c4ed63f4b7ffd2718c9bfb7a1fec1afaa2b6dc5a19fbd1dce7c64ed.
Raw log/proof: pr134-d356534-security-failed-job.log and
pr134-d356534-native-failure-proof.json. No twenty-fifth-gate acceptance or fresh
UI inspection occurred. Latest fully accepted native remains d59f36e / native24.

Failure happened in bubblewrap, before the guarded man process started:
loopback: Failed RTM_NEWADDR: No child processes. The setup service lacks
CAP_NET_ADMIN, required for interface configuration (Linux capabilities(7):
https://man7.org/linux/man-pages/man7/capabilities.7.html). That missing capability
is the likely setup cause, not a proved native fix yet. The follow-up adds it
ONLY to the fixed setup service ceiling. Bubblewrap still retains only SETUID,
SETGID and SETPCAP before setpriv clears groups and every capability set. The
man guard still requires all five sets, including bounding, to equal zero.
The regression rejects a child retaining NET_ADMIN. No private-network or kernel
state check is disabled. Root/Linux execution remains disposable CI only.

Tree manifests/delta are now retained before index parsing or regeneration so a
later failure retains byte-to-tree context. Bounded binary launch failure streams
are also saved before propagating the original failure. Successful fixed artifact
names and all twenty-five acceptance gates remain unchanged. Full caller/script,
source/description/link/filter, generated-state and production policies still apply.

New local package_man_sources parses actual record bytes and compares direct A/B
primary filenames and lstat timestamps with the hash-bound candidate tree. Every
parent must be a real observed directory; traversal/absolute/binary-unrepresentable
names stay unbound. Link metadata is compared without following its target. C-E
virtual/cat records remain explicitly unresolved, never source paths derived from
alias names or pointers. Complete source graph, descriptions, filters and all
mutation/publication authority remain false. It is not wired into staging yet.

A separate implementation agrees on native24 baseline and candidate inputs:
baseline 3 indexes / 3,826 direct records / 3,602 primary / 3,596 bound, with four
missing-or-aliased parents and two absent source files; candidate 5 indexes /
3,830 direct / 3,606 primary, all 3,606 bound. Both retain 224 virtual records as
unresolved. Exact code inspection confirms man-db 2.13.1 captures lstat time before
following links; C alias pointer time is not assumed to prove alias source meaning.
Research source files are bounded data extracted from the already hash-checked
official tarball, never built or executed; its DSC PGP signature remains unverified.

Focused portable suite now runs 117 tests, 108 pass and nine Linux-only checks
skip on Mac. Repository lint/diff checks pass. Canonical writer/record framing at
local 54bfab3 still need their first native reader/writer quality test. That test
uses its own empty/single/max-size/split synthetic fixtures, never an untrusted
staged DB in a native library on Mac. The two prepared commits can now be pushed
with the setup correction because the prior VM run is terminal and preserved.
Task-root outputs/CONTINUATION.md will hold the next exact head/run/session.
No merge/publication/activation; all original phases 0-7 remain incomplete. Disk
about 50 GiB free / 76 percent; no data deleted; preserve unrelated duplicate files.

## Canonical cache bytes and record framing prepared locally (2026-10-28)

Remote and live CI remain d356534fe5ef9de7b3c62cc6605d74217b434cbb /
40693734664. Security job 122834882711 is still live. Do not push this next
source until that run is terminal and its available evidence is retained: the
workflow cancels an earlier run on a new push. One-shot local session 22196 is
still live and observes only the existing run with TWENTY-FIVE acceptance options.
Quality at d356534 passed 864 tests, with one Mac-specific skip. Native fresh-cache
rebuild, its independent artifact acceptance and fresh UI inspection remain pending.

New local package_gdbm_encode emits deterministic standard little-endian 64-bit
GDBM bytes from bounded binary key/value pairs. Prefix partitions and linear
probe positions are deterministic, allocation metadata is rebuilt, and inactive
fields/padding/trailing space are fixed from scratch. require_canonical compares
all bytes with a fresh encoding. This removes a future acceptance blind spot for
unused database bytes; it does not validate man-db semantics or permit publication.
A separate byte-number implementation agrees exactly on all eight retained native24
databases: 7,756 records, input 1,212,416 bytes, output 1,025,024 bytes. On 512
seed-13426 mutations both validators agree: 405 reject; 107 remain canonical with
potentially changed record contents, which still require separate source binding.
No native database library was loaded on Mac. An unprivileged Linux-only test will
read empty/single/max-frame/split binary fixtures and update/delete/insert in its
own synthetic encoded database. That native compatibility test has NOT run yet.

New local package_man_records reads the exact man-db 2.5.0 version, ten-field
binary frames (only the first nine tabs split), bounded timestamps and A-E record
types. It resolves case-sensitive multi-key records against their lower-case
reference keys, rejects incomplete/duplicate/unresolved references and exposes
orphan keys. Descriptions, filters, compression, pointers and alias names remain
inert base64 data. A separate implementation agrees on all eight native24 files:
7,656 direct records, 92 reference records, 202 links and no orphan multi-keys.
Both reject eight deliberately malformed cases. Primary/transitive manual-source
paths, timestamps, semantic meaning and generated-state authority remain unproved.

Focused local suite: 107 tests, 98 passed and nine Linux-only checks skipped.
Repository lint passes. Native24 data analysis is local derived evidence, not
native25 regeneration or native reader compatibility. These two modules are not
wired into staging or production. Keep all 18 unapproved effects rejecting; no
merge, publication, activation or complete-version claim. Disk about 50 GiB free,
76 percent used; no data deleted. Preserve the three unrelated duplicate files.

## Current verified baseline and fresh-cache follow-up (2026-10-28)

Head d59f36e9948e754b86e9fb87fdbdd5db9b85c864, run 40621100477, passed all
three jobs: quality 122595065461 (855 tests, including the native unprivileged
GNU DBM writer crosscheck), security-lab 122595065099, merge-gate 122601841693.
Artifact 12788132725 is 23,612,862 bytes, SHA256
33a18552aca152a9199c58ae90cd1050a24904e31fde2782b48482c97f85447e.
Recovered acceptance completed with exit zero, all TWENTY-FOUR options and the
prior 54-hash/45-flag/security/package/recovery chain. Tested merge
7c91eaf297157758222b19b2bad80aad99e48aeb has the expected base/head parents and
matching five source files. All six fresh UI originals and eight numeric/glyph
crops were viewed, including their contact sheet. Exact-head 15-image receipt:
outputs/acceptance-pr134-gdbm-decoding/inspection.json (relative to task root).
The displayed full 900/120 limits are clear; physical input provenance is null.
The old local process handles are gone; completed logs prove successful acceptance.

The follow-up source adds a fixed CI-only fresh-cache experiment. Baseline tools
and configuration are read-only; candidate /usr/share/man is overlaid read-only.
An independent empty tmpfs cache is capped at 16 MiB. Fixed setpriv clears groups
and all capability sets before the guarded UID 6 / GID 12 Python/mandb process.
It runs mandb --create --quiet /usr/share/man under bounded memory/tasks/runtime,
retains diagnostics and waits for the process domain to drain. The trusted tree
collector then observes the fresh cache. Up to 64 databases / 8 MiB raw bytes
are retained in one bounded JSON bundle. Pure Python compares exact logical
records against changed candidate indexes, reporting stale/missing/different keys.
Input baseline/candidate trees are reobserved and must remain unchanged.

This new path has portable tests only so far: 93 focused tests ran, 85 passed and
eight Linux-only checks were skipped on Mac. The independent synthetic comparison
agrees and rejects eight altered evidence claims. No new Root/VM operation
ran locally. Independent twenty-fifth acceptance is prepared outside Git; fresh
native CI, raw artifact acceptance, failure diagnosis and fresh UI inspection are
still required. No source authority, complete runtime closure, unused DB-space
validation, generated-state authorization, publication or merge is claimed.
Native accounting remains 107/125 with 18 unapproved effects. All original phases
0-7 and every remaining release gate below remain active and incomplete.

Latest disk about 50 GiB free / 75 percent used; no data deleted. Preserve the three
unrelated untracked duplicate files listed below. Earlier sections are historical;
use this entry and task-root outputs/CONTINUATION.md for current source/run state.

## Native man-index bytes accepted; logical decoding integrated for next CI

Exact head 9f62c05c1bb9a011b9b66e8204e99fce60b437b7 / run 40617804840 passed all
three jobs: quality 122584287348 (846 tests), security-lab 122584287075, merge-gate
122591792097. Artifact 12786772685 is 23,346,178 bytes, SHA256
ba16c62f18f6dab6d2c30a455255938283f297cd215ff13bfe94d0f30fde94fb.
One-shot 91951 exited zero: digest, tested merge 96605ca0d01ae1608d65254148a1769abd630d54,
expected base/head parents and four source files matched. All TWENTY-THREE options
plus complete prior 54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed.
Six fresh UI originals and eight numeric/glyph crops were inspected, also in a
labelled contact sheet; the 15-PNG receipt is acceptance-pr134-man-cache-bytes/inspection.json.
Full 900/120 values are readable and pending/effective numeric regions identical.
Headless only; physical provenance remains null. No verifier or evidence gate waived.

Native metadata accounting is now 107/125, with 18 unresolved effects. Eight raw
index copies across five paths total 1,212,416 bytes and match their tree metadata
and hashes. New de.UTF-8/ja.UTF-8 indexes each have only a candidate copy. Baseline
and candidate main/de/ja indexes preserve exact bytes despite changed timestamps.
No generated-content authorization or publication follows from this observation.

Local codec 71a4c9f independently decoded all eight actual retained databases:
7,756 active records, no failures, and a separate implementation agrees exactly.
This is local analysis of native23 bytes, not native decoder execution. The baseline
already has an sl cache record although usr/share/man/man6/sl.6.gz is absent from
its tree; the candidate adds that authenticated page. Do not infer cache correctness
from byte equality. Exact man-db 2.13.1 source confirms -p disables purging obsolete
entries; the observed callback uses -pq. This does not establish the baseline's
history. Source binding and trusted regeneration remain necessary.

The next source integrates bounded pure-Python logical decoding after retaining
all raw copies. It writes staged-man-index-decoding.json and a hash/size/count
summary; the independent verifier reconstructs every record from raw bytes. Inputs
are bounded to 16 files/8 MiB, each codec file 2 MiB, aggregate 65,536 records and
16 MiB serialized output. Free-space graph, unused bytes, man-db semantics, source,
regeneration and all mutation/publication authority remain false. No native library
is loaded by the codec. Failed decoding leaves raw inputs for diagnosis.

Local focused checks: 94 tests, 93 passed and one Linux-only native GNU DBM writer
fixture skipped on Mac. That unprivileged CI fixture still needs its first Linux
run. Independent actual-data integration agrees (1,943,219-byte derived report),
ten altered summaries reject, and 24-option command forwarding/lint/compile/diff
checks passed. Earlier 512 synthetic mutations agreed in both implementations.
Full local discovery remains constrained by diagnosed shared dependency file reads;
no new full-suite pass is claimed. No Root/Linux/VM execution occurred on Mac.

Next native acceptance requires TWENTY-FOUR options: add --gdbm-decoding after
--man-cache-bytes. New report is the sole additional artifact; raw copies retain
their fixed names. Refresh source/CI and inspect fresh evidence after pushing.
Full original phases 0-7, the 18 effects, script custody, dependency order, trusted
cache reconstruction, production staging/activation/runtime closure and release
requirements remain incomplete. No merge/publication. Disk about 45 GiB free.

## Bounded logical GDBM decoder prepared locally, not wired into staging

The current remote remains 9f62c05c1bb9a011b9b66e8204e99fce60b437b7, native CI
40617804840. Quality job 122584287348 passed all 846 tests; its completed raw log
and SHA-bound proof are retained. Security-lab is running. One-shot 91951 follows
that exact source with TWENTY-THREE options. Latest fully accepted native is still
1194d2a / run 40615467240 (21 options, fresh UI receipt). Do not conflate sources.

Next local package_gdbm_decode decodes active key/value records as bounded Python
data. It uses the standard/numsync little-endian off_t-64 layout and signed-char
hash facts in GNU GDBM 1.24. The accepted package inventory confirms libgdbm6t64
1.24-2 and man-db 2.13.1-1. Official upstream research source (1,195,931 bytes) was
matched to the HTTPS Debian .dsc SHA256; PGP signature was not verified, and the
source was never built/executed. Provenance is in gdbm-1.24-research-source.json.

The decoder bounds file/directory/bucket/key/value/expanded/probing work, verifies
hash/prefix/directory/probe reachability and rejects duplicate keys or overlapping
structural/data regions. Metadata disjointness is checked before bucket scanning,
so overlapping directory aliases cannot amplify cell work beyond physical input
bounds. GDBM can reserve a final block beyond EOF; active records remain strictly
bounded even when unused trailing space is absent. No native database library is
loaded. Free-space chains, unused bytes, man-db semantics, source mapping,
regeneration and change/publication authority remain explicitly false.

Local focused suite: 93 tests, 92 passed and one deliberately Linux-only native
GNU DBM writer test skipped on Mac. That future CI-only unprivileged fixture creates,
splits, deletes and reuses its own database, then compares exact records. It never
feeds staged data to a native library and has not run in CI yet. Independent Python
decoding matches synthetic standard/extended/binary fixtures and rejects eleven
report/raw substitutions. Deterministic seed 13424, 512 mutated synthetic files:
both decoders reject 289 and agree on 223 bounded decodes with unvalidated-space
flags false. Lint/compilation/diff checks passed. No Root/Linux execution on Mac.

Hold this codec source from pushing/wiring until native23 supplies actual baseline
and candidate index bytes. First decode those retained bytes locally and compare
both implementations. Only then add explicit native decoding artifacts/gates to
the staging path. Do not infer records from hashes or treat this synthetic result
as native cache correctness. Trusted regeneration from authenticated manual-source
inputs using immutable baseline tools remains necessary. Reconstructed caches can
be the publication inputs; the original untrusted binary layout need not become
authority. No reconstruction/activation mechanism is implemented by this codec.
Full original phases 0-7 and all remaining requirements stay incomplete. No merge.

## Native observed callback arguments accepted; combined cache batch next

Exact head 1194d2a74cf70f48e2d793e1d466ac3160594393 / CI run 40615467240 passed
all three jobs: quality 122576810621 (836 tests), security-lab 122576810886 and
merge-gate 122583355167. Artifact 12786081414 is 22,978,862 bytes, SHA256
939cb415dca4a2349a71d74a70d2ac76b058ff0c02f112a79ed73da89da6e838.
One-shot session 21423 exited zero after digest verification, fetching tested merge
5965b99ca8d9c51acd2f2513e58e4ceef8690cb9 and verifying its expected base/head
parents and worker source bytes. All TWENTY-ONE staging options and the complete
54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed. No verifier gate waived.

Independent raw-trace recomputation links two callbacks: libc-bin.postinst
triggered ldconfig (PID 7980, entry 47), and man-db.postinst triggered
/usr/share/man (PID 7982, entry 51), to exact installed identities/declarations
and authenticated activation sources. Both scripts and mandb PID 7983 retain
explicit normal zero exits in observed generation zero. Ancestry, complete exec
coverage, script contents at exec, effects and all authority remain false.
Production remains securebits 43; the compared CI-only stage uses 11.

Six fresh UI originals plus four numeric and four glyph crops were inspected,
with all eight crops also visible in a labelled contact sheet. Receipt
acceptance-pr134-trigger-arguments/inspection.json binds fifteen PNG hashes to
this head/run/artifact. Full 900/120 values are readable; pending/effective numeric
regions are pixel-identical. Headless evidence only; physical provenance null.
Current native accounting still verifies 55/125 and rejects 70 effects. Recomputing
the future local ctime-only metadata rule on this new artifact agrees independently
at 107/125 with 18 unresolved; this is not native cache-policy proof.

Local commits 89d8a01 and 96c8993 prepare the metadata rule and bounded, manifest-
bound raw man-index collection as one combined future batch. Its native acceptance
requires TWENTY-THREE options: add --cache-tag-metadata and --man-cache-bytes after
--trigger-arguments. Eighty-five focused tests, independent negative substitutions,
CLI forwarding, lint/compilation/diff checks passed. Full local suite remains
limited by diagnosed shared-environment file read stalls; no local full pass is
claimed. Baseline index contents have not yet been collected/parsed/authorized.

Base remains 65fdfc02e3dbb18f791a92374a24690ae4e1ba87; all five review threads were
resolved at refresh. Push the combined batch now, then validate its exact head.
Full original phases 0-7 remain active; script custody, dependency order, generated
content and loader/log policy, production staging/activation/runtime closure and
release gates remain incomplete. No merge/publication. Disk about 45 GiB free.

## Bounded man-index byte retention prepared locally

The next local source now also retains raw baseline/candidate bytes for every
changed man index in the fixed root/one-locale profile. Paths are selected from
recomputed tree deltas, never a caller allowlist. At most eight database paths,
2 MiB per file and 8 MiB total are allowed. Baseline absence and candidate removal
are explicit. Raw data must match the exact tree size/hash and plain UID 6/GID 12,
0644, single-link/no-xattr profile; no database library is loaded or executed.

A descriptor-relative reader rejects symlink ancestors/leaves, stale observed
ownership/mode/link/size/timestamps, and identity/path changes during reading.
This is separate from the Root-owned catalog reader because legitimate man cache
files are owned by man. Unit fixtures initially lacked required root manifest
entries; those were corrected without weakening tree admission. Portable file
identity/alias/change tests run as the ordinary Mac user, never Root/Linux probes.
All 85 focused tests passed after correction, plus lint, compilation/diff checks,
independent opaque-byte matching, ten substituted report/byte rejections and mocked
23-option CLI forwarding. No native collection or cache semantics claim yet.

New artifacts use deterministic staged-man-index-N-baseline.db and
staged-man-index-N-candidate.db names. The independent verifier derives the complete
expected set from both tree manifests, checks all raw byte hashes and report
fields, and keeps database-record/source/regeneration/generated-state/authority
claims false. Future acceptance adds --man-cache-bytes after the prepared
--cache-tag-metadata rule: TWENTY-THREE options. The local metadata rule still has
only a derived 107/125 accounted result with 18 unknown effects; it is not native
proof. This batch includes both metadata and byte-retention work in one future run.

Current remote 1194d2a / CI 40615467240 still requires TWENTY-ONE options. Quality
passed 836 tests; security is running. Session 21423 follows this run and must not
be restarted on timeout. Hold source push until its artifact is inspected. Latest
accepted native remains 43c7ed4 / run 40612599127 (twenty options). Full phases 0-7
and all outstanding production/cache/script/release work remain active. No merge.

## Preserved man-cache tag metadata classification prepared locally

The live remote source is 1194d2a74cf70f48e2d793e1d466ac3160594393, CI run
40615467240. Quality job 122576810621 passed all 836 tests; its raw completed log
and SHA-bound proof are retained. Security-lab remains running. One-shot session
21423 and watcher 74612 follow this same run. It requires TWENTY-ONE acceptance
options, without the following new metadata rule. Latest fully accepted native
source remains 43c7ed4 / run 40612599127 with twenty options and visual inspection.

The next local rule classifies existing Debian man-cache CACHEDIR.TAG files only
when their bytes/hash, mtime, ownership, mode, links, xattrs and every other field
are identical to the baseline; only ctime may differ. The scoped profile requires
a plain nonempty bounded 0644 file, UID 6/GID 12, one link, matching hardlink anchor,
and a canonical root or one-locale tag path. Strict integer types exclude booleans.
New files, changed content/mtime/security metadata and other/deeper paths remain
unresolved. This does not validate tag semantics or any generated cache content.
Existing parent-directory timestamp rules then apply without changing security
metadata. Strict rejection of every remaining unknown effect stays in place.

All 78 focused accounting/callback/staging/decoder tests passed locally, including
three new accounting tests with multiple metadata substitutions. Independent local
recomputation on accepted native20 manifests agrees: 26 unchanged tags plus their
parent timestamps raise accounted differences from 55 to 107 of 125, leaving 18
unresolved. This is a derived LOCAL result, not native22 proof. Twelve altered
classification/metadata/authority reports reject. Lint, compilation, diff checks
and a mocked 22-option CLI forwarding check passed. No Root/Linux execution on Mac.

Future native acceptance adds --cache-tag-metadata after --trigger-arguments:
TWENTY-TWO options, explicitly gated so older twenty/21-option artifacts retain
legacy accounting expectations. No new artifact names. Hold the next push until
current native21 completes and is inspected. Full v2.1 phases 0-7 remain active;
script custody, new/changed cache content, loader state, logs, dependency order,
production staging/activation/runtime closure and release gates remain incomplete.
No publication or merge. Disk remains about 45 GiB free; no data deleted.

## Native process exits accepted; observed callback linkage next

Exact remote head 43c7ed45d05195ac536addeff9c3ff44d034f074 / run40612599127 ALL3SUCCESS:
quality122567494075 (all830 tests), security122567496155, merge-gate122575492327.
Artifact12784892346, 23,028,245 bytes, SHA256
d3b209125ecdd96aa679b0f88dc8852c782d5c750a3cbb9b363c88a2cdaae7b0.
One-shot session56197 exited0: acquired digest-bound artifact, fetched tested merge
7dde297e3bf033ce7b70742908cb21a91b3728fb, verified parents base65fdfc02.../head43c7ed45...
and worker source equality, then passed all TWENTY staging options plus complete
prior 54-hash/45-flag/PAM/Stop/recovery/package/ELF acceptance. No gate waived.

Trusted trace independently decodes30 exec records (20 replacements/10 failures)
and31 terminal summaries. libc-bin.postinst PID7894 exec47/exit50, man-db.postinst
PID7896 exec51/exit55, mandb PID7897 exec53/exit54 each have explicit normal zero
exits in observed generation0 with no intervening image replacement. These are
three bounded observations, not all-process status/credentials/ancestry/coverage,
script-at-exec or callback effect authority. Production remains securebits43;
CI-only staging remains11. Scheduled APT writer precondition passed this run.

Six fresh UI originals, four numeric crops and four magnified duration crops
actually inspected; receipt acceptance-pr134-process-outcomes/inspection.json has
14 PNG hashes. A preliminary apparent clipped-digit concern was resolved with
magnified glyphs and pixel-identical pending/effective numeric regions: full900
and120 values are visible. No UI source change needed. Headless only; physical
input provenance null. Strict accounting still verifies55/125 differences and
rejects70 unapproved effects. Generated man/cache/log policy remains incomplete.

Local callback source7208eab (not yet native21 tested) recomputed both observed
callback argument sets on this new native20 evidence, independently agreeing.
Earlier67 focused tests, twelve altered-report rejections, 21-option CLI forwarding,
lint and compile checks passed. Full local discovery also stalled when using exact
Git archive source and a fresh cache; samples show shared virtualenv pydantic .pyc
and langchain beta_decorator.py reads. Both owned tests exited143; no assertion
failure/full local suite success claimed. Existing caches/source not deleted.

Next push the prepared callback source with this evidence. Its native acceptance
requires TWENTY-ONE options (--trigger-arguments after --process-outcomes). Retain
this accepted20 artifact separately. All five current CodeRabbit threads resolved;
base unchanged. Full original v2.1 phases0-7 remain incomplete; no merge/publication.
Disk45GiB/78percent. No local VM/model or Root/Linux execution on Mac.

## Observed trigger argument linkage prepared locally; native run still pending

Current running native CI is 40612599127 at remote 43c7ed45d05195ac536addeff9c3ff44d034f074.
Completed quality job 122567494075 passed all 830 tests; raw connected job log and
SHA-bound proof retained. Security-lab remains running, not accepted. This source
requires twenty acceptance options, including --process-outcomes. Re-poll the same
run/watch session 45178; do not restart on an observation timeout.

Next LOCAL source adds package_trigger_arguments.require_arguments. It recomputes
signed-control/baseline declaration activation linkage and installed package identity,
then requires each observed callback's exact postinst/triggered argv frame to name
exactly the supported trigger set. Reordered names are equivalent; duplicate, empty,
missing, additional and unknown names reject. Multi-Arch same uses qualified info
paths. Unknown successful maintainer scripts, duplicate or missing callbacks reject.
The guard reports bounded argument linkage only; ancestry, coverage, script bytes at
exec, effects and all change/publication authority remain false. No script executes
on Mac. Source reference: Debian deb-triggers(5), and Debian Policy maintainer-script
exit-status guidance. This is necessary evidence, not callback authorization.

Six new tests plus existing staging/linkage/outcome/decoder regressions: all 67
passed locally. New module recomputed both callbacks on archived accepted 75fdfe3
bytes; independent implementation agrees and rejects twelve altered reports. This
is local analysis of old evidence, not fresh native twenty-one-option acceptance.
Lint, embedded worker/helper compilation and diff checks passed. Future acceptance
adds --trigger-arguments after --process-outcomes (TWENTY-ONE); old/current twenty
option source must not be tested with the new requirement. No new artifact names.
Hold the next source push until the live twenty-option run is terminal and inspected.
Keep all current/failed evidence; full goal remains active and incomplete. No merge.

## Native process-outcome attempt rejected; CI APT writers now quiesced

Head 43a5f3c/run 40554651554: quality passed all 827 tests, but security-lab and
merge-gate failed. Acquisition's final catalog load rejected changed APT source
index identity before staging or terminal-trace collection. No process-outcome
native success is claimed. Artifact 12757142876 (2,910,460 bytes), SHA256
9f85b77817009dc357e8134b14cae9b1d5a535d799c743bf849584cf516f3c47 was downloaded
with failed-run custody only. Failure log and raw quality proof are retained under
task outputs. Latest accepted native remains 75fdfe3 with nineteen options.

Failed VM serial logs show both scheduled APT timers enabled. This is a possible
concurrent writer, not conclusive actor attribution. Disposable guest preparation
now persistently masks/stops both daily timers and services before controlled APT
operations. The staging acquisition requires all four fixed units masked/inactive
before opening the catalog. Catalog fingerprint and live identity rechecks remain
unchanged and must still reject every source change. No production timer policy
changes. Three focused guard tests plus fifteen outcome/decoder tests passed;
lint, shell syntax and diff checks passed. Source 43c7ed45d05195ac536addeff9c3ff44d034f074
is pushed; fresh native validation must pass all jobs and twenty acceptance options.
Old failed artifacts cannot substitute. Full goal remains incomplete; no merge.

## Process-outcome trace prepared; native validation pending

The trusted CI tracer retains terminal summaries using -q. Explicit decoder dialect
strace-hex-execve-exit-v1 records normal exits, signals and core-dump markers plus
observed PID generations. Legacy decoding remains unchanged and rejects terminal
frames. Generations distinguish observed reuse; they are not proof of births or
ancestry. Malformed, truncated, out-of-range and pending-call terminal frames fail.

A fixed guard requires exactly one successful image record and a later normal zero
exit in the same observed PID generation for libc-bin.postinst triggered ldconfig,
man-db.postinst triggered /usr/share/man, and /usr/bin/mandb -pq. An intervening
successful image replacement rejects. These are bounded observations; full process
coverage, credentials at exec, script bytes, ancestry, trigger/change/publication
authority remain false. Production securebits 43 remains unchanged.

Independent acceptance now requires TWENTY options, adding --process-outcomes after
--compatible-stage. It independently decodes raw bytes and recomputes all three
matches. Old nineteen-option native artifacts cannot prove these exits. Fifteen
focused tests passed (seven new outcomes and eight decoder regressions); Ruff and
diff checks passed. Independent synthetic matching and eleven substitutions passed.
The full local suite stalled reading an existing mano_provider credentials .pyc;
process sample retained, owned process terminated with exit 143. This is neither
a full-suite pass nor an assertion failure; CI must supply full-suite evidence.
No Linux/Root execution ran on Mac. Latest accepted native remains 75fdfe3/run
40548807617; new source must pass fresh native CI and twenty-option acceptance.
Full v2.1 phases 0-7 remain incomplete. No merge, publication or activation.

## Native actual-compatible-stage accepted; mandb starts, generated state unresolved

Exact head 75fdfe36d9b46d6fded86ad837fbde3ecba2546a / run 40548807617 ALL3SUCCESS:
quality 122346621695, security-lab 122346622343, merge-gate 122359638200.
Artifact 12755003539, 23,000,502 bytes, SHA256
8a7c28a09b7208d6d2632bbd4590eb51783f2d732252f8cb857b4edcd6131732.
Download 98514 and full independent acceptance 44936 exited 0. All NINETEEN options
plus complete 54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed. Exact CI
merge 68cbebe716cd9c5b16544de8b7032c4306346fd2 was fetched before acceptance;
parents are base 65fdfc02... and exact head 75fdfe36..., with both worker sources
identical to PR-head bytes. No verifier gate removed and no native rerun needed.

Actual CI staging worker used securebits 11 with fixed 0xdb ceiling/NNP/namespaces.
Trace now 30 calls: 20 successful image replacements, 10 failed attempts. Exact setpriv
UID-drop invocation at line 28 followed by /usr/bin/mandb -pq at line 29, PID 7899.
Direct dpkg/diagnostic ldconfig return 0; dpkg stdout 533 bytes, stderr 0. Thus prior
setpriv failure is resolved in CI staging. This proves image startup, not mandb
exit status, credentials at exec, ancestry, complete exec coverage, script bytes
or trigger authority. Production remains securebits 43, not changed by this run.

Actual generated state now adds man-cache changes: strict accounting verifies 55
of 125 differences and rejects 70 unapproved. Those include CACHEDIR.TAG/index.db/
cat6/man-cache directory changes, plus prior cache/log/synthetic negative files.
Do not authorize them by name or report this as all mutations validated. Complete
man-cache content/source/regeneration policy, loader cache/aux-cache, log and
callback outcomes/provenance remain required. No publication or activation.

Six fresh UI originals/four numeric crops actually inspected, full 900/120 values
readable; receipt outputs/acceptance-pr134-compatible-stage/inspection.json under
task root. Physical provenance null. Full CI quality 820 tests passed, raw log+SHA
proof in pr134-75fdfe3-quality-proof.json. Local full-suite import-read stalls were
not passes; CI supplies exact-head full-suite evidence. Full original v2.1 phases
0-7 remain incomplete, including production staging/activation/runtime closure
and remaining product/signed OS release gates. No merge. No live CI pending.

Next: acquire bounded process outcomes (current exec trace suppresses exit frames),
then bind actual callback identity/arguments/script custody and generated man/cache
state to approved inputs; maintain strict unknown-effect rejection and no replay.
Disk 42.9 GiB / 79 percent, no threshold warning, no deletion or local VM/model images.

## Actual compatible staging prepared; full suite delegated to CI

CI staging now uses the separately native-tested securebits 11 profile with the
same 0xdb ceiling, NNP, namespaces, sealed input layout and private masks. Main
worker reports uid-drop-compatible-v1; production code remains securebits 43.
The locked 43 and alternative 11 UID comparison still runs with all negative checks.
After raw trace/custody/command evidence is retained, a new fixed guard requires
exact setpriv --reuid man --regid man --init-groups -- /usr/bin/mandb -pq followed
by a successful /usr/bin/mandb image record with argv [/usr/bin/mandb,-pq], same
observed PID and strictly later entry. Missing, duplicate, failed, reordered or
substituted records reject. PID linkage is an observed trace match, not verified
caller ancestry. Process exit status, credentials at mandb exec, complete coverage,
script bytes, callback authority and publication remain explicitly false.

Independent acceptance adds --compatible-stage after all eighteen prior options
(NINETEEN). Old sources still require securebits 43; only the explicit new option
requires 11 plus the matching profile and independently decoded actual trace.
No new artifact names; raw records and the new report remain hash-bound. Actual
mandb execution/new generated filesystem state need their own native source run.

Local focused tests: three new compatible-stage tests and five UID comparison
regressions passed. The old native fixture lacking mandb is rejected; synthetic
frames match and ten report/profile/missing-record substitutions are rejected by
an independent implementation. Ruff, embedded workers/helper compilation and
diff checks passed. Full local discovery stalled in existing filesystem reads:
first stop_state.cpython-313.pyc, then prompts.py with a fresh temporary cache.
Process sample/open descriptors retained under task-root outputs. Both owned test
processes were deliberately terminated (exit 143); these are not test passes or
assertion failures. Existing user files/caches were not deleted. Full suite must
run in CI quality before considering this source verified. No new Root/Linux
execution occurred on Mac. User authorized continuing in disposable CI.

Full original v2.1 phases 0-7 remain incomplete; no merge/publication. Next native
run must pass all jobs and nineteen options, including actual mandb image record,
then fresh six UI originals/four crops and exact-source custody. Keep failed
4ae4901 artifact and accepted 5a16944 evidence distinct. Disk 42.9 GiB / 79 percent,
no warning threshold crossed, no deletion or local VM/model downloads.

## Native UID-drop comparison accepted; actual package callback still next

Exact source 5a16944273bf906c3286a9af7f68fa68e38e5cf5 / CI 40441722096
ALL3SUCCESS: quality 121983390612, security-lab 121983390726, merge-gate
121990160907. Artifact 12706668261: 22,976,977 bytes, SHA256
962443cb7feb4b9033ffde2a6c6e7df4257930d33dd3c552a550df008795e95a.
Download 5280 exited 0. First independent acceptance 25628 failed because temporary
GitHub merge source 80e596dcbeaec7a8f3f0e0d237413069ae773d7e was absent locally.
Fetched exact object (session 62137 exited 0); verified parents are base 65fdfc02...
and exact PR head 5a169442..., and both worker source files equal PR-head bytes.
No verifier gate changed and no native rerun. Wrapper preserved/rotated the first
failure log; repeat acceptance 36208 exited 0. All EIGHTEEN options plus complete
54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed on the same bundle.

Actual locked control reproduced setpriv failure. Alternative securebits 11:
UID 6/6/6, GID 12/12/12, groups [12], effective/permitted/ambient caps 0,
inheritable/bounding 0xdb, NNP 1. Capability addition, root-ID restoration and
securebits reset each failed EPERM with identical before/after state. Both fixed
test domains drained. Source and raw reports independently matched. This proves
only the isolated helper comparison, not mandb or package callback completion.
Main staged package worker and production still use securebits 43. Current main
stage trace 29 calls / 19 image replacements / 10 failures; accounting 55/64, 9 unapproved.
Six fresh UI originals/four numeric crops actually inspected, full 900/120 readable;
bound receipt outputs/acceptance-pr134-uid-drop-comparison/inspection.json under
task root. Headless only; physical provenance null. No publication.

Next: apply the proven alternative only to CI staging worker, with the same 0xdb
ceiling/NNP/private namespaces/negative controls, then acquire actual package
trigger/mandb trace, command diagnostics and generated-state changes. Do not
change production policy merely from the helper comparison. Keep independent
acceptance versioned so old 43 native sources retain their own expectations.
Actual callback status/ancestry/script bytes/authority, complete cache/log/unlisted
mutation policy, production staging/activation/runtime closure and original v2.1
phases 0-7 remain incomplete. No merge. No new CI currently pending.

Disk recovered externally to 43.3 GiB free / 79 percent; user notified. No data deleted
by this agent; no local VM/model downloads. Keep threshold checks before builds.

## Native UID comparison failed on test-source read permission; corrected locally

Source 4ae4901b43fa4cdcdfd4b175e418f675836ca80d / CI 40439743818 is terminal
FAILURE: quality passed, security-lab and merge-gate failed. No merge or bypass.
Retained artifact 12705434673 is byte-verified: 2,902,841 bytes, SHA256
507ffed583bc1a6f0a9dd031273eb81ecdc7d7bef190a12b8808b7f15d2d4659.
Download session 4434 exited 0; failed-run custody only, NOT acceptance. Raw failed
job log saved as pr134-4ae4901-failed-job.log. New VM failure-copy branch preserved
both staged-uid-drop-locked.json and staged-uid-drop-compatible.json in the bundle.
Their raw bytes are saved separately with pr134-4ae4901- prefixes under outputs.

Locked control: securebits 43, all five caps 0xdb, NNP 1, private namespaces, drained;
setpriv exit 1 and exact original keep-process-capabilities EPERM error.
Alternative: securebits 11, same initial caps/NNP/private namespace state, drained;
exit 2, no stdout, exact stderr:
/usr/bin/python3: can't open file '/run/probe.py': [Errno 13] Permission denied
This identifies a fixture bug: the test source was mode 0400 Root-owned while the
child runs as man. It does NOT prove the subsequent capability/escalation checks.

The correction gives only the fixed uid-drop.py source mode 0444, still opened
exclusively under Root-private BASE and read-only bound at /run/probe.py. Existing
staging probe.py stays 0400. No execution policy, capability ceiling, negative
control, namespace, output-custody or escalation requirement is weakened. A new
portable temporary-file regression checks read/no-write mode, exact source bytes
and refusal to overwrite an existing source. No Root/Linux worker executes on Mac.
817 local tests: 762 passed, 55 skipped; Ruff, embedded compilation, shell and diff pass.
The corrected source still requires fresh native CI and all EIGHTEEN acceptance
options. Latest accepted source remains 7af2987 / run 40436347345 with 17 options.
Original v2.1 full goal remains incomplete; no candidate publication or merge.
Disk ~19.7 GiB / 91 percent, warned; no deletion / local VM / model images.

## CI-only UID-drop comparison prepared locally

Added a fixed comparison before staged dpkg execution: securebits 43 remains the
locked negative control, while a separate disposable worker uses securebits 11
(same NOROOT/no-setuid-fixup locks, no KEEP_CAPS lock). Both retain the exact 0xdb
capability ceiling, NNP and private namespaces. The main package worker still uses
43; production code is unchanged. The alternative is a compatibility experiment,
not authorization to weaken a boundary.

The fixed setpriv invocation drops all three user/group IDs to the baseline man
account, initializes its groups, then executes fixed Python from a read-only
/run mount. The child must have zero effective/permitted/ambient capabilities,
no inherited bit outside 0xdb, bounded set 0xdb, NNP 1, securebits 11 and unchanged
private namespaces. Attempts to regain root IDs, add CAP_SYS_ADMIN or clear
securebits must fail EPERM without changing state. Parent capability addition
must also fail. Each dedicated resource-limited systemd domain must drain.
The old control must reproduce the exact observed keep-caps error with exit 1.
This does not execute mandb or prove callback success/ancestry/script authority.

Comparison program and complete raw observations are retained and bound by hash.
Failure reports are saved before validation, and VM orchestration now copies guest
evidence before exiting on any staging-probe failure. The main stage artifact
manifest adds exactly staged-uid-drop-program.py and staged-uid-drop-comparison.json.
Independent acceptance adds --uid-drop-comparison after all seventeen prior options
(EIGHTEEN total), comparing program bytes to the exact Git source and checking
both profile results. Legacy sources keep their prior option sets.

816 local tests: 761 passed, 55 skipped. Four new tests use only synthetic kernel
reports and argument construction; neither Root/Linux worker runs on this Mac.
Existing portable subprocess tests still run unprivileged only. Ruff, embedded
worker/helper compilation, shell syntax and diff checks pass. Real UID-drop/kernel
behavior remains unmeasured until this source's native CI. Original v2.1 phases 0-7
and production staging/activation/runtime closure remain incomplete. No merge.
Disk about 19.7 GiB / 91 percent; warned, no deletion or local VM/model downloads.

## Native command diagnostics accepted; UID-drop conflict identified

Exact source 7af29875a140435d4108f5ab5366c3130a73b1fd / CI 40436347345
ALL3SUCCESS: quality 121965805875, security-lab 121965806144, merge-gate
121973388566. Artifact 12704898914, 23,028,150 bytes, SHA256
3bcaffbce1cf80b2ea56f1718476b6ebece93165f45532b9e97f765c280e7508.
Download 84551 and independent full acceptance 32717 exited zero. All seventeen
options plus prior 54-hash/45-flag/PAM/Stop/recovery/package/ELF chain passed.
Six fresh UI originals/four numeric crops actually inspected, full 900/120 values
readable; receipt outputs/acceptance-pr134-command-diagnostics/inspection.json
under task root. Physical provenance null; no publication.

Native dpkg stdout 533 bytes; stderr 67 bytes. Exact stderr:
setpriv: keep process capabilities failed: Operation not permitted
Direct dpkg/diagnostic ldconfig both returned zero with complete captures;
ldconfig streams empty. Thus direct dpkg success did not establish callback
completion. Trace still 29 calls, 19 zero execve returns/10 failures. Cache 572/577,
accounting 55/64 with 9 unapproved effects rejected. No mandb execution observed.
Installed util-linux 2.41.5-0+deb13u1, man-db 2.13.1-1 from bound baseline status.

Upstream util-linux v2.41.5 setpriv.c lines 1099-1100 unconditionally call
prctl(PR_SET_KEEPCAPS,1) and emit the matching error on failure. Retrieved through
authenticated read-only GitHub API; saved task-root outputs/util-linux-2.41.5-setpriv.c,
SHA256 4519ded6f9df4e0b1b649fdba34a3db5cd23805bfdd2cb57e1ffa52fd360eedb.
Source https://github.com/util-linux/util-linux/blob/v2.41.5/sys-utils/setpriv.c
Kernel API https://www.man7.org/linux/man-pages/man2/PR_SET_KEEPCAPS.2const.html
states EPERM for SECBIT_KEEP_CAPS_LOCKED. Native worker securebits 43 contains that
lock. This is a concrete compatibility conflict, not evidence to silently weaken
the production boundary. Next: CI-only differential UID-drop compatibility test
with old locked control and proposed bounded alternative; verify all capability
sets/UID/GID/groups/NNP, failed escalation and domain drain before policy changes.
No such alternative has run yet. Production securebits/caps remain unchanged.

CI is terminal, no new run pending. Local=remote 7af2987 before this evidence note.
Full original v2.1 phases 0-7 remain incomplete: callback authority/ancestry/script
bytes, cache objects/regeneration, unlisted state, production staging/activation/
runtime closure, remaining product and signed OS release gates. PR 134 not ready.
Disk ~19.7 GiB free/91 percent, warning already delivered. No deletion/VM/model images.

## Native execution decoder accepted; command diagnostics next

Exact source 9cb9ae5cbd6308becbb37952cd8e820729b0d242, CI 40335584785
ALL3SUCCESS: quality 121616140956, security-lab 121616140549, merge-gate
121633496328. Artifact 12659191351: 22,981,755 bytes, SHA256
8e3c3b4b73040f7ec395e9c3396268dceaa82eae9eba2b45b1504d5bd8a4a793.
Download session 56368 and full independent acceptance 40009 exited zero.
All sixteen staging options plus the full 54-hash/45-flag prior chain passed.
Raw trace/version/custody JSON matched the worker report; independent decoding
reproduced 29 calls, 19 zero execve returns and 10 failed attempts. Image replacement
is not process exit success. Callback outcomes, ancestry, all-exec coverage,
actual trigger argument policy, script contents and publication remain unverified.
Cache tables remain 572/577; strict accounting is 55/64 with nine unapproved
changes rejected. No candidate activation or publication.

Six fresh originals and four numeric crops actually inspected; full 900/120
values readable. Bound receipt in task-root outputs:
acceptance-pr134-exec-decoding/inspection.json. Headless only, physical provenance null.
Five existing CodeRabbit threads reverified resolved. Main/base is unchanged at
65fdfc02e3dbb18f791a92374a24690ae4e1ba87; refresh before merge.

Local diagnostic commit de42adc624b1e73a3c47d974ff79b7b676dcd5c4 is ready
to push with this evidence record. Its new native run must pass SEVENTEEN options,
adding --command-diagnostics after --exec-decoding. Direct child return codes and
bounded raw stdout/stderr will help diagnose the unresolved mandb outcome; no
native diagnostic bytes have been acquired yet. Full original v2.1 phases 0-7
remain active/incomplete, including production staging/activation/runtime closure,
callback authority, unlisted mutations and the remaining product/release gates.

Disk warning delivered: about 19.8 GiB free / 91 percent. No deletion; only small
necessary artifacts. No local VM/model downloads. Stop large downloads below 10 GiB.

## Local bounded command diagnostics (not pushed)

The CI staging worker now observes dpkg and diagnostic ldconfig via a portable
selector-based reader: separate raw stdout/stderr, each at most 64 KiB, a monotonic
per-command deadline and a separate child session for timeout/flood cleanup. It
waits for the actual direct child's return code. Flood/deadline captures are
explicitly incomplete and fail the controller's success gate. The outer systemd
cgroup/45-second deadline and drain remain required; process-group cleanup alone
is not a confinement or descendant-outcome proof.

A failed dpkg skips the synthetic cache step and reports ldconfig as null. The
controller exports raw streams and the command JSON before later checks; it still
rejects nonzero/incomplete/skipped commands, retaining raw trace/custody as well.
A successfully returned worker JSON means observations were delivered, not that
the package transaction succeeded. Stream bytes/hash/base64/size and reported
return codes are cross-checked. Raw command output is untrusted data and is never
executed or printed as terminal control content.

812 local tests: 757 passed, 55 skipped in the repository dependency environment.
Five new tests exercise real portable unprivileged helper processes only, covering
binary stdout/stderr, nonzero status, flood, deadline, failed dpkg/skipped cache,
and altered metadata/authority. No Root/Linux worker ran on this Mac. Ruff,
embedded PROGRAM compilation, independent helper compilation and diff checks pass.
Independent local synthetic acceptance matches streams and rejects six altered
reports/raw substitutions; no new native mandb diagnosis is claimed yet.

Current remote remains 9cb9ae5cbd6308becbb37952cd8e820729b0d242, CI 40335584785
verified live. Keep this follow-up local until that source's sixteen-option native
acceptance and fresh visual checks pass. Future diagnostic-source acceptance adds
--command-diagnostics after --exec-decoding (SEVENTEEN options), requiring exactly
four fixed raw streams plus staged-command-diagnostics.json in the success bundle.
Callback process outcomes, all-exec coverage, trigger/script authority, generated
mutation policy and publication remain unverified. Full v2.1 remains active.
Disk about 20.2 GiB free / 90 percent; no deletion or local VM/model downloads.

## Native FD and loader-cache evidence accepted; decoder next

Head 9e41442d2fa5fbf78549bb209f8a94af4cd6dd91 / CI 40329962502 completed
ALL3SUCCESS: quality 121596447604, security-lab 121596447176, merge-gate
121612328967. Artifact 12655402696, 22,970,782 bytes, SHA256
aeeb6e22014ea49d612b6d9fe08668a90c726ef3ba90cb90d41d40e9912b7054.
Download 45374 and full independent acceptance 9159 exited zero. All fifteen
options and preceding 54-hash/45-flag/package/PAM/Stop/recovery/ELF checks passed.
Worker inherited-FD snapshot independently checked; cache tables/tree binding
recomputed: 572 before / 577 after. No library-object/regeneration authority.
Strict accounting remains 55/64 differences; nine unknown effects rejected.
Six fresh UI originals plus four numeric crops actually inspected; full 900/120
values visible. Receipt: outputs/acceptance-pr134-fd-cache-observation/inspection.json
under task root. Headless only; physical provenance null. No publication.

The strict execution decoder commit 00e844fe58ebf023a85980996e2573ef4245a612
is ready for the next source run. It is not proved by this accepted source.
After push, acceptance must include SIXTEEN flags, adding --exec-decoding after
all fifteen prior options. Raw/version/custody export must survive decoder failure.
Full original v2.1 phases 0-7 remain incomplete, including callback provenance,
process outcomes, unknown mutation policy, production staging/activation/runtime
closure and the remaining product/release requirements below. No merge yet.
Disk about 20.2 GiB free / 90 percent; no deletion or local VM/model downloads.

## Local strict execve frame decoder (not pushed)

package_exec_decode decodes the actual strace -f -qq -xx execve form, including
bounded unfinished/resumed pairs keyed by PID. Other syscalls/dialects, unknown or
truncated frames, unreadable/nonhex strings, embedded C terminators and unmatched
pending calls fail closed. Original argument bytes remain base64 data; nothing is
executed. Limits cover raw bytes, physical/reassembled lines, individual strings,
argv counts, pending calls and total expanded argument bytes.

807 local tests: 752 passed, 55 skipped. Nine new tests include the exact native
2011fdd fixture, interleaving, failed attempts, arbitrary non-NUL argument bytes,
quotas and raw/version/custody retention. The decoder and independent implementation
match all 29 calls: 19 zero returns and 10 failed ENOENT attempts. A zero execve
return is image replacement, NOT process exit success. Process outcomes, caller
ancestry, complete coverage, actual trigger policy, script contents and authority
remain false. Seven altered reports/custody substitutions are rejected; synthetic
interleaved and malformed-frame cross-checks also agree. This is LOCAL new code on
saved native bytes plus a derived local custody projection, not new-source VM proof.

Raw trace, utility version and a separate custody JSON are retained before decoding
and later validation, so rejection preserves witnesses. Exact artifact manifests
add only staged-exec-trace-custody.json when decoding is required. The custody asset
must equal the main report's observation and worker proof. Future source acceptance
adds --exec-decoding after all fifteen prior options (SIXTEEN total). Current remote
9e41442/run40329962502 uses fifteen and cannot prove this local decoder. Keep it
unpushed until that source is accepted. Exact fixture SHA256:
6cacfecc59faf8360c9a4bbaee5bbd2f800d6aac0539f17fa6c943ed7f037899.

Disk fell to about 19.2 GiB free/91 percent; user warned. No data deleted. Continue
only small necessary artifacts with checks; no local VM/model images. Stop new
large downloads below 10 GiB. Recheck before any download.

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
