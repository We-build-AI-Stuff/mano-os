# Staged package and loader-cache feasibility

Status: native producer reported staging success; raw evidence transfer failed. Independent acceptance, production integration and publication remain incomplete.

The current package worker writes selected live /usr, /etc and /var trees.
Filename rules protect specific authority paths but do not establish complete
loader/plugin/persistence protection. In particular, mutable loader-cache bindings
can redirect a later privileged helper to another file. Blocking cache writes
without a legitimate ldconfig path would break normal shared-library installation.
Additional deny rules alone do not resolve that conflict.

Evaluate package work in a private writable btrfs clone before changing production
execution. The existing layout contract already requires one coherent root
subvolume for package payload, dpkg/APT state and boot files. A COW clone can retain
that coherence while keeping the live root available to the trusted controller.
This is groundwork for choosing a publication mechanism, not an implementation of
one or a decision to require reboot for every application installation.

The CI-only probe refuses non-Linux/non-Debian/non-disposable contexts. It creates
one fresh private clone and retains it for inspection. It selects only the fixed
sl package and its small new-package dependency closure from authenticated Debian
APT metadata, acquires official HTTPS archive URLs without proxies/redirects and
checks exact sizes/SHA256. No model-selected package, path or command is accepted.

The clone worker runs dpkg with those read-only archives, modifies a controlled
canary and adds one clearly synthetic compiled shared library before running real
ldconfig. It uses private namespaces, a bounded systemd unit, NoNewPrivileges,
locked securebits and an independently observed six-capability state. It does
not use the production native guard or production PAM/grant/journal path, and it
does not claim their security guarantees. Its fixed signed workload is not an
adversarial confinement test.

After the unit drains, compare the entire candidate package database with the
before state, require the exact new-package versions and signed sl executable
bytes, and check the candidate cache contains the synthetic SONAME. Check live
package state, automatic marks, loader inputs and inventoried helper/ELF bytes
remain unchanged. The deliberately created live canary must retain its original
bytes while its cloned counterpart changes. No candidate files or cache are
published, activated or selected for boot. Peak space remains unmeasured.

The production work still required includes:

- Use the actual fixed native guard, Stop domain, sealed archives and current
  consent/deadline/boot generation throughout staging, without reusing an action.
- Validate all candidate mutations and executable provenance after every worker
  and descendant has drained; a changed dpkg database is not sufficient evidence.
- Define treatment of conffiles, maintainer-generated state, services, account and
  policy changes, dependency upgrades/removals, triggers and Pre-Depends.
- Keep trusted controller code, ELF/plugin/search policy and credentials immutable
  during staging and activation. Account for aliases, open descriptors and mappings.
- Choose and test coherent publication/activation, crash/Stop/ENOSPC recovery,
  no replay, status/catalog/tool-registry refresh and rollback. Do not describe a
  sequence of file replacements as atomic whole-system activation.
- Demonstrate the required Linux package/application matrix and protected-runtime
  security updates. An installable clone alone does not satisfy the product goal.

References for the fixed privilege-drop and metadata interfaces:

- https://man7.org/linux/man-pages/man1/setpriv.1.html
- https://apt-team.pages.debian.net/python-apt/library/apt.package.html

Local safety tests and compilation do not establish native feasibility. Require
a fresh successful Debian CI report before any claim about the clone experiment.


## Payload inventory groundwork

mano_runtime.package_payload inventories an uncompressed tar stream without
filesystem extraction, command execution or symlink traversal. It records regular
file hashes, byte counts, numeric ownership/modes/timestamps, literal symlinks and
resolved in-archive hardlink provenance. Canonical path, duplicate, object-type,
entry/byte/metadata budgets and interruption checks reject ambiguous inputs.
Unknown PAX security attributes, hardlink metadata conflicts and symlink-parent
ambiguity remain explicit unsupported metadata. They are not permission grants.

This module is not yet wired into production or the native staging probe. Its
caller must bind verified immutable archive identity, isolate the parser under
process memory/CPU limits, and independently compare the candidate and baseline.
Tar library extension-header parsing precedes the per-entry checks; these budgets
are not a claim of constant-memory parsing or a substitute for that worker limit.
The result explicitly sets signature verification, candidate verification and
publication authority to false. Merged-package collisions, conffiles, removals,
aliases and generated state still require a candidate-aware validation contract.
Seventeen focused local tests cover traversal, duplicates, link chains/cycles,
unsupported metadata, resource quotas, truncation and revocation. Native use and
complete candidate validation remain unverified.


## Native admission failure

Run40171677448 at7eeabfe passed quality but failed before download/clone work at
the combined candidate admission check. The log did not identify the failing
field; no underlying authentication/identity cause is claimed yet. The next
source records only public candidate metadata and the exact failed field names
on stderr, while preserving official-origin, trust, size, SHA and architecture
requirements. It uses APT's documented shortname for the archive filename and
checks raw Package/Version/Architecture record identity independently. Ten local
admission/safety tests pass; fresh native diagnostics remain required.


## Canonical catalog source correction

Run 40174227139 at 044d4a8 failed admission for libncurses6 with a trusted
origin whose site was empty. The failed field was trusted_origin. This proves
the immediate rejection condition; it does not identify every property of the
cloud mirror configuration or establish that later staging steps work.

The probe now uses the existing verified catalog, checks its input fingerprints,
and prepares a private APT root with the catalog's canonical official sources,
indexes, keyring, status and marks. It rejects unsettled package state and
rechecks catalog custody and live state after acquisition. It never updates or
fetches indexes through host mirror configuration. Official-site, trusted-origin,
archive hash, size, architecture and raw-record identity checks remain required.
Four additional local tests cover private cache setup, unsettled state, changed
custody and invalid catalog rejection. Native confirmation is still required.

## Descriptor-relative payload path comparison

`mano_runtime.package_candidate.compare_payload` accepts an already-owned root
file descriptor and an inventoried manifest. It verifies manifest integrity and
requires supported metadata. Each parent component opens with directory and
no-follow flags; leaf metadata uses no-follow lookup. Regular files must match
size, SHA256, ownership and permissions and retain stable inode metadata through
reading. Symlinks must match literal targets; hard links must share the expected
regular file's device and inode. Cancellation propagates and the caller's root
file descriptor remains owned by the caller.

The caller must drain writers and retain exclusive private custody. This helper
observes only listed payload paths. It does not scan unlisted mutations, compare
baseline changes, resolve merged-package conflicts, verify timestamps or shared
directory metadata, authenticate an archive, or authorize publication. Those
fields remain explicitly false. Parent symlinks are refused, including legitimate
merged-/usr aliases until a baseline-aware policy exists. This helper is not yet
wired into production or the staging probe; immutable archive binding and the
resource-limited inventory worker remain necessary before integration.

Fifteen local filesystem regressions cover matching bytes/links, same-size content
substitution, copied hard links, mode changes, symlink and FIFO substitution,
parent aliases, missing paths, manifest changes, unsupported metadata, unlisted
file evidence limits, interruption, concurrent metadata changes and root FD type.

## Archive-to-container identity binding

`mano_runtime.package_container.bind` requires immutable bounded bytes and the
expected whole-archive SHA256/length before parsing common ar member framing.
It records member offsets, sizes and hashes, requires ordered Debian version,
control and data members, and preserves documented gzip/xz/zstd/bzip2/lzma names
without decompressing or executing anything. It rejects duplicates, long-name
extensions, malformed numeric headers, missing padding and truncation. Additional
underscore/trailing members are recorded rather than interpreted as effects.
The format contract is documented at
https://manpages.debian.org/trixie/dpkg-dev/deb.5.en.html .

The CI acquisition probe calls this binding before writing an authenticated
archive and retains the result in each archive record. The expectations still
come from the verified catalog; matching caller-supplied values is not itself
signature verification. Payload inventory, candidate filesystem verification and
publication authority remain false. Ten container test methods include all
24 documented control/data compression combinations; an acquisition regression
checks both a bound container and a hash-matching malformed container that must
not reach archive custody. Native confirmation and independent artifact binding
acceptance are still required. No production executor changes are included.

## Unprivileged inventory worker and listed-path integration

The CI prototype now inventories each acquired archive before creating the clone.
A fixed systemd unit runs the observer as nobody with an empty capability bounding
set, NoNewPrivileges, read-only system paths, hidden homes, private network/tmp/
devices, 512 MiB memory, 16 tasks and a 25-second lifetime. The observer refuses
non-Linux, root or unmarked contexts and checks all five capability sets are zero.
It also bounds address space to 384 MiB and CPU to 12 seconds before reading input.
It binds the archive SHA/length, copies bytes to a fully sealed memfd and invokes
only fixed dpkg-deb --fsys-tarfile on that descriptor. Tar inventory consumes the
pipe without extraction or maintainer execution; the decompressor is reaped or
killed on every failure. Only bounded zero padding may follow the tar terminator.

After the package unit drains, the controller uses an owned candidate root FD to
compare the inventoried paths. Worker observations are preserved as individual
hashed artifacts. This integrates previously separate components but is still
native-unverified. It does not verify unlisted mutations, baseline changes, shared
directory metadata, timestamps, merged-package ownership, adversarial confinement,
production native guard/PAM, or publication. All such authority flags stay false.
Three worker-admission tests refuse Mac/root/unmarked/privileged contexts without
native execution; an adapter regression verifies complete capabilities and fixed
unit limits and rejects malformed privilege/authority evidence. These local tests
do not prove Debian decompression or systemd confinement works.

## Native credential-mask lifecycle failure

Run40175533325 at2dbc4b6 got past candidate admission, archive acquisition and
clone creation but failed when bubblewrap could not find the shared fixture asset
/usr/lib/mano-os/empty-credential. Package installation was not reached. The
prototype now creates its own empty file with exclusive creation and mode0400
inside the fresh private experiment directory before taking the snapshot. Both
shadow paths use that read-only bind source. Existing files or symlinks are
refused; tests verify no reused target is modified. This fixes the identified
missing-source dependency without claiming later native steps have passed.

## Tree observation and change accounting groundwork

`mano_runtime.package_tree` adds Linux-only descriptor-relative observation for
future baseline/candidate comparison. It opens directories and regular files
without following symlinks, records content hashes, uid/gid/mode/times, literal
symlink targets, special-object types, hard-link relationships and hashes of
all visible extended attributes, including ACL/capability metadata. It refuses
foreign filesystem boundaries, detects inode metadata changes while reading,
and imposes entry/depth/content/metadata/xattr budgets. It explicitly excludes
.snapshots and reports hard links whose aliases were not all observed.

Its delta function returns all observed additions, removals and modifications;
it does not whitelist generated state or grant effect authority. Snapshot
custody, immutable roots and full filesystem validation remain unverified. The
scanner is not yet wired into the native clone probe. Before using it there,
create and independently check a read-only baseline clone, run scans under fixed
resource/Stop limits, and account for every resulting change without dropping
unknown mutations. Exclusions and unobserved aliases must remain explicit.

Four portable tests cover change accounting, xattr-only differences, tampered
manifests/exclusions and refusal on Mac before descriptor I/O. Six actual Linux
filesystem/xattr tests cover bytes/links/FIFO/exclusion, xattrs, external aliases,
quotas, interruption and mutation; they are skipped locally and require CI.

The container reader now treats trailing members as opaque after the required
version/control/data triple, including names resembling alternate control/data
compression formats. It preserves the selected required payload rather than
confusing a trailing extension with a second required payload. A regression
covers that case. Independent acceptance selects the bound required data member;
it does not choose a payload by scanning for any matching filename suffix.

## Read-only baseline before candidate creation

The native probe now first creates a read-only btrfs baseline from the live root,
then a distinct writable candidate from that baseline. It checks kernel ro=true/
ro=false properties, unique UUIDs/subvolume IDs and both parent relationships.
The baseline package status must match the pre-effect bytes, and its read-only
property and status are rechecked after the package worker drains. Raw property
and status bytes are exported. No snapshots are published or deleted.

This prepares stable inputs for the tree scanner but does not yet run that scanner
or establish whole-tree immutability/validation. Two mocked-command tests verify
the exact clone sequence and reject eight ancestry/identity/property failures.
They do not execute btrfs locally. Native baseline evidence requires fresh CI and
explicit --staged-readonly-baseline independent acceptance; older artifacts must
not be interpreted as containing a read-only source baseline.


## Native producer success and evidence-transfer failure

Run40176846496 atbe69678 passed quality but failed when tar attempted to create
an archive containing the literal name staged-*. The preserved producer report
records successful dpkg/ldconfig execution, matching libncurses6/sl payload paths
(15 and33 entries), unchanged live inputs, drained child domain and no publication.
The raw staged artifacts are absent from the uploaded ZIP. Those statements are
producer evidence only; independent raw-evidence acceptance has not passed.

The driver now reads the report's bounded artifact/hash map, validates fixed
staged basenames, and sends exact NUL-delimited filenames to remote GNU tar with
--null --verbatim-files-from --files-from=-. It no longer relies on creation-mode
wildcards. Invalid paths/options/control bytes/hashes fail before list output;
pipefail preserves errors across the transfer. Three portable regressions and
a Linux GNU tar archive-content regression cover this contract.

## Trusted tree collector integration (native unverified)

The prototype now scans the read-only baseline before package work, scans the
candidate after package drainage, then scans the baseline again. Both baseline
manifests must agree. It exports all three manifests and the complete observed
change report; additions/removals/modifications are not whitelisted or authorized.
The fixed .snapshots exclusion and unobserved hard-link aliases remain explicit.
This does not establish complete candidate validation or publication eligibility.

The collector is trusted controller code, not an adversarial executor. It accepts
only baseline/candidate roles under the private Root-owned experiment directory.
Its CI-only guard refuses Mac, non-Root, unmarked/non-VM contexts, unexpected
capabilities and missing NoNewPrivileges. It retains DAC_READ_SEARCH and SYS_ADMIN
to read otherwise-hidden trusted.* extended-attribute names. That privilege is
part of its trusted computing base; no adversarial confinement claim is made.
It executes trusted live-system Python code, never code from the candidate.

The fixed transient unit has a read-only system view, hidden homes, private
network/tmp/devices, 512 MiB memory, eight tasks and a 90-second runtime. The worker
checks its exact kernel cgroup path, memory.max and pids.max, and separately sets
384 MiB address-space, 60-second CPU, zero file-size/core limits. Six admission
regressions and an adapter regression test wrong roles, contexts, capabilities,
limits and private-directory ownership without running a Root collector locally.
Native scans, resource feasibility and independent tree-artifact acceptance are
still required. Production guard/PAM and change-authorization flags remain false.


## Collector admission diagnostics and explicit inheritance

Run 40221230798 at 80c371c passed quality but failed at the first collector guard
before package execution. The combined capability/NoNewPrivileges assertion failed;
actual values were not logged, so the individual failing field is unproven. The
failed artifact and raw log are preserved without an acceptance claim.

The unit now explicitly requests the same DAC_READ_SEARCH/SYS_ADMIN pair in its
ambient set as in its bounding set. The contract requires exactly that two-bit
mask in all five capability sets, with NoNewPrivileges enabled. Effective,
permitted and bounding privileges are not expanded. Inheritance is explicit for
fixed trusted helper execution; this is still trusted Root inspection code, not
an adversarial sandbox. Denial diagnostics emit only selected capability/NNP
metadata. No arbitrary process status, user input or credential values are logged.

A fixed admission-only mode checks the same privilege and kernel resource context
without opening the private directory or any snapshot. CI runs it after the first
btrfs boot verification, before the expensive Broker/PAM test chain. Successful
context is exported separately; real scans must explicitly report admission_only
as false. Independent acceptance rejects an admission record masquerading as a
scan. Local mocked checks and synthetic acceptance are not native confirmation
of the admission correction or the actual collector.


## Accepted tree evidence and combined payload gate

Run 40223650928 at 20e4fe1 passed all three CI jobs. Independent acceptance checked
artifact 12611276738 (22,947,547 bytes, SHA256
868e40f6cc94d09be2c30c1807b40751f9b02c05a5925e20f6b3df211ecdff85), including
54 hashes, 45 flags and the prior package/PAM/Stop/recovery checks. The collector
admission and three real tree scans passed. Its baseline contains 62,778 entries;
the candidate contains 62,821. The baseline-after manifest equals baseline-before.
The independently recomputed delta has 43 additions, 23 modifications, no removals
and no reported unseen hardlink aliases. Six fresh headless permissions screenshots
were inspected. This does not prove physical input or independent reacquisition
of the candidate filesystem.

A new combined payload gate consumes the authenticated package inventories and
the drained tree observations. It rejects non-directory path collisions even for
identical bytes, conflicting shared-directory ownership/modes, symlink parents,
changed shared-directory security metadata, payload content/ownership/mode/xattrs/
timestamps, and hardlink groups with aliases outside their package-local payload.
New directories require the inventoried ownership/mode and no extra xattrs;
existing directories preserve baseline ownership/mode/xattrs. Directory timestamps
remain unresolved because unpacking descendants changes them. All other unlisted
changes also remain unresolved; a path resembling dpkg state or a loader cache
receives no authority by its name. No caller-supplied whitelist exists.

Twelve portable regressions exercise overlap, metadata and alias attacks,
interruption and rejection of unsupported/tampered inventories. Applied locally
to the already accepted native observations, the gate validates 44 distinct paths
from two packages and leaves 40 changes unresolved. An independent implementation
rechecks that result and rejects seven altered report cases. This is offline
validation of new code against prior observations, not execution of the new source
in the VM. Fresh exact-head native CI remains required. The CI probe now invokes
the gate after candidate drainage and includes its result in the main report.

Generated-state validators, protected-runtime policy, complete mutation approval,
production authority/PAM staging and coherent activation remain required. The
combined payload result always keeps generated-state validation, change authority,
whole-candidate verification and publication false. It cannot authorize deployment.


## Preserve all fields on packages outside the approved change set

The former database postcondition compared only package identity, state and version.
That could miss changed dependencies, conffiles, trigger fields or unknown metadata
on an unapproved package with an unchanged version/state. The database reader now
retains every field and continuation, rejects duplicate fields (case insensitive),
NUL values, parser bodies and malformed field names, and compares all fields for
records outside the approved package set. Field order/header case are semantic
no-ops. The historical receipt schema remains unchanged so this does not invalidate
old recovery evidence or claim that old source enforced the stronger invariant.
Both the production postcondition and CI-only staging check use this comparison.

Three new regressions cover metadata deletion/addition, duplicate non-identity
fields, parser ambiguity, continuations and equivalent header ordering/case. The
full local suite has 692 tests:637 passed/55 skipped. An independent line-oriented
reader checked all unapproved record fields in four prior native transactions
(695,694,696,695 records respectively) and rejected four injected metadata changes.
That is offline historical-input evidence; fresh native CI is still required for
the new source. Approved-package control metadata, generated-state validation and
coherent publication remain separate unfinished gates.


## Prepared authenticated control metadata gate

The unprivileged archive observer now reads the control tar from the same sealed,
SHA-bound Debian archive, using fixed dpkg-deb --ctrl-tarfile under its existing
empty-capability/NNP/cgroup/CPU/address-space limits. No control member is extracted
to disk or executed. The uncompressed control input is bounded to 16 MiB, individual
members to 4 MiB, total content to 8 MiB, control fields to 1 MiB and member count
256. Only a root directory and flat regular files are supported. Links, nested
paths, duplicate/ambiguous fields, installed-state headers, unsupported metadata
and nonzero bytes after the tar terminator are rejected. Identity fields must
match the authenticated candidate before candidate package execution.

After drainage, each new package's entire installed status record must equal its
authenticated control fields plus install-ok-installed state. Every package outside
the approved set retains all baseline fields. Copied md5sums, shlibs, symbols,
triggers and supported maintainer/config/template files must match control hashes,
lengths, UID/GID/modes, have no extra xattrs and exactly one link. Multi-Arch:same
names derive their architecture suffix from the bound control field. Unknown
control members remain explicitly unsupported. This gate currently addresses new
packages; upgrades/removals and existing configuration records require separate
policies, and no generic compatibility claim is made.

Generated .list/conffile records, trigger effects, loader caches, logs, parent
metadata, protected-runtime changes and all other effects still require validation.
The result keeps generated-state validation, maintainer-effect verification,
change authorization and publication false. No control filename confers authority.

Thirteen new portable tests cover malformed/linked/nested inputs, resource budgets,
metadata drift, whole-record identity/content, multiarch naming, duplicate/preexisting
packages, aliases, unsupported extensions, child cleanup and decompressor errors.
The complete local suite has705tests:650passed/55skipped. Applied locally to saved
3484744 archive/tree/status evidence, two records and five info paths match. A
separate implementation recomputes those observations and rejects five altered
reports. Those are historical-input/local-code checks, not new-source native
execution. The current remote95d20a0 CI remains queued; keep this follow-up local
until that run is terminal. Fresh CI and explicit --staged-control-metadata
independent acceptance are required for this addition.


## Prepared generated file-list validation

Generated dpkg .list files are now checked against the authenticated payload path
set for each new package. Lists require a bounded LF-terminated UTF-8 encoding,
no CR/NUL, exactly one entry per payload member, no duplicates and exact canonical
absolute spellings (including /. for the archive root). Ordering alone grants no
authority. Missing/extra paths, aliases, traversal spellings and newline-ambiguous
payload names fail closed. This checks file ownership bookkeeping, not the effects
of scripts or other generated state.

After writer drainage, the controller reads each fixed info path through its owned
candidate directory FD. Intermediate/leaf symlinks are refused; nonblocking open
avoids FIFO hangs. File type, same filesystem, ownership/mode/link count, exact
size/timestamps and final inode identity must match the preceding tree observation.
The file hash must match that observation as well. Root ownership, mode0644,
one link, no reported xattrs and the exact hardlink anchor are required. Bounded
reads and interruption checkpoints close all newly owned descriptors on failure.
Generic descriptor regressions use user-owned temporary files; they do not prove
Root authority or physical/native input provenance.

Twelve portable regressions cover path sets, ambiguity, quotas, interruption,
Root ownership/multiarch binding, symlink/FIFO refusal, real descriptor bytes,
stale metadata/content and mutation during reading. The full local suite has717
tests:662passed/55skipped. For saved3484744 evidence, lists reconstructed from
authenticated archive member order have exactly the recorded candidate hashes:
424bytes/15entries for libncurses6 and823bytes/33entries for sl. The independent
reader verifies those48entries and rejects five altered reports. Reconstruction
is not new-source native descriptor evidence. The exported result carries bounded
base64 list bytes for independent rechecking against the raw payload and tree.

Control and list follow-ups remain local while95d20a0 CI40259735562 runs. Their
fresh head must pass native CI and independent acceptance with both new flags
--staged-control-metadata and --staged-file-lists (plus closure/tree/prior checks).
All other generated-state validation, whole-candidate verification, change authority
and publication remain false. Conffiles, trigger/cache/log/status-backup effects,
protected-runtime policy and coherent activation are still required.


## Prepared database file binding and known-preimage backup classification

Database transition checks validate records, but must also bind those actual bytes
to the observed candidate status file. The staging probe now requires both the
pre-change and final status bytes to match the corresponding baseline/candidate
tree lengths and SHA256 hashes. Both must be plain Root-owned, single-link files
with safe read modes, no reported xattrs and the exact hardlink anchors. The final
status access mode must equal the baseline mode. This is byte/metadata custody,
not a replacement for control-field or transaction validation.

The status-old backup is only classified as a known preimage if its content hash,
length, mode and preserved mtime match the original status. A missing backup or a
safe but different/intermediate backup remains unresolved; it is not automatically
rejected as an invalid Debian transaction or blessed by its filename. Unsafe
backup file metadata fails closed. Whole-generated-state validation, transaction
validation, changes authority and publication remain false in this component.

Six regressions cover independent before/after bindings, unsafe metadata, aliases,
mode drift, intermediate/missing backups, preimage timestamp changes and interruption.
The complete local suite has723tests:668passed/55skipped; the missing-backup edge
case was also rechecked with the focused suite. The independent reader checked
saved95d20a0 bytes/tree, bound both status files and identified the recorded backup
as the known preimage; six altered report cases were rejected. That is local
historical-input evidence, not fresh native execution of this source. This follow-up
stays local while ec22401 CI40262851330 runs. Fresh source acceptance must include
--staged-database-files in addition to control/list/closure/tree/prior flags.


## Prepared complete change accounting and strict unknown-change rejection

The combined audit recomputes payload, control, database and generated-list
validations from the original observations and owned candidate FD. The caller
cannot supply an exception path list or a pre-approved report. It accounts for
validated payload entries/directories, exact copied control files, validated lists
and known database files. Existing empty dpkg lock files only receive a timestamp
classification when content, ownership, safe mode, links, anchor and xattrs are
unchanged. The dpkg updates directory must retain identical security metadata and
be empty in both snapshots before its timestamp change is classified. Other parent
directory timestamp changes need a directly accounted child change and otherwise
identical metadata. No directory or package-name prefix blesses extra files.

Unknown control requirements and unresolved backups remain explicit even if no
corresponding path delta exists. require_accounted recomputes the audit internally
and throws UnaccountedChanges for any remaining paths or requirements. It does not
trust a caller-supplied fully-accounted boolean. A successful content accounting
still does not establish protected-runtime safety, approval, confinement, custody
through publication or whole-candidate verification. Those authority flags remain
false. The private _account helper consumes only the audit's recomputed gate
results; it is not a model-facing policy interface.

The fixed CI experiment deliberately changes a non-package canary and injects a
synthetic library. Its complete accounting must therefore reject the candidate.
The probe requires the canary to remain unresolved and checks that the strict
entry point actually throws with the same unresolved set. It exports classification
and this scoped rejection result; no candidate is activated. This is a controlled
unknown-change rejection test, not broad adversarial confinement proof.

Eight new portable tests cover unknown paths, metadata drift, safe/unsafe lock
changes, nonempty updates journals, latent requirements, strict rejection despite
a forged boolean, exact observation identity and parent timestamp derivation.
731localtests:676passed/55skipped,Ruff/compile/diffpass. Against savedec22401
inputs, 55of66changes are accounted and11remain unresolved: loader cache/aux-cache,
synthetic library/symlink, canary, dpkg log, provider mountpoint and their affected
parents. The strict entry point rejects them. The saved native list receipt was
substituted for FD reading in that offline check; it is not new-source native
execution. An independent reader recomputes the same result and rejects six
altered report cases. This follow-up stays local while8d61ad1 CI40265061248 runs.
Fresh later acceptance requires --staged-change-accounting plus all prior gates.


## Prepared raw dpkg log acquisition without event approval

The log mutation remains one of the unresolved changes. Earlier artifacts retain
only the tree hash/length, so they cannot establish whether the old prefix was
preserved or what events were appended. The CI-only probe now reads bounded
var/log/dpkg.log bytes from the private read-only baseline and drained candidate,
binds them to their tree observations and exports fixed staged-dpkg-log-before/
after artifacts through the existing validated filename/hash transfer. No other
logs or arbitrary caller-selected paths are acquired.

The observer requires plain Root-owned, mode0644, single-link files with no
reported xattrs and the exact hardlink anchors. Both content lengths and SHA256
must agree with the corresponding tree. It records prefix preservation, appended
byte count and suffix hash; rewrites/truncations explicitly lack an append claim.
It does not parse events, verify their semantics or account for the log change.
Those flags and publication/change authority remain false. The combined change
audit continues to reject a changed log, even when it happens to be append-only.

Six portable tests cover prefixes, empty/unchanged inputs, rewrite/truncation,
independent baseline binding, metadata/alias/hash errors and quotas. The complete
local suite has737tests:682passed/55skipped,Ruff/compile/diffpass. The independent
reader checks synthetic byte/tree fixtures and rejects five altered reports.
No actual native log bytes have been acquired for this new source yet; those
fixtures do not prove Debian event syntax or behavior. The log event policy must
be based on real native evidence before it can approve a mutation. This addition
stays local while8d61ad1 CI40265061248 runs. Fresh later source acceptance requires
--staged-log-observation and both raw files, with accounting and all earlier gates.
