# Staged package and loader-cache feasibility

Status: CI-only staging and strict unknown-change rejection are independently accepted through 31eb9ba. Production authority integration, complete mutation policy, protected-runtime closure and publication remain incomplete. The log-frame decoder below requires fresh native CI.

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


## Accepted unknown-change rejection and actual log evidence

Run40267405507 at31eb9ba passed quality/security-lab/merge-gate. Artifact12627821277
(22,904,164bytes,SHA256284e4ada5725c60839c54b878ce70f59ef1bea3c1dfc95a8a23ec740484e2ebf)
was byte-verified and independently accepted with all54hashes/45flags and every
prior gate plus accounting/log observation. The strict guard actually rejected
11unresolved effects after accounting55of66changes. Six fresh GUI originals and
four numeric crops were inspected;900/120values are readable. Headless evidence
still does not prove physical input or a finished product.

The native log preserved its197,189byte baseline and appended1,360bytes. Its21
events include the two new package installs plus libc-bin and man-db trigger
processing. The suffix SHA256 is
c47b68d87eeab5e4c201d8b3d063efbe97d2032901b4e81a3fcce526e1cbe596.
The recorded suffix is retained as tests/fixtures/dpkg-log-31eb9ba-append.txt.
These are native facts, not synthetic log examples or approval of their semantics.
The old watcher ended with a network timeout; authoritative checks confirmed CI
success. The slow artifact download was preserved until its digest verified.

## Prepared bounded event-frame decoder

package_log_decode follows the event families documented in Debian's dpkg --log
interface: startup, state updates, package actions and conffile decisions. It
bounds bytes/event count/line length, validates real calendar timestamps and
package/version token syntax, and refuses unknown events, ambiguous fields,
incomplete lines, invalid UTF8 and control/format/line-separator characters.
Literal conffile spaces remain data and no path is opened. Rewritten logs have no
decoded append; an empty append is not installation proof. Timestamps remain local
strings with no verified timezone/window.

The decoder preserves explicit false flags for package scope, trigger authority,
time window, complete semantics, log accounting, change authority and publication.
Syntactically valid trigger records are not proof that their execution was allowed.
The original byte observer remains a separate non-semantic component. The log
therefore remains unresolved in the combined change audit.

Six new tests include the exact captured21event fixture, documented event classes,
malformed/unknown fields, timestamp/control/encoding errors, quotas and rewrite/
empty cases.743localtests:688passed/55skipped,Ruff/compile/diffpass. A separate
implementation decoded all21events from the accepted raw logs and rejected six
altered reports. This is local new-code execution against native inputs, not
native execution of the new source. Fresh CI must also require
--staged-log-decoding after all six earlier options.

Reference: https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html#OPTIONS


## Prepared log identity/version scope check

package_log_scope recomputes the append decoder and complete before/after package
records. New package identities must be distinct, absent from the baseline and
settled at the exact authenticated candidate version. Every unapproved database
record remains unchanged. Qualified log identities must exist; unqualified names
must resolve to exactly one actual architecture. New install/configure/status
versions must match the approved candidate. New packages may reference their own
trigger at that candidate version, but no trigger permission is inferred.

For existing packages, only trigger processing and its possible status records
are classified as references, at the unchanged installed version. Other install,
configure, upgrade, removal or unpacking actions on a baseline package fail scope
inspection. A conffile decision or a different startup operation needs a separate
policy. The inspector does not validate event order, declared trigger authority,
time window, whole-log semantics or log mutation approval. Empty logs provide no
execution evidence. References to libc-bin/man-db are not blanket permissions.

Seven regressions cover versions/architectures/unknown identities, baseline action
substitution, multiarch ambiguity, self-trigger references, duplicate/existing plan
records, metadata drift, conffile/startup scope, rewritten and empty inputs.
750localtests:695passed/55skipped,Ruff/compile/diffpass. Applied locally to the
accepted31eb9ba bytes it matches20package events across21frames and retains two
unapproved trigger references. An independent implementation reproduces the result
and rejects six altered reports. This is local source against native input, not
execution of the new source in the VM. Later acceptance requires
--staged-log-scope after all seven prior options.

## Decoder CI bootstrap network failure and preserved retry

Run40282316047 atfc81e10 passed quality but failed while preparing the CI image:
Debian's libatspi2.0-0t64 archive download ended with an OpenSSL connection reset
(exit100). The VM probes and new decoder did not run. No parser defect or native
success is inferred. Raw job log and byte-verified failed artifact12632218896
(35,109bytes,SHA2568fc69f2978e8db093988deb41c1778c031a74cc993ac9da28ee7c11bee7a4075)
are retained. Existing guest/install scripts already use Acquire::Retries=3;
no origin/TLS/signature/security check was weakened.

Fresh workflow-dispatch run40283471563 executes the entire unchanged CI workflow
at the exact samefc81e10 head while retaining the failed run/artifact. The scope
follow-up remains local until that retry is terminal. No failed probe was skipped,
no protection was disabled and no artifact was deleted for a green check.


## Bounded trigger declarations prepared for native acquisition

The archive observer now retains the exact `triggers` member bytes, bounded to
1 MiB and matched to the authenticated control inventory. The parser accepts the
six documented interest/activation directive forms, strips comments, bounds the
number and length of declarations, and rejects ambiguous or unsafe file paths.
An absent member remains distinct from an empty member.

For existing trigger references, the probe resolves the fixed dpkg info basename
from the actual baseline database, including Multi-Arch: same. It reads only the
corresponding private baseline `.triggers` file. Root ownership, mode 0644, one
link, empty xattrs, exact tree size and SHA256 are required. Missing baseline
packages or files produce explicit unavailable observations. Caller-selected
paths cannot substitute for these records.

These observations do not prove that a payload change activates an interest,
that a named trigger was legitimately activated, or that the resulting maintainer
script effects are acceptable. Trigger authority, changes and publication remain
false. Sequence, time and complete mutation accounting remain separate work.

758 local tests completed (703 passed, 55 skipped), including eight focused
regressions for parsing, bounds, baseline binding, absence, identity drift and
Multi-Arch naming. The independent reader matches accepted31 archive declarations
and a SYNTHETIC baseline fixture and rejects five tampered reports. Actual baseline
libc-bin/man-db declaration bytes have not yet been acquired by this source in
CI. Fresh acceptance requires --staged-trigger-declarations after log scope and
all earlier gates. The decoder-only retry passed all three CI jobs; artifact and
visual acceptance is pending separately.


## Decoder retry independently accepted

Full retry run 40283471563 at fc81e1076719a5b578f701ecebb462209e5890d9
passed quality, security-lab and merge-gate. Artifact 12634355338 is 22,982,680
bytes with SHA256 f455bf0d86a62744abcbf5c504e758ee0d420c3acf7b9d2674042b877c21f66e.
The downloaded bytes match GitHub's digest. Independent acceptance passed 54
hash checks, 45 required flags and the full prior package/PAM/Stop/recovery/ELF
and staging chain. All 21 decoded event frames were independently recomputed.
The strict guard still rejects 11 unaccounted effects among 66 changes; decoding
has not authorized the changed log. Six fresh UI originals and four numeric crops
were actually inspected, with full 900/120 values visible. The bound inspection
receipt is retained under task outputs/acceptance-pr134-log-decoding-retry.
This is headless evidence; physical input provenance remains null. The scope and
trigger-declaration follow-ups need their own fresh native run and acceptance.


## Necessary trigger activation-source guard (local follow-up)

The linkage guard recomputes exact package identity/version scope, candidate
payload validation, copied control validation and fixed baseline declaration
binding. It re-parses authenticated archive declaration bytes rather than trusting
an observation's decoded list or claimed authority. Each referenced package must
have a declared interest supported by at least one activation in the approved
new-install closure. A named activation comes from an archive activate directive.
A file interest matches an exact lexical archive path or a directory-boundary
prefix; symlink destinations are never resolved for matching. A binary search
finds a witness in sorted inventories, and output links have a fixed quota.

This follows the upstream [dpkg trigger specification](https://github.com/guillemj/dpkg/blob/main/doc/spec/triggers.txt)
and [declaration manual](https://manpages.debian.org/trixie/dpkg-dev/deb-triggers.5.en.html).
The acquired specification text is SHA256
3283d48c0ecb80b5621aaccc02d9ee49e62b6737f64fc6d27830531185b75172
(Git blob 1d185aa132f132cd5d742ce436bfce40a83c39d6). Its naming contract also
revealed that non-ASCII names must be rejected; the parser and independent reader
now enforce printable 7-bit trigger names.

An interest alone, an unrelated activation, unavailable baseline declarations or
an invented decoded declaration cannot satisfy the guard. Explicit dynamic
maintainer-script dpkg-trigger calls need different evidence and are unsupported
by this fixed new-install guard. Matching a possible source does not establish
which names dpkg actually passed to postinst. The guard therefore leaves actual
trigger arguments, authority, event sequence, script effects and publication
unverified. No unknown cache/log mutation is approved by linkage.

766 local tests completed (711 passed, 55 skipped), including eight linkage
regressions. Ruff, compilation and diff checks pass. An independent reader
recomputed two links on a SYNTHETIC fixture and rejected four altered reports.
Native run 40286784670 still executes the preceding declaration-acquisition
source; it cannot prove linkage execution. The follow-up remains local until that
source is accepted. Future acceptance requires --staged-trigger-linkage in addition
to declarations, scope and all earlier gates.


## Supported new-install event state sequences (local follow-up)

The new sequence gate starts from absent approved packages and unchanged baseline
packages. It requires exactly one initial archives/install startup, one complete
install → half-installed → unpacked → configure → half-configured → installed
cycle per new package, and complete pending → trigproc → half-configured →
installed cycles for referenced trigger packages. Only pending notifications may
interleave an active package action. Repeated complete trigger cycles are bounded
by the existing event quota. The gate rejects overlapping actions, missing action
frames, repeated install/configure, partial final state, uncaused trigger execution,
unsettled pending state and decreasing timestamp text. It does not infer missing
frames from the final database.

This is an explicitly supported state-sequence profile, not proof of dependency
ordering or every Debian installation pattern. Local timestamp text has no trusted
timezone/window yet. Actual trigger arguments and script effects remain unverified,
and neither the changed log nor any filesystem effect becomes authorized.

773 local tests completed (718 passed, 55 skipped), including seven sequence
regressions and the exact previously captured native suffix. Ruff, compilation
and diff checks pass. Applied to accepted fc81e10 raw logs and full databases, the
new local gate matches 21 events and two trigger cycles. A separate implementation
recomputed the sequence and rejected six altered reports. This does not establish
new-source native execution. Later fresh acceptance requires --staged-log-sequence
in addition to trigger linkage and all preceding gates. The current 8f77c70 native
run has neither new guard and must not be accepted using these options.


## Controller-relative UTC log execution window (local follow-up)

The probe now sets TZ=UTC0 in the worker and in dpkg's explicit environment and
records both witnesses. The controller samples boot ID, realtime nanoseconds and
monotonic nanoseconds immediately around the bounded systemd worker execution.
The window gate requires an unchanged canonical boot ID, exact integer sample
fields, nonnegative intervals no longer than 60 seconds and wall/monotonic elapsed
times differing by no more than two seconds. A changed boot, backward clock or
larger clock jump fails this evidence gate.

Every appended event is interpreted in UTC. Since dpkg timestamps have second
resolution, its integer event second must lie between the floor of the start and
end realtime seconds, inclusive. Event seconds must also be nondecreasing. The
gate rejects an empty or rewritten append. Source custody and the trusted
controller are prerequisites: arbitrary submitted clock samples or a timezone
claim do not prove execution. This checks controller-relative consistency and
containment; external absolute time authority remains unverified. Actual trigger
arguments, dependency ordering, maintainer effects and log/publication authority
remain separate requirements.

779 local tests completed (724 passed, 55 skipped), with six focused clock cases
covering precision boundaries, out-of-window events, decreasing times, drift,
duration, integer/type bounds, boot changes and timezone substitution. Ruff,
compilation and diff checks pass. An independent reader recomputed two events on
a SYNTHETIC clock fixture and rejected seven altered reports, including an
inconsistent dpkg environment. This source has not acquired native clock samples.
Future fresh acceptance requires --staged-log-time-window in addition to all
preceding gates. The current 8f77c70 run contains none of these new local guards.


## Aggregate trigger acquisition and package-name lookup bounds

The baseline declaration reader now limits the entire reference set to 4 MiB of
raw bytes and 4096 decoded directives. Individual file quotas alone allowed up
to 256 MiB of retained source bytes and many decoded reports. The reader checks
the accumulated declared size before reading an excess file and rejects excess
directives before retaining that source. Fixed paths, safe metadata, exact hashes
and all previous authority restrictions remain mandatory. The independent reader
checks these aggregate bounds from actual exported bytes and parsed declarations.

Log scope now builds a package-name index once, avoiding a full database scan for
each unqualified log entry. Missing or multiarch-ambiguous names still fail.
781 local tests completed (726 passed, 55 skipped), including aggregate byte and
directive regressions; Ruff, compilation and diff checks pass. Native validation
of these local changes remains pending the next fresh source run.


## Avoid creating absent private-state mask targets

The accepted fc81e10 baseline had no var/lib/mano-provider entry. The candidate
contained a new empty Root-owned mode-0755 directory there, and var/lib timestamps
changed. The unconditional bubblewrap tmpfs target created these setup effects.
They remain unresolved in that historical evidence; no retrospective allowance
is introduced.

The staging probe now derives its two fixed private-state mask targets from the
read-only baseline. Existing directories remain masked regardless of which service
user owns their contents. Absent state has no clone data to hide and receives no
mount target. Symlink/non-directory leaves and missing or non-directory ancestors
are rejected before launching the worker. A package that unexpectedly creates
private state is not excused by this change.

783 local tests completed (728 passed, 55 skipped), including mask selection and
alias/parent regressions. Ruff, compilation and diff checks pass. The independent
reader requires the exact baseline-derived target list, unchanged existing private
subtrees and continued absence of absent targets. It passes a SYNTHETIC unchanged
fixture and rejects four substitutions; it also rejects the actual historical
provider-directory creation as intended. New-source native execution is pending.
Fresh follow-up acceptance must add --staged-private-state-masks to all prior gates.
This is a setup correction, not complete privilege confinement or publication.


## Declaration acquisition independently accepted at 8f77c70

Run 40286784670 at 8f77c70efeb254cc28d0e627bb6abb9c382a0d48 passed all
three CI jobs. Artifact 12635203732 (22,934,745 bytes) matches SHA256
98f9f84b79478a82f28132f864bd4191db34028ef0a5991a0052183f7e8a571a.
Independent acceptance passed 54 hash checks, all 45 flags and the full prior
package/PAM/Stop/recovery/ELF/staging chain, including actual declaration bytes:
one archive trigger file and both baseline libc-bin/man-db files. Six fresh UI
originals/four numeric crops were inspected with full 900/120 values visible;
the task outputs retain a hash-bound inspection receipt. Physical provenance null.

The acquired baseline bytes declare libc-bin interest-await ldconfig and man-db
interest-noawait for six man directories. The new LOCAL linkage implementation
and its independent reader match two sources on these native inputs: libncurses6's
activate-noawait ldconfig and sl's lexical /usr/share/man payload. The new LOCAL
sequence checker and independent reader match 21 frames/two trigger cycles.
Neither new implementation executed in that VM run. The follow-up batch still
needs its own native source run and all thirteen acceptance options. The old
strict guard continues to reject 11 unknown effects among 66 changes. No log,
trigger script or candidate publication authority is inferred.


## CI-only trusted execution-trace capture prepared locally

The package-name log does not record the exact trigger names passed to postinst.
The next evidence source is a trusted Root strace collector outside the candidate
namespace, following execve/execveat while the fixed bwrap workload runs. Debian's
[strace manual](https://manpages.debian.org/trixie/strace/strace.1.en.html)
documents fork following, hexadecimal string output and kill-on-exit. The probe
uses those options without syscall-count detachment. The collector is part of the
trusted inspection TCB and has Root tracing authority; it is not a restriction on
package capabilities or a production sandbox.

The raw destination is inside the exclusively created mode-0700 controller BASE,
hidden behind the candidate's snapshot mask. This avoids a Root tracer opening
a replaceable evidence-directory target. The file is precreated exclusively with
mode 0600. The systemd unit caps each file at 16 MiB, retains existing memory/task/
runtime limits, and the worker reports the inherited file limit. Capture fails
closed at the byte boundary or on a changed/aliased/non-Root trace. Raw trace and
actual utility version are exported as SHA-bound artifacts after the child domain
drains. A failed invocation instead retains bounded partial bytes and explicit
worker_failed metadata; it produces no successful acceptance receipt.

The trace is deliberately opaque at this stage. Fork-following is not proof of
all descendants or all execution: CLONE_UNTRACED and other ptrace coverage limits
must remain visible. Argument decoding, complete coverage, script bytes at exec,
trigger authority and publication stay false. A valid-looking trace line alone
cannot bless a callback or maintainer effect. Instrumentation changes timing and
inherits the file-size ceiling, so this is a specific CI observation context.

787 local tests completed (732 passed, 55 skipped), including four mocked-command/
FD custody, quota, alias, mutation and partial-evidence tests. Ruff, compilation,
embedded worker compilation, shell syntax and diff checks pass. An independent
reader bound SYNTHETIC opaque bytes and rejected six report alterations. No Root
or tracer execution occurred on the Mac. The preceding remote ef19cf4 source
contains none of this capture. A later fresh native run must add --staged-exec-trace
to all thirteen prior acceptance options, then supply actual data before parser
or trigger-argument claims can be made.


## Combined log and private-state guards independently accepted

Head ef19cf4adc34787a61e283a0802febde1457cea3 passed all three jobs in run
40321845193. Artifact 12650077946 (22,961,675 bytes) matches SHA256
08f5e6ed3ab673b8ff5c39004877a60a3935ba6ec7d0ab8803a13bcf2d241e17.
Independent acceptance passed 54 hash checks, all 45 required flags and the full
package/PAM/Stop/recovery/ELF/staging chain with all thirteen guard options.
Native results independently recomputed: two supported declaration links, 21 event
frames/two trigger cycles, UTC event containment across 649000902 monotonic ns,
exact broker-state masking with two private entries unchanged, and absent provider
state remaining absent. This is controller-relative time consistency, not an
external time authority or general performance benchmark. Actual callback arguments
remain unverified. Six fresh UI originals/four numeric crops were inspected with
full 900/120 values visible and a bound receipt retained. Physical provenance null.

The setup correction removes two historical differences. Strict accounting now
verifies 55 of 64 differences and still rejects nine unknown effects. No remaining
cache/log/synthetic-library mutation is approved merely because the log guards pass.
The raw execution-trace implementation in 69b19f1 needs a separate native source
run and fourteen acceptance options. This accepted source contains no tracer.


## Explicit worker descriptor snapshot before package execution (local follow-up)

The CI worker now enumerates /proc/self/fd before package invocation and requires
only standard input, output and error. It ignores a transient enumeration entry
only if fstat reports EBADF, propagates other errors and rejects any live extra
descriptor. This is a necessary provenance check: a leaked writable controller or
trace descriptor could undermine captured evidence even when its pathname is
hidden. The worker reports the empty nonstdio set and the controller enforces it.
It does not prove all descriptor use later in the execution.

Trace observation schema 1.1 identifies the check. Independent acceptance requires
the worker's exact empty set and true check result for that schema. Schema 1.0
captures remain readable but explicitly have no inherited-descriptor verification.
The existing fourteen-option acceptance chain is unchanged; source versions are
not silently promoted to stronger claims. Current 2011fdd native execution does
not contain this follow-up.

789 local tests completed (734 passed, 55 skipped). Two additional tests compile
and execute only the isolated helper AST with mocked descriptor operations;
closed enumeration, live extra descriptors and permission failures are covered.
The independent SYNTHETIC reader rejects extra descriptors and false verification,
and explicitly leaves legacy verification false. Root/Linux execution on the Mac
and native descriptor acquisition did not occur. Argument parsing, script bytes,
complete trace coverage and execution/publication authority remain separate work.


## Bounded loader-cache decoding prepared locally

The new observer decodes the supported glibc new-format 1.1 little-endian layout
from bytes without opening or loading any referenced library. It bounds the raw
file, table count and expanded string budget; checks header/reserved/extension
ranges; requires terminated UTF8/control-free strings and canonical lexical paths;
and preserves legitimate suffix-sharing in the string table. Zero hwcap/OS-version
fields and the optional opaque generator section define this explicit profile.
Old/compat formats, nonzero hwcaps and other extensions need separate support.
Flags, generator identity, search order, library objects, unused-byte semantics and
exact regeneration remain unverified. No cache mutation is approved by decoding.

The layout was checked against the glibc-2.41 header (Git blob
0ee6571315630fb8156d633c48c86b1086dbcd43, SHA256
d82003ce9e95ffb9fe685426e7591784d9296b2e7fbfa2a519168c5884b5d881)
and the [Debian glibc cache producer](https://sources.debian.org/src/glibc/2.41-12%2Bdeb13u3/elf/cache.c/).
The observer also binds the fixed cache bytes to captured plain Root-owned mode
0644/one-link/xattr-free tree entries, checking byte quotas before hashing.
The existing ldconfig diagnostic remains separate and unchanged.

798 local tests completed (743 passed, 55 skipped), including nine cache cases.
One test expectation was corrected: an embedded NUL terminates a C string, and a
shorter name is structurally valid; unused string bytes are not thereby approved.
Ruff, compilation and diff checks pass. Applied locally to accepted ef19cf4 native
inputs, the decoder reads 568 baseline and 573 candidate entries. The five added
entries are libform, libmenu, libncurses, libpanel and the deliberately unapproved
fixture library. An independent reader recomputes both tables and rejects seven
altered reports. This is new local code on native inputs, not new-source VM proof.
Future acceptance requires --staged-loader-cache after all fourteen earlier options.
Library-object, cache-regeneration and publication authority remain false.


## Native opaque execution trace independently accepted

Run 40325437426 at 2011fddef433a894e8e04d8dc4efb4f01f1f5f54 passed all three
jobs. Artifact 12651604704 (22,991,681 bytes) matches SHA256
0bf8fd352f1e0c71d85b4dcb50afd93a1927d6bf0cff6cc92f08df7361be14f3.
Independent acceptance passed 54 hash checks, all 45 flags and the complete prior
chain with fourteen options. The verifier initially omitted the two fixed trace
assets from its manifest; adding exactly those names under the trace option
retained exact set equality and all hashes. The same unchanged artifact passed;
no native probe, security condition or CI job was skipped. A local failure record
from tool output is retained; the initial full log was overwritten, so acceptance
logs now rotate before retries rather than silently replacing earlier attempts.

The actual strace 6.13 trace is 15,864 bytes/29 lines with SHA256
6cacfecc59faf8360c9a4bbaee5bbd2f800d6aac0539f17fa6c943ed7f037899.
Stable Root 0600/one-link custody was checked. Manual hex-string inspection shows
libc-bin.postinst triggered ldconfig and man-db.postinst triggered /usr/share/man.
This is raw observation, not a formal decoder, complete tracing or script-content/
authority proof. Schema 1.0 has no inherited-FD verification. All six fresh GUI
originals/four crops were inspected with full 900/120 values visible; the bound
receipt is retained and physical provenance remains null. Nine unknown filesystem
effects remain blocked. Descriptor schema 1.1 and loader-cache observation need a
separate source run and fifteen-option acceptance before native claims.


## Strict bounded execve frame decoding prepared locally

The decoder now targets the actual native strace -f -qq -xx bytes and retains its
exact 2011fdd input as a regression fixture. It handles complete and interleaved
unfinished/resumed execve records, recording entry/completion line numbers. Positive
PID prefixes, complete hex-quoted C strings, bounded argv/environment summaries
and explicit zero/errno returns are required. Non-NUL bytes remain base64 data,
including non-UTF8/control argument bytes. Unknown calls/dialects, truncation,
unreadable arguments, malformed quotes and unpaired resumes fail rather than
being silently skipped. Raw bytes, lines, strings, argv/pending counts and expanded
bytes all have fixed limits. No trace content is executed or used as an instruction.

The fixture contains 29 calls: 19 zero returns and ten failed ENOENT search attempts.
Zero indicates successful execve image replacement, not the invoked program's exit
status or desired effect. The decoder does not establish process outcomes, caller
ancestry, all execution, actual trigger policy, script bytes or authority. For
example, observing setpriv invocation does not establish the eventual mandb result.
Those evidence boundaries remain explicit despite syntactic argument decoding.

Raw trace, version and custody metadata are now exported before decoding or later
postconditions, preserving a rejected input. The separate custody asset is SHA-bound
and must exactly match the main report's observation/worker proof. Its fixed name
is added only for the decoding gate; exact manifest equality remains mandatory.

807 local tests completed (752 passed, 55 skipped), including nine new cases for
native bytes, malformed/resumed records, C-string bytes, limits and witness assets.
Ruff, compilation, embedded worker compilation and diff checks pass. An independent
implementation recomputed all 29 frames and rejected seven report/custody alterations;
interleaved and malformed synthetic cases also agree. The custody projection used
in the local selfcheck is derived locally from native 2011fdd data, not a newly
captured asset. Current 9e41442 native source lacks this decoder. Later acceptance
requires --staged-exec-decoding after all fifteen earlier options. No new-source
native decoder or trigger authority claim is made.


### Bounded command diagnostics follow-up (local only)

The raw exec trace cannot prove child process success. In particular, the earlier
native trace shows a successful setpriv image replacement but no mandb exec frame;
that is insufficient to diagnose a capability failure or to establish coverage.
The next CI source will retain dpkg and diagnostic ldconfig stdout/stderr as
separate byte artifacts, bounded at 64 KiB each while reading, and direct child
return codes. Deadlines and excessive output produce incomplete observations,
which the controller rejects. Failed dpkg skips the cache fixture command.

The worker can return observations even for command failure; the controller saves
these witnesses, then rejects any nonzero/incomplete/skipped command. Existing
unit resource limits and cgroup drain stay mandatory. These direct child outcomes
do not prove nested callback outcomes, ancestry, script bytes at exec, all-exec
coverage, absence of errors, or authorized mutations. Streams are retained as raw
bytes/base64 data, never interpreted as instructions or terminal control content.

Local verification: 812 tests, 757 passed and 55 platform skips, including five
portable helper tests; Ruff/compilation/diff checks passed. Independent synthetic
verification matches raw streams and rejects six substitutions. No new-source
Linux/Root/VM execution or mandb diagnosis is claimed. Its future native acceptance
requires all sixteen preceding options plus --command-diagnostics and five exact
new artifacts; the currently running decoder source uses only sixteen options.


### UID-drop compatibility comparison (CI only, not yet native-verified)

Accepted command diagnostics at 7af2987 show a concrete incompatibility: dpkg
returns zero while setpriv reports PR_SET_KEEPCAPS denied. The fixed securebits 43
include KEEP_CAPS_LOCKED, which Linux documents as rejecting that call with EPERM.
The comparison keeps that failure as a required negative control and separately
tries securebits 11 under the same 0xdb ceiling/NNP/private namespace construction.
It requires the actual setpriv UID drop, zero effective/permitted/ambient child
capabilities, unchanged state after failed root/capability/securebit escalation,
and drained domains. This does not run mandb or establish package callback success.
The production worker and main staging worker keep their existing securebits 43.

Both workers execute only fixed source in disposable Debian CI. Raw comparison
records and program bytes are retained, with failure evidence copied before VM
orchestration exits. Future native acceptance requires the two fixed new artifacts,
exact-source program bytes and all eighteen options. Local verification has 816
tests (761 passed, 55 skipped), including four synthetic comparison tests; lint,
compilation, shell and diff checks passed. Native results are still pending.


Native comparison at 4ae4901/run 40439743818 failed, with raw failure evidence
retained. The locked control reproduced the expected error. The alternative
reached Python but could not read its Root-owned mode-0400 source after UID drop.
Only the fixed comparison source is now mode 0444 under the Root-private source
directory and its existing read-only bind. The main worker source remains 0400.
A regression checks readable/non-writable mode, exact bytes and exclusive creation.
817 local tests passed (762 passed, 55 skipped), with lint/compile/shell/diff checks.
The alternative's child capability and escalation assertions remain unproven until
a fresh native run passes; no native guard or acceptance requirement was waived.


### Actual package stage under the compared profile (native result pending)

The isolated securebits-11 UID-drop comparison passed native acceptance at
5a16944/run 40441722096. The CI-only package worker now uses that same bounded
profile, while production remains unchanged. Both comparison controls remain
mandatory. The stage must observe the exact setpriv UID-drop invocation followed
by the fixed mandb -pq image record in the same observed PID, in trace order.
A zero execve result does not prove mandb exited successfully; credentials at exec,
process ancestry, complete coverage and callback authority remain unverified.
All newly generated filesystem state still passes through strict accounting.

The explicit nineteenth acceptance option requires the new worker profile and
recomputes the trace match. Earlier artifacts retain their old securebits-43
expectation. Three new focused tests plus five UID comparison tests passed locally;
independent synthetic checks reject ten substitutions. Lint/compile/diff passed.
The full local suite stalled on existing file reads during import, including a
fresh-cache attempt, and was terminated with diagnostics retained. Full-suite
validation is delegated to CI; no local full-suite success is claimed for this
change. Linux/Root execution remains exclusively in disposable CI.


Native run 40548807617 at 75fdfe3 passed all nineteen options and the complete
prior acceptance chain. The actual stage now records setpriv followed by mandb
image replacement, with empty dpkg stderr. Thirty exec records decode independently
(20 successful image replacements, 10 failures). The strict guard accounts for
55/125 differences and rejects 70 unapproved effects, including newly generated
man-cache tags/indexes/directories. This is observed startup and state change,
not verified callback exit status, credentials/ancestry/script authority or
generated-state correctness. Full CI quality passed 820 tests. Fresh UI evidence
was visually inspected; physical provenance remains null. No production policy
change, publication, activation or merge is authorized by this experiment.


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
