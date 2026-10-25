# Staged package and loader-cache feasibility

Status: native diagnostics identified an empty cloud-mirror origin site; canonical signed-catalog input prepared. Production integration and publication remain undecided.

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
