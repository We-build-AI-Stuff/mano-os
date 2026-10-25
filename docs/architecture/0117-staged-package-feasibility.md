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
