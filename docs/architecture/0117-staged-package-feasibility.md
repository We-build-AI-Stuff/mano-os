# Staged package and loader-cache feasibility

Status: CI experiment prepared; production integration and publication undecided.

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
