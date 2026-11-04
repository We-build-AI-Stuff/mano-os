# Recorded workflow memory observations

The disposable Linux CI harness observes the installed runtime while the existing
recorded project registers, publishes its source, fails a test, corrects the source
and verifies the passing test's artifact. It changes no grant, sandbox, service
limit or execution endpoint. Native collection is pending until the changed
revision runs successfully and its downloaded evidence is inspected.

The service hierarchy is not one common runtime cgroup. The observer reads five
fixed, nonoverlapping groups and verifies their actual systemd unit placement:

| Component | Group |
| --- | --- |
| Broker | `/system.slice/mano-broker.service` |
| Launcher and all delegated task groups | `/system.slice/mano-launcher.service` |
| Core, including controller/provider/egress children when active | `/mano.slice/mano-core.slice` |
| Native approval adapter | `/system.slice/mano-approve.service` |
| Independent Stop service | `/system.slice/mano-stopd.service` |

Ten samples precede registration, at a target interval of 50 ms. The final sample
is the reported warm pre-workflow observation; this is not cold-boot idle memory.
During the workflow a bounded observer samples `memory.current` for each group.
The raw observations retain elapsed times and the duration of each batch of reads.
The maximum sum of those readings is a sampled, sequential component sum. It is
not an atomic total and does not include the human compositor/prompt, CI harness
or unrelated system services. The observer must run outside the measured groups.

For each component the collector also holds one `memory.peak` descriptor from
before registration until after verification. Its reset and later read use that
same descriptor, as specified by the [Linux 6.12 cgroup documentation](https://www.kernel.org/doc/html/v6.12/admin-guide/cgroup-v2.html).
These are kernel peaks for the named groups and their descendants. Summing
component peaks would combine values that may have occurred at different times,
so the report does not present that sum as a concurrent peak. Exact aggregate and
whole-product peak fields stay `null`.

The existing `developer-project/` export includes `runtime-memory.json`, with raw
pre-workflow/workflow samples and a summary. File hashes cover it, and the main
manifest and broker-service report reference the same summary. Existing exact-file,
PAM, replay and Stop assertions remain unchanged. The legacy unqualified
`peak_ram_bytes` remains unknown; consumers should use the new scoped observations.

The collector is restricted to the disposable Linux Root harness and fixed paths.
It rejects changed cgroup identity, invalid counters, missing placement and an
incomplete observation. Portable tests exercise parsing and summary semantics,
not Linux execution. No runtime collector runs on the Mac. These VM observations
do not establish physical 8 GB performance or complete Phase 1/v2.1 acceptance.
