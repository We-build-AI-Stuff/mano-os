# Installed runtime OOM observations

The broker-service CI fixture includes one approved terminal action that attempts
to allocate more than its existing task memory ceiling. The allocation runs in
the production launcher sandbox, with its ordinary grant and resource limits.
The Root observer never performs the allocation or changes the limits. This
trial runs only in the disposable QEMU Linux guest; native acceptance is pending.

The observer requires no other task groups under the launcher, records its
hierarchical kernel memory events, and rejects an unexpected concurrent group.
An interrupted command alone is insufficient: `oom` and `oom_kill` must both increase.
The group OOM also kills the in-group report-producing supervisor, so the journal
must preserve an unverified `unknown` action with no fabricated exit/output.
Submitting that same request must return the same action without executing it.
Broker, launcher, native approval and independent Stop must retain their process
IDs, process start times and restart counts. The native human task-status request
must still work. A separate PAM-approved terminal command must then finish with
the exact expected captured stdout and empty stderr. No model is connected.

`broker-service.json` includes `terminal_execution.installed_runtime_oom`, with the
task/action/approval identities, before/after kernel counters, surviving services,
and three monotonic durations. OOM time means the observer's first detection, not
the exact kernel event timestamp. Readiness verification starts there and includes service, custody, replay and
native human-status checks;
follow-up completion includes the additional synthetic CI PAM interaction and
command. These are one-trial VM observations, not statistical latency bounds.

This checks installed-runtime task containment and post-OOM transport/execution.
It does not prove full desktop responsiveness, physical 8 GB performance or
complete phase acceptance. The separate existing primitive OOM test remains
separate evidence. Full-human-desktop responsiveness stays unknown in this report.
