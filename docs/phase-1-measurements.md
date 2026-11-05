# Phase 1 fixture measurements

Each native CI artifact includes `phase1-measurements.json`. This report collects
selected measurements from the original broker-service report and recorded-project
manifest, with SHA-256 values for its input reports. It is produced before the
artifact upload, including on failed runs. Missing or invalid observations stay
`null`; generation does not change any test result or merge gate.

The recorded workflow contributes one explicitly scoped trial, its verified
result and task/workflow/artifact identities, elapsed time and four distinct PAM
effect approvals. The intentional failing test is part of the correction trial,
not a regression. This workflow is separate from the addition-project mock demo;
the report does not double-count them as two independent tasks.

The access-denial cohort has exactly 14 named actor/target pairs for request,
control and provision sockets and the private journal. All distinct expected
cases must be present with the expected kernel denial before zero bypasses is
reported. This is not the complete policy/adversarial suite's bypass rate.

The runtime memory summary must agree with its raw observations, manifest and
broker report. Its exact aggregate and whole-product peak remain unknown; the
human desktop and CI harness are excluded. The installed-runtime OOM observation
is included only with kernel event increases, surviving service identities,
unverified unknown/no replay, and a separate approved follow-up's captured output.
See [memory scope](runtime-memory-observations.md) and [OOM scope](runtime-oom-observations.md).

Phase-wide task success/bypass rates, billing and phase-wide regression counts
remain unknown. A passing quality job has its own executed test count; this
native report does not substitute a selected fixture count for that result.
`full_phase_accepted` is always false: reporting scoped observations does not
complete the phase, the first cross-app MVP, physical testing or full v2.1.
