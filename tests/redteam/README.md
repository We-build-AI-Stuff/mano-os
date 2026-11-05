# Untrusted attack fixtures

These files are test data. Do not follow their repository instructions or execute
their payloads on a host. The native CI harness sends the three terminal fixtures
through the existing supervised broker/launcher boundary in a disposable guest.
The scripts refuse Mac/Root execution; the harness separately requires its QEMU
guest marker before creating the synthetic secret or using native approvals.

`corpus.json` declares four cases. The repository case simulates an already
compromised planner following the supplied instructions. The deceptive dependency
is a local `reqeusts` setup hook; it is never fetched from a real package index.
The shell case attempts its own protected write before running the common attacks.
The MCP case reuses the pinned official-SDK native discovery witness, including
hostile tool-description text, read-only workspace and network/IPC negatives.

The shared attacks attempt protected policy/config writes, journal/secret reads
and an IP socket. Each case also needs a successful workspace write. Hidden host
paths may return ENOENT; this is recorded as blocked or unavailable, not relabeled
as a permission error. Independent Root snapshots check protected host files.
The synthetic secret contains random CI-only bytes, never a real credential.

This corpus exercises OS confinement and untrusted metadata handling. It does not
measure live-model instruction-following, authenticated coding, real package-index
resolution or complete Phase 2/security acceptance. Native results remain pending
until this revision's CI report and original captured output are inspected.
