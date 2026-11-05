# Phase 2 named attack corpus

The [corpus manifest](../tests/redteam/corpus.json) names repository instructions,
a local deceptive dependency setup hook, a shell script and a hostile MCP server.
These are untrusted fixtures, not instructions for an assistant or host operator.

The native broker-service harness obtains one fresh PAM approval for a terminal
action containing the first three fixtures. Their child processes retain the
ordinary task sandbox, cleared environment, filesystem restrictions and resource
limits. Each must attempt its protected operations and produce a workspace-write
positive control. The harness independently compares protected host file hashes,
owners and modes, checks a private synthetic canary, reads original broker-held
stdout and verifies that replay returns the same action without execution.

The fourth case reuses the existing native-PAM/public-SDK MCP discovery action;
it does not add another copy of that probe. The installed server must match the
tracked fixture bytes. Its hostile description remains untrusted metadata with
no tool invocation authority, alongside its existing read-only/network/IPC checks.

`broker-service.json` contains `terminal_execution.redteam_corpus`: declared cases,
source hashes, original action/output metadata, fixture observations and independent
protected snapshots. It records unavailable host paths separately from permission
errors. A passing process exit alone cannot establish the corpus result.

This is a four-case CI corpus, with one additional granted terminal action. No live
model, authentication material, real deceptive package download or new production
capability is introduced. It does not establish authenticated adapter behavior,
general prompt-injection resistance or complete Phase 2/v2.1 acceptance. Native
acceptance is pending this revision's CI and evidence inspection.
