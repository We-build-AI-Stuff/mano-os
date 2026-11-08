# Ideas and Improvements for mano-OS

## Note
Hi Claude, I am Jules, the user's agent, not the user. Here are some thoughts and ideas for mano-OS I've put together.

## Feature Ideas

1. **Integration with File Sync Services**
   Currently, mano-OS operates heavily within its own local runtime and isolated scopes. Allowing an authorized bridge to common file sync services (like Dropbox, Google Drive, Nextcloud) with strictly scoped permissions would allow users to more easily ingest data for agents to work on.

2. **Automated Error Recovery Suggestions for Agents**
   If an agent runs into an execution boundary issue or a permission error, mano-broker could optionally supply a small, bounded context snippet hinting at *why* it failed (e.g., "Missing explicit desktop PTY"). This would make it easier to self-correct during complex tasks without bothering the human user unnecessarily.

3. **Interactive Debug Shell for Failed Tasks**
   When a task crashes or hits an emergency stop, provide a restricted interactive debugging shell to the human user. This shell would inherit the state snapshot of the failed task, allowing the human to manually execute commands to see what went wrong before deciding whether to resume or cancel the task definitively.

## Potential Improvements

1. **Test Suite Execution Isolation Improvements**
   The test suite (`pytest`) currently leaves artifacts and expects specific environment setups (like compiling the native library locally). Automating this setup in a more robust way (perhaps via a standardized `make test` or test runner wrapper script that ensures a clean state) would reduce friction for new contributors and agents. Currently, there are pre-existing test failures on `main` (e.g., in `test_file_writes.py`).

2. **Finer-Grained Resource Limits**
   The project has resource limits, but exposing them more granularly per-task could be beneficial. For example, some AI tasks might need more CPU but less disk I/O, while others might need the reverse. The `mano-broker` could support dynamic resource profile definitions requested by the agent but capped by the human.

## Identified Bugs & Flaws

1. **`test_file_writes.py` Failures on `main`**
   There are several failing tests in `tests/test_file_writes.py` on the `main` branch (e.g., `test_create_replace_empty_and_historical_receipt_without_reexecution`, `test_existing_symlink_and_hardlink_races_never_mutate_external_inode`). These seem to be related to `PermissionError: [Errno 1] Operation not permitted` when `mano_broker` tries to execute file writes during the test execution.

2. **Missing `gh` CLI tool in Environment**
   The environment expects certain GitHub actions/issues commands, but `gh` CLI isn't installed by default, making some standard automated repository management tasks harder to run directly in the environment without manual setup.
