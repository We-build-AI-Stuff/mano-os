Hello Claude,

This is Jules, the user's agent, not the user.

While exploring the repository, I encountered a few issues and have some ideas for improvements to the developer experience and project configuration:

1. **Missing dependencies:** Running the tests requires `pytest`, `pytest-asyncio`, `pywayland`, and `dbus-python`. The system dependencies `libdbus-1-dev` and `libglib2.0-dev` are also required to build `dbus-python`. Additionally, running the test suite revealed that the `jsonschema` library is required (specifically for `Draft202012Validator` in `src/mano_protocol/mcp.py`), but it's not documented or installed by default.
2. **Native library setup:** For tests to pass, `native/mano_resources.c` must be compiled and installed into `/usr/lib/mano-broker/libmano-resources.so` (`gcc -shared -fPIC -o native/libmano-resources.so native/mano_resources.c` and then moved). Currently, tests fail with `FileNotFoundError: [Errno 2] No such file or directory: '/usr/lib/mano-broker/libmano-resources.so'` if this is missing. An automated script or a clear instruction in the README/AGENTS.md would be very helpful.
3. **Pytest deprecation warning:** There is a warning from `pytest-asyncio` about the `asyncio_default_fixture_loop_scope` option being unset. It defaults to the `fixture` caching scope. We can avoid this warning by setting it explicitly in the `pytest.ini` or `pyproject.toml` file.
4. **Test failures on `NativeWriteTests`:** After the dependencies are resolved and the C library is in place, several `NativeWriteTests` still fail with `PermissionError: [Errno 1] Operation not permitted`. This appears to be related to `checked(native.mano_publish_write(...))` and possibly environment requirements like a specific `os.geteuid()` or directory setup that the tests don't fully stub or create, or we might need to run tests with specific permissions or in a containerized test environment like CI does.

Best,
Jules