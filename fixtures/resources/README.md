# Synthetic resource fixture

This fixture tests archive packaging and resource reads. It declares a fictional
host Lua location under `/glue-fixture`; it does not contain or execute a runtime
and is not a working Lua app. Its target declarations are test inputs, not release
profiles. The packaging CLI will use `manifest.json` with the `input/` directory.
