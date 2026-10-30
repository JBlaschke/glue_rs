# Historical registration byte fixtures

The three `.snapshot` files retain the exact Git blob bytes from commit
`5df3472d91daa911301538944e91779c2dc61e0b`, beneath
`fixtures/mvp/macos-trace/`. Relative paths are preserved with a `.snapshot`
suffix so historical test code cannot be discovered or imported as a test.

These are registration and test metadata fixtures. They contain no raw native
capture and do not establish a new native proof or admission. Their SHA256
values remain the original `HISTORICAL_PINS` values in `test_build_kit.py`:

| Snapshot path | SHA256 |
| --- | --- |
| `bootstrap-kit/reviewed-inputs.json.snapshot` | `8774f5bb07b46c90c8a2bbb2afdb36db531bdac0cae28b56e5efd81632dc0fa6` |
| `bootstrap-trace-kit/reviewed-inputs.json.snapshot` | `10ef1a993a1be047431fb854d1eeac8fdae622c533e67a228fce6c162e639008` |
| `bootstrap-trace-kit/test_build_kit.py.snapshot` | `34579c29f225bf1f46ece88ff8f1a3e04d603986f9692b944b3b46187de36251` |

The test reads these as bytes without executing the historical test snapshot or
requiring Git history. `REVIEWED_REGISTRATION_PINS` separately checks the live
registration files. The live registries must retain the historical source
rosters, compile lists and proof entries; only reviewed source identities and
their source revision advance.
