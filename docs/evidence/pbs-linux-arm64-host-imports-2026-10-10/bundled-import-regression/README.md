# Bundled archive imports regression

Fresh GNU Linux arm64 captures from clean implementation
`9aababab78156f84628128060b64f51906bde5fe` retain the existing
[archive source/resource fixture](../../../../fixtures/python-imports/README.md).
`source-status.txt` and `source-diff.patch` are empty. The pinned image and
compressed-trace replay instructions are in the [parent evidence](../README.md).

The release launcher is 3,266,864 bytes, SHA-256
`bc0d43be649fc4eb9b0c15720baad5e77556b37f2369ea9e68be10a82f3b27c5`.
The valid archive is 83,092,494 bytes, SHA-256
`cb4c6365600e29efd3066ec9f233f2f1467a7a13f3438c4f12defbe4bb9f9520`;
the same-size corrupt archive is
`da8b417cd2059fd7137bca38f7f367ee6292d1c911d247adb75bb0f10f8665d8`.
`fixture-summary.json` records 2,194 resources, including 2,174 pinned stdlib
sources totaling 39,158,056 uncompressed bytes. The unchanged library is
73,563,968 bytes; six producer-compiled frozen modules provide startup.

| Mode | Records | Exit | Stdout / stderr bytes |
| --- | ---: | ---: | ---: |
| success | 33,512 | 0 | 100 / 0 |
| app-error | 33,518 | 1 | 100 / 66 |
| corrupt-source | 28,700 | 1 | 0 / 99 |

Successful and ordinary-loader comparison output is exactly:

```text
PASS Python=3.13.16 imports=archive packages=archive namespaces=archive resources=streams answer=42
```

The app-error diagnostic follows that line. The corruption control flips only
archive byte 341,451, the start of the stored 104-byte package source, and
rejects before runtime loading. All three complete raw captures and retained
compressed replays pass the unchanged bundled-import policy. Each trace has
one PID. Release tests report 56 passes and Clippy succeeds.

The fixture still verifies all archive inputs before sealed-image loading,
supports immutable resource streams through finalization, and rejects source
fallback or resource materialization attempts. This regression does not widen
the accepted Python versions, package set, extension policy, or platforms.
