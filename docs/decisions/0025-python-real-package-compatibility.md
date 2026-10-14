# Real pure-Python package compatibility and Python requirements (A7/A10)

Status: implementation contract, 13 October 2026.

Exercise unmodified, explicitly pinned upstream wheels through the existing
`python-host`, `python-template` and `build-python` workflow. The first corpus is
markdown-it-py 4.2.0, mdit-py-plugins 0.6.1 and mdurl 0.1.2. Their declared base
dependency closure fits the existing application, distribution and RECORD caps.
The fixture selects the plugin dependency explicitly; optional linkification and
other extras are outside this workload. Preserve upstream source, assets,
metadata and licenses. Product building still performs no installation,
dependency resolution, target imports or interpreter execution.

Add portable admission of `Requires-Python` against the selected pinned runtime
version. Pure wheel tags alone do not establish interpreter-version compatibility.
Apply the same check to direct metadata-profile archives and installed-package
building, including distributions supplied by the explicit application tree,
before provider acquisition/output publication. Missing requirements
retain existing admission. Duplicate, folded, empty, malformed, unsupported or
unsatisfied requirements reject with an actionable diagnostic.

Use a bounded release-only subset of Python version specifiers: comma-conjoined
`<`, `<=`, `>`, `>=`, `==`, `!=` and `~=` comparisons; one to three decimal release
components; terminal `.*` prefixes for equality/inequality only; and compatible
release comparisons with at least two components. Zero-pad numeric releases for
comparison. Permit ordinary ASCII space around specifiers and a single enclosing
pair of parentheses. Reject prerelease/dev/post/local/epoch/arbitrary-equality
syntax explicitly rather than interpreting it as supported. The selected runtime
remains conventional CPython 3.13.16; this adds no runtime/version discovery or
selection. Bound the field value to 256 ASCII bytes and the conjunct count to 16,
and reject integer overflow.

Prepare the corpus with the matching stock PBS producer and offline pip into a
fresh unseeded conventional venv. Independently verify installed payloads against
wheel hashes and RECORD ownership, generated wrapper/cache omissions, deterministic
RECORD rewriting, product reports and complete archive inventories. Portable Mac
building must work with the venv interpreter absent. Compare a fixed rendering,
tokens, real distribution metadata and resource streams with ordinary pinned
Python; then execute the same archive application through all three providers on
immutable relocated GNU Linux arm64 storage with complete syscall traces.

Keep historical trace policies unchanged. A new isolated workload policy must pin
the complete real application inventory/output and preserve archive, readiness,
loader, host-source/cache, descriptor ownership, no-extraction, process and network
checks. Any additional observed allocation/startup operations require narrow
documented predicates and hostile controls. CRC damage must reject before provider
acquisition. Retain fresh runtime and preparation evidence without duplicating
large upstream runtime trees. This establishes only this corpus and cell; broader
packages, native extensions, providers/platforms and release gates remain open.

The development trace observes five failed stdout terminal-window queries from
the loaded argparse console callable, after the second thread query and before
output publication. Pin their exact request, retained stdout owner, `ENOTTY`
result, phase and count. The install-only cell additionally remaps one live
anonymous allocation from 282,624 to 565,248 bytes after its four original startup
remaps. Track that observation separately, retaining exact size, flags,
alignment, owner, image-overlap and startup-phase checks. Neither change admits
extra file writes, image acquisition, process creation or network operations;
missing/extra/reordered/foreign-owner observations must reject.

Primary sources: [markdown-it-py release](https://pypi.org/project/markdown-it-py/4.2.0/),
[mdit-py-plugins release](https://pypi.org/project/mdit-py-plugins/0.6.1/),
[mdurl release](https://pypi.org/project/mdurl/0.1.2/),
[Python version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/),
[Requires-Python](https://packaging.python.org/en/latest/specifications/core-metadata/#requires-python).
