from importlib import metadata, resources
import contextlib
# Fixture hashing uses the reviewed CPython 3.13 built-in, without OpenSSL.
from _sha2 import sha256
import io
import json
import os


# Baseline and archive execution use identical package/application bytes. Only
# checks that require virtual archive paths differ for ordinary stock Python.
BASELINE = os.environ.get("GLUE_REAL_PACKAGE_BASELINE") == "1"
os.environ["LC_ALL"] = "C"
VERSIONS = {"markdown-it-py": "4.2.0", "mdit-py-plugins": "0.6.1", "mdurl": "0.1.2"}
COUNTS = {"markdown-it-py": 76, "mdit-py-plugins": 62, "mdurl": 13}
INPUT = """---
title: Portable markdown
---
# Portable markdown

A **strong** and *emphasized* [link](https://example.invalid/caf\u00e9?x=1&y=2).

- [x] Sources and assets
- [ ] No extraction

A footnote.[^note]

[^note]: Pinned packages with `inline code`.
"""
EXPECTED_HTML_SHA = "f4af45afee1a6ecba7f3f602c9f94440c40fe81feb5a1e43d6180c20a6a1a5a7"
EXPECTED_TOKENS_SHA = "6c8937090d00eab425262de58669778eb2d5392164547afe0963ab5e0297f69f"
EXPECTED_TOKEN_COUNT = 30
OUTPUT = "glue python real packages ok: markdown-it-py=4.2.0 mdit-py-plugins=0.6.1 mdurl=0.1.2 render=tokens=metadata=resources=entrypoint\n"


def workload():
    from markdown_it import MarkdownIt
    from mdit_py_plugins.footnote import footnote_plugin
    from mdit_py_plugins.front_matter import front_matter_plugin
    from mdit_py_plugins.tasklists import tasklists_plugin
    import markdown_it
    import mdit_py_plugins
    import mdurl

    assert markdown_it.__version__ == "4.2.0", 'real package fixture: markdown_it.__version__ == "4.2.0"'
    assert mdit_py_plugins.__version__ == "0.6.1", 'real package fixture: mdit_py_plugins.__version__ == "0.6.1"'
    assert mdurl.__version__ == "0.1.2", 'real package fixture: mdurl.__version__ == "0.1.2"'
    engine = MarkdownIt("commonmark", {"html": False, "linkify": False})
    engine.use(front_matter_plugin).use(footnote_plugin).use(tasklists_plugin)
    html = engine.render(INPUT)
    tokens = engine.parse(INPUT)
    serialized = json.dumps([token.as_dict() for token in tokens], sort_keys=True,
                            separators=(",", ":"), ensure_ascii=True).encode("ascii")
    assert tokens[0].type == "front_matter" and tokens[0].content == "title: Portable markdown", 'real package fixture: tokens[0].type == "front_matter" and tokens[0].content == "title: Portable markdown"'
    assert any(token.type == "footnote_block_open" for token in tokens), 'real package fixture: any(token.type == "footnote_block_open" for token in tokens)'
    assert any("contains-task-list" in str(token.attrs) for token in tokens), 'real package fixture: any("contains-task-list" in str(token.attrs) for token in tokens)'
    return {"html": html, "html_sha256": sha256(html.encode("utf-8")).hexdigest(),
            "tokens_json": serialized.decode("ascii"), "tokens_sha256": sha256(serialized).hexdigest(),
            "token_count": len(tokens)}


def verify_metadata_and_resources():
    for project, version in VERSIONS.items():
        distribution = metadata.distribution(project)
        assert metadata.version(project.upper().replace("-", "_")) == version, 'real package fixture: metadata.version(project.upper().replace("-", "_")) == version'
        assert distribution.metadata["Name"] == project, 'real package fixture: distribution.metadata["Name"] == project'
        assert distribution.metadata["Version"] == version, 'real package fixture: distribution.metadata["Version"] == version'
        retained = [path for path in distribution.files if "__pycache__" not in str(path).split("/") and not str(path).startswith("../../../bin/")]
        assert len(retained) == COUNTS[project], 'real package fixture: len(retained) == COUNTS[project]'
        if not BASELINE:
            assert len(distribution.files) == len(retained), 'real package fixture: len(distribution.files) == len(retained)'
        assert distribution.read_text("missing.txt") is None, 'real package fixture: distribution.read_text("missing.txt") is None'
        assert distribution.read_text("INSTALLER") == "pip\n", 'real package fixture: distribution.read_text("INSTALLER") == "pip\\n"'
        assert distribution.read_text("REQUESTED") == "", 'real package fixture: distribution.read_text("REQUESTED") == ""'
        assert distribution.metadata["Requires-Python"] == (">=3.7" if project == "mdurl" else ">=3.10"), 'real package fixture: distribution.metadata["Requires-Python"] == (">=3.7" if project == "mdurl" else ">=3.10")'
        if not BASELINE:
            assert str(distribution.locate_file("")).startswith("glue://"), 'real package fixture: str(distribution.locate_file("")).startswith("glue://")'
    assert metadata.requires("mdurl") is None, 'real package fixture: metadata.requires("mdurl") is None'
    assert metadata.requires("markdown-it-py")[0] == "mdurl~=0.1", 'real package fixture: metadata.requires("markdown-it-py")[0] == "mdurl~=0.1"'
    assert metadata.requires("mdit-py-plugins")[0] == "markdown-it-py>=2.0.0,<5.0.0", 'real package fixture: metadata.requires("mdit-py-plugins")[0] == "markdown-it-py>=2.0.0,<5.0.0"'
    assert metadata.packages_distributions()["markdown_it"] == ["markdown-it-py"], 'real package fixture: metadata.packages_distributions()["markdown_it"] == ["markdown-it-py"]'
    assert metadata.packages_distributions()["mdit_py_plugins"] == ["mdit-py-plugins"], 'real package fixture: metadata.packages_distributions()["mdit_py_plugins"] == ["mdit-py-plugins"]'
    assert metadata.packages_distributions()["mdurl"] == ["mdurl"], 'real package fixture: metadata.packages_distributions()["mdurl"] == ["mdurl"]'
    resource_specs = (
        ("markdown_it", "port.yaml", 2447, "8edfeb7703a77e870e5799dcdf9adebd3c9b00040c229ffed5f95aff9dbbb151"),
        ("mdit_py_plugins.container", "README.md", 2533, "a7744ba99d43dbd71ddd840795027d2fec01a94f25604df80f123ad72d61278b"),
        ("mdit_py_plugins.container", "LICENSE", 1073, "c91339910d300f163edcaddbfb3909f1cffae19a496b7fe3935a9a4073dc305a"),
    )
    for package, name, size, digest in resource_specs:
        item = resources.files(package).joinpath(name)
        assert item.is_file(), 'real package fixture: item.is_file()'
        payload = item.read_bytes()
        assert len(payload) == size and sha256(payload).hexdigest() == digest, 'real package fixture: len(payload) == size and sha256(payload).hexdigest() == digest'
        assert item.read_text() == payload.decode("utf-8"), 'real package fixture: item.read_text() == payload.decode("utf-8")'
        with item.open("rb") as stream:
            assert stream.read() == payload, 'real package fixture: stream.read() == payload'
        if not BASELINE:
            assert "glue://" in repr(item), 'real package fixture: "glue://" in repr(item)'
            try:
                os.fspath(item)
            except TypeError:
                pass
            else:
                raise AssertionError("package resource acquired a physical path")
            try:
                with resources.as_file(item):
                    raise AssertionError("package resource materialized on disk")
            except (TypeError, RuntimeError):
                pass
    for package in ("markdown_it", "mdit_py_plugins", "mdurl"):
        assert resources.files(package).joinpath("py.typed").read_bytes() == b"# Marker file for PEP 561\n", 'real package fixture: resources.files(package).joinpath("py.typed").read_bytes() == b"# Marker file for PEP 561\\n"'
    for project, name, size, digest in (
        ("markdown-it-py", "licenses/LICENSE", 1078, "4a2260d6e2cd0f5a151a1e86dbfe7d3ed552b1e2beabf9941c1ba5c49cbce484"),
        ("mdit-py-plugins", "licenses/LICENSE", 1078, "4a2260d6e2cd0f5a151a1e86dbfe7d3ed552b1e2beabf9941c1ba5c49cbce484"),
        ("mdurl", "LICENSE", 2338, "7c605df6e28667a9603118e98274f64a49ce3eed0d26fccce9534a345e0ef955"),
    ):
        payload = metadata.distribution(project).read_text(name).encode("utf-8")
        assert len(payload) == size and sha256(payload).hexdigest() == digest, 'real package fixture: len(payload) == size and sha256(payload).hexdigest() == digest'
    entries = metadata.entry_points(group="console_scripts", name="markdown-it")
    assert len(entries) == 1, 'real package fixture: len(entries) == 1'
    entry = next(iter(entries))
    assert entry.value == "markdown_it.cli.parse:main" and entry.dist.name == "markdown-it-py", 'real package fixture: entry.value == "markdown_it.cli.parse:main" and entry.dist.name == "markdown-it-py"'
    function = entry.load()
    assert callable(function) and function.__module__ == "markdown_it.cli.parse", 'real package fixture: callable(function) and function.__module__ == "markdown_it.cli.parse"'
    capture = io.StringIO()
    with contextlib.redirect_stdout(capture):
        try:
            function(["--version"])
        except SystemExit as error:
            assert error.code == 0, 'real package fixture: error.code == 0'
        else:
            raise AssertionError("upstream console callable did not complete its version action")
    assert capture.getvalue() == "markdown-it-py [version 4.2.0]\n", 'real package fixture: capture.getvalue() == "markdown-it-py [version 4.2.0]\\n"'
    try:
        metadata.version("glue-real-package-physical-lure")
    except metadata.PackageNotFoundError:
        pass
    else:
        raise AssertionError("physical metadata escaped the archive")
    assert list(metadata.distributions(path=[])) == [], 'real package fixture: list(metadata.distributions(path=[])) == []'
    if not BASELINE:
        assert list(metadata.distributions(path=["/physical/distribution/lure"])) == [], 'real package fixture: list(metadata.distributions(path=["/physical/distribution/lure"])) == []'
        virtual_root = str(metadata.distribution("markdown-it-py").locate_file(""))
        assert {item.name for item in metadata.distributions(path=[virtual_root])} == set(VERSIONS), 'real package fixture: {item.name for item in metadata.distributions(path=[virtual_root])} == set(VERSIONS)'


def main():
    verify_metadata_and_resources()
    result = workload()
    assert result["html_sha256"] == EXPECTED_HTML_SHA, 'real package fixture: result["html_sha256"] == EXPECTED_HTML_SHA'
    assert result["tokens_sha256"] == EXPECTED_TOKENS_SHA, 'real package fixture: result["tokens_sha256"] == EXPECTED_TOKENS_SHA'
    assert result["token_count"] == EXPECTED_TOKEN_COUNT, 'real package fixture: result["token_count"] == EXPECTED_TOKEN_COUNT'
    print(OUTPUT, end="")


if __name__ == "__main__":
    main()
