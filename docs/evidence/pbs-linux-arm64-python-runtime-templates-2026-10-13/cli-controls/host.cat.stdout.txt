from importlib import metadata, resources
import os


distribution = metadata.distribution("GLUE__META...DEMO")
assert metadata.version("glue-meta-demo") == "1.2.3"
assert metadata.metadata("Glue.Meta-Demo")["Name"] == "Glue.Meta-Demo"
assert metadata.requires("glue-meta-demo") == ['Glue-Optional>=1; extra == "test"']
assert distribution.read_text("missing.txt") is None

entries = metadata.entry_points(group="glue.archive.plugins", name="answer")
entry = next(iter(entries))
assert len(entries) == 1 and entry.load()() == 42
assert entry.dist.name == "Glue.Meta-Demo"
assert metadata.packages_distributions()["glue_meta_demo"] == ["Glue.Meta-Demo"]
assert metadata.packages_distributions()["glue_meta_namespace"] == ["Glue.Meta-Demo"]

paths = {str(path): path for path in metadata.files("glue-meta-demo")}
resource = paths["glue_meta_demo/data/message,one.txt"]
assert resource.read_text() == "archive metadata resource\n"
assert resource.read_binary() == b"archive metadata resource\n"
assert resource.hash.mode == "sha256" and resource.size == 26
assert str(resource.locate()).startswith("glue://")
assert distribution.locate_file("").is_dir()
assert distribution.locate_file("glue_meta_demo").exists()
assert not distribution.locate_file("missing.txt").exists()
with resource.locate().open("rb") as stream:
    assert stream.read() == resource.read_binary()

for operation in (lambda: os.fspath(resource.locate()), lambda: resources.as_file(resource.locate())):
    try:
        operation()
    except (TypeError, RuntimeError):
        pass
    else:
        raise AssertionError("metadata paths must remain virtual")

try:
    metadata.version("Glue-Metadata-Physical-Lure")
except metadata.PackageNotFoundError:
    pass
else:
    raise AssertionError("physical distribution metadata escaped the archive")

assert list(metadata.distributions(path=[])) == []
assert list(metadata.distributions(path=["/physical/distribution/lure"])) == []
virtual_root = str(distribution.locate_file(""))
assert [item.name for item in metadata.distributions(path=[virtual_root])] == ["Glue.Meta-Demo"]
print("glue python distribution metadata ok: version=1.2.3 plugin=42 files=" + str(len(paths)))
