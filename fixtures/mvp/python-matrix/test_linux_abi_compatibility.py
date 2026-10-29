"""Semantic controls use synthetic metadata; no native acceptance is executed."""
import copy
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
import warnings
import zipfile

SOURCE = Path(__file__).with_name("linux_abi_compatibility.py")
SPEC = importlib.util.spec_from_file_location("linux_abi_compatibility", SOURCE)
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def identity(raw):
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def wheel(files=None):
    files = files if files is not None else {
        "cryptography/__init__.py": b"__version__ = '50.0.2'\n",
        "cryptography/hazmat/bindings/_rust.abi3.so": b"synthetic native member, never executed",
        "cryptography-50.0.2.dist-info/WHEEL": b"Wheel-Version: 1.0\nTag: cp39-abi3-manylinux_2_34_x86_64\n",
        "cryptography-50.0.2.dist-info/METADATA": b"Name: cryptography\nVersion: 50.0.2\n",
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, raw in files.items():
            archive.writestr(name, raw)
    return stream.getvalue()


class SummaryFixture:
    """Explicitly substitute a tiny test wheel pin; never native evidence."""
    def __init__(self, arch="x86_64"):
        self.arch = arch
        self.target = arch + "-unknown-linux-gnu"
        self.wheel = wheel()
        self.members = m.wheel_inventory(self.wheel)
        self.rows = copy.deepcopy(m._INPUT_ROWS)
        selected = list(self.rows[arch])
        selected[1] = (selected[1][0], selected[1][1], identity(self.wheel)["sha256"], len(self.wheel), selected[1][4])
        self.rows[arch] = tuple(selected)
        self.pin_patch = patch.object(m, "_INPUT_ROWS", self.rows)
        self.pin_patch.start()
        self.references = {version: self.receipt("python-source-normalized", version)
                           for version in ("3.13.16", "3.14.8")}
        self.manifest = m.official_manifest(arch)
        self.cases = {}
        for cell in m.cells_for(arch):
            version = m.compatibility_plan(arch)["runtime_versions"][cell.route]
            receipt = self.receipt(cell.recipe, version)
            cwd = "/owned/cases/" + cell.label + "/work"
            inputs = cwd + "/build inputs"
            minor = version.split(".")[1]
            native = cell.route != "patch"
            environment = {"kind": "ordinary", "version": [3, int(minor)], "pip_present": True,
                           "framework_input_prepared": False, "runtime": inputs + "/runtime/bin/python3." + minor}
            prepare = ["/usr/bin/python3", "/repo/fixtures/mvp/python-matrix/prepare.py", inputs,
                       "bin/python3." + minor, "ordinary"]
            if native:
                prepare.append("--native")
            prepare.extend(["--receipt-output", cwd[:-5] + "/environment-receipt.json"])
            receipt["commands"] = {
                "prepare": {"argv": prepare, "cwd": cwd, "executed": True, "timed_out": False, "exit": 0},
                "build": {"argv": ["/tools/glue", "build", "python", inputs + "/project", "--env", inputs + "/environment",
                                   "--entry", "main.py", "--output", cwd + "/built", "--normalize-native-paths",
                                   "--native-search", "/usr/lib"], "executed": True, "timed_out": False, "exit": 0},
            }
            inventory = {"environment-receipt.json": identity(encoded(environment))}
            output = b""
            if native:
                output = encoded({"status": "abi3-ok", "cryptography": "50.0.2"})
                inventory["project/main.py"] = m.ABI3_PROJECT.copy()
                prefix = "environment/lib/python3." + minor + "/site-packages/"
                for name, pin in self.members.items():
                    inventory["installed/" + name] = pin
                    inventory[prefix + name] = pin
                backend = "_cffi_backend.cpython-" + ("313" if cell.route == "cp313" else "314") + "-" + arch + "-linux-gnu.so"
                inventory["installed/" + backend] = identity(b"synthetic independent cffi " + minor.encode())
                inventory[prefix + backend] = inventory["installed/" + backend]
                for name in ("reference", "run"):
                    receipt["commands"][name] = {"stdout": {"path": name + ".stdout", **identity(output)}}
            raw_inventory = encoded(inventory)
            receipt["input_inventory"] = {"path": "input-inventory.json", **identity(raw_inventory)}
            self.cases[cell.label] = m.CaseEvidence(encoded(receipt), encoded(environment), raw_inventory, output, output)
        self.statuses = [{"case": cell.label, "exit": 0} for cell in m.cells_for(arch)]
        self.patch_provenance = {"target": self.target, "version": "3.13.15", "archive": self.manifest["patch"],
                                 "runtime_executable": self.receipt("", "3.13.15")["runtime"]["inputs"]["runtime-executable"],
                                 "native_bytes_edited": False}
        self.wheel_receipts = {}
        for tag in ("cp313", "cp314"):
            entries = []
            for release, route in zip(m.PACKAGES, ("cryptography", "cffi-" + tag, "pycparser")):
                name, version = release.split("==")
                pin = self.manifest[route]
                entries.append({"release": release, "metadata": "https://pypi.org/pypi/" + name + "/" + version + "/json",
                                "filename": pin["name"], "url": pin["url"], "size": pin["size"], "sha256": pin["sha256"]})
            self.wheel_receipts[tag] = encoded({"test_only": True, "python": tag,
                "target": "linux-arm64" if arch == "aarch64" else "linux-x86_64", "wheels": entries})

    def close(self):
        self.pin_patch.stop()

    def receipt(self, recipe, version):
        major, minor, patch_version = map(int, version.split("."))
        return {"status": "passed", "commit": "a" * 40, "case": recipe, "target": self.target,
                "host": {"target": self.target}, "reference_kind": "stock",
                "runtime": {"target": self.target, "version": version, "provider": "bundled", "implementation": "cpython",
                            "abi": {"language": "python", "gil": "conventional", "debug": False,
                                    "version": {"major": major, "minor": minor, "patch": patch_version}},
                            "inputs": {"runtime-executable": identity((version + self.arch).encode()),
                                       "stdlib:encodings/__init__.py": identity((version + "stdlib").encode())}},
                "launcher": {"path": "payload/glue", **identity(b"same synthetic glue launcher")},
                "checks": {name: {"status": "passed"} for name in m._REQUIRED_CHECKS}}

    def edit_receipt(self, label, edit):
        evidence = self.cases[label]
        value = json.loads(evidence.receipt)
        edit(value)
        self.cases[label] = replace(evidence, receipt=encoded(value))

    def edit_inventory(self, label, edit):
        evidence = self.cases[label]
        value = json.loads(evidence.inventory)
        edit(value)
        raw = encoded(value)
        receipt = json.loads(evidence.receipt)
        receipt["input_inventory"] = {"path": "input-inventory.json", **identity(raw)}
        self.cases[label] = replace(evidence, receipt=encoded(receipt), inventory=raw)

    def summary(self, **kwargs):
        values = dict(result=0, reference_receipts={k: encoded(v) for k, v in self.references.items()},
                      wheel_receipts=self.wheel_receipts, patch_provenance=encoded(self.patch_provenance),
                      cryptography_wheel=self.wheel, finished_utc="synthetic unit control")
        values.update(kwargs)
        return m.summarize(self.arch, self.statuses, self.manifest, self.cases, **values)


class CompatibilityControls(unittest.TestCase):
    def fixture(self, arch="x86_64"):
        value = SummaryFixture(arch)
        self.addCleanup(value.close)
        return value

    def failed(self, value, text=None):
        report = value.summary()
        self.assertEqual(report["status"], "failed", report)
        if text:
            self.assertIn(text, " ".join(report["errors"]))

    def test_closed_assets_match_actual_existing_provisioner_selection(self):
        spec = importlib.util.spec_from_file_location("provision_abi3_control", SOURCE.parents[1] / "python-native/provision.py")
        provision = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(provision)
        for arch, wheel_target in (("x86_64", "linux-x86_64"), ("aarch64", "linux-arm64")):
            assets = m.official_manifest(arch)
            self.assertEqual(set(assets), {"patch", "cryptography", "cffi-cp313", "cffi-cp314", "pycparser"})
            self.assertIn("cpython-3.13.15+20260929-" + arch + "-unknown-linux-gnu-install_only", assets["patch"]["name"])
            self.assertEqual(assets["cryptography"]["name"], "cryptography-50.0.2-cp39-abi3-manylinux_2_34_" + arch + ".whl")
            for tag in ("cp313", "cp314"):
                self.assertTrue(provision.compatible(assets["cryptography"]["name"], tag, wheel_target))
                self.assertTrue(provision.compatible(assets["cffi-" + tag]["name"], tag, wheel_target))
            self.assertFalse(provision.compatible(assets["cffi-cp314"]["name"], "cp313", wheel_target))
        for value in ("arm64", "macos-arm64", "x86_64-unknown-linux-gnu", None, [], True):
            with self.assertRaises(ValueError):
                m.compatibility_plan(value)

    def test_synthetic_complete_closure_is_explicitly_not_native_or_m2_acceptance(self):
        for arch in ("x86_64", "aarch64"):
            value = self.fixture(arch)
            report = value.summary()
            self.assertEqual(report["status"], "passed", report)
            self.assertFalse(report["full_m2_acceptance"])
            self.assertFalse(report["native_execution_performed_by_summary"])
            self.assertEqual(report["wrong_abi_refusal"]["status"], "unverified")
            value.close()

    def test_runtime_patch_must_change_sha_not_only_version_or_size(self):
        value = self.fixture()
        baseline = value.references["3.13.16"]["runtime"]["inputs"]["runtime-executable"]
        value.edit_receipt("python-patch-3.13.15-source", lambda r: r["runtime"]["inputs"]["runtime-executable"].update(
            sha256=baseline["sha256"], size=baseline["size"] + 1))
        self.failed(value, "different runtime-executable digest")

    def test_patch_requires_same_included_launcher_bytes(self):
        value = self.fixture()
        value.edit_receipt("python-patch-3.13.15-source", lambda r: r["launcher"].update(identity(b"rebuilt glue")))
        self.failed(value, "glue launcher differs")

    def test_runtime_minor_cannot_be_relabelled_by_case_name(self):
        value = self.fixture()
        value.edit_receipt("python-abi3-3.14.8", lambda r: r["runtime"].update(version="3.13.16"))
        self.failed(value, "version")

    def test_abi3_runtime_closure_must_match_each_checked_minor(self):
        value = self.fixture()
        value.edit_receipt("python-abi3-3.14.8", lambda r: r["runtime"]["inputs"].update({"stdlib:extra.py": identity(b"host fallback")}))
        self.failed(value, "runtime/stdlib differs")

    def test_wrong_source_commit_or_native_target_cannot_pass(self):
        value = self.fixture()
        value.edit_receipt("python-abi3-3.13.16", lambda r: r.update(commit="b" * 40, target="aarch64-unknown-linux-gnu"))
        self.failed(value, "source commits differ")

    def test_every_required_v02_gate_is_required(self):
        value = self.fixture()
        for name in m._REQUIRED_CHECKS:
            with self.subTest(name=name):
                evidence = value.cases["python-abi3-3.13.16"]
                value.edit_receipt("python-abi3-3.13.16", lambda r: r["checks"].pop(name))
                self.failed(value, "V02")
                value.cases["python-abi3-3.13.16"] = evidence

    def test_build_cannot_use_an_unrelated_environment_or_entry(self):
        value = self.fixture()
        for option, replacement in (("--env", "/unrelated/env"), ("--entry", "different.py")):
            with self.subTest(option=option):
                evidence = value.cases["python-abi3-3.13.16"]
                def edit(receipt):
                    argv = receipt["commands"]["build"]["argv"]
                    argv[argv.index(option) + 1] = replacement
                value.edit_receipt("python-abi3-3.13.16", edit)
                self.failed(value, "selected prepared tree/file route")
                value.cases["python-abi3-3.13.16"] = evidence

    def test_duplicate_environment_or_archive_override_is_rejected(self):
        value = self.fixture()
        for addition in (["--env", "/extra"], ["--runtime", "/archive"], ["--module", "main"]):
            with self.subTest(addition=addition):
                evidence = value.cases["python-patch-3.13.15-source"]
                value.edit_receipt("python-patch-3.13.15-source", lambda r: r["commands"]["build"]["argv"].extend(addition))
                self.failed(value, "tree/file route")
                value.cases["python-patch-3.13.15-source"] = evidence

    def test_build_output_must_be_its_own_work_built_with_one_separated_value(self):
        value = self.fixture()
        label = "python-patch-3.13.15-source"
        for replacement in ("/unrelated/built", "/owned/cases/" + label + "/built"):
            with self.subTest(replacement=replacement):
                evidence = value.cases[label]
                def edit(receipt):
                    argv = receipt["commands"]["build"]["argv"]
                    argv[argv.index("--output") + 1] = replacement
                value.edit_receipt(label, edit)
                self.failed(value, "selected prepared tree/file route")
                value.cases[label] = evidence
        for alteration in ("duplicate", "equals", "missing-value"):
            with self.subTest(alteration=alteration):
                evidence = value.cases[label]
                def edit(receipt):
                    argv = receipt["commands"]["build"]["argv"]
                    index = argv.index("--output")
                    output = argv[index + 1]
                    if alteration == "duplicate":
                        argv.extend(["--output", output])
                    elif alteration == "equals":
                        argv[index:index + 2] = ["--output=" + output]
                    else:
                        del argv[index:index + 2]
                        argv.append("--output")
                value.edit_receipt(label, edit)
                self.failed(value, "selected prepared tree/file route")
                value.cases[label] = evidence

    def test_malformed_preparation_paths_and_native_marker_fail_closed(self):
        value = self.fixture()
        for malformed in (None, [], {"cwd": "bad"}):
            with self.subTest(malformed=malformed):
                evidence = value.cases["python-patch-3.13.15-source"]
                value.edit_receipt("python-patch-3.13.15-source", lambda r: r["commands"]["prepare"].update(cwd=malformed))
                self.failed(value, "paths are malformed")
                value.cases["python-patch-3.13.15-source"] = evidence
        value.edit_receipt("python-abi3-3.13.16", lambda r: r["commands"]["prepare"]["argv"].remove("--native"))
        self.failed(value, "preparation command")

    def test_retained_environment_requires_original_inventory_binding(self):
        value = self.fixture()
        evidence = value.cases["python-abi3-3.13.16"]
        altered = json.loads(evidence.environment)
        altered["pip_present"] = False
        value.cases["python-abi3-3.13.16"] = replace(evidence, environment=encoded(altered))
        self.failed(value, "differs from original input inventory")

    def test_changed_native_member_is_rejected_even_if_both_prepared_copies_match(self):
        value = self.fixture()
        member = "cryptography/hazmat/bindings/_rust.abi3.so"
        for label, minor in (("python-abi3-3.13.16", "13"), ("python-abi3-3.14.8", "14")):
            def edit(inv):
                inv["installed/" + member] = identity(b"same replaced wheel on both minors")
                inv["environment/lib/python3." + minor + "/site-packages/" + member] = inv["installed/" + member]
            value.edit_inventory(label, edit)
        self.failed(value, "differ from retained official wheel")

    def test_added_or_omitted_crypto_member_cannot_hide_in_matching_native_hash(self):
        value = self.fixture()
        value.edit_inventory("python-abi3-3.13.16", lambda inv: inv.update({"installed/cryptography/extra.py": identity(b"extra")}))
        self.failed(value, "original installed cryptography bytes differ")

    def test_wrong_minor_cffi_is_rejected_in_a_positive_abi3_cell(self):
        value = self.fixture()
        def edit(inv):
            for name in list(inv):
                if "_cffi_backend.cpython-313-" in name:
                    inv[name.replace("cpython-313-", "cpython-314-")] = inv.pop(name)
        value.edit_inventory("python-abi3-3.13.16", edit)
        self.failed(value, "cffi backend")

    def test_crypto_operations_require_pinned_source_and_bound_success_output(self):
        value = self.fixture()
        value.edit_inventory("python-abi3-3.13.16", lambda inv: inv.update({"project/main.py": identity(b"print version only")}))
        self.failed(value, "operation project source differs")
        value = self.fixture()
        evidence = value.cases["python-abi3-3.14.8"]
        raw = encoded({"status": "import-only", "cryptography": "50.0.2"})
        value.cases["python-abi3-3.14.8"] = replace(evidence, reference_stdout=raw, run_stdout=raw)
        value.edit_receipt("python-abi3-3.14.8", lambda r: [r["commands"][name]["stdout"].update(identity(raw)) for name in ("reference", "run")])
        self.failed(value, "crypto operation result differs")

    def test_source_wheel_and_recorded_provisioner_pins_are_required(self):
        value = self.fixture()
        self.assertEqual(value.summary(cryptography_wheel=value.wheel + b"changed")["status"], "failed")
        row = json.loads(value.wheel_receipts["cp314"])
        row["wheels"][1]["filename"] = value.manifest["cffi-cp313"]["name"]
        value.wheel_receipts["cp314"] = encoded(row)
        self.failed(value, "per-minor official pins")

    def test_patch_staging_bridge_requires_original_archive_and_actual_executable(self):
        value = self.fixture()
        value.patch_provenance["runtime_executable"] = identity(b"different staged interpreter")
        self.failed(value, "staged-interpreter provenance differs")
        value = self.fixture()
        value.patch_provenance["native_bytes_edited"] = True
        self.failed(value, "staged-interpreter provenance differs")

    def test_status_roster_bool_and_unrelated_failures_remain_visible(self):
        value = self.fixture()
        for rows in (value.statuses[:2], value.statuses + [value.statuses[0]],
                     [{"case": row["case"], "exit": False} for row in value.statuses],
                     [{"case": row["case"], "exit": 1} for row in value.statuses]):
            with self.subTest(rows=rows):
                original = value.statuses
                value.statuses = rows
                self.failed(value)
                value.statuses = original
        report = value.summary(result=1)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(all(cell["status"] == "passed" for cell in report["cases"]))

    def test_malformed_untrusted_metadata_returns_failure_without_traceback(self):
        value = self.fixture()
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'[]', b'null'):
            with self.subTest(raw=raw):
                self.assertEqual(value.summary(patch_provenance=raw)["status"], "failed")
        malformed = json.loads(value.wheel_receipts["cp314"])
        malformed["wheels"][0]["release"] = []
        value.wheel_receipts["cp314"] = encoded(malformed)
        self.failed(value, "provisioning choices")


class WheelControls(unittest.TestCase):
    def test_reader_hashes_ordinary_members_without_extraction_or_execution(self):
        members = {"danger.pth": b"import os;raise RuntimeError('must never execute')", "a.txt": b"data"}
        self.assertEqual(m.wheel_inventory(wheel(members)), {name: identity(raw) for name, raw in members.items()})

    def test_traversal_absolute_alias_and_case_collisions_are_rejected(self):
        for members in ({"../escape": b"x"}, {"/absolute": b"x"}, {"a/./b": b"x"},
                        {"a\\b": b"x"}, {"A.py": b"x", "a.py": b"y"},
                        {"caf\u00e9": b"x", "cafe\u0301": b"y"}):
            with self.subTest(members=list(members)):
                with self.assertRaises(ValueError):
                    m.wheel_inventory(wheel(members))

    def test_duplicate_names_symlinks_and_nonarchives_are_rejected(self):
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("duplicate", b"x")
                archive.writestr("duplicate", b"y")
        with self.assertRaises(ValueError):
            m.wheel_inventory(stream.getvalue())
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            member = zipfile.ZipInfo("link")
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, b"target")
        with self.assertRaises(ValueError):
            m.wheel_inventory(stream.getvalue())
        with self.assertRaises(ValueError):
            m.wheel_inventory(b"not a ZIP")

    def test_official_hash_and_stable_abi_native_member_are_both_required(self):
        raw = wheel()
        with self.assertRaises(ValueError):
            m._cryptography_members(raw, m.official_manifest("x86_64")["cryptography"])
        wrong = wheel({"cryptography/binding.cpython-313-x86_64-linux-gnu.so": b"x"})
        with self.assertRaises(ValueError):
            m._cryptography_members(wrong, identity(wrong))
        foreign = wheel({"foreign.py": b"x", "cryptography/hazmat/bindings/_rust.abi3.so": b"x"})
        with self.assertRaises(ValueError):
            m._cryptography_members(foreign, identity(foreign))


class RefusalControls(unittest.TestCase):
    def evidence(self):
        arch = "x86_64"
        reference = SummaryFixture.__new__(SummaryFixture)
        reference.arch, reference.target = arch, arch + "-unknown-linux-gnu"
        receipt = reference.receipt("python-source-normalized", "3.13.16")
        runtime = receipt["runtime"]["inputs"]["runtime-executable"]
        backend = "_cffi_backend.cpython-314-x86_64-linux-gnu.so"
        inventory = encoded({"installed/" + backend: identity(b"genuine source pin is recorded separately"),
                             "environment/lib/python3.13/site-packages/" + backend: identity(b"genuine source pin is recorded separately"),
                             "runtime/bin/python3.13": runtime})
        stderr = encoded({"code": "runtime_abi_mismatch", "message": "wrong ABI", "remedy": "supply compatible inputs"})
        root = "/owned/cases/python-wrong-abi-refusal"
        inputs = root + "/work/build inputs"
        record = {"target": reference.target, "commit": "a" * 40, "runtime_version": "3.13.16", "runtime_executable": runtime,
                  "foreign_wheel": m.official_manifest(arch)["cffi-cp314"], "input_inventory": identity(inventory),
                  "command": {"executed": True, "timed_out": False, "exit": 1, "cwd": root + "/work",
                              "argv": ["/tools/glue", "build", "python", inputs + "/project", "--env", inputs + "/environment",
                                       "--entry", "main.py", "--output", root + "/rejected output", "--python", "3.13", "--json"],
                              "stderr": identity(stderr)},
                  "output_path": root + "/rejected output", "output_before": {"kind": "absent"}, "output_after": {"kind": "absent"},
                  "sentinel_path": root + "/sibling sentinel", "sentinel_before": {"sentinel.txt": identity(b"preserve")},
                  "sentinel_after": {"sentinel.txt": identity(b"preserve")}}
        return m.RefusalEvidence(encoded(record), stderr, inventory), encoded(receipt)

    def test_separate_refusal_metadata_is_not_native_execution(self):
        evidence, reference = self.evidence()
        report = m.assess_refusal("x86_64", evidence, reference)
        self.assertEqual(report["status"], "passed", report)
        self.assertFalse(report["native_execution_performed_by_summary"])

    def test_output_collision_is_not_an_abi_diagnostic(self):
        evidence, reference = self.evidence()
        stderr = encoded({"code": "output_exists"})
        record = json.loads(evidence.record)
        record["command"]["stderr"] = identity(stderr)
        evidence = replace(evidence, record=encoded(record), stderr=stderr)
        self.assertEqual(m.assess_refusal("x86_64", evidence, reference)["status"], "failed")

    def test_runtime_and_other_entry_overrides_cannot_change_the_refusal_route(self):
        for option, value in (("--runtime", "/unrelated/runtime"), ("--module", "main"), ("--console-script", "sample")):
            for words in ([option, value], [option + "=" + value]):
                with self.subTest(words=words):
                    evidence, reference = self.evidence()
                    record = json.loads(evidence.record)
                    record["command"]["argv"].extend(words)
                    report = m.assess_refusal("x86_64", replace(evidence, record=encoded(record)), reference)
                    self.assertEqual(report["status"], "failed", report)
                    self.assertIn("foreign environment/output/sibling sentinel", " ".join(report["errors"]))

    def test_mutated_output_sentinel_inventory_or_unrelated_env_cannot_pass(self):
        for field, value in (("output_after", {"kind": "directory"}), ("sentinel_after", {}),
                             ("input_inventory", identity(b"unrelated"))):
            evidence, reference = self.evidence()
            record = json.loads(evidence.record)
            record[field] = value
            self.assertEqual(m.assess_refusal("x86_64", replace(evidence, record=encoded(record)), reference)["status"], "failed")
        evidence, reference = self.evidence()
        record = json.loads(evidence.record)
        record["command"]["argv"][record["command"]["argv"].index("--env") + 1] = "/unrelated/env"
        self.assertEqual(m.assess_refusal("x86_64", replace(evidence, record=encoded(record)), reference)["status"], "failed")

    def test_missing_or_malformed_refusal_cannot_be_inferred_from_positive_cases(self):
        _, reference = self.evidence()
        for evidence in (None, b"{}", m.RefusalEvidence(b"{}", b"{}", b"{}")):
            self.assertEqual(m.assess_refusal("x86_64", evidence, reference)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
