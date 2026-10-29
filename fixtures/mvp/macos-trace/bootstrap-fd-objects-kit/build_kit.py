#!/usr/bin/env python3
"""Fixed object-READY kit profile. Unconfigured; never executes its artifacts."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
BASE = 'fixtures/mvp/macos-trace/'
REGISTRY_RELATIVE = BASE + 'bootstrap-fd-objects-kit/reviewed-inputs.json'
REGISTRY = HERE / 'reviewed-inputs.json'
WRAPPER = BASE + 'bootstrap-fd-objects-kit/build_kit.py'
spec = importlib.util.spec_from_file_location('glue_fd_objects_kit_core', HERE.parent / 'bootstrap-kit/build_kit.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
PROBE_SOURCES = tuple(BASE + 'bootstrap-probe/' + n for n in ('context_probe.c', 'probe_report.c'))
REQUEST_SOURCES = tuple(BASE + n for n in (
    'bootstrap-kit/make_request.c', 'bootstrap-kit/request_catalog.c',
    'bootstrap-admission/bootstrap_admission.c', 'bootstrap-request/bootstrap_request.c',
    'bootstrap-wire/bootstrap_wire.c', 'target-credentials/target_credentials.c'))
RUNNER_SOURCES = tuple(BASE + n for n in (
    'bootstrap-runner/owned_bootstrap_main.c', 'bootstrap-runner/runner_catalog.c',
    'bootstrap-object-runner/object_protocol.c', 'bootstrap-object-runner/object_support.c',
    'bootstrap-object-runner/object_files.c', 'bootstrap-object-runner/object_child.c',
    'bootstrap-object-runner/object_parent.c', 'bootstrap-request/bootstrap_request.c',
    'bootstrap-wire/bootstrap_wire.c', 'bootstrap-probe/probe_report.c',
    'bootstrap-io/bootstrap_io.c', 'bootstrap-signals/bootstrap_signals.c',
    'bootstrap-admission/bootstrap_admission.c', 'target-credentials/target_credentials.c',
    'target-descriptors/target_descriptors.c', 'target-endpoints/target_endpoints.c',
    'bootstrap-object-wire/bootstrap_object_wire.c', 'target-fd-objects/target_fd_objects.c'))
POLICY = replace(
    core.LEGACY_POLICY,
    registry_relative=REGISTRY_RELATIVE, registry_schema='glue-bootstrap-fd-objects-kit-inputs-v1',
    recipe_schema='glue-bootstrap-fd-objects-kit-recipe-v1', build_id_schema='glue-bootstrap-fd-objects-kit-build-id-v1',
    result_schema='glue-bootstrap-fd-objects-kit-result-v1', partial_failure_schema='glue-bootstrap-fd-objects-kit-partial-failure-v1',
    signing_prefix='glue.mvp.fdobjects', error_prefix='fd-objects-kit',
    artifacts=(core.ArtifactPolicy('context-probe', 'probe_sources', expected_sources=PROBE_SOURCES),
               core.ArtifactPolicy('bootstrap-fd-objects-runner', 'runner_sources', expected_sources=RUNNER_SOURCES),
               core.ArtifactPolicy('make-request', 'request_sources', expected_sources=REQUEST_SOURCES)),
    guard_paths=(BASE + 'bootstrap-kit/build_kit.py', WRAPPER, REGISTRY_RELATIVE),
    required_helpers=(BASE + 'bootstrap-kit/build_kit.py', WRAPPER,
                      BASE + 'bootstrap-object-runner/objects_profile.h'),
    excluded_runner_parts=('/bootstrap-kit/', '/bootstrap-probe/', '/bootstrap-fd-objects-kit/'))


def registry(data):
    value = core.registry(data, policy=POLICY)
    if value['source_revision'] is None:
        core.require(not value['sources'] and not value['proofs'] and
                     all(not value[k] for k in ('probe_sources', 'runner_sources', 'request_sources')),
                     'unconfigured object registry must be completely empty')
    return value


def construct(proof_path, inspector_path, output):
    # The checked-in empty registry refuses in core before source/proof/output IO.
    registry(REGISTRY.read_bytes())
    return core.construct(proof_path, inspector_path, output, policy=POLICY)


def main():
    return core.main(policy=POLICY)


if __name__ == '__main__':
    sys.exit(main())
