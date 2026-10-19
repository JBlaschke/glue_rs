#!/usr/bin/env python3
"""Guarded owned-tracing kit profile; currently unconfigured and non-executing."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REGISTRY = HERE / 'reviewed-inputs.json'
spec = importlib.util.spec_from_file_location('glue_bootstrap_trace_kit_core', HERE.parent / 'bootstrap-kit' / 'build_kit.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

BASE = 'fixtures/mvp/macos-trace/'
PROBE_SOURCES = tuple(BASE + 'bootstrap-probe/' + n for n in ('context_probe.c', 'probe_report.c'))
REQUEST_SOURCES = tuple(BASE + n for n in (
    'bootstrap-kit/make_request.c', 'bootstrap-kit/request_catalog.c',
    'bootstrap-admission/bootstrap_admission.c', 'bootstrap-request/bootstrap_request.c',
    'bootstrap-wire/bootstrap_wire.c', 'target-credentials/target_credentials.c'))
RUNNER_SOURCES = tuple(BASE + n for n in (
    'bootstrap-runner/owned_bootstrap_main.c', 'bootstrap-runner/runner_catalog.c',
    'bootstrap-runner/runner_protocol.c', 'bootstrap-runner/runner_support.c',
    'bootstrap-runner/runner_files.c', 'bootstrap-runner/runner_child.c',
    'bootstrap-runner/runner_parent.c', 'bootstrap-request/bootstrap_request.c',
    'bootstrap-wire/bootstrap_wire.c', 'bootstrap-probe/probe_report.c',
    'bootstrap-io/bootstrap_io.c', 'bootstrap-signals/bootstrap_signals.c',
    'bootstrap-admission/bootstrap_admission.c', 'target-credentials/target_credentials.c',
    'target-descriptors/target_descriptors.c', 'target-endpoints/target_endpoints.c',
    'bootstrap-runner/runner_trace.c', 'trace-session/trace_session.c',
    'owned-trace-backend/owned_trace_backend.c'))

POLICY = core.KitPolicy(
    BASE + 'bootstrap-trace-kit/reviewed-inputs.json',
    'glue-owned-trace-kit-inputs-v1', b'System Integrity Protection status: disabled.\n', 'disabled',
    'glue-owned-trace-kit-recipe-v1', 'glue-owned-trace-kit-build-id-v1',
    'glue-owned-trace-kit-result-v1', 'glue-owned-trace-kit-partial-failure-v1',
    'glue.mvp.ownedtrace', 'owned-trace-kit',
    (core.ArtifactPolicy('context-probe', 'probe_sources', expected_sources=PROBE_SOURCES),
     core.ArtifactPolicy('owned-trace-runner', 'runner_sources', ('-DGLUE_OWNED_TRACING',), ('-lproc', '-ldtrace'),
                         core.SYSTEM_DEPENDENCIES + (b'/usr/lib/libdtrace.dylib',), RUNNER_SOURCES),
     core.ArtifactPolicy('make-request', 'request_sources', expected_sources=REQUEST_SOURCES)),
    (BASE + 'bootstrap-kit/build_kit.py', BASE + 'bootstrap-trace-kit/build_kit.py',
     BASE + 'bootstrap-trace-kit/reviewed-inputs.json'),
    (BASE + 'bootstrap-kit/build_kit.py', BASE + 'bootstrap-trace-kit/build_kit.py'),
    ('/bootstrap-kit/', '/bootstrap-trace-kit/', '/bootstrap-probe/'), True)


def registry(data):
    return core.registry(data, policy=POLICY)


def admitted_proof(proof_path, inspector_path, rules):
    return core.admitted_proof(proof_path, inspector_path, rules, policy=POLICY)


def macho(data, *, artifact='owned-trace-runner'):
    core.artifact_policy(POLICY, artifact)
    return core.macho(data, policy=POLICY, artifact=artifact)


def construct(proof_path, inspector_path, output):
    return core.construct(proof_path, inspector_path, output, policy=POLICY)


def main():
    return core.main(policy=POLICY)


if __name__ == '__main__':
    sys.exit(main())
