#!/usr/bin/env python3
"""Unconfigured match-repair tracing profile; no kit is admitted for building."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
REGISTRY = HERE / 'reviewed-inputs.json'
spec = importlib.util.spec_from_file_location(
    'glue_bootstrap_trace_match_parent', HERE.parent / 'bootstrap-trace-kit' / 'build_kit.py')
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
core = trace.core
BASE = trace.BASE
WRAPPER = BASE + 'bootstrap-trace-match-kit/build_kit.py'
REGISTRY_RELATIVE = BASE + 'bootstrap-trace-match-kit/reviewed-inputs.json'

POLICY = replace(
    trace.POLICY,
    registry_relative=REGISTRY_RELATIVE,
    guard_paths=(BASE + 'bootstrap-kit/build_kit.py',
                 BASE + 'bootstrap-trace-kit/build_kit.py', WRAPPER, REGISTRY_RELATIVE),
    required_helpers=trace.POLICY.required_helpers + (WRAPPER,),
    excluded_runner_parts=trace.POLICY.excluded_runner_parts + ('/bootstrap-trace-match-kit/',))


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
