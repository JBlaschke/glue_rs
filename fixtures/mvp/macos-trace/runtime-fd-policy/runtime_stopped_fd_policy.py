"""Fixed stopped raw FD intent projection; no observer-derived output authority.

The sole public factory accepts original bytes. The approved reader retains the
whole outer capture; only private child attempt selection enters the FD engine.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
from pathlib import Path
from typing import Iterable, Optional

_BASE = Path(__file__).resolve().parent.parent
DEPENDENCY_IDENTITIES = (
    ('runtime-boundary/runtime_stopped.py', '0fdec3de70394b674637b157fbdd7c83f2d72976928c0d5a2770626503416a78'),
    ('runtime-fd-policy/runtime_fd_policy.py', 'd3d82aed9c040e4e531a93d28fc38f7395715b2ec2fdc8e34cf45fe23a6a4f66'),
)
for _relative, _digest in DEPENDENCY_IDENTITIES:
    with (_BASE / _relative).open('rb') as _stream:
        _code = _stream.read(65537)
    if len(_code) > 65536 or hashlib.sha256(_code).hexdigest() != _digest:
        raise ValueError('stopped FD policy fixed dependency identity: ' + _relative)
del _relative, _digest, _stream, _code


def _import(name, relative):
    spec = importlib.util.spec_from_file_location(name, _BASE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_STOPPED = _import('_stopped_fd_reader', 'runtime-boundary/runtime_stopped.py')
_FD = _import('_stopped_fd_engine', 'runtime-fd-policy/runtime_fd_policy.py')
RuntimeRecipeEvidence = _STOPPED.RuntimeRecipeEvidence
RawValidationError = _STOPPED.RawValidationError
SOURCE_COMMIT = _FD.SOURCE_COMMIT


@dataclass(frozen=True)
class StoppedPolicyPhaseAccounting:
    ordinal: int
    role: str
    reader_role: str
    child_attempt_index: Optional[int] = None
    owner_control_index: Optional[int] = None


@dataclass(frozen=True)
class RuntimeStoppedFdPolicy:
    protocol: str
    status: str
    diagnostic: object
    attempts: tuple
    fcntl_attempts: tuple
    phase_accounting: tuple[StoppedPolicyPhaseAccounting, ...]
    windows: tuple
    conflicts: tuple
    transitions: tuple
    final_bindings: tuple
    violations: tuple
    gaps: tuple
    output_exemptions: tuple = ()
    native_admission: bool = False
    output_capabilities_authorized: bool = False
    state_feed_eligible: bool = False
    successful_effect_linearization: bool = False
    full_trace_acceptance: bool = False
    final_state_is_live: bool = False
    retention_before_continue_proved: bool = False
    ofd_identity_proved: bool = False
    descriptor_generation_proved: bool = False
    backing_identity_proved: bool = False
    native_origin_authenticated: bool = False
    raw_origin_authenticated: bool = False
    quiescence_proved: bool = False
    authorizes_sink_exemptions: bool = False
    full_flags_proved: bool = False
    c_and_trace_clock_origins_calibrated: bool = False
    foreign_controller_excluded: bool = False

    @property
    def source(self):
        return self.diagnostic.source

    def to_dict(self):
        return _FD._V1._plain(self)


def _accounting(diagnostic, roles):
    # Owner indexes and child indexes are different domains, even if their
    # numeric values happen to coincide. Every original outer row is retained.
    rows = []
    for original in diagnostic.phase_accounting:
        child = roles.get(original.source_ordinal)
        _FD._V1._require(child is None or original.control_index is None,
                         'stopped FD owner/child accounting collision')
        rows.append(StoppedPolicyPhaseAccounting(original.source_ordinal,
            original.role if child is None else child.role, original.role,
            None if child is None else child.attempt_index, original.control_index))
    _FD._V1._require(tuple(row.ordinal for row in rows) ==
        tuple(phase.ordinal for phase in diagnostic.source.phases),
        'stopped FD whole outer phase conservation')
    return tuple(rows)


def evaluate_runtime_stopped_fd_policy_raw(program: bytes, probes: bytes, errors: bytes,
        event_lines: Iterable[bytes], *, owner_pid: int, target_pid: int,
        contract_bytes: bytes, launch_evidence: RuntimeRecipeEvidence,
        output_observation: bytes) -> RuntimeStoppedFdPolicy:
    """Read the original stopped profile once, then evaluate child intent only.

    Raw CONT is a conditional intended cut. GLUEPX supplies no output seed,
    binding/flag snapshot, retention receipt or permission. Invalid raw evidence
    raises; diagnostic gaps produce request/accounting facts without a state
    prefix, even when the retained diagnostic has associated child pairs.
    """
    diagnostic = _STOPPED.pair_runtime_stopped_raw(program, probes, errors, event_lines,
        owner_pid=owner_pid, target_pid=target_pid, contract_bytes=contract_bytes,
        launch_evidence=launch_evidence, output_observation=output_observation)
    capture = diagnostic.source
    entries = [phase for phase in capture.phases
               if phase.raw_scalars[0] in (2, 15) and phase.raw_scalars[2] == target_pid]
    if diagnostic.gaps:
        attempts, commands = _FD._unpaired_attempts(entries, contract_bytes,
            extended=True, status_queries=True)
        roles = {a.entry.ordinal: _FD.PhaseAccounting(a.entry.ordinal,
            'opaque-mach-entry' if a.entry.raw_scalars[0] == 15 else 'unresolved-image-context', i)
            for i, a in enumerate(attempts)}
        violations = tuple(_FD._finding('forbidden-path-mutation' if a.intent == 'path-mutation-attempt'
            else 'forbidden-open-intent', a,
            'forbidden requested intent is retained despite incomplete stopped diagnostics')
            for a in attempts if a.intent == 'path-mutation-attempt' or
            a.source_name in _FD.OPEN_NAMES and a.write_reasons)
        gaps = tuple(_FD.PolicyFinding('stopped-' + gap.code, gap.source_ordinal, '', gap.message)
                     for gap in diagnostic.gaps)
        result = _FD._FdEvaluation('incomplete', (), (), (), (), violations, gaps)
    else:
        _FD._V1._require(diagnostic.images is not None, 'stopped FD complete child images')
        attempts, roles, commands = _FD._paired_attempts(diagnostic.images, entries,
            contract_bytes, extended=True, status_queries=True)
        # No conditional output seeds, including for numeric fd1/2 or matched PX.
        # The original full capture and raw hash are passed without replacement.
        result = _FD._evaluate_validated(capture, diagnostic.launch,
            diagnostic.images.transitions, (), attempts, commands,
            extended=True, status_queries=True)
    return RuntimeStoppedFdPolicy('darwin-runtime-stopped-fd-policy-v1', result.status,
        diagnostic, attempts, commands, _accounting(diagnostic, roles), result.windows,
        result.conflicts, result.transitions, result.final_bindings,
        result.violations, result.gaps)
