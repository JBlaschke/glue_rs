#!/usr/bin/env python3
"""Closed independent GNU preparation audits for the two stripped input forms.

The historical tree/publication graph is imported privately without changing
its predicates. The artifact adapter adds one authenticated compressed input,
two complete read/EOF passes, and their two exact rewinds. Neither input form
permits acquisition of an interpreter, an input mapping, or unselected files.
"""
from __future__ import annotations

import argparse
import gzip
import importlib.util
import inspect
import json
from pathlib import Path
import re
import sys
import tarfile

HERE = Path(__file__).resolve().parent


def local(name, path, bindings=None):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    old_path = list(sys.path)
    previous = {key: sys.modules.get(key) for key in bindings or {}}
    sys.modules[name] = module  # dataclass annotations resolve this module.
    try:
        sys.modules.update(bindings or {})
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = old_path
        for key, value in previous.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    return module


prepare = local('_stripped_process_prepare', HERE / 'prepare.py')
TREE = local('_stripped_private_tree_process', HERE.parent / 'python-runtime-trees/test_process.py',
             {'prepare': prepare.TREE})
require = prepare.require
descriptor, string, split_arguments = TREE.descriptor, TREE.string, TREE.split_arguments
decode_bytes = TREE.decode_bytes
ContractBase = TREE.Contract


class Contract(ContractBase):
    input_kind = 'tree'
    artifact_identity = None
    artifact_prefix = None

    @property
    def command(self):
        return [self.program, 'python-host', '--provider', prepare.PROVIDER,
                '--runtime-tree' if self.input_kind == 'tree' else '--pbs-install-only',
                self.root, '--output', self.prefix, '--json']


def contract(program, prefix, report_bytes, root=None, input_audit=None, artifact=None, artifact_file=None):
    require((root is None) != (artifact is None), 'exactly one preparation input is required')
    source = root or artifact
    for path in (program, source, prefix):
        TREE.path_string(path)
    require(not (source == prefix or source.startswith(prefix + '/') or prefix.startswith(source + '/')),
            'preparation input/output overlap')
    stock, provenance = prepare.expected_provenance()
    stock = {name: {'size': row['size'], 'sha256': row['sha256']} for name, row in stock.items()}
    provenance['files'] = stock
    prefixes = {}
    if root is not None:
        if input_audit is None:
            input_audit = prepare.audit_input(Path(root))
        expected = {'schema_version': 0, 'input_root': root, 'input_layout': 'stock-install-only-stripped',
                    'selected_files': stock, 'selected_file_count': 1041, 'selected_input_bytes': 38093257,
                    'input_python_execution_observed': False, 'complete_input_inventory_observed': False}
        if 'source_kind' in input_audit or 'artifact' in input_audit:
            expected.update(source_kind='authenticated-selected-tar-projection',
                            artifact=prepare.inspection.pins()['stripped_artifact'])
        require(prepare.same_json({key: value for key, value in input_audit.items()
                                   if key != 'selected_file_prefixes'}, expected), 'stripped input audit facts/schema differ')
        require(set(input_audit['selected_file_prefixes']) == set(stock), 'stripped input prefix inventory differs')
        for name, value in input_audit['selected_file_prefixes'].items():
            require(type(value) is str and re.fullmatch('[0-9a-f]*', value) is not None and
                    len(value) == 2 * min(512, stock[name]['size']), 'stripped input prefix length/spelling differs')
            prefixes[name] = bytes.fromhex(value)
            if stock[name]['size'] <= 512:
                require(prepare.same_json(prepare.identity(prefixes[name]), stock[name]), 'complete short input bytes differ')
        for key in ('artifact', 'artifact_entries', 'artifact_payload_bytes', 'omitted_files', 'omitted_bytes'):
            provenance[key] = None
        tree = {'input_root': root, 'input_layout': 'stock-install-only-stripped',
                'inspection_scope': 'selected-prerequisites-only',
                'expected_artifact': {key: prepare.inspection.pins()['stripped_artifact'][key]
                                      for key in ('filename', 'size', 'sha256', 'url')},
                'sysconfig_input': stock[prepare.SYSCONFIG], 'sysconfig_output': stock[prepare.SYSCONFIG],
                'sysconfig_normalized': False, 'sysconfig_template': None}
        ordered = {}
        for key, value in provenance.items():
            ordered[key] = value
            if key == 'omitted_bytes':
                ordered['installed_tree'] = tree
        provenance = ordered
    else:
        pin = prepare.inspection.pins()['stripped_artifact']
        artifact_file = Path(artifact_file or artifact)
        observed, artifact_prefix = prepare.regular_identity(artifact_file, pin['size'])
        require(prepare.same_json(observed, {key: pin[key] for key in ('size', 'sha256')}), 'process artifact pin differs')
        with tarfile.open(artifact_file, 'r:gz') as archive:
            for member in archive:
                name = member.name.removeprefix('python/')
                if name in stock:
                    require(member.isfile() and name not in prefixes, 'selected artifact member type/uniqueness differs')
                    data = archive.extractfile(member).read()
                    require(prepare.same_json(prepare.identity(data), stock[name]), 'selected artifact member identity differs')
                    prefixes[name] = data[:512]
        require(set(prefixes) == set(stock), 'selected artifact members absent')
        provenance['artifact'] = {key: pin[key] for key in ('filename', 'size', 'sha256', 'url')}
    original_sysconfig = (HERE.parent / 'python-runtime-trees/stock-sysconfig.py').read_bytes()
    require(prepare.same_json(prepare.identity(original_sysconfig), stock[prepare.SYSCONFIG]) and
            prefixes[prepare.SYSCONFIG] == original_sysconfig[:512], 'stock-only sysconfig prefix differs')
    library_prefix = bytes.fromhex(prepare.inspection.pins()['stripped_library_prefix_256_hex'])
    require(prefixes[prepare.LIBRARY][:256] == library_prefix, 'stripped library header prefix differs')
    provenance_bytes = TREE.compact(provenance)
    expected_report = {'provider': prepare.PROVIDER, 'prefix': prefix, 'provenance': provenance,
                       'provenance_file': {'path': 'provenance.json'} | prepare.identity(provenance_bytes),
                       'files': stock, 'file_count': 1041, 'payload_bytes': 38093257,
                       'directory_count': len(TREE.directories(stock)), 'file_mode': 292,
                       'directory_mode': 365, 'mtime_seconds': prepare.MTIME}
    require(report_bytes == TREE.compact(expected_report), 'complete stripped report bytes differ')
    outputs = stock | {'provenance.json': prepare.identity(provenance_bytes)}
    output_prefixes = prefixes | {'provenance.json': provenance_bytes[:512]}
    result = Contract(program, source, prefix, stock, prefixes, outputs, output_prefixes,
                      report_bytes, provenance_bytes, 'stock-install-only-stripped')
    if artifact is not None:
        result.input_kind = 'artifact'
        result.artifact_identity, result.artifact_prefix = observed, artifact_prefix
    return result


class ArtifactAudit(TREE.Audit):
    """One artifact owner; two complete pin-validation/decode read passes."""
    def __init__(self, expected):
        super().__init__(expected)
        self.input_open_order = [expected.root]
        self.input_dirs, self.root_ancestors = set(), set()
        self.artifact_path_stats = self.artifact_fd_stats = self.rewinds = self.read_pass = 0
        self.pass_bytes = 0
        self.artifact_closed = False

    def complete_inputs(self):
        require(self.artifact_closed and self.input_open_index == 1 and self.read_pass == 2 and
                self.rewinds == 2 and not any(owner.kind.startswith('input-') for owner in self.live.values()),
                'publication precedes both complete compressed passes/EOF/close')

    def complete_overlap_preflight(self):
        self.complete_inputs()
        require(self.output_absence_probes == 0, 'artifact mode adds an unclassified output absence probe')

    def open(self, args, result):
        pathname = string(args[1])
        if pathname == self.expected.root:
            require(len(args) == 3 and TREE.flags(args[2]) == {'O_RDONLY', 'O_CLOEXEC'} and
                    self.artifact_path_stats == 1 and self.input_open_index == 0 and not self.created_dirs,
                    'artifact open is repeated/write-capable or lacks prior regular metadata')
            require(self.resolved(args[0], pathname) == self.expected.root, 'artifact open path differs')
            number, returned = descriptor(result)
            require(type(number) is int and number > 2 and number not in self.live and returned == self.expected.root,
                    'artifact descriptor aliases or reassigns another owner')
            self.live[number] = TREE.Owner(returned, 'input-artifact')
            self.input_open_index = self.selected_opened = self.max_input_owners = 1
        else:
            super().open(args, result)

    def stat(self, name, args, result):
        pathname = string(args[1])
        if pathname == '' and descriptor(args[0])[0] in self.live and self.live[descriptor(args[0])[0]].kind == 'system':
            return super().stat(name, args, result)
        if pathname == self.expected.root:
            require(name == 'statx' and len(args) == 5 and result == '0' and
                    args[2:4] == ['AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW', 'STATX_ALL'] and
                    self.artifact_path_stats == 0 and self.input_open_index == 0,
                    'artifact path stat is repeated/non-regular/following aliases')
            self.artifact_path_stats += 1
            metadata = args[4]
        elif pathname == '' and descriptor(args[0])[0] in self.live and self.live[descriptor(args[0])[0]].kind == 'input-artifact':
            _, owner = self.owner(args[0], {'input-artifact'})
            require(result == '0' and self.artifact_fd_stats == 0 and self.rewinds == 0 and
                    ((name == 'statx' and args[2:4] == ['AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH', 'STATX_ALL']) or
                     (name == 'newfstatat' and args[3] == 'AT_EMPTY_PATH')),
                    'artifact descriptor stat is repeated/outside initial ownership phase')
            self.artifact_fd_stats += 1
            metadata = args[4] if name == 'statx' else args[2]
        else:
            require(pathname and self.resolved(args[0], pathname) in self.parent_ancestors and
                    result == '0' and not self.created_dirs, 'artifact parent metadata escapes publication admission')
            self.complete_inputs()
            metadata = args[4] if name == 'statx' else args[2]
            require('S_IFDIR|' in metadata, 'artifact output parent is not a directory')
            return
        size = re.search(r'\b(?:stx_size|st_size)=(\d+)', metadata)
        require('S_IFREG|' in metadata and size is not None and
                int(size.group(1)) == self.expected.artifact_identity['size'], 'artifact regular-file size differs')

    def transfer(self, name, args, result):
        number = descriptor(args[0])[0]
        owner = self.live.get(number)
        if owner is None or owner.kind != 'input-artifact':
            return super().transfer(name, args, result)
        self.owner(args[0], {'input-artifact'})
        require(name == 'read' and len(args) == 3 and args[2].isdigit() and result.isdigit() and
                self.rewinds == self.read_pass + 1 and self.artifact_fd_stats == 1 and not self.created_dirs,
                'artifact read is write-capable or outside its two rewind/read phases')
        requested, returned = int(args[2]), int(result)
        require(0 < requested <= 65536 and returned <= requested and
                returned <= self.expected.artifact_identity['size'] - self.pass_bytes,
                'compressed read exceeds bounded request/file size')
        self.check_buffer(args[1], requested, returned, self.expected.artifact_prefix, self.pass_bytes)
        if returned == 0:
            require(self.pass_bytes == self.expected.artifact_identity['size'], 'compressed EOF precedes complete artifact')
            self.read_pass += 1
            self.pass_bytes = 0
        else:
            self.pass_bytes += returned
            self.input_bytes += returned

    def close(self, args, result):
        number = descriptor(args[0])[0]
        owner = self.live.get(number)
        if owner is not None and owner.kind == 'input-artifact':
            self.owner(args[0], {'input-artifact'})
            require(len(args) == 1 and result == '0' and self.read_pass == self.rewinds == 2 and not self.pass_bytes,
                    'artifact closed before two complete read/EOF passes')
            del self.live[number]
            self.artifact_closed = True
            self.selected_closed = 1
        else:
            super().close(args, result)

    def line(self, line):
        match = re.fullmatch(r'(\d+)\s+(lseek|readlink|readlinkat)\((.*)\)\s+=\s+(.+)\n?', line)
        if match is None:
            return super().line(line)
        require(self.pid == int(match.group(1)) and self.execs == 1 and not self.exit_groups and not self.exits,
                'artifact seek/path operation outside one live process')
        name, args, result = match.group(2), split_arguments(match.group(3)), match.group(4)
        if name == 'lseek':
            require(len(args) == 3 and args[1:] == ['0', 'SEEK_SET'] and result == '0', 'artifact rewind differs')
            self.owner(args[0], {'input-artifact'})
            require(self.artifact_fd_stats == 1 and self.rewinds == self.read_pass and self.read_pass < 2 and not self.pass_bytes,
                    'artifact rewind occurs before EOF or adds another pass')
            self.rewinds += 1
        else:
            self.complete_inputs()
            require(len(args) == (3 if name == 'readlink' else 4) and not self.created_dirs and
                    (string(args[0]) if name == 'readlink' else self.resolved(args[0], string(args[1]))) in self.parent_ancestors and
                    result.startswith('-1 EINVAL '), 'readlink is outside ordinary output parent resolution')

    def finish(self):
        require(self.execs == self.exits == self.exit_groups == 1, 'artifact trace lacks one successful executable/exit')
        self.complete_inputs()
        self.complete_overlap_preflight()
        self.complete_publication()
        if self.expected.require_system_reads:
            require(self.system_closed == TREE.SYSTEM_LIBRARIES | {'/etc/ld.so.cache', '/proc/' + str(self.pid) + '/maps'},
                    'artifact system startup read/close inventory differs')
        require(self.artifact_path_stats == self.artifact_fd_stats == 1 and
                self.input_bytes == 2 * self.expected.artifact_identity['size'] and
                self.output_bytes == sum(row['size'] for row in self.expected.outputs.values()) and
                self.stdout_bytes == len(self.expected.report), 'complete artifact/publication transfer totals differ')
        return {'schema_version': 0, 'program': self.expected.program, 'artifact': self.expected.root,
                'prefix': self.expected.prefix, 'execve_count': 1, 'successful_exit_count': 1,
                'compressed_read_passes': 2, 'compressed_input_bytes': self.input_bytes,
                'published_files': len(self.finished_files), 'published_directories': len(self.finished_dirs),
                'published_bytes': self.output_bytes, 'stdout_bytes': self.stdout_bytes,
                'child_creation_count': 0, 'network_count': 0, 'outside_prefix_mutation_count': 0,
                'initial_output_absence_probe_count': 0,
                'unselected_input_read_count': 0, 'input_output_mapping_count': 0,
                'compressed_regular_size_complete_reads_eof_rewinds_close_verified': True,
                'publication_after_complete_input_read_and_close': True,
                'publication_exclusive_modes_mtimes_closes_verified': True,
                'visible_input_output_prefixes_verified': True, 'trace_string_limit': 512,
                'full_payload_identities_source': 'independent compressed artifact and selected bytes audit; abbreviated trace is not a full byte hash'}


def audit_lines(lines, expected):
    audit = TREE.Audit(expected) if expected.input_kind == 'tree' else ArtifactAudit(expected)
    for number, line in enumerate(lines, 1):
        try:
            audit.line(line)
        except ValueError as error:
            raise ValueError(f'line {number}: {error}') from error
    return audit.finish()


def audit_trace(path, expected):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        result = audit_lines(stream, expected)
    return result | {'trace_identity': prepare.identity(path.read_bytes()),
                     'report_identity': prepare.identity(expected.report)}


def hostile_controls(lines, expected):
    if expected.input_kind == 'tree':
        # Only the fixture command token in the historical mutation generator
        # changes. Every private parser/ownership/publication predicate remains.
        source = inspect.getsource(TREE.hostile_controls)
        needle = "modified('wrong-provider', 0, '\"host-install\"', '\"host-full\"')"
        require(source.count(needle) == 1, 'historical mutation provider needle differs')
        source = source.replace(needle, "modified('wrong-provider', 0, '\"host-install-stripped\"', '\"host-full\"')")
        namespace = dict(TREE.__dict__) | {'audit_lines': audit_lines}
        exec(compile(source, str(HERE / 'historical-private-mutations.py'), 'exec'), namespace)
        return namespace['hostile_controls'](lines, expected)
    audit_lines(lines, expected)
    pid = re.match(r'\d+', lines[0]).group(0)
    cases = {}
    def first(needle):
        return next(index for index, line in enumerate(lines) if needle in line)
    def removed(label, index):
        cases[label] = lines[:index] + lines[index + 1:]
    def replaced(label, index, old, new):
        require(old in lines[index], 'artifact hostile needle differs: ' + label)
        changed = lines[:]
        changed[index] = changed[index].replace(old, new, 1)
        cases[label] = changed
    opening = next(index for index, line in enumerate(lines) if ' openat(' in line and
                   '"' + expected.root + '"' in line)
    reads = [index for index, line in enumerate(lines) if ' read(' in line and '<' + expected.root + '>' in line]
    seeks = [index for index, line in enumerate(lines) if ' lseek(' in line]
    eof = [index for index in reads if ', "", ' in lines[index]]
    output_write = next(index for index, line in enumerate(lines) if ' write(' in line and '<' + expected.prefix + '/' in line)
    removed('missing-initial-rewind', seeks[0])
    removed('missing-second-rewind', seeks[1])
    removed('missing-first-eof', eof[0])
    removed('missing-second-eof', eof[1])
    removed('missing-compressed-read', reads[0])
    replaced('wrong-provider', 0, '"host-install-stripped"', '"host-install"')
    replaced('wrong-input-option', 0, '"--pbs-install-only"', '"--runtime-tree"')
    replaced('artifact-write-capable', opening, 'O_RDONLY|O_CLOEXEC', 'O_RDWR|O_CLOEXEC')
    replaced('wrong-artifact-owner', opening, '<' + expected.root + '>', '</foreign>')
    replaced('artifact-written', reads[0], ' read(', ' write(')
    replaced('rewind-middle', seeks[1], ', 0, SEEK_SET', ', 1, SEEK_SET')
    replaced('wrong-stdout-byte', first(' write(1<'), '"', '"X')
    replaced('publication-output-read', output_write, ' write(', ' read(')
    for label, syscall in {
        'child': 'clone(NULL, 0, NULL, NULL, NULL) = 43',
        'network': 'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 9',
        'foreign-input': 'openat(AT_FDCWD</workspace>, "/foreign", O_RDONLY|O_CLOEXEC) = 9</foreign>',
        'artifact-map': 'mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, ' + lines[opening].split(' = ')[-1].strip() + ', 0) = 0x123000',
        'anonymous-exec': 'mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x123000',
        'exec-protection': 'mprotect(0x123000, 4096, PROT_READ|PROT_EXEC) = 0',
        'descriptor-alias': 'dup(3<' + expected.root + '>) = 9<' + expected.root + '>',
        'foreign-mutation': 'unlink("/foreign") = 0',
    }.items():
        cases[label] = lines[:opening + 1] + [pid + '  ' + syscall + '\n'] + lines[opening + 1:]
    outcomes = {}
    for label, changed in cases.items():
        try:
            audit_lines(changed, expected)
        except ValueError as error:
            outcomes[label] = {'rejected': True, 'reason': str(error)}
        else:
            raise ValueError('artifact hostile trace accepted: ' + label)
    return {'schema_version': 0, 'hostile_controls': len(outcomes), 'rejected_controls': len(outcomes),
            'all_controls_rejected': True, 'controls': outcomes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('trace', 'program', 'prefix', 'report'):
        parser.add_argument('--' + name, required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--artifact')
    inputs.add_argument('--runtime-tree')
    parser.add_argument('--input-audit', type=Path)
    parser.add_argument('--artifact-file', type=Path,
                        help='locally cached authenticated artifact when replaying a trace with another mount path')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--hostile-controls', action='store_true')
    args = parser.parse_args()
    try:
        expected = contract(args.program, args.prefix, Path(args.report).read_bytes(), root=args.runtime_tree,
                            input_audit=prepare.strict_json(args.input_audit.read_bytes()) if args.input_audit else None,
                            artifact=args.artifact, artifact_file=args.artifact_file)
        result = audit_trace(Path(args.trace), expected)
        if args.hostile_controls:
            opener = gzip.open if args.trace.endswith('.gz') else open
            with opener(args.trace, 'rt', encoding='utf-8') as stream:
                result = hostile_controls(stream.readlines(), expected) | {
                    'trace_identity': result['trace_identity'], 'report_identity': result['report_identity']}
        if args.output:
            prepare.write_json(args.output, result)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('stripped preparation process audit: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
