import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('syscall_contract',Path(__file__).with_name('syscall_contract.py'))
C=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(C)


class ContractTests(unittest.TestCase):
 def test_pure_bounded_parser_matches_file_loader_without_io(self):
  raw=(C.SOURCE/'contracts.json').read_bytes()
  expected=C.load_table()
  with patch.object(C,'bounded_read',side_effect=AssertionError('pure parser opened a file')):
   actual=C.parse_table(raw)
   self.assertEqual(actual,expected)
   self.assertEqual(C.entry_facts('mmap',[1,2,3,4,5,6,7,8],actual)['fields']['fd'],5)
  for bad in (bytearray(raw),raw.decode(),None,b'x'*(C.MAX_TABLE+1),b'{"x":1,"x":2}'):
   with self.assertRaises(C.UnsupportedContract):C.parse_table(bad)
  # Input parsing remains generic; asset pinning belongs to the owned adapter.
  alternate=json.loads(raw);alternate['calls'][0]['number']=381
  self.assertEqual(C.parse_table(json.dumps(alternate).encode())[1][alternate['calls'][0]['name']]['number'],381)
 def test_direct_and_guarded_open_positions_differ(self):
  direct=C.entry_facts('open',[101,2,0o644,999,0,0,0,0])
  guarded=C.entry_facts('guarded_open_np',[101,202,303,2,0o644,0,0,0])
  self.assertEqual(direct['fields'],{'path':101,'flags':2,'mode':0o644})
  self.assertEqual(guarded['fields'],{'path':101,'guard':202,'guardflags':303,'flags':2,'mode':0o644})
  self.assertFalse(direct['full_trace_acceptance'])
 def test_at_and_protected_open_roles(self):
  result=C.entry_facts('openat_dprotected_np',[C.U64-1,101,2,3,4,0o644,77,0])
  self.assertEqual(result['fields'],{'dirfd':C.U64-1,'path':101,'flags':2,'class':3,'dpflags':4,'mode':0o644,'authfd':77})
  self.assertIn('dirfd-object-if-relative',result['requirements'])
 def test_symlink_target_is_literal_not_destination(self):
  a=C.entry_facts('symlink',[11,22,0,0,0,0,0,0])
  b=C.entry_facts('symlinkat',[11,44,22,0,0,0,0,0])
  self.assertEqual(a['fields'],{'literal_target':11,'new_path':22})
  self.assertEqual(b['fields'],{'literal_target':11,'dirfd':44,'new_path':22})
 def test_two_directory_bases_and_clone_source_fd(self):
  a=C.entry_facts('renameatx_np',[11,22,33,44,55,0,0,0])
  self.assertEqual(a['fields'],{'source_dirfd':11,'source_path':22,'destination_dirfd':33,'destination_path':44,'flags':55})
  b=C.entry_facts('fclonefileat',[11,33,44,55,0,0,0,0])
  self.assertEqual(b['fields'],{'source_fd':11,'destination_dirfd':33,'destination_path':44,'flags':55})
 def test_bsd_sendfile_is_input_fd_then_output_socket(self):
  result=C.entry_facts('sendfile',[11,22,33,44,55,66,0,0])
  self.assertEqual(result['fields']['source_fd'],11)
  self.assertEqual(result['fields']['destination_fd'],22)
 def test_nested_spawn_aio_and_ioctl_not_plain_paths(self):
  spawn=C.entry_facts('posix_spawn',[1,2,3,4,5,0,0,0])
  self.assertEqual(spawn['fields']['executable_path'],2)
  self.assertEqual(spawn['fields']['spawn_descriptor'],3)
  self.assertIn('ordered-file-and-port-actions',spawn['requirements'])
  aio=C.entry_facts('aio_write',[123,0,0,0,0,0,0,0])
  self.assertEqual(aio['fields'],{'aiocb':123})
  self.assertIn('reject-unmodeled-async',aio['requirements'])
  self.assertIn('reject-unmodeled-command',C.entry_facts('ioctl',[1,2,3,0,0,0,0,0])['requirements'])
 def test_mmap_field_order_and_rights_requirements(self):
  mmap=C.entry_facts('mmap',[11,22,33,44,55,66,0,0])
  self.assertEqual(mmap['fields'],{'address':11,'length':22,'protection':33,'flags':44,'fd':55,'offset':66})
  self.assertIn('shared-write-capability',mmap['requirements'])
  self.assertIn('Mach-VM-alias-accounting',mmap['requirements'])
 def test_failed_return_cannot_erase_entry_attempt(self):
  entry=C.entry_facts('write',[9,10,11,0,0,0,0,0])
  returned=C.return_facts([C.U64,C.U64,C.U64,13,13])
  self.assertTrue(entry['entry_attempt_observed'])
  self.assertEqual(entry['family'],'fd-mutation')
  self.assertEqual(returned['kernel_error_bits'],13)
  self.assertFalse(returned['full_trace_acceptance'])
 def test_return_duplication_errno_and_restart_are_explicit(self):
  self.assertEqual(C.return_facts([3,3,0,0,0])['primary_result_bits'],3)
  for value in ([3,4,0,0,0],[C.U64,C.U64,C.U64,2,13]):
   with self.assertRaises(C.UnsupportedContract):C.return_facts(value)
  self.assertTrue(C.return_facts([C.U64,C.U64,C.U64,C.U64,C.U64])['control_flow_unmodeled'])
 def test_no_default_allow_for_unknown_linux_or_new_sdk_route(self):
  for name in ('io_uring_setup','aio_readv','aio_writev','sys_open','unknown'):
   with self.assertRaises(C.UnsupportedContract):C.entry_facts(name,[0]*8)
  with self.assertRaises(C.UnsupportedContract):C.require_full_trace_acceptance()
 def test_malformed_word_vectors_rejected(self):
  for value in ([0]*7,[0]*9,[True]+[0]*7,[-1]+[0]*7,[1<<64]+[0]*7,[1.0]+[0]*7):
   with self.assertRaises(C.UnsupportedContract):C.entry_facts('open',value)
 def test_unknown_provider_and_syscall_make_observation_incomplete(self):
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary)/'timeline.jsonl'
   rows=[{'consumer_index':1,'raw':{'provider':'syscall','function':'io_uring_setup','name':'entry','kind':2},'raw_uint64_after_header':[0]*8},
         {'consumer_index':2,'raw':{'provider':'mach_trap','function':'mach_msg2_trap','name':'entry','kind':15},'raw_uint64_after_header':[0]*8}]
   path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
   result=C.inspect_timeline(path)
   self.assertEqual(result['status'],'incomplete')
   self.assertEqual(result['unsupported_calls'],{'io_uring_setup':1})
   self.assertEqual(result['other_provider_events'],{'mach_trap':1})
   self.assertFalse(result['native_coverage_attestation'])
 def test_open_path_bytes_remain_separate_uninterpreted_evidence(self):
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary)/'timeline.jsonl'
   row={'consumer_index':1,'raw':{'provider':'syscall','function':'open','name':'entry','kind':14},'raw_uint64_after_header':[]}
   path.write_text(json.dumps(row)+'\n')
   result=C.inspect_timeline(path)
   self.assertEqual(result['uninterpreted_auxiliary_bsd_events'],{'open-path':1})
   self.assertEqual(result['entries'],0)
   self.assertEqual(result['status'],'incomplete')
 def test_duplicate_json_and_truncated_timeline_fail(self):
  with self.assertRaises(C.UnsupportedContract):C.parse_json(b'{"x":1,"x":2}')
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary)/'timeline.jsonl';path.write_bytes(b'{}')
   with self.assertRaises(C.UnsupportedContract):C.inspect_timeline(path)
 def test_malformed_unknown_entry_and_bsd_phase_rejected(self):
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary)/'timeline.jsonl'
   for event,value in (({'provider':'syscall','function':'unknown','name':'entry','kind':2},[0]*7),
                       ({'provider':'syscall','function':'open','name':'return','kind':2},[0]*8),
                       ({'provider':'syscall','function':'open','name':'entry','kind':True},[0]*8)):
    path.write_text(json.dumps({'consumer_index':1,'raw':event,'raw_uint64_after_header':value})+'\n')
    with self.assertRaises(C.UnsupportedContract):C.inspect_timeline(path)
 def test_table_revision_and_source_positions_require_exact_types(self):
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary)/'contracts.json'
   for field,value in (('revision',True),('number',True),('source_line',True)):
    table=json.loads((C.SOURCE/'contracts.json').read_text())
    if field=='revision':table[field]=value
    else:table['calls'][0][field]=value
    path.write_text(json.dumps(table))
    with self.assertRaises(C.UnsupportedContract):C.load_table(path)
 def test_symlink_and_oversized_sources_rejected(self):
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary)/'file';path.write_bytes(b'abc')
   alias=Path(temporary)/'alias';alias.symlink_to(path)
   with self.assertRaises(OSError):C.bounded_read(alias,10)
   with self.assertRaises(C.UnsupportedContract):C.bounded_read(path,2)
 def test_all_entries_bounded_and_source_tagged(self):
  table,calls,identity=C.load_table()
  self.assertEqual(len(calls),161)
  self.assertEqual(table['sdk']['canonical_name'],'macosx27.0')
  self.assertEqual(table['sdk_only_reject'],['aio_readv','aio_writev'])
  self.assertIn('not proven lifecycle target',table['lifecycle_constraint'])
  self.assertIn('partial io.d fi_pathname',table['fd_constraint'])
  self.assertEqual(len(identity),64)


if __name__=='__main__':unittest.main()
