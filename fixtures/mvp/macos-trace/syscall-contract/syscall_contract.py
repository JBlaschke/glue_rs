#!/usr/bin/env python3
"""Pinned Darwin BSD argument contracts; never an extraction acceptance oracle."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SOURCE=Path(__file__).resolve().parent
MAX_TABLE=256*1024
MAX_BYTES=128*1024*1024
MAX_LINE=64*1024
MAX_EVENTS=500000
U64=(1<<64)-1


class UnsupportedContract(ValueError):
    pass


def require(condition,message):
    if not condition:
        raise UnsupportedContract(message)


def parse_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'duplicate JSON key')
            result[key]=value
        return result
    try:
        return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(UnsupportedContract('nonfinite JSON')))
    except (ValueError,UnicodeError,RecursionError) as error:
        raise UnsupportedContract('invalid contract JSON: '+str(error)) from error


def bounded_read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        facts=os.fstat(stream.fileno())
        require(stat.S_ISREG(facts.st_mode) and facts.st_nlink==1 and facts.st_size<=limit,'bounded ordinary file required')
        raw=stream.read(limit+1)
        require(len(raw)<=limit,'input exceeds bound')
        after=os.fstat(stream.fileno())
        require((facts.st_dev,facts.st_ino,facts.st_size,facts.st_mtime_ns,facts.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'input changed while reading')
        return raw


def load_table(path=SOURCE/'contracts.json'):
    raw=bounded_read(path,MAX_TABLE)
    return parse_table(raw)


def parse_table(raw):
    """Parse bounded immutable contract bytes without opening any file.

    The caller owns asset identity/admission. This helper preserves load_table's
    table semantics; it does not assert that arbitrary valid bytes are pinned.
    """
    require(type(raw) is bytes and len(raw)<=MAX_TABLE,'bounded immutable contract bytes required')
    table=parse_json(raw)
    require(type(table) is dict and type(table.get('revision')) is int and table['revision']==1 and table.get('protocol')=='darwin-bsd-syscall-contract-v1','unsupported table')
    require(table.get('full_trace_acceptance') is False,'table cannot grant acceptance')
    calls=table.get('calls')
    require(type(calls) is list and 0<len(calls)<=256,'call-table bound')
    by_name={}
    for call in calls:
        require(type(call) is dict and type(call.get('name')) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,126}',call['name']),'invalid call name')
        require(call['name'] not in by_name,'duplicate call name')
        require(type(call.get('number')) is int and 0<=call['number']<1024 and type(call.get('source_line')) is int and call['source_line']>0,'invalid source position')
        require(type(call.get('return_type')) is str and len(call['return_type'])<=63,'invalid return type')
        require(type(call.get('family')) is str and len(call['family'])<=63,'invalid family')
        require(type(call.get('requirements')) is list and 0<len(call['requirements'])<=32 and all(type(item) is str and 0<len(item)<=127 for item in call['requirements']),'invalid requirements')
        require(type(call.get('arguments')) is list and len(call['arguments'])<=8 and all(type(item) is str and 0<len(item)<=255 for item in call['arguments']),'argument count exceeds captured register words')
        require(type(call.get('selectors')) is dict and all(type(role) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,126}',role) and type(i) is int and 0<=i<len(call['arguments']) for role,i in call['selectors'].items()),'invalid argument selector')
        require(call.get('attempt_phase')=='entry' and call.get('native_adapter_status')=='requires-calibration-and-state','unsupported contract policy')
        by_name[call['name']]=call
    return table,by_name,hashlib.sha256(raw).hexdigest()


def words(value,count):
    require(type(value) is list and len(value)==count and all(type(x) is int and 0<=x<=U64 for x in value),'canonical uint64 word vector required')
    return value


def entry_facts(name,raw_words,table=None):
    """Select source-declared raw argument words; never dereference or normalize pointers.

    The caller must first validate the source-matched raw transport. Returned
    requirements are unresolved proof obligations, not an allowlist or FD model.
    Entry-side intent remains present even when a subsequent syscall fails.
    """
    _,calls,identity=load_table() if table is None else table
    require(type(name) is str and name in calls,'unsupported syscall: '+str(name))
    raw_words=words(raw_words,8)
    call=calls[name]
    return {'protocol':'darwin-bsd-entry-facts-v1','name':name,'number':call['number'],'family':call['family'],
            'fields':{role:raw_words[index] for role,index in call['selectors'].items()},
            'raw_words':list(raw_words),'source_argument_count':len(call['arguments']),
            'entry_attempt_observed':True,'requirements':list(call['requirements']),
            'contract_sha256':identity,'full_trace_acceptance':False,
            'scope':'Argument selection only; no C-string, signed-width, pathname/FD/object, output-policy or raw native ABI verdict.'}


def return_facts(raw_words):
    """Check source-declared duplication/errno fields without fabricating libc results."""
    value=words(raw_words,5)
    require(value[0]==value[1],'provider primary return duplication differs')
    require(value[3]==value[4],'provider kernel error and builtin errno differ')
    return {'protocol':'darwin-bsd-return-facts-v1','primary_result_bits':value[0],
            'secondary_result_bits':value[2],'kernel_error_bits':value[3],
            'control_flow_unmodeled':value[3]>(1<<31)-1,
            'full_trace_acceptance':False,'scope':'Raw source fields only; no return type normalization, successful-effect ordering or completed-call pairing.'}


def validate_source(master,table=None):
    table=load_table() if table is None else table
    raw=bounded_read(master,128*1024)
    require(hashlib.sha256(raw).hexdigest()==table[0]['sources']['syscalls.master']['sha256'],'pinned source identity differs')
    lines=raw.decode().splitlines()
    for call in table[1].values():
        line=lines[call['source_line']-1]
        match=re.search(r'^\s*(\d+)\s+\S+\s+\S+\s+\{\s*(.*?)\s+(\w+)\((.*?)\)',line)
        require(match is not None,'source declaration absent')
        arguments=[] if match[4]=='void' else [a.strip() for a in match[4].split(',')]
        require(int(match[1])==call['number'] and match[3].removeprefix('sys_')==call['name'] and match[2]==call['return_type'] and arguments==call['arguments'],'source declaration differs: '+call['name'])
    return len(table[1])


def inspect_timeline(path):
    table=load_table()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    known=Counter(); unknown=Counter(); families=Counter(); other=Counter(); auxiliary=Counter()
    entries=returns=control_flow=0
    digest=hashlib.sha256()
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=MAX_BYTES,'bounded ordinary timeline required')
        size=0
        for index,line in enumerate(iter(lambda:stream.readline(MAX_LINE+1),b''),1):
            size+=len(line);digest.update(line)
            require(index<=MAX_EVENTS and size<=MAX_BYTES and len(line)<=MAX_LINE and line.endswith(b'\n'),'timeline bounds/truncated line')
            row=parse_json(line)
            require(type(row) is dict and type(row.get('consumer_index')) is int and row['consumer_index']==index,'timeline index gap')
            event=row.get('raw')
            require(type(event) is dict,'timeline raw event required')
            if event.get('provider')!='syscall':
                provider=event.get('provider')
                require(type(provider) is str and len(provider)<=63,'invalid provider')
                other[provider]+=1
                continue
            name=event.get('function')
            require(type(name) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,126}',name),'invalid function name')
            require(type(event.get('kind')) is int,'invalid BSD event kind')
            if event['kind']==2 and event.get('name')=='entry':
                value=words(row.get('raw_uint64_after_header'),8)
                entries+=1
                if name not in table[1]:unknown[name]+=1;continue
                facts=entry_facts(name,value,table)
                known[name]+=1;families[facts['family']]+=1
            elif event['kind']==3 and event.get('name')=='return':
                facts=return_facts(row.get('raw_uint64_after_header'))
                returns+=1;control_flow+=facts['control_flow_unmodeled']
            elif event['kind']==14 and name=='open' and event.get('name')=='entry':
                words(row.get('raw_uint64_after_header'),0)
                auxiliary['open-path']+=1
            else:
                raise UnsupportedContract('unsupported BSD event phase')
        after=os.fstat(stream.fileno())
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'timeline changed while reading')
    return {'protocol':'darwin-bsd-coverage-observation-v1','status':'incomplete' if unknown or control_flow or auxiliary or any(p!='dtrace' for p in other) else 'inspected',
            'timeline_sha256':digest.hexdigest(),'contract_sha256':table[2],'entries':entries,'returns':returns,
            'known_calls':dict(sorted(known.items())),'unsupported_calls':dict(sorted(unknown.items())),
            'families':dict(sorted(families.items())),'unmodeled_control_flow_returns':control_flow,
            'other_provider_events':dict(sorted(other.items())),'uninterpreted_auxiliary_bsd_events':dict(sorted(auxiliary.items())),'lifecycle_and_mach_unmodeled':bool(other.keys()-{'dtrace'}),
            'native_coverage_attestation':False,
            'full_trace_acceptance':False,'scope':'Read-only lookup over a separately validated reader export. No transport attestation, path/FD model, call pairing, mutation verdict or complete Darwin oracle.'}


def require_full_trace_acceptance():
    raise UnsupportedContract('Source contracts cannot establish complete Darwin R02 acceptance')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeline',type=Path)
    parser.add_argument('--source',type=Path,help='optional exact pinned syscalls.master identity/declaration audit')
    parser.add_argument('--acceptance',action='store_true')
    args=parser.parse_args()
    try:
        if args.acceptance:require_full_trace_acceptance()
        if args.source:
            print(json.dumps({'source_declarations_checked':validate_source(args.source),'full_trace_acceptance':False}))
        if args.timeline:
            result=inspect_timeline(args.timeline);print(json.dumps(result,sort_keys=True))
            return 0 if result['status']=='inspected' else 1
        require(args.source is not None,'--source or --timeline is required')
        return 0
    except (UnsupportedContract,OSError,ValueError,TypeError,KeyError,IndexError) as error:
        print('Darwin syscall contract: '+str(error),file=sys.stderr);return 1


if __name__=='__main__':
    sys.exit(main())
