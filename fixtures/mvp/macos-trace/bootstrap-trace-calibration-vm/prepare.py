#!/usr/bin/env python3
"""Prepare only the fixed positive/denied calibration; reviewed kit only."""
import argparse
from dataclasses import dataclass
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets
import shlex
import sys

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / 'bootstrap-trace-vm/prepare.py'
SHARED_SHA = '3549edd7c6418ea9f40c9c791c919573dcf9ae6ea9d9eb609a849787de4e1719'
# Only the successful 20261018-02 kit and closed independent reviews are admitted.
APPROVED = {'kit_manifest_sha256': '825d99567feb42bce9915e46e590436291ebffaa2dd1b28ed5c2bb9db124ffde',
 'kit_review_manifest_sha256': '0162fb433e3490b53a4cf13fd26591abb5107118732f29261aa3d0d759428273',
 'catalog_review_manifest_sha256': '8a120aa2be0dcc52b72a36261aa5b25c5deca0d86d8411561b84cfce0c3b196a',
 'builder_receipt_manifest_sha256': '34640346684b2e7332f6ee7dbde715b8b366c88940d3f35b698fa0d5e0eba73d',
 'build_id': '69de4c44aa5d083c2cba64b1ee83b1978577ee61f46221ca64f620d3413d155f',
 'catalog_sha256': '65f3b9ed3d72f7ce79fdf314be0a40ba249bcb4d4d1c1263d281c328c3e47904',
 'recipe_sha256': '3a55ff7ff82f5673d68b92ef9fc4230eaf656f8a31208daed8e687c15d839689',
 'source_lock_sha256': 'f2943d170c27c3ee5eb3c8b151efc2986d840c92c867505f7aa6b669f167d5af',
 'source_revision': 'e2c728bcdb25ceb151f8f434859c668faf0abcd0',
 'observation_sha256': '73bf83eb26f49a3f98092beeaee1665afc65b6997721d2aac20d9d5fb9ac7d1c',
 'proof_entry': {'binary_sha256': 'c78b9ddab7bb9feb15d8575847018b88d3dc6c8c520037867fa7ed82b2b2b77a',
                 'guest_output_name': 'glue-bootstrap-deployment-v1-Ap5KkPYA',
                 'inspector_manifest_sha256': 'd5f5519e2f59eff40114297e6c4bdef952f40968352bfe2154e1e4efd96e6505',
                 'inspector_source_commit': 'd2bd45d',
                 'kernel_release': '25.6.0',
                 'manifest_sha256': 'cd57a36af2a9db11f7d24105485137f7afb2ad9743161db190d7ed6c7ca361fd',
                 'os_build': '25G83',
                 'os_version': '26.6.2',
                 'review_manifest_sha256': '2b3c60fc811ed292cd3e33a33851ba751a1de8c3667c5c2df8f4062000d80dfb',
                 'wrapper_sha256': 'e58ba58269ce9bc39dbffcca0112325d6aaa6cb49550a5dddbc8b6329556e500'},
 'artifacts': {'context-probe': {'sha256': '5aed421f11750b0d49c83300f2b8e818309b1fc886e8c535ab9e31f3b40b38e5',
                                 'size': 52912},
               'make-request': {'sha256': '236e78b2f38a79b5711e5d152526b9cfaf3d8735b8ecb0a8287bce81dd376818',
                                'size': 72240},
               'owned-trace-runner': {'sha256': 'ddd14bbe29b38e0f02427dad92fa16c74c63fc2bc04eda1980681475a6b9c1bc',
                                      'size': 164528}}}
EXECUTION_ENABLED = True

@dataclass(frozen=True, slots=True)
class _Admission:
    approved_json: bytes | None
    metadata: tuple
    execution: bool

# Immutable internal policies; no CLI or ambient-environment policy selector.
POLICY = _Admission(json.dumps(APPROVED,sort_keys=True,separators=(',',':')).encode(),
    (
        ('catalog.bin', '65f3b9ed3d72f7ce79fdf314be0a40ba249bcb4d4d1c1263d281c328c3e47904', 269),
        ('recipe.json', '3a55ff7ff82f5673d68b92ef9fc4230eaf656f8a31208daed8e687c15d839689', 2882),
        ('source-lock.json', 'f2943d170c27c3ee5eb3c8b151efc2986d840c92c867505f7aa6b669f167d5af', 7740),
        ('admitted-proof.json', '827a9ebf0fc885a17e88ded781323faa0643c8bef7d96439316a31c4dcdd98fc', 2461),
        ('build-result.json', '1b7e5ec56461bba6b4b4f3fb119cfe670675601eaaeb70bc52f670e4b40bcef1', 1286),
        ('build-SHA256SUMS', '825d99567feb42bce9915e46e590436291ebffaa2dd1b28ed5c2bb9db124ffde', 15919),
    ), EXECUTION_ENABLED)
UNCONFIGURED = _Admission(None, (), False)

def approval(policy):
    return None if policy.approved_json is None else json.loads(policy.approved_json)
PROGRAMS = ('context-probe', 'owned-trace-runner', 'make-request')
CASES = ('positive', 'denied')
EVENT_CAP = 128 * 1024 * 1024
EXPORT_CAP = 135 * 1024 * 1024
INSPECTOR_PATH = '/Volumes/My Shared Files/glue-mvp-macos-vm-toolkit/bootstrap-inspector-v1-20261016/inspect-deployment'
INSPECTOR_SHA = 'c78b9ddab7bb9feb15d8575847018b88d3dc6c8c520037867fa7ed82b2b2b77a'
METADATA = {'catalog.bin':'catalog.bin','recipe.json':'recipe.json','source-lock.json':'source-lock.json',
    'admitted-proof.json':'admitted-proof.json','build-result.json':'result.json','build-SHA256SUMS':'SHA256SUMS'}
CONTROL_ROLES = ('input.sha256','native.argv','native.stdout','native.stderr','native.status')
BASE_ROLES = ('request.bin','status.bin','probe.stdout','probe.stderr','result.json','trace.json')
TRACE_ROLES = ('program.d','probes.tsv','events.jsonl','errors.jsonl')

def sha(data): return hashlib.sha256(data).hexdigest()
def require(value,message):
    if not value: raise ValueError(message)
def enabled(*, _policy=POLICY):
    require(_policy.approved_json is not None and _policy.execution is True, 'calibration kit/execution is not configured')
def shared():
    require(sha(SHARED.read_bytes()) == SHARED_SHA, 'reviewed shared preparer source differs')
    spec=importlib.util.spec_from_file_location('glue_calibration_shared',SHARED)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
def primitives(): return shared().primitives()
GATES_SHA = '5384644c9d20bb6792fdf6c97e218758ba9f5d44af328bcb01cf36a1b87f5910'
def gates():
    require(sha((HERE.parent/'bootstrap-trace-vm/gates.py').read_bytes())==GATES_SHA,'reviewed metadata gates differ')
    return shared().gates()
def substitute(template,values): return shared().substitute(template,values)
def guard(command): return shared().guard(command)
def load_kit(path, *, _policy=POLICY):
    enabled(_policy=_policy)
    base=shared(); contract=base.HERE/'kit_contract.py'
    require(sha(contract.read_bytes()) == base.KIT_CONTRACT_SHA, 'reviewed kit contract source differs')
    spec=importlib.util.spec_from_file_location('glue_calibration_kit_contract',contract)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    value = module.load_approved_kit(path,approval(_policy),primitives)
    data,manifest,unused_result,unused_observed,unused_entry = value
    _verify_metadata(data,manifest,_policy=_policy)
    return value

def _verify_metadata(data,manifest, *, _policy=POLICY):
    selected_members(_policy=_policy)  # exact six-member source policy
    for name,digest,size in _policy.metadata:
        raw = manifest if METADATA[name]=='SHA256SUMS' else data[METADATA[name]]
        require(len(raw)==size and sha(raw)==digest,'approved kit metadata differs')
def case_roles(case):
    require(case in CASES, 'case selector')
    return CONTROL_ROLES+BASE_ROLES+(() if case=='denied' else TRACE_ROLES)
def role_cap(role): return shared().role_cap(role)
def evidence_limits():
    names={'plan.json':262144,'batch.tsv':4096}
    for phase in ('install','install-context'):
        for suffix,cap in [('argv',32768),('stdout',8192),('stderr',8192),('status',4)]:
            names[phase+'.'+suffix]=cap
    del names['install-context.stdout']; names['install-context.bin']=64
    for case in CASES:
        for suffix,cap in [('argv',32768),('stdout',8192),('stderr',8192),('status',4)]: names['case-'+case+'.'+suffix]=cap
        for suffix,cap in [('argv',8192),('bin',16384),('stderr',4096),('status',4)]: names['requests/'+case+'.'+suffix]=cap
        for role in case_roles(case):
            names['cases/'+case+'/'+role]=role_cap(role)
            for suffix,cap in [('argv',32768),('stderr',8192),('status',4)]: names['exports/'+case+'/'+role+'.'+suffix]=cap
    return dict(sorted(names.items()))
def plan_from_identity(build_id,catalog_sha,artifacts,observed,entry,nonce, *, _policy=POLICY):
    p,unused=primitives(); p.sha(build_id); p.sha(catalog_sha)
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}',nonce),'batch nonce')
    p.exact_keys(artifacts,PROGRAMS)
    for a in artifacts.values(): p.exact_keys(a,('sha256','size')); p.sha(a['sha256']); p.integer(a['size'],1,4194304)
    approved=approval(_policy)
    if _policy.execution:
        enabled(_policy=_policy)
        require(build_id==approved['build_id'] and catalog_sha==approved['catalog_sha256'] and artifacts==approved['artifacts'], 'unapproved plan kit identity')
        require(entry==approved['proof_entry'] and sha(p.canonical(observed))==approved['observation_sha256'],'unapproved plan proof/observation')
    else:
        require(approved is None,'unconfigured policy has approval')
    guest_os=shared().profile(entry,observed,p); tmp='/System/Volumes/Data/private/tmp/'
    paths={'guest_packet':'/Volumes/My Shared Files/glue-mvp-macos-vm-toolkit/bootstrap-trace-calibration-'+nonce,
        'guest_work':tmp+'glue-btc-user-'+nonce,'root_stage':tmp+'glue-btc-stage-'+nonce,
        'guest_export':'/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-bootstrap-trace-calibration-'+nonce,
        'guest_run_receipt':tmp+'glue-btc-launch-'+nonce,
        'guest_receipt_export':'/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-bootstrap-trace-calibration-receipt-'+nonce,
        'build_dir':'/System/Volumes/Data/Library/GlueMVPFixtures/'+build_id}
    limits=evidence_limits()
    return p.strict_json(p.canonical(dict(schema='glue-bootstrap-trace-calibration-plan-v1',
        profile='fixed-owned-context-bsd-mach-v1',approval=approved,execution_enabled=_policy.execution,
        nonce=nonce,build_id=build_id,catalog_sha256=catalog_sha,artifacts=artifacts,observation=observed,
        proof_entry=entry,guest_os=guest_os,paths=paths,outputs={c:tmp+'glue-btc-'+nonce+'-'+c for c in CASES},
        budgets={'attempt_ms':10000,'cleanup_ms':2000},evidence_limits=limits,evidence_total_limit=EXPORT_CAP,
        event_line_limit=8192,event_count_limit=1000000,evidence_files=sorted(limits),full_acceptance=False)))
def make_plan(result,observed,entry,nonce, *, _policy=POLICY):
    p,unused=primitives()
    require(result['schema']=='glue-owned-trace-kit-result-v1' and result['status']=='built-reproducibly','tracing result schema/status')
    require(all(result[k] is False for k in ('new_binaries_executed','installed','kernel_exec_proof','full_acceptance')),'kit scope')
    p.exact_keys(result['artifacts'],PROGRAMS)
    return plan_from_identity(result['build_id'],result['catalog_sha256'],{n:{k:result['artifacts'][n][k] for k in ('sha256','size')} for n in PROGRAMS},observed,entry,nonce,_policy=_policy)

READ_MATCH = 'read_match() {\n    rm_expected=$1; shift\n    rm_actual=$("$@") || return 2\n    [ "$rm_actual" = "$rm_expected" ]\n}'
LAST_BYTE_ZERO = 'last_byte_zero() {\n    lb_value=$("$3" -An -tu1 -j "$2" -N 1 "$1") || return 2\n    set -f\n    set -- $lb_value\n    [ "$#" = 1 ] && [ "$1" = 0 ]\n}'


def render_details(plan, *, _policy=POLICY):
    p, unused = primitives()
    base = shared()
    expected = plan_from_identity(plan['build_id'],plan['catalog_sha256'],plan['artifacts'],
        plan['observation'],plan['proof_entry'],plan['nonce'],_policy=_policy)
    require(p.canonical(plan) == p.canonical(expected),'unreviewed plan/path/limits')
    require((_policy.execution is True and _policy.approved_json is not None) or (_policy.approved_json is None and _policy.execution is False and not _policy.metadata), 'renderer policy')
    values = {k.upper():shlex.quote(v) for k,v in plan['paths'].items()}
    values.update(ENABLED='1' if _policy.execution else '0',UID=str(plan['observation']['ids'][0]),
        INSPECTOR_PATH=shlex.quote(INSPECTOR_PATH),INSPECTOR_SHA=INSPECTOR_SHA,
        KIT_SHA=shlex.quote(approval(_policy)['kit_manifest_sha256'] if _policy.execution else 'UNAPPROVED-CALIBRATION'),CATALOG_SHA=plan['catalog_sha256'],
        GUEST_MODEL=shlex.quote(plan['guest_os']['model']),GUEST_VERSION=shlex.quote(plan['guest_os']['version']),
        GUEST_BUILD=shlex.quote(plan['guest_os']['build']),GUEST_KERNEL=shlex.quote('Darwin ' + plan['guest_os']['kernel'] + ' arm64'),
        METADATA_GATES=gates().shell_checks(),READ_MATCH=READ_MATCH,LAST_BYTE_ZERO=LAST_BYTE_ZERO)
    for case in CASES: values['OUT_' + case.upper()] = shlex.quote(plan['outputs'][case])
    checks = []
    def current(key,kind,value):
        checks.append('current_json_matches ' + shlex.quote(key) + ' ' + kind + ' ' + shlex.quote(str(value)) + ' || return 2')
    for key,value in {'schema':'glue-bootstrap-deployment-observation-v1','model':plan['guest_os']['model'],'kernel_release':plan['guest_os']['kernel']}.items(): current(key,'string',value)
    for key,value in {'tc_compatible':'true','settings_changed':'false','executable_admission':'false','full_acceptance':'false'}.items(): current(key,'bool',value)
    for key,seq in [('ids',plan['observation']['ids']),('groups',plan['observation']['groups'])]:
        current(key,'array',len(seq))
        for i,value in enumerate(seq): current(key + '.' + str(i),'integer',value)
    current('components','array',5)
    for i,item in enumerate(plan['observation']['components']):
        prefix = 'components.' + str(i); checks.append('current_json_dictionary ' + prefix + ' || return 2')
        for key,value in item.items():
            if key == 'fsid':
                current(prefix + '.fsid','array',2)
                for j,word in enumerate(value): current(prefix + '.fsid.' + str(j),'integer',word)
            else: current(prefix + '.' + key,'string' if type(value) is str else 'integer',value)
    values['CURRENT_DEPLOYMENT_CHECKS'] = '\n    '.join(checks)
    values['INSTALL_FILES'] = '\n'.join('install_file ' + shlex.quote(n) + ' ' + str(a['size']) + ' ' + shlex.quote(a['sha256']) + ' || return 2' for n,a in plan['artifacts'].items())
    values['CASE_ROLES'] = '\n'.join('        ' + c + ') roles=' + shlex.quote(' '.join(case_roles(c))) + ' ;;' for c in CASES)
    values['ROLE_CAPS'] = '\n'.join('        ' + role + ') cap=' + str(role_cap(role)) + ' ;;' for role in dict.fromkeys(r for c in CASES for r in case_roles(c)))
    values['EVIDENCE_LIMITS'] = '\n'.join(str(cap) + '\t' + n for n,cap in plan['evidence_limits'].items())
    root = substitute((HERE/'root-stage.sh.in').read_text(),values)
    stage = plan['paths']['root_stage']; script = stage + '/root-stage.sh'
    ids = guard('read_match 0 /usr/bin/id -ru') + guard('read_match 0 /usr/bin/id -u')
    check = 'set -eu; ' + READ_MATCH + '; ' + ids
    for text in ('[ -d ' + shlex.quote(stage) + ' ]','[ ! -L ' + shlex.quote(stage) + ' ]',
        'read_match 0:40700 /usr/bin/stat -f %u:%p ' + shlex.quote(stage),
        '[ -f ' + shlex.quote(script) + ' ]','[ ! -L ' + shlex.quote(script) + ' ]',
        'read_match 0:100500:1 /usr/bin/stat -f %u:%p:%l ' + shlex.quote(script),
        'read_match ' + str(len(root)) + ' /usr/bin/stat -f %z ' + shlex.quote(script),
        'read_match ' + shlex.quote(sha(root) + '  ' + script) + ' /usr/bin/shasum -a 256 ' + shlex.quote(script)): check += guard(text)
    values['ROOT_CHECK'] = shlex.quote(check + 'exec /bin/sh ' + shlex.quote(script) + ' "$1"')
    bootstrap = 'set -eu; umask 077; set -C; ' + READ_MATCH + '; ' + ids + guard('read_match 0:41777 /usr/bin/stat -f %u:%p /System/Volumes/Data/private/tmp')
    bootstrap += guard('[ ! -e ' + shlex.quote(stage) + ' ]') + guard('[ ! -L ' + shlex.quote(stage) + ' ]')
    bootstrap += '/bin/mkdir -m 0700 ' + shlex.quote(stage) + '; /bin/chmod -N ' + shlex.quote(stage) + '; '
    source = plan['paths']['guest_packet'] + '/root-stage.sh'
    bootstrap += guard('[ -f ' + shlex.quote(source) + ' ]') + guard('[ ! -L ' + shlex.quote(source) + ' ]')
    bootstrap += '/usr/bin/head -c ' + str(len(root)+1) + ' ' + shlex.quote(source) + ' > ' + shlex.quote(script) + '; '
    bootstrap += guard('read_match ' + str(len(root)) + ' /usr/bin/stat -f %z ' + shlex.quote(script))
    bootstrap += '/bin/chmod -N ' + shlex.quote(script) + '; /bin/chmod 0500 ' + shlex.quote(script) + '; '
    values['ROOT_BOOTSTRAP'] = shlex.quote(bootstrap + check + 'exec /bin/sh ' + shlex.quote(script) + ' install')
    values['ROOT_SHA'] = sha(root); values['ROOT_SIZE'] = len(root)
    outer = substitute((HERE/'outer.sh.in').read_text(),values)
    values['OUTER_SHA_RAW'] = sha(outer)
    values['OUTER_SIZE'] = len(outer)
    launch = substitute((HERE/'launch.sh.in').read_text(),values)
    return ({'root-stage.sh':root,'outer.sh':outer,'launch.sh':launch}, values)


def render(plan, *, _policy=POLICY):
    return render_details(plan,_policy=_policy)[0]

def root_commands(plan, *, _policy=POLICY):
    unused, values = render_details(plan,_policy=_policy)
    prefix = ['/usr/bin/sudo','-n','/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL=C','TZ=UTC','/bin/sh','-c']
    result={'install':prefix+[shlex.split(values['ROOT_BOOTSTRAP'])[0]]}
    allowed = {'export-install-context'} | {'case-'+c for c in CASES} | {'export-'+c+':'+r for c in CASES for r in case_roles(c)}
    for phase in allowed:result[phase]=prefix+[shlex.split(values['ROOT_CHECK'])[0], 'glue-bootstrap-trace-calibration', phase]
    return result

def root_argv(plan, phase, *, _policy=POLICY):
    commands=root_commands(plan,_policy=_policy)
    require(phase in commands,'root phase selector')
    return commands[phase]

def selected_members(*, _policy=POLICY):
    approved=approval(_policy);enabled(_policy=_policy)
    selected=[dict(member='payload/'+n,original='kit/'+n,**approved['artifacts'][n]) for n in PROGRAMS]
    require(tuple(n for n,h,z in _policy.metadata)==tuple(METADATA),'metadata policy roster')
    selected.extend(dict(member='metadata/'+n,original=METADATA[n],sha256=h,size=z) for n,h,z in _policy.metadata)
    return selected

def subset(*, _policy=POLICY):
    return dict(schema='glue-bootstrap-trace-calibration-subset-v1',approval=approval(_policy),
        selected=selected_members(_policy=_policy),original_inventory_is_detached_metadata=True,full_acceptance=False)

def packet_limits(*, _policy=POLICY):
    limits={item['member']:item['size'] for item in selected_members(_policy=_policy)}
    limits.update({'plan.json':262144,'root-stage.sh':1048576,'outer.sh':1048576,'launch.sh':65536,'derived-subset.json':65536})
    return limits

def prepare(kit, output, *, _policy=POLICY):
    enabled(_policy=_policy)
    data,manifest,result,observed,entry = load_kit(kit,_policy=_policy)
    p,unused = primitives()
    plan = make_plan(result,observed,entry,secrets.token_hex(8),_policy=_policy)
    scripts = render(plan,_policy=_policy)
    output = Path(output); p.outside_repository(output,HERE.parents[3])
    parent = p.open_directory(output.parent)
    try:
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',output.name),'output leaf')
        os.mkdir(output.name,0o700,dir_fd=parent)
    finally: os.close(parent)
    def put(name,raw,mode=0o444):
        p.relative_name(name); path = output/name; path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with path.open('xb') as f: f.write(raw)
        os.chmod(path,mode)
    selected = []
    for name in PROGRAMS:
        raw = data['kit/' + name]; put('payload/' + name,raw,0o555)
        selected.append({'member':'payload/' + name,'original':'kit/' + name,'sha256':sha(raw),'size':len(raw)})
    for name,original in METADATA.items():
        raw = manifest if original == 'SHA256SUMS' else data[original]; put('metadata/' + name,raw)
        selected.append({'member':'metadata/' + name,'original':original,'sha256':sha(raw),'size':len(raw)})
    put('plan.json',p.canonical(plan))
    for name,raw in scripts.items(): put(name,raw,0o555)
    require(selected==selected_members(_policy=_policy),'selected fixed kit members')
    put('derived-subset.json',p.canonical(subset(_policy=_policy)))
    fd = p.open_directory(output)
    try: inventory = ''.join(sha(p.read_member(fd,n)) + '  ' + n + '\n' for n in sorted(p.tree_members(fd)))
    finally: os.close(fd)
    put('SHA256SUMS',inventory.encode())
    return plan


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--kit',required=True,type=Path); cli.add_argument('--output',required=True,type=Path)
    args = cli.parse_args()
    try: prepare(args.kit,args.output)
    except (ValueError,OSError,KeyError) as exc:
        print('bootstrap-trace-calibration-vm: ' + str(exc)[:512],file=sys.stderr); return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
