#!/usr/bin/env python3
"""Prepare only the fixed positive/denied calibration; currently unconfigured."""
import argparse
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
APPROVED = None
EXECUTION_ENABLED = False
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
def enabled():
    require(APPROVED is not None and EXECUTION_ENABLED is True, 'calibration kit/execution is not configured')
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
def load_kit(path):
    enabled()
    base=shared(); contract=base.HERE/'kit_contract.py'
    require(sha(contract.read_bytes()) == base.KIT_CONTRACT_SHA, 'reviewed kit contract source differs')
    spec=importlib.util.spec_from_file_location('glue_calibration_kit_contract',contract)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.load_approved_kit(path,APPROVED,primitives)
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
def plan_from_identity(build_id,catalog_sha,artifacts,observed,entry,nonce):
    p,unused=primitives(); p.sha(build_id); p.sha(catalog_sha)
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{16}',nonce),'batch nonce')
    p.exact_keys(artifacts,PROGRAMS)
    for a in artifacts.values(): p.exact_keys(a,('sha256','size')); p.sha(a['sha256']); p.integer(a['size'],1,4194304)
    guest_os=shared().profile(entry,observed,p); tmp='/System/Volumes/Data/private/tmp/'
    paths={'guest_packet':'/Volumes/My Shared Files/glue-mvp-macos-vm-toolkit/bootstrap-trace-calibration-'+nonce,
        'guest_work':tmp+'glue-btc-user-'+nonce,'root_stage':tmp+'glue-btc-stage-'+nonce,
        'guest_export':'/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-bootstrap-trace-calibration-'+nonce,
        'guest_run_receipt':tmp+'glue-btc-launch-'+nonce,
        'guest_receipt_export':'/Volumes/My Shared Files/glue-mvp-macos-vm-results/glue-bootstrap-trace-calibration-receipt-'+nonce,
        'build_dir':'/System/Volumes/Data/Library/GlueMVPFixtures/'+build_id}
    limits=evidence_limits()
    return p.strict_json(p.canonical(dict(schema='glue-bootstrap-trace-calibration-plan-v1',
        profile='fixed-owned-context-bsd-mach-v1',approval=APPROVED,execution_enabled=EXECUTION_ENABLED,
        nonce=nonce,build_id=build_id,catalog_sha256=catalog_sha,artifacts=artifacts,observation=observed,
        proof_entry=entry,guest_os=guest_os,paths=paths,outputs={c:tmp+'glue-btc-'+nonce+'-'+c for c in CASES},
        budgets={'attempt_ms':10000,'cleanup_ms':2000},evidence_limits=limits,evidence_total_limit=EXPORT_CAP,
        event_line_limit=8192,event_count_limit=1000000,evidence_files=sorted(limits),full_acceptance=False)))
def make_plan(result,observed,entry,nonce):
    p,unused=primitives()
    require(result['schema']=='glue-owned-trace-kit-result-v1' and result['status']=='built-reproducibly','tracing result schema/status')
    require(all(result[k] is False for k in ('new_binaries_executed','installed','kernel_exec_proof','full_acceptance')),'kit scope')
    p.exact_keys(result['artifacts'],PROGRAMS)
    return plan_from_identity(result['build_id'],result['catalog_sha256'],{n:{k:result['artifacts'][n][k] for k in ('sha256','size')} for n in PROGRAMS},observed,entry,nonce)

READ_MATCH = 'read_match() {\n    rm_expected=$1; shift\n    rm_actual=$("$@") || return 2\n    [ "$rm_actual" = "$rm_expected" ]\n}'
LAST_BYTE_ZERO = 'last_byte_zero() {\n    lb_value=$("$3" -An -tu1 -j "$2" -N 1 "$1") || return 2\n    set -f\n    set -- $lb_value\n    [ "$#" = 1 ] && [ "$1" = 0 ]\n}'


def render_details(plan):
    p, unused = primitives()
    base = shared()
    expected = plan_from_identity(plan['build_id'],plan['catalog_sha256'],plan['artifacts'],
        plan['observation'],plan['proof_entry'],plan['nonce'])
    require(p.canonical(plan) == p.canonical(expected),'unreviewed plan/path/limits')
    require(EXECUTION_ENABLED is False and APPROVED is None,
            'renderer requires separate reviewed admission before execution support')
    values = {k.upper():shlex.quote(v) for k,v in plan['paths'].items()}
    values.update(ENABLED='0',UID=str(plan['observation']['ids'][0]),
        INSPECTOR_PATH=shlex.quote(INSPECTOR_PATH),INSPECTOR_SHA=INSPECTOR_SHA,
        KIT_SHA=shlex.quote('UNAPPROVED-CALIBRATION'),CATALOG_SHA=plan['catalog_sha256'],
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


def render(plan):
    return render_details(plan)[0]

def root_commands(plan):
    unused, values = render_details(plan)
    prefix = ['/usr/bin/sudo','-n','/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL=C','TZ=UTC','/bin/sh','-c']
    result={'install':prefix+[shlex.split(values['ROOT_BOOTSTRAP'])[0]]}
    allowed = {'export-install-context'} | {'case-'+c for c in CASES} | {'export-'+c+':'+r for c in CASES for r in case_roles(c)}
    for phase in allowed:result[phase]=prefix+[shlex.split(values['ROOT_CHECK'])[0], 'glue-bootstrap-trace-calibration', phase]
    return result

def root_argv(plan, phase):
    commands=root_commands(plan)
    require(phase in commands,'root phase selector')
    return commands[phase]

def prepare(kit, output):
    enabled()
    data,manifest,result,observed,entry = load_kit(kit)
    p,unused = primitives()
    plan = make_plan(result,observed,entry,secrets.token_hex(8))
    scripts = render(plan)
    output = Path(output); p.outside_repository(output,HERE.parents[3])
    parent = p.open_directory(output.parent)
    try:
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}',output.name),'output leaf')
        os.mkdir(output.name,0o700,dir_fd=parent)
    finally: os.close(parent)
    def put(name,raw,mode=0o444):
        p.relative_name(name); path = output/name; path.parent.mkdir(parents=True,exist_ok=True)
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
    put('derived-subset.json',p.canonical({'schema':'glue-bootstrap-trace-calibration-subset-v1','approval':APPROVED,
        'selected':selected,'original_inventory_is_detached_metadata':True,'full_acceptance':False}))
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
