#!/usr/bin/env python3
"""Retain sixteen clean stock install-only host-source captures after the legacy61 child.

Run from the repository root only after every final audit/check is complete.
Large installations, archives and executables are identified, not copied.
"""
import argparse
import datetime
import gzip
import hashlib
import importlib.util
import io
import tarfile
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

REPO = Path.cwd().resolve()
CAPTURE = REPO / 'target/python-install-host-source-apps-final-capture'
BUILD = REPO / 'target/python-install-host-source-apps-final-build'
CHECKS = REPO / 'target/python-install-host-source-app-checks'
COMMIT = '7a8e32c54d0375a755b55a679e18ef97e6c50114'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'file': path.name, 'size': path.stat().st_size, 'sha256': digest}


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def clean_receipt(capture, modes):
    require((capture / 'source-revision.txt').read_text().strip() == COMMIT, 'capture revision differs: ' + str(capture))
    require((capture / 'source-status.txt').read_bytes() == (capture / 'source-diff.patch').read_bytes() == b'', 'capture was dirty: ' + str(capture))
    require({p.name.removesuffix('.trace.txt') for p in capture.glob('*.trace.txt')} == set(modes), 'capture trace inventory differs: ' + str(capture))
    for mode in modes:
        require((capture / (mode + '.trace-check.txt')).read_text().startswith('Trace checks passed:'), 'live replay missing: ' + mode)


def validate_host_trees(policy):
    provenance = json.loads((CAPTURE / 'host-runtime-provenance.json').read_text())
    source_pins = json.loads((REPO / 'fixtures/python-install-host-source-apps/source-pins.json').read_text())
    cache_pins = json.loads((REPO / 'fixtures/python-install-host-source-apps/cache-pins.json').read_text())
    artifact = REPO / 'target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz'
    require(artifact.is_file() and not artifact.is_symlink() and artifact.stat().st_size == 57626877, 'cached install-only artifact size/type differs')
    with artifact.open('rb') as stream:
        payload = stream.read(57626878)
    require(len(payload) == 57626877 and sha(payload) == '397ca401f416c3c99330a6be16d735d0cbeaf53e82070b80395b2fb4a8891f34', 'complete artifact identity differs')
    stock, links, count = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
        for member in archive:
            count += 1
            require(count <= 10000 and member.name.startswith('python/') and all(part not in ('', '.', '..') for part in member.name.split('/')) and member.mtime == 1704067200 and 0 <= member.size <= 268435456, 'unbounded/noncanonical stock member')
            key = member.name.removeprefix('python/')
            require(key not in stock and key not in links, 'duplicate stock member')
            if member.isfile():
                with archive.extractfile(member) as stream:
                    digest, size = hashlib.sha256(), 0
                    while block := stream.read(min(65536, member.size + 1 - size)):
                        size += len(block)
                        require(size <= member.size, 'stock member exceeds its bound')
                        digest.update(block)
                require(size == member.size, 'stock member is truncated')
                stock[key] = {'size': size, 'sha256': digest.hexdigest(), 'mtime': member.mtime, 'mode': member.mode & 0o777}
            elif member.issym():
                links[key] = {'target': member.linkname, 'mtime': member.mtime}
            else:
                raise ValueError('unexpected stock member type')
    require(count == 4526 and len(stock) == 3478 and len(links) == 1048 and sum(item['size'] for item in stock.values()) == 182155939, 'independent complete stock inventory differs')
    require(provenance['artifact'] == {'size': len(payload), 'sha256': sha(payload)} and provenance['complete_stock_files'] == stock and provenance['complete_stock_symlinks'] == links, 'complete captured stock provenance differs from upstream bytes')
    require(provenance['stock_sources'] == 1037 and provenance['stock_source_bytes'] == 15894268 and provenance['stock_caches'] == 3 and provenance['stock_cache_bytes'] == 21157 and len(provenance['runtime_trees']) == 10, 'selected source/cache/tree inventory differs')
    actual_sources = {key.removeprefix('lib/python3.13/'): {field: spec[field] for field in ('size','sha256')} for key,spec in stock.items() if key.startswith('lib/python3.13/') and key.endswith('.py')}
    actual_caches = {key.removeprefix('lib/python3.13/'): {field: spec[field] for field in ('size','sha256')} for key,spec in stock.items() if key.startswith('lib/python3.13/') and '/__pycache__/' in key}
    require(actual_sources == policy.SPECS == source_pins['files'] and actual_caches == policy.CACHE_SPECS == cache_pins['files'], 'independently decoded selected prerequisites differ from compiled pins')
    require({field:stock['lib/libpython3.13.so.1.0'][field] for field in ('size','sha256')} == {'size':73563968,'sha256':'42be968275d5be2d9e632ec9ef6790dd2c10f1d4a710ad1028fc2b687242f219'}, 'selected library pin differs')
    for name in ('source','cache'):
        fact = identity(REPO / ('fixtures/python-install-host-source-apps/' + name + '-pins.json'))
        require(provenance[name + '_inventory'] == {key:fact[key] for key in ('size','sha256')}, 'captured source/cache inventory identity differs')
    audit = json.loads((CAPTURE / 'post-runtime-provider-audit.json').read_text())
    require(audit['all_ten_provider_trees_passed'] is True and audit['independent_post_runtime_audit'] is True and audit['complete_stock_files'] == 3478 and audit['complete_stock_symlinks'] == 1048 and audit['artifact'] == provenance['artifact'], 'independent post-runtime provider audit differs')
    require((CAPTURE / 'post-runtime-provider-audit.exit-status.txt').read_bytes() == b'0\n' and (CAPTURE / 'post-runtime-provider-audit.stderr.txt').read_bytes() == b'', 'post-runtime provider audit failed')
    require((CAPTURE / 'runtime-volume-removal.stdout.txt').read_bytes() == (CAPTURE / 'runtime-volume-name.txt').read_bytes() and (CAPTURE / 'runtime-volume-removal.stderr.txt').read_bytes() == b'', 'ephemeral provider volume cleanup differs')
    require(set(audit['trees']) == {'primary',*policy.CONTROLS} and all(tree['read_only'] is True and tree['stock_mtimes_preserved'] is True and tree['declared_changes_only'] is True and tree['symlinks'] == 1048 for tree in audit['trees'].values()), 'ten complete read-only tree proofs differ')
    volume = json.loads((CAPTURE / 'runtime-volume-inspect.json').read_text())
    require(len(volume) == 1 and volume[0]['Name'] + '\n' == (CAPTURE / 'runtime-volume-name.txt').read_text() and volume[0]['Driver'] == 'local', 'Linux volume transport receipt differs')
    trees = {}
    for mode in ('primary',) + policy.CONTROLS:
        prefix = policy.PREFIX if mode == 'primary' else policy.prefix_for(mode)
        require(prefix in provenance['runtime_trees'], 'runtime prefix is absent from complete provenance')
        tree = audit['trees'][mode]
        trees[mode] = {'prefix':prefix, **tree, 'snapshot_source_files':1036 if mode == 'missing-source' else 1037}
    return trees


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_commit')
    parser.add_argument('--retention-date', default='2026-10-12')
    args = parser.parse_args()
    require(args.source_commit == COMMIT and re.fullmatch(r'\d{4}-\d{2}-\d{2}', args.retention_date) is not None, 'reviewed checkpoint and ISO retention date required')
    datetime.date.fromisoformat(args.retention_date)
    out = REPO / ('docs/evidence/pbs-linux-arm64-python-install-host-source-apps-' + args.retention_date)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    branch = subprocess.check_output(['git', 'branch', '--show-current'], cwd=REPO, text=True).strip()
    require(commit == COMMIT, 'current source differs from reviewed checkpoint')
    require(out.is_dir() and not out.is_symlink() and {path.name for path in out.iterdir()} == {'regressions'} and not (out / 'regressions').is_symlink(), 'legacy child must create only known regressions subtree first')
    allowed = (out / 'regressions').relative_to(REPO).as_posix() + '/'
    status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=REPO, text=True)
    require(all(line.startswith('?? ' + allowed) for line in status.splitlines()), 'source dirty outside known retained regressions')
    spec = importlib.util.spec_from_file_location('host_source_retention_policy', REPO / 'scripts/check-linux-python-install-host-source-app-trace.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    cells = ('bundled-archived', 'bundled-host', 'host-archived', 'host-host')
    controls = ('corrupt-native', 'missing-host-image', 'wrong-host-image')
    legacy = [('host-source', ('minimal','resources','stdlib','app-error','syntax','nul','corrupt-source','missing-source','wrong-source','deep-cache','startup-native','startup-bytecode','missing-library')), ('source', ('minimal','resources','app-error','syntax','nul','corrupt-source')),
              ('runner', ('bundled-imports','host-imports') + cells + controls),
              ('native', cells + tuple(cell + '-app-error' for cell in cells) + controls),
              ('host-import', ('success','app-error','corrupt-source','wrong-library','wrong-import-source','missing-import-source','cached-import-bytecode')),
              ('bundled-import', ('success','app-error','corrupt-source')), ('frozen', ('success','missing-encodings','bad-bytecode','app-error')),
              ('host-startup', ('success','wrong-library','wrong-stdlib','missing-encodings','symlink-stdlib','missing-library','cached-bytecode','app-error'))]
    for group, modes in legacy:
        clean_receipt(REPO / ('target/python-install-host-source-apps-' + group + '-regression-capture'), modes)
    clean_receipt(CAPTURE, policy.MODES)
    require((CAPTURE / 'development-opt-in.txt').read_bytes() == b'false\n', 'development opt-in on final capture')
    require((CAPTURE / 'source-branch.txt').read_text().strip() == branch, 'capture-time branch receipt differs')
    image = json.loads((CAPTURE / 'image-inspect.json').read_text())
    require(len(image) == 1 and image[0]['Id'] == '62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe' and image[0]['Digest'] == 'sha256:c3aa290549c5ba0e63aec9de61fc10b6e4bd59e89c0c3f72bb270dd426eedeba', 'captured runtime image identity differs')
    require((CAPTURE / 'commands.sh').read_bytes() == subprocess.check_output(['git','show',commit + ':fixtures/python-install-host-source-apps/run-linux.sh'],cwd=REPO), 'capture harness differs from checkpoint')
    control = json.loads((CAPTURE / 'control-audit.json').read_text())
    require(control['source_revision'] == commit and control['source_clean'] and control['counts'] == {'runtime_cases':16,'controls':60,'provenance_receipts':4,'provenance_files':8} and not control['findings'], 'fresh clean60 control/provenance audit incomplete')
    audit = json.loads((CHECKS / 'product-trace-audit.json').read_text())
    require(audit['capture_revision'] == audit['repository_revision'] == commit and audit['capture_status'] == audit['repository_status'] == '' and audit['passed'] and audit['baseline_count'] == len(audit['baselines']) == 16 and audit['mutation_count'] == audit['rejected_count'] == len(audit['mutations']) and audit['mutation_count'] > 0 and all(item['rejected'] is True for item in audit['mutations']), 'fresh clean hostile audit incomplete')
    require(all(item['passed'] is True for item in audit['baselines']), 'hostile audit baselines failed')
    require(audit['script_sha256'] == identity(CHECKS / 'product-trace-audit.py')['sha256'] and audit['source_inventory_sha256'] == identity(REPO / 'fixtures/python-install-host-source-apps/source-pins.json')['sha256'] and audit['cache_inventory_sha256'] == identity(REPO / 'fixtures/python-install-host-source-apps/cache-pins.json')['sha256'], 'hostile audit script/source/cache identities differ')
    for name,digest in audit['checker_sha256'].items():
        require(digest == sha(subprocess.check_output(['git','show',commit + ':scripts/' + name],cwd=REPO)), 'audited checker differs from checkpoint: ' + name)
    require(audit['stdlib_sources'] == 1037 and audit['stdlib_bytes'] == 15894268 and audit['startup_caches'] == 3 and audit['startup_cache_bytes'] == 21157 and audit['capture_metadata_sha256'] == identity(CAPTURE / 'source-metadata.json')['sha256'], 'hostile audit workload/inventory binding differs')
    require({item['mode'] for item in audit['baselines']} == set(policy.MODES), 'hostile audit baseline mode inventory differs')
    for item in audit['baselines']:
        mode = item['mode']
        require(item['trace_sha256'] == identity(CAPTURE / (mode + '.trace.txt'))['sha256'] and item['archive_sha256'] == identity(BUILD / 'relocated Python install host source apps' / (mode + '.glue'))['sha256'], 'hostile audit baseline is from another trace/archive capture')
    require(control['script']['sha256'] == identity(CHECKS / 'product-control-audit.py')['sha256'] and control['metadata']['sha256'] == identity(CAPTURE / 'source-metadata.json')['sha256'] and len(control['runtime']) == 16 and len(control['controls']) == 60, 'control audit script/metadata/workload binding differs')
    shortcuts = audit['accepted_rejection_shortcuts']
    require(len(shortcuts) == 1 and shortcuts[0]['mode'] == 'corrupt-source' and shortcuts[0]['accepted'] is True, 'explicit partial-CRC shortcut control missing')
    replays = list((out / 'regressions').rglob('*.compressed-trace-check.exit-status.txt'))
    require(len(list((out / 'regressions').rglob('*.trace.txt.gz'))) == len(replays) == 61 and all(path.read_bytes() == b'0\n' for path in replays), 'legacy61 compressed replays incomplete')
    source = BUILD / 'relocated Python install host source apps'
    for line in (CAPTURE / 'artifacts.sha256').read_text().splitlines():
        digest, recorded = line.split('  ',1)
        require(recorded.startswith('/build-target/') and identity(BUILD / recorded.removeprefix('/build-target/'))['sha256'] == digest, 'artifact hash receipt differs')
    records, manifests, content = {}, {}, {}
    for mode in policy.MODES:
        archive = source / (mode + '.glue')
        records[mode] = policy.archive_record(archive, mode)
        require(records[mode] == policy.retained_metadata(CAPTURE / 'source-metadata.json', mode, archive.stat().st_size), 'actual archive/typed metadata differs: ' + mode)
        require((CAPTURE / (mode + '.exit-status.txt')).read_bytes() == (str(0 if mode in policy.SUCCESS else 1) + '\n').encode(), 'captured status differs: ' + mode)
        require(((CAPTURE / (mode + '.stdout.txt')).read_bytes(), (CAPTURE / (mode + '.stderr.txt')).read_bytes()) == policy.expected_output(mode), 'captured output differs: ' + mode)
        with archive.open('rb') as stream:
            locator = stream.read(64)
            manifests[mode] = stream.read(struct.unpack_from('<Q',locator,16)[0])
        resources = json.loads(manifests[mode])['resources']
        content[mode] = {'resources':len(resources),'uncompressed_bytes':sum(item['size'] for item in resources.values())}
    require(manifests['minimal'] == manifests['corrupt-source'], 'corruption changes manifest')
    good, bad = (source / 'minimal.glue').read_bytes(), (source / 'corrupt-source.glue').read_bytes()
    changes = [i for i,(left,right) in enumerate(zip(good,bad)) if left != right]
    offset = records['corrupt-source']['corrupt_offset']
    require(len(good) == len(bad) and changes == [offset] and good[offset] ^ bad[offset] == 1, 'archive corruption is not exactly selected one byte')
    host_trees = validate_host_trees(policy)
    prelude = identity(REPO / 'fixtures/python-host-source-apps/prelude.py')
    require(prelude['size'] == 455 and prelude['sha256'] == '89c6fd07ec27e83baf3af9612caf44e164867d7eff81d957bcaa0c139ccfff00', 'trusted prelude identity differs')
    elf = (CAPTURE / 'launcher.elf.txt').read_text()
    require('[...]' not in elf and re.findall(r'Shared library: \[([^]]+)\]',elf) == ['libm.so.6','libgcc_s.so.1','libc.so.6'] and not re.search(r'\bUND[ \t]+(?:Py|_Py)',elf), 'complete launcher ELF dependencies/symbols differ')
    api_source = subprocess.check_output(['git','show',commit + ':crates/glue-runtime-python/src/linux.rs'],cwd=REPO,text=True)
    require('std::mem::size_of::<Api>() == 240' in api_source, 'API4 table240 assertion differs')
    for path in CAPTURE.rglob('*'):
        require(not path.is_symlink(), 'capture companion symlink')
        if path.is_file() and not path.name.endswith('.trace.txt'):
            target = out / path.relative_to(CAPTURE)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,target)
    traces, commands = {}, []
    for mode in policy.MODES:
        raw = (CAPTURE / (mode + '.trace.txt')).read_bytes()
        packed = gzip.compress(raw,compresslevel=9,mtime=0)
        require(packed[4:8] == b'\0'*4 and gzip.decompress(packed) == raw, 'gzip timestamp/content mismatch')
        trace = out / (mode + '.trace.txt.gz')
        trace.write_bytes(packed)
        traces[mode] = {'raw_bytes':len(raw),'raw_sha256':sha(raw),'gzip_bytes':len(packed),'gzip_sha256':sha(packed),'records':len(raw.splitlines()),'pids':sorted(set(int(pid) for pid in re.findall(rb'^([0-9]+)\s',raw,re.M)))}
        command = [sys.executable,'-B',str(REPO / 'scripts/check-linux-python-install-host-source-app-trace.py'),str(trace),'--mode',mode,'--stdout-file',str(out / (mode + '.stdout.txt')),'--stderr-file',str(out / (mode + '.stderr.txt')),'--metadata-file',str(out / 'source-metadata.json'),'--archive-bytes',str(records[mode]['bytes'])]
        result = subprocess.run(command,cwd=REPO,capture_output=True)
        (out / (mode + '.compressed-trace-check.txt')).write_bytes(result.stdout + result.stderr)
        (out / (mode + '.compressed-trace-check.exit-status.txt')).write_text(str(result.returncode)+'\n')
        require(result.returncode == 0, 'compressed replay failed: ' + result.stderr.decode())
        commands.append(command)
        (out / (mode + '.manifest.json')).write_bytes(manifests[mode])
    validation = out / 'validation'
    validation.mkdir()
    for name,path in [('retain-install-host-source-apps.py',Path(__file__)),('product-control-audit.py',REPO / 'target/python-install-host-source-apps-control-audit.py'),('product-control-audit-commands.sh',CHECKS / 'product-control-audit-commands.sh'),('product-trace-audit.py',CHECKS / 'product-trace-audit.py'),('product-trace-audit.json',CHECKS / 'product-trace-audit.json'),('product-trace-audit.commands.txt',CHECKS / 'product-trace-audit.commands.txt')]:
        shutil.copyfile(path,validation / name)
    save(validation / 'compressed-replay-commands.json',commands)
    shutil.copyfile(REPO / 'fixtures/python-install-host-source-apps/audit_installation.py',validation / 'audit-installation.py')
    require((REPO / 'fixtures/python-install-host-source-apps/audit_installation.py').read_bytes() == subprocess.check_output(['git','show',commit + ':fixtures/python-install-host-source-apps/audit_installation.py'],cwd=REPO), 'provider audit source differs from clean checkpoint')
    for source_path,name in [('fixtures/python-pbs/pins.json','pins.json'),('fixtures/python-bootstrap/header-pins.json','header-pins.json'),('fixtures/python-install-host-source-apps/source-pins.json','source-pins.json'),('fixtures/python-install-host-source-apps/cache-pins.json','cache-pins.json'),('fixtures/python-host-source-apps/prelude.py','prelude.py')]:
        shutil.copyfile(REPO / source_path,out / name)
    summary = {'source_commit':commit,'source_clean':True,'source_branch':{'value':branch,'receipt':'source-branch.txt','recorded_at':'capture'},'retention_date':args.retention_date,'image_id':'62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe','target_triple':'aarch64-unknown-linux-gnu',
               'launcher':identity(source / 'glue'),'archives':{mode:{'file':mode+'.glue','size':record['bytes'],'sha256':record['sha256']} for mode,record in records.items()},'content':content,
               'applications':{mode:{'app_id':record['app_id'],'component':record['component'],'entry':record['entry'],'resources':record['application'],'resource_count':len(record['application']),'bytes':sum(item['size'] for item in record['application'].values())} for mode,record in records.items()},
               'host_trees':host_trees,'source_projection':{'files':1037,'uncompressed_bytes':15894268,'derived_source_cache_locations':100,'cache_locations_required_absent':99,'required_stock_cache_files':3,'required_stock_cache_bytes':21157,'directory_owner_cap':256,'retained_owner_cap':763,'empty_sources':sum(item['size']==0 for item in policy.SPECS.values()),'inventory':identity(out / 'source-pins.json')},'trusted_prelude':prelude,'api':{'revision':4,'public_exports':29,'table_bytes':240,'provenance_receipts':4},
               'statuses':{mode:0 if mode in policy.SUCCESS else 1 for mode in policy.MODES},'stdout_bytes':{mode:len(policy.expected_output(mode)[0]) for mode in policy.MODES},'stderr_bytes':{mode:len(policy.expected_output(mode)[1]) for mode in policy.MODES},'corrupt_source':{'key':policy.CORRUPT_KEY,'size':12,'data_offset':offset,'only_changed_archive_byte':offset,'original_member_sha256':policy.expected_application('minimal')[policy.CORRUPT_KEY]['sha256'],'corrupt_member_sha256':sha(policy.CORRUPT_BYTES)},
               'controls':60,'hostile_actual_mutations':audit['mutation_count'],'accepted_rejection_shortcuts':shortcuts,'trace_read_scope':'Complete requested/returned host file counts, EOF/metadata/closure and pinned visible ELF prefix; s256 strings do not retain every source/library byte. Full file hashes are separately checked by Rust and retained host projection identities.',
               'error_finalization_scope':'Success stdout precedes retained owner release; error-mode finalization ownership is established by synchronous source/C lifetimes together with complete phase/closure traces, before outer CLI stderr.'}
    save(out / 'fixture-summary.json',summary)
    save(out / 'trace-summary.json',traces)
    save(out / 'capture-summary.json',{'install_host_source_apps':summary,'regressions':json.loads((out / 'regressions/capture-summary.json').read_text())})
    source_lines = []
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',commit],cwd=REPO).split(b'\0'):
        if not entry: continue
        meta,name = entry.split(b'\t',1)
        fields = meta.split()
        if fields[1] != b'blob' or name.startswith(b'docs/evidence/'): continue
        data = subprocess.check_output(['git','cat-file','blob',fields[2].decode()],cwd=REPO)
        source_lines.append(sha(data)+'  '+name.decode())
    (out / 'source.sha256').write_text('\n'.join(source_lines)+'\n')
    require((out / 'source.sha256').read_bytes() == (out / 'regressions/source.sha256').read_bytes(),'top/legacy source inventories differ')
    checksum_lines = [identity(path)['sha256']+'  '+path.relative_to(out).as_posix() for path in sorted(out.rglob('*')) if path.is_file() and path != out / 'SHA256SUMS']
    (out / 'SHA256SUMS').write_text('\n'.join(checksum_lines)+'\n')
    print(json.dumps({'source_commit':commit,'source_traces':16,'regression_traces':61,'compressed_replays':77,'controls':60,'hostile_mutations':audit['mutation_count'],'accepted_rejection_shortcuts':1,'source_files':len(source_lines),'retained_files_before_root_README':len(checksum_lines)+1,'output':str(out)},indent=2))


if __name__ == '__main__':
    main()
