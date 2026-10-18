"""Strict shared tracing-kit byte contract; no activation or tool execution."""
import hashlib
import os
import re

PROGRAMS = ('context-probe', 'owned-trace-runner', 'make-request')

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(ok, message):
    if not ok:
        raise ValueError(message)

def load_approved_kit(path, approved, primitives):
    p, trace = primitives()
    required = ('kit_manifest_sha256','kit_review_manifest_sha256','catalog_review_manifest_sha256',
        'builder_receipt_manifest_sha256','build_id','catalog_sha256','recipe_sha256',
        'source_lock_sha256','source_revision','observation_sha256','proof_entry','artifacts')
    p.exact_keys(approved, required)
    for k in required:
        if k not in ('source_revision','proof_entry','artifacts'):
            p.sha(approved[k])
    require(type(approved['source_revision']) is str and re.fullmatch('[0-9a-f]{40}',approved['source_revision']), 'approved source revision')
    data = p.verified_tree(path,approved['kit_manifest_sha256'])
    fd = p.open_directory(path)
    try: manifest = p.read_member(fd,'SHA256SUMS',p.MAX_JSON)
    finally: os.close(fd)
    require(sha(manifest) == approved['kit_manifest_sha256'],'kit manifest changed')
    result = p.strict_json(data['result.json'])
    require(result['schema'] == 'glue-owned-trace-kit-result-v1' and result['status'] == 'built-reproducibly','tracing kit result')
    require(result['build_id'] == approved['build_id'] and result['catalog_sha256'] == approved['catalog_sha256'],'kit identity')
    require(all(result[k] is False for k in ('new_binaries_executed','installed','kernel_exec_proof','full_acceptance')),'kit scope')
    p.exact_keys(result['artifacts'],PROGRAMS); p.exact_keys(approved['artifacts'],PROGRAMS)
    for name in PROGRAMS:
        a = result['artifacts'][name]; raw = data['kit/' + name]
        require({k:a[k] for k in ('sha256','size')} == approved['artifacts'][name],'approved artifact')
        require(sha(raw) == a['sha256'] and len(raw) == a['size'] and raw == data['builds/first/' + name] == data['builds/second/' + name],'artifact bytes')
        require(trace.macho(raw,artifact=name) == a['provenance'],'artifact provenance')
        for trial in ('first','second'):
            for phase in ('compile','sign','verify'):
                status = p.strict_json(data['logs/' + trial + '-' + name + '-' + phase + '.status.json'])
                require(status['returncode'] == 0 and status['timed_out'] is False and status['operation_errno'] is None and status['command_cleanup_unresolved'] is False,'build/signature terminal status')
    require(sha(data['catalog.bin']) == approved['catalog_sha256'] and sha(data['recipe.json']) == approved['recipe_sha256'],'catalog/recipe binding')
    recipe = p.strict_json(data['recipe.json']); require(recipe['schema'] == 'glue-owned-trace-kit-recipe-v1' and recipe['sip_policy'] == 'exact-disabled','tracing recipe')
    require(sha(data['source-lock.json']) == approved['source_lock_sha256'],'source registry binding')
    source_lock = trace.registry(data['source-lock.json'])
    require(source_lock['source_revision'] == approved['source_revision'] and source_lock['sources'],'frozen tracing sources')
    proof = p.strict_json(data['admitted-proof.json']); p.exact_keys(proof,('registry_entry','observation','full_acceptance'))
    require(proof['full_acceptance'] is False and proof['registry_entry'] == approved['proof_entry'] and proof['registry_entry'] in source_lock['proofs'],'fresh registered proof binding')
    observed = p.observation(p.canonical(proof['observation']))
    require(sha(p.canonical(observed)) == approved['observation_sha256'],'literal deployment observation')
    return data,manifest,result,observed,proof['registry_entry']

