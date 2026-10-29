"""Exact synthetic RR/RC/TL/witness vectors plus original raw image records."""
from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import runtime_recipe as recipe
import test_runtime_boundary as base
import test_runtime_images as images_fixture

OWNER, TARGET = base.OWNER, base.TARGET
put = base.put


def sha(raw):
    return hashlib.sha256(raw).digest()


def row(fd, descriptor=1, status=1, mode=0o100600, device=77, inode=1001, links=1):
    return b''.join(value.to_bytes(width, 'big') for value, width in (
        (fd, 4), (descriptor, 4), (status, 4), (mode, 4), (device, 8), (inode, 8), (links, 8)))


def rebind(e):
    request = bytearray(e.request)
    request[128:160] = sha(e.catalog)
    request_sha = sha(request)
    status = bytearray(e.status_stream)
    for start in (0, 512):
        if len(status) >= start + 88:
            status[start + 56:start + 88] = request_sha
    go = bytearray(e.go_prefix)
    if len(go) >= 52:
        go[20:52] = request_sha
    output, delivery = bytearray(e.output_witness), bytearray(e.gate_delivery)
    for wire in (output, delivery):
        if len(wire) >= 128:
            wire[32:64], wire[64:96], wire[96:128] = request_sha, sha(e.catalog), sha(status[:512])
    if len(delivery) == 240:
        delivery[176:240] = bytes(go) + bytes(64 - len(go))
    return replace(e, request=bytes(request), status_stream=bytes(status), go_prefix=bytes(go),
                   output_witness=bytes(output), gate_delivery=bytes(delivery))


def evidence(*, artifact=b'fixed-runtime-launcher', arguments=None):
    build, leaf, cwd_name = b'runtime-fixture', b'glue', b'unrelated-cwd'
    prefix = b'/System/Volumes/Data/Library/GlueMVPFixtures/'
    executable, cwd = prefix + build + b'/' + leaf, prefix + cwd_name
    argv = (executable,) + ((b'run', b'/fixed/app.glue', b'--', b'argument with spaces') if arguments is None else tuple(arguments))
    plan = b'GLUETL\0\1' + (1).to_bytes(8, 'big') + len(argv).to_bytes(4, 'big') + bytes(4)
    plan += b''.join(len(value).to_bytes(4, 'big') + value for value in argv)
    catalog = bytearray(256 + len(build) + len(leaf) + len(cwd_name) + len(plan))
    catalog[:8] = b'GLUERC01'
    for at, width, value in ((8, 4, 1), (12, 4, len(catalog)), (16, 8, len(artifact)),
        (24, 8, 1), (32, 4, 2), (36, 4, 3), (40, 8, 4), (48, 4, 5), (52, 4, 6),
        (184, 4, len(build)), (188, 4, len(leaf)), (192, 4, len(cwd_name)), (196, 4, len(plan))):
        put(catalog, at, width, value)
    catalog[56:88] = sha(artifact)
    catalog[88:120], catalog[120:152], catalog[152:184] = b'S' * 32, b'R' * 32, b'L' * 32
    catalog[256:] = build + leaf + cwd_name + plan
    old = base.launch()
    request = bytearray(208 + len(executable) + len(cwd))
    request[:208] = old.request[:208]
    request[:8] = b'GLUERR01'
    for at, value in ((12, len(request)), (16, 2), (120, 2), (176, len(executable)), (180, len(cwd))):
        put(request, at, 4, value)
    request[208:] = executable + cwd
    status = bytearray(old.ready + old.exec_attempt)
    put(status, 288 + 12, 4, 0o020666)  # Actual fixed runtime stdin is character backing.
    output = bytearray(320)
    output[:8] = b'GLUERW01'
    for at, value in ((8, 1), (12, 320), (16, OWNER), (20, TARGET), (24, 4),
                      (140, 0xffffffff), (144, 0xffffffff)):
        put(output, at, 4, value)
    output[160:] = row(40) + row(41, inode=1002) + row(40) + row(41, inode=1002)
    delivery = bytearray(240)
    delivery[:8] = b'GLUERD01'
    for at, value in ((8, 1), (12, 240), (16, OWNER), (20, TARGET), (24, 1), (28, 1), (128, 64), (152, 1)):
        put(delivery, at, 4, value)
    value = recipe.RuntimeRecipeEvidence(bytes(request), bytes(catalog), plan, bytes(status),
        artifact, bytes(output), bytes(delivery), old.go)
    return rebind(value)


def paired(data=None, **kwargs):
    return recipe.pair_runtime_recipe_raw(kwargs.pop('program', recipe._IMAGES.expected_images_program(TARGET)),
        kwargs.pop('probes', base.INVENTORY), kwargs.pop('errors', b''),
        kwargs.pop('event_lines', base.lines(images_fixture.chain(2) if data is None else data)),
        owner_pid=kwargs.pop('owner_pid', OWNER), target_pid=kwargs.pop('target_pid', TARGET),
        contract_bytes=kwargs.pop('contract_bytes', base.CONTRACT),
        launch_evidence=kwargs.pop('launch_evidence', evidence()), **kwargs)


def change(e, name, at, width, value, *, bind=False):
    raw = bytearray(getattr(e, name)); put(raw, at, width, value)
    result = replace(e, **{name: bytes(raw)})
    return rebind(result) if bind else result


class RuntimeRecipeControls(unittest.TestCase):
    def refuse(self, pattern='.', **kwargs):
        with self.assertRaisesRegex(recipe.RawValidationError, pattern) as caught:
            paired(**kwargs)
        return caught.exception

    def test_exact_generic_launch_and_original_samples_are_recomputed(self):
        result = paired()
        self.assertEqual(result.protocol, 'darwin-runtime-recipe-capture-v1')
        self.assertEqual(len(result.images.transitions), 2)
        self.assertEqual(result.launch.arguments[1:], (b'run', b'/fixed/app.glue', b'--', b'argument with spaces'))
        self.assertTrue(result.launch.cwd.endswith(b'/unrelated-cwd'))
        self.assertEqual([m.child.fd for m in result.output_witness.matches], [1, 2])
        self.assertEqual([m.parent.fd for m in result.output_witness.matches], [40, 41])
        self.assertEqual(len(result.output_witness.samples), 4)
        self.assertEqual(result.output_witness.samples[0], result.output_witness.samples[2])
        self.assertFalse(result.output_witness.authorizes_sink_exemptions or result.native_admission)
        self.assertFalse(result.output_capabilities_authorized or result.state_feed_eligible or result.full_trace_acceptance)
        self.assertTrue(all(not s.authorized_exemption and not s.native_lineage_authenticated for s in result.conditional_output_seeds))
        self.assertNotEqual(result.conditional_output_seeds[0].capture_key, result.conditional_output_seeds[1].capture_key)

    def test_real_closed_topology_requires_character_stdin(self):
        self.assertEqual(paired().launch.objects[0].mode & 0o170000, 0o020000)
        e = change(evidence(), 'status_stream', 288 + 12, 4, 0o010600, bind=True)
        self.refuse('closed descriptor topology', launch_evidence=e)

    def test_legacy_launch_profiles_do_not_become_generic_runtime_fallbacks(self):
        self.refuse('fixed selectors', launch_evidence=change(evidence(), 'request', 16, 4, 1, bind=True))
        self.refuse('canonical RR|fixed selectors', launch_evidence=replace(evidence(), request=base.launch().request))
        e = evidence()
        old = recipe._IMAGES.LaunchEvidence(e.request, e.catalog, e.status_stream[:512], e.go_prefix,
                                          e.status_stream[512:], e.launcher_artifact)
        with self.assertRaises(recipe.RawValidationError):
            recipe._IMAGES.pair_runtime_images_raw(recipe._IMAGES.expected_images_program(TARGET), base.INVENTORY,
                b'', base.lines(images_fixture.chain(1)), owner_pid=OWNER, target_pid=TARGET,
                contract_bytes=base.CONTRACT, launch_evidence=old)
        self.refuse('fixed runtime', program=base.boundary._RAW._expected_program(TARGET))

    def test_actual_c_witness_encoder_matches_independent_original_vectors(self):
        compiler = shutil.which('cc')
        self.assertIsNotNone(compiler, 'a C compiler is required')
        source = r"""
#include "runtime_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include "runtime_witness.h"
#include <stdio.h>
#include <string.h>
int nr_fail(struct nr_attempt *a, enum nr_stage s, enum nr_reason r, int e, int d) {
    (void)a; (void)s; (void)r; (void)e; (void)d;
    return -1;
}
int nr_write_new(struct nr_attempt *a, const char *n, const uint8_t *p, size_t z) {
    (void)a; (void)n; (void)p; (void)z;
    return -1;
}
int nr_sha_bytes(const uint8_t *p, size_t z, uint8_t out[32]) {
    (void)p; (void)z; (void)out;
    return -1;
}
static uint32_t get32(const uint8_t *p) {
    uint32_t n = 0;
    for (unsigned i = 0; i < 4; i++) n = (n << 8) | p[i];
    return n;
}
int main(int argc, char **argv) {
    (void)argv;
    uint8_t input[168], output[NRW_OUTPUT_BYTES], delivery[NRW_DELIVERY_BYTES];
    if (fread(input, 1, sizeof(input), stdin) != sizeof(input)) return 2;
    struct nrw_binding b = {0};
    b.owner = get32(input); b.child = get32(input + 4);
    memcpy(b.request_sha, input + 8, 32);
    memcpy(b.catalog_sha, input + 40, 32);
    memcpy(b.ready_sha, input + 72, 32);
    struct tfo_reference_observation o = {0};
    o.completed_samples = 4;
    for (unsigned i = 0; i < 4; i++) {
        o.samples[i].fd = i % 2 ? 41 : 40;
        o.samples[i].descriptor_flags = 1;
        o.samples[i].status_flags = 1;
        o.samples[i].backing = (struct tfo_backing){77, i % 2 ? 1002 : 1001, 1, 0100600};
    }
    struct tfo_error e = {TFO_STAGE_NONE, TFO_REASON_NONE, 0, -1, -1};
    struct bio_result r = {0};
    struct bio_error be = {0};
    r.bytes_moved = 64; memcpy(r.prefix, input + 104, 64);
    int written = 0;
    if (argc == 2) {
        be.stage = BIO_STAGE_OBSERVER; be.reason = BIO_REASON_OBSERVER;
        be.bytes_moved = 64; written = -1;
    }
    if (nrw_output_encode(&b, &o, &e, output) ||
        nrw_delivery_encode(&b, BR_SEND_GO, 1, &r, &be, written, 1, 0, 0, delivery)) return 3;
    if (fwrite(output, 1, sizeof(output), stdout) != sizeof(output) ||
        fwrite(delivery, 1, sizeof(delivery), stdout) != sizeof(delivery)) return 4;
    return 0;
}
"""
        e = evidence()
        binding = OWNER.to_bytes(4, 'big') + TARGET.to_bytes(4, 'big') + sha(e.request) + sha(e.catalog) + sha(e.status_stream[:512])
        native = base.BASE / 'bootstrap-runtime-runner'
        with tempfile.TemporaryDirectory(prefix='glue-runtime-witness-codec-') as folder:
            driver, binary = Path(folder) / 'witness.c', Path(folder) / 'witness'
            driver.write_text(source)
            built = subprocess.run([compiler, '-std=c11', '-D_DEFAULT_SOURCE', '-D_DARWIN_C_SOURCE',
                '-Wall', '-Wextra', '-Werror', '-pedantic',
                '-I', str(native), str(driver), str(native / 'runtime_witness.c'), '-o', str(binary)],
                capture_output=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr.decode(errors='replace'))
            encoded = subprocess.run([str(binary)], input=binding + e.go_prefix, capture_output=True, timeout=5)
            self.assertEqual(encoded.returncode, 0, encoded.stderr)
            self.assertEqual(encoded.stdout, e.output_witness + e.gate_delivery)
            self.assertEqual(len(paired(launch_evidence=replace(e, output_witness=encoded.stdout[:320],
                gate_delivery=encoded.stdout[320:])).conditional_output_seeds), 2)
            failed = subprocess.run([str(binary), 'failed-full'], input=binding + e.go_prefix, capture_output=True, timeout=5)
            self.assertEqual(failed.returncode, 0, failed.stderr)
            self.assertEqual(failed.stdout[-64:], e.go_prefix)
            self.refuse('write/close success', launch_evidence=replace(e, output_witness=failed.stdout[:320],
                gate_delivery=failed.stdout[320:]))

    def test_full_output_status_flags_are_preserved_not_reduced_to_access_bits(self):
        e = evidence()
        for flag in (9, 0x10001, 0x7ffffffd):
            status, witness = bytearray(e.status_stream), bytearray(e.output_witness)
            for i in (1, 2): put(status, 288 + 40 * i + 8, 4, flag)
            for i in range(4): put(witness, 160 + 40 * i + 8, 4, flag)
            value = paired(launch_evidence=rebind(replace(e, status_stream=bytes(status), output_witness=bytes(witness))))
            self.assertEqual(value.output_witness.samples[0].status_flags, flag)

    def test_launcher_limit_is_sixteen_mib_and_hashes_actual_bytes(self):
        for size in (4194305, 16777216):
            e = evidence(artifact=b'x' * size)
            result = paired(launch_evidence=e)
            self.assertEqual(result.launch.launcher_sha256, hashlib.sha256(e.launcher_artifact).hexdigest())
        self.refuse('launcher bytes', launch_evidence=evidence(artifact=b'x' * 16777217))
        e = evidence()
        self.refuse('size/hash', launch_evidence=replace(e, launcher_artifact=e.launcher_artifact + b'x'))

    def test_tl_retains_empty_nonutf8_and_argument_boundaries(self):
        e = evidence(arguments=(b'run', b'', b'argument with spaces', b'\xff'))
        self.assertEqual(paired(launch_evidence=e).launch.arguments[1:], (b'run', b'', b'argument with spaces', b'\xff'))
        self.assertNotEqual(e.launch_plan, evidence(arguments=(b'run', b'argument', b'with spaces', b'\xff')).launch_plan)
        e = evidence(arguments=(b'x' * (4096 - len(paired().launch.executable) - 2),))
        self.assertEqual(sum(len(v) + 1 for v in paired(launch_evidence=e).launch.arguments), 4096)
        self.refuse('copied storage', launch_evidence=evidence(arguments=(b'x' * (4096 - len(paired().launch.executable) - 1),)))
        self.refuse('target/count', launch_evidence=evidence(arguments=(b'x',) * 16))
        self.refuse('embedded NUL', launch_evidence=evidence(arguments=(b'a\0b',)))

    def test_standalone_tl_must_equal_the_entire_embedded_plan(self):
        e = evidence()
        self.refuse('standalone/embedded', launch_evidence=replace(e, launch_plan=e.launch_plan[:-1] + b'x'))
        for offset, value in ((8, 2), (20, 1)):
            plan = bytearray(e.launch_plan); put(plan, offset, 8 if offset == 8 else 4, value)
            catalog = bytearray(e.catalog); catalog[-len(plan):] = plan
            self.refuse('target/count/environment', launch_evidence=rebind(replace(e, catalog=bytes(catalog), launch_plan=bytes(plan))))

    def test_rc_rr_names_mounts_paths_and_selectors_are_exact(self):
        e = evidence()
        for name, at, value in (('request', 120, 1), ('request', 124, 1), ('request', 104, 2),
                                ('request', 108, 4095), ('catalog', 24, 0)):
            self.refuse(launch_evidence=change(e, name, at, 4 if name == 'request' else 8, value, bind=True))
        for name, at in (('request', 184), ('catalog', 200), ('catalog', 255)):
            self.refuse(launch_evidence=change(e, name, at, 1, 1, bind=True))
        self.refuse(launch_evidence=change(e, 'request', 208, 1, ord('X'), bind=True))
        self.refuse(launch_evidence=change(e, 'catalog', 256, 1, ord('.'), bind=True))

    def test_complete_status_artifact_refuses_extra_error_or_any_truncation(self):
        e = evidence()
        for size in (0, 256, 511, 512, 1023, 1025):
            status = e.status_stream[:size] if size <= 1024 else e.status_stream + b'x'
            self.refuse('complete status stream', launch_evidence=replace(e, status_stream=status))
        self.refuse('complete status stream', launch_evidence=replace(e, status_stream=e.status_stream + e.status_stream[512:]))
        self.refuse(launch_evidence=change(e, 'status_stream', 512 + 10, 2, 3, bind=True))

    def test_status_binding_and_every_reserved_region_are_checked(self):
        e = evidence()
        for at in (24, 31, 32 + 232, 511, 512 + 24, 512 + 288, 1023):
            self.refuse(launch_evidence=change(e, 'status_stream', at, 1, 1, bind=True))
        self.refuse(launch_evidence=change(e, 'status_stream', 32 + 72, 4, 502, bind=True))
        self.refuse(launch_evidence=change(e, 'status_stream', 32 + 24, 1, 1))

    def test_both_original_parent_rounds_must_stay_identical(self):
        e = evidence()
        for at in (160 + 2 * 40, 160 + 2 * 40 + 4, 160 + 2 * 40 + 8,
                   160 + 3 * 40 + 12, 160 + 3 * 40 + 16, 160 + 3 * 40 + 24, 160 + 3 * 40 + 32):
            self.refuse(launch_evidence=change(e, 'output_witness', at, 1, 1))
        for count in range(4):
            self.refuse('complete successful', launch_evidence=change(e, 'output_witness', 24, 4, count))

    def test_helper_error_is_not_overridden_by_four_good_samples(self):
        e = evidence()
        for at, value in ((128, 13), (132, 19), (136, 5), (140, 1), (144, 40)):
            self.refuse('complete successful', launch_evidence=change(e, 'output_witness', at, 4, value))
        for at in (28, 148, 159):
            self.refuse(launch_evidence=change(e, 'output_witness', at, 1, 1))

    def test_match_recomputed_from_backing_and_full_flags_not_fd_or_boolean(self):
        e = evidence()
        for offset, value in ((8, 9), (12, 0o100644), (16, 78), (24, 999), (32, 2)):
            changed = change(e, 'output_witness', 160 + offset, 4 if offset < 16 else 8, value)
            changed = change(changed, 'output_witness', 160 + 80 + offset, 4 if offset < 16 else 8, value)
            self.refuse(launch_evidence=changed)
        changed = change(e, 'output_witness', 160 + 4, 4, 0)
        changed = change(changed, 'output_witness', 160 + 80 + 4, 4, 0)
        self.refuse('held output shape', launch_evidence=changed)
        self.assertNotEqual(paired().output_witness.matches[0].child.descriptor_flags,
                            paired().output_witness.matches[0].parent.descriptor_flags)

    def test_single_link_distinct_regular_write_only_sinks_are_required(self):
        e = evidence()
        for offset, value in ((0, 2), (8, 0), (12, 0o010600), (32, 2)):
            changed = change(e, 'output_witness', 160 + offset, 4 if offset < 16 else 8, value)
            changed = change(changed, 'output_witness', 240 + offset, 4 if offset < 16 else 8, value)
            self.refuse(launch_evidence=changed)
        raw = bytearray(e.output_witness); raw[200:240] = raw[160:200]; raw[280:320] = raw[240:280]
        self.refuse('descriptor alias', launch_evidence=replace(e, output_witness=bytes(raw)))
        raw = bytearray(e.output_witness)
        for at in (200, 280): put(raw, at + 24, 8, 1001)
        status = bytearray(e.status_stream); put(status, 288 + 2 * 40 + 24, 8, 1001)
        self.refuse('backing alias', launch_evidence=rebind(replace(e, output_witness=bytes(raw), status_stream=bytes(status))))

    def test_observation_integer_domains_prevent_narrowing_or_masking(self):
        e = evidence()
        for at, value in ((160, 0x80000003), (164, 0x80000001), (168, 0x80000001), (172, 0x100100600)):
            if value > 0xffffffff:
                value = 0x01010000 | 0o100600
            self.refuse('native integer', launch_evidence=change(e, 'output_witness', at, 4, value))

    def test_delivery_accepts_original_complete_success_with_zero_error_count(self):
        result = paired()
        self.assertEqual((result.gate_delivery.bytes_moved, result.gate_delivery.bio_error_bytes_moved), (64, 0))
        self.assertEqual(result.gate_delivery.go_sha256, hashlib.sha256(evidence().go_prefix).hexdigest())
        self.assertFalse(result.gate_delivery.native_delivery_authenticated)
        self.refuse('write/close success', launch_evidence=change(evidence(), 'gate_delivery', 144, 4, 64))

    def test_failed_full_delivery_never_becomes_a_successful_go(self):
        e = evidence()
        failed = change(e, 'gate_delivery', 132, 4, 9)
        failed = change(failed, 'gate_delivery', 136, 4, 20)
        failed = change(failed, 'gate_delivery', 144, 4, 64)
        failed = change(failed, 'gate_delivery', 148, 4, 0xffffffff)
        self.assertEqual(failed.go_prefix, e.go_prefix)
        self.refuse('write/close success', launch_evidence=failed)

    def test_partial_missing_close_or_wrong_go_binding_refuses(self):
        e = evidence()
        for at, value in ((24, 2), (28, 0), (128, 63), (148, 0xffffffff),
                           (152, 0), (156, 0xffffffff), (160, 4)):
            self.refuse(launch_evidence=change(e, 'gate_delivery', at, 4, value))
        for at in (164, 175): self.refuse(launch_evidence=change(e, 'gate_delivery', at, 1, 1))
        for size in (0, 63, 65):
            self.refuse(launch_evidence=replace(e, go_prefix=e.go_prefix[:size] if size < 64 else e.go_prefix + b'x'))
        go = bytearray(e.go_prefix); go[:8] = b'GLUEGO01'
        self.refuse('original GO wire', launch_evidence=rebind(replace(e, go_prefix=bytes(go))))

    def test_all_original_artifact_hash_bindings_and_truncations_refuse(self):
        e = evidence()
        for name, at in (('output_witness', 32), ('output_witness', 64), ('output_witness', 96),
                         ('gate_delivery', 32), ('gate_delivery', 64), ('gate_delivery', 96)):
            self.refuse('exact binding', launch_evidence=change(e, name, at, 1, getattr(e, name)[at] ^ 1))
        for name in ('output_witness', 'gate_delivery'):
            value = getattr(e, name)
            for size in range(len(value)):
                self.refuse(launch_evidence=replace(e, **{name: value[:size]}))
        self.refuse(owner_pid=OWNER + 1)
        self.refuse(target_pid=TARGET + 1)

    def test_whole_capture_precedes_seeds_and_late_faults_never_return_prefix(self):
        physical = base.lines(images_fixture.chain(2))
        self.refuse(event_lines=physical + [b'{}\n'])
        self.refuse(event_lines=physical[:-1])
        self.refuse(errors=b'{"drop":1}\n')
        data = images_fixture.chain(2)
        at = next(i for i, v in enumerate(data) if v['kind'] == 2 and v['function'] == 'exit')
        data[at:at] = base.call('fork', (), 0, 1002)
        error = self.refuse('unsupported syscall', data=data)
        self.assertEqual(error.capture.raw.events, len(data))
        def broken():
            yield from physical
            raise RuntimeError('late asset fault')
        with self.assertRaisesRegex(RuntimeError, 'late asset fault'): paired(event_lines=broken())

    def test_seeds_are_capture_bound_conditional_values_not_native_object_ids(self):
        one = paired()
        two = paired(data=images_fixture.chain(1))
        self.assertNotEqual(one.conditional_output_seeds[0].capture_key, two.conditional_output_seeds[0].capture_key)
        self.assertTrue(all(s.observation_boundary == 'READY-before-GO' for s in one.conditional_output_seeds))
        self.assertFalse(one.output_witness.native_observations_authenticated or one.output_witness.lineage_authenticated)
        self.assertFalse(one.output_witness.atomic_snapshot_proved)
        self.assertTrue(all(t.artifact_sha256 is None and t.requested_path is None for t in one.images.transitions[1:]))

    def test_no_asset_io_after_import_and_single_physical_consumption(self):
        class Once:
            count = 0
            def __iter__(self):
                self.count += 1
                if self.count != 1: raise AssertionError('second consumption')
                yield from base.lines(images_fixture.chain(2))
        stream = Once()
        with patch('builtins.open', side_effect=AssertionError('file IO')), \
             patch.object(Path, 'open', side_effect=AssertionError('asset IO')):
            self.assertEqual(len(paired(event_lines=stream).conditional_output_seeds), 2)
        self.assertEqual(stream.count, 1)

    def test_frozen_values_and_fresh_serialization(self):
        result = paired()
        with self.assertRaises(FrozenInstanceError): result.output_capabilities_authorized = True
        with self.assertRaises(FrozenInstanceError): result.conditional_output_seeds[0].authorized_exemption = True
        serial = result.to_dict(); serial['output_witness']['samples'].clear(); serial['conditional_output_seeds'][0]['parent']['fd'] = 1
        self.assertEqual(len(result.to_dict()['output_witness']['samples']), 4)
        self.assertEqual(result.conditional_output_seeds[0].parent.fd, 40)


if __name__ == '__main__': unittest.main()
