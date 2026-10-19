"""Packing units and rebuilt-hash controls through the native-evidence API."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import observe_msg2 as observer
import test_pair_calls as fixtures


class MessageObservationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PairingTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.words = [0xFEDCBA9876543210, observer.KOBJECT | observer.SEND | observer.RECEIVE,
                      (0xFFFFFFFF << 32) | 0xA01F1E1D,
                      (0x90ABCDEF << 32) | 0x12345678,
                      (0x80000001 << 32) | 0x87654321,
                      (0xFEDCBA98 << 32) | 0xFFFFFFFF,
                      (0x2468ACE0 << 32) | 0x13579BDF, 0xFEDCBA9876543210]
        self.add_message(self.words, observer.U64)

    def add_message(self, words, raw_return):
        self.fixture.events[10:10] = [
            self.fixture.frame(15, tid=20, function="mach_msg2_trap", extra=words),
            self.fixture.frame(16, tid=20, function="mach_msg2_trap", extra=(raw_return,))]

    def publish(self, profile="tree-mach"):
        self.fixture.publish(profile)

    def inspect(self):
        return observer.observe_capture(self.fixture.control.capture, self.fixture.control.toolkit)

    def reject(self, pattern):
        with self.assertRaisesRegex((observer.UnsupportedMessageObservation,
                                     observer.pairing.UnsupportedPairing,
                                     observer.pairing.transport.InvalidCapability), pattern):
            self.inspect()

    def test_public_api_invokes_pairing_and_preserves_all_pair_and_frame_provenance(self):
        self.publish()
        with mock.patch.object(observer.pairing, "pair_capture", wraps=observer.pairing.pair_capture) as pairing:
            value = self.inspect()
        pairing.assert_called_once_with(self.fixture.control.capture, self.fixture.control.toolkit)
        self.assertEqual(value["paired_capture"]["raw_frames"], self.fixture.events)
        self.assertIn("toolkit_provenance", value["paired_capture"]["source_transport"])
        self.assertIn("receipt", value["paired_capture"]["source_transport"])
        message = value["messages"][0]
        call = value["paired_capture"]["calls"][message["pair_index"]]
        self.assertEqual(message["raw_entry_words"], self.words)
        self.assertEqual(message["raw_return_words"], [observer.U64])
        self.assertEqual(message["entry_index"], call["entry_index"])
        self.assertEqual(message["return_index"], call["return_index"])
        self.assertEqual(message["identity"], call["identity"])
        self.assertIs(value["full_trace_acceptance"], False)
        self.assertIs(value["source_contract"]["installed_guest_source_attested"], False)

    def test_result_cannot_mutate_source_contract_for_later_observations(self):
        self.publish()
        first = self.inspect()
        first["source_contract"]["sources_sha256"]["osfmk/ipc/mach_msg.c"] = "caller-changed"
        self.assertEqual(self.inspect()["source_contract"]["sources_sha256"]["osfmk/ipc/mach_msg.c"],
                         observer.SOURCE_CONTRACT["sources_sha256"]["osfmk/ipc/mach_msg.c"])

    def test_every_scalar_field_is_exact_and_reconstructs_packed_words(self):
        self.publish()
        fields = self.inspect()["messages"][0]["scalar_fields_under_source_contract"]
        expected = {
            "data_pointer_u64": self.words[0], "caller_options_u64": self.words[1],
            "header_bits_u32": 0xA01F1E1D, "send_size_u32": 0xFFFFFFFF,
            "remote_port_name_u32": 0x12345678, "local_port_name_u32": 0x90ABCDEF,
            "voucher_port_name_u32": 0x87654321, "message_id_bits_u32": 0x80000001,
            "message_id_i32": -2147483647, "descriptor_count_u32": 0xFFFFFFFF,
            "receive_port_name_u32": 0xFEDCBA98, "receive_size_u32": 0x13579BDF,
            "priority_u32": 0x2468ACE0, "timeout_word_u64": self.words[7],
            "timeout_low32_under_source_cast": 0x76543210, "timeout_high32_remainder": 0xFEDCBA98,
            "remote_disposition_bits": 29, "local_disposition_bits": 30,
            "voucher_disposition_bits": 31, "complex_bit": True,
            "uninterpreted_header_bits_u32": 0x20000000,
        }
        for key, word in expected.items():
            self.assertEqual(fields[key], word, key)
        reconstructed = [fields["data_pointer_u64"], fields["caller_options_u64"],
                         (fields["send_size_u32"] << 32) | fields["header_bits_u32"],
                         (fields["local_port_name_u32"] << 32) | fields["remote_port_name_u32"],
                         (fields["message_id_bits_u32"] << 32) | fields["voucher_port_name_u32"],
                         (fields["receive_port_name_u32"] << 32) | fields["descriptor_count_u32"],
                         (fields["priority_u32"] << 32) | fields["receive_size_u32"],
                         (fields["timeout_high32_remainder"] << 32) | fields["timeout_low32_under_source_cast"]]
        self.assertEqual(reconstructed, self.words)

    def test_signed_message_id_boundaries(self):
        for bits, expected in ((0, 0), (0x7FFFFFFF, 2147483647),
                               (0x80000000, -2147483648), (0xFFFFFFFF, -1)):
            with self.subTest(bits=bits):
                words = [0] * 8
                words[4] = (bits << 32) | observer.U32
                fields = observer._scalar_fields(words)
                self.assertEqual(fields["message_id_bits_u32"], bits)
                self.assertEqual(fields["message_id_i32"], expected)
                self.assertEqual(fields["voucher_port_name_u32"], observer.U32)

    def test_all_zero_and_all_scalar_field_bits_preserved_without_semantic_validation(self):
        for word in (0, observer.U64):
            words = [word] * 8
            words[1] &= ~observer.VECTOR
            fields = observer._scalar_fields(words)
            self.assertEqual(fields["header_bits_u32"], word & observer.U32)
            self.assertEqual(fields["send_size_u32"], word >> 32)
            self.assertEqual(fields["receive_size_u32"], word & observer.U32)
            self.assertEqual(fields["priority_u32"], word >> 32)
            self.assertEqual(fields["timeout_word_u64"], word)

    def test_unknown_option_and_header_bits_and_ids_are_unresolved_not_an_allowlist(self):
        self.words[1] |= 1 << 63
        self.fixture.events[10] = self.fixture.frame(15, tid=20, function="mach_msg2_trap", extra=self.words)
        self.publish()
        value = self.inspect()
        message = value["messages"][0]
        fields = message["scalar_fields_under_source_contract"]
        self.assertEqual(fields["uninterpreted_option_bits_u64"], 1 << 63)
        self.assertEqual(fields["uninterpreted_header_bits_u32"], 0x20000000)
        self.assertEqual(message["semantics"], "unresolved")
        self.assertNotIn("rpc_name", message)
        self.assertNotIn("success", message)
        self.assertIn("SIP-off", value["kobject_call_caveat"])
        self.assertTrue(fields["kobject_call_requested_bit"])

    def test_vectors_reject_through_public_api_even_with_observed_return(self):
        self.words[1] |= observer.VECTOR
        self.fixture.events[10] = self.fixture.frame(15, tid=20, function="mach_msg2_trap", extra=self.words)
        self.publish()
        self.reject("vector.*unresolved")

    def test_requested_bits_do_not_assign_completion_or_effects_even_for_return_zero(self):
        self.fixture.events[11] = self.fixture.frame(16, tid=20, function="mach_msg2_trap", extra=(0,))
        self.publish()
        message = self.inspect()["messages"][0]
        self.assertEqual(message["raw_return_words"], [0])
        self.assertEqual(message["semantics"], "unresolved")
        self.assertEqual(len(message["unobserved"]), 5)
        self.assertNotIn("success", message)
        self.assertNotIn("rpc_result", message)

    def test_disabled_mach_profile_is_explicit_and_not_an_absence_claim(self):
        del self.fixture.events[10:12]
        self.publish("tree")
        value = self.inspect()
        self.assertEqual(value["messages"], [])
        self.assertFalse(value["mach_provider_enabled"])
        self.assertEqual(value["message_coverage"], "not-enabled-in-profile")
        self.publish("tree-mach")
        self.assertEqual(self.inspect()["message_coverage"], "no-selected-pairs-observed")

    def test_nonmessage_mach_pairs_remain_in_full_provenance(self):
        self.fixture.events[10] = self.fixture.frame(15, tid=20, function="task_self_trap")
        self.fixture.events[11] = self.fixture.frame(16, tid=20, function="task_self_trap", extra=(515,))
        self.publish()
        value = self.inspect()
        self.assertEqual(value["messages"], [])
        self.assertTrue(any(c["family"][2] == "task_self_trap" for c in value["paired_capture"]["calls"]))
        self.assertEqual(value["paired_capture"]["raw_frames"], self.fixture.events)

    def test_private_packing_units_reject_malformed_uint64_words(self):
        bad = ([0] * 7, [0] * 9, tuple([0] * 8))
        for words in bad:
            with self.assertRaisesRegex(observer.UnsupportedMessageObservation, "exactly 8 uint64"):
                observer._scalar_fields(words)
        for word in (-1, 1 << 64, True, 1.0, "1", None):
            words = [0] * 8
            words[4] = word
            with self.assertRaisesRegex(observer.UnsupportedMessageObservation, "uint64"):
                observer._scalar_fields(words)

    def test_public_count_bound_rejects_before_selected_result_growth(self):
        self.publish()
        with mock.patch.object(observer, "MAX_MESSAGES", 0):
            self.reject("count exceeds diagnostic bound")

    def test_strict_reader_failure_poisoned_public_api_and_no_caller_validation_override(self):
        self.publish()
        with (self.fixture.control.capture / "target.stdout").open("ab") as stream:
            stream.write(b"late uncaptured output")
        self.reject("hash mismatch")
        with self.assertRaises(TypeError):
            observer.observe_capture(self.fixture.control.capture, self.fixture.control.toolkit, validated=True)

    def test_rebuilt_hash_malformed_return_layout_is_rejected_by_public_api(self):
        value = self.fixture.events[11]
        value["records"].pop()
        self.publish()
        self.reject("record count|record layout")

    def test_pairing_failure_is_not_replaced_by_a_partial_message_observation(self):
        self.fixture.events[11]["function"] = "task_self_trap"
        self.publish()
        self.reject("descriptor|family mismatch")

    def test_acceptance_api_and_cli_always_reject(self):
        with self.assertRaises(observer.UnsupportedMessageObservation):
            observer.require_full_trace_acceptance({"full_trace_acceptance": True})
        result = subprocess.run([sys.executable, str(Path(observer.__file__)), "--capture", "/absent",
                                 "--toolkit", "/absent", "--acceptance"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("cannot satisfy", result.stderr)


if __name__ == "__main__":
    unittest.main()
