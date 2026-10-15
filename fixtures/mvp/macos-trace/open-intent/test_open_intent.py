"""Unit semantics and standalone owned controls; not native trace evidence."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

import open_intent as intent


def request(flags=0, **changes):
    result={"revision":1,"protocol":intent.PROTOCOL,"origin":"synthetic-unit","operation":"open",
            "flags":flags,"mode":0,"path_hex":b"/synthetic/input".hex(),"dirfd":None,"result":3,"error":0}
    result.update(changes)
    return result


class OpenIntentUnits(unittest.TestCase):
    def test_write_intent_survives_failed_requests_and_readonly_create(self):
        for flags in (1,2,intent.FLAGS["O_CREAT"],intent.FLAGS["O_TRUNC"],intent.FLAGS["O_APPEND"]):
            for result,error in ((3,0),(-1,2),(-1,13)):
                with self.subTest(flags=flags,result=result,error=error):
                    decoded=intent.decode(request(flags,result=result,error=error))
                    self.assertEqual(decoded["intent"],"write-request")
                    self.assertEqual(decoded["no_output_policy"],"reject-write-intent")
                    self.assertFalse(decoded["full_trace_acceptance"])

    def test_read_and_event_requests_never_grant_acceptance(self):
        self.assertEqual(intent.decode(request())["intent"],"read-access-request")
        event=intent.FLAGS["O_EVTONLY"]
        self.assertEqual(intent.decode(request(event))["intent"],"event-access-request")
        self.assertEqual(intent.decode(request(event|intent.FLAGS["O_CREAT"]))["intent"],"write-request")
        self.assertEqual(intent.decode(request(event|intent.FLAGS["O_WRONLY"]))["intent"],"unsupported")
        with self.assertRaisesRegex(intent.UnsupportedUnit,"cannot satisfy"):
            intent.require_full_trace_acceptance([intent.decode(request())])
        with self.assertRaisesRegex(intent.UnsupportedUnit,"no calibrated"):
            intent.decode_capability({"kind":2,"records":[]})

    def test_invalid_mode_unknown_and_unmodeled_sdk_flags_reject(self):
        for flag in (3,1<<31,intent.FLAGS["O_SYMLINK"],intent.FLAGS["O_UNIQUE"],intent.FLAGS["O_EXEC"],intent.FLAGS["O_ASYNC"],intent.FLAGS["O_EXLOCK"],intent.FLAGS["O_SHLOCK"]):
            with self.subTest(flag=flag):
                decoded=intent.decode(request(flag))
                self.assertEqual(decoded["intent"],"unsupported")
                self.assertEqual(decoded["no_output_policy"],"reject-unsupported")
        self.assertEqual(intent.decode(request(1<<31))["unknown_bits"],1<<31)
        self.assertIn("O_SYMLINK",intent.decode(request(intent.FLAGS["O_SYMLINK"]))["unmodeled_sdk_flags"])

    def test_openat_dirfd_uses_canonical_darwin_values_without_truncation(self):
        for fd in (-2,0,9):
            self.assertEqual(intent.decode(request(operation="openat",dirfd=fd))["raw_normalized_request"]["dirfd"],fd)
        for fd in (-100,-1,(1<<64)-2,True,None):
            with self.subTest(fd=fd),self.assertRaises(intent.UnsupportedUnit):
                intent.decode(request(operation="openat",dirfd=fd))
        with self.assertRaisesRegex(intent.UnsupportedUnit,"open has no"):
            intent.decode(request(dirfd=-2))

    def test_unknown_routes_are_never_silent_read_only_fallbacks(self):
        for operation in ("open_nocancel","openat_nocancel","open_extended","guarded_open_np","open_dprotected_np","posix_spawn","write","mmap","fcntl","fsctl","mach_msg",""):
            with self.subTest(operation=operation),self.assertRaisesRegex(intent.UnsupportedUnit,"unsupported operation"):
                intent.decode(request(operation=operation))

    def test_exact_schema_type_path_and_return_controls(self):
        for field in intent.KEYS:
            broken=request(); del broken[field]
            with self.subTest(missing=field),self.assertRaises(intent.UnsupportedUnit): intent.decode(broken)
        broken=request(extra=True)
        with self.assertRaises(intent.UnsupportedUnit): intent.decode(broken)
        for field,values in {"flags":[True,-1,1<<32,"0",[]],"mode":[True,-1,1<<16],"result":[True,-2,1<<31],"error":[True,-1],"path_hex":["", "00", "ff\n", "fF", "f", "11"*1024],"origin":[[],"native-kernel"],"operation":[[]],"revision":[True],"protocol":[intent.ABI["protocol"]]}.items():
            for value in values:
                with self.subTest(field=field,value=str(value)[:30]),self.assertRaises(intent.UnsupportedUnit): intent.decode(request(**{field:value}))
        for result,error in ((-1,0),(0,2)):
            with self.assertRaisesRegex(intent.UnsupportedUnit,"inconsistent"):
                intent.decode(request(result=result,error=error))

    def test_json_duplicate_nonfinite_and_size_controls(self):
        for raw in (b'{"revision":1,"revision":1}',b'{"flags":NaN}',b'['*1500,b'x'*8193):
            with self.assertRaises(intent.UnsupportedUnit): intent.load_json(raw)

    def test_cli_regular_file_bounds_unknown_and_acceptance(self):
        with tempfile.TemporaryDirectory(prefix="glue open unit ") as temporary:
            root=Path(temporary); path=root/"units.jsonl"
            path.write_text(json.dumps(request())+"\n")
            argv=[sys.executable,str(intent.SOURCE/"open_intent.py"),"--input",str(path)]
            result=subprocess.run(argv,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse(json.loads(result.stdout)["full_trace_acceptance"])
            self.assertEqual(subprocess.run(argv+["--acceptance"],capture_output=True).returncode,1)
            path.write_text(json.dumps(request(1<<31))+"\n")
            self.assertEqual(subprocess.run(argv,capture_output=True).returncode,1)
            path.write_text(json.dumps(request()))
            self.assertEqual(subprocess.run(argv,capture_output=True).returncode,1)
            path.unlink(); os.mkfifo(path)
            self.assertEqual(subprocess.run(argv,capture_output=True,timeout=3).returncode,1)


@unittest.skipUnless(platform.system()=="Darwin" and platform.machine()=="arm64","requires native Darwin arm64")
class NativeOwnedControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix="glue open controls ü ")
        cls.root=Path(cls.temporary.name).resolve()
        cls.toolkit=cls.root/"toolkit"
        result=subprocess.run(["/bin/sh",str(intent.SOURCE/"prepare-controls.sh"),str(cls.toolkit)],capture_output=True)
        if result.returncode: raise AssertionError(result.stderr.decode())
        cls.executable=cls.toolkit/"open-control"

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_actual_sdk_constants_widths_minimum_and_signature(self):
        observed=json.loads(subprocess.run([str(self.executable),"--describe"],check=True,capture_output=True).stdout)
        self.assertEqual(observed,intent.ABI)
        subprocess.run(["/usr/bin/codesign","--verify","--strict",str(self.executable)],check=True,capture_output=True)
        commands=(self.toolkit/"load-commands.txt").read_text()
        self.assertIn("minos 11.0",commands); self.assertIn("sdk 26.5",commands)
        self.assertEqual((self.toolkit/"libraries.txt").read_text().count("/usr/lib/"),1)

    def test_all_native_owned_modes_have_expected_requests_and_effects(self):
        modes={"read-open":"read-access-request","event-only":"event-access-request","readwrite-open":"write-request","append-open":"write-request","denied-write-open":"write-request","readonly-create":"write-request","truncate-open":"write-request","create-unlink":"write-request","openat-dirfd":"write-request","openat-fdcwd":"write-request"}
        for mode,expected in modes.items():
            with self.subTest(mode=mode):
                root=self.root/mode
                subprocess.run([str(self.executable),"--prepare",str(root)],check=True,capture_output=True)
                result=subprocess.run([str(self.executable),"--run",mode,str(root)],capture_output=True,timeout=7)
                self.assertEqual(result.returncode,0,result.stderr)
                records=[intent.load_json(line) for line in result.stdout.splitlines()]
                self.assertEqual(len(records),2 if mode=="openat-dirfd" else 1)
                decoded=[intent.decode(record) for record in records]
                self.assertEqual(decoded[-1]["intent"],expected)
                self.assertTrue(all(d["origin"]=="owned-control-self-report" and d["full_trace_acceptance"] is False for d in decoded))
                report=json.loads(result.stderr)
                self.assertTrue(report["expected_result_observed"])
                self.assertFalse(report["full_trace_acceptance"])
                self.assertEqual((root/"input.txt").read_bytes(),b"owned trace fixture\n")
                if mode=="denied-write-open":
                    self.assertEqual((records[-1]["result"],records[-1]["error"]),(-1,2))
                    self.assertFalse((root/"missing-parent").exists())
                elif mode=="truncate-open": self.assertEqual((root/"mutable.txt").read_bytes(),b"")
                elif mode=="readonly-create": self.assertEqual((root/"readonly-created").read_bytes(),b"")
                elif mode=="create-unlink":
                    self.assertEqual((report["write_result"],report["unlink_result"]),(20,0))
                    self.assertFalse((root/"created-then-unlinked").exists())
                elif mode=="openat-dirfd":
                    self.assertGreaterEqual(records[-1]["dirfd"],0)
                    self.assertEqual((root/"created-at").read_bytes(),b"")
                elif mode=="openat-fdcwd":
                    self.assertEqual(records[-1]["dirfd"],-2)
                    self.assertEqual((root/"created-fdcwd").read_bytes(),b"")

    def test_unowned_bad_arguments_and_linked_inputs_reject(self):
        for args in ([],["--run","unknown","/"],["--run","read-open"],["--prepare","relative"]):
            self.assertEqual(subprocess.run([str(self.executable),*args],capture_output=True).returncode,2)
        root=self.root/"linked-input"
        subprocess.run([str(self.executable),"--prepare",str(root)],check=True,capture_output=True)
        mutable=root/"mutable.txt"; mutable.unlink(); mutable.symlink_to(root/"input.txt")
        result=subprocess.run([str(self.executable),"--run","truncate-open",str(root)],capture_output=True)
        self.assertEqual(result.returncode,1)
        self.assertEqual((root/"input.txt").read_bytes(),b"owned trace fixture\n")
        self.assertEqual(result.stdout,b"")


if __name__=="__main__": unittest.main()
