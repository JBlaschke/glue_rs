"""Conspicuously synthetic unit records; never native Darwin trace evidence."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import state_machine as state


def totals(p=1, t=1, returned=0, abandoned=0):
    return {"processes_created": p, "processes_exited": p, "threads_created": t, "threads_exited": t,
            "calls_entered": returned + abandoned, "calls_returned": returned, "calls_abandoned": abandoned}


class Units:
    def __init__(self, extra_fds=()):
        self.machine, self.records = state.StateMachine(), []
        objects = [{"id": name, "kind": kind} for name, kind in (("root-dir", "directory"), ("other-dir", "directory"), ("third-dir", "directory"), ("input", "regular"), ("file-a", "regular"), ("file-b", "regular"), ("stdout", "stdio-sink"), ("stderr", "stdio-sink"), ("pipe-a", "anonymous-pipe"))]
        self.event("start", {"process": "root", "pid": 100, "thread": "main", "tid": 1001, "objects": objects, "cwd": "root-dir",
                             "fds": [{"fd": fd, "object": name, "cloexec": False} for fd, name in ((0, "input"), (1, "stdout"), (2, "stderr"))] + list(extra_fds)})

    def event(self, event, data):
        record = {"revision": 1, "protocol": state.PROTOCOL, "origin": "synthetic-unit", "index": len(self.records) + 1, "event": event, "data": data}
        self.machine.feed(record)
        self.records.append(record)
        return record

    def enter(self, call, operation, args=None, process="root", thread="main", epoch=0):
        return self.event("call-enter", {"process": process, "thread": thread, "exec": epoch, "call": call, "operation": operation, "args": {} if args is None else args})

    def returned(self, call, value=0, error=0, obj=None, process="root", thread="main", epoch=0):
        return self.event("call-return", {"process": process, "thread": thread, "exec": epoch, "call": call, "value": value, "error": error, "object": obj})

    def call(self, call, operation, args, value=0, error=0, obj=None, **actor):
        self.enter(call, operation, args, **actor)
        self.returned(call, value, error, obj, **actor)

    def thread(self, name="worker", tid=1002, process="root", epoch=0):
        self.event("thread-start", {"process": process, "thread": name, "tid": tid, "exec": epoch})

    def fork(self, call="fork-a", child="child", pid=200):
        self.enter(call, "fork-parent")
        self.event("process-fork", {"parent": "root", "thread": "main", "exec": 0, "call": call, "child": child, "pid": pid})

    def exited(self, process="root", epoch=0, abandoned=(), status=0):
        self.event("process-exit", {"process": process, "exec": epoch, "exit_status": status, "abandoned_calls": list(abandoned)})

    def end(self, p=1, t=1, returned=0, abandoned=0):
        self.event("finish", {"records": len(self.records) + 1, "totals": totals(p, t, returned, abandoned)})
        return self.machine.finish()


def opened(path=b"relative", dirfd=None, cloexec=False):
    return {"path_hex": path.hex(), "dirfd": dirfd, "cloexec": cloexec}


class NormalizedStateTests(unittest.TestCase):
    def test_read_and_declared_sink_are_unit_consistency_only(self):
        unit = Units()
        unit.call("read-a", "read", {"fd": 0, "bytes": 10}, 10)
        unit.call("write-a", "write", {"fd": 1, "bytes": 7}, 7)
        unit.exited()
        result = unit.end(returned=2)
        self.assertEqual(result["status"], "normalized-unit-closed")
        self.assertFalse(result["full_trace_acceptance"])
        self.assertEqual(result["write_attempts"][0]["unit_intent"], "declared-sink-or-anonymous-pipe")
        self.assertEqual(result["peak_fds_per_process"], 3)
        with self.assertRaisesRegex(state.StateError, "cannot satisfy"):
            state.require_full_trace_acceptance(result)

    def test_fd_one_reuse_never_authorizes_file_write_including_failure(self):
        unit = Units()
        unit.call("close-one", "fd-close", {"fd": 1})
        unit.call("open-one", "fd-open", opened(b"/file-a"), 1, obj="file-a")
        unit.call("write-file", "write", {"fd": 1, "bytes": 20}, -1, 13)
        unit.exited()
        result = unit.end(returned=3)
        self.assertEqual(result["write_attempts"], [{"call": "write-file", "process": "root", "object": "file-a", "kind": "regular", "bytes": 20, "unit_intent": "filesystem-attempt"}])
        self.assertEqual(result["call_history"][-1]["binding"]["object"], "file-a")

    def test_pending_write_binds_original_object_across_number_reuse(self):
        unit = Units(); unit.thread()
        unit.enter("old-write", "write", {"fd": 1, "bytes": 5})
        unit.call("worker-close", "fd-close", {"fd": 1}, thread="worker")
        unit.call("worker-open", "fd-open", opened(), 1, obj="file-a", thread="worker")
        unit.returned("old-write", 5)
        unit.call("new-write", "write", {"fd": 1, "bytes": 5}, 5, thread="worker")
        unit.exited()
        result = unit.end(t=2, returned=4)
        self.assertEqual([a["object"] for a in result["write_attempts"]], ["stdout", "file-a"])

    def test_dup_flags_same_fd_and_exec_close_only_its_descriptors(self):
        unit = Units()
        unit.call("flags", "fd-flags", {"fd": 1, "cloexec": True})
        unit.call("same", "fd-dup2", {"source": 1, "target": 1}, 1)
        self.assertTrue(unit.machine.processes["root"]["fds"][1]["cloexec"])
        unit.call("alias", "fd-dup", {"source": 1}, 3)
        self.assertFalse(unit.machine.processes["root"]["fds"][3]["cloexec"])
        unit.enter("exec-a", "exec")
        unit.event("exec-success", {"process": "root", "thread": "main", "exec": 0, "call": "exec-a", "new_exec": 1, "new_thread": "after-exec", "new_tid": 1001, "abandoned_calls": ["exec-a"]})
        self.assertNotIn(1, unit.machine.processes["root"]["fds"])
        self.assertEqual(unit.machine.processes["root"]["fds"][3]["object"], "stdout")
        unit.exited(epoch=1)
        self.assertEqual(unit.end(t=2, returned=3, abandoned=1)["totals"], totals(t=2, returned=3, abandoned=1))

    def test_dup2_replaces_target_and_clears_close_on_exec(self):
        unit = Units()
        unit.call("flags", "fd-flags", {"fd": 2, "cloexec": True})
        unit.call("replace", "fd-dup2", {"source": 0, "target": 2}, 2)
        self.assertEqual(unit.machine.processes["root"]["fds"][2]["object"], "input")
        self.assertFalse(unit.machine.processes["root"]["fds"][2]["cloexec"])
        unit.exited(); unit.end(returned=2)

    def test_dup_requires_lowest_available_descriptor_in_declared_order(self):
        unit = Units(); unit.enter("dup", "fd-dup", {"source": 1})
        with self.assertRaisesRegex(state.StateError, "lowest unused"):
            unit.returned("dup", 4)

    def test_process_and_thread_cwd_and_dirfd_anchors_are_entry_snapshots(self):
        unit = Units(extra_fds=[{"fd": 7, "object": "root-dir", "cloexec": False}]); unit.thread()
        unit.call("thread-cwd", "thread-cwd-set", {"object": "other-dir"})
        unit.enter("relative-a", "fd-open", opened())
        unit.call("process-cwd", "cwd-set", {"object": "third-dir"}, thread="worker")
        unit.returned("relative-a", 10, obj="file-a")
        unit.call("clear-thread", "thread-cwd-set", {"object": None})
        unit.call("relative-b", "fd-open", opened(dirfd=-2), 11, obj="file-b")
        unit.call("directory-fd", "fd-open", opened(dirfd=7), 12, obj="file-a")
        unit.call("absolute", "fd-open", opened(b"/absolute", 999), 13, obj="file-a")
        unit.exited(); result = unit.end(t=2, returned=7)
        anchors = {h["call"]: h["anchor"] for h in result["call_history"]}
        self.assertEqual([anchors[k] for k in ("relative-a", "relative-b", "directory-fd", "absolute")], ["other-dir", "third-dir", "root-dir", None])

    def test_fchdir_tracks_directory_object_and_unknown_dirfd_rejects(self):
        unit = Units(extra_fds=[{"fd": 7, "object": "other-dir", "cloexec": False}])
        unit.call("fchdir", "cwd-from-fd", {"fd": 7})
        self.assertEqual(unit.machine.processes["root"]["cwd"], "other-dir")
        unit.exited(); unit.end(returned=1)
        for fd in (0, 999):
            unit = Units()
            with self.subTest(fd=fd), self.assertRaises(state.StateError):
                unit.enter("bad-dirfd", "fd-open", opened(dirfd=fd))

    def test_fork_keeps_independent_tables_and_child_after_parent_exit(self):
        unit = Units(); unit.call("cloexec", "fd-flags", {"fd": 1, "cloexec": True})
        unit.fork(); unit.thread("child-main", 2001, "child")
        unit.call("child-before-return", "write", {"fd": 1, "bytes": 4}, 4, process="child", thread="child-main")
        unit.returned("fork-a", 200)
        unit.enter("exec-a", "exec")
        unit.event("exec-success", {"process": "root", "thread": "main", "exec": 0, "call": "exec-a", "new_exec": 1, "new_thread": "exec-main", "new_tid": 1001, "abandoned_calls": ["exec-a"]})
        self.assertNotIn(1, unit.machine.processes["root"]["fds"])
        self.assertTrue(unit.machine.processes["child"]["fds"][1]["cloexec"])
        unit.exited(epoch=1)
        unit.call("child-after-exit", "write", {"fd": 1, "bytes": 2}, 2, process="child", thread="child-main")
        unit.exited("child")
        result = unit.end(p=2, t=3, returned=4, abandoned=1)
        self.assertEqual(result["process_edges"], [["root", "child"]])
        self.assertEqual(result["peak_live_processes"], 2)

    def test_root_exit_alone_never_closes_unit_tree(self):
        unit = Units(); unit.fork(); unit.thread("child-main", 2001, "child"); unit.returned("fork-a", 200); unit.exited()
        declared = totals(p=2, t=2, returned=1); declared.update(processes_exited=1, threads_exited=1)
        with self.assertRaisesRegex(state.StateError, "tree or pending calls incomplete"):
            unit.event("finish", {"records": len(unit.records) + 1, "totals": declared})

    def test_pid_and_tid_reuse_require_new_generation_tokens(self):
        unit = Units(); unit.fork(); unit.thread("first-thread", 2001, "child"); unit.returned("fork-a", 200); unit.exited("child")
        unit.fork("fork-b", "second-child", 200); unit.thread("second-thread", 2001, "second-child"); unit.returned("fork-b", 200)
        unit.exited("second-child"); unit.exited()
        unit.end(p=3, t=3, returned=2)
        unit = Units(); unit.fork(); unit.thread("first-thread", 2001, "child"); unit.returned("fork-a", 200); unit.exited("child")
        with self.assertRaisesRegex(state.StateError, "terminated process generation"):
            unit.enter("stale", "read", {"fd": 0, "bytes": 1}, process="child", thread="first-thread")

    def test_exec_requires_exact_abandoned_calls_and_rejects_old_epochs(self):
        unit = Units(); unit.thread(); unit.enter("blocked", "read", {"fd": 0, "bytes": 10}, thread="worker"); unit.enter("exec-a", "exec")
        unit.event("exec-success", {"process": "root", "thread": "main", "exec": 0, "call": "exec-a", "new_exec": 1, "new_thread": "exec-main", "new_tid": 1001, "abandoned_calls": ["exec-a", "blocked"]})
        unit.call("new-read", "read", {"fd": 0, "bytes": 10}, 10, thread="exec-main", epoch=1)
        unit.exited(epoch=1); unit.end(t=3, returned=1, abandoned=2)
        for wrong_epoch in (0, None, True):
            unit = Units(); unit.enter("exec-a", "exec")
            unit.event("exec-success", {"process": "root", "thread": "main", "exec": 0, "call": "exec-a", "new_exec": 1, "new_thread": "exec-main", "new_tid": 1001, "abandoned_calls": ["exec-a"]})
            with self.subTest(epoch=wrong_epoch), self.assertRaises(state.StateError):
                unit.enter("stale", "read", {"fd": 0, "bytes": 1}, thread="exec-main", epoch=wrong_epoch)
        unit = Units(); unit.enter("exec-a", "exec")
        with self.assertRaisesRegex(state.StateError, "explicit abandoned calls"):
            unit.event("exec-success", {"process": "root", "thread": "main", "exec": 0, "call": "exec-a", "new_exec": 1, "new_thread": "exec-main", "new_tid": 1001, "abandoned_calls": []})

    def test_orphan_overlap_reuse_and_incomplete_calls_poison_replay(self):
        for action in (lambda u: u.returned("orphan"), lambda u: (u.enter("a", "read", {"fd": 0, "bytes": 1}), u.enter("b", "read", {"fd": 0, "bytes": 1})),
                       lambda u: (u.call("a", "read", {"fd": 0, "bytes": 1}, 1), u.enter("a", "read", {"fd": 0, "bytes": 1})),
                       lambda u: (u.enter("a", "read", {"fd": 0, "bytes": 1}), u.returned("b", 1)),
                       lambda u: (u.enter("a", "read", {"fd": 0, "bytes": 1}), u.exited())):
            unit = Units()
            with self.subTest(action=action), self.assertRaises(state.StateError): action(unit)
            self.assertTrue(unit.machine.failed)
            with self.assertRaisesRegex(state.StateError, "poisoned"):
                unit.exited()

    def test_thread_exit_needs_exact_explicit_abandonment(self):
        unit = Units(); unit.thread(); unit.enter("blocked", "read", {"fd": 0, "bytes": 1}, thread="worker")
        unit.event("thread-exit", {"process": "root", "thread": "worker", "exec": 0, "abandoned_calls": ["blocked"]})
        unit.exited(); unit.end(t=2, abandoned=1)

    def test_failed_close_unknown_routes_and_ambiguous_cwd_reject(self):
        unit = Units(); unit.enter("close", "fd-close", {"fd": 0})
        with self.assertRaisesRegex(state.StateError, "close-on-error"):
            unit.returned("close", -1, 4)
        for operation in ("open", "posix_spawn", "ioctl", "mmap", "mprotect", "Mach", "fileport", "SCM_RIGHTS", "CLOFORK"):
            unit = Units()
            with self.subTest(operation=operation), self.assertRaisesRegex(state.StateError, "unknown normalized operation"):
                unit.enter("unknown", operation)
        for operation in ("fork-parent", "exec"):
            unit = Units(); unit.call("thread-cwd", "thread-cwd-set", {"object": "other-dir"}); unit.enter("call-a", operation)
            with self.subTest(operation=operation), self.assertRaisesRegex(state.StateError, "cwd override is uncalibrated"):
                if operation == "fork-parent": unit.event("process-fork", {"parent": "root", "thread": "main", "exec": 0, "call": "call-a", "child": "child", "pid": 200})
                else: unit.event("exec-success", {"process": "root", "thread": "main", "exec": 0, "call": "call-a", "new_exec": 1, "new_thread": "next", "new_tid": 1001, "abandoned_calls": ["call-a"]})

    def test_pending_close_rejects_descriptor_race_and_open_cannot_create_sink(self):
        unit = Units(); unit.thread(); unit.enter("close", "fd-close", {"fd": 1})
        unit.call("replace", "fd-dup2", {"source": 0, "target": 1}, 1, thread="worker")
        with self.assertRaisesRegex(state.StateError, "descriptor changed"):
            unit.returned("close")
        unit = Units(); unit.enter("open", "fd-open", opened())
        with self.assertRaisesRegex(state.StateError, "cannot manufacture"):
            unit.returned("open", 5, obj="stdout")

    def test_deep_schema_unknown_objects_limits_and_input_snapshot(self):
        for change in ({"origin": "native-kernel"}, {"protocol": "darwin-capability-raw-v1"}, {"revision": True}, {"extra": 1}, {"index": 3}):
            unit = Units(); record={"revision": 1,"protocol":state.PROTOCOL,"origin":"synthetic-unit","index":2,"event":"object-declare","data":{"object":{"id":"new","kind":"regular"}}}; record.update(change)
            with self.subTest(change=change), self.assertRaises(state.StateError): unit.machine.feed(record)
        unit = Units()
        with self.assertRaisesRegex(state.StateError, "unknown object"):
            unit.enter("cwd", "cwd-set", {"object": "unknown"})
        with mock.patch.object(state, "MAX_CALLS", 1):
            unit = Units(); unit.call("first", "read", {"fd": 0, "bytes": 1}, 1)
            with self.assertRaisesRegex(state.StateError, "call bound"):
                unit.enter("second", "read", {"fd": 0, "bytes": 1})
        unit = Units(); args={"fd":0,"bytes":1}; unit.enter("read", "read", args); args["fd"]=999
        unit.returned("read",1); unit.exited(); unit.end(returned=1)

    def test_unknown_event_and_footer_fields_truncation_and_extra_records(self):
        unit=Units()
        with self.assertRaisesRegex(state.StateError,"unknown normalized event"): unit.event("raw-syscall",{})
        unit=Units(); unit.exited()
        with self.assertRaisesRegex(state.StateError,"count mismatch"): unit.end(returned=1)
        unit=Units()
        with self.assertRaisesRegex(state.StateError,"missing or invalid"): unit.machine.finish()
        unit.exited(); unit.end()
        with self.assertRaisesRegex(state.StateError,"record after"): unit.event("object-declare",{})

    def test_cli_and_retained_synthetic_fixture(self):
        fixture=Path(__file__).parent/"synthetic-fd-reuse.jsonl"
        result=state.replay(fixture)
        self.assertEqual(result["write_attempts"][0]["object"],"payload-file")
        self.assertFalse(result["full_trace_acceptance"])
        argv=[sys.executable,str(Path(state.__file__)),"--input",str(fixture)]
        self.assertEqual(subprocess.run(argv,capture_output=True).returncode,0)
        self.assertEqual(subprocess.run(argv+["--acceptance"],capture_output=True).returncode,1)
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"bad.jsonl"
            for raw in (fixture.read_bytes()[:-1],fixture.read_bytes().replace(b'"revision":1',b'"revision":1,"revision":1',1),b'{"revision":NaN}\n'):
                path.write_bytes(raw)
                self.assertEqual(subprocess.run([*argv[:-1],str(path)],capture_output=True).returncode,1)
            path.unlink(); os.mkfifo(path)
            self.assertEqual(subprocess.run([*argv[:-1],str(path)],capture_output=True,timeout=3).returncode,1)
            path.unlink(); path.symlink_to(fixture)
            self.assertEqual(subprocess.run([*argv[:-1],str(path)],capture_output=True).returncode,1)


if __name__ == "__main__": unittest.main()
