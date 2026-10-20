"""Synthetic mapping controls; this suite supplies no native Darwin evidence."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import mapping_state as m


READ, WRITE, EXEC = 1, 2, 4
SHARED, PRIVATE, ANON = 1, 2, 0x1000
PAGE = 4096


class Units:
    """Only generate records; expected range operations below are independent."""

    def __init__(self, page=PAGE, process=True, backing=True):
        self.machine, self.records = m.MappingMachine(), []
        self.event("start", {"page_size": page})
        if process:
            self.process()
        if backing:
            self.backing()

    def event(self, event, data):
        record = {"revision": 1, "protocol": m.PROTOCOL,
                  "origin": "synthetic-unit", "index": len(self.records) + 1,
                  "event": event, "data": data}
        self.machine.feed(record)
        self.records.append(copy.deepcopy(record))
        return record

    def process(self, process="p", pid=101):
        return self.event("process", {"process": process, "pid": pid, "exec": 0})

    def backing(self, backing="a"):
        return self.event("backing", {"backing": backing, "kind": "regular"})

    def enter(self, call, operation, args, process="p", epoch=0):
        return self.event("enter", {"process": process, "exec": epoch,
                                   "call": call, "operation": operation, "args": args})

    def returned(self, call, operation, result=0, error=0, process="p", epoch=0):
        return self.event("returned", {"process": process, "exec": epoch,
                                      "call": call, "operation": operation,
                                      "result": result, "error": error})

    def call(self, call, operation, args, result=0, error=0, **actor):
        self.enter(call, operation, args, **actor)
        self.returned(call, operation, result, error, **actor)

    def map(self, token="map-a", address=PAGE, length=PAGE, prot=READ,
            flags=SHARED, backing="a", offset=0, call=None, **actor):
        args = map_args(token, length=length, prot=prot, flags=flags,
                        backing=backing, offset=offset)
        self.call(call or "call-" + token, "map", args, address, **actor)

    def fragments(self, process="p"):
        return self.machine.processes[process]["fragments"]

    def retire(self, process="p", epoch=0, mappings=None):
        if mappings is None:
            mappings = sorted({f["mapping"] for f in self.fragments(process)})
        return self.event("retire", {"process": process, "exec": epoch,
                                     "mappings": mappings})

    def end(self, totals=None):
        self.event("finish", {"records": len(self.records) + 1,
                              "totals": dict(self.machine.totals) if totals is None else totals})
        return self.machine.finish()

    def raw(self):
        return b"".join(json.dumps(r, separators=(",", ":")).encode("ascii") + b"\n"
                        for r in self.records)


def map_args(mapping="map-a", length=PAGE, prot=READ, flags=SHARED,
             backing="a", offset=0):
    return {"mapping": mapping, "address": 0, "length": length,
            "prot": prot, "flags": flags, "offset": offset, "backing": backing}


def fragment(mapping, backing, start, end, offset, prot=READ, flags=SHARED):
    return {"mapping": mapping, "backing": backing, "start": start, "end": end,
            "offset": offset, "flags": flags, "prot": prot}


def project(fragments):
    return [{k: f[k] for k in ("mapping", "backing", "start", "end", "offset", "flags", "prot")}
            for f in sorted(fragments, key=lambda f: f["start"])]


class PageGrid:
    """One cell per page: no engine split, coverage or coalescing helpers."""

    def __init__(self, page):
        self.page, self.cells = page, {}

    def map(self, token, backing, start, length, offset, prot, flags):
        for address in range(start, start + length, self.page):
            if address in self.cells:
                raise AssertionError("reference overlap")
            self.cells[address] = (token, backing,
                                   None if backing is None else offset + address - start,
                                   prot, flags)

    def protect(self, start, length, prot):
        for address in range(start, start + length, self.page):
            token, backing, offset, _, flags = self.cells[address]
            self.cells[address] = token, backing, offset, prot, flags

    def unmap(self, start, length):
        for address in range(start, start + length, self.page):
            del self.cells[address]

    def shared_write(self, start, length):
        return any(self.cells[a][1] is not None and self.cells[a][4] == SHARED
                   for a in range(start, start + length, self.page))

    def observed(self, fragments):
        cells = {}
        for f in fragments:
            for address in range(f["start"], f["end"], self.page):
                if address in cells:
                    raise AssertionError("engine produced overlapping fragments")
                offset = None if f["backing"] is None else f["offset"] + address - f["start"]
                cells[address] = f["mapping"], f["backing"], offset, f["prot"], f["flags"]
        return cells


class MappingStateTests(unittest.TestCase):
    def assert_poisoned(self, unit):
        with self.assertRaises(m.MappingError):
            unit.machine.finish()
        with self.assertRaises(m.MappingError):
            unit.event("backing", {"backing": "cannot-repair", "kind": "regular"})

    def reject_enter(self, args, operation="map"):
        unit = Units()
        with self.assertRaises(m.MappingError):
            unit.enter("bad", operation, args)
        self.assert_poisoned(unit)

    def test_literal_split_protection_unmap_and_reuse_keep_generations(self):
        unit = Units(); unit.backing("b")
        unit.map(length=6 * PAGE, offset=2 * PAGE)
        unit.call("protect-middle", "protect", {"address": 2 * PAGE, "length": 3 * PAGE, "prot": READ | WRITE})
        self.assertEqual(project(unit.fragments()), [
            fragment("map-a", "a", PAGE, 2 * PAGE, 2 * PAGE),
            fragment("map-a", "a", 2 * PAGE, 5 * PAGE, 3 * PAGE, READ | WRITE),
            fragment("map-a", "a", 5 * PAGE, 7 * PAGE, 6 * PAGE)])
        unit.call("remove-middle", "unmap", {"address": 3 * PAGE, "length": 3 * PAGE})
        self.assertEqual(project(unit.fragments()), [
            fragment("map-a", "a", PAGE, 2 * PAGE, 2 * PAGE),
            fragment("map-a", "a", 2 * PAGE, 3 * PAGE, 3 * PAGE, READ | WRITE),
            fragment("map-a", "a", 6 * PAGE, 7 * PAGE, 7 * PAGE)])
        unit.map("map-b", 3 * PAGE, 3 * PAGE, backing="b", offset=8 * PAGE)
        self.assertEqual(project(unit.fragments())[2],
                         fragment("map-b", "b", 3 * PAGE, 6 * PAGE, 8 * PAGE))
        unit.retire(); result = unit.end()
        self.assertFalse(result["full_trace_acceptance"])
        self.assertEqual(result["totals"], {
            "processes_created": 1, "processes_retired": 1, "backings_declared": 2,
            "calls_entered": 4, "calls_returned": 4, "mappings_requested": 2,
            "maps_installed": 2, "protects_completed": 1, "unmaps_completed": 1,
            "exec_boundaries": 0, "shared_write_attempts": 1})

    def test_adjacent_backings_and_existing_writable_requests_are_retained(self):
        unit = Units(); unit.backing("b")
        unit.map("map-a", PAGE, 2 * PAGE, prot=READ | WRITE)
        unit.map("map-b", 3 * PAGE, 2 * PAGE, backing="b", offset=8 * PAGE)
        unit.call("span-write", "protect", {"address": 2 * PAGE, "length": 2 * PAGE, "prot": WRITE})
        unit.call("repeat-write", "protect", {"address": PAGE, "length": PAGE, "prot": READ | WRITE})
        self.assertEqual({f["backing"] for f in unit.fragments()}, {"a", "b"})
        self.assertEqual(project(unit.fragments()), [
            fragment("map-a", "a", PAGE, 2 * PAGE, 0, READ | WRITE),
            fragment("map-a", "a", 2 * PAGE, 3 * PAGE, PAGE, WRITE),
            fragment("map-b", "b", 3 * PAGE, 4 * PAGE, 8 * PAGE, WRITE),
            fragment("map-b", "b", 4 * PAGE, 5 * PAGE, 9 * PAGE)])
        unit.retire(); result = unit.end()
        self.assertEqual(result["totals"]["shared_write_attempts"], 3)
        self.assertEqual([a["call"] for a in result["attempts"]],
                         ["call-map-a", "span-write", "repeat-write"])

    def test_private_and_anonymous_writes_never_hide_shared_intent(self):
        unit = Units()
        unit.map("shared", PAGE, prot=WRITE)
        unit.map("private", 2 * PAGE, prot=WRITE, flags=PRIVATE)
        unit.map("anon", 3 * PAGE, prot=WRITE, flags=PRIVATE | ANON, backing=None)
        unit.call("private-protect", "protect", {"address": 2 * PAGE, "length": 2 * PAGE, "prot": WRITE | EXEC})
        self.assertEqual(project(unit.fragments())[2],
                         fragment("anon", None, 3 * PAGE, 4 * PAGE, None, WRITE | EXEC, PRIVATE | ANON))
        unit.retire(); result = unit.end()
        self.assertEqual(result["totals"]["shared_write_attempts"], 1)
        self.assertEqual([a["call"] for a in result["attempts"]], ["call-shared"])
        self.assertFalse(result["full_trace_acceptance"])

    def test_failed_map_has_no_address_and_consumes_mapping_generation(self):
        unit = Units()
        unit.enter("failed", "map", map_args(prot=WRITE))
        self.assertEqual(unit.machine.attempts[0], {
            "call": "failed", "entry_index": 4, "process": "p", "exec": 0,
            "operation": "map", "address": None, "length": PAGE,
            "prot": WRITE, "flags": SHARED,
            "fragments": [fragment("map-a", "a", None, None, 0, WRITE)],
            "outcome": "pending", "result": None, "error": None})
        unit.returned("failed", "map", None, 13)
        self.assertEqual(unit.fragments(), [])
        unit.retire(); result = unit.end()
        self.assertEqual(result["totals"]["maps_installed"], 0)
        self.assertEqual(result["totals"]["shared_write_attempts"], 1)
        self.assertEqual(result["attempts"][0]["call"], "failed")
        self.assertEqual({k: result["attempts"][0][k] for k in ("address", "result", "error", "outcome")},
                         {"address": None, "result": None, "error": 13, "outcome": "failed"})
        self.assertFalse(result["full_trace_acceptance"])
        unit = Units(); unit.call("failed", "map", map_args(), None, 12)
        with self.assertRaises(m.MappingError):
            unit.enter("retry", "map", map_args())
        self.assert_poisoned(unit)

    def test_failed_range_changes_poison_and_preserve_entry_write_intent(self):
        for operation in ("protect", "unmap"):
            unit = Units(); unit.map(length=3 * PAGE)
            args = {"address": PAGE, "length": PAGE}
            if operation == "protect": args["prot"] = WRITE
            before = copy.deepcopy(project(unit.fragments()))
            unit.enter("failure", operation, args)
            with self.subTest(operation=operation), self.assertRaises(m.MappingError) as caught:
                unit.returned("failure", operation, -1, 13)
            self.assertEqual(caught.exception.code, "ambiguous-effect")
            self.assertEqual(project(unit.fragments()), before)
            rejection = unit.machine.rejection(caught.exception)
            self.assertFalse(rejection["full_trace_acceptance"])
            if operation == "protect":
                self.assertEqual([a["call"] for a in rejection["attempts"]], ["failure"])
                self.assertEqual(rejection["attempts"][0]["outcome"], "failed")
                self.assertEqual(rejection["attempts"][0]["result"], -1)
                self.assertEqual(rejection["attempts"][0]["error"], 13)
            self.assert_poisoned(unit)

    def test_map_and_fragment_backing_are_detached_from_caller_mutation(self):
        unit = Units(); unit.backing("b")
        args = map_args(length=2 * PAGE)
        unit.enter("first", "map", args)
        args.update(backing="b", length=PAGE, prot=WRITE)
        unit.returned("first", "map", PAGE)
        self.assertEqual(project(unit.fragments()),
                         [fragment("map-a", "a", PAGE, 3 * PAGE, 0)])
        unit.call("upgrade", "protect", {"address": PAGE, "length": PAGE, "prot": WRITE})
        self.assertTrue(all(f["backing"] == "a" for f in unit.fragments()))
        unit.retire(); result = unit.end()
        self.assertEqual(result["attempts"][0]["call"], "upgrade")

    def test_independent_page_grid_matches_bounded_transition_sequences(self):
        for page in (4096, 16384):
            unit = Units(page=page); unit.backing("b")
            grid, rng, expected_attempt_calls = PageGrid(page), random.Random(2917), []
            generation = 0
            for step in range(160):
                occupied = sorted(a // page for a in grid.cells)
                free = [n for n in range(1, 25) if n not in occupied]
                operation = rng.choice(["map"] if not occupied else ["protect", "unmap", "map"] if free else ["protect", "unmap"])
                call = "grid-call-" + str(step)
                if operation == "map":
                    first = rng.choice(free); end = first + 1
                    while end in free and end < first + 4 and rng.randrange(2): end += 1
                    start, length = first * page, (end - first) * page
                    generation += 1; token = "grid-map-" + str(generation)
                    flags = rng.choice([SHARED, PRIVATE, PRIVATE | ANON])
                    backing = None if flags & ANON else rng.choice(["a", "b"])
                    offset, prot = (0 if backing is None else rng.randrange(8) * page), rng.randrange(8)
                    unit.map(token, start, length, prot, flags, backing, offset, call=call)
                    grid.map(token, backing, start, length, offset, prot, flags)
                    if flags == SHARED and prot & WRITE: expected_attempt_calls.append(call)
                else:
                    first = rng.choice(occupied); end = first + 1
                    while end in occupied and end < first + 5 and rng.randrange(2): end += 1
                    start, length = first * page, (end - first) * page
                    args = {"address": start, "length": length}
                    if operation == "protect":
                        prot = rng.randrange(8); args["prot"] = prot
                        if prot & WRITE and grid.shared_write(start, length): expected_attempt_calls.append(call)
                        unit.call(call, operation, args); grid.protect(start, length, prot)
                    else:
                        unit.call(call, operation, args); grid.unmap(start, length)
                with self.subTest(page=page, step=step, operation=operation):
                    self.assertEqual(grid.observed(unit.fragments()), grid.cells)
            unit.retire(); result = unit.end()
            self.assertEqual([a["call"] for a in result["attempts"]], expected_attempt_calls)
            self.assertEqual(result["totals"]["calls_returned"], 160)

    def test_mapping_and_call_tokens_have_distinct_unique_namespaces(self):
        unit = Units(); unit.map("same-token", call="same-token")
        unit.call("unmap", "unmap", {"address": PAGE, "length": PAGE})
        with self.assertRaises(m.MappingError):
            unit.map("same-token", call="fresh-call")
        self.assert_poisoned(unit)
        unit = Units(); unit.map("first", call="used-call")
        with self.assertRaises(m.MappingError):
            unit.enter("used-call", "map", map_args("second"))
        self.assert_poisoned(unit)

    def test_pending_call_pairing_actor_epoch_and_serialization_are_exact(self):
        for change in ({"call": "wrong"}, {"operation": "unmap"}, {"process": "other"}, {"exec": 1}):
            unit = Units(); unit.process("other", 202)
            unit.enter("pending", "map", map_args())
            data = {"process": "p", "exec": 0, "call": "pending", "operation": "map", "result": PAGE, "error": 0}
            data.update(change)
            with self.subTest(change=change), self.assertRaises(m.MappingError): unit.event("returned", data)
            self.assert_poisoned(unit)
        unit = Units(); unit.enter("pending", "map", map_args())
        with self.assertRaises(m.MappingError): unit.enter("overlap", "map", map_args("other"))
        self.assert_poisoned(unit)
        unit = Units()
        with self.assertRaises(m.MappingError): unit.returned("orphan", "map", PAGE)
        self.assert_poisoned(unit)

    def test_processes_are_independent_and_pid_reuse_requires_retirement(self):
        unit = Units(); unit.process("q", 202)
        unit.enter("p-map", "map", map_args("p-range"))
        unit.enter("q-map", "map", map_args("q-range", flags=PRIVATE), process="q")
        unit.returned("q-map", "map", PAGE, process="q")
        unit.returned("p-map", "map", PAGE)
        self.assertEqual(unit.fragments()[0]["mapping"], "p-range")
        self.assertEqual(unit.fragments("q")[0]["mapping"], "q-range")
        unit.retire(); unit.process("p-next", 101); unit.retire("p-next"); unit.retire("q")
        result = unit.end(); self.assertEqual(result["totals"]["processes_created"], 3)
        unit = Units()
        with self.assertRaises(m.MappingError): unit.process("q", 101)
        self.assert_poisoned(unit)

    def test_exec_requires_empty_state_and_exact_one_step_epoch(self):
        unit = Units(); unit.event("exec", {"process": "p", "exec": 0, "new_exec": 1})
        unit.map(epoch=1); unit.retire(epoch=1); result = unit.end()
        self.assertEqual(result["totals"]["exec_boundaries"], 1)
        for setup, event in ((lambda u: u.map(), {"process": "p", "exec": 0, "new_exec": 1}),
                             (lambda u: u.enter("pending", "map", map_args()), {"process": "p", "exec": 0, "new_exec": 1}),
                             (lambda u: None, {"process": "p", "exec": 0, "new_exec": 2})):
            unit = Units(); setup(unit)
            with self.subTest(event=event), self.assertRaises(m.MappingError): unit.event("exec", event)
            self.assert_poisoned(unit)
        unit = Units(); unit.event("exec", {"process": "p", "exec": 0, "new_exec": 1})
        with self.assertRaises(m.MappingError): unit.map()
        self.assert_poisoned(unit)

    def test_retirement_requires_exact_mapping_set_and_preserves_history(self):
        unit = Units(); unit.map(prot=WRITE, length=3 * PAGE)
        unit.call("split", "protect", {"address": 2 * PAGE, "length": PAGE, "prot": READ})
        unit.retire(mappings=["map-a"]); result = unit.end()
        self.assertEqual(result["totals"]["shared_write_attempts"], 1)
        self.assertTrue(result["history"])
        for mappings in ([], ["unknown"], ["map-a", "map-a"], ["map-a", "extra"]):
            unit = Units(); unit.map()
            with self.subTest(mappings=mappings), self.assertRaises(m.MappingError): unit.retire(mappings=mappings)
            self.assert_poisoned(unit)
        unit = Units(); unit.retire()
        with self.assertRaises(m.MappingError): unit.process()
        self.assert_poisoned(unit)

    def test_holes_overlaps_and_unknown_backings_reject(self):
        for operation in ("protect", "unmap"):
            unit = Units(); unit.map(); unit.map("right", 3 * PAGE)
            args = {"address": PAGE, "length": 3 * PAGE}
            if operation == "protect": args["prot"] = WRITE
            with self.subTest(operation=operation), self.assertRaises(m.MappingError): unit.enter("gap", operation, args)
            self.assert_poisoned(unit)
        unit = Units(); unit.map(length=2 * PAGE)
        with self.assertRaises(m.MappingError): unit.map("overlap", 2 * PAGE)
        self.assert_poisoned(unit)
        self.reject_enter(map_args(backing="undeclared"))

    def test_unsupported_flags_protections_routes_and_inheritance_reject_even_failure(self):
        for flags in (0, 3, SHARED | ANON, ANON, PRIVATE | 0x10,
                      PRIVATE | 0x800, PRIVATE | 0x80000, PRIVATE | 0x1000000):
            with self.subTest(flags=flags): self.reject_enter(map_args(flags=flags))
        for prot in (-1, 8, 0x1000):
            with self.subTest(prot=prot): self.reject_enter(map_args(prot=prot))
        for operation in ("mmap", "mprotect", "mach_vm_map", "mach_vm_remap", "msync", "fork", "spawn", "fd-close"):
            unit = Units()
            with self.subTest(operation=operation), self.assertRaises(m.MappingError): unit.enter("unsupported", operation, {})
            self.assert_poisoned(unit)
        for event in ("fork", "vfork", "spawn", "inherit", "native-start", "raw-syscall"):
            unit = Units()
            with self.subTest(event=event), self.assertRaises(m.MappingError): unit.event(event, {})
            self.assert_poisoned(unit)

    def test_anonymous_and_file_backing_combinations_are_closed(self):
        for args in (map_args(backing=None), map_args(flags=PRIVATE | ANON),
                     map_args(flags=PRIVATE | ANON, backing=None, offset=PAGE),
                     map_args(backing=1), map_args(flags=SHARED, backing="a", offset=-PAGE)):
            with self.subTest(args=args): self.reject_enter(args)

    def test_address_alignment_domain_offsets_and_canonical_types(self):
        for field, bad in (("address", PAGE), ("length", 0), ("length", PAGE + 1),
                           ("length", -PAGE), ("length", 1 << 64), ("offset", 1),
                           ("offset", 1 << 63), ("offset", (1 << 63) - PAGE),
                           ("length", True), ("prot", False), ("offset", 0.0)):
            args = map_args(); args[field] = bad
            with self.subTest(field=field, bad=bad): self.reject_enter(args)
        for result in (0, 1, PAGE + 1, -PAGE, True, float(PAGE), (1 << 64) - PAGE, 1 << 64):
            unit = Units(); unit.enter("range", "map", map_args())
            with self.subTest(result=result), self.assertRaises(m.MappingError): unit.returned("range", "map", result)
            self.assert_poisoned(unit)
        for address, length in ((0, PAGE), (PAGE + 1, PAGE), (PAGE, PAGE - 1), ((1 << 64) - PAGE, PAGE)):
            unit = Units(); unit.map(length=2 * PAGE)
            with self.subTest(address=address, length=length), self.assertRaises(m.MappingError):
                unit.enter("range", "unmap", {"address": address, "length": length})
            self.assert_poisoned(unit)
        class IntegerSubclass(int): pass
        self.reject_enter(map_args(prot=IntegerSubclass(READ)))

    def test_canonical_return_pairs_are_operation_specific(self):
        for result, error in ((None, 0), (PAGE, 1), (-1, 13), (True, 0), (PAGE, False), (None, -1)):
            unit = Units(); unit.enter("bad", "map", map_args())
            with self.subTest(result=result, error=error), self.assertRaises(m.MappingError): unit.returned("bad", "map", result, error)
            self.assert_poisoned(unit)
        for operation in ("protect", "unmap"):
            for result, error in ((1, 0), (-1, 0), (0, 13), (None, 13), (0, True)):
                unit = Units(); unit.map()
                args = {"address": PAGE, "length": PAGE}
                if operation == "protect": args["prot"] = READ
                unit.enter("bad", operation, args)
                with self.subTest(operation=operation, result=result, error=error), self.assertRaises(m.MappingError):
                    unit.returned("bad", operation, result, error)
                self.assert_poisoned(unit)

    def test_envelope_tokens_and_closed_schemas_poison(self):
        for change in ({"revision": True}, {"revision": 2}, {"origin": "native"},
                       {"protocol": "darwin-normalized-state-unit-v1"}, {"index": 99},
                       {"index": True}, {"native_validation": True}):
            unit = Units()
            record = {"revision": 1, "protocol": m.PROTOCOL, "origin": "synthetic-unit",
                      "index": len(unit.records) + 1, "event": "backing",
                      "data": {"backing": "b", "kind": "regular"}}
            record.update(change)
            with self.subTest(change=change), self.assertRaises(m.MappingError): unit.machine.feed(record)
            self.assert_poisoned(unit)
        for token in ("", "x" * 65, "white space", "slash/name", "é", True, 1, None):
            unit = Units()
            with self.subTest(token=token), self.assertRaises(m.MappingError): unit.backing(token)
            self.assert_poisoned(unit)
        for event, data in (("process", {"process": "other", "pid": 202, "exec": 0, "parent": "p"}),
                            ("backing", {"backing": "b", "kind": "device"}),
                            ("backing", {"backing": "b"}),
                            ("enter", {"process": "p", "exec": 0, "call": "bad", "operation": "map", "args": {**map_args(), "allowed_output": True}})):
            unit = Units()
            with self.subTest(event=event, data=data), self.assertRaises(m.MappingError): unit.event(event, data)
            self.assert_poisoned(unit)

    def test_exact_footer_requires_every_process_terminal_and_no_pending(self):
        for setup in (lambda u: None, lambda u: u.enter("pending", "map", map_args())):
            unit = Units(); setup(unit)
            with self.assertRaises(m.MappingError): unit.end()
            self.assert_poisoned(unit)
        for change in ({"records": 0}, {"records": True}, {"totals": {}}, {"accepted": True}):
            unit = Units(); unit.retire()
            data = {"records": len(unit.records) + 1, "totals": dict(unit.machine.totals)}
            data.update(change)
            with self.subTest(change=change), self.assertRaises(m.MappingError): unit.event("finish", data)
            self.assert_poisoned(unit)
        unit = Units(); unit.retire(); wrong = dict(unit.machine.totals); wrong["calls_entered"] += 1
        with self.assertRaises(m.MappingError): unit.end(wrong)
        self.assert_poisoned(unit)
        unit = Units(); unit.retire(); unit.end()
        with self.assertRaises(m.MappingError): unit.backing("after-footer")

    def test_no_report_before_footer_and_input_snapshot_is_not_resumable(self):
        unit = Units(); unit.map(prot=WRITE)
        with self.assertRaises(m.MappingError):
            unit.machine._report()
        with self.assertRaises(m.MappingError) as caught: unit.machine.finish()
        diagnostic = unit.machine.rejection(caught.exception)
        self.assertFalse(diagnostic["full_trace_acceptance"])
        self.assertEqual(diagnostic["attempts"][0]["call"], "call-map-a")
        with self.assertRaises(m.MappingError): m.MappingMachine().feed(diagnostic)

    def test_entry_attempt_clips_shared_fragments_and_retains_entry_protection(self):
        unit = Units(); unit.backing("b")
        unit.map("left", PAGE, 2 * PAGE, prot=READ, offset=4 * PAGE)
        unit.map("private-middle", 3 * PAGE, prot=WRITE, flags=PRIVATE)
        unit.map("right", 4 * PAGE, 2 * PAGE, prot=EXEC, backing="b", offset=8 * PAGE)
        unit.enter("upgrade", "protect", {"address": 2 * PAGE, "length": 3 * PAGE, "prot": READ | WRITE})
        self.assertEqual(unit.machine.attempts, [{
            "call": "upgrade", "entry_index": 11, "process": "p", "exec": 0,
            "operation": "protect", "address": 2 * PAGE, "length": 3 * PAGE,
            "prot": READ | WRITE, "flags": None,
            "fragments": [fragment("left", "a", 2 * PAGE, 3 * PAGE, 5 * PAGE),
                          fragment("right", "b", 4 * PAGE, 5 * PAGE, 8 * PAGE, EXEC)],
            "outcome": "pending", "result": None, "error": None}])
        unit.returned("upgrade", "protect")
        self.assertEqual(unit.machine.attempts[0]["outcome"], "success")
        self.assertEqual(unit.machine.attempts[0]["fragments"][0]["prot"], READ)
        self.assertEqual(unit.machine.attempts[0]["fragments"][1]["prot"], EXEC)
        unit.retire(); unit.end()

    def test_declaration_call_and_record_limits_count_generations(self):
        with mock.patch.object(m, "MAX_PROCESSES", 1):
            unit = Units(); unit.retire()
            with self.assertRaises(m.MappingError): unit.process("next", 101)
            self.assert_poisoned(unit)
        with mock.patch.object(m, "MAX_BACKINGS", 1):
            unit = Units()
            with self.assertRaises(m.MappingError): unit.backing("b")
            self.assert_poisoned(unit)
        with mock.patch.object(m, "MAX_CALLS", 1):
            unit = Units(); unit.call("failed", "map", map_args(), None, 12)
            with self.assertRaises(m.MappingError): unit.enter("second", "map", map_args("second"))
            self.assert_poisoned(unit)
        with mock.patch.object(m, "MAX_RECORDS", 3):
            unit = Units()
            with self.assertRaises(m.MappingError): unit.retire()
            self.assert_poisoned(unit)

    def test_fragment_growth_is_refused_before_live_range_mutation(self):
        unit = Units(); unit.map(length=3 * PAGE)
        before = copy.deepcopy(project(unit.fragments()))
        with mock.patch.object(m, "MAX_FRAGMENTS", 2):
            with self.assertRaises(m.MappingError):
                unit.call("split", "protect", {"address": 2 * PAGE, "length": PAGE, "prot": WRITE})
        self.assertEqual(project(unit.fragments()), before)
        self.assert_poisoned(unit)
        with mock.patch.object(m, "MAX_FRAGMENTS", 1):
            unit = Units(); unit.map()
            with self.assertRaises(m.MappingError): unit.map("second", 3 * PAGE)
            self.assertEqual(project(unit.fragments()), [fragment("map-a", "a", PAGE, 2 * PAGE, 0)])
            self.assert_poisoned(unit)

    def test_attempt_and_copied_fragment_limits_include_accumulated_history(self):
        for constant, limit in (("MAX_ATTEMPTS", 1), ("MAX_ATTEMPT_FRAGMENTS", 2)):
            with mock.patch.object(m, constant, limit):
                unit = Units(); unit.map(prot=WRITE)
                before = copy.deepcopy(project(unit.fragments()))
                with self.subTest(constant=constant), self.assertRaises(m.MappingError):
                    unit.enter("second-write", "protect", {"address": PAGE, "length": PAGE, "prot": WRITE})
                self.assertEqual(project(unit.fragments()), before)
                self.assertEqual(len(unit.machine.attempts), 1)
                self.assert_poisoned(unit)
        for constant in ("MAX_SNAPSHOT_FRAGMENTS", "MAX_HISTORY"):
            unit = Units(); unit.map(length=3 * PAGE)
            before = copy.deepcopy(project(unit.fragments()))
            with mock.patch.object(m, constant, 0):
                with self.subTest(constant=constant), self.assertRaises(m.MappingError):
                    unit.enter("next", "unmap", {"address": 2 * PAGE, "length": PAGE})
            self.assertEqual(project(unit.fragments()), before)
            self.assert_poisoned(unit)

    def test_cumulative_snapshot_budget_counts_each_retained_entry_and_result_copy(self):
        with mock.patch.object(m, "MAX_SNAPSHOT_FRAGMENTS", 11):
            unit = Units(); unit.map(length=3 * PAGE)
            self.assertEqual(unit.machine.snapshot_fragments, 2)
            unit.call("first", "protect", {"address": PAGE, "length": 3 * PAGE, "prot": EXEC})
            self.assertEqual(unit.machine.snapshot_fragments, 6)
            unit.call("second", "protect", {"address": PAGE, "length": 3 * PAGE, "prot": READ})
            self.assertEqual(unit.machine.snapshot_fragments, 10)
            before = copy.deepcopy(project(unit.fragments()))
            with self.assertRaises(m.MappingError):
                unit.enter("third", "protect", {"address": PAGE, "length": 3 * PAGE, "prot": EXEC})
            self.assertEqual(unit.machine.snapshot_fragments, 10)
            self.assertEqual(project(unit.fragments()), before)
            self.assert_poisoned(unit)

    def test_cumulative_attempt_fragments_include_failed_map_outcomes_and_output_copy(self):
        with mock.patch.object(m, "MAX_ATTEMPT_FRAGMENTS", 6):
            unit = Units()
            for count in range(1, 4):
                unit.call("failed-" + str(count), "map", map_args("map-" + str(count), prot=WRITE), None, 13)
                self.assertEqual(unit.machine.attempt_fragments, count * 2)
            with self.assertRaises(m.MappingError):
                unit.enter("fourth", "map", map_args("map-4", prot=WRITE))
            self.assertEqual(unit.machine.attempt_fragments, 6)
            self.assertEqual([a["outcome"] for a in unit.machine.attempts], ["failed"] * 3)
            self.assertEqual(unit.fragments(), [])
            self.assert_poisoned(unit)

    def test_disjoint_protect_and_unmap_commute_in_declared_orders(self):
        outcomes = []
        for operations in (("protect", "unmap"), ("unmap", "protect")):
            unit = Units(); unit.map(length=6 * PAGE, offset=3 * PAGE)
            for operation in operations:
                args = ({"address": PAGE, "length": 2 * PAGE, "prot": WRITE}
                        if operation == "protect" else
                        {"address": 4 * PAGE, "length": 2 * PAGE})
                unit.call(operation, operation, args)
            outcomes.append(project(unit.fragments()))
            unit.retire(); result = unit.end()
            self.assertEqual(result["totals"]["shared_write_attempts"], 1)
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertEqual(outcomes[0], [fragment("map-a", "a", PAGE, 3 * PAGE, 3 * PAGE, WRITE),
                                      fragment("map-a", "a", 3 * PAGE, 4 * PAGE, 5 * PAGE),
                                      fragment("map-a", "a", 6 * PAGE, 7 * PAGE, 8 * PAGE)])

    def test_full_acceptance_api_unconditionally_refuses_every_value(self):
        for value in (None, {}, {"full_trace_acceptance": True}, self.__class__):
            with self.subTest(value=value), self.assertRaises(m.MappingError):
                m.require_full_trace_acceptance(value)

    def test_public_report_input_metadata_validates_shape_types_and_digest_bounds(self):
        class StringSubclass(str): pass
        class IntegerSubclass(int): pass
        class DictionarySubclass(dict): pass

        def reporter(mode):
            unit = Units(); unit.map(prot=WRITE)
            if mode == "finish":
                unit.retire()
                unit.event("finish", {"records": len(unit.records) + 1,
                                      "totals": dict(unit.machine.totals)})
                return unit.machine, unit.machine.finish
            error = m.MappingError("unit-control", "deliberately incomplete synthetic unit")
            return unit.machine, lambda info: unit.machine.rejection(error, info)

        valid = {"sha256": "a" * 64, "bytes": 0, "scope": "complete-input"}
        prefix_max = m.MAX_INPUT_BYTES + m.MAX_LINE_BYTES + 1
        invalid = [True, [], {}, DictionarySubclass(valid),
                   {**valid, "extra": 0}, {k: v for k, v in valid.items() if k != "sha256"}]
        invalid += [{**valid, "sha256": value} for value in
                    (True, [], StringSubclass("a" * 64), "A" * 64, "g" * 64, "a" * 63)]
        invalid += [{**valid, "bytes": value} for value in
                    (True, IntegerSubclass(0), -1, m.MAX_INPUT_BYTES + 1)]
        invalid += [{**valid, "scope": value} for value in
                    (True, [], {}, StringSubclass("complete-input"), "unknown")]
        invalid.append({**valid, "scope": "consumed-prefix", "bytes": prefix_max + 1})
        for mode in ("finish", "rejection"):
            for info in (None, valid, {**valid, "bytes": m.MAX_INPUT_BYTES},
                         {**valid, "scope": "consumed-prefix"},
                         {**valid, "scope": "consumed-prefix", "bytes": prefix_max}):
                machine, invoke = reporter(mode)
                with self.subTest(mode=mode, valid_metadata=info):
                    result = invoke(info)
                    self.assertFalse(result["full_trace_acceptance"])
                    self.assertEqual(result["attempts"][0]["call"], "call-map-a")
                    if info is None:
                        self.assertNotIn("input", result)
                    else:
                        self.assertEqual(result["input"], info)
                        self.assertIsNot(result["input"], info)
                    self.assertTrue(machine.materialized)
            for info in invalid:
                machine, invoke = reporter(mode)
                with self.subTest(mode=mode, invalid_metadata=info), self.assertRaises(m.MappingError):
                    invoke(info)
                self.assertFalse(machine.materialized)


class MappingDriverTests(unittest.TestCase):
    def closed(self):
        unit = Units(); unit.map(prot=WRITE); unit.retire(); unit.end()
        return unit

    def replay_bytes(self, raw):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.jsonl"; path.write_bytes(raw)
            return m.replay(path)

    def main_output(self, args):
        output_bytes, error_bytes = io.BytesIO(), io.BytesIO()
        output, errors = io.TextIOWrapper(output_bytes, encoding="utf-8"), io.TextIOWrapper(error_bytes, encoding="utf-8")
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = m.main(args)
        output.flush(); errors.flush()
        return status, output_bytes.getvalue().decode("utf-8"), error_bytes.getvalue().decode("utf-8")

    def test_closed_jsonl_reports_exact_input_hash_and_cli_never_accepts(self):
        unit = self.closed(); raw = unit.raw()
        result = self.replay_bytes(raw)
        self.assertFalse(result["full_trace_acceptance"])
        self.assertEqual(result["totals"]["shared_write_attempts"], 1)
        self.assertIn(hashlib.sha256(raw).hexdigest(), json.dumps(result, sort_keys=True))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.jsonl"; path.write_bytes(raw)
            argv = [sys.executable, str(Path(m.__file__)), "--input", str(path)]
            completed = subprocess.run(argv, capture_output=True, timeout=10)
            self.assertEqual(completed.returncode, 0)
            self.assertFalse(json.loads(completed.stdout)["full_trace_acceptance"])
            completed = subprocess.run(argv + ["--acceptance"], capture_output=True, timeout=10)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"accept", (completed.stdout + completed.stderr).lower())

    def test_acceptance_refusal_happens_before_input_open(self):
        with mock.patch.object(m, "replay", side_effect=AssertionError("must not open input")):
            status, stdout, stderr = self.main_output(["--input", "/not-present/mapping.jsonl", "--acceptance"])
        self.assertNotEqual(status, 0)
        self.assertIn("accept", (stdout + stderr).lower())
        self.assertNotIn("sha256", stdout + stderr)

    def test_strict_json_rejects_duplicates_nonfinite_truncation_and_extra_records(self):
        raw = self.closed().raw()
        for bad in (raw[:-1], raw.replace(b'"revision":1', b'"revision":1,"revision":1', 1),
                    raw.replace(b'"revision":1', b'"revision":NaN', 1),
                    raw.replace(b'"revision":1', b'"revision":Infinity', 1),
                    raw + b"{}\n", b"\n", b"[1,2]\n", b"\xff\n"):
            with self.subTest(raw=bad[:80]), self.assertRaises(m.MappingError): self.replay_bytes(bad)

    def test_input_must_be_single_link_regular_non_symlink_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); source = directory / "source.jsonl"
            source.write_bytes(self.closed().raw())
            link = directory / "link.jsonl"; link.symlink_to(source)
            with self.assertRaises(m.MappingError): m.replay(link)
            link.unlink(); os.link(source, link)
            with self.assertRaises(m.MappingError): m.replay(source)
            link.unlink(); fifo = directory / "fifo.jsonl"; os.mkfifo(fifo)
            with self.assertRaises(m.MappingError): m.replay(fifo)
            with self.assertRaises(m.MappingError): m.replay(directory)

    def test_input_line_record_and_output_bounds_are_enforced(self):
        raw = self.closed().raw()
        for constant, limit in (("MAX_INPUT_BYTES", len(raw) - 1),
                                ("MAX_LINE_BYTES", len(raw.splitlines(keepends=True)[0]) - 1),
                                ("MAX_RECORDS", 1), ("MAX_OUTPUT_BYTES", 1)):
            with mock.patch.object(m, constant, limit):
                with self.subTest(constant=constant), self.assertRaises(m.MappingError): self.replay_bytes(raw)

    def test_complete_and_consumed_prefix_digests_are_labeled_exactly(self):
        raw = self.closed().raw()
        result = self.replay_bytes(raw)
        self.assertEqual(result["input"], {"sha256": hashlib.sha256(raw).hexdigest(),
                                           "bytes": len(raw), "scope": "complete-input"})
        first_line = raw.splitlines(keepends=True)[0]
        bad = first_line.replace(b'"revision":1', b'"revision":true', 1) + b"trailing not consumed\n"
        with self.assertRaises(m.MappingError) as caught: self.replay_bytes(bad)
        consumed = bad.splitlines(keepends=True)[0]
        self.assertEqual(caught.exception.report["input"], {
            "sha256": hashlib.sha256(consumed).hexdigest(), "bytes": len(consumed),
            "scope": "consumed-prefix"})
        self.assertFalse(caught.exception.report["full_trace_acceptance"])
        self.assertTrue(caught.exception.report["diagnostic_prefix_only"])

    def test_input_non_atime_identity_mutations_reject_complete_input(self):
        raw = self.closed().raw()
        real_fstat = m.os.fstat
        for field in ("st_dev", "st_ino", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"):
            calls = []
            def changed(descriptor):
                snapshot = real_fstat(descriptor)
                calls.append(snapshot)
                if len(calls) == 1: return snapshot
                values = {name: getattr(snapshot, name) for name in
                          ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns", "st_atime_ns")}
                values[field] += 1
                return types.SimpleNamespace(**values)
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "input.jsonl"; path.write_bytes(raw)
                with mock.patch.object(m.os, "fstat", side_effect=changed):
                    with self.assertRaises(m.MappingError) as caught: m.replay(path)
                self.assertEqual(caught.exception.report["input"]["scope"], "complete-input")
                self.assertEqual(caught.exception.report["input"]["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertFalse(caught.exception.report["full_trace_acceptance"])
            self.assertEqual(len(calls), 2)

    def test_atime_only_change_does_not_reject_a_stable_input(self):
        raw, calls, real_fstat = self.closed().raw(), [], m.os.fstat
        def atime_changed(descriptor):
            snapshot = real_fstat(descriptor); calls.append(snapshot)
            values = {name: getattr(snapshot, name) for name in
                      ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns", "st_atime_ns")}
            values["st_atime_ns"] += len(calls)
            return types.SimpleNamespace(**values)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.jsonl"; path.write_bytes(raw)
            with mock.patch.object(m.os, "fstat", side_effect=atime_changed):
                result = m.replay(path)
        self.assertEqual(result["input"]["scope"], "complete-input")
        self.assertEqual(len(calls), 2)

    def test_serialized_rejection_is_bounded_when_full_ledger_cannot_fit(self):
        raw = self.closed().raw()
        normal_size = len(m.bounded_json(self.replay_bytes(raw)))
        with mock.patch.object(m, "MAX_OUTPUT_BYTES", normal_size - 1):
            with self.assertRaises(m.MappingError) as caught: self.replay_bytes(raw)
            self.assertFalse(caught.exception.report["full_trace_acceptance"])
            self.assertLessEqual(len(m.bounded_json(caught.exception.report)), normal_size - 1)
            self.assertEqual(caught.exception.report["input"]["bytes"], len(raw))


if __name__ == "__main__":
    unittest.main()
