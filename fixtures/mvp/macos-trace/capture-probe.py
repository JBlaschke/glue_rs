#!/usr/bin/env python3
"""Capture one owned Darwin syscall probe; never invoke sudo or change settings."""
import argparse
import hashlib
import json
import os
import platform
import shlex
import signal
import subprocess
from pathlib import Path


def identity(path):
    data = path.read_bytes()
    return {"size":len(data),"sha256":hashlib.sha256(data).hexdigest()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepared",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if platform.system()!="Darwin":parser.error("requires an actual macOS host")
    if os.geteuid()!=0:parser.error("root must invoke this reviewed capture; it never requests or handles a password")
    prepared=args.prepared.resolve()
    binary,input_path=prepared/"owned-probe",prepared/"input.txt"
    if not binary.is_file() or not input_path.is_file():parser.error("prepare the owned fixture first")
    output=args.output
    if not output.is_absolute():parser.error("output must be a new absolute directory")
    output.mkdir()
    program=Path(__file__).resolve().with_name("open-probe.d")
    command=["/usr/sbin/dtrace","-q","-s",str(program),"-o",str(output/"open.raw"),"-c",shlex.join([str(binary),str(input_path)])]
    timed_out=False
    with (output/"target.stdout").open("wb") as stdout,(output/"dtrace.stderr").open("wb") as stderr:
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
        try:result=child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            timed_out=True
            os.killpg(child.pid,signal.SIGKILL)
            result=child.wait()
    raw=(output/"open.raw").read_text(errors="replace") if (output/"open.raw").is_file() else ""
    error=(output/"dtrace.stderr").read_text(errors="replace")
    stdout=(output/"target.stdout").read_bytes()
    events=[line for line in raw.splitlines() if line.startswith("GLUE_MAC_OPEN_V1\t")]
    blocked="System Integrity Protection is on" in error
    observed=result==0 and not timed_out and bool(events) and stdout==b"owned-read-complete\n"
    status="captured" if observed else "unavailable" if blocked else "failed"
    receipt={"revision":1,"status":status,"host":{"system":platform.system(),"release":platform.release(),"machine":platform.machine()},
             "scope":"single named open syscall on owned ad-hoc fixture; no complete process-tree/extraction acceptance",
             "command":command,"exit":result,"timed_out":timed_out,"events":len(events),"sip_provider_rejection":blocked,
             "settings_changed":False,"password_handling":False,
             "required_remaining_capabilities":["syscall return/errno semantics","exec/fork/posix_spawn/exit and thread completeness","all filesystem mutation attempts and FD/relative-path lifecycle","shared writable mmap and non-syscall write routes","dropped/error/truncated event rejection","actual positive/negative controls and language corpora"],
             "identities":{"owned_fixture":identity(binary),"owned_input":identity(input_path),"probe_program":identity(program),"capture_script":identity(Path(__file__).resolve())},
             "evidence":{path.name:identity(path) for path in sorted(output.iterdir()) if path.is_file()}}
    (output/"capability.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print(status+": "+str(output/"capability.json"))
    return 0 if observed else 2 if blocked else 1


if __name__=="__main__":raise SystemExit(main())
