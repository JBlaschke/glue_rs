/* Exact named syscall diagnostic. No -Z, pid provider, or acceptance claim. */
#pragma D option quiet
#pragma D option strsize=4096
syscall::open:entry
/pid == $target/
{
    printf("GLUE_MAC_OPEN_V1\t%llu\t%d\t%d\t%S\n", timestamp, pid, tid, copyinstr(arg0));
}
