/* Synthetic consumer/error tests. These records are never native evidence. */
#include <assert.h>
#include <unistd.h>
static uid_t synthetic_root(void) { return 0; }
#define geteuid synthetic_root
#define main capture_native_main
#include "capture-native.c"
#undef main
#undef geteuid

/* Force setup failure without requesting root or enabling any tracing. */
dtrace_hdl_t *dtrace_open(int version, int flags, int *error) {
    (void)version; (void)flags; *error=EACCES; return NULL;
}

static void event(struct capture *state, uint64_t kind, uint64_t pid, uint64_t detail) {
    size_t size=sizeof(dtrace_eprobedesc_t)+4*sizeof(dtrace_recdesc_t);
    dtrace_eprobedesc_t *description=calloc(1,size);
    assert(description);
    uint64_t words[]={kind,1000,pid,2000,detail};
    description->dtepd_nrecs=5; description->dtepd_size=sizeof(words);
    for (int i=0;i<5;++i) { description->dtepd_rec[i].dtrd_offset=(uint32_t)i*8; description->dtepd_rec[i].dtrd_size=8; }
    dtrace_probedesc_t probe={0}; strcpy(probe.dtpd_provider,"synthetic"); strcpy(probe.dtpd_func,"unit-only");
    dtrace_probedata_t data={.dtpda_edesc=description,.dtpda_pdesc=&probe,.dtpda_data=(char *)words};
    assert(consume_probe(&data,state)==DTRACE_CONSUME_NEXT);
    free(description);
}
int main(int argc, char **argv) {
    if (argc==3 && !strcmp(argv[1],"setup-error")) {
        char *arguments[]={argv[0],"--output",argv[2],"--","/usr/bin/printf","fixture-must-not-start",NULL};
        return capture_native_main(6,arguments);
    }
    if (argc==3 && !strcmp(argv[1],"watchdog")) {
        assert(start_watchdog(1,argv[2])>0);
        for (;;) pause();
    }
    struct capture state={.events=tmpfile(),.errors=tmpfile(),.root=100};
    assert(state.events && state.errors);
    process_for(&state,100)->created=true;
    event(&state,CREATE_EVENT,100,200);
    event(&state,EXIT_EVENT,100,0);
    assert(!all_terminal(&state)); /* An exited root is not a drained tree. */
    event(&state,EXIT_EVENT,200,0);
    assert(all_terminal(&state));
    dtrace_dropdata_t drop={.dtdda_drops=3,.dtdda_msg="synthetic loss"};
    assert(drop_event(&drop,&state)==DTRACE_HANDLE_ABORT);
    assert(state.failed && state.drops==3);
    state.failed=false;
    dtrace_errdata_t error={.dteda_fault=1,.dteda_msg="synthetic copy fault"};
    assert(error_event(&error,&state)==DTRACE_HANDLE_ABORT);
    assert(state.failed && state.faults==1);
    state.failed=false;
    dtrace_eprobedesc_t malformed={.dtepd_nrecs=0};
    dtrace_probedata_t data={.dtpda_edesc=&malformed};
    assert(consume_probe(&data,&state)==DTRACE_CONSUME_ABORT && state.failed);
    fclose(state.events); fclose(state.errors);
    puts("synthetic consumer, tree ledger, malformed event, drop and fault tests passed; not capture evidence");
    return 0;
}
