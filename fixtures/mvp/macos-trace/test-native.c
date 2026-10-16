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
int dtrace_errno(dtrace_hdl_t *handle) { (void)handle; return EIO; }
const char *dtrace_errmsg(dtrace_hdl_t *handle, int error) {
    (void)handle; (void)error;
    static char message[2048]; memset(message,'x',sizeof(message)-1);
    return message;
}
static void rejected_layout(const char *mode) {
    struct capture state={.events=tmpfile(),.errors=tmpfile(),.started=true};
    assert(state.events && state.errors);
    unsigned count=!strcmp(mode,"layout-wide") ? 21 : 6;
    dtrace_eprobedesc_t *description=calloc(1,sizeof(*description)+(count-1)*sizeof(dtrace_recdesc_t));
    assert(description);
    uint64_t words[]={BEGIN_EVENT,1000,100,2000,0};
    description->dtepd_nrecs=count; description->dtepd_size=sizeof(words); description->dtepd_epid=7;
    for (unsigned i=0;i<count;++i) {
        description->dtepd_rec[i].dtrd_offset=i ? (i-1)*8 : 0;
        description->dtepd_rec[i].dtrd_size=i ? 8 : 0;
        description->dtepd_rec[i].dtrd_action=DTRACEACT_DIFEXPR;
    }
    if (!strcmp(mode,"layout-range")) {
        description->dtepd_rec[0].dtrd_offset=MAX_RECORD_BYTES;
        description->dtepd_rec[0].dtrd_size=8;
    }
    if (!strcmp(mode,"layout-wide")) description->dtepd_size=MAX_RECORD_BYTES+1;
    dtrace_probedesc_t probe={.dtpd_id=42}; strcpy(probe.dtpd_provider,"dtrace"); strcpy(probe.dtpd_name,"BEGIN");
    dtrace_probedata_t data={.dtpda_edesc=description,.dtpda_pdesc=&probe,.dtpda_data=(char *)words,.dtpda_cpu=2};
    unsigned attempts=!strcmp(mode,"layout-limit") ? 17 : 1;
    for (unsigned i=0;i<attempts;++i) assert(consume_probe(&data,&state)==DTRACE_CONSUME_ABORT && state.failed);
    const char *first=state.reason;
    fail_capture(&state,"later drain failure must not replace first cause");
    assert(state.reason==first);
    rewind(state.events); assert(fgetc(state.events)==EOF);
    rewind(state.errors);
    int byte; while ((byte=fgetc(state.errors))!=EOF) putchar(byte);
    fclose(state.events); fclose(state.errors); free(description);
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
    if (argc==2 && !strncmp(argv[1],"layout",6)) { rejected_layout(argv[1]); return 0; }
    if (argc==2 && !strcmp(argv[1],"libdtrace-error")) {
        struct capture state={.errors=tmpfile()}; assert(state.errors);
        fail_capture(&state,"first-cause");
        libdtrace_error(&state,NULL,"work","later work failure");
        assert(!strcmp(state.reason,"first-cause"));
        rewind(state.errors); int byte; while ((byte=fgetc(state.errors))!=EOF) putchar(byte);
        fclose(state.errors); return 0;
    }
    if (argc==3 && !strcmp(argv[1],"identity")) {
        struct capture state={.started=true};
        struct identity identity;
        capture_identity(&state,argv[2],&identity);
        printf("{\"status\":\"%s\",\"identity_checks_passed\":%s,\"identity\":",capture_status(&state),state.identity_failed ? "false" : "true");
        write_identity(stdout,&identity); puts("}");
        return state.failed ? 1 : 0;
    }
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
