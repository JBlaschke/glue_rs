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
    description->dtepd_nrecs=count; description->dtepd_size=sizeof(words); description->dtepd_epid=7; description->dtepd_probeid=42;
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

struct synthetic_layout {
    int kind; const char *provider, *function, *name; int count, zero; uint32_t bytes;
};
static const struct synthetic_layout layouts[]={
    {1,"dtrace","","BEGIN",6,0,56},{2,"syscall","open","entry",13,-1,120},
    {3,"syscall","open","return",10,-1,96},{4,"proc",".","create",6,0,56},
    {5,"proc",".","start",6,0,56},{6,"proc",".","exit",5,-1,56},
    {7,"proc",".","exec-success",6,0,56},{8,"proc",".","exec-failure",5,-1,56},
    {9,"proc",".","lwp-create",5,-1,56},{10,"proc",".","lwp-start",5,-1,56},
    {11,"proc",".","lwp-exit",5,-1,56},{12,"proc",".","spawn-success",5,-1,56},
    {13,"proc",".","spawn-failure",5,-1,56},{14,"syscall","open","entry",6,-1,1080},
    {15,"mach_trap","mach_test","entry",13,-1,120},{16,"mach_trap","mach_test","return",6,-1,64},
    {17,"dtrace","","END",5,-1,56},{18,"proc",".","exited",8,-1,80},
};
struct synthetic_event {
    dtrace_eprobedesc_t *description;
    dtrace_probedesc_t probe;
    char bytes[1080];
    dtrace_probedata_t data;
};
static void make_event(struct synthetic_event *event, int kind, uint64_t pid, uint64_t detail) {
    const struct synthetic_layout *layout=&layouts[kind-1];
    assert(layout->kind==kind);
    memset(event,0,sizeof(*event));
    event->description=calloc(1,sizeof(dtrace_eprobedesc_t)+12*sizeof(dtrace_recdesc_t));
    assert(event->description);
    event->description->dtepd_nrecs=layout->count; event->description->dtepd_size=layout->bytes;
    event->description->dtepd_epid=7; event->description->dtepd_probeid=42;
    event->probe.dtpd_id=42;
    strcpy(event->probe.dtpd_provider,layout->provider); strcpy(event->probe.dtpd_func,layout->function); strcpy(event->probe.dtpd_name,layout->name);
    uint64_t words[]={kind,1000,pid,2000,detail,0,1,2,3,4,5,6,7};
    int payload=0;
    for (int i=0;i<layout->count;++i) {
        dtrace_recdesc_t *record=&event->description->dtepd_rec[i];
        record->dtrd_action=1;
        if (i==layout->zero) { record->dtrd_offset=i==0 ? 12 : 64; continue; }
        record->dtrd_offset=16+(uint32_t)payload*8;
        record->dtrd_size=kind==14 && i==5 ? 1024 : 8;
        if (record->dtrd_size==8) memcpy(event->bytes+record->dtrd_offset,&words[payload],8);
        else strcpy(event->bytes+record->dtrd_offset,"/synthetic/input");
        ++payload;
    }
    event->data=(dtrace_probedata_t){.dtpda_edesc=event->description,.dtpda_pdesc=&event->probe,.dtpda_data=event->bytes};
}
static void event(struct capture *state, uint64_t kind, uint64_t pid, uint64_t detail) {
    struct synthetic_event sample; make_event(&sample,(int)kind,pid,detail);
    assert(consume_probe(&sample.data,state)==DTRACE_CONSUME_NEXT);
    free(sample.description);
}
static void negative_layouts(void) {
    for (int test=0;test<26;++test) {
        int kind=test==5 ? 17 : test==6 ? 18 : test==14 || test==18 || test==19 ? 4 : test==15 ? 15 : test>=20 ? 18 : 1;
        struct synthetic_event sample; make_event(&sample,kind,100,0);
        if (test>=22) { uint64_t target=200; memcpy(sample.bytes+48,&target,8); }
        struct capture state={.events=tmpfile(),.errors=tmpfile(),.tree=true,.mach=true};
        const char *reason="record-layout";
        switch (test) {
        case 0: sample.description->dtepd_nrecs=5; reason="record-count"; break;
        case 1: sample.description->dtepd_rec[0].dtrd_size=8; break;
        case 2: sample.description->dtepd_rec[0].dtrd_offset=16; break;
        case 3: sample.description->dtepd_rec[0].dtrd_action=2; reason="record-action"; break;
        case 4: sample.description->dtepd_rec[1].dtrd_size=0; break;
        case 5: sample.description->dtepd_nrecs=6; reason="record-count"; break;
        case 6: sample.description->dtepd_rec[6].dtrd_offset=63; break;
        case 7: sample.description->dtepd_rec[2].dtrd_size=4; break;
        case 8: sample.description->dtepd_rec[2].dtrd_offset=25; break;
        case 9: sample.description->dtepd_rec[2].dtrd_action=2; reason="record-action"; break;
        case 10: { uint64_t value=17; memcpy(sample.bytes+16,&value,8); reason="header-kind"; break; }
        case 11: { uint64_t value=(uint64_t)INT_MAX+1; memcpy(sample.bytes+32,&value,8); reason="header-pid"; break; }
        case 12: { uint64_t value=1; memcpy(sample.bytes+48,&value,8); reason="header-detail"; break; }
        case 13: strcpy(sample.probe.dtpd_provider,"unknown"); reason="probe-layout"; break;
        case 14: state.tree=false; reason="probe-layout"; break;
        case 15: state.mach=false; reason="probe-layout"; break;
        case 16: sample.probe.dtpd_id=43; reason="probe-id"; break;
        case 17: sample.description->dtepd_size=8193; reason="record-bytes"; break;
        case 18: case 20: reason="header-target"; break; /* zero target */
        case 19: case 21: { uint64_t value=(uint64_t)INT_MAX+1; memcpy(sample.bytes+48,&value,8); reason="header-target"; break; }
        case 22: { uint64_t value=0; memcpy(sample.bytes+64,&value,8); reason="target-identity"; break; }
        case 23: { uint64_t value=(uint64_t)UINT32_MAX+1; memcpy(sample.bytes+72,&value,8); reason="target-identity"; break; }
        case 24: sample.description->dtepd_nrecs=7; reason="record-count"; break;
        case 25: sample.description->dtepd_rec[6].dtrd_size=0; break;
        }
        assert(consume_probe(&sample.data,&state)==DTRACE_CONSUME_ABORT && state.failed);
        assert(!strcmp(state.reason,reason));
        rewind(state.events); assert(fgetc(state.events)==EOF);
        fclose(state.events); fclose(state.errors); free(sample.description);
    }
    puts("26 exact layout rejection controls passed; synthetic only");
}
static void shadow_exit(struct capture *state, uint64_t current_pid, uint64_t target_pid) {
    struct synthetic_event sample; make_event(&sample,EXITED_TARGET,current_pid,target_pid);
    uint64_t refcount=PINNED_P_REF_SHADOW|UINT32_C(0x102);
    memcpy(sample.bytes+72,&refcount,8);
    assert(consume_probe(&sample.data,state)==DTRACE_CONSUME_NEXT);
    free(sample.description);
}
static void terminal_rejections(void) {
    for (int test=0;test<5;++test) {
        struct capture state={.events=tmpfile(),.errors=tmpfile(),.root=100,.tree=true,.mach=true};
        process_for(&state,100)->created=true;
        if (test<3) event(&state,EXITED_TARGET,0,100);
        if (test==4) event(&state,EXITED_TARGET,0,200);
        struct synthetic_event sample;
        make_event(&sample,test==0 ? SYSCALL_ENTRY : test==1 ? EXEC_SUCCESS : test==2 ? EXITED_TARGET : CREATE_EVENT,
                   test==2 ? 0 : 100,test==4 ? 200 : test>=2 ? 100 : 0);
        long before=ftell(state.events);
        assert(consume_probe(&sample.data,&state)==DTRACE_CONSUME_ABORT && state.failed);
        assert(!strcmp(state.reason,"lifecycle-state") && ftell(state.events)==before);
        free(sample.description); fclose(state.events); fclose(state.errors);
    }
    puts("5 postterminal and PID reuse rejection controls passed; synthetic only");
}
int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"valid-layouts")) {
        for (int kind=1;kind<=18;++kind) {
            struct capture state={.events=tmpfile(),.errors=tmpfile(),.tree=true,.mach=true};
            event(&state,kind,100,kind==4 || kind==18 ? 200 : 0);
            rewind(state.events); int byte; while ((byte=fgetc(state.events))!=EOF) putchar(byte);
            fclose(state.events); fclose(state.errors);
        }
        return 0;
    }
    if (argc==2 && !strcmp(argv[1],"negative-layouts")) { negative_layouts(); return 0; }
    if (argc==2 && !strcmp(argv[1],"terminal-rejections")) { terminal_rejections(); return 0; }
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
    struct capture state={.events=tmpfile(),.errors=tmpfile(),.root=100,.tree=true,.mach=true};
    assert(state.events && state.errors);
    process_for(&state,100)->created=true;
    event(&state,EXEC_SUCCESS,100,0);
    /* Exact observed v6 failure shape: old exec thread has PID zero, but the
     * target PID aliases the live new object. Only the raw shadow bit decides. */
    shadow_exit(&state,0,100);
    assert(!state.root_terminal && !process_for(&state,100)->terminal);
    event(&state,SYSCALL_ENTRY,100,0);
    event(&state,CREATE_EVENT,100,200);
    event(&state,EXIT_EVENT,100,1);
    assert(!state.root_terminal && !process_for(&state,100)->terminal && !process_for(&state,200)->terminal);
    /* A failed-spawn exit in the parent context cannot end either process. */
    event(&state,EXITED_TARGET,100,200);
    assert(process_for(&state,200)->terminal && !process_for(&state,100)->terminal && !all_terminal(&state));
    event(&state,SYSCALL_ENTRY,100,0); /* Parent continues after child exit. */
    event(&state,EXITED_TARGET,300,100); /* Target, not current PID, closes root. */
    assert(all_terminal(&state));
    shadow_exit(&state,0,100); /* Late old-object cleanup remains raw context. */
    assert(all_terminal(&state));
    event(&state,LWP_EXIT,100,0); /* Final thread cleanup is context, not activity. */
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
