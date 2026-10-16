/* Owned diagnostic transport only. This is not an extraction oracle. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <CommonCrypto/CommonDigest.h>
#include <dtrace.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_PROCESSES 256
#define MAX_EVENTS 1000000
#define MAX_RAW_BYTES (128UL * 1024 * 1024)
#define MAX_IDENTITY_BYTES MAX_RAW_BYTES
#define MAX_RECORD_BYTES 8192

enum { BEGIN_EVENT=1, SYSCALL_ENTRY, SYSCALL_RETURN, CREATE_EVENT, START_EVENT,
       EXIT_EVENT, EXEC_SUCCESS, EXEC_FAILURE, LWP_CREATE, LWP_START, LWP_EXIT,
       SPAWN_SUCCESS, SPAWN_FAILURE, OPEN_PATH, MACH_ENTRY, MACH_RETURN, END_EVENT };
struct process { pid_t pid; bool created, terminal; };
struct capture {
    FILE *events, *errors, *inventory;
    struct process processes[MAX_PROCESSES];
    size_t processes_used;
    uint64_t events_seen, drops, faults, open_entries, open_returns;
    unsigned diagnostics;
    bool failed, root_terminal, tree, started;
    bool identity_failed;
    pid_t root;
    const char *reason;
};
static volatile sig_atomic_t interrupted;
static void on_signal(int number) { interrupted=number; }

static void fail_capture(struct capture *state, const char *reason) {
    if (!state->failed) state->reason=reason;
    state->failed=true;
}

static void json_string(FILE *output, const char *string) {
    fputc('"',output);
    for (const unsigned char *p=(const unsigned char *)string; *p; ++p) {
        if (*p=='"' || *p=='\\') { fputc('\\',output); fputc(*p,output); }
        else if (*p<32 || *p>=127) fprintf(output,"\\u%04x",*p);
        else fputc(*p,output);
    }
    fputc('"',output);
}
static double monotonic(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC,&value)) return 0;
    return (double)value.tv_sec+(double)value.tv_nsec/1e9;
}
/* Diagnostic metadata does not make a rejected layout into an accepted event.
 * Read a value only from an eight-byte record inside the bounded probe bytes. */
static bool diagnostic_value(const dtrace_probedata_t *data, const dtrace_recdesc_t *record, uint64_t *value) {
    const dtrace_eprobedesc_t *description=data->dtpda_edesc;
    if (!data->dtpda_data || description->dtepd_size>MAX_RECORD_BYTES || record->dtrd_size!=sizeof(*value) ||
        record->dtrd_offset>description->dtepd_size || record->dtrd_size>description->dtepd_size-record->dtrd_offset) return false;
    memcpy(value,data->dtpda_data+record->dtrd_offset,sizeof(*value));
    return true;
}
static void layout_error(struct capture *state, const dtrace_probedata_t *data, const char *reason) {
    fail_capture(state,reason);
    if (state->diagnostics++>=16) return;
    const dtrace_eprobedesc_t *description=data->dtpda_edesc;
    fprintf(state->errors,"{\"kind\":\"layout-error\",\"reason\":"); json_string(state->errors,reason);
    fprintf(state->errors,",\"cpu\":%d,\"epid\":%u,\"probe_id\":",data->dtpda_cpu,description->dtepd_epid);
    const dtrace_probedesc_t *probe=data->dtpda_pdesc;
    if (probe) fprintf(state->errors,"%u",probe->dtpd_id); else fputs("null",state->errors);
    const char *names[]={"provider","module","function","name"};
    const char *values[]={probe ? probe->dtpd_provider : NULL,probe ? probe->dtpd_mod : NULL,
                          probe ? probe->dtpd_func : NULL,probe ? probe->dtpd_name : NULL};
    const size_t capacities[]={sizeof(probe->dtpd_provider),sizeof(probe->dtpd_mod),sizeof(probe->dtpd_func),sizeof(probe->dtpd_name)};
    for (unsigned i=0;i<4;++i) {
        fputc(',',state->errors); json_string(state->errors,names[i]); fputc(':',state->errors);
        if (values[i]) {
            char bounded[257]; size_t count=strnlen(values[i],capacities[i]);
            if (count>=sizeof(bounded)) count=sizeof(bounded)-1;
            memcpy(bounded,values[i],count); bounded[count]=0; json_string(state->errors,bounded);
        } else fputs("null",state->errors);
    }
    fprintf(state->errors,",\"event\":%"PRIu64",\"nrecs\":%d,\"record_bytes\":%u,\"header\":[",state->events_seen,description->dtepd_nrecs,description->dtepd_size);
    for (int i=0;i<5;++i) {
        uint64_t value;
        if (i) fputc(',',state->errors);
        if (i<description->dtepd_nrecs && diagnostic_value(data,&description->dtepd_rec[i],&value)) fprintf(state->errors,"%"PRIu64,value);
        else fputs("null",state->errors);
    }
    fputs("],\"records\":[",state->errors);
    int count=description->dtepd_nrecs<20 ? description->dtepd_nrecs : 20;
    for (int i=0;i<count;++i) {
        const dtrace_recdesc_t *record=&description->dtepd_rec[i];
        uint64_t value;
        fprintf(state->errors,"%s{\"action\":%u,\"size\":%u,\"offset\":%u,\"u64\":",i ? "," : "",record->dtrd_action,record->dtrd_size,record->dtrd_offset);
        if (diagnostic_value(data,record,&value)) fprintf(state->errors,"%"PRIu64,value);
        else fputs("null",state->errors);
        fputc('}',state->errors);
    }
    fputs("]}\n",state->errors);
}
static void libdtrace_error(struct capture *state, dtrace_hdl_t *handle, const char *operation, const char *reason) {
    int error=dtrace_errno(handle);
    fail_capture(state,reason);
    if (state->diagnostics++>=16) return;
    fputs("{\"kind\":\"libdtrace-error\",\"operation\":",state->errors); json_string(state->errors,operation);
    fprintf(state->errors,",\"error\":%d,\"message\":",error);
    const char *message=dtrace_errmsg(handle,error);
    char bounded[513]; snprintf(bounded,sizeof(bounded),"%s",message ? message : "");
    json_string(state->errors,bounded); fputs("}\n",state->errors);
}
static struct process *process_for(struct capture *state, pid_t pid) {
    for (size_t i=0;i<state->processes_used;++i)
        if (state->processes[i].pid==pid) return &state->processes[i];
    if (pid<=0 || state->processes_used==MAX_PROCESSES) {
        fail_capture(state,"process identity bound exceeded"); return NULL;
    }
    struct process *process=&state->processes[state->processes_used++];
    *process=(struct process){.pid=pid};
    return process;
}
static bool all_terminal(struct capture *state) {
    for (size_t i=0;i<state->processes_used;++i)
        if (!state->processes[i].created || !state->processes[i].terminal) return false;
    return state->root_terminal;
}
static int error_event(const dtrace_errdata_t *error, void *argument) {
    struct capture *state=argument;
    ++state->faults; fail_capture(state,"DTrace error callback");
    fprintf(state->errors,"{\"kind\":\"error\",\"cpu\":%d,\"fault\":%d,\"action\":%d,\"message\":",error->dteda_cpu,error->dteda_fault,error->dteda_action);
    json_string(state->errors,error->dteda_msg ? error->dteda_msg : "");
    fputs("}\n",state->errors);
    return DTRACE_HANDLE_ABORT;
}
static int drop_event(const dtrace_dropdata_t *drop, void *argument) {
    struct capture *state=argument;
    state->drops+=drop->dtdda_drops; fail_capture(state,"DTrace drop callback");
    fprintf(state->errors,"{\"kind\":\"drop\",\"cpu\":%d,\"drop_kind\":%d,\"drops\":%"PRIu64",\"total\":%"PRIu64",\"message\":",drop->dtdda_cpu,drop->dtdda_kind,drop->dtdda_drops,drop->dtdda_total);
    json_string(state->errors,drop->dtdda_msg ? drop->dtdda_msg : "");
    fputs("}\n",state->errors);
    return DTRACE_HANDLE_ABORT;
}
static int consume_probe(const dtrace_probedata_t *data, void *argument) {
    struct capture *state=argument;
    const dtrace_eprobedesc_t *description=data->dtpda_edesc;
    uint64_t header[5]={0};
    const char *rejection="event-count";
    if (++state->events_seen>MAX_EVENTS) goto invalid;
    rejection="record-count";
    if (description->dtepd_nrecs<5 || description->dtepd_nrecs>20) goto invalid;
    rejection="record-bytes";
    if (description->dtepd_size>MAX_RECORD_BYTES) goto invalid;
    for (int i=0;i<description->dtepd_nrecs;++i) {
        const dtrace_recdesc_t *record=&description->dtepd_rec[i];
        rejection="record-range";
        if (record->dtrd_offset>description->dtepd_size || record->dtrd_size>description->dtepd_size-record->dtrd_offset) goto invalid;
        if (i<5) {
            rejection="header-width";
            if (record->dtrd_size!=sizeof(uint64_t)) goto invalid;
            memcpy(&header[i],data->dtpda_data+record->dtrd_offset,sizeof(uint64_t));
        }
    }
    rejection="header-kind";
    if (header[0]<BEGIN_EVENT || header[0]>END_EVENT) goto invalid;
    rejection="header-pid";
    if (header[2]>INT_MAX) goto invalid;
    fprintf(state->events,"{\"event\":%"PRIu64",\"cpu\":%d,\"epid\":%u,\"probe_id\":%u,\"kind\":%"PRIu64",\"timestamp\":%"PRIu64",\"pid\":%"PRIu64",\"tid\":%"PRIu64",\"detail\":%"PRIu64",\"provider\":",state->events_seen,data->dtpda_cpu,description->dtepd_epid,data->dtpda_pdesc->dtpd_id,header[0],header[1],header[2],header[3],header[4]);
    json_string(state->events,data->dtpda_pdesc->dtpd_provider);
    fputs(",\"module\":",state->events); json_string(state->events,data->dtpda_pdesc->dtpd_mod);
    fputs(",\"function\":",state->events); json_string(state->events,data->dtpda_pdesc->dtpd_func);
    fputs(",\"name\":",state->events); json_string(state->events,data->dtpda_pdesc->dtpd_name);
    fputs(",\"records\":[",state->events);
    for (int i=0;i<description->dtepd_nrecs;++i) {
        const dtrace_recdesc_t *record=&description->dtepd_rec[i];
        const unsigned char *bytes=(const unsigned char *)data->dtpda_data+record->dtrd_offset;
        fprintf(state->events,"%s{\"action\":%u,\"size\":%u,\"offset\":%u,\"hex\":\"",i ? "," : "",record->dtrd_action,record->dtrd_size,record->dtrd_offset);
        for (uint32_t j=0;j<record->dtrd_size;++j) fprintf(state->events,"%02x",bytes[j]);
        fputs("\"}",state->events);
    }
    fputs("]}\n",state->events);
    rejection="event-output";
    if (ferror(state->events) || ftello(state->events)<0 || (uint64_t)ftello(state->events)>MAX_RAW_BYTES) goto invalid;
    if (header[0]==CREATE_EVENT) {
        struct process *child=process_for(state,(pid_t)header[4]);
        if (child) child->created=true;
    } else if (header[0]==START_EVENT || header[0]==EXEC_SUCCESS) {
        struct process *process=process_for(state,(pid_t)header[2]);
        if (process) process->created=true;
    } else if (header[0]==EXIT_EVENT) {
        struct process *process=process_for(state,(pid_t)header[2]);
        if (process) process->terminal=true;
        if ((pid_t)header[2]==state->root) state->root_terminal=true;
    }
    if (!strcmp(data->dtpda_pdesc->dtpd_func,"open")) {
        if (header[0]==SYSCALL_ENTRY) ++state->open_entries;
        if (header[0]==SYSCALL_RETURN) ++state->open_returns;
    }
    return state->failed ? DTRACE_CONSUME_ABORT : DTRACE_CONSUME_NEXT;
invalid:
    layout_error(state,data,rejection);
    return DTRACE_CONSUME_ABORT;
}
static int probe_inventory(dtrace_hdl_t *handle, const dtrace_probedesc_t *probe, void *argument) {
    (void)handle;
    FILE *output=argument;
    if (strcmp(probe->dtpd_provider,"syscall") && strcmp(probe->dtpd_provider,"proc") && strcmp(probe->dtpd_provider,"mach_trap")) return 0;
    fprintf(output,"%u\t%s\t%s\t%s\t%s\n",probe->dtpd_id,probe->dtpd_provider,probe->dtpd_mod,probe->dtpd_func,probe->dtpd_name);
    return ferror(output) ? -1 : 0;
}

static void event_header(FILE *output, int kind, const char *detail) {
    fprintf(output,"trace((uint64_t)%d); trace((uint64_t)timestamp); trace((uint64_t)pid); trace((uint64_t)tid); trace((uint64_t)(%s));\n",kind,detail);
}
static int write_program(FILE *output, pid_t root, const char *profile) {
    bool tree=strcmp(profile,"open")!=0, mach=!strcmp(profile,"tree-mach");
    fprintf(output,"#pragma D option quiet\n#pragma D option strsize=1024\nBEGIN { watched[%d]=1; ",root);
    event_header(output,BEGIN_EVENT,"0"); fputs("}\nEND { ",output);
    event_header(output,END_EVENT,"0"); fputs("}\n",output);
    fprintf(output,"syscall::%s:entry /watched[pid]/ { ",tree ? "" : "open");
    event_header(output,SYSCALL_ENTRY,"ppid");
    for (int i=0;i<8;++i) fprintf(output,"trace((uint64_t)arg%d); ",i);
    fputs("}\n",output);
    fprintf(output,"syscall::%s:return /watched[pid]/ { ",tree ? "" : "open");
    event_header(output,SYSCALL_RETURN,"ppid");
    fputs("trace((uint64_t)arg0);trace((uint64_t)arg1);trace((uint64_t)arg2);trace((uint64_t)arg3);trace((uint64_t)errno); }\n",output);
    fputs("syscall::open:entry /watched[pid]/ { ",output);
    event_header(output,OPEN_PATH,"0"); fputs("trace(copyinstr(arg0,1024)); }\n",output);
    if (tree) {
        fputs("proc:::create /watched[pid]/ { watched[args[0]->pr_pid]=1; ",output);
        event_header(output,CREATE_EVENT,"args[0]->pr_pid"); fputs("}\n",output);
        fputs("proc:::start /watched[pid] || watched[ppid]/ { watched[pid]=1; ",output);
        event_header(output,START_EVENT,"ppid"); fputs("}\n",output);
        fputs("proc:::exec-success /watched[pid] || watched[ppid]/ { watched[pid]=1; ",output);
        event_header(output,EXEC_SUCCESS,"ppid"); fputs("}\n",output);
        const struct { const char *probe; int kind; const char *detail; } events[]={
            {"exit",EXIT_EVENT,"arg0"},{"exec-failure",EXEC_FAILURE,"arg0"},
            {"spawn-success",SPAWN_SUCCESS,"0"},{"spawn-failure",SPAWN_FAILURE,"arg0"},
            {"lwp-create",LWP_CREATE,"args[0]->pr_lwpid"},{"lwp-start",LWP_START,"0"},{"lwp-exit",LWP_EXIT,"0"},
        };
        for (size_t i=0;i<sizeof(events)/sizeof(events[0]);++i) {
            fprintf(output,"proc:::%s /watched[pid]/ { ",events[i].probe);
            event_header(output,events[i].kind,events[i].detail);
            if (events[i].kind==EXIT_EVENT) fputs("watched[pid]=0; ",output);
            fputs("}\n",output);
        }
    }
    if (mach) for (int which=0;which<2;++which) {
        fprintf(output,"mach_trap:::%s /watched[pid]/ { ",which ? "return" : "entry");
        event_header(output,which ? MACH_RETURN : MACH_ENTRY,"ppid");
        for (int i=0;i<(which ? 1 : 8);++i) fprintf(output,"trace((uint64_t)arg%d); ",i);
        fputs("}\n",output);
    }
    return ferror(output) ? -1 : 0;
}
static FILE *new_file(const char *directory, const char *name) {
    char path[PATH_MAX];
    int size=snprintf(path,sizeof(path),"%s/%s",directory,name);
    if (size<0 || size>=(int)sizeof(path)) { errno=ENAMETOOLONG; return NULL; }
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0644);
    if (fd<0) return NULL;
    FILE *output=fdopen(fd,"w");
    if (!output) close(fd);
    return output;
}
struct identity {
    bool valid;
    uint64_t size;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
};
static bool read_identity(const char *path, struct identity *identity) {
    unsigned char bytes[16384], digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX context;
    *identity=(struct identity){0};
    /* Nonblocking open lets the regular-file check reject FIFOs/devices without
     * waiting for a producer. The watchdog separately bounds filesystem stalls. */
    int fd=open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    if (fd<0) return false;
    struct stat facts;
    if (fstat(fd,&facts) || !S_ISREG(facts.st_mode) || facts.st_size<0 || (uint64_t)facts.st_size>MAX_IDENTITY_BYTES) {
        close(fd); return false;
    }
    FILE *input=fdopen(fd,"rb");
    if (!input) { close(fd); return false; }
    CC_SHA256_Init(&context);
    uint64_t size=0;
    bool failed=false;
    for (;;) {
        /* One sentinel byte detects a file growing beyond the limit after stat,
         * without reading an unbounded amount or allocating the file in memory. */
        uint64_t remaining=MAX_IDENTITY_BYTES-size+1;
        size_t capacity=remaining<sizeof(bytes) ? (size_t)remaining : sizeof(bytes);
        size_t count=fread(bytes,1,capacity,input);
        if (count==0) break;
        size+=count;
        if (size>MAX_IDENTITY_BYTES) { failed=true; break; }
        CC_SHA256_Update(&context,bytes,(CC_LONG)count);
    }
    if (ferror(input) || size!=(uint64_t)facts.st_size) failed=true;
    if (fclose(input)) failed=true;
    if (failed) return false;
    CC_SHA256_Final(digest,&context);
    identity->valid=true; identity->size=size;
    memcpy(identity->digest,digest,sizeof(digest));
    return true;
}
static void capture_identity(struct capture *state, const char *path, struct identity *identity) {
    if (!read_identity(path,identity)) {
        state->identity_failed=true;
        fail_capture(state,"required fixture, collector or evidence identity unavailable");
    }
}
static const char *capture_status(const struct capture *state) {
    return state->failed ? (state->started ? "failed" : "unavailable") : "captured";
}
static void write_identity(FILE *output, const struct identity *identity) {
    if (!identity->valid) { fputs("null",output); return; }
    fprintf(output,"{\"size\":%"PRIu64",\"sha256\":\"",identity->size);
    for (size_t i=0;i<sizeof(identity->digest);++i) fprintf(output,"%02x",identity->digest[i]);
    fputs("\"}",output);
}
static int usage(void) {
    fputs("usage: capture-native --output NEW_ABSOLUTE_DIR [--timeout 1..60] [--profile open|tree|tree-mach] -- /absolute/owned-fixture [ARG ...]\n",stderr);
    return 2;
}

/* This sibling bounds blocking libdtrace setup/teardown as well as the event
 * loop. A killed collector has no valid final receipt. Supplied owned fixtures
 * also carry their own alarms, including descendants that call setsid(). */
static pid_t start_watchdog(int timeout, const char *directory) {
    FILE *output=new_file(directory,"watchdog.json");
    if (!output) return -1;
    pid_t controller=getpid(), watchdog=fork();
    if (watchdog==0) {
        signal(SIGINT,SIG_DFL); signal(SIGTERM,SIG_DFL); signal(SIGHUP,SIG_DFL);
        for (int i=0;i<timeout+2;++i) sleep(1);
        if (getppid()!=controller) _exit(0);
        fputs("{\"status\":\"failed\",\"reason\":\"hard collector deadline exceeded; final capture receipt invalid\"}\n",output);
        fflush(output); fsync(fileno(output));
        /* Never signal remembered/reaped descendant PIDs: they could be reused.
         * The controlled fixtures have their own five-second descendant alarms. */
        kill(controller,SIGKILL);
        _exit(124);
    }
    fclose(output);
    return watchdog;
}

int main(int argc, char **argv) {
    const char *directory=NULL,*profile="open";
    int timeout=15,command=0;
    for (int i=1;i<argc;++i) {
        if (!strcmp(argv[i],"--")) { command=i+1; break; }
        if (i+1>=argc) return usage();
        if (!strcmp(argv[i],"--output")) directory=argv[++i];
        else if (!strcmp(argv[i],"--profile")) profile=argv[++i];
        else if (!strcmp(argv[i],"--timeout")) {
            char *end; errno=0; long value=strtol(argv[++i],&end,10);
            if (errno || !argv[i][0] || *end || value<1 || value>60) return usage();
            timeout=(int)value;
        } else return usage();
    }
    if (!directory || directory[0]!='/' || strlen(directory)>PATH_MAX-64 || command==0 || command>=argc || argv[command][0]!='/' ||
        (strcmp(profile,"open") && strcmp(profile,"tree") && strcmp(profile,"tree-mach"))) return usage();
    if (geteuid()!=0) { fputs("root must invoke this owned diagnostic; it never elevates itself\n",stderr); return 77; }
    struct stat fixture;
    if (stat(argv[command],&fixture) || !S_ISREG(fixture.st_mode) || access(argv[command],X_OK)) { perror("owned fixture"); return 2; }
    if (mkdir(directory,0755)) { perror("new capture directory"); return 2; }
    struct capture state={.tree=strcmp(profile,"open")!=0,.reason="not started"};
    state.events=new_file(directory,"events.jsonl"); state.errors=new_file(directory,"errors.jsonl");
    state.inventory=new_file(directory,"probes.tsv");
    FILE *program=new_file(directory,"program.d"), *target_out=new_file(directory,"target.stdout"), *target_err=new_file(directory,"target.stderr");
    if (!state.events || !state.errors || !state.inventory || !program || !target_out || !target_err) { perror("capture outputs"); return 1; }
    signal(SIGINT,on_signal); signal(SIGTERM,on_signal); signal(SIGHUP,on_signal);
    signal(SIGPIPE,SIG_IGN);
    const double capture_start=monotonic();
    int gate[2];
    if (pipe(gate)) { perror("launch gate"); return 1; }
    fcntl(gate[0],F_SETFD,FD_CLOEXEC); fcntl(gate[1],F_SETFD,FD_CLOEXEC);
    state.root=fork();
    if (state.root<0) { perror("fork gate"); return 1; }
    if (state.root==0) {
        setpgid(0,0); close(gate[1]);
        if (dup2(fileno(target_out),1)<0 || dup2(fileno(target_err),2)<0) _exit(125);
        char byte;
        if (read(gate[0],&byte,1)!=1 || byte!='G') _exit(125);
        close(gate[0]);
        execv(argv[command],argv+command);
        _exit(126);
    }
    setpgid(state.root,state.root); close(gate[0]);
    pid_t watchdog=start_watchdog(timeout,directory);
    if (watchdog<0) { kill(state.root,SIGKILL); close(gate[1]); waitpid(state.root,NULL,0); perror("deadline watchdog"); return 1; }
    struct process *root=process_for(&state,state.root); if (root) root->created=true;
    int program_error=write_program(program,state.root,profile);
    if (fclose(program)) program_error=-1;
    char program_path[PATH_MAX]; snprintf(program_path,sizeof(program_path),"%s/program.d",directory);
    int error=0; dtrace_hdl_t *handle=dtrace_open(DTRACE_VERSION,DTRACE_O_LP64,&error);
    bool go=false,root_reaped=false,timed_out=false,drained=false;
    int target_status=0;
    if (!handle) { fail_capture(&state,"dtrace_open unavailable"); fprintf(state.errors,"dtrace_open: %s\n",dtrace_errmsg(NULL,error)); }
    if (program_error) fail_capture(&state,"probe program output failed");
    if (handle) {
        if (dtrace_handle_drop(handle,drop_event,&state) || dtrace_handle_err(handle,error_event,&state) ||
            dtrace_setopt(handle,"bufsize","16m") || dtrace_setopt(handle,"bufpolicy","switch") ||
            dtrace_setopt(handle,"switchrate","20ms") || dtrace_setopt(handle,"statusrate","20ms") ||
            dtrace_setopt(handle,"dynvarsize","8m") || dtrace_setopt(handle,"temporal","yes")) {
            fail_capture(&state,"DTrace options/callback setup failed");
        }
        if (!state.failed && dtrace_probe_iter(handle,NULL,probe_inventory,state.inventory)) fail_capture(&state,"probe inventory unavailable");
        FILE *source=fopen(program_path,"r");
        dtrace_prog_t *compiled=source && !state.failed ? dtrace_program_fcompile(handle,source,0,0,NULL) : NULL;
        if (source) fclose(source);
        dtrace_proginfo_t info={0};
        if (!state.failed && (!compiled || dtrace_program_exec(handle,compiled,&info) || !info.dpi_matches || dtrace_go(handle))) {
            fail_capture(&state,"required DTrace program/provider unavailable");
        } else if (!state.failed) { go=true; state.started=true; }
        if (state.failed) fprintf(state.errors,"DTrace setup: %s\n",dtrace_errmsg(handle,dtrace_errno(handle)));
    }
    if (go && write(gate[1],"G",1)!=1) fail_capture(&state,"launch gate release failed");
    close(gate[1]); fclose(target_out); fclose(target_err);
    const double deadline=monotonic()+timeout;
    while (go && !state.failed) {
        if (interrupted || monotonic()>=deadline) { timed_out=!interrupted; fail_capture(&state,interrupted ? "collector interrupted" : "capture deadline exceeded"); break; }
        if (dtrace_work(handle,NULL,consume_probe,NULL,&state)==DTRACE_WORKSTATUS_ERROR) { libdtrace_error(&state,handle,"work","DTrace consume failed"); break; }
        if (!root_reaped) {
            pid_t waited=waitpid(state.root,&target_status,WNOHANG);
            if (waited==state.root) {
                root_reaped=true;
                if (!state.tree) { state.root_terminal=true; if (root) root->terminal=true; }
            } else if (waited<0 && errno!=EINTR) fail_capture(&state,"root wait failed");
        }
        if (root_reaped && all_terminal(&state)) break;
        struct timespec pause={.tv_nsec=10000000}; nanosleep(&pause,NULL);
    }
    if (go) {
        if (dtrace_stop(handle)) libdtrace_error(&state,handle,"stop","DTrace stop failed");
        for (unsigned i=0;i<100 && monotonic()<deadline;++i) {
            dtrace_workstatus_t status=dtrace_work(handle,NULL,consume_probe,NULL,&state);
            if (status==DTRACE_WORKSTATUS_DONE) { drained=true; break; }
            if (status==DTRACE_WORKSTATUS_ERROR) { libdtrace_error(&state,handle,"drain","DTrace final drain failed"); break; }
        }
        if (!drained || !all_terminal(&state)) fail_capture(&state,"final drain or observed tree incomplete");
    }
    if (handle) dtrace_close(handle);
    if (!root_reaped) {
        kill(-state.root,SIGKILL); kill(state.root,SIGKILL);
    }
    if (!root_reaped) {
        while (waitpid(state.root,&target_status,0)<0 && errno==EINTR) {}
        root_reaped=true;
    }
    if (go && !state.failed && (!WIFEXITED(target_status) || WEXITSTATUS(target_status)!=0 || !state.open_entries || !state.open_returns)) {
        fail_capture(&state,"owned fixture exit or required open events missing");
    }
    int close_error=fclose(state.events);
    if (fclose(state.errors)) close_error=-1;
    if (fclose(state.inventory)) close_error=-1;
    if (close_error) fail_capture(&state,"evidence output close failed");
    /* Resolve every required identity before selecting the final status. A hash
     * failure must never leave a captured receipt containing a null identity. */
    const char *files[]={"program.d","events.jsonl","errors.jsonl","probes.tsv","target.stdout","target.stderr","watchdog.json"};
    struct identity fixture_identity,collector_identity={0},evidence_identities[sizeof(files)/sizeof(files[0])];
    capture_identity(&state,argv[command],&fixture_identity);
    char executable[PATH_MAX]; uint32_t executable_size=sizeof(executable);
    if (_NSGetExecutablePath(executable,&executable_size)==0) capture_identity(&state,executable,&collector_identity);
    else { state.identity_failed=true; fail_capture(&state,"collector executable path unavailable for identity"); }
    for (size_t i=0;i<sizeof(files)/sizeof(files[0]);++i) {
        char path[PATH_MAX]; snprintf(path,sizeof(path),"%s/%s",directory,files[i]);
        capture_identity(&state,path,&evidence_identities[i]);
    }
    FILE *report=new_file(directory,"capability.json");
    if (!report) {
        kill(watchdog,SIGTERM); while (waitpid(watchdog,NULL,0)<0 && errno==EINTR) {}
        perror("capability receipt"); return 1;
    }
    struct utsname host; uname(&host);
    char product[64]="unavailable",build[64]="unavailable";
    size_t product_size=sizeof(product),build_size=sizeof(build);
    if (sysctlbyname("kern.osproductversion",product,&product_size,NULL,0)) strcpy(product,"unavailable");
    if (sysctlbyname("kern.osversion",build,&build_size,NULL,0)) strcpy(build,"unavailable");
    fprintf(report,"{\"revision\":1,\"protocol\":\"darwin-capability-raw-v1\",\"scope\":\"owned diagnostic transport only; no complete process-tree or extraction-oracle acceptance\",\"status\":\"%s\",\"reason\":",capture_status(&state));
    json_string(report,state.failed ? state.reason : "owned fixture exited, required open events observed, observed tree drained");
    fputs(",\"profile\":",report); json_string(report,profile);
    fputs(",\"host\":{\"system\":",report); json_string(report,host.sysname);
    fputs(",\"release\":",report); json_string(report,host.release);
    fputs(",\"machine\":",report); json_string(report,host.machine);
    fputs(",\"product_version\":",report); json_string(report,product);
    fputs(",\"build\":",report); json_string(report,build);
    fprintf(report,"},\"elapsed_seconds\":%.6f,\"root_pid\":%d,\"root_wait_status\":%d,\"deadline_seconds\":%d,\"timed_out\":%s,\"interrupted_signal\":%d,\"started\":%s,\"drained\":%s,\"events\":%"PRIu64",\"drops\":%"PRIu64",\"errors\":%"PRIu64",\"open_entries\":%"PRIu64",\"open_returns\":%"PRIu64",\"argv\":[",monotonic()-capture_start,state.root,target_status,timeout,timed_out ? "true" : "false",(int)interrupted,state.started ? "true" : "false",drained ? "true" : "false",state.events_seen,state.drops,state.faults,state.open_entries,state.open_returns);
    for (int i=command;i<argc;++i) { if (i!=command) fputc(',',report); json_string(report,argv[i]); }
    fputs("],\"processes\":[",report);
    for (size_t i=0;i<state.processes_used;++i) fprintf(report,"%s{\"pid\":%d,\"created\":%s,\"terminal\":%s}",i ? "," : "",state.processes[i].pid,state.processes[i].created ? "true" : "false",state.processes[i].terminal ? "true" : "false");
    fputs("],\"fixture\":",report); write_identity(report,&fixture_identity);
    fputs(",\"collector\":",report); write_identity(report,&collector_identity);
    fputs(",\"evidence\":{",report);
    for (size_t i=0;i<sizeof(files)/sizeof(files[0]);++i) {
        if (i) fputc(',',report); json_string(report,files[i]); fputc(':',report); write_identity(report,&evidence_identities[i]);
    }
    fprintf(report,"},\"identity_checks_passed\":%s,\"full_trace_acceptance\":false,\"settings_changed\":false}\n",state.identity_failed ? "false" : "true");
    bool report_error=ferror(report)!=0; if (fclose(report)) report_error=true;
    kill(watchdog,SIGTERM);
    while (waitpid(watchdog,NULL,0)<0 && errno==EINTR) {}
    if (report_error) return 1;
    return state.failed ? (state.started ? 1 : 77) : 0;
}
