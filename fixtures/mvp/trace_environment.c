#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) && !defined(__ILP32__) && (defined(__x86_64__) || defined(__aarch64__))
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#define NATIVE_MACHINE "x86_64"
#elif defined(__aarch64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define NATIVE_MACHINE "aarch64"
#endif

/* Native 64-bit Linux kernel async-I/O interfaces. POSIX libc AIO based on
 * ordinary threads/syscalls is deliberately allowed and remains traceable. */
#define ASYNC_CALLS(X) \
    X(io_uring_setup) X(io_uring_enter) X(io_uring_register) \
    X(io_setup) X(io_destroy) X(io_submit) X(io_cancel) \
    X(io_getevents) X(io_pgetevents)
#define DENY_CALL(name) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),

static int install_policy(void) {
    struct utsname host;
    if (uname(&host) != 0 || strcmp(host.machine, NATIVE_MACHINE) != 0) {
        fprintf(stderr, "trace environment requires native %s Linux\n", NATIVE_MACHINE);
        return -1;
    }
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        /* x32 uses the same audit architecture with a different syscall ABI. */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
#endif
        ASYNC_CALLS(DENY_CALL)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { (unsigned short)(sizeof(filter) / sizeof(filter[0])), filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        perror("install trace environment policy");
        return -1;
    }
    return 0;
}

static int ordinary_file_io(void) {
    char name[] = "/tmp/glue-trace-environment-XXXXXX", bytes[4] = {0};
    int fd = mkstemp(name);
    if (fd < 0) return -1;
    int removed = unlink(name) == 0;
    int ok = removed && write(fd, "file", 4) == 4 &&
        lseek(fd, 0, SEEK_SET) == 0 && read(fd, bytes, 4) == 4 &&
        memcmp(bytes, "file", 4) == 0;
    if (close(fd) != 0) ok = 0;
    if (!removed) unlink(name);
    return ok ? 0 : -1;
}

static int verify_filtered(void) {
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER) {
        fprintf(stderr, "required inherited no_new_privs/filter mode is absent\n");
        return -1;
    }
    struct denied { const char *name; long number; };
#define PROBE_CALL(name) { #name, __NR_##name },
    const struct denied calls[] = { ASYNC_CALLS(PROBE_CALL) };
    printf("{\"no_new_privs\":1,\"seccomp_mode\":2,\"syscalls\":[");
    for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); ++i) {
        errno = 0;
        long result = syscall(calls[i].number, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL);
        int error = errno;
        if (result != -1 || error != ENOSYS) {
            fprintf(stderr, "%s did not return ENOSYS: result=%ld errno=%d\n", calls[i].name, result, error);
            return -1;
        }
        printf("%s{\"name\":\"%s\",\"number\":%ld,\"errno\":%d}", i ? "," : "", calls[i].name, calls[i].number, error);
    }
#if defined(__x86_64__)
    errno = 0;
    if (syscall(__NR_getpid | 0x40000000U) != -1 || errno != ENOSYS) {
        fprintf(stderr, "x32 ABI guard did not return ENOSYS\n");
        return -1;
    }
    /* Exercise the other audit architecture using a real compat syscall,
     * without relying on an installed 32-bit executable or loader. */
    long compat_result;
    __asm__ volatile("int $0x80" : "=a"(compat_result) : "0"(20L)
                     : "r8", "r9", "r10", "r11", "memory", "cc");
    if (compat_result != -ENOSYS) {
        fprintf(stderr, "i386 audit architecture guard did not return ENOSYS\n");
        return -1;
    }
    printf("],\"abi_guards\":{\"x32_errno\":%d,\"i386_errno\":%d}", ENOSYS, ENOSYS);
#else
    printf("]");
#endif
    if (ordinary_file_io() != 0 || getpid() <= 0) {
        perror("ordinary file/process syscall control");
        return -1;
    }
    printf(",\"ordinary_file_io\":true,\"native_syscalls_allowed\":true}");
    return 0;
}

static int probe(void) {
    struct io_uring_params parameters = {0};
    errno = 0;
    long control = syscall(__NR_io_uring_setup, 1U, &parameters);
    int control_error = control < 0 ? errno : 0;
    if (control >= 0 && close((int)control) != 0) return 1;
    int before_nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    int before_filter = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (install_policy() != 0) return 1;
    int output[2];
    if (pipe2(output, O_CLOEXEC) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(output[0]);
        if (dup2(output[1], STDOUT_FILENO) < 0) _exit(125);
        close(output[1]);
        execl("/proc/self/exe", "glue-trace-environment", "--probe-child", (char *)NULL);
        _exit(126);
    }
    close(output[1]);
    char inherited[8192]; size_t size = 0;
    for (;;) {
        ssize_t count = read(output[0], inherited + size, sizeof(inherited) - size - 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return 1;
        if (count == 0) break;
        size += (size_t)count;
        if (size == sizeof(inherited) - 1) return 1;
    }
    close(output[0]); inherited[size] = '\0';
    int status;
    while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) return 1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "inherited exec child failed\n"); return 1;
    }
    printf("{\"policy\":\"traceable-native-syscalls-v1\",\"architecture\":\"%s\",", NATIVE_MACHINE);
    printf("\"uid\":%lu,\"gid\":%lu,", (unsigned long)getuid(), (unsigned long)getgid());
    printf("\"before_policy\":{\"setup_succeeded\":%s,\"setup_errno\":%d,\"no_new_privs\":%d,\"seccomp_mode\":%d},", control >= 0 ? "true" : "false", control_error, before_nnp, before_filter);
    printf("\"parent\":");
    if (verify_filtered() != 0) return 1;
    printf(",\"inherited_exec_child\":%s,\"status\":\"passed\"}\n", inherited);
    return 0;
}
#endif

int main(int argc, char **argv) {
    int is_probe = argc == 2 && strcmp(argv[1], "--probe") == 0;
    int is_child = argc == 2 && strcmp(argv[1], "--probe-child") == 0;
    int is_exec = argc >= 3 && strcmp(argv[1], "--") == 0 && argv[2][0] != '\0';
    if (!is_probe && !is_child && !is_exec) {
        fprintf(stderr, "usage: glue-trace-environment --probe | -- COMMAND [ARG ...]\n");
        return 2;
    }
#if defined(__linux__) && !defined(__ILP32__) && (defined(__x86_64__) || defined(__aarch64__))
    if (is_probe) return probe();
    if (is_child) { int result = verify_filtered(); if (!result) putchar('\n'); return result ? 1 : 0; }
    if (install_policy() != 0) return 1;
    execvp(argv[2], argv + 2);
    int error = errno;
    perror("exec trace-environment command");
    return error == ENOENT ? 127 : 126;
#else
    fprintf(stderr, "trace environment supports native 64-bit Linux x86_64/aarch64 only\n");
    return 77;
#endif
}
