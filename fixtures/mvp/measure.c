/* Small measurement parent avoids inheriting the Python harness's RSS floor. */
#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) { perror("clock_gettime"); exit(125); }
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}
static double seconds(struct timeval value) {
    return (double)value.tv_sec + (double)value.tv_usec / 1000000.0;
}
int main(int argc, char **argv) {
    pid_t child, waited;
    int status, code;
    long uid;
    double started, finished;
    struct rusage usage;
    FILE *file;
    unsigned long long rss;
    if (argc < 5) { fputs("usage: measure REPORT PIDFILE UID|-1 COMMAND ARGS...\n", stderr); return 125; }
    uid = strtol(argv[3], NULL, 10);
    started = now();
    child = fork();
    if (child < 0) { perror("fork"); return 125; }
    if (child == 0) {
        if (uid >= 0 && (setgroups(0, NULL) != 0 || setgid((gid_t)uid) != 0 || setuid((uid_t)uid) != 0)) {
            perror("measurement privilege drop"); _exit(125);
        }
        execvp(argv[4], argv + 4);
        perror("measurement exec"); _exit(125);
    }
    file = fopen(argv[2], "w");
    if (file != NULL) { fprintf(file, "%ld\n", (long)child); fclose(file); }
    do { waited = wait4(child, &status, 0, &usage); } while (waited < 0 && errno == EINTR);
    finished = now();
    if (waited != child) { perror("wait4"); return 125; }
    code = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
    rss = (unsigned long long)usage.ru_maxrss;
#ifndef __APPLE__
    rss *= 1024;
#endif
    file = fopen(argv[1], "w");
    if (file == NULL) { perror("measurement report"); return 125; }
    fprintf(file, "{\"pid\":%ld,\"exit\":%d,\"elapsed_seconds\":%.9f,\"user_seconds\":%.9f,\"system_seconds\":%.9f,\"peak_rss_bytes\":%llu}\n",
            (long)child, code, finished-started, seconds(usage.ru_utime), seconds(usage.ru_stime), rss);
    if (fclose(file) != 0) { perror("measurement report close"); return 125; }
    return code >= 0 ? code : 128-code;
}
