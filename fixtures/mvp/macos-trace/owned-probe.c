/* Diagnostic fixture owned by the test, never packaged application code. */
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buffer[64];
    int file;
    ssize_t count;
    if (argc != 2) return 64;
    alarm(3);
    /* Use the exact Darwin open syscall so a single named probe suffices.
       libc's syscall entry point is deprecated for production applications. */
    file = (int)syscall(SYS_open, argv[1], O_RDONLY | O_CLOEXEC, 0);
    if (file < 0) { perror("owned open"); return 65; }
    count = read(file, buffer, sizeof(buffer));
    if (close(file) != 0 || count != 20) return 66;
    return write(STDOUT_FILENO, "owned-read-complete\n", 20) == 20 ? 0 : 67;
}
