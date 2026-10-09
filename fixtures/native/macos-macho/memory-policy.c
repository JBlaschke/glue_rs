/* Local signed MAP_JIT policy control, independent of archived native images. */
#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int (*answer_fn)(void);

int main(void) {
    const size_t page = 16384;
    const size_t arena_size = 2 * page;
    if (sysconf(_SC_PAGESIZE) != (long)page ||
        pthread_jit_write_protect_supported_np() != 1) {
        fprintf(stderr, "memory-policy failed: require 16 KiB pages and JIT write protection\n");
        return EXIT_FAILURE;
    }
    unsigned char *arena = mmap(NULL, arena_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (arena == MAP_FAILED) {
        perror("memory-policy MAP_JIT allocation");
        return EXIT_FAILURE;
    }
    pthread_jit_write_protect_np(0);
    /* arm64: mov w0, #42; ret. The code and data occupy complete owned pages. */
    const unsigned instructions[] = {0x52800540, 0xd65f03c0};
    memcpy(arena, instructions, sizeof(instructions));
    *(int *)(arena + page) = 7;

    errno = 0;
    int text_result = mprotect(arena, page, PROT_READ | PROT_EXEC);
    int text_errno = errno;
    errno = 0;
    int data_result = mprotect(arena + page, page, PROT_READ | PROT_WRITE);
    int data_errno = errno;
    if (text_result != -1 || text_errno != EACCES ||
        data_result != -1 || data_errno != EACCES) {
        pthread_jit_write_protect_np(1);
        fprintf(stderr, "memory-policy failed: unexpected demotion text=%d errno=%d data=%d errno=%d\n",
                text_result, text_errno, data_result, data_errno);
        (void)munmap(arena, arena_size);
        return EXIT_FAILURE;
    }
    void *data = mmap(arena + page, page, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (data != arena + page) {
        pthread_jit_write_protect_np(1);
        perror("memory-policy owned data replacement");
        (void)munmap(arena, arena_size);
        return EXIT_FAILURE;
    }
    *(int *)data = 7;
    sys_icache_invalidate(arena, sizeof(instructions));
    pthread_jit_write_protect_np(1);

    answer_fn answer;
    _Static_assert(sizeof(answer) == sizeof(arena), "macOS arm64 pointer ABI");
    memcpy(&answer, &arena, sizeof(answer));
    int result = answer();
    /* Ordinary data remains writable after JIT write protection is enabled. */
    *(int *)data = 8;
    int observed_data = *(const int *)data;
    if (result != 42 || observed_data != 8) {
        fprintf(stderr, "memory-policy failed: answer=%d data=%d\n", result, observed_data);
        (void)munmap(arena, arena_size);
        return EXIT_FAILURE;
    }
    if (munmap(arena, arena_size) != 0) {
        perror("memory-policy release");
        return EXIT_FAILURE;
    }
    printf("PASS JIT demotion text=%d errno=%d data=%d errno=%d\n",
           text_result, text_errno, data_result, data_errno);
    puts("PASS owned anonymous data replacement answer=42 data=8");
    return EXIT_SUCCESS;
}
