#include <pthread.h>
static _Thread_local int state;
int secondary_answer(void) { return 42; }
static void *worker(void *ignored) {
    (void)ignored;
    state = 7;
    return state == 7 ? (void *)1 : (void *)0;
}
int secondary_threads(void) {
    pthread_t thread;
    void *result = 0;
    state = 17;
    if (pthread_create(&thread, 0, worker, 0) != 0) return 0;
    if (pthread_join(thread, &result) != 0) return 0;
    return result == (void *)1 && state == 17;
}
