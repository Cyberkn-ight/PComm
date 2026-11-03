#include "lifecycle.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
} gate_t;

typedef struct {
    gate_t *gate;
    int result;
} waiter_t;

static void *wait_for_shutdown(void *arg) {
    waiter_t *waiter = (waiter_t *)arg;
    pthread_mutex_lock(&waiter->gate->mutex);
    waiter->gate->ready++;
    pthread_cond_broadcast(&waiter->gate->condition);
    pthread_mutex_unlock(&waiter->gate->mutex);
    waiter->result = pcomm_shutdown_wait(60000);
    return NULL;
}

int main(void) {
    enum { WORKERS = 12 };
    gate_t gate = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0};
    pthread_t threads[WORKERS];
    waiter_t waiters[WORKERS];
    unsigned started = 0;
    int failed = 0;
    pcomm_shutdown_reset();
    if (pcomm_shutdown_requested() || pcomm_shutdown_wait(2) != 0) failed = 1;
    for (unsigned i = 0; i < WORKERS; i++) {
        waiters[i] = (waiter_t){&gate, -99};
        if (pthread_create(&threads[i], NULL, wait_for_shutdown, &waiters[i]) != 0) {
            failed = 1;
            break;
        }
        started++;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready < started) pthread_cond_wait(&gate.condition, &gate.mutex);
    pthread_mutex_unlock(&gate.mutex);
    pcomm_shutdown_request();
    pcomm_shutdown_request();
    if (!pcomm_shutdown_requested() || pcomm_shutdown_wait(0) != 1) failed = 1;
    for (unsigned i = 0; i < started; i++) {
        if (pthread_join(threads[i], NULL) != 0) abort();
        if (waiters[i].result != 1) failed = 1;
    }
    if (started != WORKERS) failed = 1;
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);
    pcomm_shutdown_reset();
    if (pcomm_shutdown_requested() || pcomm_shutdown_wait(0) != 0) failed = 1;
    if (failed) {
        fputs("Shutdown flag/wake/reset checks failed.\n", stderr);
        return EXIT_FAILURE;
    }
    puts("Shutdown flag, concurrent wake, repeated request, and reset checks passed.");
    return EXIT_SUCCESS;
}
