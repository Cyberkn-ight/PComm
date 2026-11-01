#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "lifecycle.h"

#include <stdatomic.h>

static atomic_int g_stopping = 0;

int pcomm_shutdown_requested(void) {
    return atomic_load_explicit(&g_stopping, memory_order_acquire);
}

#ifdef _WIN32
#include <windows.h>

/* Native winpthreads exposes condattr_setclock but rejects CLOCK_MONOTONIC.
 * Windows condition variables provide relative waits without wall-clock jumps.
 */
static SRWLOCK g_stop_mutex = SRWLOCK_INIT;
static CONDITION_VARIABLE g_stop_condition = CONDITION_VARIABLE_INIT;

void pcomm_shutdown_request(void) {
    AcquireSRWLockExclusive(&g_stop_mutex);
    atomic_store_explicit(&g_stopping, 1, memory_order_release);
    WakeAllConditionVariable(&g_stop_condition);
    ReleaseSRWLockExclusive(&g_stop_mutex);
}

void pcomm_shutdown_reset(void) {
    AcquireSRWLockExclusive(&g_stop_mutex);
    atomic_store_explicit(&g_stopping, 0, memory_order_release);
    ReleaseSRWLockExclusive(&g_stop_mutex);
}

int pcomm_shutdown_wait(uint32_t milliseconds) {
    uint64_t started = GetTickCount64();
    int result = 0;
    AcquireSRWLockExclusive(&g_stop_mutex);
    while (!pcomm_shutdown_requested()) {
        uint64_t elapsed = GetTickCount64() - started;
        if (elapsed >= milliseconds) break;
        DWORD remaining = (DWORD)(milliseconds - elapsed);
        if (remaining == INFINITE) remaining--;
        if (!SleepConditionVariableSRW(&g_stop_condition, &g_stop_mutex, remaining, 0) &&
            GetLastError() != ERROR_TIMEOUT) { result = -1; break; }
    }
    if (pcomm_shutdown_requested()) result = 1;
    ReleaseSRWLockExclusive(&g_stop_mutex);
    return result;
}

#else
#include <errno.h>
#include <pthread.h>
#include <time.h>

static pthread_mutex_t g_stop_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_stop_condition;
static pthread_once_t g_stop_once = PTHREAD_ONCE_INIT;
static int g_stop_init_error = 0;

static void initialize_stop_condition(void) {
    pthread_condattr_t attributes;
    int rc = pthread_condattr_init(&attributes);
    if (rc != 0) { g_stop_init_error = rc; return; }
    rc = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
    if (rc == 0) rc = pthread_cond_init(&g_stop_condition, &attributes);
    pthread_condattr_destroy(&attributes);
    g_stop_init_error = rc;
}

void pcomm_shutdown_request(void) {
    pthread_once(&g_stop_once, initialize_stop_condition);
    pthread_mutex_lock(&g_stop_mutex);
    atomic_store_explicit(&g_stopping, 1, memory_order_release);
    if (g_stop_init_error == 0) pthread_cond_broadcast(&g_stop_condition);
    pthread_mutex_unlock(&g_stop_mutex);
}

void pcomm_shutdown_reset(void) {
    pthread_once(&g_stop_once, initialize_stop_condition);
    pthread_mutex_lock(&g_stop_mutex);
    atomic_store_explicit(&g_stopping, 0, memory_order_release);
    pthread_mutex_unlock(&g_stop_mutex);
}

int pcomm_shutdown_wait(uint32_t milliseconds) {
    if (pthread_once(&g_stop_once, initialize_stop_condition) != 0 || g_stop_init_error != 0) return -1;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) return -1;
    deadline.tv_sec += milliseconds / 1000;
    deadline.tv_nsec += (long)(milliseconds % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    if (pthread_mutex_lock(&g_stop_mutex) != 0) return -1;
    int rc = 0;
    while (!pcomm_shutdown_requested() && rc == 0) {
        rc = pthread_cond_timedwait(&g_stop_condition, &g_stop_mutex, &deadline);
    }
    int result = pcomm_shutdown_requested() ? 1 : rc == ETIMEDOUT ? 0 : -1;
    if (pthread_mutex_unlock(&g_stop_mutex) != 0) return -1;
    return result;
}

#endif
