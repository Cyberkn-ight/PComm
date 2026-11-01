#ifndef PCOMM_LIFECYCLE_H
#define PCOMM_LIFECYCLE_H

#include <stdint.h>

/* Request shutdown from normal thread context, not a signal handler. */
void pcomm_shutdown_request(void);
int pcomm_shutdown_requested(void);

/* Reset only before starting workers, after every previous worker has joined. */
void pcomm_shutdown_reset(void);

/* Interruptible delay: 0 timeout, 1 shutdown, -1 clock/condition error. */
int pcomm_shutdown_wait(uint32_t milliseconds);

#endif
