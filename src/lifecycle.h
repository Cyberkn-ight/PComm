#ifndef PCOMM_LIFECYCLE_H
#define PCOMM_LIFECYCLE_H

#include <stdint.h>

void pcomm_shutdown_request(void);
int pcomm_shutdown_requested(void);

void pcomm_shutdown_reset(void);

int pcomm_shutdown_wait(uint32_t milliseconds);

#endif
