#ifndef PCOMM_CONFIG_H
#define PCOMM_CONFIG_H

#include "pcomm.h"

void pcomm_config_defaults(pcomm_config_t *cfg);

int pcomm_config_from_argv(pcomm_config_t *cfg, int argc, char **argv);

#endif
