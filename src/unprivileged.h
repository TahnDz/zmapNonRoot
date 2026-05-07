#ifndef ZMAP_UNPRIVILEGED_H
#define ZMAP_UNPRIVILEGED_H

#include <stdbool.h>

#include "iterator.h"

bool unprivileged_module_supported(void);
void start_unprivileged_scan(iterator_t *it);

#endif
