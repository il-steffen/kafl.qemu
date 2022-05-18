#pragma once

#include "qemu/osdep.h"
#include "exec/memory.h"

#define SYX_PRINTF(format, ...)     fprintf(stderr, ("[syx] " format), ##__VA_ARGS__)

// Initialization
void syx_init(void);

// Events

/**
 * A memory range is monitored and will trigger symbolic execution
 * once a memory read is detected in the given range.
 * 
 * @param start_addr 
 * @param len 
 */
void syx_event_add_memory_access(hwaddr start_addr, size_t len);
void syx_event_memory_access_enable(void);
void syx_event_memory_access_disable(void);

// Misc
void syx_snapshot_and_start_symbolic(void);
MemoryRegion* syx_get_container_mr(void);