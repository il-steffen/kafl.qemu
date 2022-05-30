#pragma once
typedef uint64_t vaddr;


#include "exec/memory.h"

#define SYX_PRINTF(format, ...)     fprintf(stderr, ("[QEMU-Syx] " format), ##__VA_ARGS__)


typedef struct syx_address_range_s {
    hwaddr phys_addr;
    vaddr virt_addr;
    size_t length;
} syx_address_range_t;

// Initialization
void syx_init(void);
void syx_init_symbolic_backend(hwaddr phys_addr, vaddr virt_addr, size_t len);
void syx_setup_workdir(char* workdir);

/** KVM functions **/

// Events

/**
 * A memory range is monitored and will trigger symbolic execution
 * once a memory read is detected in the given range.
 * 
 * @param start_addr 
 * @param len 
 */
void syx_event_add_memory_access(hwaddr phys_start_addr, vaddr virt_start_addr, size_t len);
void syx_event_memory_access_enable(void);
void syx_event_memory_access_disable(void);

// Misc
void syx_snapshot_and_start_symbolic(void);
MemoryRegion* syx_get_container_mr(void);