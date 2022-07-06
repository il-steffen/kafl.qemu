#pragma once
typedef uint64_t vaddr;

#define SymExpr void*

#include "exec/memory.h"

#include "RuntimeCommon.h"

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

// Run management
void syx_end_run(CPUState* cpu);
void syx_start_new_run(CPUState* cpu);

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

const char* sym_solver_to_string(void);