#pragma once
#ifdef QEMU_SYX

#include "qemu/osdep.h"
#include "exec/hwaddr.h"
#include "nyx/syx/syx-misc.h"
#include "exec/cpu-common.h"

typedef uint64_t vaddr;
typedef uint64_t target_ulong;


#define SYX_EVENT_NOTIFY_SYNC       0
#define SYX_EVENT_REGISTER_ASYNC    1

typedef struct syx_event_async_param_s {
    uint64_t phys_addr;
    uint64_t virt_addr;
    size_t len;
} syx_event_async_param_t;

void syx_event_add_memory_access(hwaddr phys_start_addr, vaddr virt_start_addr, size_t len, size_t fuzz_offset);
void syx_event_init(void* opaque);
uint64_t syx_event_handler(CPUState* cpu, uint32_t cmd, target_ulong target_opaque);
void syx_event_memory_access_enable(void);
void syx_event_memory_access_disable(void);

#endif
