#include "qemu/osdep.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"

#include <glib.h>

#include "syx.h"
#include "kvm/event.h"

struct SYXState {
    MemoryRegion root_mr; // Container of Memory Regions to hook for further symbolic execution.
};

typedef struct SYXState SYXState;

SYXState* syx_state = NULL;

/**
 *  Initialize SYX backend.
 *  It should be called before any other operation performed related to the SYX api.
 */
void syx_init(void) {
    syx_state = g_new0(SYXState, 1);

    // SYX containers initialization
    memory_region_init(&syx_state->root_mr, NULL, "syx-memory", UINT64_MAX);
    memory_region_add_subregion_overlap(get_system_memory(), 0, &syx_state->root_mr, 1);
}

void syx_event_add_memory_access(hwaddr start_addr, size_t len) {
    SYX_PRINTF("hwaddr start: %p\n", (void*)start_addr);
    MemoryRegion* new_mr = g_new0(MemoryRegion, 1);
    MemoryRegionOps* new_mr_ops = g_new0(MemoryRegionOps, 1);
    new_mr_ops->read = syx_event_read_memory;
    new_mr_ops->write = syx_event_write_memory;
    new_mr_ops->endianness = DEVICE_NATIVE_ENDIAN;

    memory_region_init_io(new_mr, NULL, new_mr_ops, NULL, "syx random subregion?", len);
    memory_region_add_subregion_overlap(&syx_state->root_mr, start_addr, new_mr, 2);
    SYX_PRINTF("OK!\n");
}

void syx_event_memory_access_enable(void) {
    memory_region_set_enabled(&syx_state->root_mr, true);
    SYX_PRINTF("Memory access hook enabled.\n");
}

void syx_event_memory_access_disable(void) {
    memory_region_set_enabled(&syx_state->root_mr, false);
    SYX_PRINTF("Memory access hook disabled.\n");
}

MemoryRegion* syx_get_container_mr(void) {
    return &syx_state->root_mr;
}