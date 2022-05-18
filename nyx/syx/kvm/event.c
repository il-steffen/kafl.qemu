#include "qemu/osdep.h"
#include "event.h"
#include "exec/memory.h"
#include "nyx/syx/syx.h"
#include "nyx/synchronization.h"
#include "nyx/auxiliary_buffer.h"
#include "nyx/state/state.h"

uint64_t syx_event_read_memory(void* opaque, hwaddr addr, unsigned size) {
    SYX_PRINTF("Memory Read Detected (address: 0x%lx | length: %u). Adding current run to SYX queue.\n", addr, size);
    syx_event_memory_access_disable();

    set_syx_start_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, addr, size);

    synchronization_lock();

    return (uint64_t) 'A';
}

void syx_event_write_memory(void* opaque, hwaddr addr, uint64_t data, unsigned size) {
    SYX_PRINTF("Memory Write Detected. Ignored.\n");
}