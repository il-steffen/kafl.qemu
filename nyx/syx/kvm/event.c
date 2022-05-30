#include "qemu/osdep.h"
#include "event.h"
#include "exec/memory.h"
#include "nyx/syx/syx.h"
#include "nyx/synchronization.h"
#include "nyx/auxiliary_buffer.h"
#include "nyx/state/state.h"

uint64_t syx_event_read_memory(void* opaque, hwaddr addr, unsigned size) {
    syx_address_range_t* addr_range = (syx_address_range_t*) opaque;

    hwaddr mem_read_phys_addr = addr_range->phys_addr + addr;
    vaddr mem_read_virt_addr = addr_range->virt_addr + addr;

    SYX_PRINTF("Memory Read detected at:\n");
    printf("\t- Physical address: 0x%lx\n", mem_read_phys_addr);
    printf("\t- Virtual address: 0x%lx\n\n", mem_read_virt_addr);
    syx_event_memory_access_disable();

    set_syx_start_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, addr_range->phys_addr, addr_range->virt_addr, addr_range->length);

    synchronization_lock();

    return (uint64_t) 'A';
}

void syx_event_write_memory(void* opaque, hwaddr addr, uint64_t data, unsigned size) {
    SYX_PRINTF("Memory Write Detected. Ignored.\n");
}