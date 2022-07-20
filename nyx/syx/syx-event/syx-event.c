#include "qemu/osdep.h"
#include "syx-event.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "nyx/syx/syx-common.h"
#include "nyx/synchronization.h"
#include "nyx/auxiliary_buffer.h"
#include "nyx/state/state.h"
#include "target/i386/cpu.h"
#include "nyx/memory_access.h"

/* TODO: replace the hard limit with a nice dynamic data structure */
#define MAX_MEM_RANGES 128
#define HC_ADDR_INIT_SIZE   16

uint64_t syx_event_read_memory(void* opaque, hwaddr addr, unsigned size);
void syx_event_write_memory(void* opaque, hwaddr addr, uint64_t data, unsigned size);

typedef struct syx_address_range_s {
    hwaddr phys_addr;
    vaddr virt_addr;
    size_t length;
    size_t fuzz_offset;
} syx_address_range_t;

typedef struct syx_event_state_s {
    bool is_initialized;

    MemoryRegion root_mr; // Container of Memory Regions to hook for further action

    /**
     * keep track of the recorded address ranges for opaque parameters
     */
    syx_address_range_t addr_ranges[MAX_MEM_RANGES]; 
    size_t nb_addr_ranges;

} syx_event_state_t;

typedef struct syx_event_hc_addr_s {
    hwaddr* phys_addr;
    uint64_t len;
    uint64_t capacity;
} syx_event_hc_addr_t;

static syx_event_state_t syx_event_state = {0};
static syx_event_hc_addr_t hc_addrs = {0};

static void hc_addr_add(syx_event_hc_addr_t* hc_addr, hwaddr addr) {
    if (hc_addr->len == hc_addr->capacity) {
        hc_addr->phys_addr = g_renew(hwaddr, hc_addr->phys_addr, 2 * hc_addr->capacity);
        hc_addr->capacity *= 2;
    }

    assert(hc_addr->len < hc_addr->capacity);
    hc_addr->phys_addr[hc_addr->len] = addr;
    hc_addr->len++;
}

static bool hc_addr_is_present(syx_event_hc_addr_t* hc_addr, hwaddr addr) {
    for (uint64_t i = 0; i < hc_addr->len; ++i) {
        if (hc_addr->phys_addr[i] == addr) {
            return true;
        }
    }

    return false;
}

static void ask_symbolic_exec(hwaddr phys_addr, vaddr virt_addr, size_t len, size_t fuzz_offset) {
    // Set symbolic execution parameters in the result buffer
    set_syx_sym_new_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, phys_addr, virt_addr, len, fuzz_offset);

    // Go back to python
    synchronization_lock();
}

void syx_event_init(void* opaque) {
    assert(!syx_event_state.is_initialized);
    memory_region_init(&syx_event_state.root_mr, NULL, "syx-memory", UINT64_MAX);
    memory_region_add_subregion_overlap(get_system_memory(), 0, &syx_event_state.root_mr, 1);

    hc_addrs.capacity = HC_ADDR_INIT_SIZE;
    hc_addrs.phys_addr = g_new(hwaddr, HC_ADDR_INIT_SIZE);

    syx_event_state.is_initialized = true;
}

// Should be used only in KVM for now.
void syx_event_add_memory_access(hwaddr phys_start_addr, vaddr virt_start_addr, size_t len, size_t fuzz_offset) {
    assert(syx_event_state.nb_addr_ranges < MAX_MEM_RANGES);
    assert(syx_event_state.is_initialized);

    SYX_PRINTF("Memory Hook request at:\n");
    printf("\t- Physical Address: %p\n", (void*) phys_start_addr);
    printf("\t- Virtual Address: %p\n", (void*) virt_start_addr);
    printf("\t- Length: %lu\n\n", len);

    /* Creating the new subregion */
    MemoryRegion* new_mr = g_new0(MemoryRegion, 1);
    MemoryRegionOps* new_mr_ops = g_new0(MemoryRegionOps, 1);
    new_mr_ops->read = syx_event_read_memory;
    new_mr_ops->write = syx_event_write_memory;
    new_mr_ops->endianness = DEVICE_NATIVE_ENDIAN;

    /* Updating the internal SYX state */
    syx_event_state.addr_ranges[syx_event_state.nb_addr_ranges].phys_addr = phys_start_addr;
    syx_event_state.addr_ranges[syx_event_state.nb_addr_ranges].virt_addr = virt_start_addr;
    syx_event_state.addr_ranges[syx_event_state.nb_addr_ranges].length = len;
    syx_event_state.addr_ranges[syx_event_state.nb_addr_ranges].fuzz_offset = fuzz_offset;

    /* Adding the fresh memory range to the SYX container */
    memory_region_init_io(new_mr, NULL, new_mr_ops, &syx_event_state.addr_ranges[syx_event_state.nb_addr_ranges], "syx memory hook subregion", len);
    memory_region_add_subregion_overlap(&syx_event_state.root_mr, phys_start_addr, new_mr, 2);

    syx_event_state.nb_addr_ranges++;
}

static void syx_event_handle_async(CPUState* cpu, target_ulong target_opaque) {
    X86CPU* xcpu = X86_CPU(cpu);
    CPUX86State* env = &(xcpu->env);

    syx_cmd_event_async_t* params = SYX_HC_GET_PARAM(syx_cmd_event_async_t, cpu, target_opaque);
    vaddr vaddr_to_hook = params->virt_addr_to_hook;
    size_t mem_len = params->len;
    size_t fuzz_offset = params->fuzz_input_offset;

	hwaddr phys_addr_to_hook = get_paging_phys_addr(cpu, env->cr[3], vaddr_to_hook);

    if (!GET_GLOBAL_STATE()->syx_sym_tcg_enabled) {
		syx_event_add_memory_access(phys_addr_to_hook, vaddr_to_hook, mem_len, fuzz_offset);
    } else {
        // Not using physical address for consistency reason...
        // The check should be added once cross-snapshoting works.
        if (vaddr_to_hook == GET_GLOBAL_STATE()->syx_virt_addr
            && mem_len == GET_GLOBAL_STATE()->syx_len) {
                syx_sym_start(phys_addr_to_hook, vaddr_to_hook, mem_len);
                syx_snapshot_increment_push(syx_get_snapshot(), cpu);
            } else {
                SYX_PRINTF("Not initializing symbolic execution\n");
                SYX_PRINTF("\t- Phys symbolized: 0x%lx | Phys hypercall: 0x%lx\n", GET_GLOBAL_STATE()->syx_phys_addr, phys_addr_to_hook);
                SYX_PRINTF("\t- Virt symbolized: 0x%lx | Virt hypercall: 0x%lx\n", GET_GLOBAL_STATE()->syx_virt_addr, vaddr_to_hook);
                SYX_PRINTF("\t- Len symbolized: %u | Len hypercall: %lu\n\n", GET_GLOBAL_STATE()->syx_len, mem_len);
                abort();
            }
    }
}

static void syx_event_handle_sync(CPUState* cpu, target_ulong target_opaque) {
    X86CPU* xcpu = X86_CPU(cpu);
    CPUX86State* env = &(xcpu->env);

    syx_cmd_event_sync_t* params = SYX_HC_GET_PARAM(syx_cmd_event_sync_t, cpu, target_opaque);
    vaddr vaddr_to_sym_exec = params->virt_addr_to_sym_exec;
    size_t mem_len = params->len;
    size_t fuzz_offset = params->fuzz_input_offset;

	hwaddr phys_addr_to_sym_exec = get_paging_phys_addr(cpu, env->cr[3], vaddr_to_sym_exec);

    if (!GET_GLOBAL_STATE()->syx_sym_tcg_enabled) {
        ask_symbolic_exec(phys_addr_to_sym_exec, vaddr_to_sym_exec, mem_len, fuzz_offset);
    } else {
        if (vaddr_to_sym_exec == GET_GLOBAL_STATE()->syx_virt_addr
            && mem_len == GET_GLOBAL_STATE()->syx_len) {
                syx_sym_start(phys_addr_to_sym_exec, vaddr_to_sym_exec, mem_len);
                syx_snapshot_increment_push(syx_get_snapshot(), cpu);
            } else {
                SYX_PRINTF("Not initializing symbolic execution\n");
                SYX_PRINTF("\t- Phys symbolized: 0x%lx | Phys hypercall: 0x%lx\n", GET_GLOBAL_STATE()->syx_phys_addr, phys_addr_to_sym_exec);
                SYX_PRINTF("\t- Virt symbolized: 0x%lx | Virt hypercall: 0x%lx\n", GET_GLOBAL_STATE()->syx_virt_addr, vaddr_to_sym_exec);
                SYX_PRINTF("\t- Len symbolized: %u | Len hypercall: %lu\n\n", GET_GLOBAL_STATE()->syx_len, mem_len);
                abort();
            }
    }
}

uint64_t syx_event_handler(CPUState* cpu, uint32_t cmd, target_ulong target_opaque) {
    uint64_t ret = (uint64_t) -1;

    switch(cmd) {
        case SYX_CMD_EVENT_ASYNC:
            syx_event_handle_async(cpu, target_opaque);
            ret = 0;
            break;
        case SYX_CMD_EVENT_SYNC:
            syx_event_handle_sync(cpu, target_opaque);
            ret = 0;
            break;
        default:
            break;
    }

    return ret;
}

uint64_t syx_event_read_memory(void* opaque, hwaddr addr, unsigned size) {
    syx_address_range_t* addr_range = (syx_address_range_t*) opaque;

    hwaddr mem_read_phys_addr = addr_range->phys_addr + addr;
    vaddr mem_read_virt_addr = addr_range->virt_addr + addr;

    SYX_PRINTF("Memory Read detected at:\n");
    printf("\t- Physical address: 0x%lx\n", mem_read_phys_addr);
    printf("\t- Virtual address: 0x%lx\n", mem_read_virt_addr);
    printf("\t- Fuzzer offset: 0x%lx\n\n", addr_range->fuzz_offset);
    syx_event_memory_access_disable();

    ask_symbolic_exec(addr_range->phys_addr, addr_range->virt_addr, addr_range->length, addr_range->fuzz_offset);

    // TODO: change that...
    return (uint64_t) 'A';
}

void syx_event_write_memory(void* opaque, hwaddr addr, uint64_t data, unsigned size) {
    SYX_PRINTF("Memory Write Detected. Ignored.\n");
}

void syx_event_memory_access_enable(void) {
    memory_region_set_enabled(&syx_event_state.root_mr, true);
    SYX_PRINTF("Memory access hook enabled.\n");
}

void syx_event_memory_access_disable(void) {
    memory_region_set_enabled(&syx_event_state.root_mr, false);
    SYX_PRINTF("Memory access hook disabled.\n\n");
}
