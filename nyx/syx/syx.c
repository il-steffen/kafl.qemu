#include "qemu/osdep.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"

#include <glib.h>
#include <assert.h>

#include "syx.h"
#include "kvm/event.h"
#include "tcg/snapshot/snapshot.h"

#include "nyx/helpers.h"
#include "nyx/memory_access.h"
#include "nyx/state/state.h"

#include "exec/cpu_ldst.h"

#define SymExpr void*
#include "RuntimeCommon.h"

/* TODO: replace the hard limit with a nice dynamic data structure */
#define MAX_MEM_RANGES 128

struct SYXState {
    bool is_symbolic_tcg; // Tells whether the actual qemu instance is running symbolically or not.

    MemoryRegion root_mr; // Container of Memory Regions to hook for further symbolic execution.

    /**
     * keep track of the recorded address ranges for opaque parameters
     */
    syx_address_range_t addr_ranges[MAX_MEM_RANGES]; 
    size_t nb_addr_ranges;

    /*
     * Output Configuration
     */
    char* syx_sym_output_f;
    int syx_sym_output_fd;

    void* host_input_addr;
    size_t input_len;
};

typedef struct SYXState SYXState;

SYXState syx_state = {0};

/**
 *  Initialize SYX backend.
 *  It should be called before any other operation performed related to the SYX api.
 */
void syx_init(void) {
    syx_state.is_symbolic_tcg = GET_GLOBAL_STATE()->syx_sym_tcg_enabled;

    // SYX containers initialization
    memory_region_init(&syx_state.root_mr, NULL, "syx-memory", UINT64_MAX);
    memory_region_add_subregion_overlap(get_system_memory(), 0, &syx_state.root_mr, 1);
}

void syx_init_symbolic_backend(hwaddr phys_addr, vaddr virt_addr, size_t len) {
    assert(syx_state.is_symbolic_tcg);
    assert(is_enabled_tcg_mode());

    CPUState* cpu = qemu_get_cpu(0);
    X86CPU *x86_cpu = X86_CPU(cpu);
	CPUX86State *env = &x86_cpu->env;
    int mmu_idx = cpu_mmu_index(env, false);

    uint8_t* input_to_symbolize = g_new0(uint8_t, len);

    read_virtual_memory(virt_addr, input_to_symbolize, len, cpu);

    void *host_addr = tlb_vaddr_to_host(env, virt_addr, MMU_DATA_LOAD, mmu_idx);

    syx_state.host_input_addr = host_addr;
    syx_state.input_len = len;

    _sym_initialize((char*) input_to_symbolize, (char*) host_addr, len, syx_state.syx_sym_output_f);
}

// Should be used only in KVM for now.
void syx_event_add_memory_access(hwaddr phys_start_addr, vaddr virt_start_addr, size_t len) {
    assert(syx_state.nb_addr_ranges < MAX_MEM_RANGES);

    SYX_PRINTF("Memory Hook request at:\n");
    printf("\t- Physical Address: %p\n", (void*) phys_start_addr);
    printf("\t- Length: %lu\n\n", len);

    /* Creating the new subregion */
    MemoryRegion* new_mr = g_new0(MemoryRegion, 1);
    MemoryRegionOps* new_mr_ops = g_new0(MemoryRegionOps, 1);
    new_mr_ops->read = syx_event_read_memory;
    new_mr_ops->write = syx_event_write_memory;
    new_mr_ops->endianness = DEVICE_NATIVE_ENDIAN;

    /* Updating the internal SYX state */
    syx_state.addr_ranges[syx_state.nb_addr_ranges].phys_addr = phys_start_addr;
    syx_state.addr_ranges[syx_state.nb_addr_ranges].virt_addr = virt_start_addr;
    syx_state.addr_ranges[syx_state.nb_addr_ranges].length = len;

    /* Adding the fresh memory range to the SYX container */
    memory_region_init_io(new_mr, NULL, new_mr_ops, &syx_state.addr_ranges[syx_state.nb_addr_ranges], "syx memory hook subregion", len);
    memory_region_add_subregion_overlap(&syx_state.root_mr, phys_start_addr, new_mr, 2);

    syx_state.nb_addr_ranges++;
}

void syx_setup_workdir(char* workdir) {
    assert(asprintf(&syx_state.syx_sym_output_f,"%s/sym_results", workdir) > 0);
}

void syx_event_memory_access_enable(void) {
    memory_region_set_enabled(&syx_state.root_mr, true);
    SYX_PRINTF("Memory access hook enabled.\n");
}

void syx_event_memory_access_disable(void) {
    memory_region_set_enabled(&syx_state.root_mr, false);
    SYX_PRINTF("Memory access hook disabled.\n\n");
}

MemoryRegion* syx_get_container_mr(void) {
    return &syx_state.root_mr;
}

void syx_end_run(CPUState* cpu) {
    _sym_analyze_run();
    sleep(4);
}

void syx_start_new_run(CPUState* cpu) {
	tcg_snapshot_restore_root(cpu);
    char* new_input = _sym_start_new_run();
    if (!new_input) {
        SYX_PRINTF("END OF RUN\n");
        exit(0);
    }
    memcpy(syx_state.host_input_addr, new_input, syx_state.input_len);

    SYX_PRINTF("New run ready!\n");
}