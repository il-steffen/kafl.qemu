#include "qemu/osdep.h"
#include "syx-sym.h"
#include "nyx/memory_access.h"
#include "target/i386/cpu.h"

#include "nyx/syx/syx-common.h"

#include "nyx/synchronization.h"
#include "nyx/auxiliary_buffer.h"
#include "nyx/state/state.h"

#include "exec/cpu_ldst.h"

// SYX_NAMESPACE_NEW(sym, SYX_NAMESPACE_SYM, )

#ifndef SymExpr
#define SymExpr void*
#endif

#include "RuntimeCommon.h"

typedef struct syx_sym_state_s {
    /*
     * Output Configuration
     */
    char* syx_sym_output_f;
    int syx_sym_output_fd;

    void* host_input_addr;
    size_t input_len;
} syx_sym_state_t;

syx_sym_state_t syx_sym_state = {0};

void syx_sym_init(void* opaque) {

}

void syx_sym_start(hwaddr phys_addr, vaddr virt_addr, size_t len) {
    CPUState* cpu = qemu_get_cpu(0);
    X86CPU *x86_cpu = X86_CPU(cpu);
	CPUX86State *env = &x86_cpu->env;
    int mmu_idx = cpu_mmu_index(env, false);

    uint8_t* input_to_symbolize = g_new0(uint8_t, len);

    read_virtual_memory(virt_addr, input_to_symbolize, len, cpu);

    void *host_addr = tlb_vaddr_to_host(env, virt_addr, MMU_DATA_LOAD, mmu_idx);

    syx_sym_state.host_input_addr = host_addr;
    syx_sym_state.input_len = len;

    _sym_initialize((char*) input_to_symbolize, (char*) host_addr, len, syx_sym_state.syx_sym_output_f);
}

uint64_t syx_sym_handler(CPUState* cpu, uint32_t cmd, target_ulong target_opaque) {
    uint64_t ret = (uint64_t) -1;

    switch(cmd) {
        case SYX_CMD_SYM_END:
            printf("[SYX] End of run. Executing post-run functions...\n");
            syx_sym_end_run(cpu);
            syx_sym_start_new_run(cpu);
            ret = 0;
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}

void syx_sym_setup_workdir(char* workdir) {
    assert(asprintf(&syx_sym_state.syx_sym_output_f,"%s/sym_results", workdir) > 0);
}

void syx_sym_end_run(CPUState* cpu) {
    // _sym_analyze_run();
    syx_sym_flush_results();
}

void syx_sym_start_new_run(CPUState* cpu) {
    char* new_input = _sym_start_new_run();
    if (!new_input) {
        SYX_PRINTF("End of symbolic execution. Restoring root snapshot and asking for a new task...\n");
        syx_snapshot_root_restore(syx_get_snapshot(), cpu);
        set_syx_sym_wait_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
        synchronization_lock();
        
    }

    syx_snapshot_increment_restore_last(syx_get_snapshot());
    memcpy(syx_sym_state.host_input_addr, new_input, syx_sym_state.input_len);

    SYX_PRINTF("New run ready!\n");
}

void syx_sym_flush_results(void) {
    size_t nb_flush = _sym_flush_results();
    if (nb_flush > 0) {
        set_syx_sym_flush_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
        synchronization_lock();
    }
}