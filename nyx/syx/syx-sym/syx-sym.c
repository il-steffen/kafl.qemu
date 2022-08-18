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

    // Symbolic Execution Input Informations
    void* host_symbolized_addr_start;
    size_t fuzzer_input_offset;
    size_t symbolized_input_len;
} syx_sym_state_t;

syx_sym_state_t syx_sym_state = {0};

void syx_sym_init(void* opaque) {
    assert(syx_sym_state.syx_sym_output_f != NULL);

    _sym_initialize(syx_sym_state.syx_sym_output_f);
}

void syx_sym_run_start(CPUState* cpu) {
    //SYX_PRINTF("Waiting for symbolic execution request...\n");
    set_syx_sym_wait_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
    synchronization_lock();

    syx_sym_state.symbolized_input_len = GET_GLOBAL_STATE()->syx_len;
    syx_sym_state.fuzzer_input_offset = GET_GLOBAL_STATE()->syx_fuzzer_input_offset;
    syx_sym_state.host_symbolized_addr_start = (void*) (((uint8_t*)(GET_GLOBAL_STATE()->shared_payload_buffer_host_location)) + syx_sym_state.fuzzer_input_offset);

    //SYX_PRINTF("Symbolic Execution request received!\n");
    //SYX_PRINTF("\t-fuzzer input location: %p\n", GET_GLOBAL_STATE()->shared_payload_buffer_host_location);
    //SYX_PRINTF("\t-fuzzer input location: %p\n", syx_sym_state.host_symbolized_addr_start);
    //SYX_PRINTF("\t-fuzzer input offset: %u\n", GET_GLOBAL_STATE()->syx_fuzzer_input_offset);
    //SYX_PRINTF("\t-len: %u\n", GET_GLOBAL_STATE()->syx_len);
    //SYX_PRINTF("\t-first hex: %2X\n", *(uint8_t*)(syx_sym_state.host_symbolized_addr_start));

    //SYX_PRINTF("\tSymbolic memory dump:\n");

    //qemu_hexdump((char*) syx_sym_state.host_symbolized_addr_start, stderr, "", syx_sym_state.symbolized_input_len);

    _sym_run_start(syx_sym_state.host_symbolized_addr_start, syx_sym_state.symbolized_input_len);
}

uint64_t syx_sym_handler(CPUState* cpu, uint32_t cmd, target_ulong target_opaque) {
    uint64_t ret = (uint64_t) -1;

    switch(cmd) {
        case SYX_CMD_SYM_END:
            // printf("[SYX] End of run. Executing post-run functions...\n");
            syx_sym_run_end(cpu);
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

static void flush_sym_results(void) {
    size_t nb_flush = _sym_flush_results();
    if (nb_flush > 0) {
        set_syx_sym_flush_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
        synchronization_lock();
    }
}

static void post_run_handler(void) {
    flush_sym_results();
}

void syx_sym_run_end(CPUState* cpu) {
    post_run_handler();

    // Snapshot restoration must be done BEFORE a call to
    // _sym_start_try_next_internal_run to avoid overwriting
    // the next symbolic input.
    syx_snapshot_root_restore(syx_get_snapshot(), cpu);

    bool new_input = _sym_run_try_start_next_internal_run();

    // No new internal run; start a new full run.
    if (!new_input) {
        SYX_PRINTF("End of symbolic execution for current symbolic request.\n"
                    "Asking for a new task...\n");
        syx_sym_run_start(cpu);
    }

    // SYX_PRINTF("Starting next internal run...\n");
}

void syx_sym_run_generate_new_inputs(void) {
    _sym_run_generate_new_inputs();
}

bool syx_sym_fuzz_is_symbolized_input(size_t fuzzer_input_offset, size_t len) {
    return (fuzzer_input_offset == syx_sym_state.fuzzer_input_offset && len == syx_sym_state.symbolized_input_len);
}