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
    uint32_t fuzzer_input_offset;
    uint32_t symbolized_input_len;
} syx_sym_state_t;

syx_sym_state_t syx_sym_state = {0};

static void* payload_offset_to_host_addr(uint32_t payload_offset) {
    return (void*)((uint64_t) GET_GLOBAL_STATE()->shared_payload_buffer_host_location_pg[(payload_offset / x86_64_PAGE_SIZE)] + (payload_offset & x86_64_PAGE_OFFSET_MASK));
}

static inline uint32_t get_page_offset(uint64_t value) {
    return value / x86_64_PAGE_SIZE;
}

// check whether [payload_offset; payload_offset + len[ is contiguous
// in host memory.
static bool payload_range_host_contiguous(uint32_t payload_offset, uint32_t len) {
    if (len < x86_64_PAGE_SIZE) {
        return true;
    }

    for (uint32_t i = get_page_offset(payload_offset); i < get_page_offset(payload_offset + len) - 1; ++i) {
        if ((uint64_t) GET_GLOBAL_STATE()->shared_payload_buffer_host_location_pg[i] != ((uint64_t) GET_GLOBAL_STATE()->shared_payload_buffer_host_location_pg[i + 1]) + x86_64_PAGE_SIZE) {
            return false;
        }
    }

    return true;
}

void syx_sym_init(void* opaque) {
    assert(syx_sym_state.syx_sym_output_f != NULL);

    _sym_initialize(syx_sym_state.syx_sym_output_f);
}

void syx_sym_run_start(CPUState* cpu) {
    SYX_PRINTF("Waiting for symbolic execution request...\n");
    set_syx_sym_wait_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
    synchronization_lock();

    assert(payload_range_host_contiguous(GET_GLOBAL_STATE()->syx_fuzzer_input_offset, GET_GLOBAL_STATE()->syx_len));

    syx_sym_state.symbolized_input_len = GET_GLOBAL_STATE()->syx_len;
    syx_sym_state.fuzzer_input_offset = GET_GLOBAL_STATE()->syx_fuzzer_input_offset;
    syx_sym_state.host_symbolized_addr_start = (void*) payload_offset_to_host_addr(syx_sym_state.fuzzer_input_offset);

    SYX_DEBUG("Symbolic Execution request received!\n");
    SYX_DEBUG("\t-fuzzer input location: %p\n", GET_GLOBAL_STATE()->shared_payload_buffer_host_location_pg[0]);
    SYX_DEBUG("\t-fuzzer input location: %p\n", syx_sym_state.host_symbolized_addr_start);
    SYX_DEBUG("\t-fuzzer input offset: %u\n", GET_GLOBAL_STATE()->syx_fuzzer_input_offset);
    SYX_DEBUG("\t-len: %u\n", GET_GLOBAL_STATE()->syx_len);
    SYX_DEBUG("\t-hexdump: \n");
#ifdef CONFIG_DEBUG_SYX
    qemu_hexdump(GET_GLOBAL_STATE()->shared_payload_buffer_host_location_pg[0], stderr, "", 32);
#endif

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
    //_sym_print_deps();
}

void syx_sym_hexdump_current_input(void) {
    SYX_DEBUG("== Current input hexdump ==");

    uint32_t nb_bytes_to_print = 50;

    uint32_t nb_pages = (nb_bytes_to_print / x86_64_PAGE_SIZE);

    if (nb_bytes_to_print > 0 && nb_bytes_to_print % x86_64_PAGE_SIZE != 0) {
        nb_pages++;
    }

    {
        uint32_t nb_remaining_bytes = nb_bytes_to_print;
        
        for (uint32_t i = 0; i < nb_pages; ++i) {
            qemu_hexdump(GET_GLOBAL_STATE()->shared_payload_buffer_host_location_pg[i], stderr, "[SYX INPUT] ", MIN(nb_remaining_bytes, x86_64_PAGE_SIZE));
            nb_remaining_bytes -= x86_64_PAGE_SIZE;
        }
        // nb_remaining_bytes value is undefined from this point onwards
    }
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
        syx_sym_run_start(cpu);
    }
}

void syx_sym_run_generate_new_inputs(void) {
    _sym_run_generate_new_inputs();
}

bool syx_sym_fuzz_is_symbolized_input(size_t fuzzer_input_offset, size_t len) {
    return (fuzzer_input_offset == syx_sym_state.fuzzer_input_offset && len == syx_sym_state.symbolized_input_len);
}