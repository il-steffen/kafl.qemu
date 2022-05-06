#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg.h"
#include "tcg-runtime-syx.h"
#include "exec/exec-all.h"

#define SymExpr void*
#include "RuntimeCommon.h"

#define MMIO_RANGES_INIT_SIZE   16

SYXMmioRangeDynArray syx_mmio_range_dyn_array_init(void);
void syx_mmio_range_dyn_array_add(SYXMmioRange* mmio_range);
SYXMmioRange* syx_mmio_range_get(size_t idx);

bool syx_enabled = false;
SYXState* syx_state = NULL;

void syx_init(vaddr start_addr, size_t len) {
    SYX_PRINTF("initialization... ");

    syx_state = g_malloc0(sizeof(SYXState));
    syx_state->mmio_array = syx_mmio_range_dyn_array_init();

    SYXMmioRange mmio_range = {
        .active = true,
        .len = len,
        .start_addr = start_addr
    };

    syx_mmio_range_dyn_array_add(&mmio_range);

    _sym_initialize((char*) start_addr, len);

    printf("done.\n");
}

bool syx_is_initialized(void) {
    return syx_state != NULL;
}

bool syx_is_enabled(void) {
    return syx_enabled;
}

void syx_enable(CPUX86State* cpu) {
    syx_enabled = true;

    // tb_flush((CPUState*) cpu);
}

void syx_disable(void) {
    syx_enabled = false;
}

void syx_add_mmio(vaddr start_addr, size_t len) {
    SYX_PRINTF("Add MMIO... ");

    SYXMmioRange mmio_range = {
        .active = true,
        .len = len,
        .start_addr = start_addr
    };

    _sym_add_input_buffer((void *) start_addr, len);

    syx_mmio_range_dyn_array_add(&mmio_range);
    printf("Done.\n");
}

SYXMmioRangeDynArray syx_mmio_range_dyn_array_init(void) {
    SYXMmioRangeDynArray mmio_range_array;

    mmio_range_array.capacity = MMIO_RANGES_INIT_SIZE;
    mmio_range_array.mmio_ranges = g_new0(SYXMmioRange, mmio_range_array.capacity);
    mmio_range_array.len = 0;

    return mmio_range_array;
}

void syx_mmio_range_dyn_array_add(SYXMmioRange* mmio_range) {
    if (syx_state->mmio_array.len == syx_state->mmio_array.capacity) {
        syx_state->mmio_array.capacity *= 2;
        syx_state->mmio_array.mmio_ranges = g_realloc(syx_state->mmio_array.mmio_ranges, syx_state->mmio_array.capacity);
    }

    syx_state->mmio_array.mmio_ranges[syx_state->mmio_array.len++] = *mmio_range;
}

// returns NULL if out of range
SYXMmioRange* syx_mmio_range_get(size_t idx) {
    if (idx >= syx_state->mmio_array.len) {
        return NULL;
    }

    return &(syx_state->mmio_array.mmio_ranges[idx]);
}

// Returns -1 if the address is not in the mmio range
int32_t syx_address_to_mmio(target_ulong address) {
    if (syx_is_initialized()) {
        for (size_t i = 0; i < syx_state->mmio_array.len; ++i) {
            SYXMmioRange* mmio_range = syx_mmio_range_get(i);

            assert(mmio_range != NULL);

            if (mmio_range->start_addr <= address && address < mmio_range->start_addr + mmio_range->len) {
                return i;
            }
        }
    }

    return -1;
}