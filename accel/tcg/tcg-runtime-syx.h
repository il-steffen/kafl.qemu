#pragma once

#define TCG_VMCALL_SYX_INIT         0
#define TCG_VMCALL_SYX_ADD_MMIO     1

#include <stdio.h>

#define SYX_PRINTF(format, ...)     fprintf(stderr, ("[syx] " format), ##__VA_ARGS__)

// An MMIO range to execute symbolically
struct SYXMmioRange {
    // MMIO start address
    vaddr start_addr;

    // Length of the MMIO range
    size_t len;

    // Is the MMIO range actively tracked?
    bool active;
};

// A dynamic array implementation for MMIO
// ranges storage.
struct SYXMmioRangeDynArray {
    struct SYXMmioRange* mmio_ranges;
    size_t len;
    size_t capacity;
};

struct SYXState {
    struct SYXMmioRangeDynArray mmio_array;
};

typedef struct SYXMmioRange SYXMmioRange;
typedef struct SYXMmioRangeDynArray SYXMmioRangeDynArray;
typedef struct SYXState SYXState;

void syx_init(vaddr start_addr, size_t len);
bool syx_is_initialized(void);
bool syx_is_enabled(void);
void syx_enable(CPUX86State* cpu);
void syx_disable(void);
void syx_add_mmio(vaddr start_addr, size_t len);
int32_t syx_address_to_mmio(target_ulong address);