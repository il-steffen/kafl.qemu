#pragma once
#ifdef QEMU_SYX

#include "qemu/osdep.h"
#include "exec/hwaddr.h"
#include "nyx/syx/syx-misc.h"

typedef uint64_t vaddr;
typedef uint64_t target_ulong;


// Run: starts from the beginning of the target to fulfill
//      a given request
// Internal run: starts from the beginning of the target and
//               is due to an input generated internally.

// namespace API

void syx_sym_init(void* opaque);

uint64_t syx_sym_handler(CPUState* cpu, uint32_t cmd, target_ulong target_opaque);


void syx_sym_setup_workdir(char* workdir);
bool syx_sym_fuzz_is_symbolized_input(size_t fuzzer_input_offset, size_t len);

// Run

// To call once it's possible to receive and handle a symbolic request
void syx_sym_run_start(CPUState* cpu);

// To call at the end of a run. Depending on the situation, it will either
// Continue with a new internal input or start a new full run.
void syx_sym_run_end(CPUState* cpu);

// Input generation is automatically diabled
// At the end of a run (being internal or not)
void syx_sym_run_generate_new_inputs(void);
#endif