#pragma once

#include "qemu/osdep.h"
#include "exec/hwaddr.h"
#include "nyx/syx/syx-misc.h"

typedef uint64_t vaddr;
typedef uint64_t target_ulong;

void syx_sym_init(void* opaque);
void syx_sym_start(hwaddr phys_addr, vaddr virt_addr, size_t len);
uint64_t syx_sym_handler(CPUState* cpu, uint32_t cmd, target_ulong target_opaque);
void syx_sym_setup_workdir(char* workdir);
void syx_sym_flush_results(void);
void syx_sym_end_run(CPUState* cpu);
void syx_sym_start_new_run(CPUState* cpu);