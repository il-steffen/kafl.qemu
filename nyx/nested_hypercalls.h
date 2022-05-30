#pragma once 

/* HyperTrash! */
void handle_hypercall_kafl_nested_hprintf(CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_prepare(CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_config(CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_release(CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_acquire(CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_early_release(CPUState *cpu, uint64_t hypercall_arg);