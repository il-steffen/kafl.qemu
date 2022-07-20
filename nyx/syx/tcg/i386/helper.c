#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "target/i386/cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg.h"
#include "linux-headers/linux/kvm.h"
#include "nyx/hypercall/hypercall.h"

target_ulong helper_vmcall(CPUX86State *env) {
    uint64_t hypercall_id = env->regs[R_EAX];
    uint64_t hypercall_nb = env->regs[R_EBX]+100;
    uint64_t hypercall_param1 = env->regs[R_ECX];
    uint64_t hypercall_param2 = env->regs[R_EDX];
    target_ulong hypercall_ret = 0;
    CPUState* cpu = env_cpu(env);

    if (hypercall_id == HYPERCALL_KAFL_RAX_ID) {
        if (hypercall_nb >= KVM_EXIT_KAFL_ACQUIRE && hypercall_nb < KVM_EXIT_KAFL_ACQUIRE + 100) {
            assert(handle_kafl_hypercall(cpu, hypercall_nb, hypercall_param1) == 0);
        }
    }

    // Should be used to update disas structure
    return env->eip;
}