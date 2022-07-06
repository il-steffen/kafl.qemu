#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/log.h"
#include "nyx/syx/tcg/tcg-runtime-syx.h"
#include "linux-headers/linux/kvm.h"
#include "nyx/syx/syx.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/syx/tcg/snapshot/snapshot.h"

target_ulong helper_vmcall(CPUX86State *env) {
    uint64_t hypercall_id = env->regs[R_EAX];
    uint64_t hypercall_nb = env->regs[R_EBX]+100;
    uint64_t hypercall_param1 = env->regs[R_ECX];
    uint64_t hypercall_param2 = env->regs[R_EDX];
    target_ulong hypercall_ret = 0;
    CPUState* cpu = env_cpu(env);

    if (hypercall_id == HYPERCALL_KAFL_RAX_ID) {
        if (hypercall_nb >= KVM_EXIT_KAFL_ACQUIRE && hypercall_nb < KVM_EXIT_KAFL_ACQUIRE + 100) {
            handle_kafl_hypercall(cpu, hypercall_nb, hypercall_param1);
        }
    }

    return env->eip;
}

void helper_printf(target_ulong val) {
    printf("VAL: 0x%lx\n", val);
}