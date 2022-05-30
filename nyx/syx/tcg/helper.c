#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/log.h"
#include "nyx/syx/tcg/tcg-runtime-syx.h"
#include "linux-headers/linux/kvm.h"
#include "nyx/syx/syx.h"
#include "nyx/hypercall/hypercall.h"

void helper_vmcall(CPUX86State *env) {
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
        // if (hypercall_nb == KVM_EXIT_KAFL_SYX_INIT) {
        //     syx_init();
        //     syx_enable(env);
        // }
        // else if (syx_is_initialized()) {
        //     switch(hypercall_nb) {
        //         case KVM_EXIT_KAFL_SYX_ADD_MEMORY_ACCESS:
        //             syx_add_mmio(hypercall_param1, hypercall_param2);
        //             break;
        //         default:
        //             SYX_PRINTF("vmcall: vmcall parameter unknown (ignored).\n");
        //             hypercall_ret = -1;
        //     }
        // } else {
        //     SYX_PRINTF("vmcall: impossible to execute if SYX is not initialized.\n");
        //     hypercall_ret = -2;
        // }

        // env->regs[R_EAX] = hypercall_ret;
    }
}

void helper_check_syx_mmio(CPUX86State *env, void* addr) {
    int32_t mmio_idx;

    // SYX_PRINTF("LOAD HANDLER\n");

    // if ((mmio_idx = syx_address_to_mmio((target_ulong) addr)) != -1) {
    //     SYX_PRINTF("MMIO LOAD DETECTED TO ADDRESS %p (idx %d)\n", addr, mmio_idx);
    // }
}