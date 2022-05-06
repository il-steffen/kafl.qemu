#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/log.h"
#include "accel/tcg/tcg-runtime-syx.h"

void helper_vmcall(CPUX86State *env) {
    uint64_t hypercall_nb = env->regs[R_EAX];
    uint64_t hypercall_param1 = env->regs[R_EBX];
    uint64_t hypercall_param2 = env->regs[R_ECX];
    target_ulong hypercall_ret = 0;

    SYX_PRINTF("VMCALL detected with parameter 0x%lx\n", hypercall_nb);


    if (hypercall_nb == TCG_VMCALL_SYX_INIT) {
        syx_init(hypercall_param1, hypercall_param2);
        syx_enable(env);
    }
    else if (syx_is_initialized()) {
        switch(hypercall_nb) {
            case TCG_VMCALL_SYX_ADD_MMIO:
                syx_add_mmio(hypercall_param1, hypercall_param2);
                break;
            default:
                SYX_PRINTF("vmcall: vmcall parameter unknown.\n");
                hypercall_ret = -1;
        }
    } else {
        SYX_PRINTF("vmcall: impossible to execute if SYX is not initialized.\n");
        hypercall_ret = -2;
    }

    env->regs[R_EAX] = hypercall_ret;
}

void helper_check_syx_mmio(CPUX86State *env, void* addr) {
    int32_t mmio_idx;

    // SYX_PRINTF("LOAD HANDLER\n");

    if ((mmio_idx = syx_address_to_mmio((target_ulong) addr)) != -1) {
        SYX_PRINTF("MMIO LOAD DETECTED TO ADDRESS %p (idx %d)\n", addr, mmio_idx);
    }
}