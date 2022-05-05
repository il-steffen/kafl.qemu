#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/log.h"
#include "nyx/syx.h"

void helper_vmcall(CPUX86State *env) {
    uint64_t hypercall_nb = env->regs[R_EAX];
    uint64_t hypercall_ret = 0;

    SYX_PRINTF("VMCALL detected with parameter 0x%lx\n", hypercall_nb);

    env->regs[R_EAX] = hypercall_ret;
}