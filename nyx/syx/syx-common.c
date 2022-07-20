#include "syx-common.h"
#include "nyx/memory_access.h"
#include "qemu/main-loop.h"
#include "nyx/state/state.h"

static syx_namespace_t syx_namespaces[SYX_NS_MAX] = {
    SYX_NAMESPACE_ENTRY(SYX_NS_ID_SNAPSHOT, true, syx_snapshot_init, syx_snapshot_handler,
        SYX_ACCEL_DECODE(SYX_ACCEL_TCG),
        SYX_ARCH_DECODE(SYX_ARCH_X86)),

    SYX_NAMESPACE_ENTRY(SYX_NS_ID_EVENT, false, syx_event_init, syx_event_handler,
        SYX_ACCEL_DECODE(SYX_ACCEL_KVM) | SYX_ACCEL_DECODE(SYX_ACCEL_TCG),
        SYX_ARCH_DECODE(SYX_ARCH_X86)),

    SYX_NAMESPACE_ENTRY(SYX_NS_ID_SYM, false, syx_sym_init, syx_sym_handler,
        SYX_ACCEL_DECODE(SYX_ACCEL_TCG),
        SYX_ARCH_DECODE(SYX_ARCH_X86))
};

typedef struct syx_state_s {
    syx_accel accel;
    syx_arch arch;

    bool is_symbolic;
    bool is_initialized;

    syx_snapshot_t* snapshot;
} syx_state_t;

syx_state_t syx_state = {0};

void* get_data_from_target(CPUState* cpu, vaddr virt_addr, size_t len) {
    void* data = g_new(void, len);
    read_virtual_memory(virt_addr, data, len, cpu);
    return data;
}

static bool arch_is_compatible(syx_namespace_t* ns, syx_arch arch) {
    return (ns->supported_arch & SYX_ARCH_DECODE(arch)) != 0; 
}

static bool accel_is_compatible(syx_namespace_t* ns, syx_accel accel) {
    return (ns->supported_accel & SYX_ACCEL_DECODE(accel)) != 0;
}

void syx_init(bool is_symbolic) {
    bool must_unlock_iothread = false;
    if (!qemu_mutex_iothread_locked()) {
        qemu_mutex_lock_iothread();
        must_unlock_iothread = true;
    }
    assert(!syx_state.is_initialized);

    assert(syx_state.accel != SYX_ACCEL_UNDEF);
    assert(syx_state.arch != SYX_ARCH_UNDEF);

    syx_state.is_symbolic = is_symbolic;

    assert(syx_namespaces[SYX_NS_ID_SNAPSHOT].is_used);
    syx_snapshot_init_params_t snapshot_params = {
        .page_size = 4096
    };
    syx_namespaces[SYX_NS_ID_SNAPSHOT].init(&snapshot_params);

    for (uint64_t i = 0; i < SYX_NS_MAX; i++) {
        syx_namespace_t* current_ns = &syx_namespaces[i];

        if (current_ns->is_used && !current_ns->init_has_opaque_param) {
            current_ns->init(NULL);
        }
    }

    syx_state.is_initialized = true;
    if (must_unlock_iothread) {
	    qemu_mutex_unlock_iothread();
    }
}

uint64_t syx_handle(CPUState* cpu, uint8_t ns_id, uint32_t cmd, target_ulong target_opaque, uint64_t api_version) {
    assert(SYX_API_VERSION == api_version);

    syx_namespace_t* ns = &syx_namespaces[ns_id];
    assert(ns->is_used);

    assert(syx_state.is_initialized);

    assert(arch_is_compatible(ns, syx_state.arch));
    assert(accel_is_compatible(ns, syx_state.accel));

    return ns->handler(cpu, cmd, target_opaque);
}

void syx_set_arch(syx_arch arch) {
    assert(syx_state.arch == SYX_ARCH_UNDEF);
    syx_state.arch = arch;
}

void syx_set_accel(syx_accel accel) {
    assert(syx_state.accel == SYX_ACCEL_UNDEF);
    syx_state.accel = accel;
}

void syx_set_snapshot(syx_snapshot_t* snapshot) {
    syx_state.snapshot = snapshot;
}

syx_arch syx_get_arch(void) {
    return syx_state.arch;
}

syx_accel syx_get_accel(void) {
    return syx_state.accel;
}

syx_snapshot_t* syx_get_snapshot(void) {
    return syx_state.snapshot;
}

bool syx_is_symbolic(void) {
    return syx_state.is_symbolic;
}