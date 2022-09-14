#pragma once
#ifdef QEMU_SYX

/**
 * SYX is a project adding several additions to QEMU
 * aiming at supporting Symbolic Execution (or more
 * precisely Concolic Execution) in QEMU (full emulation).
 * Because SYX is now composed of several (more or
 * less) independent parts, it was decided to separate
 * the differents big blocs in differents "namespaces".
 * 
 * VM generally make use of hypercalls to communicate with
 * SYX directly for various reasons (works well in
 * most accels, generally unused during TCG translation) which
 * makes it portable.
 * 
 * The way to call the main handler function is highly CPU-dependent.
 * For now, only x86 platform is supported but it should be possible
 * to add various new architectures by following the current implementation.
 * It was originally made to make it "easy" to add new CPU architectures.
 */

#include "qemu/osdep.h"
#include "syx-api.h"

#include "syx-event/syx-event.h"
#include "syx-snapshot/syx-snapshot.h"
#include "syx-sym/syx-sym.h"

typedef uint64_t target_ulong;

// Architecture
typedef enum syx_arch {
    SYX_ARCH_UNDEF = 0,
    SYX_ARCH_X86
} syx_arch;

// Accel
typedef enum syx_accel {
    SYX_ACCEL_UNDEF = 0,
    SYX_ACCEL_KVM,
    SYX_ACCEL_TCG
} syx_accel;

/**
 * Main structure to define a new namespace.
 * A namespace is a family of features linked
 * together.
 * The generally achieve independent tasks.
 * 
 * id: ID of the namespace. Should be defined
 * in this file.
 * 
 * handler: Main function to call to do
 * something in the namespace. The opaque
 * can be whatever would be useful for
 * the namespace being called
 */
typedef struct syx_namespace_s {
    glue(glue(uint,SYX_NS_BITS),_t) id;
    bool is_used;

    bool init_has_opaque_param;
    void (*init)(void*);

    uint64_t (*handler)(CPUState*, uint32_t, target_ulong);

    uint8_t supported_accel;
    uint8_t supported_arch;
} syx_namespace_t;

static_assert(SYX_NS_BITS < SYX_HC_REGISTER_SIZE);

#define SYX_ACCEL_DECODE(_accel_id_)    (1 << (_accel_id_))

#define SYX_ARCH_DECODE(_arch_id_)      (1 << (_arch_id_))

#define SYX_ACCEL_DECODE_CHECKED(_accel_id_)                                                \
    ({                                                                              \
        assert(sizeof_field(syx_namespace_t, supported_accel) * 8 > (_accel_id_));  \
        SYX_ACCEL_DECODE(_accel_id_);                                                        \
    })

#define SYX_ARCH_DECODE_CHECKED(_arch_id_)                                                  \
    ({                                                                              \
        assert(sizeof_field(syx_namespace_t, supported_arch) * 8 > (_arch_id_));    \
        SYX_ARCH_DECODE(_arch_id_);                                                         \
    })

#define SYX_NAMESPACE_ENTRY(_id_, _init_opaque_, _init_, _handler_, _accel_, _arch_) \
        [_id_] = {                                 \
            .id = (_id_),                                                            \
            .is_used = true,                                                         \
            .init_has_opaque_param = (_init_opaque_),                                  \
            .init = (_init_),                                                        \
            .handler = (_handler_),                                                  \
            .supported_accel = (_accel_),                                            \
            .supported_arch = (_arch_)                                              \
        }

// Misc functions
#define SYX_HC_GET_PARAM(_type_, _cpu_, _opaque_vaddr_)    (_type_ *) get_data_from_target(_cpu_, _opaque_vaddr_, sizeof(_type_))

void syx_init(bool is_symbolic);

uint64_t syx_handle(CPUState* cpu, uint8_t ns_id, uint32_t cmd, target_ulong target_opaque, uint64_t api_version);

void syx_set_arch(syx_arch arch);
void syx_set_accel(syx_accel accel);
void syx_set_snapshot(syx_snapshot_t* snapshot);

syx_arch syx_get_arch(void);
syx_accel syx_get_accel(void);
syx_snapshot_t* syx_get_snapshot(void);

bool syx_is_symbolic(void);

void* get_data_from_target(CPUState* cpu, vaddr virt_addr, size_t len);

#endif