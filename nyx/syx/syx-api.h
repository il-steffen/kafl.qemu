#pragma once

#include "stdint.h"
#include "stdbool.h"

#ifndef glue
#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#endif

// API version
#define SYX_API_VERSION 6

// Hypercall Parameters **To adapt depending on the target**
#define SYX_HC_REGISTER_SIZE 64
#define SYX_NS_BITS             8
#define SYX_CMD_BITS            (SYX_HC_REGISTER_SIZE - SYX_NS_BITS)

// Namespaces ID
#define SYX_NS_ID_NYX 0
#define SYX_NS_ID_SYM 1
#define SYX_NS_ID_SNAPSHOT 2
#define SYX_NS_ID_EVENT 3

// Hypercall Type
#define SYX_HC_TYPE             glue(glue(uint, SYX_HC_REGISTER_SIZE), _t)
// Namespace Type
#define SYX_NS_TYPE             glue(glue(uint, SYX_NS_BITS), _t)

#define SYX_NS_BITMASK          (((SYX_HC_TYPE) 1 << SYX_NS_BITS) - 1)
#define SYX_NS_MASK             (((SYX_HC_TYPE) SYX_NS_BITMASK) << SYX_CMD_BITS)
#define SYX_CMD_MASK            (((SYX_HC_TYPE) 1 << SYX_CMD_BITS) - 1)
#define SYX_NS_MAX              (1 << SYX_NS_BITS)

#ifndef KVM_EXIT_KAFL_SYX
#define KVM_EXIT_KAFL_SYX 150
#define KVM_EXIT_GUEST_KAFL_SYX (KVM_EXIT_KAFL_SYX - 100)
#endif

#ifndef HYPERCALL_KAFL_RAX_ID
#define HYPERCALL_KAFL_RAX_ID				0x01f
#endif

// Issue Hypercall with version
#define SYX_HYPERCALL(_ns_id_, _cmd_, _opaque_)                     \
	({                                                              \
        uint64_t _nr = HYPERCALL_KAFL_RAX_ID;                       \
        SYX_HC_TYPE _hc = _cmd_ | ((SYX_HC_TYPE)_ns_id_ << SYX_CMD_BITS);        \
        asm volatile ("vmcall"                                      \
                : "+a"(_nr)                                         \
                : "b"(KVM_EXIT_GUEST_KAFL_SYX),                           \
                  "c"(_hc),                                       \
                  "d"(_opaque_),                                    \
                  "S"(SYX_API_VERSION)                              \
        );                                                          \
        _nr;                                                        \
    })


/**
 * === SYX API ===
 */

//
// Event Namespace API
//

/**
 * @brief Start Symbolic Execution in QEMU-TCG
 * once this Hypercall is issued.
 * 
 * @param syx_cmd_event_sync_t
 */
#define SYX_CMD_EVENT_SYNC  0
typedef struct syx_cmd_event_sync_s {
    size_t fuzzer_input_offset; // Offset in the fuzzer buffer to symbolize
    size_t len; // Length of the symbolized input

    bool unique; // Will make the symbolic request only once
} syx_cmd_event_sync_t;

/**
 * @brief Start Symbolic Execution in QEMU-TCG
 * if an asynchronous read happens at the given
 * virtual address and length
 * 
 * @param syx_cmd_event_async_t
 */
#define SYX_CMD_EVENT_ASYNC  1
typedef struct syx_cmd_event_async_s {
    size_t fuzzer_input_offset;
    size_t len;
} syx_cmd_event_async_t;

//
// Snapshot Namespace API
//
#define SYX_CMD_SNAPSHOT_NEW_ROOT           0
#define SYX_CMD_SNAPSHOT_RESTORE_TO_ROOT    1

//
// Sym Namespace API
//
#define SYX_CMD_SYM_START                   0
#define SYX_CMD_SYM_END                     1
