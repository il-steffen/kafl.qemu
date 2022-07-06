#pragma once

#include "qemu/osdep.h"
#include "qom/object.h"
#include "cpu.h"
#include "device-save.h"

typedef struct tcg_snapshot_ramblock_s {
    uint8_t* ram;
    uint64_t used_length;
    char idstr[256];
} tcg_snapshot_ramblock_t;

typedef struct tcg_snapshot_root_s {
    tcg_snapshot_ramblock_t* ram_blocks;
    uint64_t nb_ram_blocks;

    device_save_state_t* dss;
} tcg_snapshot_root_t;

typedef struct tcg_snapshot_dirty_page_s {
    hwaddr addr;
    uint8_t* page;
} tcg_snapshot_dirty_page_t;

typedef struct tcg_snapshot_increment_s {
    // Back to root snapshot if NULL
    struct tcg_snapshot_increment_s* parent;

    CPUState cpu_state; /* The CPU state at snapshot time */
    tcg_snapshot_dirty_page_t* dirty_pages; 
    uint64_t dirty_pages_nb;
} tcg_snapshot_increment_t;

typedef struct tcg_snapshot_s {
    bool enabled;

    tcg_snapshot_root_t root_snapshot;
    tcg_snapshot_increment_t* last_snapshot;

    uint64_t page_size;
    uint64_t page_mask;

    // Dirty pages since the last snapshot
    // Only physical addresses are stored at this point
    // Better if a few addresses are marked
    hwaddr* dirty_list;
    uint64_t dirty_list_size;
    uint64_t dirty_list_capacity;
} tcg_snapshot_t;

void tcg_snapshot_init(CPUState* cpu, uint64_t page_size);

/**
 * @brief Create an incremental snapshot.
 * For now, only simple linked list snapshotting is 
 * allowed. 'graph' snapshoting may be implemented if
 * necessary at some point.
 * 
 * @param snapshot The snapshot global state.
 */
void tcg_snapshot_create_increment(CPUState* cpu);
void tcg_snapshot_restore_until(uint32_t nb_incremental_snapshots);
void tcg_snapshot_restore_root(CPUState* cpu);
void tcg_snapshot_load(tcg_snapshot_t* snapshot);

bool tcg_snapshot_is_enabled(void);

/**
 * @brief Add a dirty physical address to the list
 * 
 * @param paddr The physical address to add
 */
void tcg_snapshot_dirty_list_add(hwaddr paddr);

/**
 * @brief Same as tcg_snapshot_dirty_list_add. The difference
 * being that it has been specially compiled for full context
 * saving so that it can be called from anywhere, even in
 * extreme environments where SystemV ABI is not respected.
 * 
 * @param dummy A dummy argument. it is to comply with
 *              tcg-target.inc.c special environment.
 * @param host_addr The host address where the dirty page is located.
 */
void tcg_snapshot_dirty_list_add_tcg_target(uint64_t dummy, void* host_addr);