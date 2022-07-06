#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/sysemu.h"
#include "cpu.h"
#include "qemu/main-loop.h"
#include "migration/qemu-file.h"
#include "migration/vmstate.h"
#include "migration/savevm.h"
#include "memory.h"

#include "exec/ram_addr.h"
#include "exec/ramlist.h"
#include "exec/address-spaces.h"
#include "exec/exec-all.h"

#include "sysemu/block-backend.h"
#include "migration/register.h"

#include "target/i386/cpu.h"

#include "snapshot.h"
#include "qemu-file-ram.h"
#include "device-save.h"
#include "nyx/syx/syx.h"

#define DIRTY_PAGES_LIST_INIT_SIZE      512
#define DIRTY_PAGES_LIST_GROW_FACTOR    2

tcg_snapshot_t snapshot = {0};

static void tcg_snapshot_dirty_list_init(void) {
    snapshot.dirty_list_size = 0;
    snapshot.dirty_list_capacity = DIRTY_PAGES_LIST_INIT_SIZE;
    snapshot.dirty_list = g_new(hwaddr, DIRTY_PAGES_LIST_INIT_SIZE);
}

static inline void tcg_snapshot_dirty_list_add_internal(hwaddr paddr) {
    assert(snapshot.dirty_list != NULL);

    paddr &= snapshot.page_mask;

    // Avoid adding already marked addresses
    for (int i = 0; i < snapshot.dirty_list_size; ++i) {
        if (snapshot.dirty_list[i] == paddr) {
            return;
        }
    }

    if (snapshot.dirty_list_size == snapshot.dirty_list_capacity) {
        uint64_t new_capacity = snapshot.dirty_list_capacity * DIRTY_PAGES_LIST_GROW_FACTOR;
        snapshot.dirty_list_capacity = new_capacity;
        snapshot.dirty_list = g_realloc(snapshot.dirty_list, new_capacity);
    }

    snapshot.dirty_list[snapshot.dirty_list_size] = paddr;

    snapshot.dirty_list_size++;
}

// The implementation is pretty bad, it would be nice to store host addr directly for
// the memcopy happening later on.
__attribute__((target("no-3dnow,no-sse,no-mmx"),no_caller_saved_registers)) void tcg_snapshot_dirty_list_add_tcg_target(uint64_t dummy, void* host_addr) {
    // early check to know whether we should log the page access or not
    if (!tcg_snapshot_is_enabled()) {
        return;
    }

    ram_addr_t offset;
    RAMBlock* rb = qemu_ram_block_from_host((void*) host_addr, true, &offset);

    assert(rb);
    
    hwaddr paddr = rb->mr->addr + offset;
    // If this assert is ever false, please understand why
    // qemu_ram_block_from_host result with true as second
    // param would not be host page aligned.
    assert(paddr == (paddr & snapshot.page_mask));

    tcg_snapshot_dirty_list_add_internal(paddr);
}

void tcg_snapshot_dirty_list_add(hwaddr paddr) {
    // early check to know whether we should log the page access or not
    if (!tcg_snapshot_is_enabled()) {
        return;
    }

    tcg_snapshot_dirty_list_add_internal(paddr);
}

static inline void tcg_snapshot_dirty_list_flush(void) {
    snapshot.dirty_list_size = 0;
}

static void tcg_snapshot_create_root(CPUState* cpu) {
    RAMBlock* block;
    uint64_t nb_blocks = 0;
    device_save_state_t* dss = device_save_all();

    RAMBLOCK_FOREACH(block) {
        nb_blocks++;
    }

    snapshot.root_snapshot.ram_blocks = g_new0(tcg_snapshot_ramblock_t, nb_blocks);
    snapshot.root_snapshot.nb_ram_blocks = nb_blocks;
    snapshot.root_snapshot.dss = dss;

    uint64_t ram_block_idx = 0;
    RAMBLOCK_FOREACH(block) {
        // SYX_PRINTF("Saving block %s\n", block->idstr);
        tcg_snapshot_ramblock_t* snapshot_ram_block = &snapshot.root_snapshot.ram_blocks[ram_block_idx];
        strcpy(snapshot_ram_block->idstr, block->idstr);
        snapshot_ram_block->used_length = block->used_length;

        snapshot_ram_block->ram = g_new(uint8_t, block->used_length);
        memcpy(snapshot_ram_block->ram, block->host, block->used_length);

        ram_block_idx++;
    }
    assert(ram_block_idx == nb_blocks);
}

static tcg_snapshot_ramblock_t* find_ramblock(char* idstr) {
    // SYX_PRINTF("\t\t\tfind_ramblock: nb_ram_block = %lu\n", snapshot.root_snapshot.nb_ram_blocks);
    for (size_t i = 0; i < snapshot.root_snapshot.nb_ram_blocks; i++) {
        // SYX_PRINTF("\t\t\tfind_ramblock: comparing %s with %s\n", idstr, snapshot.root_snapshot.ram_blocks[i].idstr);
        if (!strcmp(idstr, snapshot.root_snapshot.ram_blocks[i].idstr)) {
            return &snapshot.root_snapshot.ram_blocks[i];
        }
    }

    return NULL;
}

static void restore_page_from_root(hwaddr addr) {
    MemoryRegion* system_mr = get_system_memory();
    MemoryRegionSection mr_section = memory_region_find(system_mr, addr, snapshot.page_size);
    assert(mr_section.size != 0 && mr_section.mr != NULL);
    if (mr_section.mr->ram) {
        tcg_snapshot_ramblock_t* ram_block = find_ramblock(mr_section.mr->ram_block->idstr);
        assert(ram_block != NULL);
        assert(!strcmp(mr_section.mr->ram_block->idstr, ram_block->idstr));
        // SYX_PRINTF("Content of the vm before restoration:\n");
        // qemu_hexdump((char*) mr_section.mr->ram_block->host + mr_section.offset_within_region, stdout, "\t", 128);
        memcpy(mr_section.mr->ram_block->host + mr_section.offset_within_region,
                ram_block->ram + mr_section.offset_within_region, snapshot.page_size);
        // SYX_PRINTF("Content of the vm at root:\n");
        // qemu_hexdump((char*) mr_section.mr->ram_block->host + mr_section.offset_within_region, stdout, "\t", 128);
    }
}

static void restore_page(tcg_snapshot_dirty_page_t* page) {
    MemoryRegion* system_mr = get_system_memory();
    MemoryRegionSection mr_section = memory_region_find(system_mr, page->addr, snapshot.page_size);
    assert(mr_section.size != 0 && mr_section.mr != NULL);
    if (mr_section.mr->ram) {
        memcpy(mr_section.mr->ram_block->host + mr_section.offset_within_region, page->page, snapshot.page_size);
    }
}

static void tcg_snapshot_restore_root_from_dirty_list(void) {
    for (size_t i = 0; i < snapshot.dirty_list_size; ++i) {
        // SYX_PRINTF(" %lu) Restore page at address %p...\n", i, (void*) snapshot.dirty_list[i]);
        restore_page_from_root(snapshot.dirty_list[i]);
    }
}

void tcg_snapshot_restore_root(CPUState* cpu) {
    tcg_snapshot_restore_root_from_dirty_list();
    device_restore_all(snapshot.root_snapshot.dss);
    tcg_snapshot_dirty_list_flush();

    SYX_PRINTF("Restoration done.\n");
}

void tcg_snapshot_init(CPUState* cpu, uint64_t page_size) {
    // mtree_info(false, false, false);

    snapshot.page_size = page_size;
    snapshot.page_mask = ((uint64_t)-1) << __builtin_ctz(page_size);
    // SYX_PRINTF("Page size: %lu\nPage mask: 0x%lx\n\n", page_size, snapshot.page_mask);

    tcg_snapshot_create_root(cpu);

    tcg_snapshot_dirty_list_init();

    snapshot.enabled = true;
}

static void flush_dirty_list_and_copy_dirty_pages(CPUState* cpu, tcg_snapshot_increment_t* this) {
    uint64_t nb_dirty_pages = snapshot.dirty_list_size;

    this->dirty_pages_nb = nb_dirty_pages;
    this->dirty_pages = g_new(tcg_snapshot_dirty_page_t, nb_dirty_pages);

    for (uint64_t dirty_list_idx = 0; dirty_list_idx < snapshot.dirty_list_size; dirty_list_idx++) {
        this->dirty_pages[dirty_list_idx].addr = snapshot.dirty_list[dirty_list_idx];
        this->dirty_pages[dirty_list_idx].page = g_new(uint8_t, snapshot.page_size);

        cpu_physical_memory_read(snapshot.dirty_list[dirty_list_idx], this->dirty_pages[dirty_list_idx].page, snapshot.page_size);
    }

    tcg_snapshot_dirty_list_flush();
}

void tcg_snapshot_create_increment(CPUState* cpu) {
    tcg_snapshot_increment_t* new_increment = g_new0(tcg_snapshot_increment_t, 1);

    new_increment->parent = snapshot.last_snapshot;
    snapshot.last_snapshot = new_increment;

    memcpy(&new_increment->cpu_state, cpu, sizeof(CPUState));

    flush_dirty_list_and_copy_dirty_pages(cpu, new_increment);
}

bool tcg_snapshot_is_enabled(void) {
    return snapshot.enabled;
}