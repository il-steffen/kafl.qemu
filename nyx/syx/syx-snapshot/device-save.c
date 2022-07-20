#include "qemu/osdep.h"
#include "device-save.h"
#include "migration/qemu-file.h"
#include "qemu-file-ram.h"
#include "migration/vmstate.h"
#include "qemu/main-loop.h"
#include "nyx/syx/syx-misc.h"

#include "migration/savevm.h"

extern SaveState savevm_state;

extern void save_section_header(QEMUFile *f, SaveStateEntry *se, uint8_t section_type);
extern int vmstate_save(QEMUFile *f, SaveStateEntry *se, QJSON *vmdesc);
extern void save_section_footer(QEMUFile *f, SaveStateEntry *se);

// iothread must be locked
device_save_state_t* device_save_all(void) {
    device_save_state_t* dss = g_new0(device_save_state_t, 1);
    SaveStateEntry *se;

    dss->kind = DEVICE_SAVE_KIND_FULL;
    dss->save_buffer = g_new0(uint8_t, QEMU_FILE_RAM_LIMIT);

    QEMUFile* f = qemu_file_ram_write_new(dss->save_buffer, QEMU_FILE_RAM_LIMIT);
    
    QTAILQ_FOREACH(se, &savevm_state.handlers, entry) {
        int ret;

        if (se->is_ram) {
            continue;
        }
        if ((!se->ops || !se->ops->save_state) && !se->vmsd) {
            continue;
        }
        if (se->vmsd && !vmstate_save_needed(se->vmsd, se->opaque)) {
            continue;
        }
        if (!strcmp(se->idstr, "globalstate")) {
            continue;
        }

        // SYX_PRINTF("Saving section %s...\n", se->idstr);

        save_section_header(f, se, QEMU_VM_SECTION_FULL);

        ret = vmstate_save(f, se, NULL);

        if (ret) {
            SYX_PRINTF("Device save all error: %d\n", ret);
            abort();
        }

        save_section_footer(f, se);
    }

    printf("\n");

    qemu_put_byte(f, QEMU_VM_EOF);

    qemu_fclose(f);

    return dss;
}

void device_restore_all(device_save_state_t* device_save_state) {
    QEMUFile* f = qemu_file_ram_read_new(device_save_state->save_buffer, QEMU_FILE_RAM_LIMIT);
    
    qemu_load_device_state(f);

    qemu_load_device_state(f);
    qemu_fclose(f);
}

void device_free_all(device_save_state_t* dss) {
    g_free(dss->save_buffer);
}