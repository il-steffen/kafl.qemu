#pragma once

#include "qemu/osdep.h"
#include "exec/hwaddr.h"

uint64_t syx_event_read_memory(void* opaque, hwaddr addr, unsigned size);
void syx_event_write_memory(void* opaque, hwaddr addr, uint64_t data, unsigned size);