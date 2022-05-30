
// SYXMmioRangeDynArray syx_mmio_range_dyn_array_init(void) {
//     SYXMmioRangeDynArray mmio_range_array;
// 
//     mmio_range_array.capacity = MMIO_RANGES_INIT_SIZE;
//     mmio_range_array.mmio_ranges = g_new0(SYXMmioRange, mmio_range_array.capacity);
//     mmio_range_array.len = 0;
// 
//     return mmio_range_array;
// }
// 
// void syx_mmio_range_dyn_array_add(SYXMmioRange* mmio_range) {
//     if (syx_state->mmio_array.len == syx_state->mmio_array.capacity) {
//         syx_state->mmio_array.capacity *= 2;
//         syx_state->mmio_array.mmio_ranges = g_realloc(syx_state->mmio_array.mmio_ranges, syx_state->mmio_array.capacity);
//     }
// 
//     syx_state->mmio_array.mmio_ranges[syx_state->mmio_array.len++] = *mmio_range;
// }
// 
// // returns NULL if out of range
// SYXMmioRange* syx_mmio_range_get(size_t idx) {
//     if (idx >= syx_state->mmio_array.len) {
//         return NULL;
//     }
// 
//     return &(syx_state->mmio_array.mmio_ranges[idx]);
// }
// 