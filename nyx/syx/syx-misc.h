#pragma once

#define SYX_PRINTF(format, ...)     fprintf(stderr, ("[QEMU-SYX] " format), ##__VA_ARGS__)

#define SYX_ERROR_REPORT(format, ...)   error_report(("[QEMU-SYX] " format), ##__VA_ARGS__)