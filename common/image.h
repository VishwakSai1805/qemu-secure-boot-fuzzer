#ifndef IMAGE_H
#define IMAGE_H
#include <stdint.h>

/* Signed application image header, 512 bytes at 0x00004000. The payload
 * (Cortex-M vector table first) follows immediately at 0x00004200. */
#define APP_HEADER_ADDR  0x00004000u
#define APP_PAYLOAD_ADDR 0x00004200u
#define APP_MAX_LEN      (0x00040000u - APP_PAYLOAD_ADDR)
#define IMG_MAGIC        0x31505041u   /* "APP1" little-endian */

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t payload_len;
    uint32_t reserved;       /* must be zero, covered by the MAC */
    uint8_t  mac[32];        /* HMAC-SHA256(key, header[0:16] || payload) */
    uint8_t  pad[512 - 48];
} app_header_t;

/* Development key. Real deployments provision a per-device secret. */
#define DEV_KEY_BYTES \
    { 0x51,0x45,0x4d,0x55,0x2d,0x4d,0x33,0x2d,0x44,0x45,0x56,0x2d,0x4b,0x45,0x59,0x21 }
#endif
