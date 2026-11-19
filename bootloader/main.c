/* Secure bootloader: verifies the HMAC-SHA256 of the application image in
 * flash before transferring control to it. Fails closed. */
#include <stdint.h>
#include "../common/uart.h"
#include "../common/sha256.h"
#include "../common/image.h"

#define SCB_VTOR (*(volatile uint32_t *)0xE000ED08u)

static int ct_equal(const uint8_t *a, const uint8_t *b, int n)
{
    uint8_t d = 0;
    for (int i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

static int verify_image(void)
{
    static const uint8_t key[16] = DEV_KEY_BYTES;
    const app_header_t *h = (const app_header_t *)APP_HEADER_ADDR;
    const uint8_t *payload = (const uint8_t *)APP_PAYLOAD_ADDR;
    uint8_t mac[32];
    sha256_ctx ctx;

    if (h->magic != IMG_MAGIC) return 0;
    if (h->payload_len == 0 || h->payload_len > APP_MAX_LEN) return 0;
    if (h->reserved != 0) return 0;

    hmac_sha256_init(&ctx, key, sizeof key);
    sha256_update(&ctx, (const uint8_t *)h, 16);
    sha256_update(&ctx, payload, h->payload_len);
    hmac_sha256_final(&ctx, key, sizeof key, mac);
    return ct_equal(mac, h->mac, 32);
}

static void jump_to_app(void)
{
    const uint32_t *vt = (const uint32_t *)APP_PAYLOAD_ADDR;
    SCB_VTOR = APP_PAYLOAD_ADDR;
    __asm volatile("msr msp, %0\n\tbx %1" :: "r"(vt[0]), "r"(vt[1]) : "memory");
    for (;;) { }
}

void boot_main(void)
{
    uart_init();
    uart_puts("[BOOT] Verifying application image...\n");
    if (!verify_image()) {
        uart_puts("[BOOT] PANIC: Invalid Signature\n");
        for (;;) { __asm volatile("wfi"); }   /* halt */
    }
    uart_puts("[BOOT] Signature OK, jumping to application\n");
    jump_to_app();
}
