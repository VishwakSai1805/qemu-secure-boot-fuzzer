/* TLV command parser for the app firmware.
 *
 * VULN-1 (stack buffer overflow): CMD_ECHO copies `len` attacker-controlled
 *   bytes into a fixed 16-byte stack buffer with no bounds check.
 * VULN-2 (integer underflow): CMD_SET_OFFSET computes `len - 1` as an
 *   unsigned 8-bit count with no check that len >= 1, then uses it to copy
 *   bytes into a stack array, wrapping to 255 on len==0.
 * VULN-3 (unauthenticated arbitrary memory read): CMD_READ_MEM reads a
 *   32-bit address directly from the attacker's frame and echoes back
 *   4 bytes from it over UART, with no range or alignment check.
 */
#include "parser.h"
#include "../common/uart.h"

static void echo_cmd(uint8_t len, const uint8_t *value)
{
    uint8_t buf[16];                 /* VULN-1: no clamp on len */
    for (uint8_t i = 0; i < len; i++) buf[i] = value[i];
    uart_puts("[APP] ECHO: ");
    for (uint8_t i = 0; i < len; i++) uart_putc((char)buf[i]);
    uart_putc('\n');
}

static volatile uint8_t g_offset_scratch;  /* sink so the loop below is not optimized away */

static void set_offset_cmd(uint8_t len, const uint8_t *value)
{
    uint8_t stage[8];
    uint8_t count = (uint8_t)(len - 1);   /* VULN-2: underflows when len == 0 */
    for (uint8_t i = 0; i < count && i < 255; i++) {
        stage[i % 8] = value[i % (len ? len : 1)];
        g_offset_scratch = stage[i % 8];
    }
    uart_puts("[APP] OFFSET SET count=");
    uart_put_hex(count);
    uart_putc('\n');
}

static void put_hex_byte(uint8_t v)
{
    static const char h[] = "0123456789abcdef";
    uart_putc(h[(v >> 4) & 0xf]);
    uart_putc(h[v & 0xf]);
}

static void read_mem_cmd(uint8_t len, const uint8_t *value)
{
    if (len < 4) { uart_puts("[APP] READ_MEM: short frame\n"); return; }
    uint32_t addr = (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
                    ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
    const uint8_t *p = (const uint8_t *)addr;   /* VULN-3: unchecked, unauthenticated */
    uart_puts("[APP] READ_MEM @");
    uart_put_hex(addr);
    uart_puts(" = ");
    for (int i = 0; i < 4; i++) put_hex_byte(p[i]);
    uart_putc('\n');
}

void parser_handle_frame(uint8_t type, uint8_t len, const uint8_t *value)
{
    switch (type) {
        case CMD_ECHO:       echo_cmd(len, value); break;
        case CMD_SET_OFFSET: set_offset_cmd(len, value); break;
        case CMD_READ_MEM:   read_mem_cmd(len, value); break;
        case CMD_PING:       uart_puts("[APP] PONG\n"); break;
        default:             uart_puts("[APP] ERR unknown cmd\n"); break;
    }
}
