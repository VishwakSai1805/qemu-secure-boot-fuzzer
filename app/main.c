#include "../common/uart.h"
#include "parser.h"

/* Reads binary TLV frames from UART0: [type:1][len:1][value: len bytes]. */
void app_main(void)
{
    uint8_t type, len, value[256];

    uart_init();
    uart_puts("[APP] Ready\n");

    for (;;) {
        type = uart_getc();
        len  = uart_getc();
        for (uint16_t i = 0; i < len; i++) value[i] = uart_getc();
        parser_handle_frame(type, len, value);
    }
}
