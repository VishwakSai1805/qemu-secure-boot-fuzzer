#include "../common/uart.h"

void app_main(void)
{
    uart_init();
    uart_puts("[APP] Ready\n");
    for (;;) { __asm volatile("wfi"); }
}
