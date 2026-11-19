/* Polling UART0 driver for the Stellaris LM3S6965 (QEMU lm3s6965evb). */
#include "uart.h"

#define UART0_BASE 0x4000C000u
#define UART_DR    (*(volatile uint32_t *)(UART0_BASE + 0x000))
#define UART_FR    (*(volatile uint32_t *)(UART0_BASE + 0x018))
#define UART_CTL   (*(volatile uint32_t *)(UART0_BASE + 0x030))
#define FR_RXFE    (1u << 4)
#define FR_TXFF    (1u << 5)
#define RCGC1      (*(volatile uint32_t *)0x400FE104u)

void uart_init(void)
{
    RCGC1 |= 1u;                 /* clock UART0 */
    UART_CTL = (1u << 0) | (1u << 8) | (1u << 9);  /* UARTEN | TXE | RXE */
}

void uart_putc(char c)
{
    while (UART_FR & FR_TXFF) { }
    UART_DR = (uint8_t)c;
}

void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
}

void uart_put_hex(uint32_t v)
{
    static const char h[] = "0123456789abcdef";
    for (int i = 28; i >= 0; i -= 4) uart_putc(h[(v >> i) & 0xf]);
}

int uart_getc_nonblock(void)
{
    if (UART_FR & FR_RXFE) return -1;
    return (int)(UART_DR & 0xff);
}

uint8_t uart_getc(void)
{
    int c;
    while ((c = uart_getc_nonblock()) < 0) { }
    return (uint8_t)c;
}
