#ifndef UART_H
#define UART_H
#include <stdint.h>
void uart_init(void);
void uart_putc(char c);
void uart_puts(const char *s);
void uart_put_hex(uint32_t v);
int  uart_getc_nonblock(void);   /* -1 when RX FIFO empty */
uint8_t uart_getc(void);         /* blocking poll */
#endif
