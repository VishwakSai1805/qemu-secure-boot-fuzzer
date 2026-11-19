/* HardFault/UsageFault handler: dumps the stacked exception frame over
 * UART0 so the fuzzer can parse crash register state, then halts. */
#include <stdint.h>
#include "../common/uart.h"

#define SCB_CFSR (*(volatile uint32_t *)0xE000ED28u)
#define SCB_HFSR (*(volatile uint32_t *)0xE000ED2Cu)

static void dump(const char *name, uint32_t v)
{
    uart_puts(name); uart_put_hex(v); uart_putc('\n');
}

/* frame points at r0,r1,r2,r3,r12,lr,pc,psr pushed by the exception entry */
void HardFault_Handler_C(uint32_t *frame)
{
    uart_puts("[FAULT] HardFault\n");
    dump("[FAULT] R0=",  frame[0]);
    dump("[FAULT] R1=",  frame[1]);
    dump("[FAULT] R2=",  frame[2]);
    dump("[FAULT] R3=",  frame[3]);
    dump("[FAULT] R12=", frame[4]);
    dump("[FAULT] LR=",  frame[5]);
    dump("[FAULT] PC=",  frame[6]);
    dump("[FAULT] PSR=", frame[7]);
    dump("[FAULT] CFSR=", SCB_CFSR);
    dump("[FAULT] HFSR=", SCB_HFSR);
    uart_puts("[FAULT] HALT\n");
    for (;;) { __asm volatile("wfi"); }
}

__attribute__((naked)) void HardFault_Handler(void)
{
    __asm volatile(
        "mrs r0, msp      \n"
        "tst lr, #4       \n"   /* was PSP used? (not expected here) */
        "beq 1f           \n"
        "mrs r0, psp      \n"
        "1: b HardFault_Handler_C \n"
    );
}
