#include <stdint.h>

extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;
extern void app_main(void);
extern void HardFault_Handler(void);

void Reset_Handler(void)
{
    uint32_t *src = &_sidata, *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;
    for (dst = &_sbss; dst < &_ebss; ) *dst++ = 0;
    app_main();
    for (;;) { }
}

void Default_Handler(void) { for (;;) { } }

/* 16-entry Cortex-M system vector table, 512-byte aligned by the header size.
 * Index 3 is the HardFault vector; the crash fuzzer relies on it to dump
 * register state before halting. */
__attribute__((section(".vectors"), used))
const void *const vector_table[16] = {
    &_estack, Reset_Handler,
    Default_Handler, HardFault_Handler, Default_Handler, Default_Handler,
    Default_Handler, 0, 0, 0, 0, Default_Handler, Default_Handler, 0,
    Default_Handler, Default_Handler,
};
