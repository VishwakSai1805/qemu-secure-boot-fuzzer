MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00004200, LENGTH = 240K - 0x200
    SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
ENTRY(Reset_Handler)
SECTIONS
{
    .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) . = ALIGN(4); } > FLASH
    _sidata = LOADADDR(.data);
    .data : { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > SRAM AT > FLASH
    .bss  : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > SRAM
    _estack = ORIGIN(SRAM) + LENGTH(SRAM);
    /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) }
}
