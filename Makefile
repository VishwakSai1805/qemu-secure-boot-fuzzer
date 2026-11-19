CROSS   ?= arm-none-eabi-
CC      := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
CFLAGS  := -mcpu=cortex-m3 -mthumb -Os -g -ffreestanding -fno-builtin \
           -fno-stack-protector -fno-pie -Wall -Wextra -Wno-unused-parameter
LDFLAGS := -nostdlib -nostartfiles -Wl,--gc-sections
B       := build

COMMON_SRC := common/uart.c common/sha256.c
BOOT_SRC   := bootloader/startup.c bootloader/main.c $(COMMON_SRC)
APP_SRC    := app/startup.c app/main.c app/parser.c app/fault.c $(COMMON_SRC)

.PHONY: all clean
all: $(B)/flash.bin

$(B)/bootloader.elf: $(BOOT_SRC) bootloader/bootloader.ld common/image.h | $(B)
	$(CC) $(CFLAGS) $(LDFLAGS) -T bootloader/bootloader.ld $(BOOT_SRC) -o $@
$(B)/app.elf: $(APP_SRC) app/app.ld | $(B)
	$(CC) $(CFLAGS) $(LDFLAGS) -T app/app.ld $(APP_SRC) -o $@
$(B)/%.bin: $(B)/%.elf
	$(OBJCOPY) -O binary $< $@
$(B)/flash.bin: $(B)/bootloader.bin $(B)/app.bin tools/sign_image.py
	python3 tools/sign_image.py --bootloader $(B)/bootloader.bin --app $(B)/app.bin -o $@
$(B):
	mkdir -p $@
clean:
	rm -rf $(B)
