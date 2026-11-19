#ifndef PARSER_H
#define PARSER_H
#include <stdint.h>

/* Binary TLV command frame over UART0: [type:1][len:1][value: len bytes].
 * This parser is an INTENTIONALLY VULNERABLE training target for the
 * fuzzer (see SPEC.md / reports/vulnerability_report.md). Do not reuse
 * in production firmware. */

#define CMD_ECHO       0x01   /* copies value into a small fixed stack buffer      */
#define CMD_SET_OFFSET 0x02   /* len-1 used as an unsigned byte count; underflows  */
#define CMD_READ_MEM   0x03   /* reads 4 bytes from an attacker-chosen address     */
#define CMD_PING       0x04   /* safe: replies "PONG"                             */

void parser_handle_frame(uint8_t type, uint8_t len, const uint8_t *value);

#endif
