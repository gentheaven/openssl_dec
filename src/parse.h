#ifndef __PARSE_H
#define __PARSE_H

#include <inttypes.h>
#include <winsock2.h>
#include <windows.h>

extern unsigned char local_prikey[32];

//tools
extern void print_hex(char* name, uint8_t* buf, int len);
extern void print_char(char* name, uint8_t* buf, int len);
extern void compare_result(char* name, unsigned char* right, unsigned char* calc, int len);

extern void str2hex(const char* str, int str_len, uint8_t* out);

//test cipher
extern int test_x25519(void);
extern int test_hkdf_secrets(void);
extern int demonstrate_digest(void);
extern int test_aesgcm(void);

extern void test_secrets(void);

extern void parse_init(void);
extern void parse_exit(void);

extern void parse_packet(int index, char* buf, u_int len);

#endif