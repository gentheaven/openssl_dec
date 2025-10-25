#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void print_hex(char* name, uint8_t* buf, int len)
{
	if (name)
		printf("%s", name);

	int i;
	for (i = 0; i < len; i++) {
		printf("%.2x", buf[i]);
	}
	printf("\n");
}

void print_char(char* name, uint8_t* buf, int len)
{
	if (name)
		printf("%s", name);

	int i;
	for (i = 0; i < len; i++) {
		printf("%c", buf[i]);
	}
	printf("\n");
}

//a0ec31fc7de66fddc2f7af1280dd28b5abe8bab3c4b94afa11c0fef068392e63
//string to hex
void str2hex(const char* str, int str_len, uint8_t* out)
{
	int out_len = str_len >> 1;
	int i;
	unsigned int num;
	for (i = 0; i < out_len; i++) {
		sscanf(str, "%2x", &num);
		str = str + 2;
		out[i] = num & 0xff;
	}
}

void compare_result(char* name, unsigned char* right, unsigned char* calc, int len)
{
	if (memcmp(right, calc, len)) {
		printf("wrong result: %s\n", name);
		print_hex("right: ", right, len);
		print_hex("wrong: ", calc, len);
	}
	else {
		printf("%s: pass\n", name);
		print_hex(NULL, calc, len);
	}
	printf("\n");
}
