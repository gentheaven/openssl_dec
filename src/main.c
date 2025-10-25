#include "pcap.h"
#include "libnet.h"

#include "parse.h"
#include "cipher.h"

OSSL_LIB_CTX* glib_ctx = NULL;

//ecdhe local private key(32B) 60c436e016e222581407cd72eb98fd81877414960a23041f5b8d2868dbbbe765
const char local_prikey_str[] = "60c436e016e222581407cd72eb98fd81877414960a23041f5b8d2868dbbbe765";
unsigned char local_prikey[32];

void parse_packets(char* path, int stop_index)
{
	pcap_t* pcap;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("start to parse %s\n\n", path);
	pcap = pcap_open_offline(path, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Error: %s\n", errbuf);
		return;
	}

	struct pcap_pkthdr header;
	u_char* packet;
	int i = 0;
	while (1) {
		packet = (u_char*)pcap_next(pcap, &header);
		if (!packet)
			break;
		i++;
		parse_packet(i, packet, header.len);
		if (i >= stop_index)
			break;
	}
	pcap_close(pcap);

	printf("end to parse %s\n\n\n", path);
}

static const char separte_line[] = "****************************************************";

void test_code(void)
{
	test_x25519();
	printf("%s\n", separte_line);

	test_hkdf_secrets();
	printf("%s\n", separte_line);

	demonstrate_digest();
	printf("%s\n", separte_line);

	test_aesgcm();
	printf("%s\n", separte_line);
}

int main(int argc, char** argv)
{
	OSSL_LIB_CTX* ctx = openssl_init();
	if (!ctx)
		return -1;
	glib_ctx = ctx;
	str2hex(local_prikey_str, sizeof(local_prikey_str), local_prikey);

	//test_code();
	//test_secrets();

	parse_init();
	parse_packets("res\\s_connect.pcapng", 7);
	parse_exit();


	openssl_exit(ctx);
}
