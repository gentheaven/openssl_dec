#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/safestack.h"
#include "openssl/pem.h"

#include "parse.h"
#include "cipher.h"

/*
ecdhe local private key(32B) 60c436e016e222581407cd72eb98fd81877414960a23041f5b8d2868dbbbe765
ecdhe peer  public  key(32B) df36682fdaee3c8a0d82ecd3307e7f5c1859c4717e64b5b5a1f7e02aa5c6b946
ecdhe pre-master secret(32B) 0c8e6ff0577cf91cc177cc380ffa1bc9178893fcfaa2c36754366f1a9d1f8201
early     secret(48B) 7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5
handshake secret(48B) 580de75af6b3c62b40157b9e0d2945f41ea2af44a9c78ed69c60d56d5beaa035989aa9366a8f83558f2e234c2016be5d
master    secret(48B) 2ea372e99385a2272efa0daf3cf8855186f9800ab08a521a08adcb5687de901716347049b9dad321b575a9d131a25818

*/
static const char peer_pubkey_str[] = "df36682fdaee3c8a0d82ecd3307e7f5c1859c4717e64b5b5a1f7e02aa5c6b946";
static unsigned char peer_pubkey[32];

static const char pre_masterkey_str[] = "0c8e6ff0577cf91cc177cc380ffa1bc9178893fcfaa2c36754366f1a9d1f8201";
static unsigned char pre_masterkey[32];

static const char early_secret_str[] = 
	"7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5";
static unsigned char early_secret[48];

static const char handshake_secret_str[] =
	"580de75af6b3c62b40157b9e0d2945f41ea2af44a9c78ed69c60d56d5beaa035989aa9366a8f83558f2e234c2016be5d";
static unsigned char handshake_secret[48];

static const char master_secret_str[] =
	"2ea372e99385a2272efa0daf3cf8855186f9800ab08a521a08adcb5687de901716347049b9dad321b575a9d131a25818";
static char master_secret[48];

/* server_handshake_traffic_secret
s hs traffic
handshake_traffic_hash    0fd9a374c696d582caf4e0570a3e60ee072c57e87a350920e0ed6a295ac95f953f686bf0dcb0712a9a00d8906785dd7c
server_hs_traffic_secret  b0a60c4afd55b1ebadd842915305eaa8cfb6315ab54fc969604a87d62f45d8ecbc6e8d41e2bee720288f228e0d6e62d8
key(32B)                  426acab666d9df805a49d7c2f53a50fd4038abf71e87b3058e169db76f24aa0d
IV(12B)                   04b97c0a384e2fab1270d42d
*/
static const char shs_start_hash_str[] = "0fd9a374c696d582caf4e0570a3e60ee072c57e87a350920e0ed6a295ac95f953f686bf0dcb0712a9a00d8906785dd7c";
static char shs_start_hash[48];

static const char shs_traffic_str[] = "b0a60c4afd55b1ebadd842915305eaa8cfb6315ab54fc969604a87d62f45d8ecbc6e8d41e2bee720288f228e0d6e62d8";
static char shs_traffic[48];

static const char shs_start_key_str[] = "426acab666d9df805a49d7c2f53a50fd4038abf71e87b3058e169db76f24aa0d";
static char shs_start_key[32];

static const char shs_start_iv_str[] = "04b97c0a384e2fab1270d42d";
static char shs_start_iv[12];

/* server_application_traffic_secret_0
s ap traffic
server_app_traffic_secret 0cd4f52e2e44fe15337b5cf76a2afb801b4a6ec19cda118ed0030184290e4b2bef64eb32eec909c0d1bf1aac239f2938
server_finished_hash      eb8f36c4b8d1044b544085657b72ee786c14ad47d5b872ed9a6b86c47155b23e65f448b50fee17472c2dc682cf87d329
key(32B)                  beff18a4924aa5aaa1dfa951b55d5d88092a48fe9e8900b634663fc90a25131d
IV(12B)                   fa1e89b3d79558983311eed3
*/
static const char sats_fin_hash_str[] = "eb8f36c4b8d1044b544085657b72ee786c14ad47d5b872ed9a6b86c47155b23e65f448b50fee17472c2dc682cf87d329";
static char sats_fin_hash[48];

static const char sats_traffic_str[] = "0cd4f52e2e44fe15337b5cf76a2afb801b4a6ec19cda118ed0030184290e4b2bef64eb32eec909c0d1bf1aac239f2938";
static char sats_traffic[48];

static const char sats_start_key_str[] = "beff18a4924aa5aaa1dfa951b55d5d88092a48fe9e8900b634663fc90a25131d";
static char sats_start_key[32];

static const char sats_start_iv_str[] = "fa1e89b3d79558983311eed3";
static char sats_start_iv[12];


/*
 * openssl-3.5.4\demos\keyexch\x25519.c
 * This is a demonstration of key exchange using X25519.
 * Ordinarily you would use random keys, which are demonstrated below. 
 */
int test_x25519(void)
{
	/* Test X25519 key exchange with random keys. */
	printf("start to test ECDHE: X25519\n");
	printf("Key exchange using random keys:\n");

	unsigned char pubkAlice_data[32]; //generated pubk to send to other peer
	unsigned char pubkBob_data[32]; //generated pubk to send to other peer
	EVP_PKEY* keyAlice;
	EVP_PKEY* keyBob;

	unsigned char secretAlice[32]; //pre-master secret
	unsigned char secretBob[32]; //pre-master secret

	keyAlice = create_x25519_key(NULL, pubkAlice_data);
	keyBob = create_x25519_key(NULL, pubkBob_data);

	cal_x25519_secret(keyAlice, pubkBob_data, secretAlice);
	cal_x25519_secret(keyBob, pubkAlice_data, secretBob);

	compare_result("pre master key(32B): ", secretAlice, secretBob, 32);
	EVP_PKEY_free(keyAlice);
	EVP_PKEY_free(keyBob);

	printf("\nKey exchange using known answer (deterministic):\n");
	str2hex(peer_pubkey_str, sizeof(peer_pubkey_str), peer_pubkey);
	str2hex(pre_masterkey_str, sizeof(pre_masterkey_str), pre_masterkey);
	keyAlice = create_x25519_key(local_prikey, pubkAlice_data);
	cal_x25519_secret(keyAlice, peer_pubkey, secretAlice);
	compare_result("pre master key(32B): ", pre_masterkey, secretAlice, 32);
	EVP_PKEY_free(keyAlice);

	printf("end to test ECDHE: X25519\n\n");
	return EXIT_SUCCESS;
}

int test_hkdf_secrets(void)
{
	printf("start to test HKDF secrets\n");
	unsigned char early[48];
	unsigned char handshake[48];
	unsigned char master[48];

	str2hex(pre_masterkey_str, (int)strlen(pre_masterkey_str), pre_masterkey);
	str2hex(early_secret_str, (int)strlen(early_secret_str), early_secret);
	str2hex(handshake_secret_str, (int)strlen(handshake_secret_str), handshake_secret);
	str2hex(master_secret_str, (int)strlen(master_secret_str), master_secret);

	//sha384
	tls_early_sha384(early);
	compare_result("early sha384", early_secret, early, 48);

	tls_handshake_sha384(early, pre_masterkey, handshake);
	compare_result("handshake sha384", handshake_secret, handshake, 48);

	tls_master_sha384(handshake, master);
	compare_result("master sha384", master_secret, master, 48);

	printf("end to test HKDF secrets\n\n");
	return EXIT_SUCCESS;
}

//openssl-3.5.4\demos\digest\EVP_MD_demo.c
 /*
  * Example of using EVP_MD_fetch and EVP_Digest* methods to calculate
  * a digest of static buffers
  */

  /*-
   * This demonstration will show how to digest data using
   * the soliloqy from Hamlet scene 1 act 3
   * The soliloqy is split into two parts to demonstrate using EVP_DigestUpdate
   * more than once.
   */

static const char* hamlet_1 =
"To be, or not to be, that is the question,\n"
"Whether tis nobler in the minde to suffer\n"
"The \xc5\xbflings and arrowes of outragious fortune,\n"
"Or to take Armes again in a sea of troubles,\n"
"And by opposing, end them, to die to sleep;\n"
"No more, and by a sleep, to say we end\n"
"The heart-ache, and the thousand natural shocks\n"
"That flesh is heir to? tis a consumation\n"
"Devoutly to be wished. To die to sleep,\n"
"To sleepe, perchance to dreame, Aye, there's the rub,\n"
"For in that sleep of death what dreams may come\n"
"When we haue shuffled off this mortal coil\n"
"Must give us pause. There's the respect\n"
"That makes calamity of so long life:\n"
"For who would bear the Ships and Scorns of time,\n"
"The oppressor's wrong, the proud man's Contumely,\n"
"The pangs of dispised love, the Law's delay,\n"
;
static const char* hamlet_2 =
"The insolence of Office, and the spurns\n"
"That patient merit of the'unworthy takes,\n"
"When he himself might his Quietas make\n"
"With a bare bodkin? Who would fardels bear,\n"
"To grunt and sweat under a weary life,\n"
"But that the dread of something after death,\n"
"The undiscovered country, from whose bourn\n"
"No traveller returns, puzzles the will,\n"
"And makes us rather bear those ills we have,\n"
"Then fly to others we know not of?\n"
"Thus conscience does make cowards of us all,\n"
"And thus the native hue of Resolution\n"
"Is sickled o'er with the pale cast of Thought,\n"
"And enterprises of great pith and moment,\n"
"With this regard their currents turn awry,\n"
"And lose the name of Action. Soft you now,\n"
"The fair Ophelia? Nymph in thy Orisons\n"
"Be all my sins remember'd.\n"
;

/* The known value of the SHA3-512 digest of the above soliloqy */
static unsigned char known_answer[] = {
	0xbb, 0x69, 0xf8, 0x09, 0x9c, 0x2e, 0x00, 0x3d,
	0xa4, 0x29, 0x5f, 0x59, 0x4b, 0x89, 0xe4, 0xd9,
	0xdb, 0xa2, 0xe5, 0xaf, 0xa5, 0x87, 0x73, 0x9d,
	0x83, 0x72, 0xcf, 0xea, 0x84, 0x66, 0xc1, 0xf9,
	0xc9, 0x78, 0xef, 0xba, 0x3d, 0xe9, 0xc1, 0xff,
	0xa3, 0x75, 0xc7, 0x58, 0x74, 0x8e, 0x9c, 0x1d,
	0x14, 0xd9, 0xdd, 0xd1, 0xfd, 0x24, 0x30, 0xd6,
	0x81, 0xca, 0x8f, 0x78, 0x29, 0x19, 0x9a, 0xfe,
};

int demonstrate_digest(void)
{
	EVP_MD_CTX* md_ctx = NULL;
	int ret = -1;
	unsigned int digest_length;
	unsigned char digest_value[64];

	md_ctx = digest_init(glib_ctx, "SHA3-512");
	/* Digest parts one and two of the soliloqy */
	if (EVP_DigestUpdate(md_ctx, hamlet_1, strlen(hamlet_1)) != 1) {
		fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
		goto cleanup;
	}
	if (EVP_DigestUpdate(md_ctx, hamlet_2, strlen(hamlet_2)) != 1) {
		fprintf(stderr, "EVP_DigestUpdate(hamlet_2) failed.\n");
		goto cleanup;
	}
	if (EVP_DigestFinal(md_ctx, digest_value, &digest_length) != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed.\n");
		goto cleanup;
	}

	compare_result("SHA3-512 result: ", known_answer, digest_value, 64);
	ret = 0;

cleanup:
	digest_exit(md_ctx);
	return ret;
}

//openssl-3.5.4\demos\cipher\aesgcm.c
/* AES-GCM test data obtained from NIST public test vectors */
/* AES key */
static unsigned char gcm_key[] = {
	0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
	0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
	0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

/* Unique initialisation vector */
static unsigned char gcm_iv[] = {
	0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
static unsigned char gcm_aad[] = {
	0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
	0x7f, 0xec, 0x78, 0xde
};


int test_aesgcm(void)
{
	char test_str[] = "hello world AES_256_GCM";
	size_t ori_len = strlen(test_str);
	char enc_str[1024];
	char dec_str[1024];
	unsigned char tag[EVP_MAX_AEAD_TAG_LENGTH];

	struct tls_cipher* enc = tls_cipher_init(0, NULL);
	tls_cipher_set(enc, 
		gcm_key, sizeof(gcm_key),
		gcm_iv, sizeof(gcm_iv),
		gcm_aad, sizeof(gcm_aad));

	int ret;
	int enc_len, dec_len;
	ret = aes_gcm_enc(enc, test_str, ori_len, tag, enc_str, &enc_len);
	ret = aes_gcm_dec(enc, tag, enc_str, (int)ori_len, dec_str, &dec_len);
	if (ret != EXIT_SUCCESS) {
		printf("test AES_256_GCM failed\n");
		print_hex("ori text:\n", test_str, (int)ori_len);
		print_hex("dec text:\n", dec_str, (int)ori_len);
	}else {
		printf("test AES_256_GCM passed\n");
		print_char("ori text: ", test_str, (int)ori_len);
		print_char("dec text: ", dec_str, (int)ori_len);
	}

	tls_cipher_exit(enc);
	return EXIT_SUCCESS;
}

//input: ECDHE local_prikey[32]
void test_secrets(void)
{
	unsigned char early[48];
	unsigned char handshake[48];
	unsigned char master[48];

	str2hex(peer_pubkey_str, sizeof(peer_pubkey_str), peer_pubkey);
	str2hex(pre_masterkey_str, (int)strlen(pre_masterkey_str), pre_masterkey);
	str2hex(early_secret_str, (int)strlen(early_secret_str), early_secret);
	str2hex(handshake_secret_str, (int)strlen(handshake_secret_str), handshake_secret);
	str2hex(master_secret_str, (int)strlen(master_secret_str), master_secret);

	//pre-master key
	EVP_PKEY* keyAlice;
	unsigned char pubkAlice_data[32]; //generated pubk to send to other peer
	unsigned char secretAlice[32]; //pre-master secret
	keyAlice = create_x25519_key(local_prikey, pubkAlice_data);
	cal_x25519_secret(keyAlice, peer_pubkey, secretAlice);
	EVP_PKEY_free(keyAlice);
	compare_result("pre-master key", pre_masterkey, secretAlice, 32);

	//HKDF-Extract(salt, IKM) -> PRK: earyl, handshake, master
	tls_early_sha384(early);
	compare_result("early secret", early_secret, early, 48);

	tls_handshake_sha384(early, pre_masterkey, handshake);
	compare_result("handshake secret", handshake_secret, handshake, 48);

	tls_master_sha384(handshake, master);
	compare_result("master secret", master_secret, master, 48);

	//HKDF-Expand(PRK, info, L) -> OKM, server_handshake_traffic_secret
	str2hex(shs_start_hash_str, (int)strlen(shs_start_hash_str), shs_start_hash);
	str2hex(shs_traffic_str, (int)strlen(shs_traffic_str), shs_traffic);
	str2hex(shs_start_key_str, (int)strlen(shs_start_key_str), shs_start_key);
	str2hex(shs_start_iv_str, (int)strlen(shs_start_iv_str), shs_start_iv);
	
	//server_handshake_traffic_secret
	unsigned char shts[48];
	unsigned char shts_key[32];
	unsigned char shts_iv[12];
	derive_secret(handshake, shs_start_hash, "s hs traffic", shts);
	compare_result("server_handshake_traffic_secret", shs_traffic, shts, 48);

	derive_key(shts, shts_key);
	compare_result("server handshake key", shs_start_key, shts_key, 32);
	derive_iv(shts, shts_iv);
	compare_result("server handshake IV", shs_start_iv, shts_iv, 12);

	//server_application_traffic_secret_0
	unsigned char sats[48];
	unsigned char sats_key[32];
	unsigned char sats_iv[12];

	str2hex(sats_fin_hash_str, (int)strlen(sats_fin_hash_str), sats_fin_hash);
	str2hex(sats_traffic_str, (int)strlen(sats_traffic_str), sats_traffic);
	str2hex(sats_start_key_str, (int)strlen(sats_start_key_str), sats_start_key);
	str2hex(sats_start_iv_str, (int)strlen(sats_start_iv_str), sats_start_iv);

	derive_secret(master, sats_fin_hash, "s ap traffic", sats);
	compare_result("server_application_traffic_secret_0", sats_traffic, sats, 48);

	derive_key(sats, sats_key);
	compare_result("server application key", sats_start_key, sats_key, 32);
	derive_iv(sats, sats_iv);
	compare_result("server application IV", sats_start_iv, sats_iv, 12);
}

time_t ASN1_TIME_to_time_t(const ASN1_TIME* asn1_time) 
{
	struct tm tm;
	memset(&tm, 0, sizeof(tm));

	if (!ASN1_TIME_to_tm(asn1_time, &tm)) {
		return 0;
	}

	return mktime(&tm);
}

X509* get_cert(char* path)
{
	FILE* fp = fopen(path, "r");
	if (!fp)
		return NULL;
	X509* x = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	return x;
}

int print_cert(void)
{
	X509 * x = get_cert("res\\certs\\server.crt");
	BIO* b = BIO_new_fp(stdout, BIO_NOCLOSE);

	//RFC5280
	//print useful information
	printf("X509 Certificate information\n");

	//Version: 3 (0x2)
	//Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	long version = X509_get_version(x);
	printf("version: %ld(0x%x)\n", version + 1, version);

	//Signature Algorithm: sha256WithRSAEncryption
	//const X509_ALGOR* tsig_alg = X509_get0_tbs_sigalg(x);
	int mdnid, pknid;
	//md: Message Digest algorithm, NID_sha384, NID_sha256
	//pk: Public Key algorithm, NID_rsaEncryption, NID_dsa
	X509_get_signature_info(x, &mdnid, &pknid,NULL, NULL);
	printf("%s With %s\n", OBJ_nid2ln(mdnid), OBJ_nid2ln(pknid));

	EVP_PKEY* pkey = X509_get0_pubkey(x);
	int bits = EVP_PKEY_bits(pkey);
	int bytes = EVP_PKEY_size(pkey);
	printf("Public-Key: (%d bit) (%d byte)\n", bits, bytes); //Public-Key: (2048 bit)

	// Subject: CN=albert
	X509_NAME* subject = X509_get_subject_name(x);
	char common_name[256];
	int ret;
	ret = X509_NAME_get_text_by_NID(subject, NID_commonName, common_name, sizeof(common_name));
	if (ret > 0)
		printf("comman name(CN) = %s\n", common_name);

	//Issuer: CN=albert-CA
	subject = X509_get_issuer_name(x);
	ret = X509_NAME_get_text_by_NID(subject, NID_commonName, common_name, sizeof(common_name));
	if (ret > 0)
		printf("Issuer: CN = %s\n", common_name);
	
	/* Validity
	 Not Before: Oct  6 23:57:46 2025 GMT
     Not After : Jul 26 23:57:46 2028 GMT
	*/
	const ASN1_TIME* not_before = X509_get0_notBefore(x);
	const ASN1_TIME* not_after = X509_get0_notAfter(x);
	time_t current_time = time(NULL);
	time_t start_time = ASN1_TIME_to_time_t(not_before);
	time_t end_time = ASN1_TIME_to_time_t(not_after);
	if (current_time < start_time) {
		printf("not valid\n");
	} else if (current_time > end_time) {
		printf("over time\n");
	} else {
		printf("Validity\n");
		printf("    Not Before: ");
		ASN1_TIME_print(b, not_before);
		printf("\n");
		printf("    Not After : ");
		ASN1_TIME_print(b, not_after);
		printf("\n");
	}

//STACK of all the extensions of a certificate
/*
	The following certificate extensions are defined in PKIX standards such as RFC5280.
Basic Constraints                  NID_basic_constraints
Key Usage                          NID_key_usage
Extended Key Usage                 NID_ext_key_usage

Subject Key Identifier             NID_subject_key_identifier
Authority Key Identifier           NID_authority_key_identifier

Private Key Usage Period           NID_private_key_usage_period

Subject Alternative Name           NID_subject_alt_name
Issuer Alternative Name            NID_issuer_alt_name
*/
	printf("\nX509v3 extensions:\n\n");
	print_cert_ext(x, NID_authority_key_identifier);
	print_cert_ext(x, NID_basic_constraints);
	print_cert_ext(x, NID_key_usage);
	print_cert_ext(x, NID_subject_alt_name);
	print_cert_ext(x, NID_subject_key_identifier);

	const ASN1_BIT_STRING* psig = NULL;
	X509_get0_signature(&psig, NULL, x);
	printf("sig value:\n");
	BIO_dump_indent_fp(stdout, psig->data, psig->length, 2);

	printf("\n\n");
	//X509_print(b, x);

	X509_free(x);
	BIO_free(b);
	return 0;
}

int test_rsa(void)
{
	int ret = EXIT_FAILURE;
	const unsigned char* msg = "hello world";
	size_t msg_len = strlen(msg);
	size_t encrypted_len = 0, decrypted_len = 0;
	unsigned char* encrypted = NULL, * decrypted = NULL;

	EVP_PKEY* pubkey = NULL;
	EVP_PKEY* prikey = NULL;
	pubkey = rsa_get_key_fromfile("res\\certs\\server.crt", 0, 1);
	if (!pubkey)
		goto cleanup;
	prikey = rsa_get_key_fromfile("res\\certs\\server.key", 0, 0);
	if (!prikey)
		goto cleanup;

	//encrypt by public key
	if (!ras_encrypt_key(pubkey,
		msg, msg_len, &encrypted, &encrypted_len)) {
		fprintf(stderr, "encryption failed.\n");
		goto cleanup;
	}

	//decrypt by private key
	if (!rsa_decrypt_key(prikey,
		encrypted, encrypted_len,
		&decrypted, &decrypted_len)) {
		fprintf(stderr, "decryption failed.\n");
		goto cleanup;
	}

	if (CRYPTO_memcmp(msg, decrypted, decrypted_len) != 0) {
		fprintf(stderr, "Decrypted data does not match expected value\n");
		goto cleanup;
	}
	printf("RSA Decrypted data match:\n%s\n", msg);
	ret = EXIT_SUCCESS;

cleanup:
	if(pubkey)
		EVP_PKEY_free(pubkey);
	if (prikey)
		EVP_PKEY_free(prikey);
	if(decrypted)
		OPENSSL_free(decrypted);
	if(encrypted)
		OPENSSL_free(encrypted);

	if (ret != EXIT_SUCCESS)
		ERR_print_errors_fp(stderr);
	return ret;
}

int test_rsa_ext(void)
{
	int ret = EXIT_FAILURE;
	const unsigned char* msg = "hello world";
	size_t msg_len = strlen(msg);
	size_t encrypted_len = 0, decrypted_len = 0;
	unsigned char* encrypted = NULL, * decrypted = NULL;

	unsigned char content[2048];
	int content_len;
	FILE* fp = fopen("res\\certs\\server.bin", "rb");
	content_len = (int)fread(content, 1, 2048, fp);
	fclose(fp);
	ret = ras_encrypt(content, content_len, msg, msg_len, &encrypted, &encrypted_len);

	fp = fopen("res\\certs\\server_pri.bin", "rb");
	content_len = (int)fread(content, 1, 2048, fp);
	fclose(fp);
	ret = rsa_decrypt(content, content_len, encrypted, encrypted_len, &decrypted, &decrypted_len);
	if (!memcmp(msg, decrypted, decrypted_len))
		printf("RSA ext Decrypted data match:\n%s\n", msg);

	if (decrypted)
		OPENSSL_free(decrypted);
	if (encrypted)
		OPENSSL_free(encrypted);

	return 0;
}

/*
 * This function demonstrates RSA signing of a SHA-256 digest using the PSS
 * padding scheme. You must already have hashed the data you want to sign.
 * For a higher-level demonstration which does the hashing for you, see
 * rsa_pss_hash.c.
 *
 * For more information, see RFC 8017 section 9.1. The digest passed in
 * (test_digest above) corresponds to the 'mHash' value.
 */
static int test_sign(void)
{
	int ret = 0;
	EVP_PKEY* pkey = NULL;
	size_t sig_len;
	unsigned char* sig = NULL;

	X509* x;
	x = get_cert("res\\certs\\server.crt");
	if (!x)
		return -1;

	//calc hash
	const ASN1_BIT_STRING* psig;
	X509_get0_signature(&psig, NULL, x);

	int hash_len = 32;
	unsigned char hash[EVP_MAX_MD_SIZE];
	cert_tbs_hash(x, hash);

	//private key
	pkey = rsa_get_key_fromfile("res\\certs\\RootCA.key", 0, 0);
	if (!pkey)
		goto end;
	ret = rsa_sign(pkey, hash, hash_len, &sig, &sig_len);
	if (ret && !memcmp(psig->data, sig, sig_len))
		printf("Passed for Cal sign value\n");
	else
		printf("Failed for Cal sign value\n");
#if 0
	fprintf(stdout, "sig value:\n");
	BIO_dump_indent_fp(stdout, sig, (int)sig_len, 2);
	fprintf(stdout, "\n");
#endif
	ret = 1;

end:
	X509_free(x);
	EVP_PKEY_free(pkey);
	OPENSSL_free(sig);

	return ret;
}

static int verify_sign(void)
{
	int ret = 0;
	EVP_PKEY* pkey = NULL;
	X509* x = NULL;

	//openssl x509 -in RootCA.crt -pubkey -noout > public_key.pem
	pkey = rsa_get_key_fromfile("res\\certs\\RootCA.crt", 0, 1);
	if (!pkey)
		goto end;

	x = get_cert("res\\certs\\server.crt");

	int hash_len = 32;
	unsigned char hash[EVP_MAX_MD_SIZE];
	cert_tbs_hash(x, hash);

	const ASN1_BIT_STRING* psig = NULL;
	X509_get0_signature(&psig, NULL, x);

	ret = rsa_verify_sign(pkey, hash, hash_len, psig->data, psig->length);
	if(ret)
		printf("Passed for Verify signature\n");
	else
		printf("Failed for Verify signature\n");

end:
	X509_free(x);
	EVP_PKEY_free(pkey);
	return ret;
}

//create sign of msg by private key;
//verify sign by public key
static int verify_sign_pss(void)
{
	int ret = 0;
	unsigned char* sig = NULL;
	size_t sig_len;

	EVP_PKEY* pubkey = NULL;
	EVP_PKEY* prikey = NULL;
	pubkey = rsa_get_key_fromfile("res\\certs\\server.crt", 0, 1);
	if (!pubkey)
		goto end;
	prikey = rsa_get_key_fromfile("res\\certs\\server.key", 0, 0);
	if (!prikey)
		goto end;

	char msg[] = "hello world";
	int msg_len = (int)strlen(msg);
	//create 256 bytes sign, used private key
	ret = rsa_sign_pss(prikey, msg, msg_len, &sig, &sig_len);
	if (!ret)
		goto end;

	//verify sign, used public key
	ret = rsa_verify_sign_pss(pubkey, msg, msg_len, sig, sig_len);
	if (ret)
		printf("Passed for PSS Verify signature\n");
	else
		printf("Failed for PSS Verify signature\n");

end:
	OPENSSL_free(sig);
	EVP_PKEY_free(pubkey);
	EVP_PKEY_free(prikey);
	return ret;
}


int test_cert(void)
{
	test_sign();
	verify_sign();
	verify_sign_pss();
	return 0;
}
