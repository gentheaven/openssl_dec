#include "pcap.h"
#include "libnet.h"
#include "openssl/ssl3.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"

#include "llhttp.h"
#include "parse.h"
#include "cipher.h"

enum cypher_state {
	CYPHER_STATE_TEXT = 0, //plain text
	CYPHER_STATE_HANDSHAKE,
	CYPHER_STATE_APP
};
OSSL_HANDSHAKE_STATE gHandShake_state = TLS_ST_BEFORE;
int gCypher_state = CYPHER_STATE_TEXT;//plain text: 0; cryptographic text: 1


/*
* RFC8446, 5.2. Record Payload Protection
struct {
	opaque content[TLSPlaintext.length];
	ContentType type;
	uint8 zeros[length_of_padding];
} TLSInnerPlaintext;

struct {
	ContentType opaque_type = application_data; // 23
	ProtocolVersion legacy_record_version = 0x0303; // TLS v1.2
	uint16 length; //TLSPlaintext.length + 1 + length_of_padding
	opaque encrypted_record[TLSCiphertext.length];
} TLSCiphertext;

AAD: Additional Authenticated Data
additional_data : 5 bytes
TLSCiphertext.opaque_type 1B || 
TLSCiphertext.legacy_record_version 2B || 
TLSCiphertext.length 2B
*/
struct digest_content {
	uint8_t msg_type;
	int offset;
	int len;
};

#define MAX_RECORD_NUM 16
#define MAX_HANDSHAKE_LEN (64 * 1024) //64KB

struct parse_info {
	unsigned char* prikey;

	//digest calc
	char handshake_buf[MAX_HANDSHAKE_LEN];
	int handshake_len;
	struct digest_content mdc[MAX_RECORD_NUM]; //message digest calc
	int mdc_cnt; //0 based

	struct tls_cipher* enc; //Encryption and decryption

	u_int cipher_suite; //default: TLS_AES_256_GCM_SHA384 (0x1302)
	u_int group;
	char* server_pub_key;
	u_int server_pub_key_len;

	u_int hash_len;
	//secrets
	int mid_secrets_done; //finished cal handshake_traffic_hash and 4 secrets
	unsigned char pms[X25519_KEYLEN]; //pre-master key
	unsigned char early[EVP_MAX_MD_SIZE];
	unsigned char handshake[EVP_MAX_MD_SIZE];
	unsigned char master[EVP_MAX_MD_SIZE];

	unsigned char handshake_traffic_hash[EVP_MAX_MD_SIZE];
	int handshake_traffic_hash_done;

	unsigned char server_finished_hash[EVP_MAX_MD_SIZE];
	int server_finished_hash_done;

	int handshake_secrets_done; //finished cal handshake_traffic_secret
	int app_secrets_done; //finished cal application_traffic_secret

	//server_handshake_traffic_secret: shts
	unsigned char shts[EVP_MAX_MD_SIZE];
	struct final_secret shts_keys;

	//client_handshake_traffic_secret: chts
	unsigned char chts[EVP_MAX_MD_SIZE];
	struct final_secret chts_keys;

	//server_application_traffic_secret_0: sats
	unsigned char sats[EVP_MAX_MD_SIZE];
	struct final_secret sats_keys;

	//client_application_traffic_secret_0: cats
	unsigned char cats[EVP_MAX_MD_SIZE];
	struct final_secret cats_keys;

	//cert
	char* cert;
	int cert_len;

	//http parser
	llhttp_t parser;
	llhttp_settings_t settings;
};

struct parse_info gParse_info;

static void calc_hsfin_hash(void);
void verify_data(int c2s, char* server_data);

void parse_init(void)
{
	struct parse_info* parse = &gParse_info;
	memset(parse, 0, sizeof(struct parse_info));
	parse->prikey = local_prikey;
}

void parse_exit(void)
{
	struct parse_info* parse = &gParse_info;
	if (parse->enc)
		tls_cipher_exit(parse->enc);
}

//return origin buf
char* get_buf_size(char* buf, u_int* len)
{
	memcpy(len, buf, 4);
	return (buf + 4);
}

void set_buf_size(char* buf, int len)
{
	memcpy(buf, &len, 4);
}

//4 bytes: len, then buffer content
char* malloc_buf(char* buf, int len)
{
	char* out;
	out = malloc(len + 4);
	memcpy(out, &len, 4);
	memcpy(out + 4, buf, len);
	return out;
}

void update_buf(char** ori, char* buf, int len)
{
	char* out = *ori;
	if (!out) {
		//first
		out = malloc(MAX_HANDSHAKE_LEN);
		*ori = out;
		set_buf_size(out, 0);
	}

	//copy buf conten, update length
	u_int old_len, new_len;
	char* old;

	//copy content
	old = get_buf_size(out, &old_len);
	new_len = old_len + len;
	if (new_len >= MAX_HANDSHAKE_LEN) {
		printf("update_buf: too large buffer, current size = %d\n", new_len);
		return;
	}
	memcpy(old + old_len, buf, len);
	//update len
	memcpy(out, &new_len, 4);
}

void record_handshake_len(int type, char* buf, int len)
{
	struct parse_info* parse = &gParse_info;
	struct digest_content* dc = &parse->mdc[parse->mdc_cnt];

	int offset = parse->handshake_len;
	if ((offset + len) >= MAX_HANDSHAKE_LEN) {
		printf("record_handshake_len: handshake packet size is more than 64KB\n");
		return;
	}
	char* dest = parse->handshake_buf + offset;
	memcpy(dest, buf, len);
	dc->msg_type = type;
	dc->offset = offset;
	dc->len = len;

	parse->mdc_cnt++;
	parse->handshake_len += len;
}

/*
* start type: client hello
* end type: input parameter
*/
int calc_hash(int end_type, unsigned char* out, char* algo)
{
	EVP_MD_CTX* md_ctx = NULL;

	struct parse_info* parse = &gParse_info;
	struct digest_content* dc = parse->mdc;

	md_ctx = digest_init(glib_ctx, algo);
	int total_len = 0;
	while (1) {
		if (end_type == dc->msg_type) {
			total_len = dc->offset + dc->len;
			if (EVP_DigestUpdate(md_ctx, parse->handshake_buf, total_len) != 1) {
				fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
				goto cleanup;
			}
			break;
		}
		dc++;
	}

	if (EVP_DigestFinal(md_ctx, out, &parse->hash_len) != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed.\n");
		goto cleanup;
	}
	digest_exit(md_ctx);
	return EXIT_SUCCESS;

cleanup:
	if (md_ctx)
		digest_exit(md_ctx);
	return EXIT_FAILURE;
}

//server hello set it
void record_ciphersuite(u_int cs)
{
	gParse_info.cipher_suite = cs;
}

//server hello set it
void record_group(u_int group, char* key, u_int key_len)
{
	gParse_info.group = group;
	gParse_info.server_pub_key = key;
	gParse_info.server_pub_key_len = key_len;
}

/*
type = application_data = 23; //1B
version = 0x0303; //2B
len: 2B
*/
void fill_aad(unsigned char* aad, u_int len)
{
	unsigned char* head = aad;
	*head = 23; //application_data
	head++;

	//version
	unsigned short version = 0x0303;
	memcpy(head, &version, 2);
	head += 2;

	//len
	len = htons(len);
	memcpy(head, &len, 2);
}

//struct final_secret* keys = get_proper_keys(c2s, gCypher_state);
struct final_secret* get_proper_keys(int c2s, int state)
{
	struct parse_info* parse = &gParse_info;
	struct final_secret* keys = &parse->shts_keys;

	if (c2s) {//client keys
		if (state == CYPHER_STATE_HANDSHAKE)
			keys = &parse->chts_keys;
		else
			keys = &parse->cats_keys;
	} else {//server keys
		if (state == CYPHER_STATE_HANDSHAKE)
			keys = &parse->shts_keys;
		else
			keys = &parse->sats_keys;
	}

	return keys;
}

/* Increment the sequence counter */
void tls_increment_sequence(int c2s)
{
	struct final_secret* keys = get_proper_keys(c2s, gCypher_state);
	keys->seq++;
}

/*
* in: unsigned char iv[12]
* in: seq
* out: unsigned char out[12]
*/
void calc_nonce(unsigned char* iv, uint64_t seq, unsigned char* out)
{
	int i;
	seq = htonll(seq);
	memset(out, 0, 12);
	memcpy(out + 4, &seq, 8);
	for (i = 0; i < 12; i++) {
		out[i] = iv[i] ^ out[i];
	}
}

/*
* c2s = 1: client to server
* c2s = 0: server to client
*
* after decryption, buf content as follows:
 struct {
          opaque content[TLSPlaintext.length];
          uint8_t type;
          uint8 tag[16];
      } TLSInnerPlaintext;
* out:
*	type: opaque_type
*
*/
int decode_app_data(int c2s, char* buf, u_int len, uint8_t* type)
{
	int offset = 16;
	struct parse_info* parse = &gParse_info;
	struct final_secret* keys = &parse->shts_keys;

	keys = get_proper_keys(c2s, gCypher_state);

	//Additional Authenticated Data(AAD)
	unsigned char aad[5];
	fill_aad(aad, len);
	
	//the last 16 bytes is TAG value
	unsigned char tag[EVP_MAX_AEAD_TAG_LENGTH];
	len = len - EVP_MAX_AEAD_TAG_LENGTH;
	memcpy(tag, buf + len, EVP_MAX_AEAD_TAG_LENGTH);

	unsigned char nonce[12];
	calc_nonce(keys->iv, keys->seq, nonce);

	struct tls_cipher* enc = parse->enc;
	if (!enc) {
		enc = tls_cipher_init(0, NULL);
		parse->enc = enc;
		printf("start to decode handshake packets:\n\n");
	}
	aes_gcm_set(enc, keys->key, nonce, aad);

	int ret = aes_gcm_dec(enc, tag, (unsigned char*)buf, len, buf, &len);
	if (ret != EXIT_SUCCESS)
		printf("decode_app_data failed\n");

	*type = buf[len - 1];
	const char* name = do_ssl_trace_str(*type, ssl_content_tbl, ssl_content_tbl_num);
	printf("content type is %s(%d)\n", name, *type);
	return ret;
}

/*
server hello : SSL3_RT_CHANGE_CIPHER_SPEC call this function
	start to cal ClientHello...ServerHello hash
	{0x1302, "TLS_AES_256_GCM_SHA384"}
	TLS1_3_CK_AES_256_GCM_SHA384 = 0x03001302
	{29, "ecdh_x25519"},

hash/keys shared with server and client
	handshake_traffic_hash
	pre-master key
	early_secret
	handshake_secret
	master_secret

return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
*/
int  calc_handshake_secrets(void)
{
	struct parse_info* parse = &gParse_info;

	if (!parse->handshake_traffic_hash_done) {
		calc_hash(SSL3_MT_SERVER_HELLO, parse->handshake_traffic_hash, "SHA384");
		parse->handshake_traffic_hash_done = 1;
	}

	if (parse->mid_secrets_done)
		return EXIT_SUCCESS;
	if (parse->group != 29 || parse->cipher_suite != 0x1302)
		return EXIT_FAILURE;
	printf("\ncalc server_handshake_traffic_secret hash\n");
	printf("cipher suite: TLS_AES_256_GCM_SHA384, group: ecdh_x25519\n");

	int sha_len = parse->hash_len;
	print_hex("handshake hash: ", parse->handshake_traffic_hash, sha_len);

	//pre-master key
	EVP_PKEY* pmskey;
	unsigned char pubkey_data[X25519_KEYLEN]; //generated pubk to send to other peer
	pmskey = create_x25519_key(parse->prikey, pubkey_data);
	cal_x25519_secret(pmskey, parse->server_pub_key, parse->pms);
	EVP_PKEY_free(pmskey);
	print_hex("pre-master key: ", parse->pms, X25519_KEYLEN);

	//HKDF-Extract(salt, IKM) -> PRK: earyl, handshake, master
	tls_early_sha384(parse->early);
	print_hex("early key:      ", parse->early, sha_len);

	tls_handshake_sha384(parse->early, parse->pms, parse->handshake);
	print_hex("handshake key:  ", parse->handshake, sha_len);

	tls_master_sha384(parse->handshake, parse->master);
	print_hex("master key:     ", parse->master, sha_len);

	parse->mid_secrets_done = 1;
	return EXIT_SUCCESS;
}

/*
* when got SSL3_RT_CHANGE_CIPHER_SPEC record,
* call this function
* 
* handshake = 1: handshake_traffic_secret
* handshake = 0: application_traffic_secret
* 
return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
*/
int calc_secrets(int handshake)
{
	struct parse_info* parse = &gParse_info;
	int sha_len = parse->hash_len;

	if(handshake) {
		if (parse->handshake_secrets_done)
			return EXIT_SUCCESS;

		//server_handshake_traffic_secret = Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello);
		calc_secrets_ext(parse->handshake, "s hs traffic", parse->handshake_traffic_hash,
			parse->shts, &parse->shts_keys);
		
		//client_handshake_traffic_secret = Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello);
		calc_secrets_ext(parse->handshake, "c hs traffic", parse->handshake_traffic_hash,
			parse->chts, &parse->chts_keys);

		parse->handshake_secrets_done = 1;
		return EXIT_SUCCESS;
	}

	if(parse->app_secrets_done)
		return EXIT_SUCCESS;

	//client_application_traffic_secret_0 = Derive-Secret(Master Secret, "c ap traffic", ClientHello...server Finished)
	calc_secrets_ext(parse->master, "c ap traffic", parse->server_finished_hash,
		parse->cats, &parse->cats_keys);

	//server_application_traffic_secret_0 = Derive-Secret(Master Secret, "s ap traffic", ClientHello...server Finished)
	calc_secrets_ext(parse->master, "s ap traffic", parse->server_finished_hash,
		parse->sats, &parse->sats_keys);
	parse->app_secrets_done = 1;
	return EXIT_SUCCESS;
}

int get_previous_type(struct digest_content* dc, int type)
{
	int pre = -1;
	while (1) {
		pre = dc->msg_type;
		dc++;
		if (dc->msg_type == type) {
			return pre;
		}
	}
	return pre;
}

/*
update server_finished_hash: <ClientHello...server Finished>
verify data
*/
void calc_hsfin_hash(void)
{
	struct parse_info* parse = &gParse_info;
	if (parse->server_finished_hash_done)
		return;
	calc_hash(SSL3_MT_FINISHED, parse->server_finished_hash, "SHA384");
	parse->server_finished_hash_done = 1;
	//print_hex("server_finished_hash:\n", parse->server_finished_hash, parse->hash_len);
}

/*
* verify_data
* RFC8446
* 4.4.4. Finished
* 
verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
* Only included if present
* 
Context = (ClientHello ... Certificate*, CertificateVerify*)

hash = Transcript-Hash(Context);
finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length);
verify_data = HMAC(finished_key, hash);

Base Key for each scenario:

server hello: BaseKey = server_handshake_traffic_secret

   +-----------+-------------------------+-----------------------------+
   | Mode      | Handshake Context       | Base Key                    |
   +-----------+-------------------------+-----------------------------+
   | Server    | ClientHello ... later   | server_handshake_traffic_   |
   |           | of EncryptedExtensions/ | secret                      |
   |           | CertificateRequest      |                             |
   |           |                         |                             |
   | Client    | ClientHello ... later   | client_handshake_traffic_   |
   |           | of server               | secret                      |
   |           | Finished/EndOfEarlyData |                             |
   |           |                         |                             |
   | Post-     | ClientHello ... client  | client_application_traffic_ |
   | Handshake | Finished +              | secret_N                    |
   |           | CertificateRequest      |                             |
   +-----------+-------------------------+---------------------------
*/
void verify_data(int c2s, char* server_data)
{
	struct parse_info* parse = &gParse_info;

	unsigned char hash[SHA384_DIGEST_LENGTH];
	unsigned char finished[EVP_MAX_MD_SIZE];
	int pre = SSL3_MT_CERTIFICATE_VERIFY;
	unsigned char* secret = parse->shts;
	unsigned char* phash = hash;
	if (c2s) {
		secret = parse->chts;
		pre = SSL3_MT_FINISHED;
		phash = parse->server_finished_hash;
	} else {
		secret = parse->shts;
		pre = get_previous_type(parse->mdc, SSL3_MT_FINISHED);
		calc_hash(pre, hash, "SHA384");
	}
	
	//finished_key = HKDF-Expand-Label(BaseKey, Label, "", HashLength)
	//tls13_derive_finishedkey("finished")
	derive_secret(secret, NULL, "finished", finished);

	unsigned char verify_data[SHA384_DIGEST_LENGTH];
	size_t outlen;
	hmac_verify_data(finished, phash, verify_data, outlen);
	compare_result("server verify data", server_data, verify_data, SHA384_DIGEST_LENGTH);
}

/*
Extension: key_share (len=1263) X25519MLKEM768, x25519
	Type: key_share (51)
	Length: 1263
	Key Share extension
		Client Key Share Length: 1261
		Key Share Entry: Group: Reserved (GREASE), Key Exchange length: 1
		Key Share Entry: Group: X25519MLKEM768, Key Exchange length: 1216
			Group: X25519MLKEM768 (4588)
			Key Exchange Length: 1216
			Key Exchange [бн]: 9e4672db78af592a03c26a277e892b925b26c34437ebaa40
		Key Share Entry: Group: x25519, Key Exchange length: 32

		RFC8846
		4.2.8. Key Share

struct {
	KeyShareEntry client_shares<0..2^16-1>; //length: 2B
} KeyShareClientHello;

struct {
	KeyShareEntry server_share; //no length field
} KeyShareServerHello;

struct {
	NamedGroup group;
	opaque key_exchange<1..2^16-1>;
} KeyShareEntry;
*/
void parse_key_share(int client, struct hello_extension* head)
{
	char* buf = (char*)head;
	char* cur = buf;

	u_int total_len = ntohs(head->length);
	int offset = 4;
	cur = cur + offset;
	total_len = total_len - offset;

	//Key Share extension
	if (client) {
		uint16_t share_len = PACKET_GET_2(cur);
		offset = 2;
		cur = cur + offset;
		total_len = total_len - offset;
	}

	//key share entry
	struct hello_extension* entry = (struct hello_extension*)cur;
	uint16_t entry_len;
	uint16_t type;
	uint16_t cur_len = 0;
	const char* name;
	while (1) {
		type = ntohs(entry->type);
		entry_len = ntohs(entry->length);
		name = do_ssl_trace_str(type, ssl_groups_tbl, ssl_groups_tbl_num);
		printf("group: %s(%d), len = %d\n", name, type, entry_len);
		if (!client) {
			//server ECDHE pub key
			cur_len = ntohs(entry->length);
			print_hex("server key: ", cur + 4, cur_len);
			record_group(type, cur + 4, cur_len);
		}
		//next extension
		cur_len = cur_len + entry_len + 4;
		entry = (struct hello_extension*)(cur + cur_len);
		if (cur_len >= total_len)
			break;
	}
	printf("\n");
}

/*
RFC7301: Application - Layer Protocol Negotiation
opaque ProtocolName<1..2^8-1>;

   opaque ProtocolName<1..2^8-1>;

   struct {
	   ProtocolName protocol_name_list<2..2^16-1>
   } ProtocolNameList;
*/
void parse_alpn(int c2s, struct hello_extension* head)
{
	char* cur = (char*)head;
	int total_len = ntohs(head->length);
	cur = cur + 4;

	//protocol_name_list
	int name_list_len = PACKET_GET_2(cur);
	cur += 2;

	//ProtocolName: http/1.1
	int len, offset;
	total_len = name_list_len;
	while (total_len > 0) {
		len = *cur;
		print_char("ALPN protocol name: ", cur + 1, len);
		offset = len + 1;
		cur += offset;
		total_len -= offset;
	}
}

void parse_hello_ext(int c2s, char* buf, u_int len)
{
	uint16_t cipher_len = PACKET_GET_2(buf);
	printf("Extensions length: %d\n", cipher_len);

	int offset = 2;
	char* cur = buf + offset;
	u_int total_len = len - offset;
	struct hello_extension* head = (struct hello_extension*)cur;

	uint16_t cur_len = 0;
	uint16_t extopt_len;
	uint16_t type;
	char* temp;
	const char* name;
	while (1) {
		type = ntohs(head->type);
		extopt_len = ntohs(head->length);

		name = do_ssl_trace_str(type, ssl_exts_tbl, ssl_exts_tbl_num);
		printf("extension_type=%s(%d), length=%d\n", name, type, extopt_len);
		switch (type) {
		case TLSEXT_TYPE_server_name:
			//skip 2 bytes list_length, temp point to struct ext_ServerName
			//name_type: 1B, length: 2B
			temp = cur + cur_len + 6;
			if (*temp == TLSEXT_NAMETYPE_host_name) {
				temp++; //skip type 1B
				int name_len = PACKET_GET_2(temp);
				temp += 2; //skip len 2B
				print_char("server_name = ", temp, name_len);
			}
			break;
		case TLSEXT_TYPE_key_share:
			parse_key_share(c2s, head);
			break;
		case TLSEXT_TYPE_application_layer_protocol_negotiation:
			parse_alpn(c2s, head);
			break;
		default:
			break;
		}
		//next extension
		cur_len = cur_len + extopt_len + 4;
		head = (struct hello_extension*)(cur + cur_len);
		if (cur_len >= cipher_len)
			break;
	}
}

/*
7.4.1.3. Server Hello

uint8 CipherSuite[2];
struct {
	//same as client hello
	ProtocolVersion server_version;
	Random random;
	SessionID session_id;

	//different with client hello
	CipherSuite cipher_suite;
	CompressionMethod compression_method;
	select (extensions_present) {
		case false:
			struct {};
		case true:
			Extension extensions<0..2^16-1>;
	};
} ServerHello;
*/
void parse_shello(int c2s, char* buf, u_int len)
{
	struct SSlHello* head = (struct SSlHello*)buf;

	print_hex("Random:     ", head->random, 32);
	int id_len = head->session_id_len;
	print_hex("Session ID: ", head->session_id, id_len);

	int offset = 2 + 32 + 1 + id_len;
	char* cur = buf + offset;
	u_int total_len = len - offset;
	//uint8 CipherSuite[2];
	uint16_t CipherSuite = PACKET_GET_2(cur);
	const char* name = do_ssl_trace_str(CipherSuite, ssl_ciphers_tbl, ssl_ciphers_tbl_num);
	printf("Cipher Suite: %s(0x%x)\n", name, CipherSuite);
	record_ciphersuite(CipherSuite);

	//skip compression_method
	offset = offset + 3; //CipherSuite: 2B, compression_method: 1B
	cur = buf + offset;
	total_len = len - offset;
	//extensions
	parse_hello_ext(c2s, cur, total_len);
}

void parse_chello(int client, char* buf, u_int len)
{
	struct SSlHello* head = (struct SSlHello*)buf;

	print_hex("Random:     ", head->random, 32);
	int id_len = head->session_id_len;
	print_hex("Session ID: ", head->session_id, id_len);

	//version: 2B; random: 32B; session id len: 1B
	int offset = 2 + 32 + 1 + id_len;
	char* cur = buf + offset;
	u_int total_len = len - offset;

	//CipherSuite length: 2B
	uint16_t cipher_len = PACKET_GET_2(cur);
	printf("total %d cipher suites\n", cipher_len / 2);
	offset = cipher_len + 2;
	cur = cur + offset;
	total_len = total_len - offset;

	//CompressionMethod compression_methods<1..2^8-1>;
	id_len = *cur;
	offset = 1 + id_len;
	cur = cur + offset;
	total_len = total_len - offset;
	parse_hello_ext(client, cur, total_len);
}

//uint8_t length[3];  bytes in message
int get_3Bytes_len(uint8_t* ptr)
{
	int len;
	memcpy(&len, ptr, 3);
	len = ntohl(len);
	len = len >> 8;
	return len;
}

int parse_newsession_ticket(int c2s, char* buf, u_int len)
{
	struct new_session_ticket* nst = (struct new_session_ticket*)buf;
	if (c2s) {
		//client to server
		return 0;
	}

	//server to client
	/*
	* opaque ticket_nonce<0..255>;
	ticket_nonce: A per-ticket value that is unique across all tickets issued on this connection.
	*/
	char* cur = buf + NEW_SESSION_TICKET_NONCE_OFFSET;
	//uint64_t nonce = ntohll(*(uint64_t*)cur);
	//ticket lenght 2B
	cur = cur + nst->nonce_len;
	u_short ticket_len = PACKET_GET_2(cur);
	cur = cur + 2;
	print_hex("session ticket: ", cur, 16);
	return 0;
}

int cb_header_field(llhttp_t* ph, const char* at, size_t length)
{
	int i;
	for (i = 0; i < length; i++) {
		printf("%c", at[i]);
	}
	return 0;
}

int cb_header_value(llhttp_t* ph, const char* at, size_t length)
{
	if (length)
		print_char(": ", (uint8_t*)at, (int)length);
	return 0;
}

int cb_body(llhttp_t* ph, const char* at, size_t length)
{
	if (length) {
		printf("\noutput file(%lld bytes): index.htm\n", length);
		FILE* fp = fopen("index.html", "wb");
		fwrite(at, 1, length, fp);
		fclose(fp);
	}
	return 0;
}

/* client hello: include Extension: ALPN
* so appliction type is http
* 
* ALPN: Application-Layer Protocol Negotiation
Extension: application_layer_protocol_negotiation (len=14)
	Type: application_layer_protocol_negotiation (16)
	Length: 14
	ALPN Extension Length: 12
	ALPN Protocol
		ALPN string length: 2
		ALPN Next Protocol: h2
		ALPN string length: 8
		ALPN Next Protocol: http/1.1
*/
void parse_http(int c2s, char* buf, u_int len)
{
	struct parse_info* parse = &gParse_info;
	llhttp_t *parser = &parse->parser;
	llhttp_settings_t *settings = &parse->settings;

	//http parser
	llhttp_settings_init(settings);
	llhttp_init(parser, HTTP_BOTH, settings);

	settings->on_header_field = cb_header_field;
	settings->on_header_value = cb_header_value;
	settings->on_body = cb_body;

	llhttp_execute(parser, buf, len);
}

void output_cert(char* buf, int len)
{
	struct parse_info* parser = &gParse_info;
	parser->cert = buf;
	parser->cert_len = len;
#if 0
	printf("write certification content to file server_cert.bin\n");
	//write to file
	FILE* fp = fopen("server_cert.bin", "wb");
	fwrite(buf, 1, len, fp);
	fclose(fp);
#endif
	//print cert information
	printf("*********** parsing cert ***********\n");

	X509* x;
	const unsigned char* p = buf;
	x= d2i_X509(NULL, &p, len);

	//Signature Algorithm: sha256WithRSAEncryption
	int mdnid, pknid;
	X509_get_signature_info(x, &mdnid, &pknid, NULL, NULL);
	printf("%s With %s\n", OBJ_nid2ln(mdnid), OBJ_nid2ln(pknid));

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
	BIO* b = BIO_new_fp(stdout, BIO_NOCLOSE);
	//return -1 if asn1_time is earlier than, or equal to, in_tm
	if (X509_cmp_time(not_before, &current_time) < 0 &&
		X509_cmp_time(not_after, &current_time) > 0) {
		printf("Validity\n");
		printf("    Not Before: ");
		ASN1_TIME_print(b, not_before);
		printf("\n");
		printf("    Not After : ");
		ASN1_TIME_print(b, not_after);
		printf("\n");
	}
	BIO_free(b);

	printf("\nX509v3 extensions:\n\n");
	print_cert_ext(x, NID_authority_key_identifier);
	print_cert_ext(x, NID_basic_constraints);
	print_cert_ext(x, NID_key_usage);
	print_cert_ext(x, NID_subject_alt_name);
	print_cert_ext(x, NID_subject_key_identifier);

	//Signature Value:
	const ASN1_BIT_STRING* psig = NULL;
	X509_get0_signature(&psig, NULL, x);
	printf("Signature Value:\n");
	BIO_dump_indent_fp(stdout, psig->data, psig->length, 2);

	printf("***********end parsing cert ***********\n");
	X509_free(x);
}

//RFC8446 4.4.2. Certificate
int parse_certificate(int c2s, char* buf, u_int len)
{
	struct Certificate* ct = (struct Certificate*)buf;
	char* cur = buf;

	//Certificate
	uint8_t request_context_len = ct->request_context_len;
	int offset;
	offset = CERTIFICATE_OFFSET(request_context_len);
	len -= offset;
	cur += offset;

	//certificate_list
	struct CertificateEntry_list* ct_list = (struct CertificateEntry_list*)cur;
	int ct_list_len;
	ct_list_len = get_3Bytes_len(ct_list->cert_list_len);
	cur += 3;
	int left = ct_list_len;

	int entry_index = 0;
	//CertificateEntry[i]
	struct CertificateEntry* entry;
	int cert_data_len;
	struct cert_extension* ext;
	int ext_len;
	while (left > 0) {
		entry = (struct CertificateEntry*)cur;
		cert_data_len = get_3Bytes_len(entry->cert_data_len);

		printf("cert(%d): len is %d bytes\n", entry_index + 1, cert_data_len);
		output_cert(cur + 3, cert_data_len);

		offset = CERT_EXT_OFFSET(cert_data_len);
		left -= offset;
		cur += offset;
		ext = (struct cert_extension*)cur;
		ext_len = ntohs(ext->len);

		//ext
		offset = 2 + ext_len;
		left -= offset;
		cur += offset;
		entry_index++;
	}
	printf("total %d certs\n\n", entry_index);
	return 0;
}

int client_verify_sig(char* sig, int sig_len, unsigned char* hash)
{
	unsigned char tls13tbs[TLS13_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
	int tbs_len;
	tbs_len = get_cert_verify_tbs_data(tls13tbs, TLS_ST_SW_CERT_VRFY, hash, 48);

	struct parse_info* parser = &gParse_info;
	X509* x;
	const unsigned char* p = parser->cert;
	x = d2i_X509(NULL, &p, parser->cert_len);
	EVP_PKEY* pkey = X509_get0_pubkey(x);
	int ret = rsa_verify_sign_pss(pkey, tls13tbs, tbs_len, sig, sig_len);
	if (ret)
		printf("client_verify_sig: passed\n");

	X509_free(x);
	return ret;
}

//RFC8446 4.4.3. Certificate Verify
int parse_certificate_verify(int c2s, char* buf, u_int len)
{
	struct CertificateVerify* cv = (struct CertificateVerify*)buf;
	uint16_t algo = htons(cv->algorithm);
	const char* name = got_SignatureScheme_name(algo);
	printf("SignatureScheme is %s\n", name);

	char* cur = buf + 4;
	int sig_len = htons(cv->signature_len);
	printf("Signature Value:\n");
	BIO_dump_indent_fp(stdout, cur, sig_len, 2);

	unsigned char hash[EVP_MAX_MD_SIZE];
	calc_hash(SSL3_MT_CERTIFICATE, hash, "SHA384");
	//print_hex("Certificate hash:\n", hash, 48);

	client_verify_sig(cur, sig_len, hash);
	printf("\n");
	return 0;
}

//if client recv SSL3_MT_FINISHED msg, return 1; otherwise return 0
int parse_handleshake(int c2s, char* buf, u_int len)
{
	struct TLSHandshake* hsHeader = (struct TLSHandshake*)buf;
	char* cur;
	u_int total_len;

	cur = buf + TLS_HS_LEN;
	total_len = len - TLS_HS_LEN;

	printf("handleshake layer: ");
	const char* name = do_ssl_trace_str(hsHeader->msg_type, ssl_handshake_tbl, ssl_handshake_tbl_num);
	printf("%s\n", name);

	int ext_len;
	ext_len = get_3Bytes_len(hsHeader->length);
	printf("length is %d\n", ext_len);

	int record_len = ext_len + TLS_HS_LEN;
	record_handshake_len(hsHeader->msg_type, buf, record_len);

	switch (hsHeader->msg_type) {
	case SSL3_MT_CLIENT_HELLO:
		gHandShake_state = TLS_ST_CW_CLNT_HELLO; //client write: client hello
		parse_chello(c2s, cur, total_len);
		break;
	case SSL3_MT_SERVER_HELLO:
		gHandShake_state = TLS_ST_SW_SRVR_HELLO; //server write: server hello
		parse_shello(c2s, cur, total_len);
		break;
	case SSL3_MT_ENCRYPTED_EXTENSIONS:
		break;
	case SSL3_MT_NEWSESSION_TICKET:
		//parse_newsession_ticket(c2s, cur, ext_len);
		break;
	case SSL3_MT_CERTIFICATE:
		parse_certificate(c2s, cur, ext_len);
		break;
	case SSL3_MT_SERVER_KEY_EXCHANGE:
		break;
	case SSL3_MT_CERTIFICATE_REQUEST:
		break;
	case SSL3_MT_SERVER_DONE:
		break;
	case SSL3_MT_CERTIFICATE_VERIFY:
		parse_certificate_verify(c2s, cur, ext_len);
		break;
	case SSL3_MT_CLIENT_KEY_EXCHANGE:
		break;
	case SSL3_MT_FINISHED:
		//print_hex("server verify data\n", cur, ext_len);
		calc_hsfin_hash();
		verify_data(c2s, cur);
		calc_secrets(0);
		if (c2s) {
			return 1;
		}
		break;
	default:
		return 0;
	}

	return 0;
}

void parse_tls(int c2s, char* buf, u_int len)
{
	printf("TLS part: len is %d\n", len);
	//record level
	struct TLSRecord* record = (struct TLSRecord*)buf;
	char* cur;
	u_int total_len, offset, record_len;

	cur = buf;
	total_len = len;
	offset = TLS_RECORD_LEN;
	int ret = 0;
	char* decode;
	uint8_t type;
	int finished = 0;
	while (total_len > 0) {
		printf("record layer: ");
		record_len = ntohs(record->length);

		switch (record->type) {
		case SSL3_RT_CHANGE_CIPHER_SPEC:
			printf("change cipher spec\n");
			//after this, all text is cryptographic
			calc_handshake_secrets();
			calc_secrets(1);
			gCypher_state = CYPHER_STATE_HANDSHAKE;
			break;
		case SSL3_RT_ALERT:
			printf("alert\n");
			break;
		case SSL3_RT_HANDSHAKE:
			printf("handshake: length is %d\n", record_len);
			parse_handleshake(c2s, cur + TLS_RECORD_LEN, total_len - TLS_RECORD_LEN);
			break;
		case SSL3_RT_APPLICATION_DATA:
			printf("app data: length is %d\n", record_len);
			decode = cur + TLS_RECORD_LEN;
			ret = decode_app_data(c2s, decode, record_len, &type);
			if (ret == EXIT_SUCCESS) {
				if (SSL3_RT_APPLICATION_DATA == type)
					parse_http(c2s, decode, total_len - TLS_RECORD_LEN);
				else if (SSL3_RT_HANDSHAKE == type)
					finished = parse_handleshake(c2s, decode, total_len - TLS_RECORD_LEN);
				else //SSL3_RT_ALERT or SSL3_RT_CHANGE_CIPHER_SPEC
					break;
			}
			tls_increment_sequence(c2s);
			if(finished)
				gCypher_state = CYPHER_STATE_APP;
			break;
		default:
			printf("error type: %d\n", record->type);
			return;
		}

		offset = TLS_RECORD_LEN + record_len;
		cur = cur + offset;
		total_len = total_len - offset;
		record = (struct TLSRecord*)cur;
	}
}

void parse_packet(int index, char* buf, u_int len)
{
	u_long family = *(u_long*)buf;
	if (family != 2)
		return;

	//family: 4 bytes
	u_int total_len = len - 4;
	char* cur = buf + 4;
	printf("packet %d: length is %d\n", index, total_len);

	//IP header
	struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)cur;
	int ip_total_len = ntohs(ip_hdr->ip_len);
	int ip_len = ip_hdr->ip_hl * 4;
	printf("IP header length is %d\n", ip_len);
	if (ip_hdr->ip_p != IPPROTO_TCP)
		return;

	//TCP header
	total_len = total_len - ip_len;
	cur = cur + ip_len;

	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)cur;
	int tcp_len = tcp_hdr->th_off * 4;
	uint16_t sport, dport;
	sport = ntohs(tcp_hdr->th_sport);
	dport = ntohs(tcp_hdr->th_dport);
	printf("TCP header length is %d\n", tcp_len);
	printf("Source Port: %d\n", sport);
	printf("Dest Port: %d\n", dport);

	//TLS
	int c2s = 0; //client to server
	if (sport == IPPORT_HTTPS) {
		c2s = 0;
		printf("\nTLS: server to client\n");
	}
	else if (dport == IPPORT_HTTPS) {
		c2s = 1;
		printf("\nTLS: client to server\n");
	}
	else {
		//not https
		return;
	}

	//TLS part
	total_len = total_len - tcp_len;
	cur = cur + tcp_len;
	parse_tls(c2s, cur, total_len);
	printf("\n\n========================\n");
}

//xxx, random, secret
void fill_secret(FILE* fp, unsigned char* dst, struct final_secret* keys)
{
	char buf[256];
	//CLIENT_HANDSHAKE_TRAFFIC_SECRET, random, secret
	fscanf(fp, "%s", buf);
	fscanf(fp, "%s", buf);
	fscanf(fp, "%s", buf);
	str2hex(buf, (int)strlen(buf), dst);

	derive_key(dst, keys->key);
	derive_iv(dst, keys->iv);
}

//wireshark export TLS session secrets
void read_secrets(char* path)
{
	struct parse_info *parse = &gParse_info;
	FILE* fp = fopen(path, "r");
	if (!fp)
		return;

	//fill secrets
	fill_secret(fp, parse->chts, &parse->chts_keys);
	fill_secret(fp, parse->shts, &parse->shts_keys);
	fill_secret(fp, parse->sats, &parse->sats_keys);
	fill_secret(fp, parse->cats, &parse->cats_keys);
	
	parse->app_secrets_done = 1;
	parse->handshake_secrets_done = 1;
	parse->mid_secrets_done = 1;
	fclose(fp);
}
