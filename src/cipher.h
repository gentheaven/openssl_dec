#ifndef __CIPHER_H
#define __CIPHER_H

#include <inttypes.h>

#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/sha.h"

#define X25519_KEYLEN 32

extern OSSL_LIB_CTX* glib_ctx;

extern OSSL_LIB_CTX* openssl_init(void);
extern void openssl_exit(OSSL_LIB_CTX* ctx);

extern void openssl_err_msg(void);

struct final_secret {
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];

	/* RFC8446 5.3. Per-Record Nonce
	A 64-bit sequence number is maintained separately for reading and writing records.
	The appropriate sequence number is incremented by one after reading or writing each record.
	Each sequence number is set to zero at the beginning of a connection and whenever the key is changed;
	the first record transmitted under a particular traffic key MUST use sequence number 0.

	* 1. The 64-bit record sequence number is encoded in network byte order and padded to the left with zeros to iv_length.
	* 2. The padded sequence number is XORed with either the static client_write_iv or server_write_iv (depending on the role).
	* The resulting quantity (of length iv_length) is used as the per-record nonce.
	*/
	uint64_t seq;
};


//===============================================================================
//ECDHE
/*
 * in: priv_key[32] or NULL
 * out: pubk_data[32]
 * e.g.
 unsigned char pubk_data[32]; //generated pubk to send to other peer
 EVP_PKEY* key = create_x25519_key(NULL, pubk_data);
 */
extern EVP_PKEY* create_x25519_key(unsigned char* priv_key, unsigned char* pubk_data);

/*
* in:
*	key: local key
*	peer_pubkey[32]: peer public key
* out:
*	secret[32]
*
* return:
*	0: success
*	1: failed

* e.g.
	unsigned char secret[32]; //pre-master secret
	cal_x25519_secret(local_key, peer_pubkey, secret);
*/
extern int cal_x25519_secret(EVP_PKEY* key, unsigned char* peer_pubkey, unsigned char* secret);

//===============================================================================

//HKDF
/* same as function tls13_generate_secret
* ssl\tls13_enc.c: line 164
* 
* rfc5869
* PRK = HMAC-Hash(salt, IKM)
* PRK: PseudoRandom Key (of HashLen octets)
* IKM: Input Keying Material
* salt: a non-secret random value)
	if not provided, it is set to a string of HashLen zeros.
* hash_name: SSL_TXT_SHA256, SSL_TXT_SHA384
* 
 * Given the previous secret |salt| of length |salt_len|,
 and a new input secret |ikm| of length |ikm_len|,
 generate a new secret and store it in the location
 * pointed to by |outsecret|.
 Returns:
	 EXIT_SUCCESS(0)  on success
	 EXIT_FAILURE(1)  on failure
 * secret = hash_function(salt, ikm);
 * in:
 *	salt[salt_len]
 *	ikm[ikm_len]
 * out:
 *	secret[out_len]
 */
extern int tls13_hkdf_extract(char* hash_name,
	const unsigned char* salt, size_t salt_len,
	const unsigned char* ikm, size_t ikm_len,
	unsigned char* secret, size_t secret_len);

//Early Secret = HKDF-Extract(salt, IKM) = HKDF-Extract(0, 0) = const value
#define tls_early_serect(hash_name, outsecret, out_len) \
	tls13_hkdf_extract(hash_name, NULL, 0, NULL, 0, outsecret, out_len)
#define tls_early_sha384(outsecret) tls_early_serect("SHA384", outsecret, SHA384_DIGEST_LENGTH)
#define tls_early_sha256(outsecret) tls_early_serect("SHA256", outsecret, SHA256_DIGEST_LENGTH)


//Handshake Secret = HKDF-Extract(salt, IKM) = HKDF-Extract(Early Secret, (EC)DHE)
//HKDF-Extract(Early Secret, Pre-Master Secret)
#define tls_handshake_serect(hash_name, early, pms, outsecret, out_len) \
	tls13_hkdf_extract(hash_name, early, out_len, pms, X25519_KEYLEN, outsecret, out_len)

#define tls_handshake_sha384(early, pms, outsecret) \
	tls_handshake_serect("SHA384", early, pms, outsecret, SHA384_DIGEST_LENGTH)
#define tls_handshake_sha256(early, pms, outsecret) \
	tls_handshake_serect("SHA256", early, pms, outsecret, SHA256_DIGEST_LENGTH)

//Master Secret = HKDF-Extract(salt, IKM) = HKDF-Extract(Handshake Secret, 0)
#define tls_master_serect(hash_name, Handshake, outsecret, out_len) \
	tls13_hkdf_extract(hash_name, Handshake, out_len, NULL, 0, outsecret, out_len)

#define tls_master_sha384(Handshake, outsecret) \
	tls_master_serect("SHA384", Handshake, outsecret, SHA384_DIGEST_LENGTH)
#define tls_master_sha256(Handshake, outsecret) \
	tls_master_serect("SHA256", Handshake, outsecret, SHA256_DIGEST_LENGTH)


/*
 * Given a |secret|; a |label| of length |labellen|; and |data| of length
 * |datalen| (e.g. typically a hash of the handshake messages), derive a new
 * secret |outlen| bytes long and store it in the location pointed to be |out|.
 * The |data| value may be zero length. 
 *
 Derive-Secret(Secret, Label, Messages) =
	HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
	out = tls13_hkdf_expand(secret, label, hash, hash_len);
return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
 */
extern int tls13_hkdf_expand(OSSL_LIB_CTX* libctx, char* hash_name,
	const unsigned char* secret,
	const unsigned char* label,
	const unsigned char* data, size_t datalen,
	unsigned char* out, size_t outlen);

/*
 * Given a |secret| generate a |key| of length |keylen| bytes.
 return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
 */
extern int tls13_derive_key(OSSL_LIB_CTX* libctx, char* hash_name,
	const unsigned char* secret,
	unsigned char* key, size_t keylen);

/*
 * Given a |secret| generate an |iv| of length |ivlen = 12| bytes.
 * return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
 */
extern int tls13_derive_iv(OSSL_LIB_CTX* libctx, char* hash_name,
	const unsigned char* secret, unsigned char* iv);

/*
client_handshake_traffic_secret =
	Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello);
server_handshake_traffic_secret =
	Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello);
*/

//sha384
#define derive_secret(secret, hash, label, out) \
	tls13_hkdf_expand(NULL, "SHA384", secret, label, hash, SHA384_DIGEST_LENGTH, out, SHA384_DIGEST_LENGTH)

//verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, ClientHello ... (beore)server finished));
#define hmac_verify_data(finishedkey, hash, out, outlen) \
	EVP_Q_mac(NULL, "HMAC", NULL, "SHA384", NULL, \
		finishedkey, SHA384_DIGEST_LENGTH, hash, SHA384_DIGEST_LENGTH, out, SHA384_DIGEST_LENGTH, &outlen);

//AES_256_GCM: 32B
#define derive_key(secret, key) tls13_derive_key(glib_ctx, "SHA384", secret, key, 32)
#define derive_iv(secret, iv)    tls13_derive_iv(glib_ctx, "SHA384", secret, iv);

/*
  server_handshake_traffic_secret = 
    Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello);

  out = Derive-Secret(secret, label, hash);
  equal to:
  calc_secrets_ext(secret, label, hash, out);

return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
*/
extern int calc_secrets_ext(
	unsigned char* secret, const unsigned char* label, unsigned char* hash, //in
	unsigned char* out, struct final_secret* keys); //out

//===============================================================================
//Digest, MD: Message digest

/*
* SSL_TXT_SHA256, SSL_TXT_SHA384
	ctx = digest_init(gctx, digest_name); //"SHA384", "SH256", "SHA3-384", "SHA3-512"
	digest_update(ctx, buf, buf_len);
	digest_update(ctx, buf1, buf1_len);
	...
	EVP_DigestFinal(ctx, out, &out_len);
	digest_exit(ctx);

	EVP_MD_CTX_reset(ctx); //Resets the digest context ctx. This can be used to reuse an already existing context.
*/
extern EVP_MD_CTX* digest_init(OSSL_LIB_CTX* lib_ctx, const char* digest_name);
#define digest_exit EVP_MD_CTX_free


struct tls_cipher {
	int type; //AES_256_GCM, etc.

	OSSL_LIB_CTX* lib_ctx;
	EVP_CIPHER_CTX* ctx;
	EVP_CIPHER* cipher;
	
	//in
	unsigned char key[EVP_MAX_KEY_LENGTH];
	size_t key_len;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	size_t iv_len;
	//TLS 1.3 AAD = type 1B || version 2B || length 2B
	unsigned char aad[32]; //max 32B
	size_t aad_len;
};

/*
tls_cipher_init();
tls_cipher_set();

aes_gcm_enc();
aes_gcm_dec();

tls_cipher_exit();

*/
extern struct tls_cipher* tls_cipher_init(int type, OSSL_LIB_CTX* libctx);

extern void tls_cipher_exit(struct tls_cipher* ptls_cipher);

extern void tls_cipher_set(struct tls_cipher* enc,
	unsigned char* key, size_t key_len,
	unsigned char* iv, size_t iv_len,
	unsigned char* aad, size_t aad_len);

//suppose type = AES_256_GCM

/*
return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
*/
extern int aes_gcm_enc(struct tls_cipher* ptls_cipher,
	unsigned char* text, size_t textlen, //in
	unsigned char* tag, unsigned char* out, int* outlen); //out: tag[16], out[outlen]

/*
return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
*/
extern int aes_gcm_dec(struct tls_cipher* ptls_cipher, 
	unsigned char* tag, //in
	unsigned char* cipher, int cipherlen, //in
	unsigned char* out, int* outlen); //out: out[outlen]

//AES_256_GCM: 32B
#define aes_gcm_set(enc, key, iv, aad) \
	tls_cipher_set(enc, key, 32, iv, 12, aad, SSL3_RT_HEADER_LENGTH)

//RSA
 
/*
* in:
*der = 1 : DER format
* der = 0 : PEM format
*
*public = 1, get pub key, cert
* public = 0, get private key
*
*call EVP_PKEY_free(pkey); after use it
*/
extern EVP_PKEY* rsa_get_key_fromfile(char* filename, int der, int public);

//key: private key, caller free buffer 'out' by OPENSSL_free(out)
extern int ras_encrypt(const unsigned char* key, size_t key_len,
	const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len);

//key: public key, caller free buffer 'out' by OPENSSL_free(out)
extern int rsa_decrypt(const unsigned char* key, size_t key_len,
	const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len);

extern int rsa_decrypt_key(EVP_PKEY* pkey,
	const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len);

extern int ras_encrypt_key(EVP_PKEY* pkey,
	const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len);

extern void print_cert_ext(X509* x, int nid);

/* RSA_PKCS1_PADDING
return:
*	1 is OK
*	0 is failed
*/
extern int rsa_sign(EVP_PKEY* pkey,
	unsigned char* in, int in_len, unsigned char** out, size_t* out_len);

extern int rsa_sign_pss(EVP_PKEY* pkey,
	unsigned char* in, int in_len, unsigned char** out, size_t* out_len);

// TBS: To Be Signed
//unsigned char hash[EVP_MAX_MD_SIZE]
extern int cert_tbs_hash(X509* x, unsigned char* hash);

/*
* RSA_PKCS1_PADDING
return:
*	1 is OK
*	0 is failed
*/
extern int rsa_verify_sign(EVP_PKEY* pkey, unsigned char* hash, int hash_len, unsigned char* sig, size_t sig_len);

extern int rsa_verify_sign_pss(EVP_PKEY* pkey, unsigned char* hash, int hash_len, unsigned char* sig, size_t sig_len);

/*
 * Size of the to-be-signed TLS13 data, without the hash size itself:
 * 64 bytes of value 32, 33 context bytes, 1 byte separator
 */
#define TLS13_TBS_START_SIZE            64
#define TLS13_TBS_PREAMBLE_SIZE         (TLS13_TBS_START_SIZE + 33 + 1)

/*
* openssl-3.5.4\ssl\statem\statem_lib.c. get_cert_verify_tbs_data
unsigned char tls13tbs[TLS13_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
get_cert_verify_tbs_data(tls13tbs, TLS_ST_SW_CERT_VRFY, hash, hash_len);

return: real length of tls13tbs
	tls13tbs[ret]
*/
extern int get_cert_verify_tbs_data(unsigned char* tls13tbs, int state,
	unsigned char* hdata, size_t hdatalen); //in: hdata[hdatalen]

/*
* Signature Algorithm: sha256
*/
extern int calc_hash256(char* data, int len, unsigned char* hash);

#endif