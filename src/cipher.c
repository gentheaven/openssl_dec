#include <stdlib.h>

#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/kdf.h"
#include "openssl/sha.h"
#include "openssl/err.h"


#include "parse.h"
#include "cipher.h"

/* ASCII: "tls13 ", in hex for EBCDIC compatibility */
static const unsigned char label_prefix[] = "\x74\x6C\x73\x31\x33\x20";

OSSL_LIB_CTX* openssl_init(void)
{
	return OSSL_LIB_CTX_new();
}

void openssl_exit(OSSL_LIB_CTX* ctx)
{
	if(ctx)
		OSSL_LIB_CTX_free(ctx);
}

/*
 * in: priv_key[32] or NULL
 * out: pubk_data[32]
 * e.g.
 unsigned char pubk_data[32]; //generated pubk to send to other peer
 EVP_PKEY* key = create_x25519_key(NULL, pubk_data);
 */
EVP_PKEY* create_x25519_key(unsigned char* priv_key,unsigned char* pubk_data)
{
	EVP_PKEY* key = NULL;
	if (priv_key) {
		key = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", NULL, priv_key,32);
	} else {
		key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
	}
	if (!key)
		return NULL;

	size_t len;
	int ret = EVP_PKEY_get_octet_string_param(key,
			OSSL_PKEY_PARAM_PUB_KEY,
			pubk_data,
			32,
			&len);
	if (!ret) {
		//error
		EVP_PKEY_free(key);
		return NULL;
	}

	return key;
}

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
int cal_x25519_secret(EVP_PKEY* key, unsigned char* peer_pubkey, unsigned char* secret)
{
	int ret = 0;
	EVP_PKEY* remote_peer_pubk = NULL;
	EVP_PKEY_CTX* ctx = NULL;

	/* Load public key for remote peer. */
	remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL,
			peer_pubkey, 32);
	if (remote_peer_pubk == NULL) {
		fprintf(stderr, "EVP_PKEY_new_raw_public_key_ex() failed\n");
		goto end;
	}

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	if (!ctx) {
		fprintf(stderr, "evp_pkey_ctx_new_from_pkey() failed\n");
		goto end;
	}

	ret = EVP_PKEY_derive_init(ctx);
	if (ret == 0) {
		fprintf(stderr, "EVP_PKEY_derive_init() failed\n");
		goto end;
	}

	/* Configure each peer with the other peer's public key. */
	ret = EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk);
	if (ret == 0) {
		fprintf(stderr, "EVP_PKEY_derive_set_peer() failed\n");
		goto end;
	}

	/* Determine the secret length. */
	size_t secret_len;
	if (EVP_PKEY_derive(ctx, NULL, &secret_len) == 0) {
		fprintf(stderr, "EVP_PKEY_derive() failed\n");
		goto end;
	}

	/*
	* We are using X25519, so the secret generated will always be 32 bytes.
	* However for exposition, the code below demonstrates a generic
	* implementation for arbitrary lengths.
	*/
	if (secret_len != 32) { /* unreachable */
		fprintf(stderr, "Secret is always 32 bytes for X25519\n");
		goto end;
	}

	/* Derive the shared secret */
	ret = EVP_PKEY_derive(ctx, secret, &secret_len);
	if (ret == 0) {
		fprintf(stderr, "EVP_PKEY_derive() failed\n");
		goto end;
	}
	return 0;

end:
	//error
	if(ctx)
		EVP_PKEY_CTX_free(ctx);
	if(remote_peer_pubk)
		EVP_PKEY_free(remote_peer_pubk);

	return 1;
}

//HKPF
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
int tls13_hkdf_extract(char* hash_name,
	const unsigned char* salt, size_t salt_len,
	const unsigned char* ikm, size_t ikm_len,
	unsigned char* secret, size_t secret_len)
{
	/* ASCII: "derived", in hex for EBCDIC compatibility */
	static const char derived_secret_label[] = "\x64\x65\x72\x69\x76\x65\x64";

	int ret = EXIT_FAILURE;
	EVP_KDF* kdf = NULL;
	EVP_KDF_CTX* kctx = NULL;

	/* Fetch the key derivation function implementation */
	kdf = EVP_KDF_fetch(glib_ctx, OSSL_KDF_NAME_TLS1_3_KDF, NULL);
	
	if (kdf == NULL) {
		fprintf(stderr, "EVP_KDF_fetch() returned NULL\n");
		goto end;
	}

	/* Create a context for the key derivation operation */
	kctx = EVP_KDF_CTX_new(kdf);
	if (kctx == NULL) {
		fprintf(stderr, "EVP_KDF_CTX_new() returned NULL\n");
		goto end;
	}

	OSSL_PARAM params[7];
	OSSL_PARAM* p = params;
	int mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;

	*p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
		(char*)hash_name, 0);

	if (ikm)
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
			(unsigned char*)ikm, ikm_len);

	if (salt)
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
			(unsigned char*)salt, salt_len);

	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX,
		(unsigned char*)label_prefix,
		sizeof(label_prefix) - 1);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL,
		(unsigned char*)derived_secret_label,
		sizeof(derived_secret_label) - 1);
	*p++ = OSSL_PARAM_construct_end();

	/* Derive the key */
	ret = EVP_KDF_derive(kctx, secret, secret_len, params);
	if (ret <= 0) {
		fprintf(stderr, "EVP_KDF_derive() failed\n");
		goto end;
	}

	ret = EXIT_SUCCESS;
end:
	if(kctx)
		EVP_KDF_CTX_free(kctx);
	if(kdf)
		EVP_KDF_free(kdf);
	return ret;
}

/*
 * Given a |secret|; a |label| of length |labellen|; and |data| of length
 * |datalen| (e.g. typically a hash of the handshake messages), derive a new
 * secret |outlen| bytes long and store it in the location pointed to be |out|.
 * The |data| value may be zero length. 
 Derive-Secret(Secret, Label, Messages) =
	HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
	out = tls13_hkdf_expand(secret, label, hash, hash_len);

	hash_name = hash_function name for secret: secret = hash_function(salt, ikm);
return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
 */
int tls13_hkdf_expand(OSSL_LIB_CTX* libctx, char* hash_name,
	const unsigned char* secret,
	const unsigned char* label,
	const unsigned char* data, size_t datalen,
	unsigned char* out, size_t outlen)
{
	EVP_KDF* kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_TLS1_3_KDF, NULL);
	EVP_KDF_CTX* kctx;
	OSSL_PARAM params[7], * p = params;
	int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;

	kctx = EVP_KDF_CTX_new(kdf);
	EVP_KDF_free(kdf);
	if (kctx == NULL)
		return 0;

	EVP_MD* md = NULL;
	md = EVP_MD_fetch(libctx, hash_name, NULL);
	size_t hashlen = (size_t)EVP_MD_get_size(md);
	EVP_MD_free(md);

	size_t labellen = strlen(label);

	*p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
		hash_name, 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
		(unsigned char*)secret, hashlen);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX,
		(unsigned char*)label_prefix,
		sizeof(label_prefix) - 1);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL,
		(unsigned char*)label, labellen);
	if (data != NULL)
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DATA,
			(unsigned char*)data,
			datalen);
	*p++ = OSSL_PARAM_construct_end();

	int ret;
	ret = EVP_KDF_derive(kctx, out, outlen, params);
	EVP_KDF_CTX_free(kctx);

	if (ret <= 0) {
		printf("tls13_hkdf_expand error \n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/*
 * Given a |secret| generate a |key| of length |keylen| bytes.
return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
 */
int tls13_derive_key(OSSL_LIB_CTX* libctx, char* hash_name,
	const unsigned char* secret,
	unsigned char* key, size_t keylen)
{
	/* ASCII: "key", in hex for EBCDIC compatibility */
	static const unsigned char keylabel[] = "\x6B\x65\x79";

	return tls13_hkdf_expand(libctx, hash_name, secret, keylabel,
		NULL, 0, key, keylen);
}

/*
 * Given a |secret| generate an |iv| of length |ivlen = 12| bytes.
 * return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
 */
int tls13_derive_iv(OSSL_LIB_CTX* libctx, char* hash_name,
	const unsigned char* secret, unsigned char* iv)
{
	/* ASCII: "iv", in hex for EBCDIC compatibility */
	static const unsigned char ivlabel[] = "\x69\x76";
	return tls13_hkdf_expand(libctx, hash_name, secret, ivlabel,
		NULL, 0, iv, 12);
}

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
int calc_secrets_ext(
	unsigned char* secret, const unsigned char* label, unsigned char* hash, //in
	unsigned char* out, struct final_secret* keys) //out
{
	derive_secret(secret, hash, label, out);
	derive_key(out, keys->key);
	derive_iv(out, keys->iv);
	return EXIT_SUCCESS;
}


EVP_MD_CTX* digest_init(OSSL_LIB_CTX* lib_ctx, const char* digest_name)
{
	EVP_MD* message_digest = NULL;
	message_digest = EVP_MD_fetch(lib_ctx, digest_name, NULL);

	EVP_MD_CTX* digest_context = NULL;
	digest_context = EVP_MD_CTX_new();
	EVP_DigestInit(digest_context, message_digest);
	EVP_MD_free(message_digest);

	return digest_context;
}

//suppose type = AES_256_GCM
struct tls_cipher* tls_cipher_init(int type, OSSL_LIB_CTX* libctx)
{
	struct tls_cipher* ret;
	ret = malloc(sizeof(struct tls_cipher));
	memset(ret, 0, sizeof(struct tls_cipher));

	ret->type = type;
	ret->lib_ctx = libctx;
	ret->ctx = EVP_CIPHER_CTX_new();
	ret->cipher = EVP_CIPHER_fetch(libctx, "AES-256-GCM", NULL);

	return ret;
}

void tls_cipher_set(struct tls_cipher* enc,
	unsigned char* key, size_t key_len,
	unsigned char* iv, size_t iv_len,
	unsigned char* aad, size_t aad_len)
{
	memcpy(enc->key, key, key_len);
	memcpy(enc->iv, iv, iv_len);
	memcpy(enc->aad, aad, aad_len);
	enc->key_len = key_len;
	enc->iv_len = iv_len;
	enc->aad_len = aad_len;
}


void tls_cipher_exit(struct tls_cipher* ptls_cipher)
{
	EVP_CIPHER_free(ptls_cipher->cipher);
	EVP_CIPHER_CTX_free(ptls_cipher->ctx);
	free(ptls_cipher);
}

//suppose type = AES_256_GCM
/*
return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
*/
int aes_gcm_enc(struct tls_cipher* ptls_cipher,
	unsigned char* text, size_t textlen, //in
	unsigned char* tag, unsigned char* out, int* outlen) //out: tag[16], out[outlen]
{
	OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
	/* Set IV length if default 96 bits is not appropriate */
	params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ptls_cipher->iv_len);

	/*
		* Initialise an encrypt operation with the cipher/mode, key, IV and
		* IV length parameter.
		*/
	if (!EVP_EncryptInit_ex2(ptls_cipher->ctx, ptls_cipher->cipher, 
		ptls_cipher->key, ptls_cipher->iv, params))
		goto err;

	/* Zero or more calls to specify any AAD */
	if (!EVP_EncryptUpdate(ptls_cipher->ctx, NULL, outlen, 
		ptls_cipher->aad, (int)ptls_cipher->aad_len))
		goto err;

	/* Encrypt plaintext */
	if (!EVP_EncryptUpdate(ptls_cipher->ctx, out, outlen,
		(const unsigned char*)text, (int)textlen))
		goto err;

	/* Finalise: note get no output for GCM */
	int tmplen;
	if (!EVP_EncryptFinal_ex(ptls_cipher->ctx, out, &tmplen))
		goto err;

	/* Get tag */
	if (tag) {
		params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
			tag, EVP_MAX_AEAD_TAG_LENGTH);

		if (!EVP_CIPHER_CTX_get_params(ptls_cipher->ctx, params))
			goto err;
	}

	return EXIT_SUCCESS;
err:
	return EXIT_FAILURE;
}

/*
return:
	EXIT_SUCCESS(0)  on success
	EXIT_FAILURE(1)  on failure
*/
int aes_gcm_dec(struct tls_cipher* ptls_cipher,
	unsigned char* tag, //in
	unsigned char* cipher, int cipherlen, //in
	unsigned char* out, int* outlen) //out: out[outlen]
{
	int rv = 1;
	OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
	/* Set IV length if default 96 bits is not appropriate */
	params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ptls_cipher->iv_len);

	/*
		* Initialise an encrypt operation with the cipher/mode, key, IV and
		* IV length parameter.
		*/
	if (!EVP_DecryptInit_ex2(ptls_cipher->ctx, ptls_cipher->cipher, 
		ptls_cipher->key, ptls_cipher->iv, params))
		goto err;

	/* Zero or more calls to specify any AAD */
	if (!EVP_DecryptUpdate(ptls_cipher->ctx, NULL, outlen, 
		ptls_cipher->aad, (int)ptls_cipher->aad_len))
		goto err;

	/* Decrypt plaintext */
	if (!EVP_DecryptUpdate(ptls_cipher->ctx, out, outlen, cipher, cipherlen))
		goto err;

	if (tag) {
		/* Set expected tag value. */
		params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
			(void*)tag, EVP_MAX_AEAD_TAG_LENGTH);
		if (!EVP_CIPHER_CTX_set_params(ptls_cipher->ctx, params))
			goto err;
	}

	/* Finalise: note get no output for GCM */
	int tmplen;
	rv = EVP_DecryptFinal_ex(ptls_cipher->ctx, out, &tmplen);
	if (rv > 0 || !tag) //tag == NULL, not care ret
		return EXIT_SUCCESS;

err:
	return EXIT_FAILURE;
}