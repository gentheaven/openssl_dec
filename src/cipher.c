#include <stdlib.h>

#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/kdf.h"
#include "openssl/sha.h"
#include "openssl/err.h"
#include "openssl/decoder.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"

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

void openssl_err_msg(void)
{
	unsigned long err_code;
	char err_buf[256];
	err_code = ERR_get_error();
	ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
	printf("OpenSSL error: %s\n", err_buf);
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

	//log
	printf("\"%s\" secret\n", label);
	print_hex(NULL, out, SHA384_DIGEST_LENGTH);
	print_hex("key: ", keys->key, 32);
	print_hex("IV: ", keys->iv, 12);
	printf("\n");
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

//openssl-3.5.4\demos\encrypt\rsa_encrypt.c
EVP_PKEY* rsa_get_key(const unsigned char* key, size_t key_len, int public)
{
	OSSL_DECODER_CTX* dctx = NULL;
	EVP_PKEY* pkey = NULL;
	int selection;
	const unsigned char* data;
	size_t data_len;

	data = key;
	data_len = key_len;
	if (public)
		selection = EVP_PKEY_PUBLIC_KEY;
	else
		selection = EVP_PKEY_KEYPAIR;
	dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, "RSA",
		selection, NULL, NULL);
	(void)OSSL_DECODER_from_data(dctx, &data, &data_len);
	OSSL_DECODER_CTX_free(dctx);
	return pkey;
}

/*
* in:
*	der = 1: DER format
*	der = 0: PEM format
*
*	public = 1, get pub key, cert
*	public = 0, get private key
* 
* call EVP_PKEY_free(pkey); after use it
*/
EVP_PKEY* rsa_get_key_fromfile(char* filename, int der, int public)
{
	EVP_PKEY* pkey = NULL;
	FILE* fp = NULL;
	if(der)
		fp = fopen(filename, "rb");
	else
		fp = fopen(filename, "r");
	if (!fp)
		return NULL;

	if (public) {
		//read from cert, PEM_read_PUBKEY
		X509* cert = NULL;
		if (der)
			cert = d2i_X509_fp(fp, NULL);
		else
			cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (cert) {
			EVP_PKEY* temp = X509_get0_pubkey(cert);
			if (temp)
				pkey = EVP_PKEY_dup(temp);
			X509_free(cert);
		}
	} else {
		//private key, standalone file
		if(der)
			pkey = d2i_PrivateKey_fp(fp, NULL);
		else
			pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	}

	fclose(fp);
	return pkey;
}

/* Set optional parameters for RSA PKCSV15 Padding */
static void rsa_set_optional_params(OSSL_PARAM* p)
{
	/* "pkcs1" is used by default if the padding mode is not set */
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
		OSSL_PKEY_RSA_PAD_MODE_PKCSV15, 0);
	/* "SHA1" is used if this is not set */
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
		"SHA256", 0);

	/*
	 * OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST and
	 * OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS can also be optionally added
	 * here if the MGF1 digest differs from the OAEP digest.
	 */
	*p = OSSL_PARAM_construct_end();
}

int rsa_decrypt_key(EVP_PKEY* pkey,
	const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len)
{
	int ret = 0;
	size_t buf_len = 0;
	unsigned char* buf = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	OSSL_PARAM params[5];

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (ctx == NULL) {
		fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed.\n");
		goto cleanup;
	}

	/* The parameters used for encryption must also be used for decryption */
	rsa_set_optional_params(params);
	/* If no optional parameters are required then NULL can be passed */
	if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
		fprintf(stderr, "EVP_PKEY_decrypt_init_ex() failed.\n");
		goto cleanup;
	}
	/* Calculate the size required to hold the decrypted data */
	if (EVP_PKEY_decrypt(ctx, NULL, &buf_len, in, in_len) <= 0) {
		fprintf(stderr, "EVP_PKEY_decrypt() failed.\n");
		goto cleanup;
	}
	buf = OPENSSL_zalloc(buf_len);
	if (buf == NULL) {
		fprintf(stderr, "Malloc failed.\n");
		goto cleanup;
	}
	if (EVP_PKEY_decrypt(ctx, buf, &buf_len, in, in_len) <= 0) {
		fprintf(stderr, "EVP_PKEY_decrypt() failed.\n");
		goto cleanup;
	}
	*out_len = buf_len;
	*out = buf;
	ret = 1;

cleanup:
	if (!ret)
		OPENSSL_free(buf);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

int ras_encrypt_key(EVP_PKEY* pkey,
	const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len)
{
	int ret = 0;
	size_t buf_len = 0;
	unsigned char* buf = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* pub_key = NULL;
	OSSL_PARAM params[5];

	/* Get public key */
	pub_key = pkey;
	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pub_key, NULL);
	if (ctx == NULL) {
		fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey() failed.\n");
		goto cleanup;
	}
	rsa_set_optional_params(params);
	/* If no optional parameters are required then NULL can be passed */
	if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
		fprintf(stderr, "EVP_PKEY_encrypt_init_ex() failed.\n");
		goto cleanup;
	}
	/* Calculate the size required to hold the encrypted data */
	if (EVP_PKEY_encrypt(ctx, NULL, &buf_len, in, in_len) <= 0) {
		fprintf(stderr, "EVP_PKEY_encrypt() failed.\n");
		goto cleanup;
	}
	buf = OPENSSL_zalloc(buf_len);
	if (buf == NULL) {
		fprintf(stderr, "Malloc failed.\n");
		goto cleanup;
	}
	if (EVP_PKEY_encrypt(ctx, buf, &buf_len, in, in_len) <= 0) {
		fprintf(stderr, "EVP_PKEY_encrypt() failed.\n");
		goto cleanup;
	}
	*out_len = buf_len;
	*out = buf;
	ret = 1;

cleanup:
	if (!ret)
		OPENSSL_free(buf);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}


/*
 * The length of the input data that can be encrypted is limited by the
 * RSA key length minus some additional bytes that depends on the padding mode.
 */
int ras_encrypt(const unsigned char* key, size_t key_len,
	const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len)
{
	int ret = 0;
	EVP_PKEY* pub_key = NULL;

	/* Get public key */
	pub_key = rsa_get_key(key, key_len, 1);
	if (pub_key == NULL) {
		fprintf(stderr, "Get public key failed.\n");
		return 0;
	}
	ret = ras_encrypt_key(pub_key, in, in_len, out, out_len);
	EVP_PKEY_free(pub_key);
	return ret;
}

int rsa_decrypt(const unsigned char* key, size_t key_len,
	const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len)
{
	int ret = 0;
	EVP_PKEY* priv_key = NULL;

	/* Get private key */
	priv_key = rsa_get_key(key, key_len, 0);
	if (priv_key == NULL) {
		return 0;
	}

	ret = rsa_decrypt_key(priv_key, in, in_len, out, out_len);
	EVP_PKEY_free(priv_key);
	return ret;
}

/*
* Signature Algorithm: sha256WithRSAEncryption
*/
int calc_hash256(char* data, int len, unsigned char* hash)
{
	EVP_MD_CTX* md_ctx = NULL;
	int ret = -1;
	unsigned int digest_length;

	md_ctx = digest_init(glib_ctx, "SHA256");
	/* Digest parts one and two of the soliloqy */
	if (EVP_DigestUpdate(md_ctx, data, len) != 1) {
		fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
		goto cleanup;
	}
	if (EVP_DigestFinal(md_ctx, hash, &digest_length) != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed.\n");
		goto cleanup;
	}

	//print_hex("SHA256 value: ", hash, digest_length);
	ret = 0;

cleanup:
	digest_exit(md_ctx);
	return ret;
}


//unsigned char hash[EVP_MAX_MD_SIZE]
int cert_tbs_hash(X509* x, unsigned char* hash)
{
	unsigned char* tbs = NULL;
	int tbs_len;

	tbs_len = i2d_re_X509_tbs(x, &tbs);
	calc_hash256(tbs, tbs_len, hash);
	if (tbs)
		OPENSSL_free(tbs);
	return 0;
}

/* RSA_PKCS1_PADDING
 * This function demonstrates RSA signing of a SHA-256 digest using the PSS
 * padding scheme. You must already have hashed the data you want to sign.
 * For a higher-level demonstration which does the hashing for you, see
 * rsa_pss_hash.c.
 *
 * For more information, see RFC 8017 section 9.1. The digest passed in
 * (test_digest above) corresponds to the 'mHash' value.
 * 
 * return:
 *	1 is OK
 *  0 is failed
 */
int rsa_sign(EVP_PKEY* pkey,
	unsigned char* in, int in_len, unsigned char** out, size_t* out_len)
{
	int ret = 0;
	EVP_PKEY_CTX* ctx = NULL;
	EVP_MD* md = NULL;

	size_t sig_len;
	unsigned char* sig = NULL;
	*out = NULL;

	/* Fetch hash algorithm we want to use. */
	md = EVP_MD_fetch(NULL, "SHA256", NULL);
	if (md == NULL) {
		fprintf(stderr, "Failed to fetch hash algorithm\n");
		goto end;
	}

	/* Create signing context. */
	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (ctx == NULL) {
		fprintf(stderr, "Failed to create signing context\n");
		goto end;
	}

	/* Initialize context for signing and set options. */
	if (EVP_PKEY_sign_init(ctx) == 0) {
		fprintf(stderr, "Failed to initialize signing context\n");
		goto end;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 0) {
		fprintf(stderr, "Failed to configure padding\n");
		goto end;
	}

	if (EVP_PKEY_CTX_set_signature_md(ctx, md) == 0) {
		fprintf(stderr, "Failed to configure digest type\n");
		goto end;
	}

	/* Determine length of signature. */
	if (EVP_PKEY_sign(ctx, NULL, &sig_len, in, in_len) == 0) {
		fprintf(stderr, "Failed to get signature length\n");
		goto end;
	}

	/* Allocate memory for signature. */
	sig = OPENSSL_malloc(sig_len);
	if (sig == NULL) {
		fprintf(stderr, "Failed to allocate memory for signature\n");
		goto end;
	}

	/* Generate signature. */
	if (EVP_PKEY_sign(ctx, sig, &sig_len, in, in_len) != 1) {
		openssl_err_msg();
		fprintf(stderr, "Failed to sign\n");
		goto end;
	}

	*out = sig;
	*out_len = sig_len;
	ret = 1;
end:
	EVP_PKEY_CTX_free(ctx);
	EVP_MD_free(md);
	return ret;
}

/*
 * This function demonstrates RSA signing of an arbitrary-length message.
 * Hashing is performed automatically. In this example, SHA-256 is used. If you
 * have already hashed your message and simply want to sign the hash directly,
 * see rsa_pss_direct.c.
 */
int rsa_sign_pss(EVP_PKEY* pkey,
	unsigned char* in, int in_len, unsigned char** out, size_t* out_len)
{
	int ret = 0;
	EVP_MD_CTX* mctx = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	size_t sig_len;
	unsigned char* sig = NULL;

	*out = NULL;
	/* Create MD context used for signing. */
	mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		fprintf(stderr, "Failed to create MD context\n");
		goto end;
	}

	if (EVP_DigestSignInit_ex(mctx, &pctx, "SHA256", NULL, NULL, pkey, NULL) <= 0) {
		fprintf(stderr, "Failed to initialize signing context\n");
		goto end;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
		|| EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
			RSA_PSS_SALTLEN_DIGEST) <= 0) {
		goto end;
	}

	/*
	 * Feed data to be signed into the algorithm. This may
	 * be called multiple times.
	 */
	if (EVP_DigestSignUpdate(mctx, in, in_len) == 0) {
		fprintf(stderr, "Failed to hash message into signing context\n");
		goto end;
	}

	/* Determine signature length. */
	if (EVP_DigestSignFinal(mctx, NULL, &sig_len) == 0) {
		fprintf(stderr, "Failed to get signature length\n");
		goto end;
	}

	/* Allocate memory for signature. */
	sig = OPENSSL_malloc(sig_len);
	if (sig == NULL) {
		fprintf(stderr, "Failed to allocate memory for signature\n");
		goto end;
	}

	/* Generate signature. */
	if (EVP_DigestSignFinal(mctx, sig, &sig_len) == 0) {
		fprintf(stderr, "Failed to sign\n");
		goto end;
	}

	*out = sig;
	*out_len = sig_len;
	ret = 1;
end:
	EVP_MD_CTX_free(mctx);
	if (ret == 0)
		OPENSSL_free(sig);

	return ret;
}

/*
* RSA_PKCS1_PADDING
return:
*	1 is OK
*	0 is failed
*/
int rsa_verify_sign(EVP_PKEY* pkey, unsigned char* hash, int hash_len, unsigned char* sig, size_t sig_len)
{
	int ret = 0;
	EVP_PKEY_CTX* ctx = NULL;
	EVP_MD* md = NULL;

	/* Fetch hash algorithm we want to use. */
	md = EVP_MD_fetch(NULL, "SHA256", NULL);
	if (md == NULL) {
		fprintf(stderr, "Failed to fetch hash algorithm\n");
		goto end;
	}

	/* Create verification context. */
	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (ctx == NULL) {
		fprintf(stderr, "Failed to create verification context\n");
		goto end;
	}

	/* Initialize context for verification and set options. */
	if (EVP_PKEY_verify_init(ctx) == 0) {
		fprintf(stderr, "Failed to initialize verification context\n");
		goto end;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 0) {
		fprintf(stderr, "Failed to configure padding\n");
		goto end;
	}

	if (EVP_PKEY_CTX_set_signature_md(ctx, md) == 0) {
		fprintf(stderr, "Failed to configure digest type\n");
		goto end;
	}

	/* Verify signature. */
	if (EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len) == 0) {
		openssl_err_msg();
		fprintf(stderr, "Failed to verify signature; "
			"signature may be invalid\n");
		goto end;
	}

	ret = 1;
end:
	EVP_PKEY_CTX_free(ctx);
	EVP_MD_free(md);
	return ret;
}

/*
 * This function demonstrates verification of an RSA signature over an
 * arbitrary-length message using the PSS signature scheme. Hashing is performed
 * automatically.
 */
int rsa_verify_sign_pss(EVP_PKEY* pkey, unsigned char* hash, int hash_len, unsigned char* sig, size_t sig_len)
{
	int ret = 0;
	EVP_MD_CTX* mctx = NULL;
	EVP_PKEY_CTX* pctx = NULL;

	/* Create MD context used for verification. */
	mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		fprintf(stderr, "Failed to create MD context\n");
		goto end;
	}

	if (EVP_DigestVerifyInit_ex(mctx, &pctx, "SHA256", NULL, NULL, pkey, NULL) <= 0) {
		fprintf(stderr, "Failed to initialize signing context\n");
		goto end;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
		|| EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
		goto end;
	}

	/*
	 * Feed data to be signed into the algorithm. This may
	 * be called multiple times.
	 */
	if (EVP_DigestVerifyUpdate(mctx, hash, hash_len) == 0) {
		fprintf(stderr, "Failed to hash message into signing context\n");
		goto end;
	}

	/* Verify signature. */
	if (EVP_DigestVerifyFinal(mctx, sig, sig_len) == 0) {
		openssl_err_msg();
		goto end;
	}

	ret = 1;
end:
	EVP_MD_CTX_free(mctx);
	return ret;
}


//X509_print -> X509V3_extensions_print -> X509V3_EXT_print
void print_cert_ext(X509* x, int nid)
{
	char common_name[256];
	const STACK_OF(X509_EXTENSION)* exts = X509_get0_extensions(x);

	//get extension
	int index;
	index = X509v3_get_ext_by_NID(exts, nid, -1);
	if (index == -1)
		return;
	X509_EXTENSION* ext;
	ext = X509_get_ext(x, index);

	//get extension name
	ASN1_OBJECT* obj;
	obj = X509_EXTENSION_get_object(ext);
	if (obj) {
		i2t_ASN1_OBJECT(common_name, sizeof(common_name), obj);
		printf("%s\n", common_name);
	}

	//X509V3_EXT_print
	void* ext_str = NULL;
	char* value = NULL;
	ASN1_OCTET_STRING* extoct;
	const unsigned char* p;
	int extlen;
	const X509V3_EXT_METHOD* method;
	STACK_OF(CONF_VALUE)* nval = NULL;

	extoct = X509_EXTENSION_get_data(ext);
	p = ASN1_STRING_get0_data(extoct);
	extlen = ASN1_STRING_length(extoct);
	//method = X509V3_EXT_get(ext);
	method = X509V3_EXT_get_nid(nid);
	ext_str = ASN1_item_d2i(NULL, &p, extlen, ASN1_ITEM_ptr(method->it));
	if (!ext_str)
		goto clean;

	if (method->i2v)
		nval = method->i2v(method, ext_str, NULL);
	else if (method->i2s)
		value = method->i2s(method, ext_str);
	if (value) {
		printf("    %s\n", value);
		goto clean;
	}
	if (!nval)
		goto clean;

	//X509V3_EXT_val_prn(NULL, nval, 8, method->ext_flags & X509V3_EXT_MULTILINE);
	int i, num;
	num = sk_CONF_VALUE_num(nval);
	CONF_VALUE* cur;
	printf("    ");
	for (i = 0; i < num; i++) {
		cur = sk_CONF_VALUE_value(nval, i);
		if (!cur->name)
			printf("%s, ", cur->value);
		else if (!cur->value)
			printf("%s, ", cur->name);
		else
			printf("%s:%s ", cur->name, cur->value);
	}
	printf("\n");

clean:
	sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
	OPENSSL_free(value);
	if (method->it)
		ASN1_item_free(ext_str, ASN1_ITEM_ptr(method->it));
	else
		method->ext_free(ext_str);
}

/*
RFC8446 4.4.3. Certificate Verify
The signature is a
   digital signature using that algorithm.  The content that is covered
   under the signature is the hash output as described in Section 4.4.1,
   namely:

	  Transcript-Hash(Handshake Context, Certificate)

   The digital signature is then computed over the concatenation of:
   -  A string that consists of octet 32 (0x20) repeated 64 times
   -  The context string
   -  A single 0 byte which serves as the separator
   -  The content to be signed
*/

/*
* openssl-3.5.4\ssl\statem\statem_lib.c. get_cert_verify_tbs_data
unsigned char tls13tbs[TLS13_TBS_PREAMBLE_SIZE + EVP_MAX_MD_SIZE];
get_cert_verify_tbs_data(tls13tbs, TLS_ST_SW_CERT_VRFY, hash, hash_len);

return: tls13tbs[ret]
*/
int get_cert_verify_tbs_data(unsigned char* tls13tbs, int state,
	unsigned char* hdata, size_t hdatalen) //in: hdata[hdatalen]
{
	/* ASCII: "TLS 1.3, server CertificateVerify", in hex for EBCDIC compatibility */
	static const char servercontext[] = "\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72"
		"\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79";
	/* ASCII: "TLS 1.3, client CertificateVerify", in hex for EBCDIC compatibility */
	static const char clientcontext[] = "\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x63\x6c\x69"
		"\x65\x6e\x74\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79";

	int hashlen = (int)hdatalen;

	/* Set the first 64 bytes of to-be-signed data to octet 32 */
	memset(tls13tbs, 32, TLS13_TBS_START_SIZE);
	/* This copies the 33 bytes of context plus the 0 separator byte */
	if (state == TLS_ST_CR_CERT_VRFY || state == TLS_ST_SW_CERT_VRFY)
		strcpy((char*)tls13tbs + TLS13_TBS_START_SIZE, servercontext);
	else
		strcpy((char*)tls13tbs + TLS13_TBS_START_SIZE, clientcontext);

	memcpy(tls13tbs + TLS13_TBS_PREAMBLE_SIZE, hdata, hdatalen);
	hashlen = TLS13_TBS_PREAMBLE_SIZE + hashlen;
	return hashlen;
}

