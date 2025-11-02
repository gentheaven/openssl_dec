
#include "pcap.h"
#include "libnet.h"
#include "openssl/ssl3.h"

//copied from openssl-3.5.4-src\openssl-3.5.4\ssl\t1_trce.c

/* Version number */

static const ssl_trace_tbl ssl_version_tbl[] = {
    {SSL3_VERSION, "SSL 3.0"},
    {TLS1_VERSION, "TLS 1.0"},
    {TLS1_1_VERSION, "TLS 1.1"},
    {TLS1_2_VERSION, "TLS 1.2"},
    {TLS1_3_VERSION, "TLS 1.3"},
    {DTLS1_VERSION, "DTLS 1.0"},
    {DTLS1_2_VERSION, "DTLS 1.2"},
    {DTLS1_BAD_VER, "DTLS 1.0 (bad)"}
};

const ssl_trace_tbl ssl_content_tbl[] = {
    {SSL3_RT_CHANGE_CIPHER_SPEC, "ChangeCipherSpec"},
    {SSL3_RT_ALERT, "Alert"},
    {SSL3_RT_HANDSHAKE, "Handshake"},
    {SSL3_RT_APPLICATION_DATA, "ApplicationData"},
};

/* Handshake types, sorted by ascending id  */
const ssl_trace_tbl ssl_handshake_tbl[] = {
    {SSL3_MT_HELLO_REQUEST, "HelloRequest"},
    {SSL3_MT_CLIENT_HELLO, "ClientHello"},
    {SSL3_MT_SERVER_HELLO, "ServerHello"},
    {DTLS1_MT_HELLO_VERIFY_REQUEST, "HelloVerifyRequest"},
    {SSL3_MT_NEWSESSION_TICKET, "NewSessionTicket"},
    {SSL3_MT_END_OF_EARLY_DATA, "EndOfEarlyData"},
    {SSL3_MT_ENCRYPTED_EXTENSIONS, "EncryptedExtensions"},
    {SSL3_MT_CERTIFICATE, "Certificate"},
    {SSL3_MT_SERVER_KEY_EXCHANGE, "ServerKeyExchange"},
    {SSL3_MT_CERTIFICATE_REQUEST, "CertificateRequest"},
    {SSL3_MT_SERVER_DONE, "ServerHelloDone"},
    {SSL3_MT_CERTIFICATE_VERIFY, "CertificateVerify"},
    {SSL3_MT_CLIENT_KEY_EXCHANGE, "ClientKeyExchange"},
    {SSL3_MT_FINISHED, "Finished"},
    {SSL3_MT_CERTIFICATE_URL, "CertificateUrl"},
    {SSL3_MT_CERTIFICATE_STATUS, "CertificateStatus"},
    {SSL3_MT_SUPPLEMENTAL_DATA, "SupplementalData"},
    {SSL3_MT_KEY_UPDATE, "KeyUpdate"},
    {SSL3_MT_COMPRESSED_CERTIFICATE, "CompressedCertificate"},
# ifndef OPENSSL_NO_NEXTPROTONEG
    {SSL3_MT_NEXT_PROTO, "NextProto"},
# endif
    {SSL3_MT_MESSAGE_HASH, "MessageHash"}
};

/* Cipher suites */
const ssl_trace_tbl ssl_ciphers_tbl[] = {
    {0x0000, "TLS_NULL_WITH_NULL_NULL"},
    {0x0001, "TLS_RSA_WITH_NULL_MD5"},
    {0x0002, "TLS_RSA_WITH_NULL_SHA"},
    {0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
    {0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
    {0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
    {0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
    {0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"},
    {0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0009, "TLS_RSA_WITH_DES_CBC_SHA"},
    {0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"},
    {0x000C, "TLS_DH_DSS_WITH_DES_CBC_SHA"},
    {0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x000F, "TLS_DH_RSA_WITH_DES_CBC_SHA"},
    {0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA"},
    {0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"},
    {0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
    {0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"},
    {0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"},
    {0x001A, "TLS_DH_anon_WITH_DES_CBC_SHA"},
    {0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"},
    {0x001D, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"},
    {0x001E, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"},
    {0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"},
    {0x0020, "TLS_KRB5_WITH_RC4_128_SHA"},
    {0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA"},
    {0x0022, "TLS_KRB5_WITH_DES_CBC_MD5"},
    {0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"},
    {0x0024, "TLS_KRB5_WITH_RC4_128_MD5"},
    {0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5"},
    {0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"},
    {0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"},
    {0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"},
    {0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"},
    {0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"},
    {0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"},
    {0x002C, "TLS_PSK_WITH_NULL_SHA"},
    {0x002D, "TLS_DHE_PSK_WITH_NULL_SHA"},
    {0x002E, "TLS_RSA_PSK_WITH_NULL_SHA"},
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
    {0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"},
    {0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"},
    {0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"},
    {0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},
    {0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
    {0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"},
    {0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"},
    {0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"},
    {0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
    {0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"},
    {0x003B, "TLS_RSA_WITH_NULL_SHA256"},
    {0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
    {0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"},
    {0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"},
    {0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"},
    {0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"},
    {0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"},
    {0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"},
    {0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"},
    {0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"},
    {0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"},
    {0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"},
    {0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"},
    {0x0081, "TLS_GOSTR341001_WITH_28147_CNT_IMIT"},
    {0x0083, "TLS_GOSTR341001_WITH_NULL_GOSTR3411"},
    {0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"},
    {0x008A, "TLS_PSK_WITH_RC4_128_SHA"},
    {0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA"},
    {0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA"},
    {0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA"},
    {0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"},
    {0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"},
    {0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"},
    {0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"},
    {0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"},
    {0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"},
    {0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA"},
    {0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA"},
    {0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"},
    {0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"},
    {0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA"},
    {0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
    {0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"},
    {0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"},
    {0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"},
    {0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"},
    {0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"},
    {0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"},
    {0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256"},
    {0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384"},
    {0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"},
    {0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"},
    {0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B0, "TLS_PSK_WITH_NULL_SHA256"},
    {0x00B1, "TLS_PSK_WITH_NULL_SHA384"},
    {0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256"},
    {0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384"},
    {0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"},
    {0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"},
    {0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256"},
    {0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384"},
    {0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"},
    {0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"},
    {0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"},
    {0x5600, "TLS_FALLBACK_SCSV"},
    {0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"},
    {0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"},
    {0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"},
    {0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"},
    {0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"},
    {0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
    {0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
    {0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
    {0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA"},
    {0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA"},
    {0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"},
    {0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"},
    {0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"},
    {0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
    {0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    {0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
    {0xC015, "TLS_ECDH_anon_WITH_NULL_SHA"},
    {0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA"},
    {0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"},
    {0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"},
    {0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"},
    {0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"},
    {0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"},
    {0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"},
    {0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"},
    {0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"},
    {0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"},
    {0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"},
    {0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"},
    {0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
    {0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
    {0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"},
    {0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"},
    {0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
    {0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
    {0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"},
    {0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"},
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"},
    {0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"},
    {0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"},
    {0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"},
    {0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"},
    {0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"},
    {0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"},
    {0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA"},
    {0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256"},
    {0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384"},
    {0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"},
    {0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"},
    {0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"},
    {0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"},
    {0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"},
    {0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"},
    {0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"},
    {0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"},
    {0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"},
    {0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"},
    {0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"},
    {0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"},
    {0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"},
    {0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"},
    {0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"},
    {0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"},
    {0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"},
    {0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"},
    {0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"},
    {0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"},
    {0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"},
    {0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"},
    {0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"},
    {0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"},
    {0xC09C, "TLS_RSA_WITH_AES_128_CCM"},
    {0xC09D, "TLS_RSA_WITH_AES_256_CCM"},
    {0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM"},
    {0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM"},
    {0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8"},
    {0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8"},
    {0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8"},
    {0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8"},
    {0xC0A4, "TLS_PSK_WITH_AES_128_CCM"},
    {0xC0A5, "TLS_PSK_WITH_AES_256_CCM"},
    {0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM"},
    {0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM"},
    {0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8"},
    {0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8"},
    {0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8"},
    {0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8"},
    {0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
    {0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"},
    {0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"},
    {0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"},
    {0xC102, "IANA-GOST2012-GOST8912-GOST8912"},
    {0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"},
    {0x1301, "TLS_AES_128_GCM_SHA256"},
    {0x1302, "TLS_AES_256_GCM_SHA384"},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
    {0x1304, "TLS_AES_128_CCM_SHA256"},
    {0x1305, "TLS_AES_128_CCM_8_SHA256"},
    {0xFEFE, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    {0xFEFF, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"},
    {0xFF85, "LEGACY-GOST2012-GOST8912-GOST8912"},
    {0xFF87, "GOST2012-NULL-GOST12"},
    {0xC0B4, "TLS_SHA256_SHA256"},
    {0xC0B5, "TLS_SHA384_SHA384"},
    {0xC100, "GOST2012-KUZNYECHIK-KUZNYECHIKOMAC"},
    {0xC101, "GOST2012-MAGMA-MAGMAOMAC"},
    {0xC102, "GOST2012-GOST8912-IANA"},
};

/* Compression methods */
static const ssl_trace_tbl ssl_comp_tbl[] = {
    {0x0000, "No Compression"},
    {0x0001, "Zlib Compression"}
};



/* Extensions sorted by ascending id */
const ssl_trace_tbl ssl_exts_tbl[] = {
	{TLSEXT_TYPE_server_name, "server_name"},
	{TLSEXT_TYPE_max_fragment_length, "max_fragment_length"},
	{TLSEXT_TYPE_client_certificate_url, "client_certificate_url"},
	{TLSEXT_TYPE_trusted_ca_keys, "trusted_ca_keys"},
	{TLSEXT_TYPE_truncated_hmac, "truncated_hmac"},
	{TLSEXT_TYPE_status_request, "status_request"},
	{TLSEXT_TYPE_user_mapping, "user_mapping"},
	{TLSEXT_TYPE_client_authz, "client_authz"},
	{TLSEXT_TYPE_server_authz, "server_authz"},
	{TLSEXT_TYPE_cert_type, "cert_type"},
	{TLSEXT_TYPE_supported_groups, "supported_groups"},
	{TLSEXT_TYPE_ec_point_formats, "ec_point_formats"},
	{TLSEXT_TYPE_srp, "srp"},
	{TLSEXT_TYPE_signature_algorithms, "signature_algorithms"},
	{TLSEXT_TYPE_use_srtp, "use_srtp"},
	{TLSEXT_TYPE_application_layer_protocol_negotiation,
	 "application_layer_protocol_negotiation"},
	{TLSEXT_TYPE_signed_certificate_timestamp, "signed_certificate_timestamps"},
	{TLSEXT_TYPE_client_cert_type, "client_cert_type"},
	{TLSEXT_TYPE_server_cert_type, "server_cert_type"},
	{TLSEXT_TYPE_padding, "padding"},
	{TLSEXT_TYPE_encrypt_then_mac, "encrypt_then_mac"},
	{TLSEXT_TYPE_extended_master_secret, "extended_master_secret"},
	{TLSEXT_TYPE_compress_certificate, "compress_certificate"},
	{TLSEXT_TYPE_session_ticket, "session_ticket"},
	{TLSEXT_TYPE_psk, "psk"},
	{TLSEXT_TYPE_early_data, "early_data"},
	{TLSEXT_TYPE_supported_versions, "supported_versions"},
	{TLSEXT_TYPE_cookie, "cookie_ext"},
	{TLSEXT_TYPE_psk_kex_modes, "psk_key_exchange_modes"},
	{TLSEXT_TYPE_certificate_authorities, "certificate_authorities"},
	{TLSEXT_TYPE_post_handshake_auth, "post_handshake_auth"},
	{TLSEXT_TYPE_signature_algorithms_cert, "signature_algorithms_cert"},
	{TLSEXT_TYPE_key_share, "key_share"},
	{TLSEXT_TYPE_renegotiate, "renegotiate"},
# ifndef OPENSSL_NO_NEXTPROTONEG
	{TLSEXT_TYPE_next_proto_neg, "next_proto_neg"},
# endif
};


const ssl_trace_tbl ssl_groups_tbl[] = {
	{1, "sect163k1 (K-163)"},
	{2, "sect163r1"},
	{3, "sect163r2 (B-163)"},
	{4, "sect193r1"},
	{5, "sect193r2"},
	{6, "sect233k1 (K-233)"},
	{7, "sect233r1 (B-233)"},
	{8, "sect239k1"},
	{9, "sect283k1 (K-283)"},
	{10, "sect283r1 (B-283)"},
	{11, "sect409k1 (K-409)"},
	{12, "sect409r1 (B-409)"},
	{13, "sect571k1 (K-571)"},
	{14, "sect571r1 (B-571)"},
	{15, "secp160k1"},
	{16, "secp160r1"},
	{17, "secp160r2"},
	{18, "secp192k1"},
	{19, "secp192r1 (P-192)"},
	{20, "secp224k1"},
	{21, "secp224r1 (P-224)"},
	{22, "secp256k1"},
	{23, "secp256r1 (P-256)"},
	{24, "secp384r1 (P-384)"},
	{25, "secp521r1 (P-521)"},
	{26, "brainpoolP256r1"},
	{27, "brainpoolP384r1"},
	{28, "brainpoolP512r1"},
	{29, "ecdh_x25519"},
	{30, "ecdh_x448"},
	{31, "brainpoolP256r1tls13"},
	{32, "brainpoolP384r1tls13"},
	{33, "brainpoolP512r1tls13"},
	{34, "GC256A"},
	{35, "GC256B"},
	{36, "GC256C"},
	{37, "GC256D"},
	{38, "GC512A"},
	{39, "GC512B"},
	{40, "GC512C"},
	{256, "ffdhe2048"},
	{257, "ffdhe3072"},
	{258, "ffdhe4096"},
	{259, "ffdhe6144"},
	{260, "ffdhe8192"},
	{512, "MLKEM512"},
	{513, "MLKEM768"},
	{514, "MLKEM1024"},
	{4587, "SecP256r1MLKEM768"},
	{4588, "X25519MLKEM768"},
	{4589, "SecP384r1MLKEM1024"},
	{25497, "X25519Kyber768Draft00"},
	{25498, "SecP256r1Kyber768Draft00"},
	{0xFF01, "arbitrary_explicit_prime_curves"},
	{0xFF02, "arbitrary_explicit_char2_curves"}
};

static const ssl_trace_tbl ssl_sigalg_tbl[] = {
	{TLSEXT_SIGALG_ecdsa_secp256r1_sha256, TLSEXT_SIGALG_ecdsa_secp256r1_sha256_name},
	{TLSEXT_SIGALG_ecdsa_secp384r1_sha384, TLSEXT_SIGALG_ecdsa_secp384r1_sha384_name},
	{TLSEXT_SIGALG_ecdsa_secp521r1_sha512,TLSEXT_SIGALG_ecdsa_secp521r1_sha512_name},
	{TLSEXT_SIGALG_ecdsa_sha224, TLSEXT_SIGALG_ecdsa_sha224_name},
	{TLSEXT_SIGALG_ed25519, TLSEXT_SIGALG_ed25519_name},
	{TLSEXT_SIGALG_ed448, TLSEXT_SIGALG_ed448_name},
	{TLSEXT_SIGALG_ecdsa_sha1, TLSEXT_SIGALG_ecdsa_sha1_name},
	{TLSEXT_SIGALG_rsa_pss_rsae_sha256, TLSEXT_SIGALG_rsa_pss_rsae_sha256_name},
	{TLSEXT_SIGALG_rsa_pss_rsae_sha384, TLSEXT_SIGALG_rsa_pss_rsae_sha384_name},
	{TLSEXT_SIGALG_rsa_pss_rsae_sha512, TLSEXT_SIGALG_rsa_pss_rsae_sha512_name},
	{TLSEXT_SIGALG_rsa_pss_pss_sha256, TLSEXT_SIGALG_rsa_pss_pss_sha256_name},
	{TLSEXT_SIGALG_rsa_pss_pss_sha384, TLSEXT_SIGALG_rsa_pss_pss_sha384_name},
	{TLSEXT_SIGALG_rsa_pss_pss_sha512, TLSEXT_SIGALG_rsa_pss_pss_sha512_name},
	{TLSEXT_SIGALG_rsa_pkcs1_sha256, TLSEXT_SIGALG_rsa_pkcs1_sha256_name},
	{TLSEXT_SIGALG_rsa_pkcs1_sha384, TLSEXT_SIGALG_rsa_pkcs1_sha384_name},
	{TLSEXT_SIGALG_rsa_pkcs1_sha512, TLSEXT_SIGALG_rsa_pkcs1_sha512_name},
	{TLSEXT_SIGALG_rsa_pkcs1_sha224, TLSEXT_SIGALG_rsa_pkcs1_sha224_name},
	{TLSEXT_SIGALG_rsa_pkcs1_sha1, TLSEXT_SIGALG_rsa_pkcs1_sha1_name},
	{TLSEXT_SIGALG_dsa_sha256, TLSEXT_SIGALG_dsa_sha256_name},
	{TLSEXT_SIGALG_dsa_sha384, TLSEXT_SIGALG_dsa_sha384_name},
	{TLSEXT_SIGALG_dsa_sha512, TLSEXT_SIGALG_dsa_sha512_name},
	{TLSEXT_SIGALG_dsa_sha224, TLSEXT_SIGALG_dsa_sha224_name},
	{TLSEXT_SIGALG_dsa_sha1, TLSEXT_SIGALG_dsa_sha1_name},
	{TLSEXT_SIGALG_gostr34102012_256_intrinsic, TLSEXT_SIGALG_gostr34102012_256_intrinsic_name},
	{TLSEXT_SIGALG_gostr34102012_512_intrinsic, TLSEXT_SIGALG_gostr34102012_512_intrinsic_name},
	{TLSEXT_SIGALG_gostr34102012_256_gostr34112012_256, TLSEXT_SIGALG_gostr34102012_256_gostr34112012_256_name},
	{TLSEXT_SIGALG_gostr34102012_512_gostr34112012_512, TLSEXT_SIGALG_gostr34102012_512_gostr34112012_512_name},
	{TLSEXT_SIGALG_gostr34102001_gostr3411, TLSEXT_SIGALG_gostr34102001_gostr3411_name},
	{TLSEXT_SIGALG_ecdsa_brainpoolP256r1_sha256, TLSEXT_SIGALG_ecdsa_brainpoolP256r1_sha256_name},
	{TLSEXT_SIGALG_ecdsa_brainpoolP384r1_sha384, TLSEXT_SIGALG_ecdsa_brainpoolP384r1_sha384_name},
	{TLSEXT_SIGALG_ecdsa_brainpoolP512r1_sha512, TLSEXT_SIGALG_ecdsa_brainpoolP512r1_sha512_name},
	/*
	 * Well known groups that we happen to know about, but only come from
	 * provider capability declarations (hence no macros for the
	 * codepoints/names)
	 */
	{0x0904, "mldsa44"},
	{0x0905, "mldsa65"},
	{0x0906, "mldsa87"}
};

static const ssl_trace_tbl ssl_ctype_tbl[] = {
	{1, "rsa_sign"},
	{2, "dss_sign"},
	{3, "rsa_fixed_dh"},
	{4, "dss_fixed_dh"},
	{5, "rsa_ephemeral_dh"},
	{6, "dss_ephemeral_dh"},
	{20, "fortezza_dms"},
	{64, "ecdsa_sign"},
	{65, "rsa_fixed_ecdh"},
	{66, "ecdsa_fixed_ecdh"},
	{67, "gost_sign256"},
	{68, "gost_sign512"},
};

static const ssl_trace_tbl ssl_psk_kex_modes_tbl[] = {
	{TLSEXT_KEX_MODE_KE, "psk_ke"},
	{TLSEXT_KEX_MODE_KE_DHE, "psk_dhe_ke"}
};

static const ssl_trace_tbl ssl_key_update_tbl[] = {
	{SSL_KEY_UPDATE_NOT_REQUESTED, "update_not_requested"},
	{SSL_KEY_UPDATE_REQUESTED, "update_requested"}
};

static const ssl_trace_tbl ssl_comp_cert_tbl[] = {
	{TLSEXT_comp_cert_none, "none"},
	{TLSEXT_comp_cert_zlib, "zlib"},
	{TLSEXT_comp_cert_brotli, "brotli"},
	{TLSEXT_comp_cert_zstd, "zstd"}
};

/*
 * "pgp" and "1609dot2" are defined in RFC7250,
 * although OpenSSL doesn't support them, it can
 * at least report them in traces
 */
static const ssl_trace_tbl ssl_cert_type_tbl[] = {
	{TLSEXT_cert_type_x509, "x509"},
	{TLSEXT_cert_type_pgp, "pgp"},
	{TLSEXT_cert_type_rpk, "rpk"},
	{TLSEXT_cert_type_1609dot2, "1609dot2"}
};

/// openssl-3.5.4\apps\lib\s_cb.c
/// ////////////////////////////////////////////////////////////////////////////////////
/// </summary>

/*
 * A string/int pairing; widely use for option value lookup, hence the
 * name OPT_PAIR. But that name is misleading in s_cb.c, so we also use
 * the "generic" name STRINT_PAIR.
 */
typedef struct string_int_pair_st {
    const char* name;
    int retval;
} OPT_PAIR, STRINT_PAIR;


static const STRINT_PAIR tlsext_types[] = {
    {"server name", TLSEXT_TYPE_server_name},
    {"max fragment length", TLSEXT_TYPE_max_fragment_length},
    {"client certificate URL", TLSEXT_TYPE_client_certificate_url},
    {"trusted CA keys", TLSEXT_TYPE_trusted_ca_keys},
    {"truncated HMAC", TLSEXT_TYPE_truncated_hmac},
    {"status request", TLSEXT_TYPE_status_request},
    {"user mapping", TLSEXT_TYPE_user_mapping},
    {"client authz", TLSEXT_TYPE_client_authz},
    {"server authz", TLSEXT_TYPE_server_authz},
    {"cert type", TLSEXT_TYPE_cert_type},
    {"supported_groups", TLSEXT_TYPE_supported_groups},
    {"EC point formats", TLSEXT_TYPE_ec_point_formats},
    {"SRP", TLSEXT_TYPE_srp},
    {"signature algorithms", TLSEXT_TYPE_signature_algorithms},
    {"use SRTP", TLSEXT_TYPE_use_srtp},
    {"session ticket", TLSEXT_TYPE_session_ticket},
    {"renegotiation info", TLSEXT_TYPE_renegotiate},
    {"signed certificate timestamps", TLSEXT_TYPE_signed_certificate_timestamp},
    {"client cert type", TLSEXT_TYPE_client_cert_type},
    {"server cert type", TLSEXT_TYPE_server_cert_type},
    {"TLS padding", TLSEXT_TYPE_padding},
#ifdef TLSEXT_TYPE_next_proto_neg
    {"next protocol", TLSEXT_TYPE_next_proto_neg},
#endif
#ifdef TLSEXT_TYPE_encrypt_then_mac
    {"encrypt-then-mac", TLSEXT_TYPE_encrypt_then_mac},
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    {"application layer protocol negotiation",
     TLSEXT_TYPE_application_layer_protocol_negotiation},
#endif
#ifdef TLSEXT_TYPE_extended_master_secret
    {"extended master secret", TLSEXT_TYPE_extended_master_secret},
#endif
    {"compress certificate", TLSEXT_TYPE_compress_certificate},
    {"key share", TLSEXT_TYPE_key_share},
    {"supported versions", TLSEXT_TYPE_supported_versions},
    {"psk", TLSEXT_TYPE_psk},
    {"psk kex modes", TLSEXT_TYPE_psk_kex_modes},
    {"certificate authorities", TLSEXT_TYPE_certificate_authorities},
    {"post handshake auth", TLSEXT_TYPE_post_handshake_auth},
    {"early_data", TLSEXT_TYPE_early_data},
    {NULL}
};

/* from rfc8446 4.2.3. + gost (https://tools.ietf.org/id/draft-smyshlyaev-tls12-gost-suites-04.html) */
static STRINT_PAIR signature_tls13_scheme_list[] = {
    {"rsa_pkcs1_sha1",         0x0201 /* TLSEXT_SIGALG_rsa_pkcs1_sha1 */},
    {"ecdsa_sha1",             0x0203 /* TLSEXT_SIGALG_ecdsa_sha1 */},
    /*  {"rsa_pkcs1_sha224",       0x0301    TLSEXT_SIGALG_rsa_pkcs1_sha224}, not in rfc8446 */
    /*  {"ecdsa_sha224",           0x0303    TLSEXT_SIGALG_ecdsa_sha224}      not in rfc8446 */
        {"rsa_pkcs1_sha256",       0x0401 /* TLSEXT_SIGALG_rsa_pkcs1_sha256 */},
        {"ecdsa_secp256r1_sha256", 0x0403 /* TLSEXT_SIGALG_ecdsa_secp256r1_sha256 */},
        {"rsa_pkcs1_sha384",       0x0501 /* TLSEXT_SIGALG_rsa_pkcs1_sha384 */},
        {"ecdsa_secp384r1_sha384", 0x0503 /* TLSEXT_SIGALG_ecdsa_secp384r1_sha384 */},
        {"rsa_pkcs1_sha512",       0x0601 /* TLSEXT_SIGALG_rsa_pkcs1_sha512 */},
        {"ecdsa_secp521r1_sha512", 0x0603 /* TLSEXT_SIGALG_ecdsa_secp521r1_sha512 */},
        {"rsa_pss_rsae_sha256",    0x0804 /* TLSEXT_SIGALG_rsa_pss_rsae_sha256 */},
        {"rsa_pss_rsae_sha384",    0x0805 /* TLSEXT_SIGALG_rsa_pss_rsae_sha384 */},
        {"rsa_pss_rsae_sha512",    0x0806 /* TLSEXT_SIGALG_rsa_pss_rsae_sha512 */},
        {"ed25519",                0x0807 /* TLSEXT_SIGALG_ed25519 */},
        {"ed448",                  0x0808 /* TLSEXT_SIGALG_ed448 */},
        {"rsa_pss_pss_sha256",     0x0809 /* TLSEXT_SIGALG_rsa_pss_pss_sha256 */},
        {"rsa_pss_pss_sha384",     0x080a /* TLSEXT_SIGALG_rsa_pss_pss_sha384 */},
        {"rsa_pss_pss_sha512",     0x080b /* TLSEXT_SIGALG_rsa_pss_pss_sha512 */},
        {"gostr34102001",          0xeded /* TLSEXT_SIGALG_gostr34102001_gostr3411 */},
        {"gostr34102012_256",      0xeeee /* TLSEXT_SIGALG_gostr34102012_256_gostr34112012_256 */},
        {"gostr34102012_512",      0xefef /* TLSEXT_SIGALG_gostr34102012_512_gostr34112012_512 */},
        {NULL}
};

/* from rfc5246 7.4.1.4.1. */
static STRINT_PAIR signature_tls12_alg_list[] = {
    {"anonymous", TLSEXT_signature_anonymous /* 0 */},
    {"RSA",       TLSEXT_signature_rsa       /* 1 */},
    {"DSA",       TLSEXT_signature_dsa       /* 2 */},
    {"ECDSA",     TLSEXT_signature_ecdsa     /* 3 */},
    {NULL}
};

/* from rfc5246 7.4.1.4.1. */
static STRINT_PAIR signature_tls12_hash_list[] = {
    {"none",   TLSEXT_hash_none   /* 0 */},
    {"MD5",    TLSEXT_hash_md5    /* 1 */},
    {"SHA1",   TLSEXT_hash_sha1   /* 2 */},
    {"SHA224", TLSEXT_hash_sha224 /* 3 */},
    {"SHA256", TLSEXT_hash_sha256 /* 4 */},
    {"SHA384", TLSEXT_hash_sha384 /* 5 */},
    {"SHA512", TLSEXT_hash_sha512 /* 6 */},
    {NULL}
};

const char* got_SignatureScheme_name(uint16_t id)
{
    size_t i;
    size_t ntbl = sizeof(signature_tls13_scheme_list) / sizeof(STRINT_PAIR);
    const STRINT_PAIR* tbl = signature_tls13_scheme_list;
    for (i = 0; i < ntbl; i++, tbl++) {
        if (tbl->retval == id)
            return tbl->name;
    }
    return "UNKNOWN";
}

/// <summary>
/// ////////////////////////////////////////////////////////////////////////////////////
/// </summary>

size_t ssl_exts_tbl_num = sizeof(ssl_exts_tbl) / sizeof(ssl_trace_tbl);
size_t ssl_groups_tbl_num = sizeof(ssl_groups_tbl) / sizeof(ssl_trace_tbl);
size_t ssl_handshake_tbl_num = sizeof(ssl_handshake_tbl) / sizeof(ssl_trace_tbl);
size_t ssl_ciphers_tbl_num = sizeof(ssl_ciphers_tbl) / sizeof(ssl_trace_tbl);
size_t ssl_content_tbl_num = sizeof(ssl_content_tbl) / sizeof(ssl_trace_tbl);

const char* do_ssl_trace_str(int val, const ssl_trace_tbl* tbl, size_t ntbl)
{
	size_t i;
	for (i = 0; i < ntbl; i++, tbl++) {
		if (tbl->num == val)
			return tbl->name;
	}
	return "UNKNOWN";
}

