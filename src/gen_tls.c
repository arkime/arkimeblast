#include "gen_tls.h"
#include "net_utils.h"

#include <string.h>
#include <stdio.h>

/* TLS record header: type(1) + version(2) + length(2) */
#define TLS_RECORD_HDR 5

/* Handshake header: type(1) + length(3) */
#define TLS_HS_HDR 4

/* TLS content types */
#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_HANDSHAKE          22
#define TLS_CT_APPLICATION_DATA   23

/* Handshake types */
#define TLS_HT_CLIENT_HELLO       1
#define TLS_HT_SERVER_HELLO       2
#define TLS_HT_CERTIFICATE        11
#define TLS_HT_CLIENT_KEY_EXCHANGE 16

/* Extension types */
#define EXT_SERVER_NAME           0x0000
#define EXT_EC_POINT_FORMATS      0x000b
#define EXT_SUPPORTED_GROUPS      0x000a
#define EXT_SIGNATURE_ALGORITHMS  0x000d
#define EXT_ALPN                  0x0010
#define EXT_SUPPORTED_VERSIONS    0x002b
#define EXT_KEY_SHARE             0x0033
#define EXT_PSK_KEY_EXCHANGE      0x002d
#define EXT_SESSION_TICKET        0x0023
#define EXT_ENCRYPT_THEN_MAC      0x0016
#define EXT_EXTENDED_MASTER_SECRET 0x0017
#define EXT_RENEGOTIATION_INFO    0xff01

/* SNI hostnames for diversity */
static const char *sni_hosts[] = {
    "www.example.com", "api.service.io", "cdn.cloudfront.net",
    "app.dashboard.com", "login.microsoftonline.com", "accounts.google.com",
    "static.assets.net", "graph.facebook.com", "api.github.com",
    "www.amazon.com", "play.google.com", "outlook.office365.com",
    "s3.amazonaws.com", "fonts.googleapis.com", "ajax.googleapis.com",
    "update.googleapis.com", "clients4.google.com", "storage.googleapis.com",
};
#define NUM_SNI_HOSTS (sizeof(sni_hosts) / sizeof(sni_hosts[0]))

/* TLS 1.3 cipher suites */
static const uint16_t tls13_ciphers[] = {
    0x1301, /* TLS_AES_128_GCM_SHA256 */
    0x1302, /* TLS_AES_256_GCM_SHA384 */
    0x1303, /* TLS_CHACHA20_POLY1305_SHA256 */
};
#define NUM_TLS13_CIPHERS 3

/* TLS 1.2 cipher suites */
static const uint16_t tls12_ciphers[] = {
    0xc02b, /* ECDHE-ECDSA-AES128-GCM-SHA256 */
    0xc02f, /* ECDHE-RSA-AES128-GCM-SHA256 */
    0xc02c, /* ECDHE-ECDSA-AES256-GCM-SHA384 */
    0xc030, /* ECDHE-RSA-AES256-GCM-SHA384 */
    0xcca9, /* ECDHE-ECDSA-CHACHA20-POLY1305 */
    0xcca8, /* ECDHE-RSA-CHACHA20-POLY1305 */
    0xc013, /* ECDHE-RSA-AES128-SHA */
    0xc014, /* ECDHE-RSA-AES256-SHA */
    0x009c, /* AES128-GCM-SHA256 */
    0x009d, /* AES256-GCM-SHA384 */
};
#define NUM_TLS12_CIPHERS 10

/* TLS 1.0/1.1 legacy cipher suites */
static const uint16_t tls10_ciphers[] = {
    0x002f, /* AES128-SHA */
    0x0035, /* AES256-SHA */
    0x000a, /* DES-CBC3-SHA */
    0xc013, /* ECDHE-RSA-AES128-SHA */
    0xc014, /* ECDHE-RSA-AES256-SHA */
    0x0033, /* DHE-RSA-AES128-SHA */
    0x0039, /* DHE-RSA-AES256-SHA */
};
#define NUM_TLS10_CIPHERS 7

/* Supported groups (named curves) */
static const uint16_t groups_modern[] = {
    0x001d, /* x25519 */
    0x0017, /* secp256r1 */
    0x0018, /* secp384r1 */
    0x0019, /* secp521r1 */
    0x001e, /* x448 */
};

static const uint16_t groups_legacy[] = {
    0x0017, /* secp256r1 */
    0x0018, /* secp384r1 */
    0x0019, /* secp521r1 */
};

/* Signature algorithms */
static const uint16_t sig_algs[] = {
    0x0403, /* ecdsa_secp256r1_sha256 */
    0x0503, /* ecdsa_secp384r1_sha384 */
    0x0804, /* rsa_pss_rsae_sha256 */
    0x0805, /* rsa_pss_rsae_sha384 */
    0x0806, /* rsa_pss_rsae_sha512 */
    0x0401, /* rsa_pkcs1_sha256 */
    0x0501, /* rsa_pkcs1_sha384 */
    0x0601, /* rsa_pkcs1_sha512 */
    0x0201, /* rsa_pkcs1_sha1 (legacy) */
};
#define NUM_SIG_ALGS 9

/* Helper: write 2-byte big-endian */
static inline void put16(uint8_t *p, uint16_t v) {
    p[0] = (v >> 8) & 0xff;
    p[1] = v & 0xff;
}

/* Helper: write 3-byte big-endian */
static inline void put24(uint8_t *p, uint32_t v) {
    p[0] = (v >> 16) & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = v & 0xff;
}

uint16_t gen_tls_pick_version(uint64_t *rng)
{
    uint32_t r = rng_range(rng, 100);
    if (r < 70) return 0x0304;       /* TLS 1.3 */
    if (r < 95) return 0x0303;       /* TLS 1.2 */
    if (r < 98) return 0x0302;       /* TLS 1.1 */
    return 0x0301;                    /* TLS 1.0 */
}

/* Build SNI extension */
static int ext_sni(uint8_t *p, const char *hostname) {
    size_t hlen = strlen(hostname);
    int off = 0;
    put16(p + off, EXT_SERVER_NAME); off += 2;
    put16(p + off, (uint16_t)(hlen + 5)); off += 2;   /* ext data length */
    put16(p + off, (uint16_t)(hlen + 3)); off += 2;   /* server name list length */
    p[off++] = 0;                                       /* host name type */
    put16(p + off, (uint16_t)hlen); off += 2;
    memcpy(p + off, hostname, hlen); off += (int)hlen;
    return off;
}

/* Build supported_groups extension */
static int ext_supported_groups(uint8_t *p, int modern) {
    const uint16_t *grps = modern ? groups_modern : groups_legacy;
    int count = modern ? 5 : 3;
    int off = 0;
    put16(p + off, EXT_SUPPORTED_GROUPS); off += 2;
    put16(p + off, (uint16_t)(count * 2 + 2)); off += 2;
    put16(p + off, (uint16_t)(count * 2)); off += 2;
    for (int i = 0; i < count; i++) {
        put16(p + off, grps[i]); off += 2;
    }
    return off;
}

/* Build signature_algorithms extension */
static int ext_sig_algs(uint8_t *p, int count) {
    int off = 0;
    put16(p + off, EXT_SIGNATURE_ALGORITHMS); off += 2;
    put16(p + off, (uint16_t)(count * 2 + 2)); off += 2;
    put16(p + off, (uint16_t)(count * 2)); off += 2;
    for (int i = 0; i < count; i++) {
        put16(p + off, sig_algs[i]); off += 2;
    }
    return off;
}

/* Build ALPN extension */
static int ext_alpn(uint8_t *p, int include_h2) {
    int off = 0;
    put16(p + off, EXT_ALPN); off += 2;
    if (include_h2) {
        put16(p + off, 12); off += 2; /* ext data len */
        put16(p + off, 10); off += 2; /* protocol list len */
        p[off++] = 2; memcpy(p + off, "h2", 2); off += 2;
        p[off++] = 8; memcpy(p + off, "http/1.1", 8); off += 8;
    } else {
        put16(p + off, 11); off += 2;
        put16(p + off, 9); off += 2;
        p[off++] = 8; memcpy(p + off, "http/1.1", 8); off += 8;
    }
    return off;
}

/* Build supported_versions extension (TLS 1.3 ClientHello) */
static int ext_supported_versions(uint8_t *p) {
    int off = 0;
    put16(p + off, EXT_SUPPORTED_VERSIONS); off += 2;
    put16(p + off, 5); off += 2;  /* ext data len */
    p[off++] = 4;                  /* list len */
    put16(p + off, 0x0304); off += 2; /* TLS 1.3 */
    put16(p + off, 0x0303); off += 2; /* TLS 1.2 */
    return off;
}

/* Build key_share extension with x25519 (32 bytes random key) */
static int ext_key_share(uint8_t *p, uint64_t *rng) {
    int off = 0;
    put16(p + off, EXT_KEY_SHARE); off += 2;
    put16(p + off, 38); off += 2;  /* ext data len */
    put16(p + off, 36); off += 2;  /* client key shares len */
    put16(p + off, 0x001d); off += 2; /* x25519 */
    put16(p + off, 32); off += 2;  /* key len */
    for (int i = 0; i < 32; i++)
        p[off++] = (uint8_t)rng_next(rng);
    return off;
}

/* Simple extension: just type + empty or minimal data */
static int ext_simple(uint8_t *p, uint16_t type) {
    int off = 0;
    put16(p + off, type); off += 2;
    if (type == EXT_RENEGOTIATION_INFO) {
        put16(p + off, 1); off += 2;
        p[off++] = 0;
    } else if (type == EXT_EC_POINT_FORMATS) {
        put16(p + off, 2); off += 2;
        p[off++] = 1; /* list length */
        p[off++] = 0; /* uncompressed */
    } else {
        put16(p + off, 0); off += 2;
    }
    return off;
}

int gen_tls_client_hello(uint8_t *buf, size_t bufsize, uint16_t tls_version,
                         uint64_t *rng)
{
    (void)bufsize;
    uint8_t *p = buf;
    int off = 0;

    /* TLS record header placeholder */
    p[off++] = TLS_CT_HANDSHAKE;
    put16(p + off, 0x0301); off += 2; /* record version always 0x0301 */
    int rec_len_off = off; off += 2;  /* placeholder for record length */

    /* Handshake header placeholder */
    p[off++] = TLS_HT_CLIENT_HELLO;
    int hs_len_off = off; off += 3;   /* placeholder for handshake length */

    int hs_start = off;

    /* Client version */
    if (tls_version >= 0x0304)
        put16(p + off, 0x0303); /* TLS 1.3 uses 0x0303 in legacy field */
    else
        put16(p + off, tls_version);
    off += 2;

    /* Random (32 bytes) */
    for (int i = 0; i < 32; i++)
        p[off++] = (uint8_t)rng_next(rng);

    /* Session ID */
    if (rng_range(rng, 100) < 70) {
        p[off++] = 32;
        for (int i = 0; i < 32; i++)
            p[off++] = (uint8_t)rng_next(rng);
    } else {
        p[off++] = 0;
    }

    /* Cipher suites */
    const uint16_t *ciphers;
    int ncipher;
    if (tls_version >= 0x0304) {
        /* TLS 1.3: include both 1.3 and 1.2 suites */
        int cipher_off = off;
        off += 2; /* length placeholder */
        int total = 0;
        /* Shuffle order slightly */
        int start13 = (int)rng_range(rng, NUM_TLS13_CIPHERS);
        for (int i = 0; i < NUM_TLS13_CIPHERS; i++) {
            put16(p + off, tls13_ciphers[(start13 + i) % NUM_TLS13_CIPHERS]);
            off += 2; total++;
        }
        /* Add some TLS 1.2 suites */
        int n12 = 3 + (int)rng_range(rng, 5);
        int start12 = (int)rng_range(rng, NUM_TLS12_CIPHERS);
        for (int i = 0; i < n12 && i < NUM_TLS12_CIPHERS; i++) {
            put16(p + off, tls12_ciphers[(start12 + i) % NUM_TLS12_CIPHERS]);
            off += 2; total++;
        }
        put16(p + cipher_off, (uint16_t)(total * 2));
        ciphers = NULL; ncipher = 0; /* already written */
    } else if (tls_version >= 0x0303) {
        ciphers = tls12_ciphers; ncipher = NUM_TLS12_CIPHERS;
    } else {
        ciphers = tls10_ciphers; ncipher = NUM_TLS10_CIPHERS;
    }

    if (ciphers) {
        int start = (int)rng_range(rng, (uint32_t)ncipher);
        int count = ncipher - (int)rng_range(rng, (uint32_t)(ncipher > 3 ? 3 : 0));
        put16(p + off, (uint16_t)(count * 2)); off += 2;
        for (int i = 0; i < count; i++) {
            put16(p + off, ciphers[(start + i) % ncipher]);
            off += 2;
        }
    }

    /* Compression methods */
    p[off++] = 1;  /* length */
    p[off++] = 0;  /* null compression */

    /* Extensions */
    int ext_len_off = off; off += 2;
    int ext_start = off;

    /* SNI */
    const char *sni = sni_hosts[rng_range(rng, NUM_SNI_HOSTS)];
    off += ext_sni(p + off, sni);

    /* Supported groups */
    off += ext_supported_groups(p + off, tls_version >= 0x0303);

    /* Signature algorithms */
    int nsig = (tls_version >= 0x0304) ? NUM_SIG_ALGS : (NUM_SIG_ALGS - 1);
    off += ext_sig_algs(p + off, nsig);

    /* EC point formats (TLS 1.2 and below) */
    if (tls_version <= 0x0303)
        off += ext_simple(p + off, EXT_EC_POINT_FORMATS);

    /* ALPN */
    off += ext_alpn(p + off, tls_version >= 0x0303 && rng_range(rng, 100) < 60);

    /* TLS 1.3 specific extensions */
    if (tls_version >= 0x0304) {
        off += ext_supported_versions(p + off);
        off += ext_key_share(p + off, rng);
        off += ext_simple(p + off, EXT_PSK_KEY_EXCHANGE);
    }

    /* Common optional extensions */
    if (rng_range(rng, 100) < 60)
        off += ext_simple(p + off, EXT_SESSION_TICKET);
    if (tls_version <= 0x0303) {
        off += ext_simple(p + off, EXT_ENCRYPT_THEN_MAC);
        off += ext_simple(p + off, EXT_EXTENDED_MASTER_SECRET);
    }
    off += ext_simple(p + off, EXT_RENEGOTIATION_INFO);

    /* Fill in extension length */
    put16(p + ext_len_off, (uint16_t)(off - ext_start));

    /* Fill in handshake length */
    put24(p + hs_len_off, (uint32_t)(off - hs_start));

    /* Fill in record length */
    put16(p + rec_len_off, (uint16_t)(off - rec_len_off - 2));

    return off;
}

int gen_tls_server_hello(uint8_t *buf, size_t bufsize, uint16_t tls_version,
                         uint64_t *rng)
{
    (void)bufsize;
    uint8_t *p = buf;
    int off = 0;

    p[off++] = TLS_CT_HANDSHAKE;
    put16(p + off, 0x0303); off += 2;
    int rec_len_off = off; off += 2;

    p[off++] = TLS_HT_SERVER_HELLO;
    int hs_len_off = off; off += 3;
    int hs_start = off;

    /* Server version */
    put16(p + off, 0x0303); off += 2;

    /* Random (32 bytes) */
    for (int i = 0; i < 32; i++)
        p[off++] = (uint8_t)rng_next(rng);

    /* Session ID (echo back 32 bytes) */
    p[off++] = 32;
    for (int i = 0; i < 32; i++)
        p[off++] = (uint8_t)rng_next(rng);

    /* Cipher suite */
    if (tls_version >= 0x0304) {
        put16(p + off, tls13_ciphers[rng_range(rng, NUM_TLS13_CIPHERS)]);
    } else if (tls_version >= 0x0303) {
        put16(p + off, tls12_ciphers[rng_range(rng, 6)]); /* prefer AEAD */
    } else {
        put16(p + off, tls10_ciphers[rng_range(rng, NUM_TLS10_CIPHERS)]);
    }
    off += 2;

    /* Compression */
    p[off++] = 0;

    /* Extensions */
    int ext_len_off = off; off += 2;
    int ext_start = off;

    if (tls_version >= 0x0304) {
        /* supported_versions */
        put16(p + off, EXT_SUPPORTED_VERSIONS); off += 2;
        put16(p + off, 2); off += 2;
        put16(p + off, 0x0304); off += 2;

        /* key_share */
        put16(p + off, EXT_KEY_SHARE); off += 2;
        put16(p + off, 36); off += 2;
        put16(p + off, 0x001d); off += 2; /* x25519 */
        put16(p + off, 32); off += 2;
        for (int i = 0; i < 32; i++)
            p[off++] = (uint8_t)rng_next(rng);
    }

    off += ext_simple(p + off, EXT_RENEGOTIATION_INFO);

    put16(p + ext_len_off, (uint16_t)(off - ext_start));
    put24(p + hs_len_off, (uint32_t)(off - hs_start));
    put16(p + rec_len_off, (uint16_t)(off - rec_len_off - 2));

    return off;
}

int gen_tls_certificate(uint8_t *buf, size_t bufsize, uint64_t *rng)
{
    (void)bufsize;
    uint8_t *p = buf;
    int off = 0;

    /* Generate a fake but structurally valid certificate message */
    p[off++] = TLS_CT_HANDSHAKE;
    put16(p + off, 0x0303); off += 2;
    int rec_len_off = off; off += 2;

    p[off++] = TLS_HT_CERTIFICATE;
    int hs_len_off = off; off += 3;
    int hs_start = off;

    /* Certificate list length placeholder */
    int cert_list_off = off; off += 3;
    int cert_list_start = off;

    /* Single fake certificate: 512-800 bytes of random data
     * structured just enough to look like ASN.1 DER */
    int cert_size = 512 + (int)rng_range(rng, 289);
    put24(p + off, (uint32_t)cert_size); off += 3;

    /* Fake DER: SEQUENCE { SEQUENCE { ... } } */
    p[off++] = 0x30; /* SEQUENCE */
    p[off++] = 0x82;
    put16(p + off, (uint16_t)(cert_size - 4)); off += 2;

    /* tbsCertificate SEQUENCE */
    p[off++] = 0x30;
    p[off++] = 0x82;
    int tbs_len = cert_size - 4 - 100; /* leave room for sig */
    put16(p + off, (uint16_t)tbs_len); off += 2;

    /* Fill with random data */
    rng_fill(p + off, (size_t)tbs_len, rng); off += tbs_len;

    /* signatureAlgorithm */
    p[off++] = 0x30; p[off++] = 0x0d;
    p[off++] = 0x06; p[off++] = 0x09;
    /* OID for sha256WithRSAEncryption */
    uint8_t oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
    memcpy(p + off, oid, 9); off += 9;
    p[off++] = 0x05; p[off++] = 0x00;

    /* signatureValue (remaining bytes) */
    int sig_remaining = cert_size - (off - cert_list_start - 3);
    if (sig_remaining > 0) {
        p[off++] = 0x03;
        p[off++] = 0x82;
        put16(p + off, (uint16_t)(sig_remaining - 4)); off += 2;
        p[off++] = 0x00;
        int fill = sig_remaining - 5;
        if (fill > (int)bufsize - 20 - off)
            fill = (int)bufsize - 20 - off;
        if (fill > 0) {
            rng_fill(p + off, (size_t)fill, rng); off += fill;
        }
    }

    put24(p + cert_list_off, (uint32_t)(off - cert_list_start));
    put24(p + hs_len_off, (uint32_t)(off - hs_start));
    put16(p + rec_len_off, (uint16_t)(off - rec_len_off - 2));

    return off;
}

int gen_tls_client_key_exchange(uint8_t *buf, size_t bufsize, uint64_t *rng)
{
    (void)bufsize;
    uint8_t *p = buf;
    int off = 0;

    p[off++] = TLS_CT_HANDSHAKE;
    put16(p + off, 0x0303); off += 2;
    int rec_len_off = off; off += 2;

    p[off++] = TLS_HT_CLIENT_KEY_EXCHANGE;
    int hs_len_off = off; off += 3;
    int hs_start = off;

    /* ECDHE public key (65 bytes for P-256 or 32 for X25519) */
    int key_len = (rng_range(rng, 100) < 50) ? 32 : 65;
    p[off++] = (uint8_t)key_len;
    for (int i = 0; i < key_len; i++)
        p[off++] = (uint8_t)rng_next(rng);

    put24(p + hs_len_off, (uint32_t)(off - hs_start));
    put16(p + rec_len_off, (uint16_t)(off - rec_len_off - 2));

    return off;
}

int gen_tls_change_cipher_spec(uint8_t *buf, size_t bufsize)
{
    (void)bufsize;
    buf[0] = TLS_CT_CHANGE_CIPHER_SPEC;
    put16(buf + 1, 0x0303);
    put16(buf + 3, 1);
    buf[5] = 1;
    return 6;
}

int gen_tls_app_data(uint8_t *buf, size_t bufsize, size_t payload_len,
                     uint64_t *rng)
{
    if (payload_len + TLS_RECORD_HDR > bufsize)
        payload_len = bufsize - TLS_RECORD_HDR;

    buf[0] = TLS_CT_APPLICATION_DATA;
    put16(buf + 1, 0x0303);
    put16(buf + 3, (uint16_t)payload_len);

    for (size_t i = 0; i < payload_len; i++)
        buf[TLS_RECORD_HDR + i] = (uint8_t)rng_next(rng);

    return (int)(TLS_RECORD_HDR + payload_len);
}
