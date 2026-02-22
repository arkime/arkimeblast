#ifndef ARKIMEBLAST_GEN_TLS_H
#define ARKIMEBLAST_GEN_TLS_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

/* Pick a random TLS version based on distribution (1.3 ~70%, 1.2 ~25%, 1.0/1.1 ~5%) */
uint16_t gen_tls_pick_version(uint64_t *rng);

/* Generate TLS ClientHello. Returns bytes written to buf. */
int gen_tls_client_hello(uint8_t *buf, size_t bufsize, uint16_t tls_version,
                         uint64_t *rng);

/* Generate TLS ServerHello. Returns bytes written to buf. */
int gen_tls_server_hello(uint8_t *buf, size_t bufsize, uint16_t tls_version,
                         uint64_t *rng);

/* Generate TLS Certificate message. Returns bytes written to buf. */
int gen_tls_certificate(uint8_t *buf, size_t bufsize, uint64_t *rng);

/* Generate TLS ClientKeyExchange (TLS 1.2 only). Returns bytes written. */
int gen_tls_client_key_exchange(uint8_t *buf, size_t bufsize, uint64_t *rng);

/* Generate TLS ChangeCipherSpec. Returns bytes written. */
int gen_tls_change_cipher_spec(uint8_t *buf, size_t bufsize);

/* Generate TLS Application Data record. Returns bytes written. */
int gen_tls_app_data(uint8_t *buf, size_t bufsize, size_t payload_len,
                     uint64_t *rng);

#endif /* ARKIMEBLAST_GEN_TLS_H */
