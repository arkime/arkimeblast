#ifndef ARKIMEBLAST_GEN_DNS_H
#define ARKIMEBLAST_GEN_DNS_H

#include <stdint.h>
#include <stddef.h>
#include "config-core.h"

/* Pick a random DNS query type based on distribution */
uint16_t gen_dns_pick_qtype(uint64_t *rng);

/* Generate a DNS query packet (UDP payload). Returns bytes written. */
int gen_dns_query(uint8_t *buf, size_t bufsize, uint16_t txid,
                  uint16_t qtype, uint64_t *rng);

/* Generate a DNS response packet (UDP payload). Returns bytes written.
 * query_buf/query_len: the original query for matching. */
int gen_dns_response(uint8_t *buf, size_t bufsize, uint16_t txid,
                     uint16_t qtype, const uint8_t *query_buf,
                     size_t query_len, uint64_t *rng);

#endif /* ARKIMEBLAST_GEN_DNS_H */
