#ifndef ARKIMEBLAST_NET_UTILS_H
#define ARKIMEBLAST_NET_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include "config-core.h"

/* Parse "x.x.x.x/N" into subnet_t */
int parse_cidr(const char *cidr, subnet_t *subnet);

/* Parse "http:50,https:40,dns:10" into percentages. Returns 0 on success,
 * -1 if malformed or the percentages don't sum to 100. */
int parse_mix(const char *arg, int *http, int *https, int *dns);

/* Generate random IP within subnet */
uint32_t random_ip(const subnet_t *subnet, uint64_t *rng);

/* Generate random port in ephemeral range (1024-65535) */
uint16_t random_port(uint64_t *rng);

/* xoshiro128** RNG - fast, good quality */
uint64_t rng_next(uint64_t *state);

/* Seed the RNG */
void rng_seed(uint64_t *state, uint64_t seed);

/* Random number in [0, max) */
uint32_t rng_range(uint64_t *state, uint32_t max);

/* Fill buf with n pseudo-random bytes using one rng_next() per 8 bytes
 * (~8x fewer RNG calls than a per-byte loop). Content stays fully varied. */
void rng_fill(uint8_t *buf, size_t n, uint64_t *state);

/* Like rng_fill but emits pseudo-random printable ASCII (a 64-character set).
 * Same ~8x speedup; suitable for HTTP bodies and other text-ish payloads. */
void rng_fill_printable(uint8_t *buf, size_t n, uint64_t *state);

/* IP header checksum */
uint16_t ip_checksum(const void *data, size_t len);

/* TCP/UDP checksum with pseudo-header */
uint16_t tcp_udp_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t proto,
                          const void *data, size_t len);

/* Build Ethernet header; returns bytes written (always ETH_HDRLEN) */
int build_eth_header(uint8_t *buf, uint16_t ethertype);

/* Build IPv4 header; returns bytes written (always IP_HDRLEN) */
int build_ip_header(uint8_t *buf, uint32_t src_ip, uint32_t dst_ip,
                    uint8_t proto, uint16_t total_len, uint16_t id);

/* Build TCP header (no options); returns bytes written (always TCP_HDRLEN) */
int build_tcp_header(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                     uint32_t seq, uint32_t ack, uint8_t flags,
                     uint16_t window);

/* Build UDP header; returns bytes written (always UDP_HDRLEN) */
int build_udp_header(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                     uint16_t length);

/* TCP flag constants */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10

#endif /* ARKIMEBLAST_NET_UTILS_H */
