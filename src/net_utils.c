#include "net_utils.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* ---------- RNG: xoshiro128** ---------- */

static inline uint64_t rotl(const uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

void rng_seed(uint64_t *state, uint64_t seed)
{
    /* splitmix64 to initialize */
    for (int i = 0; i < 2; i++) {
        seed += 0x9e3779b97f4a7c15ULL;
        uint64_t z = seed;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        state[i] = z ^ (z >> 31);
    }
}

uint64_t rng_next(uint64_t *state)
{
    const uint64_t s0 = state[0];
    uint64_t s1 = state[1];
    const uint64_t result = rotl(s0 * 5, 7) * 9;

    s1 ^= s0;
    state[0] = rotl(s0, 24) ^ s1 ^ (s1 << 16);
    state[1] = rotl(s1, 37);

    return result;
}

uint32_t rng_range(uint64_t *state, uint32_t max)
{
    if (max == 0) return 0;
    return (uint32_t)(rng_next(state) % max);
}

void rng_fill(uint8_t *buf, size_t n, uint64_t *state)
{
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t r = rng_next(state);
        memcpy(buf + i, &r, 8);       /* 8 payload bytes per RNG call */
    }
    if (i < n) {
        uint64_t r = rng_next(state);
        memcpy(buf + i, &r, n - i);
    }
}

void rng_fill_printable(uint8_t *buf, size_t n, uint64_t *state)
{
    /* 64 printable chars -> 6 bits index, but we key off whole bytes (mask 0x3f)
     * so we still get 8 characters out of each 64-bit RNG word. */
    static const char lut[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .";
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t r = rng_next(state);
        for (int k = 0; k < 8; k++) {
            buf[i + k] = (uint8_t)lut[r & 0x3f];
            r >>= 8;
        }
    }
    if (i < n) {
        uint64_t r = rng_next(state);
        for (; i < n; i++) {
            buf[i] = (uint8_t)lut[r & 0x3f];
            r >>= 8;
        }
    }
}

/* ---------- CIDR parsing ---------- */

int parse_cidr(const char *cidr, subnet_t *subnet)
{
    char buf[64];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';

    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;

    subnet->base = ntohl(addr.s_addr);
    subnet->mask = 32 - prefix;
    subnet->count = (1U << subnet->mask);
    if (subnet->count > 2)
        subnet->count -= 2; /* exclude network and broadcast */

    /* Zero out host bits */
    subnet->base &= ~((1U << subnet->mask) - 1);

    return 0;
}

/* Parse --mix http:50,https:40,dns:10 */
int parse_mix(const char *arg, int *http, int *https, int *dns)
{
    *http = 0; *https = 0; *dns = 0;
    char buf[128];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *tok = strtok(buf, ",");
    while (tok) {
        char *colon = strchr(tok, ':');
        if (!colon) return -1;
        *colon = '\0';
        int val = atoi(colon + 1);

        if (strcmp(tok, "http") == 0)       *http = val;
        else if (strcmp(tok, "https") == 0) *https = val;
        else if (strcmp(tok, "dns") == 0)   *dns = val;
        else { fprintf(stderr, "Unknown protocol: %s\n", tok); return -1; }

        tok = strtok(NULL, ",");
    }

    if (*http + *https + *dns != 100) {
        fprintf(stderr, "Mix percentages must sum to 100 (got %d)\n",
            *http + *https + *dns);
        return -1;
    }
    return 0;
}

uint32_t random_ip(const subnet_t *subnet, uint64_t *rng)
{
    uint32_t host = rng_range(rng, subnet->count) + 1; /* skip .0 */
    return subnet->base | host;
}

uint16_t random_port(uint64_t *rng)
{
    return (uint16_t)(1024 + rng_range(rng, 64512));
}

/* ---------- Checksums ---------- */

uint16_t ip_checksum(const void *data, size_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)p;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

uint16_t tcp_udp_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t proto,
                          const void *data, size_t len)
{
    uint32_t sum = 0;

    /* Pseudo-header */
    sum += (src_ip >> 16) & 0xffff;
    sum += src_ip & 0xffff;
    sum += (dst_ip >> 16) & 0xffff;
    sum += dst_ip & 0xffff;
    sum += htons(proto);
    sum += htons((uint16_t)len);

    /* Data */
    const uint16_t *p = (const uint16_t *)data;
    size_t remaining = len;
    while (remaining > 1) {
        sum += *p++;
        remaining -= 2;
    }
    if (remaining == 1)
        sum += *(const uint8_t *)p;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

/* ---------- Packet builders ---------- */

int build_eth_header(uint8_t *buf, uint16_t ethertype)
{
    memcpy(buf, DST_MAC, 6);
    memcpy(buf + 6, SRC_MAC, 6);
    buf[12] = (ethertype >> 8) & 0xff;
    buf[13] = ethertype & 0xff;
    return ETH_HDRLEN;
}

int build_ip_header(uint8_t *buf, uint32_t src_ip, uint32_t dst_ip,
                    uint8_t proto, uint16_t total_len, uint16_t id)
{
    memset(buf, 0, IP_HDRLEN);
    buf[0] = 0x45;                          /* version=4, IHL=5 */
    buf[1] = 0x00;                          /* DSCP/ECN */
    buf[2] = (total_len >> 8) & 0xff;       /* total length */
    buf[3] = total_len & 0xff;
    buf[4] = (id >> 8) & 0xff;              /* identification */
    buf[5] = id & 0xff;
    buf[6] = 0x40;                          /* Don't Fragment */
    buf[7] = 0x00;
    buf[8] = 64;                            /* TTL */
    buf[9] = proto;
    /* checksum at offset 10-11, filled below */
    buf[12] = (src_ip >> 24) & 0xff;
    buf[13] = (src_ip >> 16) & 0xff;
    buf[14] = (src_ip >> 8) & 0xff;
    buf[15] = src_ip & 0xff;
    buf[16] = (dst_ip >> 24) & 0xff;
    buf[17] = (dst_ip >> 16) & 0xff;
    buf[18] = (dst_ip >> 8) & 0xff;
    buf[19] = dst_ip & 0xff;

    uint16_t cksum = ip_checksum(buf, IP_HDRLEN);
    buf[10] = (cksum) & 0xff;
    buf[11] = (cksum >> 8) & 0xff;

    return IP_HDRLEN;
}

int build_tcp_header(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                     uint32_t seq, uint32_t ack, uint8_t flags,
                     uint16_t window)
{
    memset(buf, 0, TCP_HDRLEN);
    buf[0] = (src_port >> 8) & 0xff;
    buf[1] = src_port & 0xff;
    buf[2] = (dst_port >> 8) & 0xff;
    buf[3] = dst_port & 0xff;
    buf[4] = (seq >> 24) & 0xff;
    buf[5] = (seq >> 16) & 0xff;
    buf[6] = (seq >> 8) & 0xff;
    buf[7] = seq & 0xff;
    buf[8] = (ack >> 24) & 0xff;
    buf[9] = (ack >> 16) & 0xff;
    buf[10] = (ack >> 8) & 0xff;
    buf[11] = ack & 0xff;
    buf[12] = (TCP_HDRLEN / 4) << 4;       /* data offset */
    buf[13] = flags;
    buf[14] = (window >> 8) & 0xff;
    buf[15] = window & 0xff;
    /* checksum at 16-17, filled by caller */
    /* urgent at 18-19, zero */

    return TCP_HDRLEN;
}

int build_udp_header(uint8_t *buf, uint16_t src_port, uint16_t dst_port,
                     uint16_t length)
{
    buf[0] = (src_port >> 8) & 0xff;
    buf[1] = src_port & 0xff;
    buf[2] = (dst_port >> 8) & 0xff;
    buf[3] = dst_port & 0xff;
    buf[4] = (length >> 8) & 0xff;
    buf[5] = length & 0xff;
    buf[6] = 0; /* checksum, filled by caller */
    buf[7] = 0;

    return UDP_HDRLEN;
}
