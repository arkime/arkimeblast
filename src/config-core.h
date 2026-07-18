#ifndef ARKIMEBLAST_CONFIG_CORE_H
#define ARKIMEBLAST_CONFIG_CORE_H

/* Generic, delivery-independent definitions shared by the packet generator.
 * Everything here is portable and has no dependency on pthreads or AF_PACKET,
 * so it can be reused outside the standalone blaster (e.g. the Arkime reader
 * plugin in ../plugin). Delivery/threading-specific bits live in config.h. */

#include <stdint.h>
#include <stddef.h>

#define ARKIMEBLAST_VERSION "0.1.0"

#define DEFAULT_GBPS        1.0
#define DEFAULT_MIX_HTTP    50
#define DEFAULT_MIX_HTTPS   40
#define DEFAULT_MIX_DNS     10
#define DEFAULT_SUBNET_SRC  "10.0.0.0/8"
#define DEFAULT_SUBNET_DST  "172.16.0.0/12"
#define DEFAULT_DURATION    0
#define DEFAULT_SEED        0

#define MAX_PACKET_SIZE     1514
#define MIN_PACKET_SIZE     64
#define ETH_HDRLEN          14
#define IP_HDRLEN           20
#define TCP_HDRLEN          20
#define UDP_HDRLEN          8
#define MSS                 1400

#define MAX_THREADS         256
#define MAX_SESSIONS        65536

/* Source/dest MACs - locally administered, avoids ARP */
#define SRC_MAC "\x02\x00\x00\x00\x00\x01"
#define DST_MAC "\x02\x00\x00\x00\x00\x02"

typedef struct {
    uint32_t base;     /* network address in host byte order */
    uint32_t mask;     /* number of host bits */
    uint32_t count;    /* number of usable addresses */
} subnet_t;

typedef struct {
    /* CLI options */
    char         interface[64];
    double       gbps;
    int          num_threads;
    int          mix_http;       /* percentage */
    int          mix_https;      /* percentage */
    int          mix_dns;        /* percentage */
    subnet_t     subnet_src;
    subnet_t     subnet_dst;
    uint64_t     duration;       /* seconds, 0 = infinite */
    uint64_t     max_packets;    /* 0 = unlimited */
    uint64_t     max_gbytes;     /* 0 = unlimited (in GB) */
    uint64_t     seed;
    int          verbose;

    /* Derived */
    int          if_index;
} config_t;

/* Per-thread statistics (cache-line aligned to avoid false sharing) */
typedef struct __attribute__((aligned(64))) {
    uint64_t     packets_sent;
    uint64_t     bytes_sent;
    uint64_t     sessions_started;
    uint64_t     http_sessions;
    uint64_t     https_sessions;
    uint64_t     dns_sessions;
    uint64_t     retransmits;
    uint64_t     drops;
} thread_stats_t;

/* Per-thread context. The generator only reads config/rng_state/stats; the
 * tx_ring/sock_fd fields are only used by the AF_PACKET delivery layer. */
typedef struct {
    int             thread_id;
    config_t       *config;
    int             sock_fd;
    uint8_t        *tx_ring;
    size_t          tx_ring_size;
    uint32_t        tx_frame_idx;
    uint32_t        tx_frame_count;
    thread_stats_t  stats;
    uint64_t        rng_state[2]; /* xoshiro128 state */
    volatile int   *running;      /* pointer to global running flag */
    volatile int64_t *packets_remaining; /* shared atomic countdown */
} thread_ctx_t;

#endif /* ARKIMEBLAST_CONFIG_CORE_H */
