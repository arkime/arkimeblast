#ifndef ARKIMEBLAST_CONFIG_H
#define ARKIMEBLAST_CONFIG_H

#include <stdint.h>
#include <pthread.h>

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

/* TX ring defaults — sized for 20Gbps+ */
#define TX_RING_BLOCK_SIZE  (1 << 22)  /* 4MB per block */
#define TX_RING_BLOCK_NR    256        /* 1GB total ring per thread */
#define TX_RING_FRAME_SIZE  (1 << 11)  /* 2048 per frame */
#define TX_FLUSH_INTERVAL   256        /* frames between sendto kicks */

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

/* Per-thread context */
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

/* Global state */
typedef struct {
    config_t        config;
    thread_ctx_t    threads[MAX_THREADS];
    pthread_t       thread_handles[MAX_THREADS];
    volatile int    running;
    uint64_t        start_ns;         /* clock_gettime at start */
    double          peak_gbps;        /* highest 1-second Gbps */
    uint64_t        prev_bytes;       /* bytes at previous 1s tick */
    volatile int64_t packets_remaining; /* shared atomic, counts down */
    volatile int64_t bytes_remaining;   /* shared atomic, counts down */
} blast_state_t;

#endif /* ARKIMEBLAST_CONFIG_H */
