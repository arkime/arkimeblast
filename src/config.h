#ifndef ARKIMEBLAST_CONFIG_H
#define ARKIMEBLAST_CONFIG_H

/* Standalone blaster config: the portable generator definitions plus the
 * pthread / AF_PACKET TX-ring bits used only by the standalone binary
 * (main.c, afpacket.c, stats.c). The Arkime reader plugin includes only
 * config-core.h and never needs anything below. */

#include "config-core.h"
#include <pthread.h>

/* TX ring defaults — sized for 20Gbps+ */
#define TX_RING_BLOCK_SIZE  (1 << 22)  /* 4MB per block */
#define TX_RING_BLOCK_NR    256        /* 1GB total ring per thread */
#define TX_RING_FRAME_SIZE  (1 << 11)  /* 2048 per frame */
#define TX_FLUSH_INTERVAL   256        /* frames between sendto kicks */

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
