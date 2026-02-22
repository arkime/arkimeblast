#ifndef ARKIMEBLAST_RATELIMIT_H
#define ARKIMEBLAST_RATELIMIT_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    double   bytes_per_ns;    /* target rate */
    double   tokens;          /* available tokens (bytes) */
    double   max_burst;       /* max burst size */
    uint64_t last_ns;         /* last refill timestamp */
} ratelimiter_t;

/* Initialize rate limiter for target_gbps */
void ratelimit_init(ratelimiter_t *rl, double target_gbps);

/* Wait until enough tokens are available for 'bytes' bytes.
 * Spins using clock_gettime for precision. */
void ratelimit_wait(ratelimiter_t *rl, size_t bytes);

/* Get current time in nanoseconds */
uint64_t now_ns(void);

#endif /* ARKIMEBLAST_RATELIMIT_H */
