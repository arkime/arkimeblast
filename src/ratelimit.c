#include "ratelimit.h"

#include <time.h>

uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void ratelimit_init(ratelimiter_t *rl, double target_gbps)
{
    rl->bytes_per_ns = (target_gbps * 1e9) / 8.0 / 1e9; /* bytes per nanosecond */
    rl->max_burst    = target_gbps * 1e9 / 8.0 * 0.001;  /* 1ms burst */
    if (rl->max_burst < 65536)
        rl->max_burst = 65536;
    rl->tokens       = rl->max_burst;
    rl->last_ns      = now_ns();
}

void ratelimit_wait(ratelimiter_t *rl, size_t bytes)
{
    while (1) {
        uint64_t cur = now_ns();
        uint64_t elapsed = cur - rl->last_ns;
        rl->last_ns = cur;

        rl->tokens += elapsed * rl->bytes_per_ns;
        if (rl->tokens > rl->max_burst)
            rl->tokens = rl->max_burst;

        if (rl->tokens >= (double)bytes) {
            rl->tokens -= (double)bytes;
            return;
        }

        /* Spin-wait with a brief pause */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 };
        nanosleep(&ts, NULL);
    }
}
