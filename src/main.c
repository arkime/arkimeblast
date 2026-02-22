#define _GNU_SOURCE

#include "config.h"
#include "afpacket.h"
#include "net_utils.h"
#include "ratelimit.h"
#include "session.h"
#include "stats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>
#include <net/if.h>
#include <sched.h>

static blast_state_t g_state;

static void signal_handler(int sig)
{
    (void)sig;
    g_state.running = 0;
}

/* Detect physical CPU core count (not hyperthreads) */
static int detect_physical_cores(void)
{
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list", "r");
    int threads_per_core = 1;
    if (f) {
        char buf[64];
        if (fgets(buf, sizeof(buf), f)) {
            /* Count commas + ranges */
            int count = 1;
            for (char *p = buf; *p; p++) {
                if (*p == ',' || *p == '-') count++;
            }
            /* Rough: if has '-' it's a range like "0-1" meaning 2 threads */
            if (strchr(buf, '-'))
                threads_per_core = 2;
            else
                threads_per_core = count;
        }
        fclose(f);
    }

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1) nproc = 1;

    int cores = (int)(nproc / threads_per_core);
    return cores > 0 ? cores : 1;
}

/* Pick a protocol based on configured mix ratios */
static protocol_t pick_protocol(thread_ctx_t *ctx)
{
    config_t *cfg = ctx->config;
    uint32_t r = rng_range(ctx->rng_state, 100);
    if (r < (uint32_t)cfg->mix_http)
        return PROTO_HTTP;
    if (r < (uint32_t)(cfg->mix_http + cfg->mix_https))
        return PROTO_HTTPS;
    return PROTO_DNS;
}

static void *worker_thread(void *arg)
{
    thread_ctx_t *ctx = (thread_ctx_t *)arg;

    /* Setup AF_PACKET */
    if (afpacket_setup(ctx) < 0) {
        fprintf(stderr, "Thread %d: AF_PACKET setup failed\n", ctx->thread_id);
        return NULL;
    }

    /* Initialize rate limiter */
    ratelimiter_t rl;
    double thread_gbps = ctx->config->gbps / ctx->config->num_threads;
    ratelimit_init(&rl, thread_gbps);

    /* Compute per-thread limits */
    int has_pkt_limit  = ctx->config->max_packets > 0;
    /* Batch size for atomic counter updates — trades precision for throughput */
    const int batch_size = 64;
    int batch_count = 0;

    uint8_t pkt_buf[MAX_PACKET_SIZE];
    session_t session;
    int need_new_session = 1;

    while (*ctx->running) {
        if (need_new_session) {
            protocol_t proto = pick_protocol(ctx);
            session_init(&session, proto, ctx);
            ctx->stats.sessions_started++;
            switch (proto) {
            case PROTO_HTTP:  ctx->stats.http_sessions++;  break;
            case PROTO_HTTPS: ctx->stats.https_sessions++; break;
            case PROTO_DNS:   ctx->stats.dns_sessions++;   break;
            }
            need_new_session = 0;
        }

        int len = session_step(&session, pkt_buf, ctx);
        if (len == 0) {
            /* Session done */
            need_new_session = 1;
            continue;
        }
        if (len < 0) {
            /* Dropped packet — skip sending but continue session */
            continue;
        }

        ratelimit_wait(&rl, (size_t)len);

        if (afpacket_send(ctx, pkt_buf, (size_t)len) == 0) {
            ctx->stats.packets_sent++;
            ctx->stats.bytes_sent += (uint64_t)len;

            /* Check limits via shared atomic counter every batch_size packets */
            if (++batch_count >= batch_size) {
                if (has_pkt_limit) {
                    int64_t rem = __sync_sub_and_fetch(
                        ctx->packets_remaining, (int64_t)batch_count);
                    if (rem <= 0) {
                        *ctx->running = 0;
                        break;
                    }
                }
                batch_count = 0;
            }
        }
    }

    /* Flush and cleanup */
    afpacket_cleanup(ctx);
    return NULL;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n\n"
        "  -i, --interface <iface>     Network interface (required)\n"
        "      --gbps <rate>           Target Gbps (default: %.1f)\n"
        "      --threads <N>           Sending threads (default: physical cores)\n"
        "      --mix <proto:pct,...>    Traffic mix (default: http:%d,https:%d,dns:%d)\n"
        "      --subnet-src <CIDR>     Source subnet (default: %s)\n"
        "      --subnet-dst <CIDR>     Dest subnet (default: %s)\n"
        "      --duration <sec>        Duration, 0=infinite (default: %d)\n"
        "      --max-packets <N>       Stop after N packets (default: unlimited)\n"
        "      --max-gb <N>            Stop after N gigabytes sent (default: unlimited)\n"
        "      --seed <N>              RNG seed (default: %d)\n"
        "  -v, --verbose               Per-second stats\n"
        "  -h, --help                  Show this help\n\n",
        prog, DEFAULT_GBPS,
        DEFAULT_MIX_HTTP, DEFAULT_MIX_HTTPS, DEFAULT_MIX_DNS,
        DEFAULT_SUBNET_SRC, DEFAULT_SUBNET_DST,
        DEFAULT_DURATION, DEFAULT_SEED);
}

/* Parse --mix http:50,https:40,dns:10 */
static int parse_mix(const char *arg, int *http, int *https, int *dns)
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

int main(int argc, char *argv[])
{
    memset(&g_state, 0, sizeof(g_state));

    config_t *cfg = &g_state.config;
    cfg->gbps       = DEFAULT_GBPS;
    cfg->num_threads = 0; /* auto-detect */
    cfg->mix_http   = DEFAULT_MIX_HTTP;
    cfg->mix_https  = DEFAULT_MIX_HTTPS;
    cfg->mix_dns    = DEFAULT_MIX_DNS;
    cfg->duration   = DEFAULT_DURATION;
    cfg->max_packets = 0;
    cfg->max_gbytes  = 0;
    cfg->seed       = DEFAULT_SEED;
    cfg->verbose    = 0;

    if (parse_cidr(DEFAULT_SUBNET_SRC, &cfg->subnet_src) < 0 ||
        parse_cidr(DEFAULT_SUBNET_DST, &cfg->subnet_dst) < 0) {
        fprintf(stderr, "Internal error parsing default subnets\n");
        return 1;
    }

    static struct option long_opts[] = {
        {"interface",  required_argument, 0, 'i'},
        {"gbps",       required_argument, 0, 'g'},
        {"threads",    required_argument, 0, 't'},
        {"mix",        required_argument, 0, 'm'},
        {"subnet-src", required_argument, 0, 'S'},
        {"subnet-dst", required_argument, 0, 'D'},
        {"duration",   required_argument, 0, 'd'},
        {"max-packets",required_argument, 0, 'P'},
        {"max-gb",     required_argument, 0, 'G'},
        {"seed",       required_argument, 0, 's'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            strncpy(cfg->interface, optarg, sizeof(cfg->interface) - 1);
            break;
        case 'g':
            cfg->gbps = atof(optarg);
            if (cfg->gbps <= 0) { fprintf(stderr, "Invalid --gbps\n"); return 1; }
            break;
        case 't':
            cfg->num_threads = atoi(optarg);
            if (cfg->num_threads < 1 || cfg->num_threads > MAX_THREADS) {
                fprintf(stderr, "Invalid --threads (1-%d)\n", MAX_THREADS);
                return 1;
            }
            break;
        case 'm':
            if (parse_mix(optarg, &cfg->mix_http, &cfg->mix_https, &cfg->mix_dns) < 0)
                return 1;
            break;
        case 'S':
            if (parse_cidr(optarg, &cfg->subnet_src) < 0) {
                fprintf(stderr, "Invalid --subnet-src\n");
                return 1;
            }
            break;
        case 'D':
            if (parse_cidr(optarg, &cfg->subnet_dst) < 0) {
                fprintf(stderr, "Invalid --subnet-dst\n");
                return 1;
            }
            break;
        case 'd':
            cfg->duration = (uint64_t)atoll(optarg);
            break;
        case 'P':
            cfg->max_packets = (uint64_t)atoll(optarg);
            break;
        case 'G':
            cfg->max_gbytes = (uint64_t)atoll(optarg);
            break;
        case 's':
            cfg->seed = (uint64_t)atoll(optarg);
            break;
        case 'v':
            cfg->verbose = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (cfg->interface[0] == '\0') {
        fprintf(stderr, "Error: -i/--interface is required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    cfg->if_index = (int)if_nametoindex(cfg->interface);
    if (cfg->if_index == 0) {
        fprintf(stderr, "Error: interface '%s' not found\n", cfg->interface);
        return 1;
    }

    if (cfg->num_threads == 0)
        cfg->num_threads = detect_physical_cores();

    /* Print config */
    fprintf(stderr,
        "arkimeblast v%s\n"
        "  Interface:    %s (index %d)\n"
        "  Target:       %.2f Gbps\n"
        "  Threads:      %d\n"
        "  Mix:          http:%d%% https:%d%% dns:%d%%\n"
        "  Src subnet:   %u.%u.%u.%u/%d\n"
        "  Dst subnet:   %u.%u.%u.%u/%d\n"
        "  Duration:     %s\n"
        "  Max packets:  %s\n"
        "  Max GB:       %s\n"
        "  Seed:         %lu\n\n",
        ARKIMEBLAST_VERSION,
        cfg->interface, cfg->if_index,
        cfg->gbps, cfg->num_threads,
        cfg->mix_http, cfg->mix_https, cfg->mix_dns,
        (cfg->subnet_src.base >> 24) & 0xff,
        (cfg->subnet_src.base >> 16) & 0xff,
        (cfg->subnet_src.base >> 8) & 0xff,
        cfg->subnet_src.base & 0xff,
        32 - cfg->subnet_src.mask,
        (cfg->subnet_dst.base >> 24) & 0xff,
        (cfg->subnet_dst.base >> 16) & 0xff,
        (cfg->subnet_dst.base >> 8) & 0xff,
        cfg->subnet_dst.base & 0xff,
        32 - cfg->subnet_dst.mask,
        cfg->duration ? "finite" : "infinite",
        cfg->max_packets ? "set" : "unlimited",
        cfg->max_gbytes ? "set" : "unlimited",
        cfg->seed);

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    g_state.running = 1;
    g_state.start_ns = now_ns();
    g_state.peak_gbps = 0;
    g_state.prev_bytes = 0;
    g_state.packets_remaining = (int64_t)cfg->max_packets;
    g_state.bytes_remaining   = (int64_t)(cfg->max_gbytes * 1000000000ULL);

    /* Spawn worker threads */
    for (int i = 0; i < cfg->num_threads; i++) {
        thread_ctx_t *t = &g_state.threads[i];
        t->thread_id = i;
        t->config    = cfg;
        t->running   = &g_state.running;
        t->packets_remaining = &g_state.packets_remaining;
        t->sock_fd   = -1;
        memset(&t->stats, 0, sizeof(t->stats));
        rng_seed(t->rng_state, cfg->seed + (uint64_t)i);

        if (pthread_create(&g_state.thread_handles[i], NULL, worker_thread, t) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            g_state.running = 0;
            break;
        }
    }

    fprintf(stderr, "Sending traffic... (Ctrl-C to stop)\n\n");

    /* Main loop: print stats, check duration/limits */
    while (g_state.running) {
        usleep(1000000); /* 1 second */

        double elapsed = (double)(now_ns() - g_state.start_ns) / 1e9;

        if (cfg->verbose)
            stats_print_line(&g_state, elapsed);

        if (cfg->duration > 0 && elapsed >= (double)cfg->duration) {
            g_state.running = 0;
            break;
        }

        /* Check packet/byte limits */
        if (cfg->max_packets > 0 || cfg->max_gbytes > 0) {
            thread_stats_t agg;
            stats_aggregate(&g_state, &agg);

            if (cfg->max_packets > 0 && agg.packets_sent >= cfg->max_packets) {
                fprintf(stderr, "\nPacket limit reached (%" PRIu64 ")\n",
                    cfg->max_packets);
                g_state.running = 0;
                break;
            }
            if (cfg->max_gbytes > 0 &&
                agg.bytes_sent >= cfg->max_gbytes * 1000000000ULL) {
                fprintf(stderr, "\nByte limit reached (%" PRIu64 " GB)\n",
                    cfg->max_gbytes);
                g_state.running = 0;
                break;
            }
        }
    }

    /* Wait for threads to finish */
    for (int i = 0; i < cfg->num_threads; i++)
        pthread_join(g_state.thread_handles[i], NULL);

    /* Final stats */
    double elapsed = (double)(now_ns() - g_state.start_ns) / 1e9;
    stats_print_summary(&g_state, elapsed);

    return 0;
}
