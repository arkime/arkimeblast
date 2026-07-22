/******************************************************************************/
/* reader-synthetic.c -- Arkime reader plugin that generates synthetic packets
 *
 * pcapReadMethod=synthetic
 *
 * Reuses the arkimeblast packet generator (../src) to manufacture HTTP/HTTPS/DNS
 * traffic directly into Arkime's capture pipeline -- no pcap files, no live NIC.
 * Output is deterministic: the same seed produces the exact same packets and,
 * via a synthetic clock, the exact same timestamps every run.
 *
 * Build:  cd plugin && make ARKIME=../../arkime      (-> reader-synthetic.so)
 * Load:   rootPlugins=reader-synthetic.so  (NOT plugins= -- must load before
 *         the reader is selected), pcapReadMethod=synthetic
 * Config: one key, arkimeBlastCmdLine, holding arkimeblast-style options, e.g.
 *           arkimeBlastCmdLine=--seed 42 --max-sessions 20 --mix http:100,https:0,dns:0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>

#include "arkime.h"

/* arkimeblast generator (portable half only -- see config-core.h) */
#include "config-core.h"
#include "net_utils.h"
#include "session.h"

extern ArkimeConfig_t config;

/* ---- module state ---------------------------------------------------------*/
#define SYN_MAX_THREADS 64

LOCAL config_t      synConfig;      /* mix + subnets, reused by the generator  */

LOCAL uint64_t      maxSessions = 100;  /* 0 = unbounded, split over threads   */
LOCAL uint64_t      maxPackets  = 0;    /* 0 = unbounded, split over threads   */
LOCAL int           runForever  = 0;    /* ignore counts, never auto-quit      */
LOCAL int           numThreads  = 1;    /* generator/reader threads            */
LOCAL uint64_t      seed        = 0;

LOCAL uint64_t      baseTimeUS  = 1700000000ULL * 1000000ULL; /* synth clock   */
LOCAL uint64_t      timeDeltaUS = 100;  /* per-packet timestamp increment (us) */

/* Per generator thread state. Cache aligned so the counters of one thread
 * never share a line with another's -- this reader is used for capture
 * performance work, it shouldn't add false sharing of its own. */
typedef struct {
    thread_ctx_t  ctx;          /* generator context (config/rng/stats)        */
    uint64_t      clockUS;      /* this thread's synthetic clock               */
    uint64_t      maxSessions;  /* this thread's share of the limits           */
    uint64_t      maxPackets;
    uint64_t      packets;
    uint64_t      dropped;
    uint64_t      sessions;
    int           id;
} ARKIME_CACHE_ALIGN SynThread_t;

LOCAL SynThread_t   synThreads[SYN_MAX_THREADS];
LOCAL int           synThreadsDone;     /* atomic, last one out calls quit     */

/* ---- helpers --------------------------------------------------------------*/
LOCAL protocol_t pick_protocol(thread_ctx_t *ctx)
{
    config_t *cfg = ctx->config;
    uint32_t r = rng_range(ctx->rng_state, 100);
    if (r < (uint32_t)cfg->mix_http)
        return PROTO_HTTP;
    if (r < (uint32_t)(cfg->mix_http + cfg->mix_https))
        return PROTO_HTTPS;
    return PROTO_DNS;
}

/* Deterministic timestamp: base time + fixed increment per emitted packet.
 * Thread t starts at base + t*delta and steps by delta*numThreads, so every
 * thread has its own deterministic clock and no two share a timestamp. */
LOCAL struct timeval synthetic_next_ts(SynThread_t *st)
{
    struct timeval tv;
    tv.tv_sec  = st->clockUS / 1000000ULL;
    tv.tv_usec = st->clockUS % 1000000ULL;
    st->clockUS += timeDeltaUS * numThreads;
    return tv;
}

/* Parse the arkimeBlastCmdLine string into synConfig/limits/seed. */
LOCAL void synthetic_parse_cmdline(void)
{
    gchar *line = arkime_config_str(NULL, "arkimeBlastCmdLine", "");
    /* Tokenize on whitespace into a throwaway argv (values contain no spaces). */
    char *argv[64];
    int   argc = 0;
    argv[argc++] = "reader-synthetic";
    char *save = NULL;
    for (char *tok = line ? strtok_r(line, " \t", &save) : NULL; tok && argc < 63;
         tok = strtok_r(NULL, " \t", &save)) {
        argv[argc++] = tok;
    }
    argv[argc] = NULL;

    static struct option long_opts[] = {
        /* accepted-and-ignored (delivery-only, for blast CLI compatibility) */
        {"interface",   required_argument, 0, 'i'},
        {"gbps",        required_argument, 0, 'g'},
        {"threads",     required_argument, 0, 't'},
        {"duration",    required_argument, 0, 'd'},
        {"max-gb",      required_argument, 0, 'G'},
        {"verbose",     no_argument,       0, 'v'},
        /* honored */
        {"mix",         required_argument, 0, 'm'},
        {"subnet-src",  required_argument, 0, 'S'},
        {"subnet-dst",  required_argument, 0, 'D'},
        {"max-packets", required_argument, 0, 'P'},
        {"seed",        required_argument, 0, 's'},
        /* plugin-only */
        {"max-sessions",   required_argument, 0, 'M'},
        {"base-time",      required_argument, 0, 'b'},
        {"time-delta",     required_argument, 0, 'T'},
        {"run-forever",    no_argument,       0, 'f'},
        {"reader-threads", required_argument, 0, 'R'},
        {0, 0, 0, 0}
    };

    /* Capture already ran getopt for its own argv; fully reset before reuse. */
#if defined(__GLIBC__)
    optind = 0;
#else
    optind = 1;
    optreset = 1;
#endif
    opterr = 0; /* stay quiet on unknown flags rather than spamming stderr */

    int opt;
    while ((opt = getopt_long(argc, argv, "i:g:t:d:G:vm:S:D:P:s:M:b:T:fR:",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            if (parse_mix(optarg, &synConfig.mix_http, &synConfig.mix_https,
                          &synConfig.mix_dns) < 0)
                CONFIGEXIT("arkimeBlastCmdLine: bad --mix '%s'", optarg);
            break;
        case 'S':
            if (parse_cidr(optarg, &synConfig.subnet_src) < 0)
                CONFIGEXIT("arkimeBlastCmdLine: bad --subnet-src '%s'", optarg);
            break;
        case 'D':
            if (parse_cidr(optarg, &synConfig.subnet_dst) < 0)
                CONFIGEXIT("arkimeBlastCmdLine: bad --subnet-dst '%s'", optarg);
            break;
        case 'P': maxPackets  = (uint64_t)strtoull(optarg, NULL, 10); break;
        case 's': seed        = (uint64_t)strtoull(optarg, NULL, 10); break;
        case 'M': maxSessions = (uint64_t)strtoull(optarg, NULL, 10); break;
        case 'b':
            baseTimeUS = (uint64_t)strtoull(optarg, NULL, 10) * 1000000ULL;
            break;
        case 'T': timeDeltaUS = (uint64_t)strtoull(optarg, NULL, 10); break;
        case 'f': runForever  = 1; break;
        case 'R':
            numThreads = atoi(optarg);
            if (numThreads < 1 || numThreads > SYN_MAX_THREADS)
                CONFIGEXIT("arkimeBlastCmdLine: --reader-threads must be 1-%d, not '%s'",
                           SYN_MAX_THREADS, optarg);
            break;
        default:  break; /* ignored / unknown */
        }
    }
}

/* Give each thread its own rng stream, clock offset and share of the limits,
 * so a run is reproducible per thread no matter how the threads interleave. */
LOCAL void synthetic_threads_init(void)
{
    for (int t = 0; t < numThreads; t++) {
        SynThread_t *st = &synThreads[t];

        st->id          = t;
        st->ctx.config  = &synConfig;
        st->ctx.thread_id = t;
        st->clockUS     = baseTimeUS + (uint64_t)t * timeDeltaUS;
        st->maxSessions = maxSessions / numThreads;
        st->maxPackets  = maxPackets / numThreads;
        if (t == 0) {  /* thread 0 also takes the remainder */
            st->maxSessions += maxSessions % numThreads;
            st->maxPackets  += maxPackets % numThreads;
        }
        rng_seed(st->ctx.rng_state, seed + t);
    }
}

/* ---- reader thread --------------------------------------------------------*/
LOCAL void *synthetic_thread(gpointer uw)
{
    SynThread_t *st = (SynThread_t *)uw;

    int initFunc = arkime_get_named_func("arkime_reader_thread_init");
    arkime_call_named_func(initFunc, st->id, NULL);

    ArkimePacketBatch_t batch;
    arkime_packet_batch_init(&batch);

    uint8_t   buf[MAX_PACKET_SIZE];  /* reused; arkime_packet_batch copies it   */
    session_t session;
    int       need_new = 1;

    while (!config.quitting) {
        if (!runForever) {
            /* limits are global switches, the counts are this thread's share */
            if (maxSessions && st->sessions >= st->maxSessions) break;
            if (maxPackets  && st->packets  >= st->maxPackets)  break;
        }

        if (need_new) {
            protocol_t proto = pick_protocol(&st->ctx);
            session_init(&session, proto, &st->ctx);
            st->sessions++;
            need_new = 0;
        }

        int len = session_step(&session, buf, &st->ctx);
        if (len == 0) { need_new = 1; continue; }  /* session complete         */
        if (len < 0)  { st->dropped++; continue; } /* simulated drop           */
        if (len <= 4) continue;                    /* batch would reject       */

        ArkimePacket_t *packet = arkime_packet_alloc();
        packet->pkt       = buf;
        packet->pktlen    = len;
        packet->readerPos = 0;
        packet->ts        = synthetic_next_ts(st);
        /* copied stays 0 -> arkime_packet_batch mallocs+copies buf on enqueue */

        arkime_packet_batch(&batch, packet);
        arkime_packet_batch_flush(&batch);
        st->packets++;
    }

    arkime_packet_batch_flush(&batch);

    int exitFunc = arkime_get_named_func("arkime_reader_thread_exit");
    arkime_call_named_func(exitFunc, st->id, NULL);

    /* Input exhausted: once every thread is done tell capture to drain
     * sessions to ES and exit. */
    if (!runForever && __sync_add_and_fetch(&synThreadsDone, 1) == numThreads)
        arkime_quit();

    return NULL;
}

/* ---- reader interface -----------------------------------------------------*/
LOCAL void synthetic_start(void)
{
    char name[32];

    /* One thread => fully deterministic emission order. With more, each
     * thread is deterministic on its own but they interleave freely. */
    for (int t = 0; t < numThreads; t++) {
        snprintf(name, sizeof(name), "reader-syn%d", t);
        g_thread_unref(g_thread_new(name, &synthetic_thread, &synThreads[t]));
    }
}

LOCAL int synthetic_stats(ArkimeReaderStats_t *stats)
{
    stats->total   = 0;
    stats->dropped = 0;
    for (int t = 0; t < numThreads; t++) {
        stats->total   += synThreads[t].packets;
        stats->dropped += synThreads[t].dropped;
    }
    return 0;
}

LOCAL void reader_synthetic_init(const char *UNUSED(name))
{
    /* Defaults mirror arkimeblast. */
    synConfig.mix_http  = DEFAULT_MIX_HTTP;
    synConfig.mix_https = DEFAULT_MIX_HTTPS;
    synConfig.mix_dns   = DEFAULT_MIX_DNS;
    parse_cidr(DEFAULT_SUBNET_SRC, &synConfig.subnet_src);
    parse_cidr(DEFAULT_SUBNET_DST, &synConfig.subnet_dst);

    synthetic_parse_cmdline();
    synthetic_threads_init();

    arkime_reader_start = synthetic_start;
    arkime_reader_stats = synthetic_stats;

    /* Generated frames are full Ethernet (ethertype 0x0800 / 0x86dd). */
    arkime_packet_set_dltsnap(DLT_EN10MB, config.snapLen);
}

/* ---- plugin entry point ---------------------------------------------------*/
void arkime_plugin_init(void)
{
    arkime_readers_add("synthetic", reader_synthetic_init);
}
