#include "stats.h"

#include <stdio.h>
#include <inttypes.h>

void stats_aggregate(blast_state_t *state, thread_stats_t *out)
{
    out->packets_sent    = 0;
    out->bytes_sent      = 0;
    out->sessions_started = 0;
    out->http_sessions   = 0;
    out->https_sessions  = 0;
    out->dns_sessions    = 0;
    out->retransmits     = 0;
    out->drops           = 0;

    for (int i = 0; i < state->config.num_threads; i++) {
        thread_stats_t *ts = &state->threads[i].stats;
        out->packets_sent    += ts->packets_sent;
        out->bytes_sent      += ts->bytes_sent;
        out->sessions_started += ts->sessions_started;
        out->http_sessions   += ts->http_sessions;
        out->https_sessions  += ts->https_sessions;
        out->dns_sessions    += ts->dns_sessions;
        out->retransmits     += ts->retransmits;
        out->drops           += ts->drops;
    }
}

void stats_print_line(blast_state_t *state, double elapsed_sec)
{
    thread_stats_t agg;
    stats_aggregate(state, &agg);

    uint64_t delta_bytes = agg.bytes_sent - state->prev_bytes;
    double current_gbps = (double)delta_bytes * 8.0 / 1e9;

    if (current_gbps > state->peak_gbps)
        state->peak_gbps = current_gbps;

    state->prev_bytes = agg.bytes_sent;

    double avg_gbps = (elapsed_sec > 0) ? (double)agg.bytes_sent * 8.0 / elapsed_sec / 1e9 : 0;

    fprintf(stderr,
        "\r[%6.1fs] %'" PRIu64 " pkts | %.2f Gbps (avg %.2f) | "
        "%'" PRIu64 " sess (H:%'" PRIu64 " S:%'" PRIu64 " D:%'" PRIu64 ") | "
        "retx:%'" PRIu64 " drop:%'" PRIu64 "  ",
        elapsed_sec,
        agg.packets_sent, current_gbps, avg_gbps,
        agg.sessions_started,
        agg.http_sessions, agg.https_sessions, agg.dns_sessions,
        agg.retransmits, agg.drops);
}

void stats_print_summary(blast_state_t *state, double elapsed_sec)
{
    thread_stats_t agg;
    stats_aggregate(state, &agg);

    double avg_gbps = (elapsed_sec > 0) ? (double)agg.bytes_sent * 8.0 / elapsed_sec / 1e9 : 0;
    double avg_pps  = (elapsed_sec > 0) ? (double)agg.packets_sent / elapsed_sec : 0;

    int hours = (int)(elapsed_sec / 3600);
    int mins  = (int)((elapsed_sec - hours * 3600) / 60);
    double secs = elapsed_sec - hours * 3600 - mins * 60;

    fprintf(stderr, "\n\n");
    fprintf(stderr, "╔══════════════════════════════════════════════╗\n");
    fprintf(stderr, "║           arkimeblast — Summary              ║\n");
    fprintf(stderr, "╠══════════════════════════════════════════════╣\n");
    fprintf(stderr, "║  Runtime:        %02d:%02d:%05.2f                 ║\n", hours, mins, secs);
    fprintf(stderr, "╠══════════════════════════════════════════════╣\n");
    fprintf(stderr, "║  Packets sent:   %-28" PRIu64 "║\n", agg.packets_sent);
    fprintf(stderr, "║  Bytes sent:     %-28" PRIu64 "║\n", agg.bytes_sent);
    fprintf(stderr, "║  Avg Gbps:       %-28.3f║\n", avg_gbps);
    fprintf(stderr, "║  Peak Gbps:      %-28.3f║\n", state->peak_gbps);
    fprintf(stderr, "║  Avg PPS:        %-28.0f║\n", avg_pps);
    fprintf(stderr, "╠══════════════════════════════════════════════╣\n");
    fprintf(stderr, "║  Sessions:       %-28" PRIu64 "║\n", agg.sessions_started);
    fprintf(stderr, "║    HTTP:         %-28" PRIu64 "║\n", agg.http_sessions);
    fprintf(stderr, "║    HTTPS:        %-28" PRIu64 "║\n", agg.https_sessions);
    fprintf(stderr, "║    DNS:          %-28" PRIu64 "║\n", agg.dns_sessions);
    fprintf(stderr, "╠══════════════════════════════════════════════╣\n");
    fprintf(stderr, "║  Retransmits:    %-28" PRIu64 "║\n", agg.retransmits);
    fprintf(stderr, "║  Dropped pkts:   %-28" PRIu64 "║\n", agg.drops);
    fprintf(stderr, "╚══════════════════════════════════════════════╝\n");
}
