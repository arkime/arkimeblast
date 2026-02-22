#ifndef ARKIMEBLAST_STATS_H
#define ARKIMEBLAST_STATS_H

#include "config.h"

/* Aggregate stats across all threads into out */
void stats_aggregate(blast_state_t *state, thread_stats_t *out);

/* Print per-second stats line (verbose mode). Updates peak_gbps. */
void stats_print_line(blast_state_t *state, double elapsed_sec);

/* Print final summary — always called on exit (normal or Ctrl-C) */
void stats_print_summary(blast_state_t *state, double elapsed_sec);

#endif /* ARKIMEBLAST_STATS_H */
