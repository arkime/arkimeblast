#ifndef ARKIMEBLAST_AFPACKET_H
#define ARKIMEBLAST_AFPACKET_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

/* Create AF_PACKET socket and mmap TX ring. Returns 0 on success. */
int afpacket_setup(thread_ctx_t *ctx);

/* Send a raw frame via TX ring. Returns 0 on success. */
int afpacket_send(thread_ctx_t *ctx, const uint8_t *frame, size_t len);

/* Cleanup: unmap ring and close socket */
void afpacket_cleanup(thread_ctx_t *ctx);

#endif /* ARKIMEBLAST_AFPACKET_H */
