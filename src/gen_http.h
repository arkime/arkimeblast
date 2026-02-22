#ifndef ARKIMEBLAST_GEN_HTTP_H
#define ARKIMEBLAST_GEN_HTTP_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

/* Generate an HTTP request. Returns bytes written to buf. */
int gen_http_request(uint8_t *buf, size_t bufsize, uint64_t *rng);

/* Generate an HTTP response. Returns bytes written to buf.
 * body_size is filled with the total body size for Content-Length. */
int gen_http_response(uint8_t *buf, size_t bufsize, uint64_t *rng,
                      size_t *total_body_size);

/* Generate a chunk of HTTP response body. Returns bytes written. */
int gen_http_body_chunk(uint8_t *buf, size_t bufsize, size_t offset,
                        size_t total_size, uint64_t *rng);

#endif /* ARKIMEBLAST_GEN_HTTP_H */
