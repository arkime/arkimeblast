#ifndef ARKIMEBLAST_GEN_TCP_H
#define ARKIMEBLAST_GEN_TCP_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "session.h"

/* Build a TCP SYN packet. Returns total frame length. */
int gen_tcp_syn(uint8_t *buf, session_t *sess);

/* Build a TCP SYN-ACK packet. Returns total frame length. */
int gen_tcp_synack(uint8_t *buf, session_t *sess);

/* Build a TCP ACK packet (no data). Returns total frame length. */
int gen_tcp_ack(uint8_t *buf, session_t *sess, int from_client);

/* Build a TCP data packet. Returns total frame length.
 * payload/payload_len: data to embed.
 * from_client: 1=client→server, 0=server→client */
int gen_tcp_data(uint8_t *buf, session_t *sess,
                 const uint8_t *payload, size_t payload_len,
                 int from_client);

/* Build a TCP FIN packet. Returns total frame length. */
int gen_tcp_fin(uint8_t *buf, session_t *sess, int from_client);

/* Build a TCP FIN-ACK packet. Returns total frame length. */
int gen_tcp_finack(uint8_t *buf, session_t *sess, int from_client);

#endif /* ARKIMEBLAST_GEN_TCP_H */
