#ifndef ARKIMEBLAST_SESSION_H
#define ARKIMEBLAST_SESSION_H

#include <stdint.h>
#include <stddef.h>
#include "config-core.h"

typedef enum {
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_DNS
} protocol_t;

typedef enum {
    /* TCP states */
    SESS_TCP_SYN,
    SESS_TCP_SYNACK,
    SESS_TCP_ACK_HANDSHAKE,

    /* TLS states (HTTPS only) */
    SESS_TLS_CLIENT_HELLO,
    SESS_TLS_SERVER_HELLO,
    SESS_TLS_SERVER_CERT,
    SESS_TLS_CLIENT_KEY_EXCHANGE,
    SESS_TLS_CHANGE_CIPHER_SPEC_CLIENT,
    SESS_TLS_CHANGE_CIPHER_SPEC_SERVER,
    SESS_TLS_APP_DATA,

    /* HTTP states */
    SESS_HTTP_REQUEST,
    SESS_HTTP_RESPONSE,

    /* TCP teardown */
    SESS_TCP_FIN_CLIENT,
    SESS_TCP_FINACK_SERVER,
    SESS_TCP_ACK_FINAL,

    /* DNS states */
    SESS_DNS_QUERY,
    SESS_DNS_RESPONSE,

    /* Done */
    SESS_DONE
} session_state_t;

typedef struct {
    protocol_t     proto;
    session_state_t state;

    /* Addresses */
    uint32_t       src_ip;
    uint32_t       dst_ip;
    uint16_t       src_port;
    uint16_t       dst_port;

    /* TCP state */
    uint32_t       client_seq;
    uint32_t       server_seq;
    uint32_t       client_ack;
    uint32_t       server_ack;
    uint16_t       ip_id;

    /* HTTP content tracking */
    size_t         request_len;
    size_t         response_len;
    size_t         response_sent;

    /* TLS version for this session (0x0301=1.0, 0x0303=1.2, 0x0304=1.3) */
    uint16_t       tls_version;

    /* DNS transaction ID */
    uint16_t       dns_txid;
    uint16_t       dns_qtype;

    /* Retransmit / drop flags */
    int            retransmit_pending;
    uint8_t        retransmit_buf[MAX_PACKET_SIZE];
    size_t         retransmit_len;
} session_t;

/* Initialize a new session with random addresses from config */
void session_init(session_t *sess, protocol_t proto, thread_ctx_t *ctx);

/* Advance the session state machine. Writes next packet to buf.
 * Returns frame length (>0), 0 if session is done, -1 to skip (drop). */
int session_step(session_t *sess, uint8_t *buf, thread_ctx_t *ctx);

#endif /* ARKIMEBLAST_SESSION_H */
