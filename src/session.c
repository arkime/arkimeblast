#include "session.h"
#include "net_utils.h"
#include "gen_tcp.h"
#include "gen_http.h"
#include "gen_tls.h"
#include "gen_dns.h"

#include <string.h>

void session_init(session_t *sess, protocol_t proto, thread_ctx_t *ctx)
{
    memset(sess, 0, sizeof(*sess));
    sess->proto    = proto;
    sess->src_ip   = random_ip(&ctx->config->subnet_src, ctx->rng_state);
    sess->dst_ip   = random_ip(&ctx->config->subnet_dst, ctx->rng_state);
    sess->src_port = random_port(ctx->rng_state);
    sess->ip_id    = (uint16_t)rng_next(ctx->rng_state);

    switch (proto) {
    case PROTO_HTTP:
        sess->dst_port = 80;
        sess->state    = SESS_TCP_SYN;
        break;
    case PROTO_HTTPS:
        sess->dst_port   = 443;
        sess->tls_version = gen_tls_pick_version(ctx->rng_state);
        sess->state      = SESS_TCP_SYN;
        break;
    case PROTO_DNS:
        sess->dst_port = 53;
        sess->dns_txid = (uint16_t)rng_next(ctx->rng_state);
        sess->dns_qtype = gen_dns_pick_qtype(ctx->rng_state);
        sess->state    = SESS_DNS_QUERY;
        break;
    }
}

/* Check if we should simulate a retransmit (~1.5%) */
static int should_retransmit(thread_ctx_t *ctx)
{
    return rng_range(ctx->rng_state, 1000) < 15;
}

/* Check if we should simulate a drop (~0.5%) */
static int should_drop(thread_ctx_t *ctx)
{
    return rng_range(ctx->rng_state, 1000) < 5;
}

int session_step(session_t *sess, uint8_t *buf, thread_ctx_t *ctx)
{
    int len;

    /* If we have a pending retransmit, send it */
    if (sess->retransmit_pending) {
        memcpy(buf, sess->retransmit_buf, sess->retransmit_len);
        sess->retransmit_pending = 0;
        ctx->stats.retransmits++;
        return (int)sess->retransmit_len;
    }

    switch (sess->state) {

    /* ---- TCP Handshake ---- */
    case SESS_TCP_SYN:
        len = gen_tcp_syn(buf, sess);
        sess->state = SESS_TCP_SYNACK;
        return len;

    case SESS_TCP_SYNACK:
        len = gen_tcp_synack(buf, sess);
        sess->state = SESS_TCP_ACK_HANDSHAKE;
        return len;

    case SESS_TCP_ACK_HANDSHAKE:
        len = gen_tcp_ack(buf, sess, 1);
        if (sess->proto == PROTO_HTTPS)
            sess->state = SESS_TLS_CLIENT_HELLO;
        else
            sess->state = SESS_HTTP_REQUEST;
        return len;

    /* ---- TLS Handshake ---- */
    case SESS_TLS_CLIENT_HELLO: {
        uint8_t tls_buf[2048];
        int tls_len = gen_tls_client_hello(tls_buf, sizeof(tls_buf),
                                            sess->tls_version, ctx->rng_state);
        len = gen_tcp_data(buf, sess, tls_buf, (size_t)tls_len, 1);
        sess->state = SESS_TLS_SERVER_HELLO;
        if (should_retransmit(ctx)) {
            memcpy(sess->retransmit_buf, buf, len);
            sess->retransmit_len = (size_t)len;
            sess->retransmit_pending = 1;
        }
        return len;
    }

    case SESS_TLS_SERVER_HELLO: {
        uint8_t tls_buf[2048];
        int tls_len = gen_tls_server_hello(tls_buf, sizeof(tls_buf),
                                            sess->tls_version, ctx->rng_state);
        len = gen_tcp_data(buf, sess, tls_buf, (size_t)tls_len, 0);
        sess->state = SESS_TLS_SERVER_CERT;
        return len;
    }

    case SESS_TLS_SERVER_CERT: {
        uint8_t tls_buf[2048];
        int tls_len = gen_tls_certificate(tls_buf, sizeof(tls_buf), ctx->rng_state);
        len = gen_tcp_data(buf, sess, tls_buf, (size_t)tls_len, 0);
        if (sess->tls_version >= 0x0304)
            sess->state = SESS_TLS_CHANGE_CIPHER_SPEC_SERVER;
        else
            sess->state = SESS_TLS_CLIENT_KEY_EXCHANGE;
        return len;
    }

    case SESS_TLS_CLIENT_KEY_EXCHANGE: {
        uint8_t tls_buf[256];
        int tls_len = gen_tls_client_key_exchange(tls_buf, sizeof(tls_buf),
                                                   ctx->rng_state);
        len = gen_tcp_data(buf, sess, tls_buf, (size_t)tls_len, 1);
        sess->state = SESS_TLS_CHANGE_CIPHER_SPEC_CLIENT;
        return len;
    }

    case SESS_TLS_CHANGE_CIPHER_SPEC_CLIENT: {
        uint8_t tls_buf[16];
        int tls_len = gen_tls_change_cipher_spec(tls_buf, sizeof(tls_buf));
        len = gen_tcp_data(buf, sess, tls_buf, (size_t)tls_len, 1);
        sess->state = SESS_TLS_CHANGE_CIPHER_SPEC_SERVER;
        return len;
    }

    case SESS_TLS_CHANGE_CIPHER_SPEC_SERVER: {
        uint8_t tls_buf[16];
        int tls_len = gen_tls_change_cipher_spec(tls_buf, sizeof(tls_buf));
        len = gen_tcp_data(buf, sess, tls_buf, (size_t)tls_len, 0);
        sess->state = SESS_TLS_APP_DATA;
        return len;
    }

    case SESS_TLS_APP_DATA: {
        /* Send some encrypted data back and forth, then teardown */
        uint8_t tls_buf[MSS];
        size_t payload_len = 200 + rng_range(ctx->rng_state, MSS - 200);
        int tls_len = gen_tls_app_data(tls_buf, sizeof(tls_buf),
                                        payload_len, ctx->rng_state);
        int from_client = rng_range(ctx->rng_state, 2);
        len = gen_tcp_data(buf, sess, tls_buf, (size_t)tls_len, from_client);

        /* After 2-6 app data records, start teardown */
        sess->response_sent++;
        if (sess->response_sent >= 2 + rng_range(ctx->rng_state, 5))
            sess->state = SESS_TCP_FIN_CLIENT;

        if (should_drop(ctx)) {
            ctx->stats.drops++;
            return -1; /* simulate drop */
        }
        if (should_retransmit(ctx)) {
            memcpy(sess->retransmit_buf, buf, len);
            sess->retransmit_len = (size_t)len;
            sess->retransmit_pending = 1;
        }
        return len;
    }

    /* ---- HTTP ---- */
    case SESS_HTTP_REQUEST: {
        uint8_t http_buf[4096];
        int http_len = gen_http_request(http_buf, sizeof(http_buf), ctx->rng_state);
        sess->request_len = (size_t)http_len;

        /* May need multiple TCP segments */
        size_t to_send = (size_t)http_len;
        if (to_send > MSS) to_send = MSS;
        len = gen_tcp_data(buf, sess, http_buf, to_send, 1);

        if (should_drop(ctx)) {
            ctx->stats.drops++;
            return -1;
        }
        sess->state = SESS_HTTP_RESPONSE;
        return len;
    }

    case SESS_HTTP_RESPONSE: {
        if (sess->response_len == 0) {
            /* Generate response headers */
            uint8_t http_buf[4096];
            size_t body_size;
            int http_len = gen_http_response(http_buf, sizeof(http_buf),
                                              ctx->rng_state, &body_size);
            sess->response_len = (size_t)http_len + body_size;
            sess->response_sent = 0;

            size_t to_send = (size_t)http_len;
            if (to_send > MSS) to_send = MSS;
            len = gen_tcp_data(buf, sess, http_buf, to_send, 0);
            sess->response_sent = to_send;
        } else {
            /* Send body chunks */
            uint8_t body_buf[MSS];
            size_t remaining = sess->response_len - sess->response_sent;
            size_t chunk = remaining > MSS ? MSS : remaining;
            int body_len = gen_http_body_chunk(body_buf, chunk,
                                                sess->response_sent, sess->response_len,
                                                ctx->rng_state);
            len = gen_tcp_data(buf, sess, body_buf, (size_t)body_len, 0);
            sess->response_sent += (size_t)body_len;
        }

        if (should_retransmit(ctx)) {
            memcpy(sess->retransmit_buf, buf, len);
            sess->retransmit_len = (size_t)len;
            sess->retransmit_pending = 1;
        }

        if (sess->response_sent >= sess->response_len)
            sess->state = SESS_TCP_FIN_CLIENT;

        return len;
    }

    /* ---- TCP Teardown ---- */
    case SESS_TCP_FIN_CLIENT:
        len = gen_tcp_fin(buf, sess, 1);
        sess->state = SESS_TCP_FINACK_SERVER;
        return len;

    case SESS_TCP_FINACK_SERVER:
        len = gen_tcp_finack(buf, sess, 0);
        sess->state = SESS_TCP_ACK_FINAL;
        return len;

    case SESS_TCP_ACK_FINAL:
        len = gen_tcp_ack(buf, sess, 1);
        sess->state = SESS_DONE;
        return len;

    /* ---- DNS ---- */
    case SESS_DNS_QUERY: {
        uint8_t dns_buf[512];
        int dns_len = gen_dns_query(dns_buf, sizeof(dns_buf),
                                     sess->dns_txid, sess->dns_qtype, ctx->rng_state);

        /* Build UDP packet: eth + ip + udp + dns payload */
        int off = 0;
        off += build_eth_header(buf + off, 0x0800);
        uint16_t udp_len = UDP_HDRLEN + (uint16_t)dns_len;
        uint16_t ip_total = IP_HDRLEN + udp_len;
        off += build_ip_header(buf + off, sess->src_ip, sess->dst_ip,
                               17, ip_total, sess->ip_id++);
        int udp_off = off;
        off += build_udp_header(buf + off, sess->src_port, sess->dst_port, udp_len);
        memcpy(buf + off, dns_buf, dns_len);
        off += dns_len;

        /* UDP checksum */
        uint16_t cksum = tcp_udp_checksum(sess->src_ip, sess->dst_ip, 17,
                                           buf + udp_off, udp_len);
        buf[udp_off + 6] = cksum & 0xff;
        buf[udp_off + 7] = (cksum >> 8) & 0xff;

        /* Save query for response generation */
        memcpy(sess->retransmit_buf, dns_buf, dns_len);
        sess->retransmit_len = (size_t)dns_len;

        sess->state = SESS_DNS_RESPONSE;
        len = off < MIN_PACKET_SIZE ? MIN_PACKET_SIZE : off;
        return len;
    }

    case SESS_DNS_RESPONSE: {
        uint8_t dns_buf[1400];
        int dns_len = gen_dns_response(dns_buf, sizeof(dns_buf),
                                        sess->dns_txid, sess->dns_qtype,
                                        sess->retransmit_buf, sess->retransmit_len,
                                        ctx->rng_state);
        sess->retransmit_len = 0; /* clear saved query */

        int off = 0;
        off += build_eth_header(buf + off, 0x0800);
        uint16_t udp_len = UDP_HDRLEN + (uint16_t)dns_len;
        uint16_t ip_total = IP_HDRLEN + udp_len;
        /* Response: src/dst are swapped */
        off += build_ip_header(buf + off, sess->dst_ip, sess->src_ip,
                               17, ip_total, sess->ip_id++);
        int udp_off = off;
        off += build_udp_header(buf + off, sess->dst_port, sess->src_port, udp_len);
        memcpy(buf + off, dns_buf, dns_len);
        off += dns_len;

        uint16_t cksum = tcp_udp_checksum(sess->dst_ip, sess->src_ip, 17,
                                           buf + udp_off, udp_len);
        buf[udp_off + 6] = cksum & 0xff;
        buf[udp_off + 7] = (cksum >> 8) & 0xff;

        sess->state = SESS_DONE;
        len = off < MIN_PACKET_SIZE ? MIN_PACKET_SIZE : off;
        return len;
    }

    case SESS_DONE:
        return 0;
    }

    return 0;
}
