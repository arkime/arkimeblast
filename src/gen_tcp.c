#include "gen_tcp.h"
#include "net_utils.h"
#include <string.h>

/* Helper: build full frame with eth + ip + tcp + optional payload.
 * dir: 1 = client→server, 0 = server→client */
static int build_tcp_frame(uint8_t *buf, session_t *sess, uint8_t flags,
                           const uint8_t *payload, size_t payload_len,
                           int from_client)
{
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint32_t seq, ack;

    if (from_client) {
        src_ip   = sess->src_ip;
        dst_ip   = sess->dst_ip;
        src_port = sess->src_port;
        dst_port = sess->dst_port;
        seq      = sess->client_seq;
        ack      = sess->client_ack;
    } else {
        src_ip   = sess->dst_ip;
        dst_ip   = sess->src_ip;
        src_port = sess->dst_port;
        dst_port = sess->src_port;
        seq      = sess->server_seq;
        ack      = sess->server_ack;
    }

    int off = 0;
    off += build_eth_header(buf + off, 0x0800);

    uint16_t ip_total = IP_HDRLEN + TCP_HDRLEN + (uint16_t)payload_len;
    off += build_ip_header(buf + off, src_ip, dst_ip, 6, ip_total, sess->ip_id++);

    int tcp_off = off;
    off += build_tcp_header(buf + off, src_port, dst_port, seq, ack, flags, 65535);

    if (payload && payload_len > 0) {
        memcpy(buf + off, payload, payload_len);
        off += (int)payload_len;
    }

    /* TCP checksum over TCP header + payload */
    uint16_t tcp_cksum = tcp_udp_checksum(src_ip, dst_ip, 6,
                                           buf + tcp_off, TCP_HDRLEN + payload_len);
    buf[tcp_off + 16] = tcp_cksum & 0xff;
    buf[tcp_off + 17] = (tcp_cksum >> 8) & 0xff;

    return off < MIN_PACKET_SIZE ? MIN_PACKET_SIZE : off;
}

int gen_tcp_syn(uint8_t *buf, session_t *sess)
{
    sess->client_seq = 1000;
    sess->client_ack = 0;
    int len = build_tcp_frame(buf, sess, TCP_SYN, NULL, 0, 1);
    sess->client_seq++; /* SYN consumes 1 seq */
    return len;
}

int gen_tcp_synack(uint8_t *buf, session_t *sess)
{
    sess->server_seq = 2000;
    sess->server_ack = sess->client_seq;
    int len = build_tcp_frame(buf, sess, TCP_SYN | TCP_ACK, NULL, 0, 0);
    sess->server_seq++; /* SYN-ACK consumes 1 seq */
    return len;
}

int gen_tcp_ack(uint8_t *buf, session_t *sess, int from_client)
{
    if (from_client) {
        sess->client_ack = sess->server_seq;
    } else {
        sess->server_ack = sess->client_seq;
    }
    return build_tcp_frame(buf, sess, TCP_ACK, NULL, 0, from_client);
}

int gen_tcp_data(uint8_t *buf, session_t *sess,
                 const uint8_t *payload, size_t payload_len,
                 int from_client)
{
    if (from_client) {
        sess->client_ack = sess->server_seq;
    } else {
        sess->server_ack = sess->client_seq;
    }
    int len = build_tcp_frame(buf, sess, TCP_PSH | TCP_ACK, payload, payload_len, from_client);

    if (from_client)
        sess->client_seq += (uint32_t)payload_len;
    else
        sess->server_seq += (uint32_t)payload_len;

    return len;
}

int gen_tcp_fin(uint8_t *buf, session_t *sess, int from_client)
{
    int len = build_tcp_frame(buf, sess, TCP_FIN | TCP_ACK, NULL, 0, from_client);
    if (from_client)
        sess->client_seq++;
    else
        sess->server_seq++;
    return len;
}

int gen_tcp_finack(uint8_t *buf, session_t *sess, int from_client)
{
    if (from_client)
        sess->client_ack = sess->server_seq;
    else
        sess->server_ack = sess->client_seq;
    return build_tcp_frame(buf, sess, TCP_FIN | TCP_ACK, NULL, 0, from_client);
}
