#include "afpacket.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sched.h>

int afpacket_setup(thread_ctx_t *ctx)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    /* Set TPACKET_V3 */
    int version = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("setsockopt(PACKET_VERSION)");
        close(fd);
        return -1;
    }

    /* Bypass kernel qdisc layer — major throughput win */
    int qdisc_bypass = 1;
    if (setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass)) < 0) {
        /* Non-fatal: older kernels may not support it */
        perror("setsockopt(PACKET_QDISC_BYPASS) (non-fatal)");
    }

    /* Allow dropping frames instead of blocking when ring is full */
    int loss = 1;
    if (setsockopt(fd, SOL_PACKET, PACKET_LOSS, &loss, sizeof(loss)) < 0) {
        perror("setsockopt(PACKET_LOSS) (non-fatal)");
    }

    /* Setup TX ring */
    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = TX_RING_BLOCK_SIZE;
    req.tp_block_nr   = TX_RING_BLOCK_NR;
    req.tp_frame_size = TX_RING_FRAME_SIZE;
    req.tp_frame_nr   = (TX_RING_BLOCK_SIZE / TX_RING_FRAME_SIZE) * TX_RING_BLOCK_NR;

    if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
        /* Try with smaller ring if mmap fails (memory constrained) */
        req.tp_block_nr = 64;
        req.tp_frame_nr = (TX_RING_BLOCK_SIZE / TX_RING_FRAME_SIZE) * req.tp_block_nr;
        if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
            perror("setsockopt(PACKET_TX_RING)");
            close(fd);
            return -1;
        }
    }

    size_t ring_size = (size_t)req.tp_block_size * req.tp_block_nr;
    uint8_t *ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_LOCKED | MAP_POPULATE, fd, 0);
    if (ring == MAP_FAILED) {
        ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE, fd, 0);
        if (ring == MAP_FAILED) {
            ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, 0);
            if (ring == MAP_FAILED) {
                perror("mmap(TX_RING)");
                close(fd);
                return -1;
            }
        }
    }

    /* Bind to interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ctx->config->if_index;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)");
        munmap(ring, ring_size);
        close(fd);
        return -1;
    }

    ctx->sock_fd       = fd;
    ctx->tx_ring       = ring;
    ctx->tx_ring_size  = ring_size;
    ctx->tx_frame_idx  = 0;
    ctx->tx_frame_count = req.tp_frame_nr;

    return 0;
}

int afpacket_send(thread_ctx_t *ctx, const uint8_t *frame, size_t len)
{
    /* Get pointer to current TX frame */
    struct tpacket3_hdr *hdr = (struct tpacket3_hdr *)
        (ctx->tx_ring + ctx->tx_frame_idx * TX_RING_FRAME_SIZE);

    /* Wait for frame to be available — tight spin then yield */
    if (hdr->tp_status != TP_STATUS_AVAILABLE) {
        /* Kick kernel first */
        sendto(ctx->sock_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);

        int spins = 0;
        while (hdr->tp_status != TP_STATUS_AVAILABLE) {
            if (!*ctx->running)
                return -1;
            if (++spins < 10000) {
                __builtin_ia32_pause(); /* CPU spin-wait hint */
            } else {
                spins = 0;
                sendto(ctx->sock_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
                sched_yield();
            }
        }
    }

    /* Copy frame into ring buffer */
    uint8_t *data = (uint8_t *)hdr + TPACKET3_HDRLEN - sizeof(struct sockaddr_ll);
    memcpy(data, frame, len);

    /* Pad to minimum Ethernet frame size */
    if (len < MIN_PACKET_SIZE) {
        memset(data + len, 0, MIN_PACKET_SIZE - len);
        len = MIN_PACKET_SIZE;
    }

    hdr->tp_len    = (uint32_t)len;
    hdr->tp_snaplen = (uint32_t)len;
    hdr->tp_next_offset = 0;

    /* Mark as ready to send */
    __sync_synchronize();
    hdr->tp_status = TP_STATUS_SEND_REQUEST;

    /* Advance to next frame */
    ctx->tx_frame_idx = (ctx->tx_frame_idx + 1) % ctx->tx_frame_count;

    /* Notify kernel periodically — less frequent = more batching */
    if ((ctx->tx_frame_idx & (TX_FLUSH_INTERVAL - 1)) == 0) {
        sendto(ctx->sock_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    return 0;
}

void afpacket_cleanup(thread_ctx_t *ctx)
{
    if (ctx->tx_ring && ctx->tx_ring_size > 0) {
        /* Flush pending */
        sendto(ctx->sock_fd, NULL, 0, 0, NULL, 0);
        munmap(ctx->tx_ring, ctx->tx_ring_size);
        ctx->tx_ring = NULL;
    }
    if (ctx->sock_fd >= 0) {
        close(ctx->sock_fd);
        ctx->sock_fd = -1;
    }
}
