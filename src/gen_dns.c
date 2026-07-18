#include "gen_dns.h"
#include "net_utils.h"

#include <string.h>
#include <stdio.h>

/* DNS query types */
#define DNS_TYPE_A     1
#define DNS_TYPE_NS    2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA   6
#define DNS_TYPE_PTR   12
#define DNS_TYPE_MX    15
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_OPT   41

/* DNS response codes */
#define DNS_RCODE_OK       0
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_SERVFAIL 2

/* DNS flags */
#define DNS_FLAG_QR  0x8000
#define DNS_FLAG_RD  0x0100
#define DNS_FLAG_RA  0x0080
#define DNS_FLAG_AA  0x0400

static const char *base_domains[] = {
    "example.com", "test.org", "sample.net", "demo.io",
    "acme.corp", "widgets.biz", "cloudservice.app",
    "devtools.dev", "analytics.co", "datastore.cloud",
    "fastcdn.net", "webhost.com", "mailprovider.org",
    "searchengine.com", "socialnet.io", "gameserver.gg",
    "streamvid.tv", "newsportal.com", "shopfront.store",
    "bankservice.finance",
};
#define NUM_DOMAINS (sizeof(base_domains) / sizeof(base_domains[0]))

static const char *subdomains[] = {
    "www", "mail", "api", "cdn", "app", "dev", "staging",
    "beta", "auth", "login", "static", "img", "assets",
    "ns1", "ns2", "mx", "smtp", "imap", "pop", "ftp",
    "git", "ci", "monitor", "status", "docs", "wiki",
    "blog", "shop", "store", "pay", "db", "cache",
    "search", "metrics", "logs", "vault", "proxy",
};
#define NUM_SUBDOMAINS (sizeof(subdomains) / sizeof(subdomains[0]))

uint16_t gen_dns_pick_qtype(uint64_t *rng)
{
    uint32_t r = rng_range(rng, 100);
    if (r < 50) return DNS_TYPE_A;
    if (r < 75) return DNS_TYPE_AAAA;
    if (r < 83) return DNS_TYPE_MX;
    if (r < 90) return DNS_TYPE_NS;
    if (r < 95) return DNS_TYPE_TXT;
    if (r < 98) return DNS_TYPE_CNAME;
    if (r < 99) return DNS_TYPE_SOA;
    return DNS_TYPE_PTR;
}

/* Encode a DNS name (e.g. "www.example.com") into wire format.
 * Returns bytes written. */
static int dns_encode_name(uint8_t *buf, const char *name)
{
    int off = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len;
        if (dot)
            label_len = (int)(dot - p);
        else
            label_len = (int)strlen(p);

        if (label_len > 63) label_len = 63;
        buf[off++] = (uint8_t)label_len;
        memcpy(buf + off, p, label_len);
        off += label_len;

        if (dot)
            p = dot + 1;
        else
            break;
    }
    buf[off++] = 0; /* root label */
    return off;
}

/* Build a PTR-style name for reverse lookups */
static int dns_build_ptr_name(uint8_t *buf, uint32_t ip)
{
    char name[64];
    snprintf(name, sizeof(name), "%u.%u.%u.%u.in-addr.arpa",
        ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
    return dns_encode_name(buf, name);
}

int gen_dns_query(uint8_t *buf, size_t bufsize, uint16_t txid,
                  uint16_t qtype, uint64_t *rng)
{
    (void)bufsize;
    int off = 0;

    /* DNS header (12 bytes) */
    buf[off++] = (txid >> 8) & 0xff;
    buf[off++] = txid & 0xff;
    uint16_t flags = DNS_FLAG_RD;
    buf[off++] = (flags >> 8) & 0xff;
    buf[off++] = flags & 0xff;
    buf[off++] = 0; buf[off++] = 1;  /* QDCOUNT = 1 */
    buf[off++] = 0; buf[off++] = 0;  /* ANCOUNT = 0 */
    buf[off++] = 0; buf[off++] = 0;  /* NSCOUNT = 0 */
    int arcount_off = off;
    buf[off++] = 0; buf[off++] = 0;  /* ARCOUNT */

    /* Question section */
    if (qtype == DNS_TYPE_PTR) {
        uint32_t ip = (uint32_t)rng_next(rng);
        off += dns_build_ptr_name(buf + off, ip);
    } else {
        /* Build random hostname */
        char hostname[128];
        const char *sub = subdomains[rng_range(rng, NUM_SUBDOMAINS)];
        const char *dom = base_domains[rng_range(rng, NUM_DOMAINS)];

        /* Sometimes add a random numeric prefix */
        if (rng_range(rng, 100) < 30)
            snprintf(hostname, sizeof(hostname), "%s%u.%s",
                sub, rng_range(rng, 100), dom);
        else
            snprintf(hostname, sizeof(hostname), "%s.%s", sub, dom);

        off += dns_encode_name(buf + off, hostname);
    }

    buf[off++] = (qtype >> 8) & 0xff;
    buf[off++] = qtype & 0xff;
    buf[off++] = 0; buf[off++] = 1;  /* QCLASS = IN */

    /* EDNS0 OPT record (~60% of queries) */
    if (rng_range(rng, 100) < 60) {
        buf[arcount_off] = 0;
        buf[arcount_off + 1] = 1;  /* ARCOUNT = 1 */

        buf[off++] = 0;            /* root name */
        buf[off++] = 0; buf[off++] = DNS_TYPE_OPT; /* type OPT */
        buf[off++] = 0x10; buf[off++] = 0x00;      /* UDP size 4096 */
        buf[off++] = 0;            /* extended RCODE */
        buf[off++] = 0;            /* EDNS version */
        buf[off++] = 0; buf[off++] = 0; /* flags (no DO bit) */
        buf[off++] = 0; buf[off++] = 0; /* RDLENGTH = 0 */
    }

    return off;
}

int gen_dns_response(uint8_t *buf, size_t bufsize, uint16_t txid,
                     uint16_t qtype, const uint8_t *query_buf,
                     size_t query_len, uint64_t *rng)
{
    (void)bufsize;
    int off = 0;

    /* Decide response code */
    uint8_t rcode;
    uint32_t r = rng_range(rng, 100);
    if (r < 93)       rcode = DNS_RCODE_OK;
    else if (r < 97)  rcode = DNS_RCODE_NXDOMAIN;
    else              rcode = DNS_RCODE_SERVFAIL;

    /* DNS header */
    buf[off++] = (txid >> 8) & 0xff;
    buf[off++] = txid & 0xff;
    uint16_t flags = DNS_FLAG_QR | DNS_FLAG_RD | DNS_FLAG_RA | DNS_FLAG_AA;
    flags |= rcode;
    buf[off++] = (flags >> 8) & 0xff;
    buf[off++] = flags & 0xff;
    buf[off++] = 0; buf[off++] = 1;  /* QDCOUNT = 1 */
    int ancount_off = off;
    buf[off++] = 0; buf[off++] = 0;  /* ANCOUNT placeholder */
    buf[off++] = 0; buf[off++] = 0;  /* NSCOUNT = 0 */
    buf[off++] = 0; buf[off++] = 0;  /* ARCOUNT = 0 */

    /* Copy question section from query (skip header) */
    if (query_len > 12) {
        size_t qsection_len = query_len - 12;
        /* Check for OPT record and exclude it */
        const uint8_t *qp = query_buf + 12;
        /* Skip QNAME */
        while (*qp && (size_t)(qp - query_buf) < query_len) qp++;
        qp++; /* skip root */
        qp += 4; /* skip QTYPE + QCLASS */
        qsection_len = (size_t)(qp - (query_buf + 12));
        memcpy(buf + off, query_buf + 12, qsection_len);
        off += (int)qsection_len;
    }

    /* Answer section */
    int ancount = 0;
    if (rcode == DNS_RCODE_OK) {
        /* Name pointer to question (compression) */
        int name_ptr_hi = 0xc0;
        int name_ptr_lo = 0x0c;

        uint32_t ttl = 60 + rng_range(rng, 86340);

        switch (qtype) {
        case DNS_TYPE_A: {
            /* 1-4 A records */
            int nrec = 1 + (int)rng_range(rng, 4);
            for (int i = 0; i < nrec; i++) {
                buf[off++] = (uint8_t)name_ptr_hi;
                buf[off++] = (uint8_t)name_ptr_lo;
                buf[off++] = 0; buf[off++] = DNS_TYPE_A;
                buf[off++] = 0; buf[off++] = 1; /* CLASS IN */
                buf[off++] = (ttl >> 24) & 0xff;
                buf[off++] = (ttl >> 16) & 0xff;
                buf[off++] = (ttl >> 8) & 0xff;
                buf[off++] = ttl & 0xff;
                buf[off++] = 0; buf[off++] = 4; /* RDLENGTH */
                uint32_t ip = (uint32_t)rng_next(rng);
                buf[off++] = (ip >> 24) & 0xff;
                buf[off++] = (ip >> 16) & 0xff;
                buf[off++] = (ip >> 8) & 0xff;
                buf[off++] = ip & 0xff;
                ancount++;
            }
            break;
        }
        case DNS_TYPE_AAAA: {
            int nrec = 1 + (int)rng_range(rng, 2);
            for (int i = 0; i < nrec; i++) {
                buf[off++] = (uint8_t)name_ptr_hi;
                buf[off++] = (uint8_t)name_ptr_lo;
                buf[off++] = 0; buf[off++] = 0; buf[off++] = DNS_TYPE_AAAA;
                /* fix: AAAA type is 28 = 0x001c */
                off -= 3;
                buf[off++] = (DNS_TYPE_AAAA >> 8) & 0xff;
                buf[off++] = DNS_TYPE_AAAA & 0xff;
                buf[off++] = 0; buf[off++] = 1;
                buf[off++] = (ttl >> 24) & 0xff;
                buf[off++] = (ttl >> 16) & 0xff;
                buf[off++] = (ttl >> 8) & 0xff;
                buf[off++] = ttl & 0xff;
                buf[off++] = 0; buf[off++] = 16; /* RDLENGTH */
                rng_fill(buf + off, 16, rng); off += 16;
                ancount++;
            }
            break;
        }
        case DNS_TYPE_MX: {
            int nrec = 1 + (int)rng_range(rng, 3);
            for (int i = 0; i < nrec; i++) {
                buf[off++] = (uint8_t)name_ptr_hi;
                buf[off++] = (uint8_t)name_ptr_lo;
                buf[off++] = (DNS_TYPE_MX >> 8) & 0xff;
                buf[off++] = DNS_TYPE_MX & 0xff;
                buf[off++] = 0; buf[off++] = 1;
                buf[off++] = (ttl >> 24) & 0xff;
                buf[off++] = (ttl >> 16) & 0xff;
                buf[off++] = (ttl >> 8) & 0xff;
                buf[off++] = ttl & 0xff;

                /* Build MX target */
                char mx_name[64];
                snprintf(mx_name, sizeof(mx_name), "mx%d.%s",
                    i + 1, base_domains[rng_range(rng, NUM_DOMAINS)]);
                uint8_t mx_encoded[64];
                int mx_len = dns_encode_name(mx_encoded, mx_name);

                uint16_t rdlen = 2 + (uint16_t)mx_len; /* preference + name */
                buf[off++] = (rdlen >> 8) & 0xff;
                buf[off++] = rdlen & 0xff;
                uint16_t pref = (uint16_t)((i + 1) * 10);
                buf[off++] = (pref >> 8) & 0xff;
                buf[off++] = pref & 0xff;
                memcpy(buf + off, mx_encoded, mx_len);
                off += mx_len;
                ancount++;
            }
            break;
        }
        case DNS_TYPE_NS: {
            int nrec = 2 + (int)rng_range(rng, 3);
            for (int i = 0; i < nrec; i++) {
                buf[off++] = (uint8_t)name_ptr_hi;
                buf[off++] = (uint8_t)name_ptr_lo;
                buf[off++] = (DNS_TYPE_NS >> 8) & 0xff;
                buf[off++] = DNS_TYPE_NS & 0xff;
                buf[off++] = 0; buf[off++] = 1;
                buf[off++] = (ttl >> 24) & 0xff;
                buf[off++] = (ttl >> 16) & 0xff;
                buf[off++] = (ttl >> 8) & 0xff;
                buf[off++] = ttl & 0xff;

                char ns_name[64];
                snprintf(ns_name, sizeof(ns_name), "ns%d.%s",
                    i + 1, base_domains[rng_range(rng, NUM_DOMAINS)]);
                uint8_t ns_encoded[64];
                int ns_len = dns_encode_name(ns_encoded, ns_name);
                buf[off++] = (ns_len >> 8) & 0xff;
                buf[off++] = ns_len & 0xff;
                memcpy(buf + off, ns_encoded, ns_len);
                off += ns_len;
                ancount++;
            }
            break;
        }
        case DNS_TYPE_TXT: {
            buf[off++] = (uint8_t)name_ptr_hi;
            buf[off++] = (uint8_t)name_ptr_lo;
            buf[off++] = (DNS_TYPE_TXT >> 8) & 0xff;
            buf[off++] = DNS_TYPE_TXT & 0xff;
            buf[off++] = 0; buf[off++] = 1;
            buf[off++] = (ttl >> 24) & 0xff;
            buf[off++] = (ttl >> 16) & 0xff;
            buf[off++] = (ttl >> 8) & 0xff;
            buf[off++] = ttl & 0xff;

            const char *txts[] = {
                "v=spf1 include:_spf.google.com ~all",
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNA",
                "google-site-verification=abcdef12345",
                "MS=ms12345678",
            };
            const char *txt = txts[rng_range(rng, 4)];
            int txt_len = (int)strlen(txt);
            uint16_t rdlen = (uint16_t)(txt_len + 1);
            buf[off++] = (rdlen >> 8) & 0xff;
            buf[off++] = rdlen & 0xff;
            buf[off++] = (uint8_t)txt_len;
            memcpy(buf + off, txt, txt_len);
            off += txt_len;
            ancount++;
            break;
        }
        case DNS_TYPE_CNAME: {
            buf[off++] = (uint8_t)name_ptr_hi;
            buf[off++] = (uint8_t)name_ptr_lo;
            buf[off++] = (DNS_TYPE_CNAME >> 8) & 0xff;
            buf[off++] = DNS_TYPE_CNAME & 0xff;
            buf[off++] = 0; buf[off++] = 1;
            buf[off++] = (ttl >> 24) & 0xff;
            buf[off++] = (ttl >> 16) & 0xff;
            buf[off++] = (ttl >> 8) & 0xff;
            buf[off++] = ttl & 0xff;

            char cname[64];
            snprintf(cname, sizeof(cname), "%s.%s",
                subdomains[rng_range(rng, NUM_SUBDOMAINS)],
                base_domains[rng_range(rng, NUM_DOMAINS)]);
            uint8_t cn_encoded[64];
            int cn_len = dns_encode_name(cn_encoded, cname);
            buf[off++] = (cn_len >> 8) & 0xff;
            buf[off++] = cn_len & 0xff;
            memcpy(buf + off, cn_encoded, cn_len);
            off += cn_len;
            ancount++;
            break;
        }
        case DNS_TYPE_SOA: {
            buf[off++] = (uint8_t)name_ptr_hi;
            buf[off++] = (uint8_t)name_ptr_lo;
            buf[off++] = (DNS_TYPE_SOA >> 8) & 0xff;
            buf[off++] = DNS_TYPE_SOA & 0xff;
            buf[off++] = 0; buf[off++] = 1;
            buf[off++] = (ttl >> 24) & 0xff;
            buf[off++] = (ttl >> 16) & 0xff;
            buf[off++] = (ttl >> 8) & 0xff;
            buf[off++] = ttl & 0xff;

            int rdlen_off = off; off += 2;
            int rd_start = off;

            /* MNAME */
            char mname[64];
            snprintf(mname, sizeof(mname), "ns1.%s",
                base_domains[rng_range(rng, NUM_DOMAINS)]);
            off += dns_encode_name(buf + off, mname);

            /* RNAME */
            char rname[64];
            snprintf(rname, sizeof(rname), "admin.%s",
                base_domains[rng_range(rng, NUM_DOMAINS)]);
            off += dns_encode_name(buf + off, rname);

            /* SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM */
            uint32_t serial = (uint32_t)rng_next(rng);
            uint32_t vals[] = {serial, 3600, 900, 604800, 86400};
            for (int i = 0; i < 5; i++) {
                buf[off++] = (vals[i] >> 24) & 0xff;
                buf[off++] = (vals[i] >> 16) & 0xff;
                buf[off++] = (vals[i] >> 8) & 0xff;
                buf[off++] = vals[i] & 0xff;
            }

            uint16_t rdlen = (uint16_t)(off - rd_start);
            buf[rdlen_off] = (rdlen >> 8) & 0xff;
            buf[rdlen_off + 1] = rdlen & 0xff;
            ancount++;
            break;
        }
        case DNS_TYPE_PTR: {
            buf[off++] = (uint8_t)name_ptr_hi;
            buf[off++] = (uint8_t)name_ptr_lo;
            buf[off++] = (DNS_TYPE_PTR >> 8) & 0xff;
            buf[off++] = DNS_TYPE_PTR & 0xff;
            buf[off++] = 0; buf[off++] = 1;
            buf[off++] = (ttl >> 24) & 0xff;
            buf[off++] = (ttl >> 16) & 0xff;
            buf[off++] = (ttl >> 8) & 0xff;
            buf[off++] = ttl & 0xff;

            char ptr_name[64];
            snprintf(ptr_name, sizeof(ptr_name), "%s.%s",
                subdomains[rng_range(rng, NUM_SUBDOMAINS)],
                base_domains[rng_range(rng, NUM_DOMAINS)]);
            uint8_t ptr_encoded[64];
            int ptr_len = dns_encode_name(ptr_encoded, ptr_name);
            buf[off++] = (ptr_len >> 8) & 0xff;
            buf[off++] = ptr_len & 0xff;
            memcpy(buf + off, ptr_encoded, ptr_len);
            off += ptr_len;
            ancount++;
            break;
        }
        default:
            break;
        }
    }

    /* Fill in ANCOUNT */
    buf[ancount_off] = (ancount >> 8) & 0xff;
    buf[ancount_off + 1] = ancount & 0xff;

    return off;
}
