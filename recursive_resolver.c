/*
 * recursive_resolver.c — Iterative DNS resolver
 *
 * Resolves A and AAAA queries by walking the DNS hierarchy from root servers
 * down to authoritative servers. Supports:
 *   - DNS name compression (pointer following with loop detection)
 *   - Iterative resolution: root → TLD → authoritative
 *   - TTL-based answer cache
 *   - Randomized transaction IDs (arc4random/getrandom)
 *   - Timeout handling with configurable deadline
 *   - CNAME following with depth limit
 *   - --local mode: answers from a built-in zone for benchmarking
 *   - Same epoll-based event loop as the UDP forwarder baseline
 *
 * Build:
 *   Debug:   gcc -g -O1 -Wall -Wextra -fsanitize=address,undefined \
 *                -o recursive_asan recursive_resolver.c
 *   Release: gcc -O3 -Wall -Wextra -o recursive_resolver recursive_resolver.c
 *
 * Usage:
 *   ./recursive_resolver              # normal recursive mode
 *   ./recursive_resolver --local      # local-answer mode for benchmarking
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>

/* ================================================================
 * CONFIGURATION
 * ================================================================ */
#define LISTEN_PORT         5353
#define BUF_SIZE            1500        /* full Ethernet MTU */
#define MAX_EVENTS          64
#define MAX_PENDING         4096        /* in-flight resolution tasks */
#define MAX_DEPTH           16          /* referral hops per query */
#define MAX_CNAME_CHAIN     8           /* CNAME follows per query */
#define QUERY_TIMEOUT_MS    5000        /* per-query deadline */
#define UPSTREAM_TIMEOUT_MS 2000        /* per-hop timeout */

/* Cache */
#define CACHE_BUCKETS       4096
#define CACHE_MAX_ENTRIES   8192
#define MAX_CACHED_RRS      16          /* RRs stored per cache entry */
#define MAX_RR_RDATA        512

/* DNS constants */
#define DNS_HDR_SIZE        12
#define DNS_TYPE_A          1
#define DNS_TYPE_NS         2
#define DNS_TYPE_CNAME      5
#define DNS_TYPE_AAAA       28
#define DNS_CLASS_IN        1
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4

/* ================================================================
 * ROOT SERVERS (13 roots, IPv4 only for simplicity)
 * ================================================================ */
static const char *ROOT_SERVERS[] = {
    "198.41.0.4",       /* a.root-servers.net */
    "170.247.170.2",    /* b.root-servers.net */
    "192.33.4.12",      /* c.root-servers.net */
    "199.7.91.13",      /* d.root-servers.net */
    "192.203.230.10",   /* e.root-servers.net */
    "192.5.5.241",      /* f.root-servers.net */
    "192.112.36.4",     /* g.root-servers.net */
    "198.97.190.53",    /* h.root-servers.net */
    "192.36.148.17",    /* i.root-servers.net */
    "192.58.128.30",    /* j.root-servers.net */
    "193.0.14.129",     /* k.root-servers.net */
    "199.7.83.42",      /* l.root-servers.net */
    "202.12.27.33",     /* m.root-servers.net */
};
#define NUM_ROOTS 13

/* ================================================================
 * UTILITY: random TXID
 * ================================================================ */
static uint16_t rand_txid(void) {
    uint16_t val;
    if (getrandom(&val, sizeof(val), 0) != sizeof(val)) {
        /* Fallback — not cryptographically strong */
        val = (uint16_t)(rand() ^ (rand() << 8));
    }
    return val;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ================================================================
 * DNS NAME HANDLING
 * Names stored as lowercase dot-separated C strings ("www.example.com")
 * ================================================================ */

/*
 * parse_dns_name — read a DNS wire-format name with compression support.
 *
 * pkt:       start of the DNS message
 * pkt_end:   one past the last byte of the message
 * ptr:       current read position (updated on return to point past
 *            the name in the *original* position, not after pointers)
 * out:       buffer to write the dot-separated name
 * out_size:  size of out buffer
 *
 * Returns 0 on success, -1 on error (malformed name).
 */
static int parse_dns_name(const uint8_t *pkt, const uint8_t *pkt_end,
                          const uint8_t **ptr, char *out, int out_size) {
    const uint8_t *p = *ptr;
    int total = 0;
    int jumped = 0;
    const uint8_t *after_first_jump = NULL;
    int pointer_count = 0;

    while (p < pkt_end) {
        uint8_t len = *p;

        if (len == 0) {
            /* Root label — end of name */
            p++;
            if (!jumped) after_first_jump = p;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            /* Compression pointer */
            if (p + 1 >= pkt_end) return -1;
            uint16_t offset = ((len & 0x3F) << 8) | p[1];
            if (offset >= (pkt_end - pkt)) return -1;

            if (!jumped) after_first_jump = p + 2;
            jumped = 1;
            p = pkt + offset;

            if (++pointer_count > 128) return -1; /* Loop detection */
            continue;
        }

        if ((len & 0xC0) != 0) return -1; /* Reserved bits */

        p++;
        if (p + len > pkt_end) return -1;

        if (total + len + 1 >= out_size) return -1;

        if (total > 0) out[total++] = '.';
        for (int i = 0; i < len; i++) {
            out[total++] = tolower(p[i]);
        }
        p += len;
    }

    out[total] = '\0';
    *ptr = after_first_jump ? after_first_jump : p;
    return 0;
}

/*
 * encode_dns_name — write a dot-separated name into DNS wire format.
 * Returns bytes written, or -1 on error.
 */
static int encode_dns_name(const char *name, uint8_t *buf, int buf_size) {
    int pos = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);

        if (label_len == 0 || label_len > 63) return -1;
        if (pos + 1 + label_len + 1 > buf_size) return -1;

        buf[pos++] = (uint8_t)label_len;
        memcpy(&buf[pos], p, label_len);
        pos += label_len;

        p += label_len;
        if (*p == '.') p++;
    }

    if (pos + 1 > buf_size) return -1;
    buf[pos++] = 0; /* Root label */
    return pos;
}

/* Case-insensitive name comparison */
static int name_eq(const char *a, const char *b) {
    return strcasecmp(a, b) == 0;
}

/* ================================================================
 * DNS CACHE
 * ================================================================ */

/* A single cached resource record */
struct cached_rr {
    uint16_t type;
    uint16_t rdlength;
    uint8_t  rdata[MAX_RR_RDATA];
};

struct cache_entry {
    char     name[256];
    uint16_t qtype;             /* DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_NS */
    uint64_t expire_ms;         /* absolute monotonic time */
    int      rr_count;
    struct cached_rr rrs[MAX_CACHED_RRS];
    int      is_nxdomain;       /* 1 if this was an NXDOMAIN result */

    /* Hash chain */
    struct cache_entry *next;
    struct cache_entry *lru_prev, *lru_next;
};

static struct cache_entry *cache_buckets[CACHE_BUCKETS];
static struct cache_entry  cache_pool[CACHE_MAX_ENTRIES];
static struct cache_entry  lru_head; /* Dummy head for LRU list */
static int cache_count = 0;

static uint32_t cache_hash(const char *name, uint16_t qtype) {
    uint32_t h = qtype * 31;
    for (const char *p = name; *p; p++) {
        h = h * 131 + tolower(*p);
    }
    return h % CACHE_BUCKETS;
}

static void lru_remove(struct cache_entry *e) {
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}

static void lru_push_front(struct cache_entry *e) {
    e->lru_next = lru_head.lru_next;
    e->lru_prev = &lru_head;
    if (lru_head.lru_next) lru_head.lru_next->lru_prev = e;
    lru_head.lru_next = e;
}

static void cache_init(void) {
    memset(cache_buckets, 0, sizeof(cache_buckets));
    memset(cache_pool, 0, sizeof(cache_pool));
    lru_head.lru_next = &lru_head;
    lru_head.lru_prev = &lru_head;
    /* We won't use the dummy's own fields. Just set up the circular list. */
    lru_head.lru_next = NULL;
    lru_head.lru_prev = NULL;
    cache_count = 0;
}

static struct cache_entry *cache_lookup(const char *name, uint16_t qtype) {
    uint32_t h = cache_hash(name, qtype);
    uint64_t now = now_ms();

    for (struct cache_entry *e = cache_buckets[h]; e; e = e->next) {
        if (e->qtype == qtype && name_eq(e->name, name)) {
            if (e->expire_ms <= now) {
                /* Expired — remove from bucket chain */
                return NULL;
            }
            /* Move to front of LRU */
            lru_remove(e);
            lru_push_front(e);
            return e;
        }
    }
    return NULL;
}

static void cache_remove_from_bucket(struct cache_entry *e) {
    uint32_t h = cache_hash(e->name, e->qtype);
    struct cache_entry **pp = &cache_buckets[h];
    while (*pp) {
        if (*pp == e) {
            *pp = e->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

static struct cache_entry *cache_alloc(void) {
    if (cache_count < CACHE_MAX_ENTRIES) {
        struct cache_entry *e = &cache_pool[cache_count++];
        return e;
    }
    /* Evict LRU tail */
    /* Walk backwards from lru_head.lru_prev (which should be the tail) */
    /* Simple approach: scan the pool for the oldest expire */
    uint64_t oldest_expire = UINT64_MAX;
    struct cache_entry *victim = NULL;
    for (int i = 0; i < CACHE_MAX_ENTRIES; i++) {
        if (cache_pool[i].name[0] && cache_pool[i].expire_ms < oldest_expire) {
            oldest_expire = cache_pool[i].expire_ms;
            victim = &cache_pool[i];
        }
    }
    if (victim) {
        cache_remove_from_bucket(victim);
        lru_remove(victim);
        memset(victim, 0, sizeof(*victim));
        return victim;
    }
    return &cache_pool[0]; /* Shouldn't happen */
}

static void cache_insert(const char *name, uint16_t qtype,
                         const struct cached_rr *rrs, int rr_count,
                         uint32_t ttl, int is_nxdomain) {
    if (ttl == 0) return;
    if (ttl > 86400) ttl = 86400; /* Cap at 1 day */

    /* Check if entry already exists */
    uint32_t h = cache_hash(name, qtype);
    for (struct cache_entry *e = cache_buckets[h]; e; e = e->next) {
        if (e->qtype == qtype && name_eq(e->name, name)) {
            /* Update in place */
            e->expire_ms = now_ms() + (uint64_t)ttl * 1000;
            e->rr_count = rr_count;
            e->is_nxdomain = is_nxdomain;
            if (rr_count > MAX_CACHED_RRS) rr_count = MAX_CACHED_RRS;
            memcpy(e->rrs, rrs, rr_count * sizeof(struct cached_rr));
            lru_remove(e);
            lru_push_front(e);
            return;
        }
    }

    struct cache_entry *e = cache_alloc();
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->qtype = qtype;
    e->expire_ms = now_ms() + (uint64_t)ttl * 1000;
    e->is_nxdomain = is_nxdomain;
    if (rr_count > MAX_CACHED_RRS) rr_count = MAX_CACHED_RRS;
    e->rr_count = rr_count;
    memcpy(e->rrs, rrs, rr_count * sizeof(struct cached_rr));
    e->next = cache_buckets[h];
    cache_buckets[h] = e;
    lru_push_front(e);
}

/* ================================================================
 * RESOLUTION STATE — one per in-flight client query
 * ================================================================ */

enum resolve_state {
    RS_FREE = 0,
    RS_WAITING_REPLY,     /* Sent a query to a nameserver, waiting */
};

struct pending_query {
    enum resolve_state state;

    /* Original client info */
    uint16_t client_txid;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    char     qname[256];
    uint16_t qtype;

    /* Current resolution state */
    uint16_t current_txid;      /* TXID we sent upstream */
    struct sockaddr_in current_ns;
    char    current_ns_name[256]; /* For glueless lookups: NS name we're resolving */
    int     depth;
    int     cname_count;
    uint64_t deadline_ms;        /* Absolute deadline for entire resolution */
    uint64_t hop_deadline_ms;    /* Deadline for current hop */

    /* Nameserver list from last referral */
    struct sockaddr_in ns_list[13];
    int ns_count;
    int ns_tried;
};

static struct pending_query pending[MAX_PENDING];

static struct pending_query *pending_alloc(void) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].state == RS_FREE) {
            memset(&pending[i], 0, sizeof(pending[i]));
            return &pending[i];
        }
    }
    return NULL;
}

static struct pending_query *pending_find_by_txid(uint16_t txid) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].state == RS_WAITING_REPLY &&
            pending[i].current_txid == txid) {
            return &pending[i];
        }
    }
    return NULL;
}

/* ================================================================
 * DNS RESPONSE PARSING
 * ================================================================ */

struct parsed_rr {
    char     name[256];
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t rdlength;
    const uint8_t *rdata;    /* Points into the packet buffer */

    /* Decoded fields for known types */
    char     rdata_name[256]; /* For NS, CNAME: the target name */
    uint32_t rdata_ip;        /* For A records: IPv4 in network byte order */
};

struct parsed_response {
    uint16_t id;
    uint8_t  qr, opcode, aa, tc, rd, ra, rcode;
    char     qname[256];
    uint16_t qtype, qclass;

    int      an_count;
    struct parsed_rr answers[32];

    int      ns_count;
    struct parsed_rr authority[32];

    int      ar_count;
    struct parsed_rr additional[32];
};

/*
 * Parse a section (answer, authority, or additional) of a DNS message.
 * Returns 0 on success, -1 on error.
 */
static int parse_rr_section(const uint8_t *pkt, const uint8_t *pkt_end,
                            const uint8_t **ptr, struct parsed_rr *rrs,
                            int count, int max_rrs) {
    for (int i = 0; i < count; i++) {
        struct parsed_rr *rr = (i < max_rrs) ? &rrs[i] : NULL;
        char name[256];

        if (parse_dns_name(pkt, pkt_end, ptr, name, sizeof(name)) < 0)
            return -1;

        if (*ptr + 10 > pkt_end) return -1;

        uint16_t type  = ((*ptr)[0] << 8) | (*ptr)[1];
        uint16_t cls   = ((*ptr)[2] << 8) | (*ptr)[3];
        uint32_t ttl   = ((*ptr)[4] << 24) | ((*ptr)[5] << 16) |
                         ((*ptr)[6] << 8) | (*ptr)[7];
        uint16_t rdlen = ((*ptr)[8] << 8) | (*ptr)[9];
        *ptr += 10;

        if (*ptr + rdlen > pkt_end) return -1;

        if (rr) {
            snprintf(rr->name, sizeof(rr->name), "%s", name);
            rr->type = type;
            rr->cls = cls;
            rr->ttl = ttl;
            rr->rdlength = rdlen;
            rr->rdata = *ptr;
            rr->rdata_name[0] = '\0';
            rr->rdata_ip = 0;

            if (type == DNS_TYPE_A && rdlen == 4) {
                memcpy(&rr->rdata_ip, *ptr, 4);
            } else if ((type == DNS_TYPE_NS || type == DNS_TYPE_CNAME) && rdlen > 0) {
                const uint8_t *nptr = *ptr;
                parse_dns_name(pkt, pkt_end, &nptr, rr->rdata_name, sizeof(rr->rdata_name));
            }
        }

        *ptr += rdlen;
    }
    return 0;
}

static int parse_response(const uint8_t *pkt, int pkt_len, struct parsed_response *resp) {
    memset(resp, 0, sizeof(*resp));

    if (pkt_len < DNS_HDR_SIZE) return -1;

    const uint8_t *pkt_end = pkt + pkt_len;

    resp->id = (pkt[0] << 8) | pkt[1];
    resp->qr     = (pkt[2] >> 7) & 1;
    resp->opcode = (pkt[2] >> 3) & 0xF;
    resp->aa     = (pkt[2] >> 2) & 1;
    resp->tc     = (pkt[2] >> 1) & 1;
    resp->rd     = pkt[2] & 1;
    resp->ra     = (pkt[3] >> 7) & 1;
    resp->rcode  = pkt[3] & 0xF;

    int qdcount = (pkt[4] << 8) | pkt[5];
    int ancount = (pkt[6] << 8) | pkt[7];
    int nscount = (pkt[8] << 8) | pkt[9];
    int arcount = (pkt[10] << 8) | pkt[11];

    const uint8_t *ptr = pkt + DNS_HDR_SIZE;

    /* Parse question section */
    for (int i = 0; i < qdcount; i++) {
        if (i == 0) {
            if (parse_dns_name(pkt, pkt_end, &ptr, resp->qname, sizeof(resp->qname)) < 0)
                return -1;
            if (ptr + 4 > pkt_end) return -1;
            resp->qtype  = (ptr[0] << 8) | ptr[1];
            resp->qclass = (ptr[2] << 8) | ptr[3];
            ptr += 4;
        } else {
            char skip[256];
            if (parse_dns_name(pkt, pkt_end, &ptr, skip, sizeof(skip)) < 0)
                return -1;
            if (ptr + 4 > pkt_end) return -1;
            ptr += 4;
        }
    }

    /* Parse answer, authority, additional sections */
    resp->an_count = ancount < 32 ? ancount : 32;
    if (parse_rr_section(pkt, pkt_end, &ptr, resp->answers, ancount, 32) < 0)
        return -1;

    resp->ns_count = nscount < 32 ? nscount : 32;
    if (parse_rr_section(pkt, pkt_end, &ptr, resp->authority, nscount, 32) < 0)
        return -1;

    resp->ar_count = arcount < 32 ? arcount : 32;
    if (parse_rr_section(pkt, pkt_end, &ptr, resp->additional, arcount, 32) < 0)
        return -1;

    return 0;
}

/* ================================================================
 * DNS RESPONSE BUILDER
 * ================================================================ */

/*
 * Build a DNS response for a client query.
 * Returns the total length of the response, or -1 on error.
 */
static int build_response(uint8_t *buf, int buf_size,
                          uint16_t txid, const char *qname, uint16_t qtype,
                          uint8_t rcode,
                          const struct cached_rr *answers, int an_count) {
    if (buf_size < DNS_HDR_SIZE) return -1;

    /* Header */
    buf[0] = txid >> 8;
    buf[1] = txid & 0xFF;
    buf[2] = 0x81;          /* QR=1, RD=1 */
    buf[3] = 0x80 | rcode;  /* RA=1, RCODE */
    buf[4] = 0; buf[5] = 1; /* QDCOUNT = 1 */
    buf[6] = (an_count >> 8); buf[7] = an_count & 0xFF;
    buf[8] = 0; buf[9] = 0;   /* NSCOUNT = 0 */
    buf[10] = 0; buf[11] = 0; /* ARCOUNT = 0 */

    int pos = DNS_HDR_SIZE;

    /* Question section */
    int name_len = encode_dns_name(qname, &buf[pos], buf_size - pos);
    if (name_len < 0) return -1;
    pos += name_len;

    if (pos + 4 > buf_size) return -1;
    buf[pos++] = qtype >> 8;
    buf[pos++] = qtype & 0xFF;
    buf[pos++] = 0; buf[pos++] = 1; /* CLASS IN */

    /* Answer section */
    for (int i = 0; i < an_count; i++) {
        name_len = encode_dns_name(qname, &buf[pos], buf_size - pos);
        if (name_len < 0) return -1;
        pos += name_len;

        if (pos + 10 + answers[i].rdlength > buf_size) return -1;

        buf[pos++] = answers[i].type >> 8;
        buf[pos++] = answers[i].type & 0xFF;
        buf[pos++] = 0; buf[pos++] = 1; /* CLASS IN */
        /* TTL — use 60 for cached answers */
        buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 60;
        buf[pos++] = answers[i].rdlength >> 8;
        buf[pos++] = answers[i].rdlength & 0xFF;
        memcpy(&buf[pos], answers[i].rdata, answers[i].rdlength);
        pos += answers[i].rdlength;
    }

    return pos;
}

/* Build a simple error response (SERVFAIL, NXDOMAIN, NOTIMP) */
static int build_error_response(uint8_t *buf, int buf_size,
                                uint16_t txid, const char *qname,
                                uint16_t qtype, uint8_t rcode) {
    return build_response(buf, buf_size, txid, qname, qtype, rcode, NULL, 0);
}

/* ================================================================
 * LOCAL-ANSWER MODE (for benchmarking)
 * ================================================================ */
static int local_mode = 0;

struct local_record {
    const char *name;
    uint16_t type;
    uint8_t  rdata[16];
    uint16_t rdlength;
};

/* A small built-in zone for benchmark testing */
static const struct local_record local_zone[] = {
    { "example.com",      DNS_TYPE_A,    {93, 184, 216, 34},  4 },
    { "www.example.com",  DNS_TYPE_A,    {93, 184, 216, 34},  4 },
    { "test.example.com", DNS_TYPE_A,    {93, 184, 216, 34},  4 },
    { "google.com",       DNS_TYPE_A,    {142, 250, 80, 46},  4 },
    { "www.google.com",   DNS_TYPE_A,    {142, 250, 80, 46},  4 },
    { "cloudflare.com",   DNS_TYPE_A,    {104, 16, 132, 229}, 4 },
    { "github.com",       DNS_TYPE_A,    {140, 82, 121, 3},   4 },
    { "dns.google",       DNS_TYPE_A,    {8, 8, 8, 8},        4 },
    { NULL, 0, {0}, 0 },
};

static int handle_local_query(const char *qname, uint16_t qtype,
                              struct cached_rr *out, int *out_count) {
    *out_count = 0;
    for (int i = 0; local_zone[i].name; i++) {
        if (name_eq(local_zone[i].name, qname) &&
            local_zone[i].type == qtype) {
            if (*out_count < MAX_CACHED_RRS) {
                out[*out_count].type = local_zone[i].type;
                out[*out_count].rdlength = local_zone[i].rdlength;
                memcpy(out[*out_count].rdata, local_zone[i].rdata,
                       local_zone[i].rdlength);
                (*out_count)++;
            }
        }
    }
    return *out_count > 0 ? 0 : -1; /* 0 = found, -1 = NXDOMAIN */
}

/* ================================================================
 * QUERY BUILDING (for sending to nameservers)
 * ================================================================ */

/*
 * Build a DNS query packet.
 * Returns total length, or -1 on error.
 */
static int build_query(uint8_t *buf, int buf_size,
                       uint16_t txid, const char *qname, uint16_t qtype) {
    if (buf_size < DNS_HDR_SIZE) return -1;

    buf[0] = txid >> 8;
    buf[1] = txid & 0xFF;
    buf[2] = 0x01;          /* RD=1 (we set RD even though we do iterative;
                               some servers won't answer without it) */
    buf[3] = 0x00;
    buf[4] = 0; buf[5] = 1; /* QDCOUNT = 1 */
    buf[6] = 0; buf[7] = 0;
    buf[8] = 0; buf[9] = 0;
    buf[10] = 0; buf[11] = 0;

    int pos = DNS_HDR_SIZE;
    int name_len = encode_dns_name(qname, &buf[pos], buf_size - pos);
    if (name_len < 0) return -1;
    pos += name_len;

    if (pos + 4 > buf_size) return -1;
    buf[pos++] = qtype >> 8;
    buf[pos++] = qtype & 0xFF;
    buf[pos++] = 0; buf[pos++] = 1; /* CLASS IN */

    return pos;
}

/* ================================================================
 * RESOLUTION ENGINE
 * ================================================================ */

static int upstream_fd;

/*
 * Send a query to a nameserver and update pending state.
 */
static void send_to_ns(struct pending_query *pq,
                       struct sockaddr_in *ns_addr) {
    uint8_t buf[BUF_SIZE];
    pq->current_txid = rand_txid();
    pq->current_ns = *ns_addr;
    pq->hop_deadline_ms = now_ms() + UPSTREAM_TIMEOUT_MS;

    int len = build_query(buf, sizeof(buf), pq->current_txid,
                          pq->qname, pq->qtype);
    if (len < 0) {
        pq->state = RS_FREE;
        return;
    }

    sendto(upstream_fd, buf, len, 0,
           (struct sockaddr *)ns_addr, sizeof(*ns_addr));
    pq->state = RS_WAITING_REPLY;
}

/*
 * Start resolution for a pending query — pick a root server.
 */
static void start_resolution(struct pending_query *pq) {
    /* Check cache first */
    struct cache_entry *ce = cache_lookup(pq->qname, pq->qtype);
    if (ce) {
        /* Cache hit — we'll handle this in the caller */
        return;
    }

    /* Start from a random root server */
    struct sockaddr_in root;
    memset(&root, 0, sizeof(root));
    root.sin_family = AF_INET;
    root.sin_port = htons(53);
    int root_idx = rand_txid() % NUM_ROOTS;
    inet_pton(AF_INET, ROOT_SERVERS[root_idx], &root.sin_addr);

    pq->depth = 0;
    pq->cname_count = 0;
    pq->deadline_ms = now_ms() + QUERY_TIMEOUT_MS;
    pq->ns_count = 0;
    pq->ns_tried = 0;

    send_to_ns(pq, &root);
}

/*
 * Try the next nameserver from the NS list (after a timeout or error).
 * Returns 0 if we sent a new query, -1 if we've exhausted the list.
 */
static int try_next_ns(struct pending_query *pq) {
    while (pq->ns_tried < pq->ns_count) {
        int idx = pq->ns_tried++;
        send_to_ns(pq, &pq->ns_list[idx]);
        return 0;
    }
    return -1;
}

/*
 * Handle a response from a nameserver for a pending query.
 * This implements the iterative resolution logic:
 *   - If we get an answer, cache it and reply to the client.
 *   - If we get a referral, follow it.
 *   - If we get a CNAME, follow it.
 *   - If we get NXDOMAIN, reply NXDOMAIN.
 *   - If we get SERVFAIL or junk, try the next NS.
 */
static void handle_ns_response(struct pending_query *pq,
                               struct parsed_response *resp,
                               int client_fd) {
    uint8_t reply_buf[BUF_SIZE];
    int reply_len;

    /* 1. Check for NXDOMAIN */
    if (resp->rcode == DNS_RCODE_NXDOMAIN) {
        /* Cache negative result */
        uint32_t neg_ttl = 300; /* Default negative TTL */
        /* Try to get SOA minimum from authority section */
        for (int i = 0; i < resp->ns_count; i++) {
            if (resp->authority[i].type == 6 /* SOA */ && resp->authority[i].rdlength > 0) {
                /* Last 4 bytes of SOA RDATA are the minimum TTL */
                if (resp->authority[i].rdlength >= 20) {
                    const uint8_t *p = resp->authority[i].rdata + resp->authority[i].rdlength - 4;
                    neg_ttl = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
                    if (neg_ttl > 3600) neg_ttl = 3600;
                }
            }
        }
        cache_insert(pq->qname, pq->qtype, NULL, 0, neg_ttl, 1);

        reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                         pq->client_txid, pq->qname,
                                         pq->qtype, DNS_RCODE_NXDOMAIN);
        if (reply_len > 0) {
            sendto(client_fd, reply_buf, reply_len, 0,
                   (struct sockaddr *)&pq->client_addr, pq->client_len);
        }
        pq->state = RS_FREE;
        return;
    }

    /* 2. Check for answers */
    if (resp->an_count > 0) {
        struct cached_rr rrs[MAX_CACHED_RRS];
        int rr_count = 0;
        uint32_t min_ttl = 86400;
        int found_answer = 0;
        int found_cname = 0;
        char cname_target[256] = {0};

        for (int i = 0; i < resp->an_count && rr_count < MAX_CACHED_RRS; i++) {
            struct parsed_rr *rr = &resp->answers[i];

            if (rr->type == DNS_TYPE_CNAME && name_eq(rr->name, pq->qname)) {
                /* CNAME — follow it */
                found_cname = 1;
                snprintf(cname_target, sizeof(cname_target), "%s", rr->rdata_name);

                /* Also store the CNAME in the answer */
                rrs[rr_count].type = rr->type;
                rrs[rr_count].rdlength = rr->rdlength;
                if (rr->rdlength <= MAX_RR_RDATA)
                    memcpy(rrs[rr_count].rdata, rr->rdata, rr->rdlength);
                rr_count++;
                if (rr->ttl < min_ttl) min_ttl = rr->ttl;
                continue;
            }

            if (rr->type == pq->qtype && name_eq(rr->name, pq->qname)) {
                found_answer = 1;
                rrs[rr_count].type = rr->type;
                rrs[rr_count].rdlength = rr->rdlength;
                if (rr->rdlength <= MAX_RR_RDATA)
                    memcpy(rrs[rr_count].rdata, rr->rdata, rr->rdlength);
                rr_count++;
                if (rr->ttl < min_ttl) min_ttl = rr->ttl;
            }
        }

        if (found_answer) {
            /* Cache and reply */
            cache_insert(pq->qname, pq->qtype, rrs, rr_count, min_ttl, 0);

            reply_len = build_response(reply_buf, sizeof(reply_buf),
                                       pq->client_txid, pq->qname, pq->qtype,
                                       DNS_RCODE_NOERROR, rrs, rr_count);
            if (reply_len > 0) {
                sendto(client_fd, reply_buf, reply_len, 0,
                       (struct sockaddr *)&pq->client_addr, pq->client_len);
            }
            pq->state = RS_FREE;
            return;
        }

        if (found_cname && cname_target[0]) {
            /* Follow CNAME */
            if (++pq->cname_count > MAX_CNAME_CHAIN) {
                reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                                 pq->client_txid, pq->qname,
                                                 pq->qtype, DNS_RCODE_SERVFAIL);
                if (reply_len > 0) {
                    sendto(client_fd, reply_buf, reply_len, 0,
                           (struct sockaddr *)&pq->client_addr, pq->client_len);
                }
                pq->state = RS_FREE;
                return;
            }

            /* Cache the CNAME */
            cache_insert(pq->qname, DNS_TYPE_CNAME, rrs, 1, min_ttl, 0);

            /* Restart resolution with the CNAME target */
            snprintf(pq->qname, sizeof(pq->qname), "%s", cname_target);
            pq->depth = 0;
            pq->ns_count = 0;
            pq->ns_tried = 0;

            /* Check cache for the target */
            struct cache_entry *ce = cache_lookup(pq->qname, pq->qtype);
            if (ce && !ce->is_nxdomain && ce->rr_count > 0) {
                reply_len = build_response(reply_buf, sizeof(reply_buf),
                                           pq->client_txid, pq->qname,
                                           pq->qtype, DNS_RCODE_NOERROR,
                                           ce->rrs, ce->rr_count);
                if (reply_len > 0) {
                    sendto(client_fd, reply_buf, reply_len, 0,
                           (struct sockaddr *)&pq->client_addr, pq->client_len);
                }
                pq->state = RS_FREE;
                return;
            }

            /* Start from root again for the CNAME target */
            struct sockaddr_in root;
            memset(&root, 0, sizeof(root));
            root.sin_family = AF_INET;
            root.sin_port = htons(53);
            inet_pton(AF_INET, ROOT_SERVERS[rand_txid() % NUM_ROOTS], &root.sin_addr);
            send_to_ns(pq, &root);
            return;
        }
    }

    /* 3. Check for referral (NS records in authority, no answers) */
    if (resp->ns_count > 0 && resp->an_count == 0) {
        if (++pq->depth > MAX_DEPTH) {
            reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                             pq->client_txid, pq->qname,
                                             pq->qtype, DNS_RCODE_SERVFAIL);
            if (reply_len > 0) {
                sendto(client_fd, reply_buf, reply_len, 0,
                       (struct sockaddr *)&pq->client_addr, pq->client_len);
            }
            pq->state = RS_FREE;
            return;
        }

        /* Collect NS records and find glue */
        pq->ns_count = 0;
        pq->ns_tried = 0;

        for (int i = 0; i < resp->ns_count && pq->ns_count < 13; i++) {
            if (resp->authority[i].type != DNS_TYPE_NS) continue;

            char ns_name[256];
            snprintf(ns_name, sizeof(ns_name), "%s", resp->authority[i].rdata_name);
            if (ns_name[0] == '\0') continue;

            /* Look for glue A record in additional section */
            int found_glue = 0;
            for (int j = 0; j < resp->ar_count; j++) {
                if (resp->additional[j].type == DNS_TYPE_A &&
                    name_eq(resp->additional[j].name, ns_name) &&
                    resp->additional[j].rdlength == 4) {
                    struct sockaddr_in ns_addr;
                    memset(&ns_addr, 0, sizeof(ns_addr));
                    ns_addr.sin_family = AF_INET;
                    ns_addr.sin_port = htons(53);
                    memcpy(&ns_addr.sin_addr, resp->additional[j].rdata, 4);
                    pq->ns_list[pq->ns_count++] = ns_addr;
                    found_glue = 1;
                    break;
                }
            }

            if (!found_glue) {
                /* Check cache for NS IP */
                struct cache_entry *nce = cache_lookup(ns_name, DNS_TYPE_A);
                if (nce && !nce->is_nxdomain && nce->rr_count > 0) {
                    for (int k = 0; k < nce->rr_count && pq->ns_count < 13; k++) {
                        if (nce->rrs[k].type == DNS_TYPE_A && nce->rrs[k].rdlength == 4) {
                            struct sockaddr_in ns_addr;
                            memset(&ns_addr, 0, sizeof(ns_addr));
                            ns_addr.sin_family = AF_INET;
                            ns_addr.sin_port = htons(53);
                            memcpy(&ns_addr.sin_addr, nce->rrs[k].rdata, 4);
                            pq->ns_list[pq->ns_count++] = ns_addr;
                            break;
                        }
                    }
                }
                /*
                 * If no glue and no cache hit, we'd need a sub-query
                 * (glueless delegation). For simplicity, we skip this NS
                 * and try the others. Most TLD servers provide glue.
                 */
            }
        }

        if (pq->ns_count > 0) {
            /* Send to the first NS in the referral list */
            pq->ns_tried = 1;
            send_to_ns(pq, &pq->ns_list[0]);
            return;
        }

        /* No usable NS — SERVFAIL */
        reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                         pq->client_txid, pq->qname,
                                         pq->qtype, DNS_RCODE_SERVFAIL);
        if (reply_len > 0) {
            sendto(client_fd, reply_buf, reply_len, 0,
                   (struct sockaddr *)&pq->client_addr, pq->client_len);
        }
        pq->state = RS_FREE;
        return;
    }

    /* 4. SERVFAIL or unexpected — try next NS */
    if (try_next_ns(pq) < 0) {
        /* All NS exhausted — SERVFAIL to client */
        reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                         pq->client_txid, pq->qname,
                                         pq->qtype, DNS_RCODE_SERVFAIL);
        if (reply_len > 0) {
            sendto(client_fd, reply_buf, reply_len, 0,
                   (struct sockaddr *)&pq->client_addr, pq->client_len);
        }
        pq->state = RS_FREE;
    }
}

/* ================================================================
 * TIMEOUT HANDLER
 * ================================================================ */
static void check_timeouts(int client_fd) {
    uint64_t now = now_ms();

    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].state != RS_WAITING_REPLY) continue;

        /* Overall deadline expired — SERVFAIL */
        if (now >= pending[i].deadline_ms) {
            uint8_t reply_buf[BUF_SIZE];
            int reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                                 pending[i].client_txid,
                                                 pending[i].qname,
                                                 pending[i].qtype,
                                                 DNS_RCODE_SERVFAIL);
            if (reply_len > 0) {
                sendto(client_fd, reply_buf, reply_len, 0,
                       (struct sockaddr *)&pending[i].client_addr,
                       pending[i].client_len);
            }
            pending[i].state = RS_FREE;
            continue;
        }

        /* Per-hop timeout — try next NS */
        if (now >= pending[i].hop_deadline_ms) {
            if (try_next_ns(&pending[i]) < 0) {
                /* Exhausted NS list — restart from a different root */
                struct sockaddr_in root;
                memset(&root, 0, sizeof(root));
                root.sin_family = AF_INET;
                root.sin_port = htons(53);
                inet_pton(AF_INET, ROOT_SERVERS[rand_txid() % NUM_ROOTS], &root.sin_addr);
                pending[i].ns_count = 0;
                pending[i].ns_tried = 0;
                send_to_ns(&pending[i], &root);
            }
        }
    }
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(int argc, char *argv[]) {
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--local") == 0) {
            local_mode = 1;
        }
    }

    srand((unsigned)time(NULL));
    cache_init();
    memset(pending, 0, sizeof(pending));

    /* Create sockets */
    int client_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (client_fd < 0) { perror("socket(client)"); exit(1); }

    upstream_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (upstream_fd < 0) { perror("socket(upstream)"); exit(1); }

    /* Bind client socket */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LISTEN_PORT);
    if (bind(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind(client)");
        exit(1);
    }

    /* Set up epoll */
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); exit(1); }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

    if (!local_mode) {
        ev.events = EPOLLIN;
        ev.data.fd = upstream_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstream_fd, &ev);
    }

    fprintf(stderr, "Recursive resolver listening on port %d%s\n",
            LISTEN_PORT, local_mode ? " (LOCAL MODE)" : "");

    /* ============================================================
     * EVENT LOOP
     * ============================================================ */
    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int timeout_ms = local_mode ? -1 : 100; /* 100ms poll for timeouts */
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, timeout_ms);

        /* Check for timeouts (not in local mode) */
        if (!local_mode) {
            check_timeouts(client_fd);
        }

        for (int i = 0; i < nfds; i++) {
            int active_fd = events[i].data.fd;

            /* ====================================================
             * PATH A: NEW QUERY FROM CLIENT
             * ==================================================== */
            if (active_fd == client_fd) {
                uint8_t buffer[BUF_SIZE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);

                int bytes_read = recvfrom(client_fd, buffer, BUF_SIZE, 0,
                                         (struct sockaddr *)&client_addr,
                                         &client_len);
                if (bytes_read < 0) continue;
                if (bytes_read < DNS_HDR_SIZE) continue;

                /* Validate: must be a standard query */
                uint8_t qr     = (buffer[2] >> 7) & 1;
                uint8_t opcode = (buffer[2] >> 3) & 0xF;
                if (qr != 0 || opcode != 0) continue;

                uint16_t qdcount = (buffer[4] << 8) | buffer[5];
                if (qdcount < 1) continue;

                /* Parse question */
                const uint8_t *ptr = buffer + DNS_HDR_SIZE;
                const uint8_t *buf_end = buffer + bytes_read;
                char qname[256];
                if (parse_dns_name(buffer, buf_end, &ptr, qname, sizeof(qname)) < 0)
                    continue;

                if (ptr + 4 > buf_end) continue;
                uint16_t qtype  = (ptr[0] << 8) | ptr[1];
                /* uint16_t qclass = (ptr[2] << 8) | ptr[3]; */

                uint16_t client_txid = (buffer[0] << 8) | buffer[1];

                /* Only handle A and AAAA — reject others with NOTIMP */
                if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
                    uint8_t reply_buf[BUF_SIZE];
                    int reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                                        client_txid, qname, qtype,
                                                        DNS_RCODE_NOTIMP);
                    if (reply_len > 0) {
                        sendto(client_fd, reply_buf, reply_len, 0,
                               (struct sockaddr *)&client_addr, client_len);
                    }
                    continue;
                }

                /* === LOCAL MODE === */
                if (local_mode) {
                    struct cached_rr answers[MAX_CACHED_RRS];
                    int an_count = 0;
                    uint8_t rcode = DNS_RCODE_NOERROR;

                    if (handle_local_query(qname, qtype, answers, &an_count) < 0) {
                        rcode = DNS_RCODE_NXDOMAIN;
                        an_count = 0;
                    }

                    uint8_t reply_buf[BUF_SIZE];
                    int reply_len = build_response(reply_buf, sizeof(reply_buf),
                                                   client_txid, qname, qtype,
                                                   rcode, answers, an_count);
                    if (reply_len > 0) {
                        sendto(client_fd, reply_buf, reply_len, 0,
                               (struct sockaddr *)&client_addr, client_len);
                    }
                    continue;
                }

                /* === RECURSIVE MODE === */

                /* Check cache */
                struct cache_entry *ce = cache_lookup(qname, qtype);
                if (ce) {
                    uint8_t reply_buf[BUF_SIZE];
                    int reply_len;
                    if (ce->is_nxdomain) {
                        reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                                         client_txid, qname, qtype,
                                                         DNS_RCODE_NXDOMAIN);
                    } else {
                        reply_len = build_response(reply_buf, sizeof(reply_buf),
                                                   client_txid, qname, qtype,
                                                   DNS_RCODE_NOERROR,
                                                   ce->rrs, ce->rr_count);
                    }
                    if (reply_len > 0) {
                        sendto(client_fd, reply_buf, reply_len, 0,
                               (struct sockaddr *)&client_addr, client_len);
                    }
                    continue;
                }

                /* Allocate pending query */
                struct pending_query *pq = pending_alloc();
                if (!pq) {
                    /* Overloaded — SERVFAIL */
                    uint8_t reply_buf[BUF_SIZE];
                    int reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                                         client_txid, qname, qtype,
                                                         DNS_RCODE_SERVFAIL);
                    if (reply_len > 0) {
                        sendto(client_fd, reply_buf, reply_len, 0,
                               (struct sockaddr *)&client_addr, client_len);
                    }
                    continue;
                }

                pq->client_txid = client_txid;
                pq->client_addr = client_addr;
                pq->client_len = client_len;
                snprintf(pq->qname, sizeof(pq->qname), "%s", qname);
                pq->qtype = qtype;

                start_resolution(pq);
            }

            /* ====================================================
             * PATH B: RESPONSE FROM UPSTREAM NAMESERVER
             * ==================================================== */
            else if (active_fd == upstream_fd) {
                uint8_t buffer[BUF_SIZE];
                struct sockaddr_in sender_addr;
                socklen_t sender_len = sizeof(sender_addr);

                int bytes_read = recvfrom(upstream_fd, buffer, BUF_SIZE, 0,
                                         (struct sockaddr *)&sender_addr,
                                         &sender_len);
                if (bytes_read < 0) continue;
                if (bytes_read < DNS_HDR_SIZE) continue;

                /* Must be a response */
                if (!(buffer[2] & 0x80)) continue;

                uint16_t resp_txid = (buffer[0] << 8) | buffer[1];

                /* Find the pending query this response belongs to */
                struct pending_query *pq = pending_find_by_txid(resp_txid);
                if (!pq) continue;

                /* Verify sender matches the NS we queried */
                if (sender_addr.sin_addr.s_addr != pq->current_ns.sin_addr.s_addr) {
                    continue;
                }

                /* Parse the response */
                struct parsed_response resp;
                if (parse_response(buffer, bytes_read, &resp) < 0) {
                    /* Malformed — try next NS */
                    if (try_next_ns(pq) < 0) {
                        uint8_t reply_buf[BUF_SIZE];
                        int reply_len = build_error_response(reply_buf, sizeof(reply_buf),
                                                             pq->client_txid, pq->qname,
                                                             pq->qtype, DNS_RCODE_SERVFAIL);
                        if (reply_len > 0) {
                            sendto(client_fd, reply_buf, reply_len, 0,
                                   (struct sockaddr *)&pq->client_addr, pq->client_len);
                        }
                        pq->state = RS_FREE;
                    }
                    continue;
                }

                /* Handle the parsed response */
                handle_ns_response(pq, &resp, client_fd);
            }
        }
    }

    return 0;
}
