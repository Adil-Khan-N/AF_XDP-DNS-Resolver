/*
 * socket_resolver.c — Baseline DNS resolver (normal UDP sockets)
 *
 * Uses dns.c for all DNS logic. This is the control binary in the
 * benchmark: identical DNS processing to afxdp_resolver, but packets
 * go through the normal Linux networking stack.
 *
 * Build:
 *   gcc -O3 -Wall -Wextra -o socket_resolver socket_resolver.c dns.c
 *
 * Usage:
 *   sudo ./socket_resolver              # recursive mode, port 53
 *   sudo ./socket_resolver --local      # local-answer mode (benchmark)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include "dns.h"

/* ================================================================
 * CONFIGURATION
 * ================================================================ */
#define LISTEN_PORT         53
#define BUF_SIZE            1500
#define MAX_EVENTS          64
#define MAX_PENDING         4096
#define MAX_DEPTH           16
#define MAX_CNAME_CHAIN     8
#define QUERY_TIMEOUT_MS    5000
#define UPSTREAM_TIMEOUT_MS 2000

/* Cache */
#define CACHE_BUCKETS       4096
#define CACHE_MAX_ENTRIES   8192

/* ================================================================
 * ROOT SERVERS
 * ================================================================ */
static const char *ROOT_SERVERS[] = {
    "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33",
};
#define NUM_ROOTS 13

/* ================================================================
 * UTILITY
 * ================================================================ */
static uint16_t rand_txid(void) {
    uint16_t val;
    if (getrandom(&val, sizeof(val), 0) != sizeof(val))
        val = (uint16_t)(rand() ^ (rand() << 8));
    return val;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ================================================================
 * CACHE (same as recursive_resolver.c)
 * ================================================================ */
struct cache_entry {
    char     name[256];
    uint16_t qtype;
    uint64_t expire_ms;
    int      rr_count;
    struct cached_rr rrs[MAX_CACHED_RRS];
    int      is_nxdomain;
    struct cache_entry *next;
};

static struct cache_entry *cache_ht[CACHE_BUCKETS];
static struct cache_entry  cache_pool[CACHE_MAX_ENTRIES];
static int cache_count = 0;

static uint32_t cache_hash(const char *name, uint16_t qtype) {
    uint32_t h = qtype * 31;
    for (const char *p = name; *p; p++)
        h = h * 131 + tolower(*p);
    return h % CACHE_BUCKETS;
}

static void cache_init(void) {
    memset(cache_ht, 0, sizeof(cache_ht));
    memset(cache_pool, 0, sizeof(cache_pool));
    cache_count = 0;
}

static struct cache_entry *cache_lookup(const char *name, uint16_t qtype) {
    uint32_t h = cache_hash(name, qtype);
    uint64_t now = now_ms();
    for (struct cache_entry *e = cache_ht[h]; e; e = e->next) {
        if (e->qtype == qtype && dns_name_eq(e->name, name)) {
            if (e->expire_ms <= now) return NULL;
            return e;
        }
    }
    return NULL;
}

static void cache_remove_from_bucket(struct cache_entry *e) {
    uint32_t h = cache_hash(e->name, e->qtype);
    struct cache_entry **pp = &cache_ht[h];
    while (*pp) {
        if (*pp == e) { *pp = e->next; return; }
        pp = &(*pp)->next;
    }
}

static struct cache_entry *cache_alloc(void) {
    if (cache_count < CACHE_MAX_ENTRIES)
        return &cache_pool[cache_count++];
    uint64_t oldest = UINT64_MAX;
    struct cache_entry *victim = NULL;
    for (int i = 0; i < CACHE_MAX_ENTRIES; i++) {
        if (cache_pool[i].name[0] && cache_pool[i].expire_ms < oldest) {
            oldest = cache_pool[i].expire_ms;
            victim = &cache_pool[i];
        }
    }
    if (victim) {
        cache_remove_from_bucket(victim);
        memset(victim, 0, sizeof(*victim));
        return victim;
    }
    return &cache_pool[0];
}

static void cache_insert(const char *name, uint16_t qtype,
                         const struct cached_rr *rrs, int rr_count,
                         uint32_t ttl, int is_nxdomain) {
    if (ttl == 0) return;
    if (ttl > 86400) ttl = 86400;

    uint32_t h = cache_hash(name, qtype);
    for (struct cache_entry *e = cache_ht[h]; e; e = e->next) {
        if (e->qtype == qtype && dns_name_eq(e->name, name)) {
            e->expire_ms = now_ms() + (uint64_t)ttl * 1000;
            e->rr_count = rr_count > MAX_CACHED_RRS ? MAX_CACHED_RRS : rr_count;
            e->is_nxdomain = is_nxdomain;
            memcpy(e->rrs, rrs, e->rr_count * sizeof(struct cached_rr));
            return;
        }
    }

    struct cache_entry *e = cache_alloc();
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->qtype = qtype;
    e->expire_ms = now_ms() + (uint64_t)ttl * 1000;
    e->is_nxdomain = is_nxdomain;
    e->rr_count = rr_count > MAX_CACHED_RRS ? MAX_CACHED_RRS : rr_count;
    memcpy(e->rrs, rrs, e->rr_count * sizeof(struct cached_rr));
    e->next = cache_ht[h];
    cache_ht[h] = e;
}

/* ================================================================
 * PENDING QUERIES (recursive mode)
 * ================================================================ */
enum resolve_state { RS_FREE = 0, RS_WAITING_REPLY };

struct pending_query {
    enum resolve_state state;
    uint16_t client_txid;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    char     qname[256];
    uint16_t qtype;

    uint16_t current_txid;
    struct sockaddr_in current_ns;
    int     depth;
    int     cname_count;
    uint64_t deadline_ms;
    uint64_t hop_deadline_ms;

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
            pending[i].current_txid == txid)
            return &pending[i];
    }
    return NULL;
}

/* ================================================================
 * RESOLUTION ENGINE
 * ================================================================ */
static int upstream_fd;

static void send_to_ns(struct pending_query *pq, struct sockaddr_in *ns) {
    uint8_t buf[BUF_SIZE];
    pq->current_txid = rand_txid();
    pq->current_ns = *ns;
    pq->hop_deadline_ms = now_ms() + UPSTREAM_TIMEOUT_MS;

    int len = dns_build_query(buf, sizeof(buf), pq->current_txid,
                              pq->qname, pq->qtype);
    if (len < 0) { pq->state = RS_FREE; return; }

    sendto(upstream_fd, buf, len, 0, (struct sockaddr *)ns, sizeof(*ns));
    pq->state = RS_WAITING_REPLY;
}

static void start_resolution(struct pending_query *pq) {
    struct sockaddr_in root;
    memset(&root, 0, sizeof(root));
    root.sin_family = AF_INET;
    root.sin_port = htons(53);
    inet_pton(AF_INET, ROOT_SERVERS[rand_txid() % NUM_ROOTS], &root.sin_addr);

    pq->depth = 0;
    pq->cname_count = 0;
    pq->deadline_ms = now_ms() + QUERY_TIMEOUT_MS;
    pq->ns_count = 0;
    pq->ns_tried = 0;
    send_to_ns(pq, &root);
}

static int try_next_ns(struct pending_query *pq) {
    while (pq->ns_tried < pq->ns_count) {
        send_to_ns(pq, &pq->ns_list[pq->ns_tried++]);
        return 0;
    }
    return -1;
}

static void reply_error(int client_fd, struct pending_query *pq, uint8_t rcode) {
    uint8_t buf[BUF_SIZE];
    int len = dns_build_error(buf, sizeof(buf), pq->client_txid,
                              pq->qname, pq->qtype, rcode);
    if (len > 0)
        sendto(client_fd, buf, len, 0,
               (struct sockaddr *)&pq->client_addr, pq->client_len);
    pq->state = RS_FREE;
}

static void handle_ns_response(struct pending_query *pq,
                               struct parsed_response *resp,
                               int client_fd) {
    uint8_t reply_buf[BUF_SIZE];
    int reply_len;

    /* NXDOMAIN */
    if (resp->rcode == DNS_RCODE_NXDOMAIN) {
        uint32_t neg_ttl = 300;
        for (int i = 0; i < resp->ns_count; i++) {
            if (resp->authority[i].type == DNS_TYPE_SOA &&
                resp->authority[i].rdlength >= 20) {
                const uint8_t *p = resp->authority[i].rdata +
                                   resp->authority[i].rdlength - 4;
                neg_ttl = (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
                if (neg_ttl > 3600) neg_ttl = 3600;
            }
        }
        cache_insert(pq->qname, pq->qtype, NULL, 0, neg_ttl, 1);
        reply_error(client_fd, pq, DNS_RCODE_NXDOMAIN);
        return;
    }

    /* Answers */
    if (resp->an_count > 0) {
        struct cached_rr rrs[MAX_CACHED_RRS];
        int rr_count = 0;
        uint32_t min_ttl = 86400;
        int found_answer = 0, found_cname = 0;
        char cname_target[256] = {0};

        for (int i = 0; i < resp->an_count && rr_count < MAX_CACHED_RRS; i++) {
            struct parsed_rr *rr = &resp->answers[i];

            if (rr->type == DNS_TYPE_CNAME && dns_name_eq(rr->name, pq->qname)) {
                found_cname = 1;
                snprintf(cname_target, sizeof(cname_target), "%s", rr->rdata_name);
                rrs[rr_count].type = rr->type;
                rrs[rr_count].rdlength = rr->rdlength;
                if (rr->rdlength <= MAX_RR_RDATA)
                    memcpy(rrs[rr_count].rdata, rr->rdata, rr->rdlength);
                rr_count++;
                if (rr->ttl < min_ttl) min_ttl = rr->ttl;
                continue;
            }

            if (rr->type == pq->qtype && dns_name_eq(rr->name, pq->qname)) {
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
            cache_insert(pq->qname, pq->qtype, rrs, rr_count, min_ttl, 0);
            reply_len = dns_build_response(reply_buf, sizeof(reply_buf),
                                           pq->client_txid, pq->qname, pq->qtype,
                                           DNS_RCODE_NOERROR, rrs, rr_count);
            if (reply_len > 0)
                sendto(client_fd, reply_buf, reply_len, 0,
                       (struct sockaddr *)&pq->client_addr, pq->client_len);
            pq->state = RS_FREE;
            return;
        }

        if (found_cname && cname_target[0]) {
            if (++pq->cname_count > MAX_CNAME_CHAIN) {
                reply_error(client_fd, pq, DNS_RCODE_SERVFAIL);
                return;
            }
            cache_insert(pq->qname, DNS_TYPE_CNAME, rrs, 1, min_ttl, 0);
            snprintf(pq->qname, sizeof(pq->qname), "%s", cname_target);
            pq->depth = 0;
            pq->ns_count = 0;
            pq->ns_tried = 0;

            struct cache_entry *ce = cache_lookup(pq->qname, pq->qtype);
            if (ce && !ce->is_nxdomain && ce->rr_count > 0) {
                reply_len = dns_build_response(reply_buf, sizeof(reply_buf),
                                               pq->client_txid, pq->qname,
                                               pq->qtype, DNS_RCODE_NOERROR,
                                               ce->rrs, ce->rr_count);
                if (reply_len > 0)
                    sendto(client_fd, reply_buf, reply_len, 0,
                           (struct sockaddr *)&pq->client_addr, pq->client_len);
                pq->state = RS_FREE;
                return;
            }

            struct sockaddr_in root;
            memset(&root, 0, sizeof(root));
            root.sin_family = AF_INET;
            root.sin_port = htons(53);
            inet_pton(AF_INET, ROOT_SERVERS[rand_txid() % NUM_ROOTS],
                      &root.sin_addr);
            send_to_ns(pq, &root);
            return;
        }
    }

    /* Referral */
    if (resp->ns_count > 0 && resp->an_count == 0) {
        if (++pq->depth > MAX_DEPTH) {
            reply_error(client_fd, pq, DNS_RCODE_SERVFAIL);
            return;
        }

        pq->ns_count = 0;
        pq->ns_tried = 0;

        for (int i = 0; i < resp->ns_count && pq->ns_count < 13; i++) {
            if (resp->authority[i].type != DNS_TYPE_NS) continue;
            char ns_name[256];
            snprintf(ns_name, sizeof(ns_name), "%s", resp->authority[i].rdata_name);
            if (!ns_name[0]) continue;

            int found_glue = 0;
            for (int j = 0; j < resp->ar_count; j++) {
                if (resp->additional[j].type == DNS_TYPE_A &&
                    dns_name_eq(resp->additional[j].name, ns_name) &&
                    resp->additional[j].rdlength == 4) {
                    struct sockaddr_in a;
                    memset(&a, 0, sizeof(a));
                    a.sin_family = AF_INET;
                    a.sin_port = htons(53);
                    memcpy(&a.sin_addr, resp->additional[j].rdata, 4);
                    pq->ns_list[pq->ns_count++] = a;
                    found_glue = 1;
                    break;
                }
            }

            if (!found_glue) {
                struct cache_entry *nce = cache_lookup(ns_name, DNS_TYPE_A);
                if (nce && !nce->is_nxdomain && nce->rr_count > 0) {
                    for (int k = 0; k < nce->rr_count && pq->ns_count < 13; k++) {
                        if (nce->rrs[k].type == DNS_TYPE_A &&
                            nce->rrs[k].rdlength == 4) {
                            struct sockaddr_in a;
                            memset(&a, 0, sizeof(a));
                            a.sin_family = AF_INET;
                            a.sin_port = htons(53);
                            memcpy(&a.sin_addr, nce->rrs[k].rdata, 4);
                            pq->ns_list[pq->ns_count++] = a;
                            break;
                        }
                    }
                }
            }
        }

        if (pq->ns_count > 0) {
            pq->ns_tried = 1;
            send_to_ns(pq, &pq->ns_list[0]);
            return;
        }

        reply_error(client_fd, pq, DNS_RCODE_SERVFAIL);
        return;
    }

    /* Fallthrough — try next NS */
    if (try_next_ns(pq) < 0)
        reply_error(client_fd, pq, DNS_RCODE_SERVFAIL);
}

static void check_timeouts(int client_fd) {
    uint64_t now = now_ms();
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].state != RS_WAITING_REPLY) continue;

        if (now >= pending[i].deadline_ms) {
            reply_error(client_fd, &pending[i], DNS_RCODE_SERVFAIL);
            continue;
        }

        if (now >= pending[i].hop_deadline_ms) {
            if (try_next_ns(&pending[i]) < 0) {
                struct sockaddr_in root;
                memset(&root, 0, sizeof(root));
                root.sin_family = AF_INET;
                root.sin_port = htons(53);
                inet_pton(AF_INET, ROOT_SERVERS[rand_txid() % NUM_ROOTS],
                          &root.sin_addr);
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
    int local_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--local") == 0)
            local_mode = 1;
    }

    srand((unsigned)time(NULL));
    cache_init();
    memset(pending, 0, sizeof(pending));

    int client_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (client_fd < 0) { perror("socket(client)"); exit(1); }

    upstream_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (upstream_fd < 0) { perror("socket(upstream)"); exit(1); }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);

    int yes = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (bind(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); exit(1); }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);

    if (!local_mode) {
        ev.data.fd = upstream_fd;
        epoll_ctl(epfd, EPOLL_CTL_ADD, upstream_fd, &ev);
    }

    fprintf(stderr, "socket_resolver listening on port %d%s\n",
            LISTEN_PORT, local_mode ? " (LOCAL MODE)" : "");

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int timeout = local_mode ? -1 : 100;
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, timeout);

        if (!local_mode)
            check_timeouts(client_fd);

        for (int n = 0; n < nfds; n++) {
            int fd = events[n].data.fd;

            /* === Client query === */
            if (fd == client_fd) {
                uint8_t buffer[BUF_SIZE];
                struct sockaddr_in caddr;
                socklen_t clen = sizeof(caddr);

                int bytes = recvfrom(client_fd, buffer, BUF_SIZE, 0,
                                     (struct sockaddr *)&caddr, &clen);
                if (bytes < 0) continue;

                char qname[256];
                uint16_t qtype, ctxid;
                if (!dns_validate_query(buffer, bytes, qname, sizeof(qname),
                                        &qtype, &ctxid))
                    continue;

                /* Only A and AAAA */
                if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
                    uint8_t rb[BUF_SIZE];
                    int rl = dns_build_error(rb, sizeof(rb), ctxid, qname,
                                             qtype, DNS_RCODE_NOTIMP);
                    if (rl > 0)
                        sendto(client_fd, rb, rl, 0,
                               (struct sockaddr *)&caddr, clen);
                    continue;
                }

                /* Local mode */
                if (local_mode) {
                    struct cached_rr ans[MAX_CACHED_RRS];
                    int an_count = 0;
                    uint8_t rcode = DNS_RCODE_NOERROR;
                    if (dns_local_lookup(qname, qtype, ans, &an_count) < 0) {
                        rcode = DNS_RCODE_NXDOMAIN;
                        an_count = 0;
                    }
                    uint8_t rb[BUF_SIZE];
                    int rl = dns_build_response(rb, sizeof(rb), ctxid, qname,
                                                qtype, rcode, ans, an_count);
                    if (rl > 0)
                        sendto(client_fd, rb, rl, 0,
                               (struct sockaddr *)&caddr, clen);
                    continue;
                }

                /* Recursive mode — check cache */
                struct cache_entry *ce = cache_lookup(qname, qtype);
                if (ce) {
                    uint8_t rb[BUF_SIZE];
                    int rl;
                    if (ce->is_nxdomain)
                        rl = dns_build_error(rb, sizeof(rb), ctxid, qname,
                                             qtype, DNS_RCODE_NXDOMAIN);
                    else
                        rl = dns_build_response(rb, sizeof(rb), ctxid, qname,
                                                qtype, DNS_RCODE_NOERROR,
                                                ce->rrs, ce->rr_count);
                    if (rl > 0)
                        sendto(client_fd, rb, rl, 0,
                               (struct sockaddr *)&caddr, clen);
                    continue;
                }

                struct pending_query *pq = pending_alloc();
                if (!pq) {
                    uint8_t rb[BUF_SIZE];
                    int rl = dns_build_error(rb, sizeof(rb), ctxid, qname,
                                             qtype, DNS_RCODE_SERVFAIL);
                    if (rl > 0)
                        sendto(client_fd, rb, rl, 0,
                               (struct sockaddr *)&caddr, clen);
                    continue;
                }

                pq->client_txid = ctxid;
                pq->client_addr = caddr;
                pq->client_len = clen;
                snprintf(pq->qname, sizeof(pq->qname), "%s", qname);
                pq->qtype = qtype;
                start_resolution(pq);
            }

            /* === Upstream response === */
            else if (fd == upstream_fd) {
                uint8_t buffer[BUF_SIZE];
                struct sockaddr_in saddr;
                socklen_t slen = sizeof(saddr);

                int bytes = recvfrom(upstream_fd, buffer, BUF_SIZE, 0,
                                     (struct sockaddr *)&saddr, &slen);
                if (bytes < 0) continue;
                if (bytes < DNS_HDR_SIZE) continue;
                if (!(buffer[2] & 0x80)) continue;

                uint16_t txid = (buffer[0] << 8) | buffer[1];
                struct pending_query *pq = pending_find_by_txid(txid);
                if (!pq) continue;
                if (saddr.sin_addr.s_addr != pq->current_ns.sin_addr.s_addr)
                    continue;

                struct parsed_response resp;
                if (dns_parse_response(buffer, bytes, &resp) < 0) {
                    if (try_next_ns(pq) < 0)
                        reply_error(client_fd, pq, DNS_RCODE_SERVFAIL);
                    continue;
                }

                handle_ns_response(pq, &resp, client_fd);
            }
        }
    }

    return 0;
}
