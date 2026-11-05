/*
 * dns.h — Shared DNS parsing, local zone, and response builder
 *
 * Used by both socket_resolver.c (baseline) and afxdp_resolver.c
 * so the only difference between the two binaries is how packets
 * enter and leave.
 */
#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

/* ================================================================
 * CONSTANTS
 * ================================================================ */
#define DNS_HDR_SIZE      12
#define DNS_TYPE_A        1
#define DNS_TYPE_NS       2
#define DNS_TYPE_CNAME    5
#define DNS_TYPE_SOA      6
#define DNS_TYPE_AAAA     28
#define DNS_CLASS_IN      1

#define DNS_RCODE_NOERROR  0
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP   4

#define MAX_CACHED_RRS    16
#define MAX_RR_RDATA      512
#define DNS_BUF_SIZE      1500

/* ================================================================
 * DATA STRUCTURES
 * ================================================================ */

/* A single cached / answer resource record */
struct cached_rr {
    uint16_t type;
    uint16_t rdlength;
    uint8_t  rdata[MAX_RR_RDATA];
};

/* Parsed RR from a wire-format response */
struct parsed_rr {
    char     name[256];
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t rdlength;
    const uint8_t *rdata;        /* points into the packet buffer */
    char     rdata_name[256];    /* decoded target for NS / CNAME */
    uint32_t rdata_ip;           /* A record IPv4 in network order */
};

/* Fully parsed DNS response */
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

/* Local-zone entry (for --local benchmark mode) */
struct local_record {
    const char *name;
    uint16_t type;
    uint8_t  rdata[16];
    uint16_t rdlength;
};

/* ================================================================
 * FUNCTION DECLARATIONS
 * ================================================================ */

/* Name handling */
int  dns_parse_name(const uint8_t *pkt, const uint8_t *pkt_end,
                    const uint8_t **ptr, char *out, int out_size);
int  dns_encode_name(const char *name, uint8_t *buf, int buf_size);
int  dns_name_eq(const char *a, const char *b);

/* Response parsing */
int  dns_parse_rr_section(const uint8_t *pkt, const uint8_t *pkt_end,
                          const uint8_t **ptr, struct parsed_rr *rrs,
                          int count, int max_rrs);
int  dns_parse_response(const uint8_t *pkt, int pkt_len,
                        struct parsed_response *resp);

/* Packet building */
int  dns_build_response(uint8_t *buf, int buf_size,
                        uint16_t txid, const char *qname, uint16_t qtype,
                        uint8_t rcode,
                        const struct cached_rr *answers, int an_count);
int  dns_build_error(uint8_t *buf, int buf_size,
                     uint16_t txid, const char *qname,
                     uint16_t qtype, uint8_t rcode);
int  dns_build_query(uint8_t *buf, int buf_size,
                     uint16_t txid, const char *qname, uint16_t qtype);

/* Local zone */
int  dns_local_lookup(const char *qname, uint16_t qtype,
                      struct cached_rr *out, int *out_count);

/* Query validation — returns 1 if the packet is a valid standard query,
 * and fills qname/qtype/client_txid.  Returns 0 on invalid. */
int  dns_validate_query(const uint8_t *pkt, int pkt_len,
                        char *qname, int qname_size,
                        uint16_t *qtype, uint16_t *client_txid);

#endif /* DNS_H */
