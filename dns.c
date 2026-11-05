/*
 * dns.c — Shared DNS parsing, local zone, and response builder
 *
 * Extracted from recursive_resolver.c so both socket_resolver and
 * afxdp_resolver link against the identical DNS logic.
 */
#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * DNS NAME HANDLING
 * ================================================================ */

int dns_parse_name(const uint8_t *pkt, const uint8_t *pkt_end,
                   const uint8_t **ptr, char *out, int out_size) {
    const uint8_t *p = *ptr;
    int total = 0;
    int jumped = 0;
    const uint8_t *after_first_jump = NULL;
    int pointer_count = 0;

    while (p < pkt_end) {
        uint8_t len = *p;

        if (len == 0) {
            p++;
            if (!jumped) after_first_jump = p;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (p + 1 >= pkt_end) return -1;
            uint16_t offset = ((len & 0x3F) << 8) | p[1];
            if (offset >= (unsigned)(pkt_end - pkt)) return -1;
            if (!jumped) after_first_jump = p + 2;
            jumped = 1;
            p = pkt + offset;
            if (++pointer_count > 128) return -1;
            continue;
        }

        if ((len & 0xC0) != 0) return -1;

        p++;
        if (p + len > pkt_end) return -1;
        if (total + len + 1 >= out_size) return -1;

        if (total > 0) out[total++] = '.';
        for (int i = 0; i < len; i++)
            out[total++] = (char)tolower(p[i]);
        p += len;
    }

    out[total] = '\0';
    *ptr = after_first_jump ? after_first_jump : p;
    return 0;
}

int dns_encode_name(const char *name, uint8_t *buf, int buf_size) {
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
    buf[pos++] = 0;
    return pos;
}

int dns_name_eq(const char *a, const char *b) {
    return strcasecmp(a, b) == 0;
}

/* ================================================================
 * DNS RESPONSE PARSING
 * ================================================================ */

int dns_parse_rr_section(const uint8_t *pkt, const uint8_t *pkt_end,
                         const uint8_t **ptr, struct parsed_rr *rrs,
                         int count, int max_rrs) {
    for (int i = 0; i < count; i++) {
        struct parsed_rr *rr = (i < max_rrs) ? &rrs[i] : NULL;
        char name[256];

        if (dns_parse_name(pkt, pkt_end, ptr, name, sizeof(name)) < 0)
            return -1;
        if (*ptr + 10 > pkt_end) return -1;

        uint16_t type  = ((*ptr)[0] << 8) | (*ptr)[1];
        uint16_t cls   = ((*ptr)[2] << 8) | (*ptr)[3];
        uint32_t ttl   = ((*ptr)[4] << 24) | ((*ptr)[5] << 16) |
                         ((*ptr)[6] << 8)  | (*ptr)[7];
        uint16_t rdlen = ((*ptr)[8] << 8) | (*ptr)[9];
        *ptr += 10;

        if (*ptr + rdlen > pkt_end) return -1;

        if (rr) {
            snprintf(rr->name, sizeof(rr->name), "%s", name);
            rr->type = type;
            rr->cls  = cls;
            rr->ttl  = ttl;
            rr->rdlength = rdlen;
            rr->rdata = *ptr;
            rr->rdata_name[0] = '\0';
            rr->rdata_ip = 0;

            if (type == DNS_TYPE_A && rdlen == 4) {
                memcpy(&rr->rdata_ip, *ptr, 4);
            } else if ((type == DNS_TYPE_NS || type == DNS_TYPE_CNAME) && rdlen > 0) {
                const uint8_t *nptr = *ptr;
                dns_parse_name(pkt, pkt_end, &nptr, rr->rdata_name,
                               sizeof(rr->rdata_name));
            }
        }
        *ptr += rdlen;
    }
    return 0;
}

int dns_parse_response(const uint8_t *pkt, int pkt_len,
                       struct parsed_response *resp) {
    memset(resp, 0, sizeof(*resp));
    if (pkt_len < DNS_HDR_SIZE) return -1;

    const uint8_t *pkt_end = pkt + pkt_len;

    resp->id     = (pkt[0] << 8) | pkt[1];
    resp->qr     = (pkt[2] >> 7) & 1;
    resp->opcode = (pkt[2] >> 3) & 0xF;
    resp->aa     = (pkt[2] >> 2) & 1;
    resp->tc     = (pkt[2] >> 1) & 1;
    resp->rd     =  pkt[2] & 1;
    resp->ra     = (pkt[3] >> 7) & 1;
    resp->rcode  =  pkt[3] & 0xF;

    int qdcount = (pkt[4] << 8) | pkt[5];
    int ancount = (pkt[6] << 8) | pkt[7];
    int nscount = (pkt[8] << 8) | pkt[9];
    int arcount = (pkt[10] << 8) | pkt[11];

    const uint8_t *ptr = pkt + DNS_HDR_SIZE;

    for (int i = 0; i < qdcount; i++) {
        if (i == 0) {
            if (dns_parse_name(pkt, pkt_end, &ptr, resp->qname,
                               sizeof(resp->qname)) < 0)
                return -1;
            if (ptr + 4 > pkt_end) return -1;
            resp->qtype  = (ptr[0] << 8) | ptr[1];
            resp->qclass = (ptr[2] << 8) | ptr[3];
            ptr += 4;
        } else {
            char skip[256];
            if (dns_parse_name(pkt, pkt_end, &ptr, skip, sizeof(skip)) < 0)
                return -1;
            if (ptr + 4 > pkt_end) return -1;
            ptr += 4;
        }
    }

    resp->an_count = ancount < 32 ? ancount : 32;
    if (dns_parse_rr_section(pkt, pkt_end, &ptr, resp->answers, ancount, 32) < 0)
        return -1;

    resp->ns_count = nscount < 32 ? nscount : 32;
    if (dns_parse_rr_section(pkt, pkt_end, &ptr, resp->authority, nscount, 32) < 0)
        return -1;

    resp->ar_count = arcount < 32 ? arcount : 32;
    if (dns_parse_rr_section(pkt, pkt_end, &ptr, resp->additional, arcount, 32) < 0)
        return -1;

    return 0;
}

/* ================================================================
 * DNS RESPONSE / QUERY BUILDER
 * ================================================================ */

int dns_build_response(uint8_t *buf, int buf_size,
                       uint16_t txid, const char *qname, uint16_t qtype,
                       uint8_t rcode,
                       const struct cached_rr *answers, int an_count) {
    if (buf_size < DNS_HDR_SIZE) return -1;

    buf[0] = txid >> 8;
    buf[1] = txid & 0xFF;
    buf[2] = 0x81;            /* QR=1, RD=1 */
    buf[3] = 0x80 | rcode;    /* RA=1        */
    buf[4] = 0; buf[5] = 1;   /* QDCOUNT=1   */
    buf[6] = (an_count >> 8); buf[7] = an_count & 0xFF;
    buf[8] = 0; buf[9] = 0;
    buf[10] = 0; buf[11] = 0;

    int pos = DNS_HDR_SIZE;

    int nlen = dns_encode_name(qname, &buf[pos], buf_size - pos);
    if (nlen < 0) return -1;
    pos += nlen;

    if (pos + 4 > buf_size) return -1;
    buf[pos++] = qtype >> 8;
    buf[pos++] = qtype & 0xFF;
    buf[pos++] = 0; buf[pos++] = 1;

    for (int i = 0; i < an_count; i++) {
        nlen = dns_encode_name(qname, &buf[pos], buf_size - pos);
        if (nlen < 0) return -1;
        pos += nlen;

        if (pos + 10 + answers[i].rdlength > buf_size) return -1;
        buf[pos++] = answers[i].type >> 8;
        buf[pos++] = answers[i].type & 0xFF;
        buf[pos++] = 0; buf[pos++] = 1;
        buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 60;
        buf[pos++] = answers[i].rdlength >> 8;
        buf[pos++] = answers[i].rdlength & 0xFF;
        memcpy(&buf[pos], answers[i].rdata, answers[i].rdlength);
        pos += answers[i].rdlength;
    }

    return pos;
}

int dns_build_error(uint8_t *buf, int buf_size,
                    uint16_t txid, const char *qname,
                    uint16_t qtype, uint8_t rcode) {
    return dns_build_response(buf, buf_size, txid, qname, qtype, rcode, NULL, 0);
}

int dns_build_query(uint8_t *buf, int buf_size,
                    uint16_t txid, const char *qname, uint16_t qtype) {
    if (buf_size < DNS_HDR_SIZE) return -1;

    buf[0] = txid >> 8;
    buf[1] = txid & 0xFF;
    buf[2] = 0x01;            /* RD=1 */
    buf[3] = 0x00;
    buf[4] = 0; buf[5] = 1;
    buf[6] = 0; buf[7] = 0;
    buf[8] = 0; buf[9] = 0;
    buf[10] = 0; buf[11] = 0;

    int pos = DNS_HDR_SIZE;
    int nlen = dns_encode_name(qname, &buf[pos], buf_size - pos);
    if (nlen < 0) return -1;
    pos += nlen;

    if (pos + 4 > buf_size) return -1;
    buf[pos++] = qtype >> 8;
    buf[pos++] = qtype & 0xFF;
    buf[pos++] = 0; buf[pos++] = 1;

    return pos;
}

/* ================================================================
 * LOCAL ZONE (benchmark mode)
 * ================================================================ */

static const struct local_record local_zone[] = {
    { "example.com",        DNS_TYPE_A, {93,184,216,34},   4 },
    { "www.example.com",    DNS_TYPE_A, {93,184,216,34},   4 },
    { "test.example.com",   DNS_TYPE_A, {93,184,216,34},   4 },
    { "google.com",         DNS_TYPE_A, {142,250,80,46},   4 },
    { "www.google.com",     DNS_TYPE_A, {142,250,80,46},   4 },
    { "cloudflare.com",     DNS_TYPE_A, {104,16,132,229},  4 },
    { "github.com",         DNS_TYPE_A, {140,82,121,3},    4 },
    { "dns.google",         DNS_TYPE_A, {8,8,8,8},         4 },
    { NULL, 0, {0}, 0 },
};

int dns_local_lookup(const char *qname, uint16_t qtype,
                     struct cached_rr *out, int *out_count) {
    *out_count = 0;
    for (int i = 0; local_zone[i].name; i++) {
        if (dns_name_eq(local_zone[i].name, qname) &&
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
    return *out_count > 0 ? 0 : -1;
}

/* ================================================================
 * QUERY VALIDATION
 * ================================================================ */

int dns_validate_query(const uint8_t *pkt, int pkt_len,
                       char *qname, int qname_size,
                       uint16_t *qtype, uint16_t *client_txid) {
    if (pkt_len < DNS_HDR_SIZE) return 0;

    uint8_t qr     = (pkt[2] >> 7) & 1;
    uint8_t opcode = (pkt[2] >> 3) & 0xF;
    if (qr != 0 || opcode != 0) return 0;

    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    if (qdcount < 1) return 0;

    const uint8_t *ptr = pkt + DNS_HDR_SIZE;
    const uint8_t *end = pkt + pkt_len;

    if (dns_parse_name(pkt, end, &ptr, qname, qname_size) < 0) return 0;
    if (ptr + 4 > end) return 0;

    *qtype = (ptr[0] << 8) | ptr[1];
    *client_txid = (pkt[0] << 8) | pkt[1];
    return 1;
}
