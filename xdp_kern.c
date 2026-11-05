/*
 * xdp_kern.c — XDP BPF program for AF_XDP DNS resolver
 *
 * Parses Ethernet → IPv4 → UDP.  If destination port matches
 * RESOLVER_PORT (53), redirects the packet to the AF_XDP socket
 * via the XSKMAP.  Everything else is passed to the normal stack.
 *
 * Build:
 *   clang -O2 -g -target bpf -c xdp_kern.c -o xdp_kern.o
 *
 * Load (with xdp-loader or bpftool):
 *   sudo xdp-loader load -m native <iface> xdp_kern.o
 *   — or, the userspace program loads it via libbpf —
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>      /* IPPROTO_UDP */
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define RESOLVER_PORT 53

/* XSKMAP — userspace populates entry [0] with the AF_XDP socket fd */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_dns_redirect(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Ethernet header --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* --- IPv4 header --- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Variable-length IP header */
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return XDP_PASS;

    /* --- UDP header --- */
    struct udphdr *udp = (void *)((char *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Only packets destined for our resolver port */
    if (udp->dest != bpf_htons(RESOLVER_PORT))
        return XDP_PASS;

    /* Redirect to the AF_XDP socket on this RX queue */
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
