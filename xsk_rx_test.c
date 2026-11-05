/*
 * xsk_rx_test.c — Minimal AF_XDP receive test
 *
 * Sets up a UMEM and an AF_XDP socket, loads xdp_kern.o, and prints
 * the Ethernet/IP/UDP headers of every received packet.  No TX.
 * Use this to confirm that the XDP redirect is working before
 * building the full AF_XDP resolver.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o xsk_rx_test xsk_rx_test.c -lxdp -lbpf
 *
 * Usage:
 *   sudo ./xsk_rx_test <interface>
 *
 * Prerequisites:
 *   - Linux kernel with CONFIG_XDP_SOCKETS=y
 *   - apt install libxdp-dev libbpf-dev clang llvm
 *   - xdp_kern.o built via: clang -O2 -g -target bpf -c xdp_kern.c -o xdp_kern.o
 *   - Interface pinned to 1 queue: ethtool -L <iface> combined 1
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <xdp/xsk.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ================================================================
 * CONFIGURATION
 * ================================================================ */
#define NUM_FRAMES       4096
#define FRAME_SIZE       XSK_UMEM__DEFAULT_FRAME_SIZE   /* 4096 */
#define BATCH_SIZE       64

static volatile int running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", ifname);
        return 1;
    }

    /* Raise memlock limit */
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
        perror("setrlimit(MEMLOCK)");
        return 1;
    }

    signal(SIGINT, sigint_handler);

    /* ============================================================
     * 1. Allocate UMEM
     * ============================================================ */
    void *umem_area = NULL;
    size_t umem_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&umem_area, getpagesize(), umem_size)) {
        perror("posix_memalign");
        return 1;
    }
    memset(umem_area, 0, umem_size);

    struct xsk_umem *umem = NULL;
    struct xsk_ring_prod fill_ring = {0};   /* libxdp does not init cached_prod */
    struct xsk_ring_cons comp_ring = {0};

    struct xsk_umem_config umem_cfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = 0,
        .flags          = 0,    /* aligned mode */
    };

    int ret = xsk_umem__create(&umem, umem_area, umem_size,
                               &fill_ring, &comp_ring, &umem_cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create: %s\n", strerror(-ret));
        free(umem_area);
        return 1;
    }

    /* ============================================================
     * 2. Create XSK socket
     * ============================================================ */
    struct xsk_socket *xsk = NULL;
    struct xsk_ring_cons rx_ring = {0};
    struct xsk_ring_prod tx_ring = {0};

    struct xsk_socket_config xsk_cfg = {
        .rx_size        = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size        = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags   = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags      = 0,
        .bind_flags     = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };

    ret = xsk_socket__create(&xsk, ifname, 0 /* queue */,
                             umem, &rx_ring, &tx_ring, &xsk_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create: %s\n", strerror(-ret));
        xsk_umem__delete(umem);
        free(umem_area);
        return 1;
    }

    /* ============================================================
     * 3. Load XDP program and populate XSKMAP
     * ============================================================ */
    struct bpf_object *bpf_obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "bpf_object__open_file: %s\n",
                strerror((int)libbpf_get_error(bpf_obj)));
        goto cleanup;
    }

    ret = bpf_object__load(bpf_obj);
    if (ret) {
        fprintf(stderr, "bpf_object__load: %s\n", strerror(-ret));
        goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(bpf_obj,
                                                                "xdp_dns_redirect");
    if (!prog) {
        fprintf(stderr, "Cannot find xdp_dns_redirect program\n");
        goto cleanup;
    }

    int prog_fd = bpf_program__fd(prog);
    ret = bpf_xdp_attach(ifindex, prog_fd, 0 /* flags */, NULL);
    if (ret) {
        fprintf(stderr, "bpf_xdp_attach: %s\n", strerror(-ret));
        goto cleanup;
    }

    /* Populate XSKMAP entry 0 with our socket */
    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    if (!map) {
        fprintf(stderr, "Cannot find xsks_map\n");
        goto detach;
    }

    int map_fd = bpf_map__fd(map);
    int xsk_fd = xsk_socket__fd(xsk);
    __u32 key = 0;
    ret = bpf_map_update_elem(map_fd, &key, &xsk_fd, 0);
    if (ret) {
        fprintf(stderr, "bpf_map_update_elem(xsks_map): %s\n", strerror(-ret));
        goto detach;
    }

    /* ============================================================
     * 4. Pre-fill the FILL ring
     * ============================================================ */
    __u32 idx = 0;
    /* FILL ring holds fill_size (2048) entries, not NUM_FRAMES (4096) */
    ret = xsk_ring_prod__reserve(&fill_ring, umem_cfg.fill_size, &idx);
    if (ret != (int)umem_cfg.fill_size) {
        fprintf(stderr, "Could not reserve FILL ring entries\n");
        goto detach;
    }
    for (__u32 i = 0; i < umem_cfg.fill_size; i++)
        *xsk_ring_prod__fill_addr(&fill_ring, idx + i) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&fill_ring, umem_cfg.fill_size);

    /* Kick the FILL ring if needed */
    if (xsk_ring_prod__needs_wakeup(&fill_ring))
        recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);

    fprintf(stderr, "xsk_rx_test: listening on %s (Ctrl-C to stop)\n", ifname);

    /* ============================================================
     * 5. Receive loop
     * ============================================================ */
    unsigned long pkt_count = 0;

    while (running) {
        struct pollfd pfd = {
            .fd     = xsk_fd,
            .events = POLLIN,
        };

        int poll_ret = poll(&pfd, 1, 1000);
        if (poll_ret <= 0) continue;

        __u32 rx_idx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&rx_ring, BATCH_SIZE, &rx_idx);
        if (rcvd == 0) {
            /* Kick the FILL ring if the kernel needs a wakeup */
            if (xsk_ring_prod__needs_wakeup(&fill_ring))
                recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
            continue;
        }

        for (__u32 i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rx_ring,
                                                                  rx_idx + i);
            uint8_t *pkt = (uint8_t *)umem_area + desc->addr;
            uint32_t len = desc->len;

            pkt_count++;

            /* --- Print headers --- */
            if (len < sizeof(struct ethhdr)) {
                printf("[%lu] short frame (%u bytes)\n", pkt_count, len);
                continue;
            }

            struct ethhdr *eth = (struct ethhdr *)pkt;
            printf("[%lu] ETH %02x:%02x:%02x:%02x:%02x:%02x -> "
                   "%02x:%02x:%02x:%02x:%02x:%02x proto=0x%04x len=%u\n",
                   pkt_count,
                   eth->h_source[0], eth->h_source[1], eth->h_source[2],
                   eth->h_source[3], eth->h_source[4], eth->h_source[5],
                   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
                   ntohs(eth->h_proto), len);

            if (ntohs(eth->h_proto) != ETH_P_IP) continue;
            if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) continue;

            struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
            char src_ip[16], dst_ip[16];
            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));
            printf("     IP  %s -> %s proto=%u tot_len=%u\n",
                   src_ip, dst_ip, ip->protocol, ntohs(ip->tot_len));

            if (ip->protocol != IPPROTO_UDP) continue;
            int ip_hdr_len = ip->ihl * 4;
            if (len < sizeof(struct ethhdr) + (unsigned)ip_hdr_len +
                      sizeof(struct udphdr))
                continue;

            struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct ethhdr)
                                                   + ip_hdr_len);
            printf("     UDP %u -> %u len=%u\n",
                   ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
        }

        /* Release the RX ring slots */
        xsk_ring_cons__release(&rx_ring, rcvd);

        /* Recycle frames back to the FILL ring */
        __u32 fill_idx = 0;
        ret = xsk_ring_prod__reserve(&fill_ring, rcvd, &fill_idx);
        /* If we can't reserve, frames leak — fine for a test tool */
        if (ret > 0) {
            for (__u32 i = 0; i < rcvd; i++) {
                const struct xdp_desc *desc = xsk_ring_cons__rx_desc(
                    &rx_ring, rx_idx + i);
                *xsk_ring_prod__fill_addr(&fill_ring, fill_idx + i) = desc->addr;
            }
            xsk_ring_prod__submit(&fill_ring, rcvd);

            if (xsk_ring_prod__needs_wakeup(&fill_ring))
                recvfrom(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }
    }

    fprintf(stderr, "\nReceived %lu packets total\n", pkt_count);

detach:
    bpf_xdp_detach(ifindex, 0, NULL);
cleanup:
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    free(umem_area);
    if (bpf_obj) bpf_object__close(bpf_obj);

    return 0;
}
