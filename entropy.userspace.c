//
// Created by DheekshithDev on 7/28/25.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "entropy.bpf.skel.h"  // Generated skeleton header with Clang

#define PKT_COUNT 1000  // Only for 1000 packets

static FILE *logf = NULL;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz < 20) {  // Minimum TCP Header size
        fprintf(stderr, "Received incomplete TCP Header\n");
        return 0;
    }

    if (data_sz < sizeof(struct tcphdr)) {
        fprintf(stderr, "Data size (%zu) less than TCP header size.\n", data_sz);
        return 0;
    }

    struct tcphdr *tcp = (struct tcphdr *)data;

    uint16_t source_port = ntohs(tcp->source);
    uint16_t dest_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_seq = ntohl(tcp->ack_seq);
    uint16_t window = ntohs(tcp->window);

    // No need to extract flags

    // Write to a file
    if (logf) {
        fprintf(logf, "%u, %u, %u, %u, %u\n", source_port, dest_port, seq, ack_seq, window);

        // fflush(logf);  // No need to flush as I don't need the data immediately each run
    }

    return 0;
}

int main(int argc, char **argv) {
    struct entropy_bpf *skel;
    struct ring_buffer *rb = NULL;
    int ifindex, err;
    int i;
    // const int pkt_count = 1000;  // Do this only for 1000 packets

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    // Open file for logging details
    logf = fopen("entropy_events.csv", "w");
    if (!logf) {
        perror("fopen entropy_events.csv");
        return 1;
    }

    // Header row for csv file
    fprintf(logf, "src_port, dst_port, seq, ack_seq, window\n");

    // Open BPF application
    skel = entropy_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skel\n");
        return 1;
    }

    // Load and Verify BPF programs
    err = entropy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify skel %d\n", err);
    }

    // Attach XDP program
    err = entropy_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach to skel %d\n", err);
        goto cleanup;
    }

    // Attach the XDP program to specific interface
    skel->links.xdp_padding = bpf_program__attach_xdp(skel->progs.xdp_padding, ifindex);
    if (!skel->links.xdp_padding) {
        err = -errno;
        fprintf(stderr, "Failed to attach xdp_padding to the interface: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

    // Setup the ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create rb\n");
        err = -1;
        goto cleanup;
    }

    printf("Start polling the ring buffer\n");

    // Ring buffer poll
    i = 0;
    while(i <= PKT_COUNT) {
        err = ring_buffer__poll(rb, -1);

        if (err == -EINTR) continue;

        if (err <  0) {
            fprintf(stderr, "Failed to poll ring buffer: %d\n", err);
            break;
        }
        i++;
    }

cleanup:
    if (logf) fclose(logf);
    entropy_bpf__destroy(skel);
    printf("Successfully destroyed skel\n");
    return -err;
}