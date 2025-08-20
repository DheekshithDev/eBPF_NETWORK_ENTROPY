//
// Created by DheekshithDev on 7/28/25.
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <pcap/dlt.h>

#include "entropy.bpf.skel.h"  // Generated skeleton header with Clang

#define PKT_COUNT 1000  // Only for 1000 packets

static pcap_dumper_t *dumper;
static pcap_t *pcap_handle;

// Userspace side data structures
struct pcap_record {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
    uint8_t data[];
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz < sizeof(struct pcap_record)) {
        // No data
        fprintf(stderr, "No data to read error\n");
        return 0;
    }

    const struct pcap_record *rec = data;

    struct pcap_pkthdr phdr = {
        .ts = {
            .tv_sec = rec->ts_sec,
            .tv_usec = rec->ts_usec,
        },
        .caplen = rec->incl_len,
        .len = rec->orig_len,
    };

    pcap_dump((u_char *) dumper, &phdr, rec->data);

    return 0;
}

int main(int argc, char **argv) {
    struct entropy_bpf *skel;
    struct ring_buffer *rb = NULL;
    int ifindex, err = 0;
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

    pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    dumper = pcap_dump_open(pcap_handle, "capture.pcap");
    if (!dumper) {
        fprintf(stderr, "Unable to open PCAP dump: %s\n", pcap_geterr(pcap_handle));
        return 1;
    }

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
    int i = 0;
    while (i <= PKT_COUNT) {
        err = ring_buffer__poll(rb, -1); // No timeout

        if (err == -EINTR) continue;

        if (err < 0) {
            fprintf(stderr, "Failed to poll ring buffer: %d\n", err);
            break;
        }
        i++;
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    if (skel) entropy_bpf__destroy(skel);
    if (dumper) {
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
    }
    if (pcap_handle) pcap_close(pcap_handle);
    printf("Successfully destroyed rb, skel, dumper, pcap_handle\n");
    return -err;
}
