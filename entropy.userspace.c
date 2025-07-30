//
// Created by DheekshithDev on 7/28/25.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "entropy.bpf.skel.h"  // Generated skeleton header with Clang


int main(int argc, char **argv) {
    struct entropy_bpf *skel;
    int ifindex, err;

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


    cleanup:
        entropy_bpf__destroy(skel);
        return -err;

}