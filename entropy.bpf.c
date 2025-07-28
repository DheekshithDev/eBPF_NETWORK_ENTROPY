//
// Created by user on 7/24/25.
//
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>

#include "entropy.bpf.h"

#include <stdbool.h>


#define ETH_P_IP		0x0800
// #define IPPROTO_TCP		6
#define PAD_BYTES 100  // No need to define any hexadecimal or other data because I'm padding zeroes


// Function for checking pointer arithmetic for verifier
static bool verifier_checker(void *data, void *data_end, __u32 pkt_size) {

    if ((data + pkt_size) > data_end) {
        return false;
    }

    struct ethhdr *eth = data;

    // Ensure Ethernet Header is within bounds for Verifier
    if ((void *)(eth + 1) > data_end) {
        return false;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Ensure IP Header is within bounds for Verifier
    if ((void *)(ip + 1) > data_end) {
        return false;
    }

    // Calculate IP Header length
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return false;
    }

    // Ensure IP Header is within bounds
    if ((void *)ip + ip_hdr_len > data_end) {
        return false;
    }

    // Grab TCP Header
    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_hdr_len); // not casting ip to (unsigned char *) as (void *) does the same on GNU-GCC and Clang but not ISO strict C.

    // Ensure TCP Header is within bounds
    if ((void *)(tcp + 1) > data_end) {
        return false;
    }

    // Ensure TCP Header is not exceeding bounds
    int tcp_hdr_len = tcp->doff * 4;

    if ((void *)tcp + tcp_hdr_len > data_end) {
        return false;
    }

    return true;
}

// Helper function to check if the packet is TCP and IPv4  ## METHOD 1 - Easy
static bool is_tcp_ipv4(struct ethhdr *eth) {

    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return false;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Check if the protocol is TCP
    if ((ip->protocol) != IPPROTO_TCP) {
        return false;
    }

    return true;
}

SEC("xdp")
int xdp_padding(struct xdp_md *ctx) {

    void *data, *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;

    __u32 init_pkt_size, mdf_pkt_size;
    __u32 l3_len_or_mtu;
    __u32 pad_bytes;

    // Pointers to packet data
    data = (void *)(unsigned long)ctx->data;
    data_end = (void *)(unsigned long)ctx->data_end;
    // Get current packet length
    init_pkt_size = data_end - data;

    if (!verifier_checker(data, data_end, init_pkt_size)) {
        return XDP_ABORTED;
    }

    // Grab ETH Header
     eth = data;

    // Check if the packet is a TCP packet
    if (!is_tcp_ipv4(eth)) {
        // Here, I am just letting the packet go if it's not TCP; Other way I should only force-make TCP connections.
        return XDP_PASS;
    }

    // Grab IP Header
     ip = (struct iphdr *)(eth + 1);

    // Calculate IP Header length
    int ip_hdr_len = ip->ihl * 4;

    // Grab TCP Header
    tcp = (struct tcphdr *)((void *)ip + ip_hdr_len); // not casting ip to (unsigned char *) as (void *) does the same on GNU-GCC and Clang but not ISO strict C.

    // CODE FOR ACCURATE PADDING OR SHRINKING BY GRABBING ROUTE MTU
    // struct bpf_fib_lookup fib = {};
    //
    // long r = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0); // Not using BPF_FIB_LOOKUP_DIRECT as a flag
    //
    // if (r) {  // if r is not 0 and failed
    //
    // }
    //
    // __u32 mtu = fib.mtu;

    l3_len_or_mtu = 0;
    int r = bpf_check_mtu(ctx, 0, &l3_len_or_mtu, +PAD_BYTES, 0);

    if (r < 0) {
        bpf_printk("There is an Error with check MTU!");
        return XDP_DROP;
    }

    if (init_pkt_size < l3_len_or_mtu) {  // I can pad since there is space
         pad_bytes = (l3_len_or_mtu - init_pkt_size);

        // Might need to check bpf_check_mtu() again here.

        // This function itself will memset with 0 for the adjusted tail pointer; if not I'll have to use __builtin_memset() with zeroes.
        // This function also checks xdp_hard_end-tail room so I don't have to check it myself.
        if (bpf_xdp_adjust_tail(ctx, pad_bytes) < 0) {
            return XDP_ABORTED;
        }

        // DO VERIFIER POINTER ARITHMETIC CHECKS AGAIN
        data = (void *)(unsigned long)ctx->data;
        data_end = (void *)(unsigned long)ctx->data_end;
        // Get modified packet length
        mdf_pkt_size = data_end - data;

        if (!verifier_checker(data, data_end, mdf_pkt_size)) {
            return XDP_ABORTED;
        }

        bpf_printk("Packet padded successfully with zeroes!");

    } else if (init_pkt_size >= l3_len_or_mtu) {  // I can't pad since packet size is already > or = interface MTU.
        // I SHOULD SHRINK LIKE THE OTHER METHOD HERE
        bpf_printk("Packer size too large to pad!");
        return XDP_PASS;
    }

    return XDP_PASS;

}


// Force only TCP and IPv4 connections on main interface  ## METHOD 2 - Hard


char __license[] SEC("license") = "GPL";