//
// Created by ArthurK-5080 on 8/11/2025.
//
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800  /* IPv4 packet */

#define TC_ACT_OK 0  /* Terminate the packet processing pipeline and allows the packet to proceed */
#define TC_ACT_SHOT 2  /* Terminate the packet processing pipeline and drops the packet */

#define DEFAULT_MTU 1500

#define PAD_BYTES 100  // No need to define any hexadecimal or other data because I'm padding zeroes


// Function for checking pointer arithmetic for verifier
static __always_inline bool verifier_checker(void *data, void *data_end, __u32 need) {
    return data + need <= data_end;
}

// Helper function to check if the packet is TCP and IPv4  ## METHOD 1 - Easy
static __always_inline bool is_tcp_ipv4(void *data, void *data_end) {

    const __u32 need = sizeof(struct ethhdr) + offsetof(struct iphdr, protocol) + 1;
    if (data + need > data_end) {
        return false;
    }

    struct ethhdr *eth = data;
    // Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return false;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    // Check if the protocol is TCP
    if ((ip->protocol) != IPPROTO_TCP) {
        return false;
    }

    bpf_printk("The packet is TCP-IPv4!\n");
    return true;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx) {

    /* Ignore GSO/TSO Packets */
    if (ctx->gso_segs > 1 || ctx->gso_size) {
        bpf_printk("Packet is TSO/GSO; Ignoring.\n");
        return TC_ACT_OK;
    }

    if (bpf_skb_pull_data(ctx, 0)) {  // Returns 0 on success
        bpf_printk("Failed to pull data at bpf_skb_pull_data.\n");
        return TC_ACT_OK;
    }

    void *data = (void *) (__u64) ctx->data;  // (unsigned long) == (__u64)
    void *data_end = (void *) (__u64) ctx->data_end;

    // Get current packet length
    __u32 init_pkt_len = data_end - data;
    bpf_printk("Initial packet length is: %u\n", init_pkt_len);

    // Grab ETH Header
    struct ethhdr *eth = data;
    if (!verifier_checker(eth + 1, data_end, 0)) {
        return TC_ACT_SHOT;
    }

    // Grab IP Header
    struct iphdr *ip = (struct iphdr *) (eth + 1);
    if (!verifier_checker(ip + 1, data_end, 0)) {
        return TC_ACT_SHOT;
    }

    // Check if the packet is a TCP packet
    if (!is_tcp_ipv4(data, data_end)) {
        // Here, I am just letting the packet go if it's not TCP; Other way I should only force-make TCP connections.
        return TC_ACT_OK;
    }

    /* Grab Path MTU */
    struct bpf_fib_lookup fib = {};
    __u16 ip_ntohs = bpf_ntohs(ip->tot_len);

    __u32 pad_bytes = 0;

    if (ip_ntohs < DEFAULT_MTU) {
        pad_bytes = (DEFAULT_MTU - ip_ntohs);  // Just checking
        fib.tot_len = ip_ntohs + pad_bytes;
    } else {
        fib.tot_len = ip_ntohs;
    }

    long ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_OUTPUT);

    __u32 p_mtu = 0;

    if (ret == BPF_FIB_LKUP_RET_FRAG_NEEDED) {  // Fragmentation needed
        bpf_printk("bpf_fib_lookup needs fragmentation!\n");
        p_mtu = fib.mtu_result;
    } else if (ret == 0) {  // Success
        bpf_printk("bpf_fib_lookup was a success!\n");
        p_mtu = fib.mtu_result;  // Could be 0
    }

    bpf_printk("The PMTU is: %u\n", p_mtu);

    /* bpf_skb_change_tail */
    if (p_mtu && p_mtu > 0) {
        pad_bytes = (p_mtu - ip_ntohs);
    } else {
        pad_bytes = (DEFAULT_MTU - ip_ntohs);
    }

    if (ip_ntohs < p_mtu || ip_ntohs < DEFAULT_MTU) {
        bpf_printk("Packet length is < PMTU. Pad.\n");
        if (bpf_skb_change_tail(ctx, init_pkt_len + pad_bytes, 0)) {
            /* Failed */
            bpf_printk("Error with changing tail to the packet!\n");
            return TC_ACT_SHOT;
        }

        /* Perform Verifier Checks Again */
        data = (void *) (__u64) ctx->data;  // (unsigned long) == (__u64)
        data_end = (void *) (__u64) ctx->data_end;

        // Get current packet length
        __u32 mdf_pkt_len = data_end - data;

        // Grab ETH Header
        eth = data;
        if (!verifier_checker(eth + 1, data_end, 0)) {
            return TC_ACT_SHOT;
        }

        // Grab IP Header
        ip = (struct iphdr *) (eth + 1);
        if (!verifier_checker(ip + 1, data_end, 0)) {
            return TC_ACT_SHOT;
        }

        bpf_printk("Modified packet length is: %u\n", mdf_pkt_len);
    } else {
        bpf_printk("Packet length is >= PMTU. Don't Pad.\n");
    }

    return TC_ACT_OK;
}

// SEC("tc")
// int tc_ingress(struct __sk_buff *ctx) {
//
//     return TC_ACT_OK;
// }


char __license[] SEC("license") = "GPL";