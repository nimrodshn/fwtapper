#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <string.h>
#include "bpf_helpers.h"

#define BPF_ADJ_ROOM_MAC 1

// Represents the information required for redirect destination.
struct destination {
    __u32 defaultIfaceIdx;
    __u32 egressIfaceIdx;
    __u32 local_ip;
    __u32 destination_ip;
    __u8 source_mac[ETH_ALEN];
    __u8 destination_mac[ETH_ALEN];
};

// The header incapsulationg the packets sent out
// to the monitor host.
struct encaphdr {
    struct iphdr ip;
    struct udphdr udp;
};

// Contains the destination to redirect traffic to.
struct bpf_map_def SEC("maps") destinations = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct destination),
    .max_entries = 1,
    .map_flags   = BPF_F_NO_PREALLOC,
};

SEC("tc")
int router(struct __sk_buff *skb) {
    __u32 key = 0;
    struct destination *dest = bpf_map_lookup_elem(&destinations, &key);

    if (dest != NULL) {
        void *data_end = (void *)(long)skb->data_end;
        void *data = (void *)(long)skb->data;
        // Necessary validation: if L3 layer does not exist, ignore and continue.
        if (data + sizeof(struct ethhdr) > data_end) {
            return TC_ACT_OK;
        }

        struct ethhdr *eth = data;
        struct iphdr *ip_header = data + sizeof(struct ethhdr);
        struct encaphdr encap_header = {};
        if ((void*) ip_header + sizeof(struct iphdr) > data_end) {
            return TC_ACT_OK;
        }

        // Rewrite L2 destination and source.
        memcpy(&eth->h_source, dest->source_mac, ETH_ALEN);
        memcpy(&eth->h_dest, dest->destination_mac, ETH_ALEN);

        // Prepare encapsulating network header.
        memcpy(&encap_header.ip, ip_header, sizeof(struct iphdr));
        encap_header.ip.saddr = dest->local_ip;
        encap_header.ip.daddr = dest->destination_ip;
        encap_header.ip.protocol = IPPROTO_UDP;
        encap_header.ip.tot_len = __constant_htons(
            __constant_htons(ip_header->tot_len) +
            sizeof(struct encaphdr));
        set_ipv4_csum(&encap_header.ip);

        int udp_port = 3040;
        encap_header.udp.check = 0;
        encap_header.udp.source = __constant_htons(udp_port);
        encap_header.udp.dest = __constant_htons(udp_port);
        encap_header.udp.len = __constant_htons(
            (__constant_htons(ip_header->tot_len)) +
            sizeof(struct udphdr));

        int flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
        if (bpf_skb_adjust_room(skb, sizeof(struct encaphdr), BPF_ADJ_ROOM_MAC, flags)) {
           return TC_ACT_OK;
        }

        if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &encap_header, sizeof(struct encaphdr), BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH ))  {
            return TC_ACT_OK;
        };

        // zero flag means that the socket buffer is
        // redirected to the iface egress path.
        return bpf_redirect(dest->defaultIfaceIdx, 0);
    }
    return TC_ACT_OK;
}


SEC("tc")
int ingress_tapper(struct __sk_buff *skb) {
    __u32 key = 0;
    struct destination *dest = bpf_map_lookup_elem(&destinations, &key);
    if (dest != NULL) {
        bpf_clone_redirect(skb, dest->egressIfaceIdx, BPF_F_INGRESS);
    }
    return TC_ACT_OK;
}

SEC("tc")
int egress_tapper(struct __sk_buff *skb) {
    __u32 key = 0;
    struct destination *dest = bpf_map_lookup_elem(&destinations, &key);
    
    if (dest != NULL) {
        void *data_end = (void *)(long)skb->data_end;
        void *data = (void *)(long)skb->data;
        // Necessary validation: if L3 layer does not exist, ignore and continue.
        if (data + sizeof(struct ethhdr) > data_end) {
            return TC_ACT_OK;
        }

        struct ethhdr *eth = data;
        struct iphdr *ip_header = data + sizeof(struct ethhdr);
        struct encaphdr encap_header = {};
        if ((void*) ip_header + sizeof(struct iphdr) > data_end) {
            return TC_ACT_OK;
        }

        // Only tap traffic that hasn't been tapped before.
        if (ip_header->daddr != dest->destination_ip) {
            bpf_clone_redirect(skb, dest->egressIfaceIdx, BPF_F_INGRESS);
        }
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";