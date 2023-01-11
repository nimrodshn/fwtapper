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

// The header incapsulationg the packets sent out
// to the monitor host.
struct encaphdr {
    struct iphdr ip;
    struct udphdr udp;
};

// Contains the IPv4 addresses from which traffic was redirect.
struct bpf_map_def SEC("maps") origins_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 50,
    .map_flags   = BPF_F_NO_PREALLOC,
};


// Contains the interface to redirect the decapsulated traffic.
struct bpf_map_def SEC("maps") decap_iface_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
    .map_flags   = BPF_F_NO_PREALLOC,
};

SEC("tc")
int decap(struct __sk_buff *skb) {
    __u32 key = 0;
    __u32 *decap_iface = bpf_map_lookup_elem(&decap_iface_map, &key);

    if (decap_iface != NULL) {
        void *data_end = (void *)(long)skb->data_end;
        void *data = (void *)(long)skb->data;
        // Necessary validation: if L3 layer does not exist, ignore and continue.
        if (data + sizeof(struct ethhdr) > data_end) {
            return TC_ACT_OK;
        }

        struct ethhdr *eth = data;
        struct iphdr *ip_header = data + sizeof(struct ethhdr);
        if ((void*) ip_header + sizeof(struct iphdr) > data_end) {
            return TC_ACT_OK;
        }

        // Lookup incoming packets source in the origins map.
        __u32 *res  = bpf_map_lookup_elem(&origins_map, &ip_header->saddr);
        if (res != NULL) {
            // Strip the encapsulating header off the packet.
            int olen = sizeof(struct encaphdr);
            if (bpf_skb_adjust_room(skb,
                    -olen, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO)) {
                return TC_ACT_SHOT;
            }
            return bpf_redirect(*decap_iface, BPF_F_INGRESS);
        }
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";