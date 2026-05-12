// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Adrian Enderlin
// Kernloom Shield TC Egress (observe-only):
//   Counts outgoing packets and bytes per destination IP for
//   host-side data movement / exfiltration telemetry.
//
//   This program is OBSERVE ONLY — it never drops or modifies packets.
//   Enforcement (if ever added) must go through the ingress/XDP path.
//
// Build: make -C shield/bpf
// Attach: klshield attach-egress --iface eth0

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP  6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP  17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#define TC_ACT_OK 0

char _license[] SEC("license") = "Dual BSD/GPL";

/* ── Aggregate egress counters (per-cpu) ─────────────────────────── */

struct egress_totals_t {
	__u64 pkts;
	__u64 bytes;
	__u64 tcp;
	__u64 udp;
	__u64 icmp;
	__u64 other;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct egress_totals_t);
} kernloom_egress_totals SEC(".maps");

/* ── Per-destination IPv4 stats (LRU) ───────────────────────────── */

struct egress_dst4_stats_t {
	__u64 pkts;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);                    /* dst IPv4 in network byte order */
	__type(value, struct egress_dst4_stats_t);
} kernloom_egress_dst4_stats SEC(".maps");

/* ── Helper: update per-cpu totals ─────────────────────────────── */

static __always_inline void
update_totals(__u64 bytes, __u8 proto)
{
	__u32 key = 0;
	struct egress_totals_t *tot =
		bpf_map_lookup_elem(&kernloom_egress_totals, &key);
	if (!tot)
		return;

	tot->pkts++;
	tot->bytes += bytes;

	switch (proto) {
	case IPPROTO_TCP:  tot->tcp++;   break;
	case IPPROTO_UDP:  tot->udp++;   break;
	case IPPROTO_ICMP: tot->icmp++;  break;
	default:           tot->other++; break;
	}
}

/* ── Helper: update per-destination stats ──────────────────────── */

static __always_inline void
update_dst4(__u32 dst_ip, __u64 bytes)
{
	struct egress_dst4_stats_t *st =
		bpf_map_lookup_elem(&kernloom_egress_dst4_stats, &dst_ip);
	if (st) {
		st->pkts++;
		st->bytes += bytes;
	} else {
		struct egress_dst4_stats_t init = { .pkts = 1, .bytes = bytes };
		bpf_map_update_elem(&kernloom_egress_dst4_stats, &dst_ip, &init, BPF_ANY);
	}
}

/* ── TC Egress classifier ───────────────────────────────────────── */

SEC("classifier")
int tc_egress(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u64 len      = skb->len;

	/* Only inspect IPv4 egress. */
	if (skb->protocol != bpf_htons(0x0800))
		goto out;

	struct iphdr *iph = data;
	if ((void *)(iph + 1) > data_end)
		goto out;

	__u32 dst_ip = iph->daddr;
	__u8  proto  = iph->protocol;

	update_totals(len, proto);
	update_dst4(dst_ip, len);
	return TC_ACT_OK;

out:
	/* Count non-IPv4 in totals but skip per-dst tracking. */
	update_totals(len, 0xFF);
	return TC_ACT_OK;
}
