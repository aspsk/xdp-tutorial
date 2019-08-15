/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define bpf_printk(fmt, ...)                                            \
({                                                                      \
        char ____fmt[] = fmt;                                           \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);      \
})

#define  PROG_ID0 0
#define _PROG_MAX 1

#ifndef __stringify
#define __stringify_1(x...) #x
#define __stringify(x...)   __stringify_1(x)
#endif

#define PROG(ID) SEC("prog/"__stringify(ID)) int xdp_prog_ ## ID ## _func

struct bpf_map_def SEC("maps") progs = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = _PROG_MAX,
};

struct meta_info {
	__u8 l4_header_offset;
	__u8 l4_protocol;
	__u16 l4_payload_len;
} __attribute__((aligned(4)));

PROG(PROG_ID0) (struct xdp_md *ctx)
{
	__u8 hdrlen;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	int action = XDP_ABORTED;
	void *data = (void *)(long) ctx->data;
	void *data_end = (void *)(long) ctx->data_end;
	struct meta_info *meta = (void *)(long) ctx->data_meta;

	bpf_printk("received a packet\n");

	if (meta + 1 > data)
		goto out;

	bpf_printk("meta is OK\n");

	if (data + meta->l4_header_offset > data_end)
		goto out;

	bpf_printk("meta->l4_header_offset is OK\n");

	if (meta->l4_protocol == IPPROTO_UDP) {
		bpf_printk("this is a UDP packet\n");
		udphdr = (void *)(data + meta->l4_header_offset);
		if (udphdr + 1 > data_end)
			goto out;
		bpf_printk("UDP header is OK\n");

		/* ... do smth with udphdr and payload */

		__builtin_memset(udphdr, 0, sizeof(*udphdr));

	} else if (meta->l4_protocol == IPPROTO_TCP) {
		bpf_printk("this is a TCP packet\n");
		tcphdr = (void *)(data + meta->l4_header_offset);
		if (tcphdr + 1 > data_end)
			goto out;
		bpf_printk("TCP header is OK, part1\n");

		hdrlen = tcphdr->doff * 4;
		if ((void *) tcphdr + hdrlen > data_end)
			goto out;
		bpf_printk("TCP header is OK, part2\n");

		/* ... do smth with tcphdr and payload */

#if 0
		__u16 x = meta->l4_payload_len;
		if (x > 100)
			goto out;

		if (hdrlen > 64)
			goto out;

		char *payload = (void *) tcphdr + hdrlen;
		if (payload + x > data_end)
			return XDP_ABORTED;
		for (__u16 i = 0; i < x; i++)
			bpf_printk("%x", payload[i]);
		bpf_printk("\n", payload[i]);
#endif

	} else {
		bpf_printk("unknown packet type: %d\n", meta->l4_protocol);
		action = XDP_PASS;
	}

out:
	bpf_printk("returning %d\n\n", action);
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_entry")
int xdp_entry_func(struct xdp_md *ctx)
{
	int ret;
	int eth_type;
	int hdrsize;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	void *data, *data_end;
	int action = XDP_ABORTED;
	struct hdr_cursor nh;
	struct meta_info *meta;

	ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (ret < 0)
		goto out;

	data = (void *)(long) ctx->data;
	data_end = (void *)(long) ctx->data_end;
	meta = (void *)(long) ctx->data_meta;
	if (meta + 1 > data)
		goto out;

	nh.pos = data;
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		goto out;

	if (eth_type == ETH_P_IP) {
		iphdr = (void *)(eth + 1);
		if (iphdr + 1 > data_end)
			goto out;

		hdrsize = iphdr->ihl * 4;
		if (data + hdrsize > data_end)
			goto out;

		if (bpf_ntohs(iphdr->tot_len) < hdrsize)
			goto out;

		meta->l4_header_offset = sizeof(*eth) + hdrsize;
		meta->l4_protocol = iphdr->protocol;
		meta->l4_payload_len = bpf_ntohs(iphdr->tot_len) - hdrsize;
	} else if (eth_type == ETH_P_IPV6) {
		ipv6hdr = (void *)(eth + 1);
		if (ipv6hdr + 1 > data_end)
			goto out;

		meta->l4_header_offset = sizeof(*eth) + sizeof(*ipv6hdr);
		meta->l4_protocol = ipv6hdr->nexthdr;
		meta->l4_payload_len = bpf_ntohs(ipv6hdr->payload_len);
	} else {
		action = XDP_PASS;
		goto out;
	}

	bpf_tail_call(ctx, &progs, PROG_ID0);

	/* tail call failed, pass packet to the Linux stack */
	action = XDP_PASS;

out:
	return action; // xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
