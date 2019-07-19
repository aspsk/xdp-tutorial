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

#define PROG_IP 0
#define PROG_IPV6 1
#define _PROG_MAX 2

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

PROG(PROG_IP) (struct xdp_md *ctx)
{
	bpf_printk("ignore all IPv4 traffic\n");
	return xdp_stats_record_action(ctx, XDP_PASS);
}

PROG(PROG_IPV6) (struct xdp_md *ctx)
{
	bpf_printk("ignore all IPv6 traffic\n");
	return xdp_stats_record_action(ctx, XDP_DROP);
}

SEC("xdp_entry")
int xdp_entry_func(struct xdp_md *ctx)
{
	int eth_type;
	struct ethhdr *eth;
	int action = XDP_PASS;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == ETH_P_IP) {
		bpf_tail_call(ctx, &progs, PROG_IP);
		bpf_printk("bpf_tail_call: %d: failed\n", PROG_IP);
	} else if (eth_type == ETH_P_IPV6) {
		bpf_tail_call(ctx, &progs, PROG_IPV6);
		bpf_printk("bpf_tail_call: %d: failed\n", PROG_IPV6);
	}

out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
