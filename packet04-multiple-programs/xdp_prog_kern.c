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

#include "tail_common.h"
#include "tail.h"

SEC("xdp_entry")
int xdp_entry_func(struct xdp_md *ctx)
{
	int ret;
	int eth_type;
	int hdrsize;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	void *data;
	void *data_end;
	struct meta_info *meta;
	struct hdr_cursor nh;
	int action = XDP_ABORTED;

	ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
	if (ret < 0)
		goto out;

	meta = (void *)(long) ctx->data_meta;
	data = (void *)(long) ctx->data;
	data_end = (void *)(long) ctx->data_end;
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
		if ((void *) iphdr + hdrsize > data_end)
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
		meta->l4_header_offset = 0;
		meta->l4_protocol = 0;
		meta->l4_payload_len = 0;
		action = XDP_PASS;
	}

	bpf_tail_call(ctx, &progs, PROG_ID0);

out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
