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

PROG(PROG_ID0) (struct xdp_md *ctx)
{
	__u8 hdrlen;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	int action = XDP_ABORTED;
	void *data = (void *)(long) ctx->data;
	void *data_end = (void *)(long) ctx->data_end;
	struct meta_info *meta = (void *)(long) ctx->data_meta;

	if (meta + 1 > data)
		goto out;

	bpf_printk("meta is OK l4_header_offset=%d protocol=%d payload_len=%d\n",
			meta->l4_header_offset,
			meta->l4_protocol,
			meta->l4_payload_len
	);

	if (data + meta->l4_header_offset > data_end)
		goto out;

	if (meta->l4_protocol == IPPROTO_UDP) {
		bpf_printk("this is a UDP packet\n");
		udphdr = (void *)(data + meta->l4_header_offset);
		if (udphdr + 1 > data_end)
			goto out;

		/* ... do smth with udphdr and payload */

		__builtin_memset(udphdr, 0, sizeof(*udphdr));

		action = XDP_PASS;
	} else if (meta->l4_protocol == IPPROTO_TCP) {
		bpf_printk("this is a TCP packet\n");
		tcphdr = (void *)(data + meta->l4_header_offset);
		if (tcphdr + 1 > data_end)
			goto out;

		hdrlen = tcphdr->doff * 4;
		if ((void *) tcphdr + hdrlen > data_end)
			goto out;

		/* ... do smth with tcphdr and payload */

		action = XDP_PASS;
	} else {
		//bpf_printk("1");//UPT: %d\n", (int)meta->l4_protocol);
		action = XDP_PASS;
	}

out:
	bpf_printk("returning %d\n\n", action);
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
