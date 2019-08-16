#ifndef TAIL_H
#define TAIL_H

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

#endif /* TAIL_H */
