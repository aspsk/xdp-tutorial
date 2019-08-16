#ifndef TAIL_COMMON_H
#define TAIL_COMMON_H

#define bpf_printk(fmt, ...)                                            \
({                                                                      \
        char ____fmt[] = fmt;                                           \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);      \
})

struct meta_info {
	__u8 l4_header_offset;
	__u8 l4_protocol;
	__u16 l4_payload_len;
} __attribute__((aligned(4)));

#endif /* TAIL_COMMON_H */
