/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "XDP prog helper\n"
	" - Allows to populate program array map\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#include "../common/xdp_stats_kern_user.h"

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int len;
	int map_fd;
	char pin_dir[PATH_MAX];
	struct bpf_object *bpf_obj;
	struct bpf_program *bpf_prog;

	struct config cfg = {
		.ifindex   = -1,
		.filename = "xdp_prog_kern_tail.o",
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = open_bpf_map_file(pin_dir, "progs", NULL);
	if (map_fd < 0)
		return EXIT_FAIL_BPF;

	printf("map dir: %s\n", pin_dir);

	// XXX: in order to use the same stats map, we need to load the map
	// used by the xdp_entry progam and load prog/* programs as in basic04

	bpf_obj = load_bpf_object_file(cfg.filename, 0);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg.filename);
		return EXIT_FAIL_BPF;
	}

	bpf_object__for_each_program(bpf_prog, bpf_obj) {
		int id, prog_fd;
		const char *title = bpf_program__title(bpf_prog, false);

		if (strncmp("prog", title, 4)) {
			fprintf(stderr, "skipping section: %s\n", title);
			continue;
		} else {
			id = atoi(title+5);
			fprintf(stderr, "trying to load section: %s: id=%d\n", title, id);
		}

		prog_fd = bpf_program__fd(bpf_prog);
		if (prog_fd < 0) {
			fprintf(stderr, "ERR: bpf_program__fd failed\n");
			return EXIT_FAIL_BPF;
		}

		if (bpf_map_update_elem(map_fd, &id, &prog_fd, 0) < 0) {
			fprintf(stderr, "WARN: Failed to update bpf map file: err(%d):%s\n",
					errno, strerror(errno));
			return EXIT_FAIL_BPF;
		}
	}

	return EXIT_OK;
}
