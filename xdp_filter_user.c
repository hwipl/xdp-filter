/* bpf */
#include <bpf/libbpf.h>

/* XDP_FLAGS_* */
#include <linux/if_link.h>

/* if_nametoindex() */
#include <net/if.h>

int main(int argc, char **argv) {
	if (argc < 4) {
		return -1;
	}

	/* load bpf file */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
		.file		= argv[1],
	};
	struct bpf_object *obj;
	int prog_fd;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		printf("Error loading xdp program\n");
		return -1;
	}

	/* find bpf program by title/section name */
	struct bpf_program *prog;
	prog = bpf_object__find_program_by_title(obj, argv[2]);
	if (!prog) {
		printf("Error getting xdp prog from file\n");
		return -1;
	}
	prog_fd = bpf_program__fd(prog);

	/* attach bpf program to interface */
	int ifindex = if_nametoindex(argv[3]);
	__u32 xdp_flags = XDP_FLAGS_DRV_MODE;

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("Error attaching xdp program\n");
		return -1;
	}

	return 0;
}
