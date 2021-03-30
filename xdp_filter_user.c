/* bpf */
#include <bpf/libbpf.h>

/* XDP_FLAGS_* */
#include <linux/if_link.h>

/* if_nametoindex() */
#include <net/if.h>

/* load xdp section inf file and attach it to device */
int load_xdp(const char *file, const char *section, const char *device) {
	/* load bpf file */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
		.file		= file,
	};
	struct bpf_object *obj;
	int prog_fd;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		printf("Error loading xdp program\n");
		return -1;
	}

	/* find bpf program by title/section name */
	struct bpf_program *prog;
	prog = bpf_object__find_program_by_title(obj, section);
	if (!prog) {
		printf("Error getting xdp prog from file\n");
		return -1;
	}
	prog_fd = bpf_program__fd(prog);

	/* attach bpf program to interface */
	int ifindex = if_nametoindex(device);
	__u32 xdp_flags = XDP_FLAGS_DRV_MODE;

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("Error attaching xdp program\n");
		return -1;
	}

	return 0;
}

/* unload current xdp program on device */
int unload_xdp(const char *device) {
	int ifindex = if_nametoindex(device);
	__u32 xdp_flags = XDP_FLAGS_DRV_MODE;

	/* detach bpf program from interface */
	if (bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) {
		printf("Error removing xdp program\n");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv) {
	if (argc < 5) {
		return -1;
	}

	/* load xdp program? */
	if (!strncmp(argv[1], "load", 4)) {
		return load_xdp(argv[2], argv[3], argv[4]);
	}

	return -1;
}
