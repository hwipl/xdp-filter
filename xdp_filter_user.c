/* bpf */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* XDP_FLAGS_* */
#include <linux/if_link.h>

/* if_nametoindex() */
#include <net/if.h>

/* bpf object */
struct bpf_object *obj;

/* load xdp section inf file and attach it to device */
int load_xdp(const char *file, const char *section, const char *device) {
	/* load bpf file */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
		.file		= file,
	};
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

/* parse mac address in mac_string and store it in mac */
int parse_mac(const char* mac_string, char *mac) {
	return sscanf(mac_string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0],
		      &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6;
}

/* filter ethernet frames based on source mac addresses on device */
int filter_ethernet(const char *device, int num_macs, char **macs) {
	/* load xdp filter_ethernet xdp program */
	if (load_xdp("xdp_filter_kern.o", "filter_ethernet", device)) {
		return -1;
	}

	/* get map fd */
	int map_fd = bpf_object__find_map_fd_by_name(obj, "src_macs");
	if (map_fd <= 0) {
		printf("Error finding src_macs map\n");
		unload_xdp(device);
		return -1;
	}

	/* parse macs and add them to map */
	char mac[6];
	char value = 0;
	for (int i = 0; i < num_macs; i++) {
		/* parse mac */
		if (parse_mac(macs[i], mac)) {
			printf("Error parsing mac\n");
			unload_xdp(device);
			return -1;
		}

		/* add mac to map */
		if (bpf_map_update_elem(map_fd, mac, &value, BPF_ANY)) {
			printf("Error updating map\n");
			unload_xdp(device);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		return -1;
	}

	/* load xdp program? */
	if (!strncmp(argv[1], "load", 4)) {
		if (argc < 5) {
			return -1;
		}
		return load_xdp(argv[2], argv[3], argv[4]);
	}

	/* unload xdp program? */
	if (!strncmp(argv[1], "unload", 6)) {
		if (argc < 3) {
			return -1;
		}
		return unload_xdp(argv[2]);
	}

	/* filter ethernet? */
	if (!strncmp(argv[1], "ethernet", 8)) {
		if (argc < 4) {
			return -1;
		}
		return filter_ethernet(argv[2], argc - 3, argv + 3);
	}

	return -1;
}
