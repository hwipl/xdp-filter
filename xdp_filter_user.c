/* bpf */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* XDP_FLAGS_* */
#include <linux/if_link.h>

/* if_nametoindex() */
#include <net/if.h>

/* atoi() */
#include <stdlib.h>

/* inet_pton() */
#include <arpa/inet.h>

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

/* parse port number in port_string and store it in port */
int parse_port(const char *port_string, __be16 *port) {
	int p = atoi(port_string);
	if (p < 1 || p > 65535) {
		return -1;
	}

	*port = ntohs(p);
	return 0;
}

/* filter packets based on source tcp ports on device */
int filter_tcp(int drop, const char *device, int num_ports, char **ports) {
	/* set xdp program based on drop or pass mode */
	const char *xdp_prog = "filter_tcp_pass";
	if (drop) {
		xdp_prog = "filter_tcp_drop";
	}

	/* load xdp filter_udp xdp program */
	if (load_xdp("xdp_filter_kern.o", xdp_prog, device)) {
		return -1;
	}

	/* get map fd */
	int map_fd = bpf_object__find_map_fd_by_name(obj, "src_tcps");
	if (map_fd <= 0) {
		printf("Error finding src_tcps map\n");
		unload_xdp(device);
		return -1;
	}

	/* parse tcp ports and add them to map */
	__be16 port;
	char value = 0;
	for (int i = 0; i < num_ports; i++) {
		/* parse port */
		if (parse_port(ports[i], &port)) {
			printf("Error parsing tcp port\n");
			unload_xdp(device);
			return -1;
		}

		/* add port to map */
		if (bpf_map_update_elem(map_fd, &port, &value, BPF_ANY)) {
			printf("Error updating map\n");
			unload_xdp(device);
			return -1;
		}
	}

	return 0;
}

/* filter packets based on source udp ports on device */
int filter_udp(int drop, const char *device, int num_ports, char **ports) {
	/* set xdp program based on drop or pass mode */
	const char *xdp_prog = "filter_udp_pass";
	if (drop) {
		xdp_prog = "filter_udp_drop";
	}

	/* load xdp filter_udp xdp program */
	if (load_xdp("xdp_filter_kern.o", xdp_prog, device)) {
		return -1;
	}

	/* get map fd */
	int map_fd = bpf_object__find_map_fd_by_name(obj, "src_udps");
	if (map_fd <= 0) {
		printf("Error finding src_udps map\n");
		unload_xdp(device);
		return -1;
	}

	/* parse udp ports and add them to map */
	__be16 port;
	char value = 0;
	for (int i = 0; i < num_ports; i++) {
		/* parse port */
		if (parse_port(ports[i], &port)) {
			printf("Error parsing udp port\n");
			unload_xdp(device);
			return -1;
		}

		/* add port to map */
		if (bpf_map_update_elem(map_fd, &port, &value, BPF_ANY)) {
			printf("Error updating map\n");
			unload_xdp(device);
			return -1;
		}
	}

	return 0;
}

/* parse ipv6 address in ip_string and store it in ip */
int parse_ipv6(const char *ip_string, struct in6_addr *ip) {
	if (inet_pton(AF_INET6, ip_string, ip) != 1) {
		return -1;
	}
	return 0;
}

/* filter packets based on source ipv6 addresses on device */
int filter_ipv6(int drop, const char *device, int num_ips, char **ips) {
	/* set xdp program based on drop or pass mode */
	const char *xdp_prog = "filter_ipv6_pass";
	if (drop) {
		xdp_prog = "filter_ipv6_drop";
	}

	/* load xdp filter_ipv6 xdp program */
	if (load_xdp("xdp_filter_kern.o", xdp_prog, device)) {
		return -1;
	}

	/* get map fd */
	int map_fd = bpf_object__find_map_fd_by_name(obj, "src_ipv6s");
	if (map_fd <= 0) {
		printf("Error finding src_ipv6s map\n");
		unload_xdp(device);
		return -1;
	}

	/* parse ipv6s and add them to map */
	struct in6_addr ip;
	char value = 0;
	for (int i = 0; i < num_ips; i++) {
		/* parse ip */
		if (parse_ipv6(ips[i], &ip)) {
			printf("Error parsing ipv6 address\n");
			unload_xdp(device);
			return -1;
		}

		/* add ip to map */
		if (bpf_map_update_elem(map_fd, &ip, &value, BPF_ANY)) {
			printf("Error updating map\n");
			unload_xdp(device);
			return -1;
		}
	}

	return 0;
}

/* parse ipv4 address in ip_string and store it in ip */
int parse_ipv4(const char *ip_string, __be32 *ip) {
	struct in_addr i;
	if (inet_pton(AF_INET, ip_string, &i) != 1) {
		return -1;
	}
	*ip = i.s_addr;
	return 0;
}

/* filter packets based on source ipv4 addresses on device */
int filter_ipv4(int drop, const char *device, int num_ips, char **ips) {
	/* set xdp program based on drop or pass mode */
	const char *xdp_prog = "filter_ipv4_pass";
	if (drop) {
		xdp_prog = "filter_ipv4_drop";
	}

	/* load xdp filter_ipv4 xdp program */
	if (load_xdp("xdp_filter_kern.o", xdp_prog, device)) {
		return -1;
	}

	/* get map fd */
	int map_fd = bpf_object__find_map_fd_by_name(obj, "src_ipv4s");
	if (map_fd <= 0) {
		printf("Error finding src_ipv4s map\n");
		unload_xdp(device);
		return -1;
	}

	/* parse ipv4s and add them to map */
	__be32 ip;
	char value = 0;
	for (int i = 0; i < num_ips; i++) {
		/* parse ip */
		if (parse_ipv4(ips[i], &ip)) {
			printf("Error parsing ipv4 address\n");
			unload_xdp(device);
			return -1;
		}

		/* add ip to map */
		if (bpf_map_update_elem(map_fd, &ip, &value, BPF_ANY)) {
			printf("Error updating map\n");
			unload_xdp(device);
			return -1;
		}
	}

	return 0;
}

/* parse vlan id in vlan_string and store it in vlan */
int parse_vlan(const char *vlan_string, __u16 *vlan) {
	int i = atoi(vlan_string);
	if (i < 1 || i > 4095) {
		return -1;
	}

	*vlan = i;
	return 0;
}

/* filter packets based on vlan ids on device */
int filter_vlan(int drop, const char *device, int num_vlans, char **vlans) {
	/* set xdp program based on drop or pass mode */
	const char *xdp_prog = "filter_vlan_pass";
	if (drop) {
		xdp_prog = "filter_vlan_drop";
	}

	/* load xdp filter_vlan xdp program */
	if (load_xdp("xdp_filter_kern.o", xdp_prog, device)) {
		return -1;
	}

	/* get map fd */
	int map_fd = bpf_object__find_map_fd_by_name(obj, "vlan_ids");
	if (map_fd <= 0) {
		printf("Error finding vlan_ids map\n");
		unload_xdp(device);
		return -1;
	}

	/* parse vlans and add them to map */
	__u16 vlan;
	char value = 0;
	for (int i = 0; i < num_vlans; i++) {
		/* parse vlan */
		if (parse_vlan(vlans[i], &vlan)) {
			printf("Error parsing vlan\n");
			unload_xdp(device);
			return -1;
		}

		/* add vlan to map */
		if (bpf_map_update_elem(map_fd, &vlan, &value, BPF_ANY)) {
			printf("Error updating map\n");
			unload_xdp(device);
			return -1;
		}
	}

	return 0;
}

/* parse mac address in mac_string and store it in mac */
int parse_mac(const char* mac_string, char *mac) {
	return sscanf(mac_string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0],
		      &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6;
}

/* filter ethernet frames based on source mac addresses on device */
int filter_ethernet(int drop, const char *device, int num_macs, char **macs) {
	/* set xdp program based on drop or pass mode */
	const char *xdp_prog = "filter_ethernet_pass";
	if (drop) {
		xdp_prog = "filter_ethernet_drop";
	}

	/* load xdp filter_ethernet xdp program */
	if (load_xdp("xdp_filter_kern.o", xdp_prog, device)) {
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

	/* drop ethernet source MACs? */
	if (!strncmp(argv[1], "drop-eth-src-macs", 17)) {
		if (argc < 4) {
			return -1;
		}
		return filter_ethernet(1, argv[2], argc - 3, argv + 3);
	}

	/* pass ethernet source MACs? */
	if (!strncmp(argv[1], "pass-eth-src-macs", 17)) {
		if (argc < 4) {
			return -1;
		}
		return filter_ethernet(0, argv[2], argc - 3, argv + 3);
	}

	/* drop vlan ids? */
	if (!strncmp(argv[1], "drop-vlan", 9)) {
		if (argc < 4) {
			return -1;
		}
		return filter_vlan(1, argv[2], argc - 3, argv + 3);
	}

	/* pass vlan ids? */
	if (!strncmp(argv[1], "pass-vlan", 9)) {
		if (argc < 4) {
			return -1;
		}
		return filter_vlan(0, argv[2], argc - 3, argv + 3);
	}

	/* drop ipv4 source ips? */
	if (!strncmp(argv[1], "drop-ipv4-src", 13)) {
		if (argc < 4) {
			return -1;
		}
		return filter_ipv4(1, argv[2], argc - 3, argv + 3);
	}

	/* pass ipv4 source ips? */
	if (!strncmp(argv[1], "pass-ipv4-src", 13)) {
		if (argc < 4) {
			return -1;
		}
		return filter_ipv4(0, argv[2], argc - 3, argv + 3);
	}

	/* drop ipv6 source ips? */
	if (!strncmp(argv[1], "drop-ipv6-src", 13)) {
		if (argc < 4) {
			return -1;
		}
		return filter_ipv6(1, argv[2], argc - 3, argv + 3);
	}

	/* pass ipv6 source ips? */
	if (!strncmp(argv[1], "pass-ipv6-src", 13)) {
		if (argc < 4) {
			return -1;
		}
		return filter_ipv6(0, argv[2], argc - 3, argv + 3);
	}

	/* drop udp source ports? */
	if (!strncmp(argv[1], "drop-udp-src", 12)) {
		if (argc < 4) {
			return -1;
		}
		return filter_udp(1, argv[2], argc - 3, argv + 3);
	}

	/* pass udp source ports? */
	if (!strncmp(argv[1], "pass-udp-src", 12)) {
		if (argc < 4) {
			return -1;
		}
		return filter_udp(0, argv[2], argc - 3, argv + 3);
	}

	/* drop tcp source ports? */
	if (!strncmp(argv[1], "drop-tcp-src", 12)) {
		if (argc < 4) {
			return -1;
		}
		return filter_tcp(1, argv[2], argc - 3, argv + 3);
	}

	/* pass tcp source ports? */
	if (!strncmp(argv[1], "pass-tcp-src", 12)) {
		if (argc < 4) {
			return -1;
		}
		return filter_tcp(0, argv[2], argc - 3, argv + 3);
	}

	return -1;
}
