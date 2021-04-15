/* bpf */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* ethernet */
#include <linux/if_ether.h>

/* ipv4 */
#include <linux/ip.h>

/* ipv6 */
#include <linux/ipv6.h>

/* udp */
#include <linux/udp.h>

/* tcp */
#include <linux/tcp.h>

/* htons */
#include <arpa/inet.h>

/* set license to gpl */
char _license[] SEC("license") = "GPL";

/* map definitions */
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

/* vlan definitions from <linux src>/include/linux/if_vlan.h */
#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* map for source macs */
#define MAX_SRC_MACS 1024
struct bpf_elf_map SEC("maps") src_macs = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = ETH_ALEN,
	.size_value = sizeof(char),
	.max_elem = MAX_SRC_MACS,
};

/* map for vlan ids */
#define MAX_VLAN_IDS 1024
struct bpf_elf_map SEC("maps") vlan_ids = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__u16),
	.size_value = sizeof(char),
	.max_elem = MAX_VLAN_IDS,
};

/* map for source ipv4s */
#define MAX_SRC_IPV4S 1024
struct bpf_elf_map SEC("maps") src_ipv4s = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__be32),
	.size_value = sizeof(char),
	.max_elem = MAX_SRC_IPV4S,
};

/* map for source ipv6s */
#define MAX_SRC_IPV6S 1024
struct bpf_elf_map SEC("maps") src_ipv6s = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(struct in6_addr),
	.size_value = sizeof(char),
	.max_elem = MAX_SRC_IPV6S,
};

/* map for source udp ports */
#define MAX_SRC_UDPS 1024
struct bpf_elf_map SEC("maps") src_udps = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__be16),
	.size_value = sizeof(char),
	.max_elem = MAX_SRC_UDPS,
};

/* map for source tcp ports */
#define MAX_SRC_TCPS 1024
struct bpf_elf_map SEC("maps") src_tcps = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__be16),
	.size_value = sizeof(char),
	.max_elem = MAX_SRC_TCPS,
};

/* helper for checking if type is a vlan header */
int is_vlan_header(__be16 type) {
	return type == htons(ETH_P_8021Q) || type == htons(ETH_P_8021AD);
}

/* helper for getting the first vlan header in the ethernet packet in data */
void *get_first_vlan_header(void *data, void *data_end) {
	struct ethhdr *eth = data;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > data_end) {
		return 0;
	}

	/* check vlan */
	if (!is_vlan_header(eth->h_proto)) {
		return 0;
	}
	return data + sizeof(struct ethhdr);
}

/* helper for getting the next vlan header after the vlan header in data */
void *get_next_vlan_header(void *data, void *data_end) {
	struct vlan_hdr *vlan = data;

	/* check packet length for verifier */
	if (data + sizeof(struct vlan_hdr) * 2 > data_end) {
		return 0;
	}

	/* check vlan */
	if (!is_vlan_header(vlan->h_vlan_encapsulated_proto)) {
		return 0;
	}
	return data + sizeof(struct vlan_hdr);
}

/* helper for skipping vlan headers in the ethernet packet in data */
#define MAX_VLAN_HEADERS 2
int skip_vlan_headers(void *data, void *data_end, __be16 *type, void **next) {
	struct ethhdr *eth = data;
	struct vlan_hdr *vlan;
	__u16 vlan_id;
	long *value;
	int i = 0;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > data_end) {
		return -1;
	}

	/* check vlan */
	if (!is_vlan_header(eth->h_proto)) {
		*type = eth->h_proto;
		*next = eth + 1;
		return 0;
	}
	vlan = data + sizeof(struct ethhdr);

	/* skip through vlan headers */
	while (i < MAX_VLAN_HEADERS) {
		if (!is_vlan_header(vlan->h_vlan_encapsulated_proto)) {
			break;
		}
		vlan = vlan + 1;

		/* check packet length for verifier */
		if ((void *) vlan > data_end) {
			return -1;
		}
	}

	/* return next type and pointer */
	*type = vlan->h_vlan_encapsulated_proto;
	*next = vlan + 1;
	return 0;
}

/* helper for getting the layer 3 header in the ethernet packet in data */
void *get_l3_header(void *data, void *data_end, __u16 type) {
	struct ethhdr *eth = data;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) > data_end) {
		return 0;
	}

	/* check l3 type */
	if (htons(eth->h_proto) != type) {
		return 0;
	}

	return data + sizeof(struct ethhdr);
}

/* helper for getting the layer 4 header in the ethernet packet in data */
void *get_l4_header(void *data, void *data_end, __u8 type) {
	struct ethhdr *eth = data;
	struct ipv6hdr *ipv6;
	struct iphdr *ipv4;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) > data_end) {
		return 0;
	}

	/* check ip and get udp header */
	switch (htons(eth->h_proto)) {
	case ETH_P_IP:
		ipv4 = data + sizeof(struct ethhdr);

		/* check packet length for verifier */
		if ((void *) ipv4 + sizeof(struct iphdr) > data_end) {
			return 0;
		}

		/* check l4 type */
		if (ipv4->protocol != type) {
			return 0;
		}

		return ((void *) ipv4) + ipv4->ihl * 4;
	case ETH_P_IPV6:
		ipv6 = data + sizeof(struct ethhdr);

		/* check packet length for verifier */
		if ((void *) ipv6 + sizeof(struct ipv6hdr) > data_end) {
			return 0;
		}

		/* check l4 type */
		if (ipv6->nexthdr != type) {
			return 0;
		}

		return (void *) (ipv6 + 1);
	default:
		return 0;
	}
}

/* filter tcp ports and accept everything else */
SEC("filter_tcp_drop")
int _filter_tcp_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct tcphdr *tcp;
	long *value;

	/* get tcp header */
	tcp = get_l4_header(data, data_end, IPPROTO_TCP);
	if (!tcp) {
		return XDP_PASS;
	}

	/* check packet length for verifier */
	if ((void *) (tcp + 1) > data_end) {
		return XDP_PASS;
	}

	/* check if src port is in src_tcps map */
	value = bpf_map_lookup_elem(&src_tcps, &tcp->source);
	if (value) {
		/* found src port, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* accept tcp ports and filter everything else */
SEC("filter_tcp_pass")
int _filter_tcp_pass(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct tcphdr *tcp;
	long *value;

	/* get tcp header */
	tcp = get_l4_header(data, data_end, IPPROTO_TCP);
	if (!tcp) {
		return XDP_DROP;
	}

	/* check packet length for verifier */
	if ((void *) (tcp + 1) > data_end) {
		return XDP_DROP;
	}

	/* check if src port is in src_tcps map */
	value = bpf_map_lookup_elem(&src_tcps, &tcp->source);
	if (value) {
		/* found src port, drop packet */
		return XDP_PASS;
	}

	return XDP_DROP;
}

/* filter udp ports and accept everything else */
SEC("filter_udp_drop")
int _filter_udp_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct udphdr *udp;
	long *value;

	/* get udp header */
	udp = get_l4_header(data, data_end, IPPROTO_UDP);
	if (!udp) {
		return XDP_PASS;
	}

	/* check packet length for verifier */
	if ((void *) (udp + 1) > data_end) {
		return XDP_PASS;
	}

	/* check if src udp port is in src_udps map */
	value = bpf_map_lookup_elem(&src_udps, &udp->source);
	if (value) {
		/* found src udp port, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* accept udp ports and filter everything else */
SEC("filter_udp_pass")
int _filter_udp_pass(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct udphdr *udp;
	long *value;

	/* get udp header */
	udp = get_l4_header(data, data_end, IPPROTO_UDP);
	if (!udp) {
		return XDP_DROP;
	}

	/* check packet length for verifier */
	if ((void *) (udp + 1) > data_end) {
		return XDP_DROP;
	}

	/* check if src udp port is in src_udps map */
	value = bpf_map_lookup_elem(&src_udps, &udp->source);
	if (value) {
		/* found src udp port, drop packet */
		return XDP_PASS;
	}

	return XDP_DROP;
}

/* filter ipv6 addresses and accept everything else */
SEC("filter_ipv6_drop")
int _filter_ipv6_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ipv6;
	long *value;

	/* get ipv6 header */
	ipv6 = get_l3_header(data, data_end, ETH_P_IPV6);
	if (!ipv6) {
		return XDP_PASS;
	}

	/* check packet length for verifier */
	if ((void *) (ipv6 + 1) > data_end) {
		return XDP_PASS;
	}

	/* check if src ip is in src_ipv6s map */
	value = bpf_map_lookup_elem(&src_ipv6s, &ipv6->saddr);
	if (value) {
		/* found src ip, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* accept ipv6 addresses and filter everything else */
SEC("filter_ipv6_pass")
int _filter_ipv6_pass(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ipv6;
	long *value;

	/* get ipv6 header */
	ipv6 = get_l3_header(data, data_end, ETH_P_IPV6);
	if (!ipv6) {
		return XDP_DROP;
	}

	/* check packet length for verifier */
	if ((void *) (ipv6 + 1) > data_end) {
		return XDP_DROP;
	}

	/* check if src ip is in src_ipv6s map */
	value = bpf_map_lookup_elem(&src_ipv6s, &ipv6->saddr);
	if (value) {
		/* found src ip, drop packet */
		return XDP_PASS;
	}

	return XDP_DROP;
}

/* accept ipv4 addresses and filter everything else */
SEC("filter_ipv4_pass")
int _filter_ipv4_pass(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *ipv4;
	long *value;

	/* get ipv4 header */
	ipv4 = get_l3_header(data, data_end, ETH_P_IP);
	if (!ipv4) {
		return XDP_DROP;
	}

	/* check packet length for verifier */
	if ((void *) (ipv4 + 1) > data_end) {
		return XDP_DROP;
	}

	/* check if src ip is in src_ipv4s map */
	value = bpf_map_lookup_elem(&src_ipv4s, &ipv4->saddr);
	if (value) {
		/* found src ip, drop packet */
		return XDP_PASS;
	}

	return XDP_DROP;
}

/* filter ipv4 addresses and accept everything else */
SEC("filter_ipv4_drop")
int _filter_ipv4_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *ipv4;
	long *value;

	/* get ipv4 header */
	ipv4 = get_l3_header(data, data_end, ETH_P_IP);
	if (!ipv4) {
		return XDP_PASS;
	}

	/* check packet length for verifier */
	if ((void *) (ipv4 + 1) > data_end) {
		return XDP_PASS;
	}

	/* check if src ip is in src_ipv4s map */
	value = bpf_map_lookup_elem(&src_ipv4s, &ipv4->saddr);
	if (value) {
		/* found src ip, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* accept vlan ids and filter everything else */
SEC("filter_vlan_pass")
int _filter_vlan_pass(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vlan_hdr *vlan;
	__u16 vlan_id;
	long *value;

	/* get vlan header */
	vlan = get_first_vlan_header(data, data_end);
	if (!vlan) {
		return XDP_DROP;
	}

	/* check if vlan is in vlan_ids map */
	vlan_id = ntohs(vlan->h_vlan_TCI) & VLAN_VID_MASK;
	value = bpf_map_lookup_elem(&vlan_ids, &vlan_id);
	if (value) {
		/* found vlan, drop packet */
		return XDP_PASS;
	}

	return XDP_DROP;
}

/* filter vlans and accept everything else */
SEC("filter_vlan_drop")
int _filter_vlan_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vlan_hdr *vlan;
	__u16 vlan_id;
	long *value;

	/* get vlan header */
	vlan = get_first_vlan_header(data, data_end);
	if (!vlan) {
		return XDP_PASS;
	}

	/* check if vlan is in vlan_ids map */
	vlan_id = ntohs(vlan->h_vlan_TCI) & VLAN_VID_MASK;
	value = bpf_map_lookup_elem(&vlan_ids, &vlan_id);
	if (value) {
		/* found vlan, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* accept ethernet addresses and filter everything else */
SEC("filter_ethernet_pass")
int _filter_ethernet_pass(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	long *value;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_DROP;
	}

	/* check if src mac is in src_macs map */
	value = bpf_map_lookup_elem(&src_macs, eth->h_source);
	if (value) {
		/* found src mac, drop packet */
		return XDP_PASS;
	}

	return XDP_DROP;
}

/* filter ethernet addresses and accept everything else */
SEC("filter_ethernet_drop")
int _filter_ethernet_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	long *value;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_PASS;
	}

	/* check if src mac is in src_macs map */
	value = bpf_map_lookup_elem(&src_macs, eth->h_source);
	if (value) {
		/* found src mac, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}
