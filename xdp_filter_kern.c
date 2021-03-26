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

/* filter udp ports */
SEC("filter_udp")
int _filter_udp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ipv6;
	struct iphdr *ipv4;
	struct udphdr *udp;
	long *value;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) {
		return XDP_PASS;
	}

	/* check ip and get udp header */
	switch (htons(eth->h_proto)) {
	case ETH_P_IP:
		ipv4 = data + sizeof(struct ethhdr);

		if (ipv4->protocol != IPPROTO_UDP) {
			return XDP_PASS;
		}

		udp = ((void *) ipv4) + ipv4->ihl * 4;

		break;
	case ETH_P_IPV6:
		ipv6 = data + sizeof(struct ethhdr);

		if (ipv6->nexthdr != IPPROTO_UDP) {
			return XDP_PASS;
		}

		udp = (void *) (ipv6 + 1);

		break;
	default:
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

/* filter ipv6 addresses */
SEC("filter_ipv6")
int _filter_ipv6(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ipv6;
	long *value;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) {
		return XDP_PASS;
	}

	/* check ipv6 */
	if (eth->h_proto != htons(ETH_P_IPV6)) {
		return XDP_PASS;
	}
	ipv6 = data + sizeof(struct ethhdr);

	/* check if src ip is in src_ipv6s map */
	value = bpf_map_lookup_elem(&src_ipv6s, &ipv6->saddr);
	if (value) {
		/* found src ip, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* filter ipv4 addresses */
SEC("filter_ipv4")
int _filter_ipv4(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ipv4;
	long *value;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		return XDP_PASS;
	}

	/* check ipv4 */
	if (eth->h_proto != htons(ETH_P_IP)) {
		return XDP_PASS;
	}
	ipv4 = data + sizeof(struct ethhdr);

	/* check if src ip is in src_ipv4s map */
	value = bpf_map_lookup_elem(&src_ipv4s, &ipv4->saddr);
	if (value) {
		/* found src ip, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* filter vlans */
SEC("filter_vlan")
int _filter_vlan(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct vlan_hdr *vlan;
	__u16 vlan_id;
	long *value;

	/* check packet length for verifier */
	if (data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > data_end) {
		return XDP_PASS;
	}

	/* check vlan */
	if (eth->h_proto != htons(ETH_P_8021Q) &&
	    eth->h_proto != htons(ETH_P_8021AD)) {
		return XDP_PASS;
	}
	vlan = data + sizeof(struct ethhdr);


	/* check if vlan is in vlan_ids map */
	vlan_id = ntohs(vlan->h_vlan_TCI) & VLAN_VID_MASK;
	value = bpf_map_lookup_elem(&vlan_ids, &vlan_id);
	if (value) {
		/* found vlan, drop packet */
		return XDP_DROP;
	}

	return XDP_PASS;
}

/* filter ethernet addresses */
SEC("filter_ethernet")
int _filter_ethernet(struct xdp_md *ctx)
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
