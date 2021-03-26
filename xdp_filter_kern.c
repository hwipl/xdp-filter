/* bpf */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* ethernet */
#include <linux/if_ether.h>

/* ipv4 */
#include <linux/ip.h>

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

/* map for source macs */
#define MAX_SRC_MACS 1024
struct bpf_elf_map SEC("maps") src_macs = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = ETH_ALEN,
	.size_value = sizeof(char),
	.max_elem = MAX_SRC_MACS,
};

/* map for source ipv4s */
#define MAX_SRC_IPV4S 1024
struct bpf_elf_map SEC("maps") src_ipv4s = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__be32),
	.size_value = sizeof(char),
	.max_elem = MAX_SRC_IPV4S,
};

/* filter ipv4 addresses */
SEC("filter_ipv4")
int _filter_ipv4(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ipv4;
	__u32 key = 0;
	__u64 nh_off;
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

/* filter ethernet addresses */
SEC("filter_ethernet")
int _filter_ethernet(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u32 key = 0;
	__u64 nh_off;
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
