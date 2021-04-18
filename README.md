# xdp-filter

## Building

Build requirements:
* llvm, clang
* libbpf

Quick build:

```console
$ ./build.sh
```

Testing:

```console
# ./test.sh all
```

## Usage

You can use `xdp_filter_user` to configure the packet filtering:

```
Usage:
  ./xdp_filter_user load <file> <section> <device>
  ./xdp_filter_user unload <device>
  ./xdp_filter_user drop-eth-src|pass-eth-src <device> <macs>
  ./xdp_filter_user drop-vlan|pass-vlan <device> <vlan_ids>
  ./xdp_filter_user drop-ipv4-src|pass-ipv4-src <device> <ips>
  ./xdp_filter_user drop-ipv6-src|pass-ipv6-src <device> <ips>
  ./xdp_filter_user drop-udp-src|pass-udp-src <device> <ports>
  ./xdp_filter_user drop-tcp-src|pass-tcp-src <device> <ports>
```

The `drop-*` and `pass-*` commands load an XDP program on the specified network
device that starts packet filtering. The `drop-*` commands configure dropping
of the specified packets and passing everything else. The `pass-*` commands
configure passing of the specified packets and dropping everything else.
Dropped or passed packets are specified by:

* `*-eth-src`:  Ethernet source addresses
* `*-vlan`: VLAN IDs
* `*-ipv4-src`: IPv4 source addresses
* `*-ipv6-src`: IPv6 source addresses
* `*-udp-src`: UDP source ports
* `*-tcp-src`: TCP source ports

`unload` removes the currently running XDP program from device and, thus,
disables packet filtering.

`load` attaches the XDP program found in the ELF section of file to the network
device. This can be used for debugging and is not needed for configuring packet
filtering.

## Examples

Dropping packets with MAC source addresses `02:ab:cc:ba:20:01` and
`02:ab:cc:ba:20:02` and passing all other packets on device `veth1`:

```console
# ./xdp_filter_user drop-eth-src veth1 02:ab:cc:ba:20:01 02:ab:cc:ba:20:02
```

Passing packets with MAC source addresses `02:ab:cc:ba:20:01` and
`02:ab:cc:ba:20:02` and dropping all other packets on device `veth1`:

```console
# ./xdp_filter_user pass-eth-src veth1 02:ab:cc:ba:20:01 02:ab:cc:ba:20:02
```

Passing packets with VLAN IDs `100`, `200` and `300` and dropping all other
packets on device `veth1`:

```console
# ./xdp_filter_user pass-vlan veth1 100 200 300
```

Dropping packets with IPv4 source address `192.168.1.10` and passing all other
packets on device `veth1`:

```console
# ./xdp_filter_user drop-ipv4-src veth1 192.168.1.10
```

Passing packets with IPv6 source address `fe80::1` and dropping all other
packets on device `veth1`:

```console
# ./xdp_filter_user pass-ipv6-src veth1 fe80::1
```

Dropping packets with UDP source ports `2000` and `2001` and passing all other
packets on device `veth1`:

```console
# ./xdp_filter_user drop-udp-src veth1 2000 2001
```

Passing packets with TCP source ports `2000` and `2001` and dropping all other
packets on device `veth1`:

```console
# ./xdp_filter_user pass-tcp-src veth1 2000 2001
```
