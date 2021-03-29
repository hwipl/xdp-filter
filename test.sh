#!/bin/bash

# commands
IP=/usr/bin/ip

# name of network namespaces
NS_HOST1="xdp-filter-test-host1"
NS_HOST2="xdp-filter-test-host2"

# veth interfaces
VETH_HOST1="veth1"
VETH_HOST2="veth2"

# mac addresses
MAC_HOST1="0a:bc:de:f0:00:01"
MAC_HOST2="0a:bc:de:f0:00:02"

# vlan interfaces
VLAN_DEV=vlan0
VLAN_ID=100
VLAN_STACKED_DEV=vlan1
VLAN_STACKED_ID=200

# ipv4 addresses
IPV4_HOST1="192.168.1.1/24"
IPV4_HOST2="192.168.1.2/24"
IPV4_HOST1_VLAN="192.168.100.1/24"
IPV4_HOST2_VLAN="192.168.100.2/24"
IPV4_HOST1_VLAN_STACKED="192.168.200.1/24"
IPV4_HOST2_VLAN_STACKED="192.168.200.2/24"

# ipv6 addresses
IPV6_HOST1="fd00::1/64"
IPV6_HOST2="fd00::2/64"
IPV6_HOST1_VLAN="fd00:100::1/64"
IPV6_HOST2_VLAN="fd00:100::2/64"
IPV6_HOST1_VLAN_STACKED="fd00:200::1/64"
IPV6_HOST2_VLAN_STACKED="fd00:200::2/64"

# create testing network namespaces
function create_namespaces {
	echo "Creating testing network namespaces..."
	$IP netns add $NS_HOST1
	$IP netns add $NS_HOST2
}

# delete testing network namespaces
function delete_namespaces {
	echo "Removing testing network namespaces..."
	$IP netns delete $NS_HOST1
	$IP netns delete $NS_HOST2
}

# add veth interfaces to network namespaces
function add_veths {
	echo "Adding veth interfaces..."

	# add veth interfaces
	$IP netns exec $NS_HOST1 $IP link add $VETH_HOST1 type veth \
		peer name $VETH_HOST2

	# move second veth interface to other namespace
	$IP netns exec $NS_HOST1 $IP link set $VETH_HOST2 netns $NS_HOST2

	# set mac addresses of veth interfaces
	$IP netns exec $NS_HOST1 $IP link set $VETH_HOST1 address $MAC_HOST1
	$IP netns exec $NS_HOST2 $IP link set $VETH_HOST2 address $MAC_HOST2

	# set veth interfaces up
	$IP netns exec $NS_HOST1 $IP link set $VETH_HOST1 up
	$IP netns exec $NS_HOST2 $IP link set $VETH_HOST2 up
}

# delete veth interfaces from network namespaces
function delete_veths {
	echo "Removing veth interfaces..."
	$IP netns exec $NS_HOST1 $IP link delete $VETH_HOST1 type veth
}

# add vlan interfaces to veth interfaces
function add_vlans {
	echo "Adding vlan interfaces..."

	# add vlan interfaces to veth interfaces
	$IP netns exec $NS_HOST1 $IP link add link $VETH_HOST1 \
		name $VLAN_DEV type vlan id $VLAN_ID
	$IP netns exec $NS_HOST2 $IP link add link $VETH_HOST2 \
		name $VLAN_DEV type vlan id $VLAN_ID

	# add stacked vlan interfaces to existing vlan interfaces
	$IP netns exec $NS_HOST1 $IP link add link $VLAN_DEV \
		name $VLAN_STACKED_DEV type vlan id $VLAN_STACKED_ID
	$IP netns exec $NS_HOST2 $IP link add link $VLAN_DEV \
		name $VLAN_STACKED_DEV type vlan id $VLAN_STACKED_ID

	# set vlan interfaces up
	$IP netns exec $NS_HOST1 $IP link set $VLAN_DEV up
	$IP netns exec $NS_HOST2 $IP link set $VLAN_DEV up

	# set stacked vlan interfaces up
	$IP netns exec $NS_HOST1 $IP link set $VLAN_STACKED_DEV up
	$IP netns exec $NS_HOST2 $IP link set $VLAN_STACKED_DEV up
}

# delete vlan interfaces from veth interfaces
function delete_vlans {
	echo "Removing vlan interfaces..."

	# remove stacked vlan interfaces
	$IP netns exec $NS_HOST1 $IP link delete $VLAN_STACKED_DEV type vlan
	$IP netns exec $NS_HOST2 $IP link delete $VLAN_STACKED_DEV type vlan

	# remove vlan interfaces
	$IP netns exec $NS_HOST1 $IP link delete $VLAN_DEV type vlan
	$IP netns exec $NS_HOST2 $IP link delete $VLAN_DEV type vlan
}

# add ip addresses to veth interfaces
function add_ips {
	echo "Adding ip addresses to veth interfaces..."

	# add ipv4 addresses to veth interfaces
	$IP netns exec $NS_HOST1 $IP address add $IPV4_HOST1 dev $VETH_HOST1
	$IP netns exec $NS_HOST2 $IP address add $IPV4_HOST2 dev $VETH_HOST2

	# add ipv4 addresses to vlan interfaces
	$IP netns exec $NS_HOST1 $IP address add $IPV4_HOST1_VLAN dev $VLAN_DEV
	$IP netns exec $NS_HOST2 $IP address add $IPV4_HOST2_VLAN dev $VLAN_DEV

	# add ipv4 addresses to stacked vlan interfaces
	$IP netns exec $NS_HOST1 $IP address add $IPV4_HOST1_VLAN_STACKED \
		dev $VLAN_STACKED_DEV
	$IP netns exec $NS_HOST2 $IP address add $IPV4_HOST2_VLAN_STACKED \
		dev $VLAN_STACKED_DEV

	# add ipv6 addresses to veth interfaces
	$IP netns exec $NS_HOST1 $IP address add $IPV6_HOST1 dev $VETH_HOST1
	$IP netns exec $NS_HOST2 $IP address add $IPV6_HOST2 dev $VETH_HOST2

	# add ipv6 addresses to vlan interfaces
	$IP netns exec $NS_HOST1 $IP address add $IPV6_HOST1_VLAN dev $VLAN_DEV
	$IP netns exec $NS_HOST2 $IP address add $IPV6_HOST2_VLAN dev $VLAN_DEV

	# add ipv6 addresses to stacked vlan interfaces
	$IP netns exec $NS_HOST1 $IP address add $IPV6_HOST1_VLAN_STACKED \
		dev $VLAN_STACKED_DEV
	$IP netns exec $NS_HOST2 $IP address add $IPV6_HOST2_VLAN_STACKED \
		dev $VLAN_STACKED_DEV
}

# set everything up
function setup {
	create_namespaces
	add_veths
	add_vlans
	add_ips
}

# tear everything down
function tear_down {
	delete_vlans
	delete_veths
	delete_namespaces
}

# handle command line arguments
case $1 in
	"setup")
		setup
		;;
	"teardown")
		tear_down
		;;
	*)
		echo "$0 setup|teardown"
		;;
esac
