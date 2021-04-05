#!/bin/bash

# commands
IP=/usr/bin/ip
PING=/usr/bin/ping
NC=/usr/bin/nc
KILL=/usr/bin/kill

# build command
BUILD="./build.sh"

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

# tcp/udp port
PORT=2000

# udp/tcp test file
L4TESTFILE=l4test.out

# xdp files
XDP_USER_CMD="./xdp_filter_user"
XDP_OBJ_FILE="xdp_filter_kern.o"

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

# unload current xdp program
function unload_xdp {
	$IP netns exec $NS_HOST2 $XDP_USER_CMD unload $VETH_HOST2
}

# load a single xdp program
function load_xdp {
	local section=$1
	unload_xdp
	$IP netns exec $NS_HOST2 \
		$XDP_USER_CMD load $XDP_OBJ_FILE "$section" $VETH_HOST2
}

# (un)load all xdp programs
function load_all {
	load_xdp "filter_ethernet"
	load_xdp "filter_vlan"
	load_xdp "filter_ipv4"
	load_xdp "filter_ipv6"
	load_xdp "filter_udp"
	load_xdp "filter_tcp"
	unload_xdp
}

# prepare everything for a test run
function prepare_test {
	# build everything
	$BUILD

	# clean up old setup and setup everything
	tear_down 2> /dev/null
	setup
}

# ping test helper
function test_ping {
	local ip=$1
	local expect=$2

	# run ping test
	$IP netns exec $NS_HOST1 $PING -q -c 1 "${ip%/*}" > /dev/null
	local rc=$?

	# check result and compare it with expected value
	if [[ $rc == "$expect" ]]; then
		echo "OK"
	else
		echo "ERROR"
	fi
}

# test ethernet filtering
function test_ethernet {
	# prepare
	prepare_test

	# ping host 2 from host 1 (should work)
	test_ping $IPV4_HOST2 0

	# start ethernet filtering
	$IP netns exec $NS_HOST2 \
		$XDP_USER_CMD ethernet $VETH_HOST2 $MAC_HOST1

	# ping host 2 from host 1 (should not work)
	test_ping $IPV4_HOST2 1

	# cleanup
	tear_down
}

# test vlan filtering
function test_vlan {
	# prepare
	prepare_test

	# ping host 2 from host 1 (should work)
	test_ping $IPV4_HOST2_VLAN 0
	test_ping $IPV4_HOST2_VLAN_STACKED 0

	# start vlan filtering
	$IP netns exec $NS_HOST2 \
		$XDP_USER_CMD vlan $VETH_HOST2 $VLAN_ID $VLAN_STACKED_ID

	# ping host 2 from host 1 (should not work)
	test_ping $IPV4_HOST2_VLAN 1
	test_ping $IPV4_HOST2_VLAN_STACKED 1

	# cleanup
	tear_down
}

# test ipv4 filtering
function test_ipv4 {
	# prepare
	prepare_test

	# ping host 2 from host 1 (should work)
	test_ping $IPV4_HOST2 0

	# start ipv4 filtering
	$IP netns exec $NS_HOST2 \
		$XDP_USER_CMD ipv4 $VETH_HOST2 ${IPV4_HOST1%/*}

	# ping host 2 from host 1 (should not work)
	test_ping $IPV4_HOST2 1

	# cleanup
	tear_down
}

# test ipv6 filtering
function test_ipv6 {
	# prepare
	prepare_test

	# wait for dad
	sleep 3

	# ping host 2 from host 1 (should work)
	test_ping $IPV6_HOST2 0

	# start ipv6 filtering
	$IP netns exec $NS_HOST2 \
		$XDP_USER_CMD ipv6 $VETH_HOST2 ${IPV6_HOST1%/*}

	# ping host 2 from host 1 (should not work)
	test_ping $IPV6_HOST2 1

	# cleanup
	tear_down
}

# udp test helper
function run_udp {
	local sport=$1
	local expect=$2

	# prepare test file
	echo -n "" > $L4TESTFILE

	# start server and save pid
	$IP netns exec $NS_HOST2 $NC -l -p $PORT -k -u > $L4TESTFILE &
	local pid=$!
	sleep 1

	# run client
	echo "test" | $IP netns exec $NS_HOST1 \
		$NC -4u -q 1 -w 1 -p "$sport" ${IPV4_HOST2%/*} $PORT
	sleep 1

	# kill server
	$IP netns exec $NS_HOST2 $KILL $pid
	sleep 1

	# check result
	local result=1
	if [[ $(cat $L4TESTFILE) == "test" ]]; then
		local result=0
	fi

	# compare result with expected value
	if [[ $result == "$expect" ]]; then
		echo "OK"
	else
		echo "ERROR"
	fi
}

# tcp test helper
function run_tcp {
	local sport=$1
	local expect=$2

	# start server and save pid
	$IP netns exec $NS_HOST2 $NC -l -p $PORT -k > /dev/null &
	local pid=$!

	# start client and save result
	$IP netns exec $NS_HOST1 \
		$NC -4vz -p "$sport" -w 3 ${IPV4_HOST2%/*} $PORT
	local rc=$?

	# kill server
	$IP netns exec $NS_HOST2 $KILL $pid

	# check result and compare it with expected value
	if [[ $rc == "$expect" ]]; then
		echo "OK"
	else
		echo "ERROR: $rc"
	fi
}

# test udp filtering
function test_udp {
	# prepare
	prepare_test

	# test connection to host 2 from host 1 (should work)
	run_udp $((PORT-1)) 0

	# start udp filtering
	$IP netns exec $NS_HOST2 $XDP_USER_CMD udp $VETH_HOST2 $PORT

	# test connection to host 2 from host 1 (should not work)
	run_udp $PORT 1

	# cleanup
	tear_down
}

# test tcp filtering
function test_tcp {
	# prepare
	prepare_test

	# test connection to host 2 from host 1 (should work)
	run_tcp $((PORT-1)) 0

	# start udp filtering
	$IP netns exec $NS_HOST2 $XDP_USER_CMD tcp $VETH_HOST2 $PORT

	# test connection to host 2 from host 1 (should not work)
	run_tcp $PORT 1

	# cleanup
	tear_down
}

# run all tests
function test_all {
	test_ethernet
	test_vlan
	test_ipv4
	test_ipv6
	test_udp
	test_tcp
}

# handle command line arguments
case $1 in
	"setup")
		setup
		;;
	"teardown")
		tear_down
		;;
	"loadall")
		load_all
		;;
	"ethernet")
		test_ethernet
		;;
	"vlan")
		test_vlan
		;;
	"ipv4")
		test_ipv4
		;;
	"ipv6")
		test_ipv6
		;;
	"udp")
		test_udp
		;;
	"tcp")
		test_tcp
		;;
	"all")
		test_all
		;;
	*)
		echo "$0 setup|teardown|loadall|ethernet|vlan"
		;;
esac
