#!/bin/bash

# commands
IP=/usr/bin/ip
PING=/usr/bin/ping
NC=/usr/bin/nc
KILL=/usr/bin/kill
ETHTOOL=/usr/bin/ethtool

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

# tcp/udp ports
LISTEN_PORT=1999
SOURCE_PORT1=2000
SOURCE_PORT2=2001
SOURCE_PORT3=2002
SOURCE_PORT4=2003

# udp/tcp test file
L4TESTFILE=l4test.out

# test log file
LOGFILE=test.log

# xdp files
XDP_USER_CMD="./xdp_filter_user"
XDP_OBJ_FILE="xdp_filter_kern.o"

# number of errors during testing
NUM_ERRORS=0

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

# run ip link command on host 1
function ip_link_host1 {
	$IP netns exec $NS_HOST1 $IP link "$@"
}

# run ip link command on host 2
function ip_link_host2 {
	$IP netns exec $NS_HOST2 $IP link "$@"
}

# run ethtool command on host 1
function ethtool_host1 {
	$IP netns exec $NS_HOST1 $ETHTOOL "$@"
}

# run ethtool command on host 2
function ethtool_host2 {
	$IP netns exec $NS_HOST2 $ETHTOOL "$@"
}

# add veth interfaces to network namespaces
function add_veths {
	echo "Adding veth interfaces..."

	# add veth interfaces
	ip_link_host1 add $VETH_HOST1 type veth peer name $VETH_HOST2

	# move second veth interface to other namespace
	ip_link_host1 set $VETH_HOST2 netns $NS_HOST2

	# set mac addresses of veth interfaces
	ip_link_host1 set $VETH_HOST1 address $MAC_HOST1
	ip_link_host2 set $VETH_HOST2 address $MAC_HOST2

	# set veth interfaces up
	ip_link_host1 set $VETH_HOST1 up
	ip_link_host2 set $VETH_HOST2 up

	# disable vlan offloading
	ethtool_host1 -K $VETH_HOST1 tx-vlan-offload off
	ethtool_host1 -K $VETH_HOST1 rx-vlan-offload off

	ethtool_host2 -K $VETH_HOST2 tx-vlan-offload off
	ethtool_host2 -K $VETH_HOST2 rx-vlan-offload off
}

# delete veth interfaces from network namespaces
function delete_veths {
	echo "Removing veth interfaces..."
	ip_link_host1 delete $VETH_HOST1 type veth
}

# add vlan interfaces to veth interfaces
function add_vlans {
	echo "Adding vlan interfaces..."

	# add vlan interfaces to veth interfaces
	ip_link_host1 add link $VETH_HOST1 \
		name $VLAN_DEV type vlan id $VLAN_ID
	ip_link_host2 add link $VETH_HOST2 \
		name $VLAN_DEV type vlan id $VLAN_ID

	# add stacked vlan interfaces to existing vlan interfaces
	ip_link_host1 add link $VLAN_DEV \
		name $VLAN_STACKED_DEV type vlan id $VLAN_STACKED_ID
	ip_link_host2 add link $VLAN_DEV \
		name $VLAN_STACKED_DEV type vlan id $VLAN_STACKED_ID

	# set vlan interfaces up
	ip_link_host1 set $VLAN_DEV up
	ip_link_host2 set $VLAN_DEV up

	# set stacked vlan interfaces up
	ip_link_host1 set $VLAN_STACKED_DEV up
	ip_link_host2 set $VLAN_STACKED_DEV up
}

# delete vlan interfaces from veth interfaces
function delete_vlans {
	echo "Removing vlan interfaces..."

	# remove stacked vlan interfaces
	ip_link_host1 delete $VLAN_STACKED_DEV type vlan
	ip_link_host2 delete $VLAN_STACKED_DEV type vlan

	# remove vlan interfaces
	ip_link_host1 delete $VLAN_DEV type vlan
	ip_link_host2 delete $VLAN_DEV type vlan
}

# run ip address command on host 1
function ip_addr_host1 {
	$IP netns exec $NS_HOST1 $IP address "$@"
}

# run ip address command on host 2
function ip_addr_host2 {
	$IP netns exec $NS_HOST2 $IP address "$@"
}

# add ip addresses to veth interfaces
function add_ips {
	echo "Adding ip addresses to veth interfaces..."

	# add ipv4 addresses to veth interfaces
	ip_addr_host1 add $IPV4_HOST1 dev $VETH_HOST1
	ip_addr_host2 add $IPV4_HOST2 dev $VETH_HOST2

	# add ipv4 addresses to vlan interfaces
	ip_addr_host1 add $IPV4_HOST1_VLAN dev $VLAN_DEV
	ip_addr_host2 add $IPV4_HOST2_VLAN dev $VLAN_DEV

	# add ipv4 addresses to stacked vlan interfaces
	ip_addr_host1 add $IPV4_HOST1_VLAN_STACKED dev $VLAN_STACKED_DEV
	ip_addr_host2 add $IPV4_HOST2_VLAN_STACKED dev $VLAN_STACKED_DEV

	# add ipv6 addresses to veth interfaces
	ip_addr_host1 add $IPV6_HOST1 dev $VETH_HOST1
	ip_addr_host2 add $IPV6_HOST2 dev $VETH_HOST2

	# add ipv6 addresses to vlan interfaces
	ip_addr_host1 add $IPV6_HOST1_VLAN dev $VLAN_DEV
	ip_addr_host2 add $IPV6_HOST2_VLAN dev $VLAN_DEV

	# add ipv6 addresses to stacked vlan interfaces
	ip_addr_host1 add $IPV6_HOST1_VLAN_STACKED dev $VLAN_STACKED_DEV
	ip_addr_host2 add $IPV6_HOST2_VLAN_STACKED dev $VLAN_STACKED_DEV

	# wait for ipv6 dad
	sleep 3
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
	tear_down > /dev/null 2>&1
	setup >> $LOGFILE
}

# clean up after a test run
function cleanup_test {
	tear_down >> $LOGFILE
}

# run xdp user command on host 2
function run_xdp_host2 {
	$IP netns exec $NS_HOST2 $XDP_USER_CMD "$@"
}

# ping test helper
function run_ping_test {
	local ip=$1
	local expect=$2

	# run ping test
	$IP netns exec $NS_HOST1 $PING -q -c 1 "${ip%/*}" >> $LOGFILE
	local rc=$?

	# check result and compare it with expected value
	if [[ $rc == "$expect" ]]; then
		echo "OK"
	else
		echo "ERROR"
		NUM_ERRORS=$((NUM_ERRORS + 1))
	fi
}

# udp/tcp test helper
function run_l4_test {
	local ipver=$1
	local prot=$2
	local sport=$3
	local dip=$4
	local expect=$5

	# check ip version (4 or 6) and set nc parameter
	local ipv="-4"
	if [[ $ipver == "ipv6" ]]; then
		local ipv="-6"
	fi

	# check protocol (tcp or udp) and set nc parameter
	local udp=""
	if [[ $prot == "udp" ]]; then
		local udp="-u"
	fi

	# prepare test file
	echo -n "" > $L4TESTFILE

	# start server and save pid
	$IP netns exec $NS_HOST2 \
		$NC $ipv $udp -l -p $LISTEN_PORT -k > $L4TESTFILE &
	local pid=$!
	sleep 1

	# run client
	echo "test" | $IP netns exec $NS_HOST1 \
		$NC $ipv $udp -q 1 -w 1 -p "$sport" "${dip%/*}" $LISTEN_PORT
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
		NUM_ERRORS=$((NUM_ERRORS + 1))
	fi
}

# test ethernet filtering (drop specified source macs)
function test_ethernet_drop {
	# prepare
	echo "Ethernet Drop Source MACs:"
	prepare_test

	# ping host 2 from host 1 (should work)
	echo -n "  setup: "
	run_ping_test $IPV4_HOST2 0

	# start ethernet filtering with invalid mac
	run_xdp_host2 drop-eth-src-macs $VETH_HOST2 00:00:00:00:00:00

	# ping host 2 from host 1 (should work)
	echo -n "  test pass: "
	run_ping_test $IPV4_HOST2 0

	# start ethernet filtering with valid mac
	run_xdp_host2 drop-eth-src-macs $VETH_HOST2 $MAC_HOST1

	# ping host 2 from host 1 (should not work)
	echo -n "  test drop: "
	run_ping_test $IPV4_HOST2 1

	# cleanup
	cleanup_test
}

# test vlan filtering
function test_vlan {
	# prepare
	echo "VLAN:"
	prepare_test

	# ping host 2 from host 1 (should work)
	echo -n "  setup: "
	run_ping_test $IPV4_HOST2_VLAN 0
	echo -n "  stacked setup: "
	run_ping_test $IPV4_HOST2_VLAN_STACKED 0

	# start vlan filtering
	run_xdp_host2 vlan $VETH_HOST2 $VLAN_ID $VLAN_STACKED_ID

	# ping host 2 from host 1 (should not work)
	echo -n "  test: "
	run_ping_test $IPV4_HOST2_VLAN 1
	echo -n "  stacked test: "
	run_ping_test $IPV4_HOST2_VLAN_STACKED 1

	# cleanup
	cleanup_test
}

# test ipv4 filtering
function test_ipv4 {
	# prepare
	echo "IPv4:"
	prepare_test

	# ping host 2 from host 1 (should work)
	echo -n "  setup: "
	run_ping_test $IPV4_HOST2 0

	# start ipv4 filtering
	run_xdp_host2 ipv4 $VETH_HOST2 ${IPV4_HOST1%/*}

	# ping host 2 from host 1 (should not work)
	echo -n "  test: "
	run_ping_test $IPV4_HOST2 1

	# cleanup
	cleanup_test
}

# test ipv6 filtering
function test_ipv6 {
	# prepare
	echo "IPv6:"
	prepare_test

	# ping host 2 from host 1 (should work)
	echo -n "  setup: "
	run_ping_test $IPV6_HOST2 0

	# start ipv6 filtering
	run_xdp_host2 ipv6 $VETH_HOST2 ${IPV6_HOST1%/*}

	# ping host 2 from host 1 (should not work)
	echo -n "  test: "
	run_ping_test $IPV6_HOST2 1

	# cleanup
	cleanup_test
}

# test udp filtering
function test_udp {
	# prepare
	echo "UDP:"
	prepare_test

	# test connection to host 2 from host 1 (should work)
	echo -n "  ipv4 setup: "
	run_l4_test ipv4 udp $SOURCE_PORT1 $IPV4_HOST2 0
	echo -n "  ipv6 setup: "
	run_l4_test ipv6 udp $SOURCE_PORT2 $IPV6_HOST2 0

	# start udp filtering
	run_xdp_host2 udp $VETH_HOST2 \
		$SOURCE_PORT1 $SOURCE_PORT2 $SOURCE_PORT3 $SOURCE_PORT4

	# test connection to host 2 from host 1 (should not work)
	echo -n "  ipv4 test: "
	run_l4_test ipv4 udp $SOURCE_PORT3 $IPV4_HOST2 1
	echo -n "  ipv6 test: "
	run_l4_test ipv6 udp $SOURCE_PORT4 $IPV6_HOST2 1

	# cleanup
	cleanup_test
}

# test tcp filtering
function test_tcp {
	# prepare
	echo "TCP:"
	prepare_test

	# test connection to host 2 from host 1 (should work)
	echo -n "  ipv4 setup: "
	run_l4_test ipv4 tcp $SOURCE_PORT1 $IPV4_HOST2 0
	echo -n "  ipv6 setup: "
	run_l4_test ipv6 tcp $SOURCE_PORT2 $IPV6_HOST2 0

	# start udp filtering
	run_xdp_host2 tcp $VETH_HOST2 \
		$SOURCE_PORT1 $SOURCE_PORT2 $SOURCE_PORT3 $SOURCE_PORT4

	# test connection to host 2 from host 1 (should not work)
	echo -n "  ipv4 test: "
	run_l4_test ipv4 tcp $SOURCE_PORT3 $IPV4_HOST2 1
	echo -n "  ipv4 test: "
	run_l4_test ipv6 tcp $SOURCE_PORT4 $IPV6_HOST2 1

	# cleanup
	cleanup_test
}

# run all tests
function test_all {
	# print to stdout and append output to log file
	exec &> >(tee -a "$LOGFILE")

	# tests
	test_ethernet_drop
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
	"ethernet_drop")
		test_ethernet_drop
		;;
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
		echo "Usage:"
		echo "$0 setup|teardown|loadall"
		echo "$0 vlan|ipv4|ipv6|udp|tcp|all"
		echo "$0 ethernet_drop"
		exit 1
		;;
esac

# print summary and return number of errors
echo ""
echo "Number of errors: $NUM_ERRORS"
exit $NUM_ERRORS
