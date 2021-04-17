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

# invalid vlan id (not equal to any other id above) for testing
VLAN_ID_INVALID=4095

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
mapfile -t SOURCE_PORTS < <(seq 2000 2017)

# invalid port (not equal to any other id above) for testing
SOURCE_PORT_INVALID=1

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

# run ip neighbor command on host 1
function ip_neigh_host1 {
	$IP netns exec $NS_HOST1 $IP neighbor "$@"
}

# run ip neighbor command on host 2
function ip_neigh_host2 {
	$IP netns exec $NS_HOST2 $IP neighbor "$@"
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

	# add veth peer ipv4 addresses to neighbor caches
	ip_neigh_host1 add ${IPV4_HOST2%/*} lladdr $MAC_HOST2 dev $VETH_HOST1
	ip_neigh_host2 add ${IPV4_HOST1%/*} lladdr $MAC_HOST1 dev $VETH_HOST2

	# add vlan peer ipv4 addresses to neighbor caches
	ip_neigh_host1 add ${IPV4_HOST2_VLAN%/*} lladdr $MAC_HOST2 \
		dev $VLAN_DEV
	ip_neigh_host2 add ${IPV4_HOST1_VLAN%/*} lladdr $MAC_HOST1 \
		dev $VLAN_DEV

	# add stacked vlan peer ipv4 addresses to neighbor caches
	ip_neigh_host1 add ${IPV4_HOST2_VLAN_STACKED%/*} lladdr $MAC_HOST2 \
		dev $VLAN_STACKED_DEV
	ip_neigh_host2 add ${IPV4_HOST1_VLAN_STACKED%/*} lladdr $MAC_HOST1 \
		dev $VLAN_STACKED_DEV

	# add veth peer ipv6 addresses to neighbor caches
	ip_neigh_host1 add ${IPV6_HOST2%/*} lladdr $MAC_HOST2 dev $VETH_HOST1
	ip_neigh_host2 add ${IPV6_HOST1%/*} lladdr $MAC_HOST1 dev $VETH_HOST2

	# add vlan peer ipv6 addresses to neighbor caches
	ip_neigh_host1 add ${IPV6_HOST2_VLAN%/*} lladdr $MAC_HOST2 \
		dev $VLAN_DEV
	ip_neigh_host2 add ${IPV6_HOST1_VLAN%/*} lladdr $MAC_HOST1 \
		dev $VLAN_DEV

	# add stacked vlan peer ipv6 addresses to neighbor caches
	ip_neigh_host1 add ${IPV6_HOST2_VLAN_STACKED%/*} lladdr $MAC_HOST2 \
		dev $VLAN_STACKED_DEV
	ip_neigh_host2 add ${IPV6_HOST1_VLAN_STACKED%/*} lladdr $MAC_HOST1 \
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
	tear_down > /dev/null 2>&1
	setup >> $LOGFILE
}

# clean up after a test run
function cleanup_test {
	tear_down >> $LOGFILE
}

# run xdp user command on host 2
function run_xdp_host2 {
	if ! $IP netns exec $NS_HOST2 $XDP_USER_CMD "$@"; then
		NUM_ERRORS=$((NUM_ERRORS + 1))
	fi
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

# drop or pass? set expected test result and its string representation
function set_drop_or_pass {
	TEST_RESULT=(1 0)
	TEST_STRING=("drop" "pass")
	if [[ $1 == "drop" ]]; then
		TEST_RESULT=(0 1)
		TEST_STRING=("pass" "drop")
	fi
}

# test ethernet filtering, $1 specifies "drop" or "pass" test
function test_ethernet {
	# get expected test result and its string representation
	set_drop_or_pass "$1"

	# prepare
	prepare_test

	# ping host 2 from host 1 (should work)
	echo -n "  setup: "
	run_ping_test $IPV4_HOST2 0

	# start ethernet filtering with invalid mac
	run_xdp_host2 "$1-eth-src" $VETH_HOST2 00:00:00:00:00:00

	# ping host 2 from host 1 and check expected result
	echo -n "  test ${TEST_STRING[0]}: "
	run_ping_test $IPV4_HOST2 "${TEST_RESULT[0]}"

	# start ethernet filtering with valid mac
	run_xdp_host2 "$1-eth-src" $VETH_HOST2 $MAC_HOST1

	# ping host 2 from host 1 and check expected result
	echo -n "  test ${TEST_STRING[1]}: "
	run_ping_test $IPV4_HOST2 "${TEST_RESULT[1]}"

	# cleanup
	cleanup_test
}

# test ethernet filtering (drop specified source macs)
function test_ethernet_drop {
	echo "Ethernet Drop Source MACs:"
	test_ethernet drop
}

# test ethernet filtering (pass specified source macs)
function test_ethernet_pass {
	echo "Ethernet Pass Source MACs:"
	test_ethernet pass
}

# test vlan filtering, $1 specifies "drop" or "pass"
function test_vlan {
	# get expected test result and its string representation
	set_drop_or_pass "$1"

	# prepare
	prepare_test

	# ping host 2 from host 1 (should work)
	echo -n "  setup: "
	run_ping_test $IPV4_HOST2_VLAN 0
	echo -n "  stacked setup: "
	run_ping_test $IPV4_HOST2_VLAN_STACKED 0

	# start vlan filtering with invalid vlan ids
	run_xdp_host2 "$1-vlan" $VETH_HOST2 $VLAN_ID_INVALID

	# ping host 2 from host 1 and check expected result
	echo -n "  test ${TEST_STRING[0]}: "
	run_ping_test $IPV4_HOST2_VLAN "${TEST_RESULT[0]}"
	echo -n "  stacked test ${TEST_STRING[0]}: "
	run_ping_test $IPV4_HOST2_VLAN_STACKED "${TEST_RESULT[0]}"

	# start vlan filtering with valid vlan ids
	run_xdp_host2 "$1-vlan" $VETH_HOST2 $VLAN_ID $VLAN_STACKED_ID

	# ping host 2 from host 1 and check expected result
	echo -n "  test ${TEST_STRING[1]}: "
	run_ping_test $IPV4_HOST2_VLAN "${TEST_RESULT[1]}"
	echo -n "  stacked test ${TEST_STRING[1]}: "
	run_ping_test $IPV4_HOST2_VLAN_STACKED "${TEST_RESULT[1]}"

	# cleanup
	cleanup_test
}
# test vlan filtering (drop specified vlan ids)
function test_vlan_drop {
	echo "VLAN Drop VLAN IDs:"
	test_vlan drop
}

# test vlan filtering (pass specified vlan ids)
function test_vlan_pass {
	echo "VLAN Pass VLAN IDs:"
	test_vlan pass
}

# test ipv4 filtering, $1 speciefies "drop" or "pass" test
function test_ipv4 {
	# get expected test result and its string representation
	set_drop_or_pass "$1"

	# prepare
	prepare_test

	# ping host 2 from host 1 (should work)
	echo -n "  setup: "
	run_ping_test $IPV4_HOST2 0
	echo -n "  setup vlan: "
	run_ping_test $IPV4_HOST2_VLAN 0
	echo -n "  setup vlan stacked: "
	run_ping_test $IPV4_HOST2_VLAN_STACKED 0

	# start ipv4 filtering with invalid ip address
	run_xdp_host2 "$1-ipv4-src" $VETH_HOST2 0.0.0.0

	# ping host 2 from host 1 and check expected result
	echo -n "  test ${TEST_STRING[0]}: "
	run_ping_test $IPV4_HOST2 "${TEST_RESULT[0]}"
	echo -n "  test ${TEST_STRING[0]} vlan: "
	run_ping_test $IPV4_HOST2_VLAN "${TEST_RESULT[0]}"
	echo -n "  test ${TEST_STRING[0]} vlan stacked: "
	run_ping_test $IPV4_HOST2_VLAN_STACKED "${TEST_RESULT[0]}"

	# start ipv4 filtering with valid ip address
	run_xdp_host2 "$1-ipv4-src" $VETH_HOST2 ${IPV4_HOST1%/*} \
		${IPV4_HOST1_VLAN%/*} ${IPV4_HOST1_VLAN_STACKED%/*}

	# ping host 2 from host 1 and check expected result
	echo -n "  test ${TEST_STRING[1]}: "
	run_ping_test $IPV4_HOST2 "${TEST_RESULT[1]}"
	echo -n "  test ${TEST_STRING[1]} vlan: "
	run_ping_test $IPV4_HOST2_VLAN "${TEST_RESULT[1]}"
	echo -n "  test ${TEST_STRING[1]} vlan stacked: "
	run_ping_test $IPV4_HOST2_VLAN_STACKED "${TEST_RESULT[1]}"

	# cleanup
	cleanup_test
}

# test ipv4 filtering (drop specified ipv4 source addresses)
function test_ipv4_drop {
	echo "IPv4 Drop Source IP Addresses:"
	test_ipv4 drop
}

# test ipv4 filtering (pass specified ipv4 source addresses)
function test_ipv4_pass {
	echo "IPv4 Pass Source IP Addresses:"
	test_ipv4 pass
}

# test ipv6 filtering, $1 specifies "drop" or "pass" test
function test_ipv6 {
	# get expected test result and its string representation
	set_drop_or_pass "$1"

	# prepare
	prepare_test

	# ping host 2 from host 1 (should work)
	echo -n "  setup: "
	run_ping_test $IPV6_HOST2 0
	echo -n "  setup vlan: "
	run_ping_test $IPV6_HOST2_VLAN 0
	echo -n "  setup vlan stacked: "
	run_ping_test $IPV6_HOST2_VLAN_STACKED 0

	# start ipv6 filtering with invalid ip address
	run_xdp_host2 "$1-ipv6-src" $VETH_HOST2 ::

	# ping host 2 from host 1 and check expected result
	echo -n "  test ${TEST_STRING[0]}: "
	run_ping_test $IPV6_HOST2 "${TEST_RESULT[0]}"
	echo -n "  test ${TEST_STRING[0]} vlan: "
	run_ping_test $IPV6_HOST2_VLAN "${TEST_RESULT[0]}"
	echo -n "  test ${TEST_STRING[0]} vlan stacked: "
	run_ping_test $IPV6_HOST2_VLAN_STACKED "${TEST_RESULT[0]}"

	# start ipv6 filtering with valid ip address
	run_xdp_host2 "$1-ipv6-src" $VETH_HOST2 ${IPV6_HOST1%/*} \
		${IPV6_HOST1_VLAN%/*} ${IPV6_HOST1_VLAN_STACKED%/*}

	# ping host 2 from host 1 and check expected result
	echo -n "  test ${TEST_STRING[1]}: "
	run_ping_test $IPV6_HOST2 "${TEST_RESULT[1]}"
	echo -n "  test ${TEST_STRING[1]} vlan: "
	run_ping_test $IPV6_HOST2_VLAN "${TEST_RESULT[1]}"
	echo -n "  test ${TEST_STRING[1]} vlan stacked: "
	run_ping_test $IPV6_HOST2_VLAN_STACKED "${TEST_RESULT[1]}"

	# cleanup
	cleanup_test
}
# test ipv6 filtering (drop specified ipv6 source addresses)
function test_ipv6_drop {
	echo "IPv6 Drop Source IP Addresses:"
	test_ipv6 drop
}

# test ipv6 filtering (pass specified ipv6 source addresses)
function test_ipv6_pass {
	echo "IPv6 Pass Source IP Addresses:"
	test_ipv6 pass
}

# test udp/tcp filtering, $1 speciefies "drop" or "pass" test, $2 specifies
# "udp" or "tcp" test
function test_l4 {
	# get expected test result and its string representation
	set_drop_or_pass "$1"

	# prepare
	prepare_test

	# test connection to host 2 from host 1 (should work)
	echo -n "  ipv4 setup: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[0]}" $IPV4_HOST2 0
	echo -n "  ipv4 setup vlan: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[1]}" $IPV4_HOST2_VLAN 0
	echo -n "  ipv4 setup vlan stacked: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[2]}" $IPV4_HOST2_VLAN_STACKED 0
	echo -n "  ipv6 setup: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[3]}" $IPV6_HOST2 0
	echo -n "  ipv6 setup vlan: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[4]}" $IPV6_HOST2_VLAN 0
	echo -n "  ipv6 setup vlan stacked: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[5]}" $IPV6_HOST2_VLAN_STACKED 0

	# start filtering with invalid port
	run_xdp_host2 "$1-$2-src" $VETH_HOST2 $SOURCE_PORT_INVALID

	# test connection to host 2 from host 1 and check expected result
	echo -n "  ipv4 test ${TEST_STRING[0]}: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[6]}" $IPV4_HOST2 \
		"${TEST_RESULT[0]}"
	echo -n "  ipv4 test ${TEST_STRING[0]} vlan: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[7]}" $IPV4_HOST2_VLAN \
		"${TEST_RESULT[0]}"
	echo -n "  ipv4 test ${TEST_STRING[0]} vlan stacked: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[8]}" $IPV4_HOST2_VLAN_STACKED \
		"${TEST_RESULT[0]}"
	echo -n "  ipv6 test ${TEST_STRING[0]}: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[9]}" $IPV6_HOST2 \
		"${TEST_RESULT[0]}"
	echo -n "  ipv6 test ${TEST_STRING[0]} vlan: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[10]}" $IPV6_HOST2_VLAN \
		"${TEST_RESULT[0]}"
	echo -n "  ipv6 test ${TEST_STRING[0]} vlan stacked: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[11]}" $IPV6_HOST2_VLAN_STACKED \
		"${TEST_RESULT[0]}"

	# start filtering with valid ports
	run_xdp_host2 "$1-$2-src" $VETH_HOST2 "${SOURCE_PORTS[@]}"

	# test connection to host 2 from host 1 and check expected result
	echo -n "  ipv4 test ${TEST_STRING[1]}: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[12]}" $IPV4_HOST2 \
		"${TEST_RESULT[1]}"
	echo -n "  ipv4 test ${TEST_STRING[1]} vlan: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[13]}" $IPV4_HOST2_VLAN \
		"${TEST_RESULT[1]}"
	echo -n "  ipv4 test ${TEST_STRING[1]} vlan stacked: "
	run_l4_test ipv4 "$2" "${SOURCE_PORTS[14]}" $IPV4_HOST2_VLAN_STACKED \
		"${TEST_RESULT[1]}"
	echo -n "  ipv6 test ${TEST_STRING[1]}: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[15]}" $IPV6_HOST2 \
		"${TEST_RESULT[1]}"
	echo -n "  ipv6 test ${TEST_STRING[1]} vlan: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[16]}" $IPV6_HOST2_VLAN \
		"${TEST_RESULT[1]}"
	echo -n "  ipv6 test ${TEST_STRING[1]} vlan stacked: "
	run_l4_test ipv6 "$2" "${SOURCE_PORTS[17]}" $IPV6_HOST2_VLAN_STACKED \
		"${TEST_RESULT[1]}"

	# cleanup
	cleanup_test
}

# test udp filtering (drop specified udp source ports)
function test_udp_drop {
	echo "UDP Drop Source Ports:"
	test_l4 drop udp
}

# test udp filtering (pass specified udp source ports)
function test_udp_pass {
	echo "UDP Pass Source Ports:"
	test_l4 pass udp
}

# test tcp filtering (drop specified tcp source ports)
function test_tcp_drop {
	echo "TCP Drop Source Ports:"
	test_l4 drop tcp
}

# test tcp filtering (pass specified tcp source ports)
function test_tcp_pass {
	echo "TCP Pass Source Ports:"
	test_l4 pass tcp
}

# run all tests
function test_all {
	# print to stdout and append output to log file
	exec &> >(tee -a "$LOGFILE")

	# tests
	test_ethernet_drop
	test_ethernet_pass
	test_vlan_drop
	test_vlan_pass
	test_ipv4_drop
	test_ipv4_pass
	test_ipv6_drop
	test_ipv6_pass
	test_udp_drop
	test_udp_pass
	test_tcp_drop
	test_tcp_pass
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
	"ethernet_pass")
		test_ethernet_pass
		;;
	"vlan_drop")
		test_vlan_drop
		;;
	"vlan_pass")
		test_vlan_pass
		;;
	"ipv4_drop")
		test_ipv4_drop
		;;
	"ipv4_pass")
		test_ipv4_pass
		;;
	"ipv6_drop")
		test_ipv6_drop
		;;
	"ipv6_pass")
		test_ipv6_pass
		;;
	"udp_drop")
		test_udp_drop
		;;
	"udp_pass")
		test_udp_pass
		;;
	"tcp_drop")
		test_tcp_drop
		;;
	"tcp_pass")
		test_tcp_pass
		;;
	"all")
		test_all
		;;
	*)
		echo "Usage:"
		echo "$0 setup|teardown|loadall"
		echo "$0 ethernet_drop|vlan_drop|ipv4_drop|ipv6_drop|udp_drop|tcp_drop"
		echo "$0 ethernet_pass|vlan_pass|ipv4_pass|ipv6_pass|udp_pass|tcp_pass"
		echo "$0 all"
		exit 1
		;;
esac

# print summary and return number of errors
echo ""
echo "Number of errors: $NUM_ERRORS"
exit $NUM_ERRORS
