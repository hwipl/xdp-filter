#!/bin/bash

# commands
IP=/usr/bin/ip

# name of network namespaces
NS_HOST1="xdp-filter-test-host1"
NS_HOST2="xdp-filter-test-host2"

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
	$IP netns exec $NS_HOST1 $IP link add veth1 type veth peer name veth2

	$IP netns exec $NS_HOST1 $IP link set veth2 netns $NS_HOST2

	$IP netns exec $NS_HOST1 $IP link set veth1 up
	$IP netns exec $NS_HOST2 $IP link set veth2 up
}

# delete veth interfaces from network namespaces
function delete_veths {
	echo "Removing veth interfaces..."
	$IP netns exec $NS_HOST1 $IP link delete veth1 type veth
}

# add ip addresses to veth interfaces
function add_ips {
	echo "Adding ip addresses to veth interfaces..."
	$IP netns exec $NS_HOST1 $IP address add 192.168.1.1/24 dev veth1
	$IP netns exec $NS_HOST2 $IP address add 192.168.1.2/24 dev veth2
}

# set everything up
function setup {
	create_namespaces
	add_veths
	add_ips
}

# tear everything down
function tear_down {
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
