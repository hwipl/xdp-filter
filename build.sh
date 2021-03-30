#!/bin/bash

clang -O2 -emit-llvm -c xdp_filter_kern.c -o - -fno-stack-protector |
	llc -march=bpf -filetype=obj -o xdp_filter_kern.o
clang xdp_filter_user.c -o xdp_filter_user -l bpf
