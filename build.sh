#!/bin/bash

clang -O2 -emit-llvm -c xdp_filter_kern.c -o - -fno-stack-protector |
	llc -march=bpf -filetype=obj -o xdp_filter_kern.o
