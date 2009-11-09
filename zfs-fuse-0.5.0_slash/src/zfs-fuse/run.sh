#!/bin/sh
# $Id$

usage()
{
	echo "usage: $0 [-c coresiz]" >&2
	exit 1
}

core=unlimited

while getopts "c:" c; do
	case $c in
	c) core=$OPTARG;;
	*) usage;;
	esac
done

dir=$(dirname $0)

ulimit -c $core

$dir/zfs-fuse --no-daemon
