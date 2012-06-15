#!/bin/sh
# $Id$

usage()
{
	echo "usage: $0 [-c coresiz]" >&2
	exit 1
}

core=unlimited
fl=

while getopts "c:x" c; do
	case $c in
	c) core=$OPTARG	;;
	x) fl=-x	;;
	*) usage	;;
	esac
done

shift $(($OPTIND - 1))

if [ $# -ne 0 ]; then
	usage
fi

dir=$(dirname $0)

ulimit -c $core

exec $dir/zfs-fuse $fl --no-daemon
