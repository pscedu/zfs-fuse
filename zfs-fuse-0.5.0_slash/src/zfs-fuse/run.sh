#!/bin/sh

dir=$(dirname $0)

ulimit -c unlimited

echo $dir/zfs-fuse --no-daemon
