#!/bin/sh
# $Id$

dir=$(dirname $0)

ulimit -c unlimited

$dir/zfs-fuse --no-daemon
