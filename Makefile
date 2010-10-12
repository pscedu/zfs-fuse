# $Id$

ROOTDIR=..
include ${ROOTDIR}/Makefile.path
include ${MAINMK}

clean:
	@(cd ${ZFS_BASE} && ${SCONS} ROOTDIR=${ROOTDIR} -c)

all:
	@(cd ${ZFS_BASE} && ${SCONS} ROOTDIR=${ROOTDIR} debug=4)
