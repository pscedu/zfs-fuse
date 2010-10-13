# $Id$

ROOTDIR=..
include ${ROOTDIR}/Makefile.path
include ${MAINMK}

clean-hook:
	@(cd ${ZFS_BASE} && ${SCONS} ROOTDIR=${ROOTDIR}/.. -c)

all-hook:
	@(cd ${ZFS_BASE} && ${SCONS} ROOTDIR=${ROOTDIR}/.. debug=4)
