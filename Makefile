# $Id$

ROOTDIR=..
include ${ROOTDIR}/Makefile.path
include ${MAINMK}

clean-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. -c)

all-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. debug=4)

install-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. debug=4 install)
