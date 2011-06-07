# $Id$

ROOTDIR=..
include ${ROOTDIR}/Makefile.path
include ${MAINMK}

clean-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. -c)

all-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. debug=2)

install-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. debug=2 install	\
	    install_dir=${INST_SBINDIR}					\
	    man_dir=${INST_MANDIR}					\
	    cfg_dir=${INST_ETCDIR})
