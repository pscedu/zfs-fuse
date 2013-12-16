# $Id$

ROOTDIR=..
include ${ROOTDIR}/Makefile.path

MODULES+=	pthread
FORCE_TAGS=	1

include ${MAINMK}

DBGLVL=2

clean-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. -c)

all-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. debug=${DBGLVL})

install-hook:
	@(cd src && ${SCONS} ROOTDIR=${ROOTDIR}/.. debug=${DBGLVL} install	\
	    install_dir=${INST_SBINDIR}						\
	    man_dir=${INST_MANDIR}/man8						\
	    cfg_dir=${INST_ETCDIR})
