/* $Id$ */

/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Ricardo Correia.
 * Portions Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#define PSC_SUBSYS SLMSS_ZFS
#include "slashd/subsys_mds.h"

#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/cred_impl.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/mode.h>
#include <sys/xattr.h>
#include <sys/fcntl.h>
#include <sys/dmu_objset.h>

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "errno_compat.h"
#include "util.h"

#include <umem.h>

#include "zfs_slashlib.h"

#include "pfl/fs.h"

#include "creds.h"
#include "fid.h"
#include "pathnames.h"
#include "slashrpc.h"
#include "slerr.h"
#include "sltypes.h"

#include "slashd/inode.h"
#include "slashd/mdsio.h"

kmem_cache_t		*file_info_cache;
int			 stack_size;
static cred_t		 zrootcreds;

static uint64_t        *immnsIdCache[MAX_FILESYSTEMS];
static uint64_t         slz_immns_id_mask;

/* flags for zfsslash2_fidlink() */
#define	FIDLINK_CREATE		(1 << 0)
#define	FIDLINK_LOOKUP		(1 << 1)
#define	FIDLINK_REMOVE		(1 << 2)
#define	FIDLINK_DIR		(1 << 3)

/**
 * get_vnode_fids - Get SLASH2 FID + generation (external) and the
 *	ZFS/MDSIO layer inum "fid" (internal) for a vnode.
 */
static __inline void
get_vnode_fids(int vfsid, const vnode_t *vp, struct sl_fidgen *fgp,
    mdsio_fid_t *mfp)
{
	if (fgp) {
		if (VTOZ(vp)->z_id == MDSIO_FID_ROOT) {
			fgp->fg_fid = SLFID_ROOT;
#if 0
			FID_SET_SITEID(fgp->fg_fid,
			    zfs_mounts[vfsid].zm_siteid);
#endif
		} else
			fgp->fg_fid = VTOZ(vp)->z_phys->zp_s2fid;
		fgp->fg_gen = VTOZ(vp)->z_phys->zp_s2gen;
	}
	if (mfp)
		*mfp = VTOZ(vp)->z_id;
}

#define ZFS_INIT_CREDS(slcrp)	{ (slcrp)->scr_uid, (slcrp)->scr_gid, NULL }

static size_t
add_dirent(char *buf, size_t bufsize, const char *name,
    const struct stat *stbuf, off_t off)
{
	size_t entsize, namelen = strlen(name);

	entsize = PFL_DIRENT_SIZE(namelen);
	if (entsize <= bufsize && buf) {
		unsigned entlen = PFL_DIRENT_NAME_OFFSET + namelen;
		unsigned padlen = entsize - entlen;
		struct pscfs_dirent *dirent = (struct pscfs_dirent *)buf;

		dirent->pfd_ino = stbuf->st_ino;
		dirent->pfd_off = off;
		dirent->pfd_namelen = namelen;
		dirent->pfd_type = (stbuf->st_mode & 0170000) >> 12;
		strncpy(dirent->pfd_name, name, namelen);
		if (padlen)
			memset(buf + entlen, 0, padlen);
	}
	return (entsize);
}

static __inline int
hide_vnode(vnode_t *dvp, vnode_t *vp, const char *cpn)
{
	if (FID_GET_FLAGS(VTOZ(vp)->z_phys->zp_s2fid) &
	    SLFIDF_HIDE_DENTRY)
		return (1);

	if (VTOZ(dvp)->z_id == MDSIO_FID_ROOT &&
	    strcmp(cpn, SL_RPATH_META_DIR) == 0)
		return (1);
	return (0);
}

int
zfsslash2_setattrmask_2_slflags(uint mask)
{
	int to_set = 0;

	if (mask & AT_SLASH2SIZE)
		to_set |= PSCFS_SETATTRF_DATASIZE;
	if (mask & AT_PTRUNCGEN)
		to_set |= SL_SETATTRF_PTRUNCGEN;
	if (mask & AT_SLASH2NBLKS)
		to_set |= SL_SETATTRF_NBLKS;
	if (mask & AT_SLASH2ATIME)
		to_set |= PSCFS_SETATTRF_ATIME;
	if (mask & AT_SLASH2MTIME)
		to_set |= PSCFS_SETATTRF_MTIME;
	if (mask & AT_SLASH2CTIME)
		to_set |= PSCFS_SETATTRF_CTIME;
	if (mask & AT_SLASH2GEN)
		to_set |= SL_SETATTRF_GEN;
	return (to_set);
}

uint
zfsslash2_slflags_2_setattrmask(int to_set)
{
	uint mask = 0;

	if (to_set & PSCFS_SETATTRF_UID)
		mask |= AT_UID;
	if (to_set & PSCFS_SETATTRF_GID)
		mask |= AT_GID;
	if (to_set & PSCFS_SETATTRF_DATASIZE)
		mask |= AT_SLASH2SIZE;
	if (to_set & SL_SETATTRF_PTRUNCGEN)
		mask |= AT_PTRUNCGEN;
	if (to_set & SL_SETATTRF_NBLKS)
		mask |= AT_SLASH2NBLKS;
	if (to_set & PSCFS_SETATTRF_ATIME)
		mask |= AT_SLASH2ATIME;
	if (to_set & PSCFS_SETATTRF_MTIME)
		mask |= AT_SLASH2MTIME;
	if (to_set & PSCFS_SETATTRF_CTIME)
		mask |= AT_SLASH2CTIME;
	if (to_set & SL_SETATTRF_GEN)
		mask |= AT_SLASH2GEN;
	return (mask);
}

void
zfsslash2_destroy(void)
{
	int i;
#ifdef DEBUG
	extern int pscfs_exit_fuse_listener;

	fprintf(stderr, "Calling do_umount()... force %d\n",
	    pscfs_exit_fuse_listener);
#endif
	/*
	 * If exit_fuse_listener is true, then we received a signal
	 * and we're terminating the process.  Therefore we need to
	 * force unmount since there could still be open files.
	 */
	sync();
	for (i = 0; i < zfs_nmounts; i++) {
		while (do_umount(zfs_mounts[i].zm_vfs, 0) != 0)
			sync();
	}
#ifdef DEBUG
	fprintf(stderr, "do_umount() done\n");
#endif
}

int
zfsslash2_statfs(int vfsid, struct statvfs *sfb)
{
	struct statvfs64 zsfb;
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;

	memset(sfb, 0, sizeof(*sfb));
	memset(&zsfb, 0, sizeof(zsfb));
	int ret = VFS_STATVFS(vfs, &zsfb);
	if (ret != 0)
		return (ret);

	/* There's a bug somewhere in FUSE, in the kernel or in df(1) where
	   f_bsize is being used to calculate filesystem size instead of
	   f_frsize, so we must use that instead */
	/* Still there with fuse 2.7.4 apparently (you get a size in To so it shows a lot !) */
	sfb->f_bsize	= zsfb.f_frsize;
	sfb->f_frsize	= zsfb.f_frsize;
	sfb->f_blocks	= zsfb.f_blocks;
	sfb->f_bfree	= zsfb.f_bfree;
	sfb->f_bavail	= zsfb.f_bavail;
	sfb->f_files	= zsfb.f_files;
	sfb->f_ffree	= zsfb.f_ffree;
	sfb->f_favail	= zsfb.f_favail;
	sfb->f_fsid	= zsfb.f_fsid;
	sfb->f_flag	= zsfb.f_flag;
	sfb->f_namemax	= zsfb.f_namemax;

	return (0);
}

static int
fill_sstb(int vfsid, vnode_t *vp, mdsio_fid_t *mfp, struct srt_stat *sstb,
    cred_t *cred)
{
	struct sl_fidgen fg;
	vattr_t vattr;
	int error;

	ASSERT(vp);
	get_vnode_fids(vfsid, vp, &fg, mfp);

	if (sstb == NULL)
		return (0);

	memset(&vattr, 0, sizeof(vattr));
	error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);	/* zfs_getattr() */
	if (error)
		return (error);

	memset(sstb, 0, sizeof(*sstb));
	sstb->sst_fid = fg.fg_fid;
	sstb->sst_gen = fg.fg_gen;

	sstb->sst_dev = vattr.va_fsid;
	sstb->sst_ptruncgen = vattr.va_ptruncgen;
	sstb->sst_utimgen = vattr.va_s2utimgen;

	sstb->sst_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	/* subtract 1 for immutable namespace link */
	sstb->sst_nlink = (vattr.va_nlink > 1) ? (vattr.va_nlink - 1) :
	    vattr.va_nlink;
	sstb->sst_uid = vattr.va_uid;
	sstb->sst_gid = vattr.va_gid;
	sstb->sst_rdev = vattr.va_rdev;
	if (S_ISDIR(sstb->sst_mode) || S_ISLNK(sstb->sst_mode)) {
		/*
		 * We used to return this:
		 *
		 *	(vattr.va_blksize * vattr.va_nblocks)
		 *
		 * But we couldn't get consistent results from different
		 * code paths.  So we decided to adopt ZFS's way which
		 * is the number of entries in a directory.
		 */
		sstb->sst_size = vattr.va_size;
		sstb->sst_blksize = vattr.va_blksize;
		sstb->sst_blocks = vattr.va_nblocks;
	} else {
		/*
		 * sst_blksize is overridden in the MDS for metafsize
		 * and is overwritten by the CLI for network performance
		 * to IOD.
		 */
		if (fg.fg_fid == 0 && fg.fg_gen == 0)
			/* XXX, we want return local file size */
			sstb->sst_size = vattr.va_size;
		else
			sstb->sst_size = vattr.va_s2size;
		sstb->sst_blksize = vattr.va_size;
		sstb->sst_blocks = vattr.va_s2nblks;
	}

	sstb->sst_atime = vattr.va_s2atime.tv_sec;
	sstb->sst_atime_ns = vattr.va_s2atime.tv_nsec;
	sstb->sst_mtime = vattr.va_s2mtime.tv_sec;
	sstb->sst_mtime_ns = vattr.va_s2mtime.tv_nsec;
	sstb->sst_ctime = vattr.va_ctime.tv_sec;
	sstb->sst_ctime_ns = vattr.va_ctime.tv_nsec;

	return (0);
}

int
zfsslash2_getattr(int vfsid, mdsio_fid_t ino, void *finfo,
    const struct slash_creds *slcrp, struct srt_stat *sstb)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	file_info_t *info = finfo;
	boolean_t release;
	vnode_t *vp;
	int error;

	ZFS_ENTER(zfsvfs);

	if (!info) {
		znode_t *znode;

		error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
		if (error) {
			ZFS_EXIT(zfsvfs);
			/* If the inode we are trying to get was recently deleted
			   dnode_hold_impl will return EEXIST instead of ENOENT */
			return error == EEXIST ? ENOENT : error;
		}
		ASSERT(znode);
		vp = ZTOV(znode);
		release = B_TRUE;

	} else {
		vp = info->vp;
		release = B_FALSE;
	}
	ASSERT(vp);

	error = fill_sstb(vfsid, vp, NULL, sstb, &cred);

	if (release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

/* This macro makes the lookup for the xattr directory, necessary for listxattr
 * getxattr and setxattr */
#define MY_LOOKUP_XATTR(vfsid, flags)					\
	vfs_t *vfs = zfs_mounts[vfsid].zm_vfs;				\
	zfsvfs_t *zfsvfs = vfs->vfs_data;				\
	if (ino == SLFID_ROOT)						\
		ino = MDSIO_FID_ROOT;					\
									\
	ZFS_ENTER(zfsvfs);						\
									\
	znode_t *znode;							\
									\
	int error = zfs_zget(zfsvfs, ino, &znode, B_FALSE);		\
	if (error) {							\
		ZFS_EXIT(zfsvfs);					\
		return (error == EEXIST ? ENOENT : error);		\
	}								\
									\
	ASSERT(znode);							\
	vnode_t *dvp = ZTOV(znode);					\
	ASSERT(dvp);							\
									\
	vnode_t *vp = NULL;						\
									\
	error = VOP_LOOKUP(dvp, "", &vp, NULL, LOOKUP_XATTR |		\
	    (flags), NULL, &cred, NULL, NULL, NULL);			\
	if (error || vp == NULL) {					\
		if (error == ENOENT &&					\
		    ((flags) & CREATE_XATTR_DIR) == 0)			\
			error = ENOATTR;				\
		else if (error != EACCES)				\
			error = ENOSYS;					\
		goto out;						\
	}

int
zfsslash2_hasxattrs(int vfsid, const struct slash_creds *slcrp,
    mdsio_fid_t ino)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	MY_LOOKUP_XATTR(vfsid, 0);

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_mask = AT_SIZE;
	error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL);	/* zfs_getattr() */

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	if (error == ENOATTR)
		return (0);
	if (error)
		return (error);
	if (vattr.va_size == 2) // . and ..
		return (0);
	return (-1);
}

int
zfsslash2_listxattr(int vfsid, const struct slash_creds *slcrp,
    void *outbufp, size_t size, size_t *outbuf_len, mdsio_fid_t ino)
{
	int tmperror;
	char *outbuf = outbufp;
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	/* It's like a lookup, but passing LOOKUP_XATTR as a flag to VOP_LOOKUP */
	MY_LOOKUP_XATTR(vfsid, 0);

	error = VOP_OPEN(&vp, FREAD, &cred, NULL);
	if (error)
		goto out;

	// Now try a readdir...
	size_t alloc = 0, used = 0, remaining = 0;
	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN)];
		struct dirent64 dirent;
	} entry;

	struct stat fstat;
	memset(&fstat, 0, sizeof(fstat));

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	int eofp = 0;

	off_t next = 0;

	for (;;) {
		iovec.iov_base = entry.buf;
		iovec.iov_len = sizeof(entry.buf);
		uio.uio_resid = iovec.iov_len;
		uio.uio_loffset = next;

		error = VOP_READDIR(vp, &uio, &cred, &eofp, NULL, 0);
		if (error)
			goto out;

		/* No more directory entries */
		if (iovec.iov_base == entry.buf)
			break;

		next = entry.dirent.d_off;
		char *s = entry.dirent.d_name;
		if (*s == '.' && (s[1] == 0 || (s[1] == '.' && s[2] == 0)))
			continue;

		if (outbuf == NULL) {
			used += strlen(s)+1;
			continue;
		}
		if (used + strlen(s)+1 > size) {
			error = ERANGE;
			break;
		}
		strcpy(&outbuf[used], s);
		used += strlen(s)+1;

	}
	*outbuf_len = used;

	tmperror = VOP_CLOSE(vp, FREAD, 1, (offset_t) 0, &cred, NULL);
	if (!error)
		error = tmperror;
 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	if (error == ENOATTR) {
		*outbuf_len = 0;
		error = 0;
	}
	return (error);
}

int
zfsslash2_setxattr(int vfsid, const struct slash_creds *slcrp,
    const char *name, const char *value, size_t size, mdsio_fid_t ino)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	MY_LOOKUP_XATTR(vfsid, CREATE_XATTR_DIR);

	/*
	 * Now create a file inside the xattr directory with the wanted
	 * attribute.
	 */

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_type = VREG;
	vattr.va_mode = 0660;
	vattr.va_mask = AT_TYPE|AT_MODE|AT_SIZE;
	vattr.va_size = 0;

	vnode_t *new_vp;
	zfsslash2_cursor_start();
	error = VOP_CREATE(vp, (char *) name, &vattr, NONEXCL, VWRITE,
	    &new_vp, &zrootcreds, &cred, 0, NULL, NULL, NULL);
	zfsslash2_cursor_end();
	if (error)
		goto out;

	VN_RELE(vp);
	vp = new_vp;
	error = VOP_OPEN(&vp, FWRITE, &cred, NULL);
	if (error)
		goto out;

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = (void *) value;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = 0;

	zfsslash2_cursor_start();
	error = VOP_WRITE(vp, &uio, FWRITE, &cred, NULL, NULL,
	    (void *)value);
	zfsslash2_cursor_end();
	if (error)
		goto out;
	error = VOP_CLOSE(vp, FWRITE, 1, (offset_t) 0, &cred, NULL);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

int
zfsslash2_getxattr(int vfsid, const struct slash_creds *slcrp,
    const char *name, char *outbuf, size_t size, size_t *outbuf_len,
    mdsio_fid_t ino)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	MY_LOOKUP_XATTR(vfsid, 0);
	vnode_t *new_vp = NULL;
	error = VOP_LOOKUP(vp, (char *) name, &new_vp, NULL, 0, NULL,
	    &cred, NULL, NULL, NULL);
	if (error) {
		error = ENOATTR;
		goto out;
	}
	VN_RELE(vp);
	vp = new_vp;
	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_mask = AT_SIZE;

	// We are obliged to get the size first because of the stupid handling of the
	// size parameter
	error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL);
	if (error)
		goto out;
	if (size == 0) {
		*outbuf_len = vattr.va_size;
		goto out;
	}
	if (size < vattr.va_size) {
		error = ERANGE;
		goto out;
	}

	error = VOP_OPEN(&vp, FREAD, &cred, NULL);
	if (error)
		goto out;

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = outbuf;
	iovec.iov_len = vattr.va_size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = 0;

	error = VOP_READ(vp, &uio, FREAD, &cred, NULL);
	if (error)
		goto out;
	*outbuf_len = vattr.va_size;
	error = VOP_CLOSE(vp, FREAD, 1, (offset_t)0, &cred, NULL);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

int
zfsslash2_removexattr(int vfsid, const struct slash_creds *slcrp,
	const char *name, mdsio_fid_t ino)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	MY_LOOKUP_XATTR(vfsid, 0);

	zfsslash2_cursor_start();
	error = VOP_REMOVE(vp, (char *)name, &cred, NULL, 0, NULL, NULL);
	zfsslash2_cursor_end();

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	if (error == ENOENT)
		error = ENOATTR;
	return (error);
}

int
zfsslash2_lookup(int vfsid, mdsio_fid_t parent, const char *name,
    mdsio_fid_t *mfp, const struct slash_creds *slcrp,
    struct srt_stat *sstb, uint32_t *xattrsize)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	mdsio_fid_t mfid;

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_TRUE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp);

	vnode_t *vp = NULL;

	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, &cred,
	    NULL, NULL, NULL);	/* zfs_lookup() */
	if (error)
		goto out;

	if (vp == NULL) {
		error = ENOENT;
		goto out;
	}

	if (sstb || mfp || xattrsize)
		error = fill_sstb(vfsid, vp, &mfid, sstb, &cred);

	if (xattrsize)
		*xattrsize = zfsslash2_hasxattrs(vfsid, slcrp, mfid);

	if (mfp)
		*mfp = mfid;

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/*
 * XXX replace finfop with something meaningful for SLASH2 d_ino cache
 */
int
zfsslash2_opendir(int vfsid, mdsio_fid_t ino,
    const struct slash_creds *slcrp, struct sl_fidgen *fgp,
    void *finfop)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp);

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}
	/*
	 * Check permissions.
	 */
	if (!(vfs->fuse_attribute & FUSE_VFS_HAS_DEFAULT_PERM)) {
		error = VOP_ACCESS(vp, VREAD | VEXEC, 0, &cred, NULL);
		if (error)
			goto out;
	}

	/* XXX convert to the SLASH2 d_ino cache */
	file_info_t *finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if (finfo == NULL) {
		error = ENOMEM;
		goto out;
	}
	*(void **)finfop = finfo;

	finfo->vp = vp;
	finfo->flags = FREAD;

	get_vnode_fids(vfsid, vp, fgp, NULL);

 out:
	if (error)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/*
 * XXX convert to the SLASH2 d_ino cache .. same as above
 */
int
zfsslash2_release(int vfsid, __unusedx const struct slash_creds *slcrp,
    void *finfo)
{
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	file_info_t *info = finfo;

	ZFS_ENTER(zfsvfs);

	ASSERT(info->vp);
	ASSERT(VTOZ(info->vp));

#if 0
	fprintf(stdout, "zfsslash2_release: vp = %p, count = %d\n", info->vp, info->vp->v_count);
#endif
	VN_RELE(info->vp);

	kmem_cache_free(file_info_cache, info);

	ZFS_EXIT(zfsvfs);

	return 0;
}

int
zfsslash2_build_immns_cache(int vfsid)
{
	uint64_t ndirs;

	init_mmap();

	/* the number of directories at the lowest level */
	ndirs = 1 << (BPHXC * FID_PATH_DEPTH);
	immnsIdCache[vfsid] = malloc(sizeof(uint64_t) * ndirs);
	slz_immns_id_mask = (ndirs - 1) << (BPHXC * FID_PATH_START);
	return (0);
}

mdsio_fid_t
zfsslash2_getfidlinkdir(slfid_t fid)
{
	int bkt;

	bkt = (fid & slz_immns_id_mask) >> (BPHXC * FID_PATH_START);
	if (immnsIdCache[current_vfsid][bkt])
		return (immnsIdCache[current_vfsid][bkt]);

	struct vfs *vfs = zfs_mounts[current_vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	vnode_t *vp[FID_PATH_DEPTH + 1];
	znode_t *znode;
	char id_name[2];
	unsigned int ch;
	int i, error;

	error = zfs_zget(zfsvfs, mds_fidnsdir_inum[current_vfsid],
	    &znode, B_TRUE);
	if (error)
		return (error);

	ASSERT(znode);
	vp[0] = ZTOV(znode);
	ASSERT(vp[0]);

	for (i = 0; i < FID_PATH_DEPTH; i++) {
		ch = (fid >> (BPHXC * (FID_PATH_START + FID_PATH_DEPTH -
		    i - 1))) & 0xf;
		snprintf(id_name, 2, "%x", ch);
		error = VOP_LOOKUP(vp[i], id_name, &vp[i + 1], NULL, 0,
		    NULL, &zrootcreds, NULL, NULL, NULL);
		if (error)
			break;
	}

	if (i == FID_PATH_DEPTH) {
		immnsIdCache[current_vfsid][bkt] = VTOZ(vp[i])->z_id;
		psclog_debug("caching zfid=%#"PRIx64,
		    VTOZ(vp[i])->z_id);
	}

	for (; i >= 0; i--)
		VN_RELE(vp[i]);

	return (immnsIdCache[current_vfsid][bkt]);
}

/**
 * zfsslash2_readdir - Perform readdir(2) guts.
 * @vfsid: file system ID.
 * @slcrp: calling credentials.
 * @size: length of request.
 * @off: offset into directory for next batch of entries.
 * @outbuf: buffer to place entries.
 * @outbuf_len: value-result length of entries we fill.
 * @nents: value-result number of entries returned.
 * @attrv: value-result iovec to fill with stat(2) prefetching.
 * @eof: value-result indicator of end-of-file status.
 * @nextoff: next readdir(2) offset for contiguous readahead.
 * @finfo: directory handle.
 */
int
zfsslash2_readdir(int vfsid, const struct slash_creds *slcrp, size_t size,
    off_t off, void *outbuf, size_t *outbuf_len, int *nents,
    struct iovec *attrv, int *eof, off_t *nextoff, void *finfo)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	vnode_t *vp = ((file_info_t *)finfo)->vp;

	struct timespec ts_zget_start, ts_end;

	ASSERT(vp);
	ASSERT(VTOZ(vp));

	if (vp->v_type != VDIR)
		return ENOTDIR;

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN + 1)];
		struct dirent64 dirent;
	} entry;

	struct stat fstat;
	memset(&fstat, 0, sizeof(fstat));

	struct srt_readdir_ent *attr;

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	int outbuf_off = 0;
	int outbuf_resid = size;

	off_t next = off;

	int error;

	if (nents)
		*nents = 0;

	for (;;) {
		iovec.iov_base = entry.buf;
		iovec.iov_len = sizeof(entry.buf);
		uio.uio_resid = iovec.iov_len;
		uio.uio_loffset = next;

		error = VOP_READDIR(vp, &uio, &cred, eof, NULL,
		    V_RDDIR_ONEENTRY);	/* zfs_readdir() */
		if (error)
			goto out;

		/* No more directory entries */
		if (iovec.iov_base == entry.buf)
			break;

		/* No more room */
		int dsize = add_dirent(NULL, 0, entry.dirent.d_name,
		    NULL, 0);
		if (dsize > outbuf_resid)
			break;

		if (outbuf_off + attrv->iov_len + sizeof(*attr) >
		    1024 * 1024) // LNET_MTU
			break;

		/* XXX XXX avoid doing a zfs_zget() here XXX XXX */
		znode_t *znode;

		PFL_GETPTIMESPEC(&ts_zget_start);
		error = zfs_zget(zfsvfs, entry.dirent.d_ino, &znode, B_TRUE);
		if (error) {
			psclog_errorx("zget failed in dnode=%#"PRIx64
			    " name=%s ino=%#"PRIx64" (rc=%d)",
			    VTOZ(vp)->z_phys->zp_s2fid, entry.dirent.d_name,
			    entry.dirent.d_ino, error);

			next = entry.dirent.d_off;
			continue;
		}

		PFL_GETPTIMESPEC(&ts_end);
		timespecsub(&ts_end, &ts_zget_start, &ts_end);

		psclog_debug("*nents=%d *outbuf_len=%zu "
		    "zget_ino=%#"PRIx64" zget_time="PSCPRI_TIMESPEC,
		    nents ? *nents : 0, outbuf_len ? *outbuf_len : 0,
		    entry.dirent.d_ino, PSCPRI_TIMESPEC_ARGS(&ts_end));

		ASSERT(znode);
		vnode_t *tvp = ZTOV(znode);

		/*
		 * Skip internal SLASH2 meta-structure.
		 * This check should be pushed out to mount_slash once
		 * we move the pscfs_dirent packing there.
		 */
		if (hide_vnode(vp, tvp, entry.dirent.d_name))
			goto next_entry;

		mdsio_fid_t mf;

		attrv->iov_base = PSC_REALLOC(attrv->iov_base,
		    attrv->iov_len + sizeof(*attr));
		attr = PSC_AGP(attrv->iov_base, attrv->iov_len);
		memset(attr, 0, sizeof(*attr));
		attrv->iov_len += sizeof(*attr);

		/* XXX look at fidcache first */
		if (fill_sstb(vfsid, tvp, &mf, &attr->sstb, &cred))
			attr->sstb.sst_fid = FID_ANY;
//		else if (flags & XATTR &&
		else if (zfsslash2_hasxattrs(vfsid, slcrp, mf))
			attr->xattrsize = -1;

		if (VTOZ(tvp)->z_id == MDSIO_FID_ROOT)
			fstat.st_ino = SLFID_ROOT;
		else
			fstat.st_ino = VTOZ(tvp)->z_phys->zp_s2fid;

		fstat.st_mode = 0;
		switch (tvp->v_type) {
		    case VREG:
			fstat.st_mode |= S_IFREG;
			break;
		    case VDIR:
			fstat.st_mode |= S_IFDIR;
			break;
		    case VBLK:
			fstat.st_mode |= S_IFBLK;
			break;
		    case VCHR:
			fstat.st_mode |= S_IFCHR;
			break;
		    case VLNK:
			fstat.st_mode |= S_IFLNK;
			break;
		    case VSOCK:
			fstat.st_mode |= S_IFSOCK;
			break;
		    case VFIFO:
			fstat.st_mode |= S_IFIFO;
			break;
		    default:
			psclog_errorx("unknown v_type %d", tvp->v_type);
			break;
		}

		outbuf_resid -= dsize;
		add_dirent(outbuf + outbuf_off, dsize,
		    entry.dirent.d_name, &fstat, entry.dirent.d_off);

		outbuf_off += dsize;

		if (nents)
			++*nents;

 next_entry:
		VN_RELE(tvp);
		next = entry.dirent.d_off;
	}

	if (nextoff)
		*nextoff = entry.dirent.d_off;

 out:
	ZFS_EXIT(zfsvfs);
	*outbuf_len = outbuf_off;

	return error;
}

#define zfsslash2_fidlink(vfsid, fid, flags, svp, vpp)				\
	_zfsslash2_fidlink(PFL_CALLERINFOSS(SLMSS_ZFS), (vfsid), (fid), (flags), (svp), (vpp))

/**
 * zfsslash2_fidlink - Construct the by-id namespace for our internal
 *	use.  This will add an extra link to all files AND directories.
 *	Normally, a user accesses a file or a directory by its name and
 *	that is done in the by-name namespace.
 *
 * @svp:
 * @vpp: value-result vnode pointer of requested FID.
 *
 * Note that this function assumes that the upper layers of the by-id
 * namespace have already been created.  We do this when we format the
 * file system.
 */
int
_zfsslash2_fidlink(const struct pfl_callerinfo *_pfl_callerinfo,
    int vfsid, slfid_t fid, int flags, vnode_t *svp, vnode_t **vpp)
{
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	vnode_t *vp, *dvp;
	znode_t *znode;
	char id_name[20];
	uint64_t slot;
	int i, error;

	/*
	 * Map the root of SLASH2 metadir to the root of the underlying ZFS.
	 */
	if ((flags & FIDLINK_LOOKUP) && FID_GET_INUM(fid) == SLFID_ROOT) {
#if 0
		/*
		 * I have found a place in zfs_mknode() where I can
		 * write SLASH2 FID 1 into the root node.  This function
		 * is called by dsl_pool_create() twice, once by
		 * zfs_create_fs(), once by zfs_create_share_dir().
		 * Both time I see the IS_ROOT_NODE flag is used.  I
		 * don't know why ZFS seems to create two root nodes.
		 * But the change seems to fix my problem and make the
		 * hack here unneeded.  I discovered this with gdb while
		 * creating a zpool.
		 */
		VTOZ(dvp)->z_phys->zp_s2fid = 1;
#endif
		error = zfs_zget(zfsvfs, MDSIO_FID_ROOT, &znode, B_TRUE);
		if (error)
			return error == EEXIST ? ENOENT : error;

		ASSERT(znode);
		dvp = ZTOV(znode);
		ASSERT(dvp);

		*vpp = dvp;
		return 0;
	}

	error = zfs_zget(zfsvfs, zfsslash2_getfidlinkdir(fid),
	    &znode, B_TRUE);
	if (error)
		return error == EEXIST ? ENOENT : error;

	ASSERT(znode);
	dvp = ZTOV(znode);
	ASSERT(dvp);

	snprintf(id_name, sizeof(id_name), "%016"PRIx64, fid);

	if (flags & FIDLINK_LOOKUP) {
		error = VOP_LOOKUP(dvp, id_name, vpp, NULL, 0, NULL,
		    &zrootcreds, NULL, NULL, NULL);
		if (!error)
			goto out;
		if (error != ENOENT || !(flags & FIDLINK_CREATE))
			goto out;
	}
	if (flags & FIDLINK_CREATE) {
		zfsslash2_cursor_start();

		if (svp) {
			/*
			 * Create an extra link to the name in the
			 * regular name space, keeping the parent
			 * pointer intact.
			 *
			 * Tweaked in b15c349fb9463994676a52acecfefe153290e607
			 */
			error = VOP_LINK(dvp, svp, id_name, &zrootcreds,
			    NULL, FALLOWDIRLINK | FKEEPPARENT | SLASH2_IGNORE_CTIME,
			    NULL);	/* zfs_link() */
		} else {
			vattr_t vattr;

			memset(&vattr, 0, sizeof(vattr));
			vattr.va_type = VDIR;
			vattr.va_mode = 0711;
			vattr.va_mask = AT_TYPE | AT_MODE;
			vattr.va_fid = fid;
			error = VOP_MKDIR(dvp, id_name, &vattr, vpp,
			    &zrootcreds, &zrootcreds, NULL, 0, NULL, NULL);	/* zfs_mkdir() */
		}
		zfsslash2_cursor_end();
		goto out;
	}
	assert(flags & FIDLINK_REMOVE);

	zfsslash2_cursor_start();

	/*
	 * ZFS returns EPERM (1) even if root attempts to VOP_REMOVE() a
	 * directory.
	 */
	if (flags & FIDLINK_DIR)
		error = VOP_RMDIR(dvp, id_name, NULL, &zrootcreds, NULL,
		    0, NULL);
	else
		error = VOP_REMOVE(dvp, id_name, &zrootcreds, NULL, 0,
		    NULL, NULL);

	zfsslash2_cursor_end();

 out:
	psclog_debug("id_name=%s parent=%#"PRIx64" fid="SLPRI_FID" "
	    "flags=%x error=%d",
	    id_name, VTOZ(dvp)->z_id, fid, flags, error);

	VN_RELE(dvp);
	return (error);
}

/**
 * zfsslash2_lookup_slfid - Given a SLASH2 FID, lookup the inum for that
 *	corresponding file relevant to the backing metadata file system.
 *
 * This function is called from mdsio_lookup_slfid().
 */
int
zfsslash2_lookup_slfid(int vfsid, slfid_t fid,
    const struct slash_creds *slcrp, struct srt_stat *sstb,
    mdsio_fid_t *mfp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	vnode_t *vp;
	int error;

	vp = NULL;
	error = zfsslash2_fidlink(vfsid, fid, FIDLINK_LOOKUP, NULL, &vp);
	if (error)
		return (error);
	if (sstb || mfp)
		error = fill_sstb(vfsid, vp, mfp, sstb, &cred);

	VN_RELE(vp);
	return (error);
}

/**
 * zfsslash2_opencreate - Open a file (create if necessary).
 * @ino: parent inode if O_CREAT is specified; otherwise, the ZFS inum
 *	of file to open.
 * @slcrp: credentials with which to perform access.
 * @fflags: file open flags.
 * @opflags: operation flags (see MDSIO_OPENCRF_*).
 * @createmode: permission set new file should take on.
 * @name: link base name to use in parent directory if creating.
 * @mfp: value-result ZFS inum if creating.
 * @sstb: value-result stat buffer of file.
 * @finfo: value-result handle to ZFS structure; used as a descriptor to
 *	all other mdsio routines.
 * @logfunc: callback for logging create operation.
 * @getslfid: callback for retrieving a unique SLASH2 FID.
 *
 * Note that ino is the target inode if this is an open; otherwise it is
 * the inode of the parent.
 */
int
zfsslash2_opencreate(int vfsid, mdsio_fid_t ino,
    const struct slash_creds *slcrp, int fflags, int opflags,
    mode_t createmode, const char *name, mdsio_fid_t *mfp,
    struct srt_stat *sstb, void *finfop, sl_log_update_t logfunc,
    sl_getslfid_cb_t getslfid, slfid_t fid)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	/* Map flags */
	int mode, flags;

	if (fflags & O_WRONLY) {
		mode = VWRITE;
		flags = FWRITE;
	} else if (fflags & O_RDWR) {
		mode = VREAD | VWRITE;
		flags = FREAD | FWRITE;
	} else {
		mode = VREAD;
		flags = FREAD;
	}

	if (fflags & O_CREAT)
		flags |= FCREAT;
	if (fflags & O_SYNC)
		flags |= FSYNC;
	if (fflags & O_DSYNC)
		flags |= FDSYNC;
	if (fflags & O_RSYNC)
		flags |= FRSYNC;
	if (fflags & O_APPEND)
		flags |= FAPPEND;
	if (fflags & O_LARGEFILE)
		flags |= FOFFMAX;
	if (fflags & O_NOFOLLOW)
		flags |= FNOFOLLOW;
	if (fflags & O_TRUNC)
		flags |= FTRUNC;
	if (fflags & O_EXCL)
		flags |= FEXCL;

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp);

	if (flags & FCREAT) {
		if (strlen(name) > MAXNAMELEN) {
			error = ENAMETOOLONG;
			goto out;
		}

		enum vcexcl excl;

		vattr_t vattr;
		memset(&vattr, 0, sizeof(vattr));

		vattr.va_type = VREG;
		vattr.va_mode = createmode;
		vattr.va_mask = AT_TYPE|AT_MODE;

		if (sstb) {
			vattr.va_ctime.tv_sec = sstb->sst_ctim.tv_sec;
			vattr.va_ctime.tv_nsec = sstb->sst_ctim.tv_nsec;
			vattr.va_s2atime = vattr.va_ctime;
			vattr.va_s2mtime = vattr.va_ctime;
			vattr.va_mask |= AT_SLASH2ATIME | AT_SLASH2MTIME | AT_SLASH2CTIME;
		}

		if (getslfid) {
			error = getslfid(&vattr.va_fid);
			if (error)
				goto out;
		} else
			vattr.va_fid = fid;

		if (flags & FTRUNC) {
			vattr.va_size = 0;
			vattr.va_mask |= AT_SIZE;
		}
		if (flags & FEXCL)
			excl = EXCL;
		else
			excl = NONEXCL;

		vnode_t *new_vp;

		zfsslash2_cursor_start();
		/* FIXME: check filesystem boundaries */
		error = VOP_CREATE(vp, (char *)name, &vattr, excl, mode,
		    &new_vp, &zrootcreds, &cred, opflags & MDSIO_OPENCRF_NOMTIM ?
		    SLASH2_IGNORE_MTIME : 0, NULL, NULL, logfunc); /* zfs_create() */
		zfsslash2_cursor_end();

		if (error)
			goto out;

		VN_RELE(vp);
		vp = new_vp;
		if ((opflags & MDSIO_OPENCRF_NOLINK) == 0) {
			error = zfsslash2_fidlink(vfsid,
			    VTOZ(vp)->z_phys->zp_s2fid, FIDLINK_CREATE,
			    vp, NULL);
#if 0
			fprintf(stderr, "create: name = %s, fid = 0x%lx, txg = %lx, errno = %d\n",
				name, vattr.va_fid, zfsslash2_return_synced(), errno);
#endif
			if (error)
				goto out;
		}
	} else {
		/*
		 * Get the attributes to check whether file is large.
		 * We do this only if the O_LARGEFILE flag is not set and
		 * only for regular files.
		 */
		if (!(flags & FOFFMAX) && (vp->v_type == VREG)) {
			vattr_t vattr;
			memset(&vattr, 0, sizeof(vattr));
			vattr.va_mask = AT_SIZE;
			if ((error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL))) /* zfs_getattr() */
				goto out;

			if (vattr.va_size > (u_offset_t)MAXOFF32_T) {
				/*
				 * Large File API - regular open fails
				 * if FOFFMAX flag is set in file mode
				 */
				error = EOVERFLOW;
				goto out;
			}
		}

		/*
		 * Check permissions.
		 */
		if (!(vfs->fuse_attribute & FUSE_VFS_HAS_DEFAULT_PERM)) {
			error = VOP_ACCESS(vp, mode, 0, &cred, NULL);
			if (error)
				goto out;
		}
	}

	if ((flags & FNOFOLLOW) && vp->v_type == VLNK) {
		error = ELOOP;
		goto out;
	}

	if (sstb || mfp) {
		error = fill_sstb(vfsid, vp, mfp, sstb, &cred);
		if (error)
			goto out;
	}

	/* XXX it should not be an error if we can't cache the vnode */
	file_info_t *finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if (finfo == NULL) {
		error = ENOMEM;
		goto out;
	}
	*(void **)finfop = finfo;

	finfo->vp = vp;
	finfo->flags = flags;

 out:
	if (error) {
		ASSERT(vp->v_count > 0);
		VN_RELE(vp);
	}

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_readlink(int vfsid, mdsio_fid_t ino, char *buf, size_t *lenp,
    const struct slash_creds *slcrp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;
	iovec.iov_base = buf;
	iovec.iov_len = PATH_MAX - 1;
	uio.uio_resid = PATH_MAX - 1;
	uio.uio_loffset = 0;

	zfsslash2_cursor_start();
	error = VOP_READLINK(vp, &uio, &cred, NULL);	/* zfs_readlink() */

	/*
 	 * zfs_inactive() will call dmu_tx_assign(). This discovery makes
 	 * other call sites of VN_RELE() suspects as well. In retrospect,
 	 * we might as well do this at the MDS level as we used to do.
 	 */
	VN_RELE(vp);
	zfsslash2_cursor_end();

	ZFS_EXIT(zfsvfs);

	if (!error) {
		VERIFY(uio.uio_loffset < PATH_MAX);
		*lenp = uio.uio_loffset;
	}

	return error;
}

/*
 * Returns errno on failure, 0 on success.
 */
int
zfsslash2_preadv(int vfsid, const struct slash_creds *slcrp,
    struct iovec *iovs, int niov, size_t *nb, off_t off, void *finfo)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	file_info_t *info = finfo;
	vnode_t *vp = info->vp;

	ASSERT(vp);
	ASSERT(VTOZ(vp));

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	uio_t uio;
	uio.uio_iov = iovs;
	uio.uio_iovcnt = niov;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	int i;
	uio.uio_resid = 0;
	for (i = 0; i < niov; i++)
		uio.uio_resid += iovs[i].iov_len;
	uio.uio_loffset = off;

	int error = VOP_READ(vp, &uio, info->flags, &cred, NULL); /* zfs_read() */

	ZFS_EXIT(zfsvfs);

	if (error == 0)
		*nb = uio.uio_loffset - off;
	return (error);
}

int
zfsslash2_read(int vfsid, const struct slash_creds *slcrp, void *buf,
    size_t size, size_t *nb, off_t off, void *finfo)
{
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = size;
	return (zfsslash2_preadv(vfsid, slcrp, &iov, 1, nb, off, finfo));
}

int
zfsslash2_mkdir(int vfsid, mdsio_fid_t parent, const char *name,
    const struct srt_stat *sstb_in, int atflag, int opflags,
    struct srt_stat *sstb_out, mdsio_fid_t *mfp,
    sl_log_update_t logfunc, sl_getslfid_cb_t getslfid, slfid_t fid)
{
	cred_t cred = { sstb_in->sst_uid, sstb_in->sst_gid };
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/*
		 * If the inode we are trying to get was recently deleted,
		 * dnode_hold_impl will return EEXIST instead of ENOENT.
		 */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp);

	vnode_t *vp = NULL;

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_type = VDIR;
	vattr.va_mode = sstb_in->sst_mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE | AT_UID | AT_GID;
	vattr.va_uid = sstb_in->sst_uid;
	vattr.va_gid = sstb_in->sst_gid;
	if (getslfid) {
		error = getslfid(&vattr.va_fid);
		if (error)
			goto out;
	} else
		vattr.va_fid = fid;

	zfsslash2_cursor_start();
	error = VOP_MKDIR(dvp, (char *)name, &vattr, &vp, &zrootcreds, &cred, NULL,
	    opflags & MDSIO_OPENCRF_NOMTIM ? SLASH2_IGNORE_MTIME : 0,
	    NULL, logfunc); /* zfs_mkdir() */
	zfsslash2_cursor_end();
	if (error)
		goto out;

	ASSERT(vp);

	if ((opflags & MDSIO_OPENCRF_NOLINK) == 0) {
		error = zfsslash2_fidlink(vfsid,
		    VTOZ(vp)->z_phys->zp_s2fid, FIDLINK_CREATE, vp,
		    NULL);
		if (error)
			goto out;
	}

	if (sstb_out || mfp)
		error = fill_sstb(vfsid, vp, mfp, sstb_out, &zrootcreds);

#if 0
	fprintf(stderr, "mkdir: name=%s fid=0x%lx txg=%lx error=%d\n",
	    name, vattr.va_fid, zfsslash2_return_synced(), errno);
#endif

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

int
zfsslash2_rmdir(int vfsid, mdsio_fid_t parent, struct sl_fidgen *fg,
    const char *name, const struct slash_creds *slcrp,
    sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/*
		 * If the inode we are trying to get was recently deleted
		 * dnode_hold_impl will return EEXIST instead of ENOENT.
		 */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp);

	vnode_t *vp = NULL;
	/*
	 * Hold a reference to the name to be removed, so that it can
	 * be removed from the by-id namespace later.
	 */
	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, &cred,
	    NULL, NULL, NULL);
	if (error)
		goto out;

	/*
	 * FUSE doesn't care if we remove the current working directory
	 * so we just pass NULL as the cwd parameter (no problem for ZFS).
	 */
	zfsslash2_cursor_start();
	error = VOP_RMDIR(dvp, (char *)name, NULL, &cred, NULL, 0,
	    logfunc);	/* zfs_rmdir() */
	zfsslash2_cursor_end();

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if (error == EEXIST)
		error = ENOTEMPTY;

	if (fg) {
		fg->fg_fid = VTOZ(vp)->z_phys->zp_s2fid;
		fg->fg_gen = VTOZ(vp)->z_phys->zp_s2gen;
	}

	if (!error)
		error = zfsslash2_fidlink(vfsid,
		    VTOZ(vp)->z_phys->zp_s2fid,
		    FIDLINK_REMOVE | FIDLINK_DIR, NULL, NULL);

	VN_RELE(vp);

 out:
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	return error;
}

int
zfsslash2_setattr(int vfsid, mdsio_fid_t ino,
    const struct srt_stat *sstb_in, int to_set,
    const struct slash_creds *slcrp, struct srt_stat *sstb_out,
    void *finfo, sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	file_info_t *info = finfo;
	znode_t *znode;

	ZFS_ENTER(zfsvfs);

	vnode_t *vp;
	boolean_t release;

	/* XXX if to_set is NULL, error could be un-initialized */
	int error;

	int mask = SL_SETATTRF_METASIZE | PSCFS_SETATTRF_DATASIZE;
	if ((to_set & mask) == mask)
		return (EINVAL);

	if (!info) {
		error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
		if (error) {
			ZFS_EXIT(zfsvfs);
			/*
			 * If the inode we are trying to get was recently deleted
			 * dnode_hold_impl will return EEXIST instead of ENOENT.
			 */
			return error == EEXIST ? ENOENT : error;
		}
		ASSERT(znode);
		vp = ZTOV(znode);
		release = B_TRUE;
	} else {
		vp = info->vp;
		release = B_FALSE;
		znode = VTOZ(vp);

		/*
		 * Special treatment for ftruncate().
		 * This is needed because otherwise ftruncate() would
		 * fail with permission denied on read-only files.
		 * (Solaris calls VOP_SPACE instead of VOP_SETATTR on
		 * ftruncate).
		 */
		if (to_set & SL_SETATTRF_METASIZE) {
			/* Check if file is opened for writing */
			if ((info->flags & FWRITE) == 0) {
				error = EBADF;
				goto out;
			}
			/* Sanity check */
			if (vp->v_type != VREG) {
				error = EINVAL;
				goto out;
			}

			flock64_t bf;

			bf.l_whence = 0; /* beginning of file */
			bf.l_start = sstb_in->sst_size;
			bf.l_type = F_WRLCK;
			bf.l_len = (off_t) 0;

			/* FIXME: check locks */
			zfsslash2_cursor_start();
			error = VOP_SPACE(vp, F_FREESP, &bf,
			    info->flags, 0, &cred, NULL);
			zfsslash2_cursor_end();
			if (error)
				goto out;
		}
	}

	ASSERT(vp);

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));

	vattr.va_fid = VTOZ(vp)->z_phys->zp_s2fid;

	if (to_set & PSCFS_SETATTRF_MODE) {
		vattr.va_mask |= AT_MODE;
		vattr.va_mode = sstb_in->sst_mode;
	}
	if (to_set & PSCFS_SETATTRF_UID) {
		vattr.va_mask |= AT_UID;
		vattr.va_uid = sstb_in->sst_uid;
		if (vattr.va_uid > MAXUID) {
			error = EINVAL;
			goto out;
		}
	}
	if (to_set & PSCFS_SETATTRF_GID) {
		vattr.va_mask |= AT_GID;
		vattr.va_gid = sstb_in->sst_gid;
		if (vattr.va_gid > MAXUID) {
			error = EINVAL;
			goto out;
		}
	}
	if (to_set & PSCFS_SETATTRF_ATIME) {
		vattr.va_mask |= AT_SLASH2ATIME;
		vattr.va_s2atime.tv_sec = sstb_in->sst_atime;
		vattr.va_s2atime.tv_nsec = sstb_in->sst_atime_ns;
	}
	if (to_set & PSCFS_SETATTRF_MTIME) {
		vattr.va_mask |= AT_SLASH2MTIME;
		vattr.va_s2mtime.tv_sec = sstb_in->sst_mtime;
		vattr.va_s2mtime.tv_nsec = sstb_in->sst_mtime_ns;
	}
	if (to_set & PSCFS_SETATTRF_CTIME) {
		vattr.va_mask |= AT_SLASH2CTIME;
		vattr.va_ctime.tv_sec = sstb_in->sst_ctime;
		vattr.va_ctime.tv_nsec = sstb_in->sst_ctime_ns;
	}
	if (to_set & PSCFS_SETATTRF_DATASIZE) {
		vattr.va_mask |= AT_SLASH2SIZE;
		vattr.va_s2size = sstb_in->sst_size;
		if (vattr.va_s2size == 0) {
			/* full truncate - zero all old bmaps */
			vattr.va_mask |= AT_SIZE;
			vattr.va_size = SL_BMAP_START_OFF;
		}
	}
	if (to_set & SL_SETATTRF_PTRUNCGEN) {
		vattr.va_mask |= AT_PTRUNCGEN;
		vattr.va_ptruncgen = sstb_in->sst_ptruncgen;
	}
	if (to_set & SL_SETATTRF_GEN) {
		vattr.va_mask |= AT_SLASH2GEN;
		vattr.va_s2gen = sstb_in->sst_gen;
	}
	if (to_set & SL_SETATTRF_NBLKS) {
		vattr.va_mask |= AT_SLASH2NBLKS;
		vattr.va_s2nblks = sstb_in->sst_blocks;
	}
	if (to_set & SL_SETATTRF_METASIZE) {
		vattr.va_mask |= AT_SIZE;
		vattr.va_size = sstb_in->sst_size;
	}

	int flags = (to_set & (PSCFS_SETATTRF_ATIME |
	    PSCFS_SETATTRF_MTIME)) ? ATTR_S2UTIME : 0;
	if (to_set) {
		zfsslash2_cursor_start();
		error = VOP_SETATTR(vp, &vattr, flags, &cred, NULL,
		    logfunc);	/* zfs_setattr() */
		zfsslash2_cursor_end();
	}

 out:
	if (!error && sstb_out)
		error = fill_sstb(vfsid, vp, NULL, sstb_out, &cred);

	if (release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return (error);
}

int
zfsslash2_unlink(int vfsid, mdsio_fid_t parent, struct sl_fidgen *fg,
    const char *name, const struct slash_creds *slcrp,
    sl_log_update_t logfunc, void *arg)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/*
		 * If the inode we are trying to get was recently deleted
		 * dnode_hold_impl will return EEXIST instead of ENOENT.
		 */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp);

	vnode_t *vp = NULL;
	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, &cred,
	    NULL, NULL, NULL);
	if (error)
		goto out;

	zfsslash2_cursor_start();
	error = VOP_REMOVE(dvp, (char *)name, &cred, NULL, 0, logfunc,
	    arg);	/* zfs_remove() */
	zfsslash2_cursor_end();
	if (error)
		goto out;

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL);
	if (error)
		goto out;

	if (fg) {
		fg->fg_fid = VTOZ(vp)->z_phys->zp_s2fid;
		fg->fg_gen = VTOZ(vp)->z_phys->zp_s2gen;
	}

	/*
	 * The last remaining link is our FID namespace one, so remove
	 * the file.
	 */
	if (vattr.va_nlink == 1)
		error = zfsslash2_fidlink(vfsid,
		    VTOZ(vp)->z_phys->zp_s2fid, FIDLINK_REMOVE, NULL,
		    NULL);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/*
 * Returns errno on failure, 0 on success.
 */
int
zfsslash2_pwritev(int vfsid, const struct slash_creds *slcrp,
    const struct iovec *iovs, int niov, size_t *nb, off_t off,
    void *finfo, sl_log_write_t funcp, void *datap)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	file_info_t *info = finfo;

	vnode_t *vp = info->vp;
	ASSERT(vp);
	ASSERT(VTOZ(vp));

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	size_t size = 0;
	int i;
	for (i = 0; i < niov; i++)
		size += iovs[i].iov_len;

	uio_t uio;
	uio.uio_iov = (struct iovec *)iovs;
	uio.uio_iovcnt = niov;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;
	uio.uio_resid = size;
	uio.uio_loffset = off;

	zfsslash2_cursor_start();
	int error = VOP_WRITE(vp, &uio,
	    info->flags | SLASH2_IGNORE_MTIME,
	    &cred, NULL, funcp, datap);	/* zfs_write() */
	zfsslash2_cursor_end();

	ZFS_EXIT(zfsvfs);

	if (!error) {
		/* When not using direct_io, we must always write 'size' bytes */
		VERIFY(uio.uio_resid == 0);
		*nb = size - uio.uio_resid;
	}

	return error;
}

__inline int
zfsslash2_write(int vfsid, const struct slash_creds *slcrp,
    const void *buf, size_t size, size_t *nb, off_t off,
    void *finfo, sl_log_write_t funcp, void *datap)
{
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = size;
	return (zfsslash2_pwritev(vfsid, slcrp, &iov, 1, nb, off,
	    finfo, funcp, datap));
}

int
zfsslash2_write_cursor(int vfsid, void *buf, size_t size, void *finfo,
    sl_log_write_t funcp)
{
	file_info_t *info = finfo;

	vnode_t *vp = info->vp;
	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = (void *)buf;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = 0;

	int error = VOP_WRITE(vp, &uio, SLASH2_CURSOR_UPDATE, &zrootcreds,
	    NULL, funcp, buf);	/* zfs_write() */

	ZFS_EXIT(zfsvfs);

	return (error);
}

int
zfsslash2_mknod(int vfsid, mdsio_fid_t parent, const char *name,
    mode_t mode, const struct slash_creds *slcrp, struct srt_stat *sstb,
    mdsio_fid_t *mfp, sl_log_update_t logfunc, sl_getslfid_cb_t getslfid)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	if (!S_ISFIFO(mode) && !S_ISSOCK(mode))
		return EOPNOTSUPP;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp);

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_type = S_ISFIFO(mode) ? VFIFO : VSOCK;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;

	error = getslfid(&vattr.va_fid);
	if (error)
		goto out;

	vnode_t *vp = NULL;

	/* FIXME: check filesystem boundaries */
	zfsslash2_cursor_start();
	error = VOP_CREATE(dvp, (char *)name, &vattr, EXCL, 0, &vp,
	    &zrootcreds, &cred, 0, NULL, NULL, logfunc);	/* zfs_create() */
	zfsslash2_cursor_end();

	if (error)
		goto out;

	ASSERT(vp);

	error = zfsslash2_fidlink(vfsid, VTOZ(vp)->z_phys->zp_s2fid,
	    FIDLINK_CREATE, vp, NULL);
	if (error)
		goto out;

	if (sstb || mfp)
		error = fill_sstb(vfsid, vp, mfp, sstb, &cred);

 out:
	if (vp)
		VN_RELE(vp);

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_symlink(int vfsid, const char *link, mdsio_fid_t parent,
    const char *name, const struct slash_creds *slcrp,
    struct srt_stat *sstb, mdsio_fid_t *mfp, sl_log_update_t logfunc,
    sl_getslfid_cb_t getslfid, slfid_t fid)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	if (strlen(name) + strlen(link) > SL_TWO_NAME_MAX)
		return ENAMETOOLONG;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp);

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_type = VLNK;
	vattr.va_mode = 0777;
	vattr.va_mask = AT_TYPE | AT_MODE;

	if (getslfid) {
		error = getslfid(&vattr.va_fid);
		if (error)
			goto out;
	} else
		vattr.va_fid = fid;

	zfsslash2_cursor_start();
	error = VOP_SYMLINK(dvp, (char *)name, &vattr, (char *)link,
	    &zrootcreds, &cred, NULL, 0, logfunc); /* zfs_symlink() */
	zfsslash2_cursor_end();

	vnode_t *vp = NULL;

	if (error)
		goto out;

	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, &cred,
	    NULL, NULL, NULL);
	if (error)
		goto out;

	error = zfsslash2_fidlink(vfsid, VTOZ(vp)->z_phys->zp_s2fid,
	    FIDLINK_CREATE, vp, NULL);
	if (error)
		goto out;

	ASSERT(vp);

	if (sstb || mfp)
		error = fill_sstb(vfsid, vp, mfp, sstb, &cred);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_rename(int vfsid, mdsio_fid_t oldparent, const char *oldname,
    mdsio_fid_t newparent, const char *newname,
    const struct slash_creds *slcrp, sl_log_update_t logfunc, void *arg)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *op_znode, *np_znode;

	if (strlen(oldname) > MAXNAMELEN)
		return ENAMETOOLONG;
	if (strlen(newname) > MAXNAMELEN)
		return ENAMETOOLONG;
	if (strlen(oldname) + strlen(newname) > SL_TWO_NAME_MAX)
		return ENAMETOOLONG;

	int error = zfs_zget(zfsvfs, oldparent, &op_znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(op_znode);
	vnode_t *op_vp = ZTOV(op_znode);
	ASSERT(op_vp);

	error = zfs_zget(zfsvfs, newparent, &np_znode, B_FALSE);
	if (error) {
		VN_RELE(op_vp);
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(np_znode);
	vnode_t *np_vp = ZTOV(np_znode);
	ASSERT(np_vp);

	zfsslash2_cursor_start();
	error = VOP_RENAME(op_vp, (char *)oldname, np_vp, (char *)newname,
	    &cred, NULL, 0, logfunc, arg);  /* zfs_rename() */
	zfsslash2_cursor_end();

	VN_RELE(op_vp);
	VN_RELE(np_vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_fsync(int vfsid, const struct slash_creds *slcrp,
    int datasync, void *finfo)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	file_info_t *info = finfo;
	ASSERT(info->vp);
	ASSERT(VTOZ(info->vp));

	vnode_t *vp = info->vp;

	zfsslash2_cursor_start();
	int error = VOP_FSYNC(vp, datasync ? FDSYNC : FSYNC, &cred,
	    NULL);	/* zfs_fsync() */
	zfsslash2_cursor_end();

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_link(int vfsid, mdsio_fid_t ino, mdsio_fid_t newparent,
    const char *newname, const struct slash_creds *slcrp,
    sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *td_znode, *s_znode;

	if (strlen(newname) > MAXNAMELEN)
		return ENAMETOOLONG;

	int error = zfs_zget(zfsvfs, ino, &s_znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(s_znode);

	error = zfs_zget(zfsvfs, newparent, &td_znode, B_FALSE);
	if (error) {
		VN_RELE(ZTOV(s_znode));
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	vnode_t *svp = ZTOV(s_znode);
	vnode_t *tdvp = ZTOV(td_znode);
	ASSERT(svp);
	ASSERT(tdvp);

	zfsslash2_cursor_start();
	error = VOP_LINK(tdvp, svp, (char *)newname, &cred, NULL, 0,
	    logfunc);	/* zfs_link() */
	zfsslash2_cursor_end();

	vnode_t *vp = NULL;
	if (error)
		goto out;

	error = VOP_LOOKUP(tdvp, (char *)newname, &vp, NULL, 0, NULL,
	    &cred, NULL, NULL, NULL);
	if (error)
		goto out;

	ASSERT(vp);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(tdvp);
	VN_RELE(svp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_access(int vfsid, mdsio_fid_t ino, int mask,
    const struct slash_creds *slcrp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	struct vfs *vfs = zfs_mounts[vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp);

	int mode = 0;
	if (mask & R_OK)
		mode |= VREAD;
	if (mask & W_OK)
		mode |= VWRITE;
	if (mask & X_OK)
		mode |= VEXEC;

	error = VOP_ACCESS(vp, mode, 0, &cred, NULL);

	VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

/*
 * The following are functions used to replay a namespace operation
 * which originated from a remote MDS or from the local journal.
 *
 * There are some big differences between these functions and those
 * above:
 *
 *  (1) We have to start from the immutable by-id namespace (that's why
 *	we start with zfsslash2_fidlink() instead of zfs_zget());
 *
 *  (2) We don't need to log a replayed operation.
 *
 *  (3) We may want to deal gracefully with errors - a redo operation
 *      can be interrupted due to a crash/power failure.
 *
 * It seems to me that I simply can't, as root, create a file owned by
 * an arbitrary regular user directly. There are also some limitations
 * on changing owner and group membership.  As a result, all replay
 * operations are done with their original credentials captured when the
 * corresponding operation was requested.  Note that we only log when
 * ZFS declares the operation is doable.
 *
 * XXX these should be merged with the routines above.
 *
 * XXX There are still some uses of zrootcreds in replay operations.
 *     We may want to replace them all with real creds.
 */

void
zfsslash2_wait_synced(uint64_t txg)
{
	dsl_pool_t *dp;
	struct vfs *vfs = zfs_mounts[current_vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	dp = spa_get_dsl(zfsvfs->z_os->os_spa);
	txg_wait_synced(dp, txg);
}

uint64_t
zfsslash2_return_synced(void)
{
	dsl_pool_t *dp;
	uint64_t txg;
	struct vfs *vfs = zfs_mounts[current_vfsid].zm_vfs;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	dp = spa_get_dsl(zfsvfs->z_os->os_spa);
	txg = txg_return_synced(dp);
	return (txg);
}

static void
sstb2vattr(const struct srt_stat *sstb, vattr_t *vap)
{
	memset(vap, 0, sizeof(*vap));

	if (sstb->sst_fid == SLFID_ROOT)
		vap->va_fid	= MDSIO_FID_ROOT;
	else
		vap->va_fid	= sstb->sst_fid;

	vap->va_s2gen		= sstb->sst_gen;
	vap->va_s2utimgen	= sstb->sst_utimgen;
	vap->va_ptruncgen	= sstb->sst_ptruncgen;
	vap->va_s2size		= sstb->sst_size;
	vap->va_s2nblks		= sstb->sst_blocks;

	vap->va_s2atime.tv_sec	= sstb->sst_atime;
	vap->va_s2atime.tv_nsec	= sstb->sst_atime_ns;
	vap->va_s2mtime.tv_sec	= sstb->sst_mtime;
	vap->va_s2mtime.tv_nsec	= sstb->sst_mtime_ns;

	vap->va_blksize		= sstb->sst_blksize;
	vap->va_nlink		= sstb->sst_nlink;
	vap->va_uid		= sstb->sst_uid;
	vap->va_gid		= sstb->sst_gid;
	vap->va_rdev		= sstb->sst_rdev;
	vap->va_mode		= sstb->sst_mode & PERMMASK;

	vap->va_ctime.tv_sec	= sstb->sst_ctime;
	vap->va_ctime.tv_nsec	= sstb->sst_ctime_ns;
	vap->va_atime.tv_sec	= sstb->sst_atime;
	vap->va_atime.tv_nsec	= sstb->sst_atime_ns;
	vap->va_mtime.tv_sec	= sstb->sst_mtime;
	vap->va_mtime.tv_nsec	= sstb->sst_mtime_ns;
}

int
zfsslash2_replay_symlink(int vfsid, slfid_t pfid, slfid_t fid, char *name,
    char *link, struct srt_stat *sstb)
{
	vnode_t *vp, *pvp;
	vattr_t vattr;
	cred_t cred;
	int error;

	vp = pvp = NULL;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	error = zfsslash2_fidlink(vfsid, pfid, FIDLINK_LOOKUP |
	    FIDLINK_CREATE, NULL, &pvp);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, sl_strerror(error));
		goto out;
	}

	sstb2vattr(sstb, &vattr);
	vattr.va_type = VLNK;
	vattr.va_mask = AT_TYPE | AT_MODE | AT_ATIME | AT_MTIME |
	    AT_CTIME | AT_SLASH2ATIME | AT_SLASH2MTIME;

	cred.req = NULL;
	cred.cr_uid = sstb->sst_uid;
	cred.cr_gid = sstb->sst_gid;

	zfsslash2_cursor_start();
	error = VOP_SYMLINK(pvp, name, &vattr, link, &zrootcreds, &cred, NULL,
	    0, NULL); /* zfs_symlink() */
	zfsslash2_cursor_end();

	if (error)
		goto out;

	error = VOP_LOOKUP(pvp, name, &vp, NULL, 0, NULL, &zrootcreds,
	    NULL, NULL, NULL);
	if (error)
		goto out;

	error = zfsslash2_fidlink(vfsid, VTOZ(vp)->z_phys->zp_s2fid,
	    FIDLINK_CREATE, vp, NULL);

 out:
	if (vp)
		VN_RELE(vp);
	if (pvp)
		VN_RELE(pvp);
	return (error);
}

int
zfsslash2_replay_link(int vfsid, slfid_t pfid, slfid_t fid, char *name,
    struct srt_stat *sstb)
{
	vnode_t *pvp, *svp;
	cred_t cred;
	int error;

	pvp = svp = NULL;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	// xxx this should not have a CREATE
	error = zfsslash2_fidlink(vfsid, pfid, FIDLINK_LOOKUP |
	    FIDLINK_CREATE, NULL, &pvp);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, sl_strerror(error));
		goto out;
	}
	// xxx dir
	error = zfsslash2_fidlink(vfsid, fid, FIDLINK_LOOKUP |
	    FIDLINK_CREATE, NULL, &svp);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, sl_strerror(error));
		goto out;
	}

	cred.req = NULL;
	cred.cr_uid = sstb->sst_uid;
	cred.cr_gid = sstb->sst_gid;

	zfsslash2_cursor_start();
	error = VOP_LINK(pvp, svp, name, &cred, NULL, 0, NULL);	/* zfs_link() */
	zfsslash2_cursor_end();

 out:
	if (svp)
		VN_RELE(svp);
	if (pvp)
		VN_RELE(pvp);
	return (error);
}

int
zfsslash2_replay_mkdir(int vfsid, slfid_t pfid, char *name,
    struct srt_stat *sstb)
{
	vnode_t *pvp, *tvp;
	vattr_t vattr;
	cred_t cred;
	int error;

	tvp = pvp = NULL;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	error = zfsslash2_fidlink(vfsid, pfid, FIDLINK_LOOKUP, NULL,
	    &pvp);
	if (error) {
		psclog_errorx("failed to look up parent fid "SLPRI_FID": %s",
		    pfid, sl_strerror(error));
		goto out;
	}

	sstb2vattr(sstb, &vattr);
	vattr.va_type = VDIR;
	vattr.va_mask = AT_TYPE | AT_MODE | AT_ATIME | AT_MTIME |
	    AT_CTIME | AT_SLASH2ATIME | AT_SLASH2MTIME;

	cred.req = NULL;
	cred.cr_uid = sstb->sst_uid;
	cred.cr_gid = sstb->sst_gid;

	/* pass opflags */
	zfsslash2_cursor_start();
	error = VOP_MKDIR(pvp, name, &vattr, &tvp, &zrootcreds, &cred, NULL, 0, NULL,
	    NULL); /* zfs_mkdir() */
	zfsslash2_cursor_end();

	if (error) {
		psclog_errorx("failed to mkdir "SLPRI_FID": %s",
		    sstb->sst_fid, sl_strerror(error));
		goto out;
	}

	// XXX DIR
	error = zfsslash2_fidlink(vfsid, sstb->sst_fid, FIDLINK_CREATE,
	    tvp, NULL);
	if (error)
		psclog_errorx("failed to create fidlink "SLPRI_FID": %s",
		    sstb->sst_fid, sl_strerror(error));

 out:
	if (pvp)
		VN_RELE(pvp);
	if (tvp)
		VN_RELE(tvp);
	return (error);
}

int
zfsslash2_replay_create(int vfsid, slfid_t pfid, char *name,
    struct srt_stat *sstb)
{
	vnode_t *pvp, *tvp;
	vattr_t vattr;
	cred_t cred;
	int error;

	tvp = pvp = NULL;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	error = zfsslash2_fidlink(vfsid, pfid, FIDLINK_LOOKUP, NULL,
	    &pvp);
	if (error) {
		psclog_errorx("failed to look up parent fid "SLPRI_FID": %s",
		    pfid, sl_strerror(error));
		goto out;
	}

	sstb2vattr(sstb, &vattr);
	vattr.va_type = VREG;
	vattr.va_mask = AT_TYPE | AT_MODE | AT_ATIME | AT_MTIME |
	    AT_CTIME | AT_SLASH2ATIME | AT_SLASH2MTIME;

	cred.req = NULL;
	cred.cr_uid = sstb->sst_uid;
	cred.cr_gid = sstb->sst_gid;

	/* pass opflags */
	zfsslash2_cursor_start();
	error = VOP_CREATE(pvp, name, &vattr, EXCL, 0, &tvp, &zrootcreds, &cred, 0,
	    NULL, NULL, NULL); /* zfs_create() */
	zfsslash2_cursor_end();

	if (error)
		goto out;

	// XXX dir
	error = zfsslash2_fidlink(vfsid, sstb->sst_fid, FIDLINK_CREATE,
	    tvp, NULL);
	if (error)
		psclog_errorx("failed to create fidlink "SLPRI_FID": %s",
		    sstb->sst_fid, sl_strerror(error));
 out:
	if (tvp)
		VN_RELE(tvp);
	if (pvp)
		VN_RELE(pvp);
	return (error);
}

int
zfsslash2_replay_rmdir(int vfsid, slfid_t pfid, slfid_t fid, char *name)
{
	vnode_t *dvp, *vp;
	int error;

	vp = NULL;
	dvp = NULL;
	error = zfsslash2_fidlink(vfsid, pfid, FIDLINK_LOOKUP, NULL, &dvp);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, sl_strerror(error));
		goto out;
	}

	error = VOP_LOOKUP(dvp, name, &vp, NULL, 0, NULL, &zrootcreds,
	    NULL, NULL, NULL);
	if (error)
		goto out;

	if (VTOZ(vp)->z_phys->zp_s2fid != fid) {
		psclog_errorx("target ID mismatch "SLPRI_FID" vs. "SLPRI_FID,
		    VTOZ(vp)->z_phys->zp_s2fid, fid);
		error = EINVAL;
		goto out;
	}

	zfsslash2_cursor_start();
	error = VOP_RMDIR(dvp, name, NULL, &zrootcreds, NULL, 0, NULL);		/* zfs_rmdir() */
	zfsslash2_cursor_end();

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if (error == EEXIST)
		error = ENOTEMPTY;

	if (!error) {
		error = zfsslash2_fidlink(vfsid,
		    VTOZ(vp)->z_phys->zp_s2fid, FIDLINK_REMOVE |
		    FIDLINK_DIR, NULL, NULL);
		if (!error)
			/*
			 * The vnode is still there, but its underlying
			 * link count is zero.
			 */
			assert(VTOZ(vp)->z_phys->zp_links == 0);
	}

 out:
	if (vp)
		VN_RELE(vp);
	if (dvp)
		VN_RELE(dvp);
	return (error);
}

int
zfsslash2_replay_unlink(int vfsid, slfid_t pfid, slfid_t fid, char *name)
{
	vnode_t *vp, *dvp;
	int error;

	vp = dvp = NULL;
	error = zfsslash2_fidlink(vfsid, pfid, FIDLINK_LOOKUP, NULL, &dvp);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, sl_strerror(errno));
		goto out;
	}
	error = VOP_LOOKUP(dvp, name, &vp, NULL, 0, NULL, &zrootcreds,
	    NULL, NULL, NULL);
	if (error)
		goto out;
	if (VTOZ(vp)->z_phys->zp_s2fid != fid) {
		psclog_errorx("target ID mismatch "SLPRI_FID" vs. "SLPRI_FID,
		    VTOZ(vp)->z_phys->zp_s2fid, fid);
		error = EINVAL;
		goto out;
	}

	zfsslash2_cursor_start();
	error = VOP_REMOVE(dvp, name, &zrootcreds, NULL, 0, NULL, NULL);
	zfsslash2_cursor_end();

	if (error)
		goto out;

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	error = VOP_GETATTR(vp, &vattr, 0, &zrootcreds, NULL);
	if (error)
		goto out;

	/*
	 * The last remaining link is our FID namespace one,
	 * so remove the file.
	 */
	if (vattr.va_nlink == 1)
		error = zfsslash2_fidlink(vfsid,
		    VTOZ(vp)->z_phys->zp_s2fid, FIDLINK_REMOVE, NULL,
		    NULL);

 out:
	if (vp)
		VN_RELE(vp);
	if (dvp)
		VN_RELE(dvp);
	return (error);
}

int
zfsslash2_replay_setattr(int vfsid, slfid_t fid, uint mask,
    struct srt_stat *sstb)
{
	int error, flag;
	vattr_t vattr;
	vnode_t *vp;

	vp = NULL;
	error = zfsslash2_fidlink(vfsid, fid, FIDLINK_LOOKUP, NULL, &vp);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID, fid);
		goto out;
	}

	sstb2vattr(sstb, &vattr);
	vattr.va_mask = mask;

	flag = (mask & (AT_ATIME | AT_MTIME)) ? ATTR_UTIME : 0;
	if (vattr.va_mask & AT_SLASH2SIZE) {
		if (vattr.va_s2size == 0) {
			/* full truncate - zero all old bmaps */
			vattr.va_mask |= AT_SIZE;
			vattr.va_size = SL_BMAP_START_OFF;
		}
	}

	/* Note: not using zrootcreds will return EPERM (1) */
	zfsslash2_cursor_start();
	error = VOP_SETATTR(vp, &vattr, flag, &zrootcreds, NULL, NULL);		/* zfs_setattr() */
	zfsslash2_cursor_end();

	if (!error)
		error = fill_sstb(vfsid, vp, NULL, sstb, &zrootcreds);
 out:
	if (vp)
		VN_RELE(vp);
	return (error);
}

int
zfsslash2_replay_rename(int vfsid, slfid_t parent, const char *name,
    slfid_t newparent, const char *newname,
    __unusedx struct srt_stat *stat)
{
	vnode_t *p_vp, *np_vp;
	int error;

	p_vp = np_vp = NULL;
	error = zfsslash2_fidlink(vfsid, parent, FIDLINK_LOOKUP, NULL, &p_vp);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    parent, sl_strerror(errno));
		goto out;
	}
	error = zfsslash2_fidlink(vfsid, newparent, FIDLINK_LOOKUP,
	    NULL, &np_vp);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    newparent, sl_strerror(errno));
		goto out;
	}

	zfsslash2_cursor_start();
	error = VOP_RENAME(p_vp, (char *)name, np_vp, (char *)newname,
	    &zrootcreds, NULL, 0, NULL, NULL);  /* zfs_rename() */
	zfsslash2_cursor_end();

 out:
	if (p_vp)
		VN_RELE(p_vp);
	if (np_vp)
		VN_RELE(np_vp);
	return (error);
}

int
zfsslash2_replay_setxattr(__unusedx int vfsid, __unusedx slfid_t fid,
    __unusedx const char *name, __unusedx const char *value,
    __unusedx size_t size)
{
	return (0);
}

int
zfsslash2_replay_removexattr(__unusedx int vfsid, __unusedx slfid_t fid,
    __unusedx const char *name)
{
	return (0);
}
