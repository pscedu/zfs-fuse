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

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>

#include "util.h"
#include "errno_compat.h"
#include <syslog.h>

#include "zfs_slashlib.h"

#include "pfl/fs.h"

#include "creds.h"
#include "fid.h"
#include "slashd/mdsio.h"
#include "slerr.h"
#include "sljournal.h"
#include "sltypes.h"

kmem_cache_t	*file_info_cache;
cred_t		 zrootcreds;
vfs_t		*zfsVfs;			/* initialized by do_mount() */
int		 stack_size;

uint64_t        *immnsIdCache;

/* flags for zfsslash2_fidlink() */
#define	FIDLINK_CREATE		(1 << 0)
#define	FIDLINK_LOOKUP		(1 << 1)
#define	FIDLINK_REMOVE		(1 << 2)
#define	FIDLINK_DIR		(1 << 3)

#define SL_PATH_PREFIX		".sl"
#define SL_PATH_FIDNS		".slfidns"

/**
 * get_vnode_fids - Get SLASH FID + generation (external) and the
 *	ZFS/MDSIO layer inum "fid" (internal) for a vnode.
 */
static __inline void
get_vnode_fids(const vnode_t *vp, struct slash_fidgen *fgp, mdsio_fid_t *mfp)
{
	if (fgp) {
		if (VTOZ(vp)->z_id == MDSIO_FID_ROOT)
			fgp->fg_fid = SLFID_ROOT;
		else
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
	if (FID_GET_FLAGS(VTOZ(vp)->z_phys->zp_s2fid) & SLFIDF_HIDE_DENTRY)
		return (1);

	if (VTOZ(dvp)->z_id == MDSIO_FID_ROOT &&
	    strncmp(cpn, SL_PATH_PREFIX, strlen(SL_PATH_PREFIX)) == 0)
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

void
zfsslash2_destroy(void)
{
#ifdef DEBUG
	fprintf(stderr, "Calling do_umount()... force %d\n",exit_fuse_listener);
#endif
	/*
	 * If exit_fuse_listener is true, then we received a signal
	 * and we're terminating the process. Therefore we need to
	 * force unmount since there could still be opened files
	 */
	sync();
	while (do_umount(zfsVfs, 0) != 0)
		sync();
#ifdef DEBUG
	fprintf(stderr, "do_umount() done\n");
#endif
}

int
zfsslash2_statfs(struct statvfs *sfb)
{
	struct statvfs64 zsfb;

	memset(sfb, 0, sizeof(*sfb));
	memset(&zsfb, 0, sizeof(zsfb));
	int ret = VFS_STATVFS(zfsVfs, &zsfb);
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
fill_sstb(vnode_t *vp, mdsio_fid_t *mfp, struct srt_stat *sstb, cred_t *cred)
{
	struct slash_fidgen fg;
	vattr_t vattr;
	int error;

	ASSERT(vp);
	get_vnode_fids(vp, &fg, mfp);

	if (sstb == NULL)
		return (0);

	memset(&vattr, 0, sizeof(vattr));
	error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);	/* zfs_getattr() */
	if (error)
		return (error);

	memset(sstb, 0, sizeof(*sstb));
	sstb->sst_fg = fg;
	sstb->sst_dev = vattr.va_fsid;
	sstb->sst_ptruncgen = vattr.va_ptruncgen;
	sstb->sst_utimgen = vattr.va_s2utimgen;

	sstb->sst_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	/* subtract 1 for immutable namespace link */
	sstb->sst_nlink = (vattr.va_nlink > 1) ? (vattr.va_nlink - 1) : vattr.va_nlink;
	sstb->sst_uid = vattr.va_uid;
	sstb->sst_gid = vattr.va_gid;
	sstb->sst_rdev = vattr.va_rdev;
	if (S_ISDIR(sstb->sst_mode))
		/*
 		 * We used to return (vattr.va_blksize * vattr.va_nblocks) here. But
 		 * we couldn't get consistent results from different code paths. So
 		 * we decided to adopt ZFS's way, which the number of entries in a
 		 * directory.
 		 */
		sstb->sst_size = vattr.va_size;
	else
		sstb->sst_size = vattr.va_s2size;
	sstb->sst_blksize = vattr.va_blksize;
	sstb->sst_blocks = vattr.va_nblocks;

	sstb->sst_atime = vattr.va_s2atime.tv_sec;
	sstb->sst_atime_ns = vattr.va_s2atime.tv_nsec;
	sstb->sst_mtime = vattr.va_s2mtime.tv_sec;
	sstb->sst_mtime_ns = vattr.va_s2mtime.tv_nsec;
	sstb->sst_ctime = vattr.va_ctime.tv_sec;
	sstb->sst_ctime_ns = vattr.va_ctime.tv_nsec;

	return 0;
}

int
zfsslash2_getattr(mdsio_fid_t ino, void *finfo, const struct slash_creds *slcrp,
    struct srt_stat *sstb)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;
	file_info_t *info = finfo;
	vnode_t *vp;
	int error;
	boolean_t release;

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

	error = fill_sstb(vp, NULL, sstb, &cred);

	if (release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

/* This macro makes the lookup for the xattr directory, necessary for listxattr
 * getxattr and setxattr */
#define MY_LOOKUP_XATTR()						\
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);			\
	zfsvfs_t *zfsvfs = vfs->vfs_data;				\
	if (ino == 1) ino = 3;						\
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
	    CREATE_XATTR_DIR, NULL, &cred, NULL, NULL, NULL);		\
	if (error || vp == NULL) {					\
		if (error != EACCES) error = ENOSYS;			\
		goto out;						\
	}

int
zfsslash2_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size,
    const struct slash_creds *slcrp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	/* It's like a lookup, but passing LOOKUP_XATTR as a flag to VOP_LOOKUP */
	MY_LOOKUP_XATTR();

	error = VOP_OPEN(&vp, FREAD, &cred, NULL);
	if (error) {
		goto out;
	}

	// Now try a readdir...
	char *outbuf = NULL;
	size_t alloc = 0, used = 0;
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
		while (used + strlen(s)+1 > alloc) {
			alloc += 1024;
			outbuf = realloc(outbuf, alloc);
		}
		strcpy(&outbuf[used],s);
		used += strlen(s)+1;

	}

	error = VOP_CLOSE(vp, FREAD, 1, (offset_t) 0, &cred, NULL);
	if (size == 0) {
		fuse_reply_xattr(req,used);
	} else if (size < used) {
		error = ERANGE;
	} else {
		fuse_reply_buf(req,outbuf,used);
	}
	free(outbuf);
 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

int
zfsfuse_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
    const char *value, size_t size, __unusedx int flags,
    const struct slash_creds *slcrp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	MY_LOOKUP_XATTR();
	// Now the idea is to create a file inside the xattr directory with the
	// wanted attribute.

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_type = VREG;
	vattr.va_mode = 0660;
	vattr.va_mask = AT_TYPE|AT_MODE|AT_SIZE;
	vattr.va_size = 0;

	vnode_t *new_vp;
	error = VOP_CREATE(vp, (char *) name, &vattr, NONEXCL, VWRITE,
	    &new_vp, &cred, 0, NULL, NULL, NULL);
	if (error)
		goto out;

	VN_RELE(vp);
	vp = new_vp;
	error = VOP_OPEN(&vp, FWRITE, &cred, NULL);
	if (error) goto out;

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

	error = VOP_WRITE(vp, &uio, FWRITE, &cred, NULL, NULL, (void *)value);
	if (error) goto out;
	error = VOP_CLOSE(vp, FWRITE, 1, (offset_t) 0, &cred, NULL);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	// The fuse_reply_err at the end seems to be an mandatory even if there is no error
	return (error);
}

int
zfsfuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
    size_t size, const struct slash_creds *slcrp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	MY_LOOKUP_XATTR();
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
	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;

	// We are obliged to get the size 1st because of the stupid handling of the
	// size parameter
	error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL);
	if (error)
		goto out;
	if (size == 0) {
		fuse_reply_xattr(req,vattr.va_size);
		goto out;
	} else if (size < vattr.va_size) {
		fuse_reply_xattr(req, ERANGE);
		goto out;
	}
	char *buf = malloc(vattr.va_size);
	if (!buf)
		goto out;

	error = VOP_OPEN(&vp, FREAD, &cred, NULL);
	if (error) {
		free(buf);
		goto out;
	}

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = buf;
	iovec.iov_len = vattr.va_size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = 0;

	error = VOP_READ(vp, &uio, FREAD, &cred, NULL);
	if (error) {
		free(buf);
		goto out;
	}
	fuse_reply_buf(req,buf,vattr.va_size);
	free(buf);
	error = VOP_CLOSE(vp, FREAD, 1, (offset_t)0, &cred, NULL);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

int
zfsfuse_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name,
    const struct slash_creds *slcrp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);

	MY_LOOKUP_XATTR();
	error = VOP_REMOVE(vp, (char *)name, &cred, NULL, 0, NULL);

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
zfsslash2_lookup(mdsio_fid_t parent, const char *name,
    mdsio_fid_t *mfp, const struct slash_creds *slcrp,
    struct srt_stat *sstb)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

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
	    NULL, NULL, NULL);
	if (error)
		goto out;

	if (vp == NULL) {
		error = ENOENT;
		goto out;
	}

	if (sstb || mfp)
		error = fill_sstb(vp, mfp, sstb, &cred);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/*
 * XXX replace finfop with something meaningful for slash d_ino cache
 */
int
zfsslash2_opendir(mdsio_fid_t ino, const struct slash_creds *slcrp,
    struct slash_fidgen *fgp, void *finfop)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

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
	if (!(zfsVfs->fuse_attribute & FUSE_VFS_HAS_DEFAULT_PERM)) {
		error = VOP_ACCESS(vp, VREAD | VEXEC, 0, &cred, NULL);
		if (error)
			goto out;
	}

	/* XXX convert to the slash d_ino cache */
	file_info_t *finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if (finfo == NULL) {
		error = ENOMEM;
		goto out;
	}
	*(void **)finfop = finfo;

	finfo->vp = vp;
	finfo->flags = FREAD;

	get_vnode_fids(vp, fgp, NULL);

 out:
	if (error)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/*
 * XXX convert to the slash d_ino cache .. same as above
 */
int
zfsslash2_release(__unusedx const struct slash_creds *slcrp, void
    *finfo)
{
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;
	file_info_t *info = finfo;

	ZFS_ENTER(zfsvfs);

	ASSERT(info->vp);
	ASSERT(VTOZ(info->vp));

	VN_RELE(info->vp);

	kmem_cache_free(file_info_cache, info);

	ZFS_EXIT(zfsvfs);

	return 0;
}

void
zfsslash2_build_immns_cache_helper(vnode_t *root, int curdepth, int maxdepth, int *cnt)
{
	vnode_t         *vp;
	int              i;
	char		 id_name[2];

	for (i=0; i < 16; i++) {
		snprintf(id_name, 2, "%x", i);

		if (VOP_LOOKUP(root, id_name, &vp, NULL, 0, NULL, &zrootcreds,
			       NULL, NULL, NULL))
			abort();

		if (curdepth < maxdepth)
			zfsslash2_build_immns_cache_helper(vp, curdepth + 1,
				   maxdepth, cnt);
		else {
			immnsIdCache[(*cnt)++] = VTOZ(vp)->z_id;
			psc_debug("depth=%d cnt=%d zfid=%"PRIx64, curdepth,
				  *cnt, VTOZ(vp)->z_id);
		}

		VN_RELE(vp);
	}
}

void
zfsslash2_build_immns_cache(void)
{
	znode_t         *znode;
	vnode_t		*vp, *dvp;
	int		 error, cnt=0;
	zfsvfs_t	*zfsvfs = zfsVfs->vfs_data;

	immnsIdCache = malloc(sizeof(uint64_t) * pow(16,FID_PATH_DEPTH));

	error = zfs_zget(zfsvfs, MDSIO_FID_ROOT, &znode, B_TRUE);
	if (error)
		abort();

	ASSERT(znode);
	dvp = ZTOV(znode);
	ASSERT(dvp);

	error = VOP_LOOKUP(dvp, SL_PATH_FIDNS, &vp, NULL, 0, NULL, &zrootcreds,
	    NULL, NULL, NULL);

	VN_RELE(dvp);
	if (error)
		abort();

	zfsslash2_build_immns_cache_helper(vp, 1, FID_PATH_DEPTH, &cnt);
	VN_RELE(vp);
}

/*
 * At most two buffers are passed in by our callers: outbuf points to the
 * readdir result, attrs points to prefeteched attributes.
 */
int
zfsslash2_readdir(const struct slash_creds *slcrp, size_t size,
	  off_t off, void *outbuf, size_t *outbuf_len, size_t *nents,
	  void *attrs, int nstbprefetch, void *finfo)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	vnode_t *vp = ((file_info_t *)finfo)->vp;

	ASSERT(vp);
	ASSERT(VTOZ(vp));

	if (vp->v_type != VDIR)
		return ENOTDIR;

	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN + 1)];
		struct dirent64 dirent;
	} entry;

	struct stat fstat;
	memset(&fstat, 0, sizeof(fstat));

	struct srt_stat *attr = attrs;

	ASSERT((!nstbprefetch && !attrs) || (nstbprefetch && attrs));

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	int eofp = 0;

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

		error = VOP_READDIR(vp, &uio, &cred, &eofp, NULL,
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

		/* XXX XXX avoid doing a zfs_zget() here XXX XXX */
		znode_t *znode;
		error = zfs_zget(zfsvfs, entry.dirent.d_ino, &znode, B_TRUE);
		if (error)
			break;

		ASSERT(znode);
		vnode_t *tvp = ZTOV(znode);

		/*
		 * Skip internal SLASH meta-structure.
		 * This check should be pushed out to mount_slash once
		 * we move the pscfs_dirent packing there.
		 */
		if (hide_vnode(vp, tvp, entry.dirent.d_name))
			goto next_entry;

		if (nstbprefetch) {
			/* XXX look at fidcache first */
			if (fill_sstb(tvp, NULL, attr, &cred))
				attr->sst_fid = FID_ANY;
			nstbprefetch--;
			attr++;
		}
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
			(*nents)++;
 next_entry:
		VN_RELE(tvp);
		next = entry.dirent.d_off;
	}

 out:
	ZFS_EXIT(zfsvfs);
	*outbuf_len = outbuf_off;

	return error;
}

/**
 * zfsslash2_fidlink - Construct the by-id namespace for our internal
 *	use.  This will add an extra link to all files AND directories.
 *	Normally, a user accesses a file or a directory by its name and
 *	that is done in the by-name namespace.
 *
 * Note that this function assumes that the upper layers of the by-id
 * namespace have already been created.  We do this when we format the
 * file system.
 */
int
zfsslash2_fidlink(slfid_t fid, int flags, vnode_t *svp, vnode_t **vpp, int caller)
{
	int		 i;
	vnode_t		*vp;
	vnode_t		*dvp;
	int		 error;
	znode_t		*znode;
	zfsvfs_t	*zfsvfs = zfsVfs->vfs_data;
	uint64_t         slot;
	char             id_name[20];

#define IMMNSMASK 0x0fff000L

	/*
	 * Map the root of slash2 to the root of the underlying ZFS.
	 */
	if ((flags & FIDLINK_LOOKUP) && fid == 1) {
#if 0
/*
 * I have found a place in zfs_mknode() where I can write SLASH FID 1 into the
 * root node.  This function is called by dsl_pool_create() twice, once by
 * zfs_create_fs(), once by zfs_create_share_dir().  Both time I see the
 * IS_ROOT_NODE flag is used.  I don't know why ZFS seems to create two root
 * nodes.  But the change seems to fix my problem and make the hack here
 * unneeded.  I discovered this with gdb while creating a zpool.
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

	error = zfs_zget(zfsvfs, (uint64_t)immnsIdCache[(fid & IMMNSMASK) >> 12],
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
		if (svp) {
			/*
			 * Create an extra link to the name in the regular name
			 * space, keeping the parent pointer intact.
			 */
			error = VOP_LINK(dvp, svp, id_name, &zrootcreds, NULL,
				FALLOWDIRLINK | FKEEPPARENT, NULL);
		} else {
			vattr_t vattr;
			memset(&vattr, 0, sizeof(vattr));
			vattr.va_type = VDIR;
			vattr.va_mode = 0711;
			vattr.va_mask = AT_TYPE | AT_MODE;
			vattr.va_fid = fid;
			error = VOP_MKDIR(dvp, id_name, &vattr, vpp,
			    &zrootcreds, NULL, 0, NULL, NULL);	/* zfs_mkdir() */
		}
		goto out;
	}
	assert(flags & FIDLINK_REMOVE);
	/*
	 * ZFS returns EPERM (1) even if root attempts to VOP_REMOVE() a directory.
	 */
	if (flags & FIDLINK_DIR)
		error = VOP_RMDIR(dvp, id_name, NULL, &zrootcreds, NULL, 0, NULL);
	else
		error = VOP_REMOVE(dvp, id_name, &zrootcreds, NULL, 0, NULL);

 out:
	psclog_debug("id_name=%s parent=%"PRId64" linkvp=%"PRIx64" flags=%x caller=%d error=%d\n",
	    id_name, VTOZ(dvp)->z_id, fid, flags, caller, error);

	return (error);
}

int
zfsslash2_lookup_slfid(slfid_t fid, const struct slash_creds *slcrp,
    struct srt_stat *sstb, mdsio_fid_t *mfp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	vnode_t *vp;
	int error;

	vp = NULL;
	error = zfsslash2_fidlink(fid, FIDLINK_LOOKUP, NULL, &vp, __LINE__);
	if (error)
		return (error);
	if (sstb || mfp)
		error = fill_sstb(vp, mfp, sstb, &cred);

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
 * @getslfid: callback for retrieving a unique SLASH FID.
 *
 * Note that ino is the target inode if this is an open, otherwise it is
 * the inode of the parent.
 */
int
zfsslash2_opencreate(mdsio_fid_t ino, const struct slash_creds *slcrp,
    int fflags, int opflags, mode_t createmode, const char *name,
    mdsio_fid_t *mfp, struct srt_stat *sstb, void *finfop,
    sl_log_update_t logfunc, sl_getslfid_cb_t getslfid)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

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
		vattr.va_fid = getslfid();

		if (flags & FTRUNC) {
			vattr.va_size = 0;
			vattr.va_mask |= AT_SIZE;
		}
		if (flags & FEXCL)
			excl = EXCL;
		else
			excl = NONEXCL;

		vnode_t *new_vp;

		/* FIXME: check filesystem boundaries */
		error = VOP_CREATE(vp, (char *)name, &vattr, excl, mode,
		    &new_vp, &cred, 0, NULL, NULL, logfunc);	/* zfs_create() */

		if (error)
			goto out;

		VN_RELE(vp);
		vp = new_vp;
		if ((opflags & MDSIO_OPENCRF_NOLINK) == 0) {
			error = zfsslash2_fidlink(
			    VTOZ(vp)->z_phys->zp_s2fid,
			    FIDLINK_CREATE, vp, NULL, __LINE__);
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
			if ((error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL)))
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
		if (!(zfsVfs->fuse_attribute & FUSE_VFS_HAS_DEFAULT_PERM)) {
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
		error = fill_sstb(vp, mfp, sstb, &cred);
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
zfsslash2_readlink(mdsio_fid_t ino, char *buf,
    const struct slash_creds *slcrp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

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
	iovec.iov_len = PATH_MAX;
	uio.uio_resid = PATH_MAX;
	uio.uio_loffset = 0;

	error = VOP_READLINK(vp, &uio, &cred, NULL);	/* zfs_readlink() */

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if (!error) {
		VERIFY(uio.uio_loffset < PATH_MAX);
		/*
		 * We may not need this if we write NULL
		 * at symlink() time.
		 */
		buf[uio.uio_loffset] = '\0';
	}

	return error;
}

/*
 * Returns errno on failure, 0 on success.
 */
int
zfsslash2_read(const struct slash_creds *slcrp, void *buf, size_t size,
    size_t *nb, off_t off, void *finfo)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	file_info_t *info = finfo;
	vnode_t *vp = info->vp;

	ASSERT(vp);
	ASSERT(VTOZ(vp));

	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = buf;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = off;

	int error = VOP_READ(vp, &uio, info->flags, &cred, NULL);

	ZFS_EXIT(zfsvfs);

	if (error == 0)
		*nb = uio.uio_loffset - off;
	return (error);
}

int
zfsslash2_mkdir(mdsio_fid_t parent, const char *name, mode_t mode,
    const struct slash_creds *slcrp, struct srt_stat *sstb,
    mdsio_fid_t *mfp, sl_log_update_t logfunc, sl_getslfid_cb_t getslfid)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
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

	vnode_t *vp = NULL;

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_type = VDIR;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;
	vattr.va_fid = getslfid();

	error = VOP_MKDIR(dvp, (char *)name, &vattr, &vp, &cred, NULL,
	    0, NULL, logfunc); /* zfs_mkdir() */
	if (error)
		goto out;

	ASSERT(vp);

	error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2fid,
	    FIDLINK_CREATE, vp, NULL, __LINE__);
	if (error)
		goto out;

	if (sstb || mfp)
		error = fill_sstb(vp, mfp, sstb, &cred);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_rmdir(mdsio_fid_t parent, const char *name,
    const struct slash_creds *slcrp, sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
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
	error = VOP_RMDIR(dvp, (char *)name, NULL, &cred, NULL, 0,
	    logfunc);	/* zfs_rmdir() */

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if (error == EEXIST)
		error = ENOTEMPTY;

	if (!error)
		error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2fid,
		    FIDLINK_REMOVE|FIDLINK_DIR, NULL, NULL, __LINE__);

	VN_RELE(vp);

 out:
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	return error;
}

int
zfsslash2_setattr(mdsio_fid_t ino, const struct srt_stat *sstb_in,
    int to_set, const struct slash_creds *slcrp,
    struct srt_stat *sstb_out, void *finfo, sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;
	file_info_t *info = finfo;
	znode_t *znode;

	ZFS_ENTER(zfsvfs);

	vnode_t *vp;
	boolean_t release;

	int error;

	if (!info) {
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
			error = VOP_SPACE(vp, F_FREESP, &bf,
			    info->flags, 0, &cred, NULL);
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
		vattr.va_mask |= AT_CTIME;
		vattr.va_ctime.tv_sec = sstb_in->sst_ctime;
		vattr.va_ctime.tv_nsec = sstb_in->sst_ctime_ns;
	}
	if (to_set & PSCFS_SETATTRF_DATASIZE) {
		vattr.va_mask |= AT_SLASH2SIZE;
		vattr.va_s2size = sstb_in->sst_size;
	}
	if (to_set & SL_SETATTRF_PTRUNCGEN) {
		vattr.va_mask |= AT_PTRUNCGEN;
		vattr.va_ptruncgen = sstb_in->sst_ptruncgen;
	}
	if (to_set & SL_SETATTRF_GEN) {
		vattr.va_mask |= AT_SLASH2GEN;
		vattr.va_s2gen = sstb_in->sst_gen;
	}

	int flags = (to_set & (PSCFS_SETATTRF_ATIME |
	    PSCFS_SETATTRF_MTIME)) ? ATTR_S2UTIME : 0;
	if (to_set)
		error = VOP_SETATTR(vp, &vattr, flags, &cred, NULL,
		    logfunc);	/* zfs_setattr() */

 out:
	if (!error && sstb_out)
		error = fill_sstb(vp, NULL, sstb_out, &cred);

	/* Do not release if vp was an opened inode */
	if (release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_unlink(mdsio_fid_t parent, const char *name,
    const struct slash_creds *slcrp, sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
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

	vnode_t *vp = NULL;
	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, &cred,
	    NULL, NULL, NULL);
	if (error)
		goto out;

	error = VOP_REMOVE(dvp, (char *)name, &cred, NULL, 0, logfunc);	/* zfs_remove() */
	if (error)
		goto out;

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL);
	if (error)
		goto out;

	/*
	 * The last remaining link is our FID namespace one,
	 * so remove the file.
	 */
	if (vattr.va_nlink == 1)
		error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2fid,
		    FIDLINK_REMOVE, NULL, NULL, __LINE__);

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
zfsslash2_write(const struct slash_creds *slcrp, const void *buf,
    size_t size, size_t *nb, off_t off, int update_mtime, void *finfo,
    sl_log_write_t funcp, void *datap)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	file_info_t *info = finfo;

	vnode_t *vp = info->vp;
	ASSERT(vp);
	ASSERT(VTOZ(vp));

	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

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
	uio.uio_loffset = off;

	int error = VOP_WRITE(vp, &uio,
	    (info->flags | (update_mtime ? 0 : SLASH2_IGNORE_MTIME)),
	    &cred, NULL, funcp, datap);	/* zfs_write */

	ZFS_EXIT(zfsvfs);

	if (!error) {
		/* When not using direct_io, we must always write 'size' bytes */
		VERIFY(uio.uio_resid == 0);
		*nb = size - uio.uio_resid;
	}

	return error;
}

int
zfsslash2_write_cursor(void *buf, size_t size, void *finfo,
    sl_log_write_t funcp)
{
	file_info_t *info = finfo;

	vnode_t *vp = info->vp;
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

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

	int error = VOP_WRITE(vp, &uio, SLASH2_CURSOR_FLAG, &zrootcreds,
	    NULL, funcp, buf);	/* zfs_write() */

	ZFS_EXIT(zfsvfs);

	return (error);

}

int
zfsslash2_mknod(mdsio_fid_t parent, const char *name, mode_t mode,
    const struct slash_creds *slcrp, struct srt_stat *sstb,
    mdsio_fid_t *mfp, sl_log_update_t logfunc, sl_getslfid_cb_t getslfid)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	if (!(mode & S_IFIFO))
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
	vattr.va_type = VFIFO;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;
	vattr.va_fid = getslfid();

	vnode_t *vp = NULL;

	/* FIXME: check filesystem boundaries */
	error = VOP_CREATE(dvp, (char *)name, &vattr, EXCL, 0, &vp,
	    &cred, 0, NULL, NULL, logfunc);	/* zfs_create() */

	if (error)
		goto out;

	ASSERT(vp);

	error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2fid, FIDLINK_CREATE, vp, NULL, __LINE__);
	if (error)
		goto out;

	if (sstb || mfp)
		error = fill_sstb(vp, mfp, sstb, &cred);

 out:
	if (vp)
		VN_RELE(vp);

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_symlink(const char *link, mdsio_fid_t parent, const char *name,
    const struct slash_creds *slcrp, struct srt_stat *sstb,
    mdsio_fid_t *mfp, sl_getslfid_cb_t getslfid, sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	if (strlen(name) + strlen(link) > SLJ_NAMES_MAX)
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
	vattr.va_fid = getslfid();

	error = VOP_SYMLINK(dvp, (char *)name, &vattr, (char *)link,
	    &cred, NULL, 0, logfunc); /* zfs_symlink() */

	vnode_t *vp = NULL;

	if (error)
		goto out;

	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, &cred,
	    NULL, NULL, NULL);
	if (error)
		goto out;

	error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2fid, FIDLINK_CREATE, vp, NULL, __LINE__);
	if (error)
		goto out;

	ASSERT(vp);

	if (sstb || mfp)
		error = fill_sstb(vp, mfp, sstb, &cred);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(dvp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_rename(mdsio_fid_t parent, const char *name,
    mdsio_fid_t newparent, const char *newname,
    const struct slash_creds *slcrp, sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *p_znode, *np_znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;
	if (strlen(newname) > MAXNAMELEN)
		return ENAMETOOLONG;
	if (strlen(name) + strlen(newname) > SLJ_NAMES_MAX)
		return ENAMETOOLONG;

	int error = zfs_zget(zfsvfs, parent, &p_znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(p_znode);
	vnode_t *p_vp = ZTOV(p_znode);
	ASSERT(p_vp);

	error = zfs_zget(zfsvfs, newparent, &np_znode, B_FALSE);
	if (error) {
		VN_RELE(p_vp);
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(np_znode);
	vnode_t *np_vp = ZTOV(np_znode);
	ASSERT(np_vp);

	error = VOP_RENAME(p_vp, (char *)name, np_vp, (char *)newname,
	    &cred, NULL, 0, logfunc);  /* zfs_rename() */

	VN_RELE(p_vp);
	VN_RELE(np_vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_fsync(const struct slash_creds *slcrp, int datasync,
    void *finfo)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	file_info_t *info = finfo;
	ASSERT(info->vp);
	ASSERT(VTOZ(info->vp));

	vnode_t *vp = info->vp;

	int error = VOP_FSYNC(vp, datasync ? FDSYNC : FSYNC, &cred,
	    NULL);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_link(mdsio_fid_t ino, mdsio_fid_t newparent,
    const char *newname, const struct slash_creds *slcrp,
    struct srt_stat *sstb, sl_log_update_t logfunc)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

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

	error = VOP_LINK(tdvp, svp, (char *)newname, &cred, NULL, 0,
	    logfunc);	/* zfs_link() */

	vnode_t *vp = NULL;
	if (error)
		goto out;

	error = VOP_LOOKUP(tdvp, (char *)newname, &vp, NULL, 0, NULL,
	    &cred, NULL, NULL, NULL);
	if (error)
		goto out;

	ASSERT(vp);

	if (sstb)
		error = fill_sstb(vp, NULL, sstb, &cred);

 out:
	if (vp)
		VN_RELE(vp);
	VN_RELE(tdvp);
	VN_RELE(svp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_access(mdsio_fid_t ino, int mask, const struct slash_creds *slcrp)
{
	cred_t cred = ZFS_INIT_CREDS(slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

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
 * There are two big differences between these functions and those
 * above:
 *  (1) we have to start from the immutable by-id namespace (that's why
 *	we start with zfsslash2_fidlink() instead of zfs_zget());
 *  (2) we don't need to log a replayed operation.
 *
 * It seems to me that I simply can't, as root, create a file owned by
 * an arbitrary regular user directly. There are also some limitations
 * on changing owner and group membership.  As a result, all replay
 * operations are done with their original credentials captured when the
 * corresponding operation was requested.  Note that we only log when
 * ZFS declares the operation is doable.
 *
 * XXX these should be merged with the routines above.
 */

void
zfsslash2_wait_synced(uint64_t txg)
{
	dsl_pool_t *dp;

	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;
	dp = spa_get_dsl(zfsvfs->z_os->os_spa);
	txg_wait_synced(dp, txg);
}

uint64_t
zfsslash2_return_synced(void)
{
	dsl_pool_t *dp;
	uint64_t txg;

	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;
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
//	vap->va_s2blocks	= sstb->sst_nblocks;
//	vap->va_s2blksize	= sstb->sst_blksize;
//	vap->va_s2nlink		= sstb->sst_nlink;

	vap->va_s2atime.tv_sec	= sstb->sst_atime;
	vap->va_s2atime.tv_nsec	= sstb->sst_atime_ns;
	vap->va_s2mtime.tv_sec	= sstb->sst_mtime;
	vap->va_s2mtime.tv_nsec	= sstb->sst_mtime_ns;

//	vap->va_blocks		= sstb->sst_nblocks;
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
zfsslash2_replay_symlink(slfid_t pfid, slfid_t fid, char *name,
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
	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP | FIDLINK_CREATE,
	    NULL, &pvp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, slstrerror(error));
		goto out;
	}

	sstb2vattr(sstb, &vattr);
	vattr.va_type = VLNK;
	vattr.va_mask = AT_TYPE | AT_MODE | AT_ATIME | AT_MTIME |
	    AT_CTIME | AT_SLASH2ATIME | AT_SLASH2MTIME;

	cred.req = NULL;
	cred.cr_uid = sstb->sst_uid;
	cred.cr_gid = sstb->sst_gid;

	error = VOP_SYMLINK(pvp, name, &vattr, link, &cred, NULL,
	    0, NULL); /* zfs_symlink() */
	if (error)
		goto out;

	error = VOP_LOOKUP(pvp, name, &vp, NULL, 0, NULL, &zrootcreds,
	    NULL, NULL, NULL);
	if (error)
		goto out;

	error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2fid,
	    FIDLINK_CREATE, vp, NULL, __LINE__);

 out:
	if (vp)
		VN_RELE(vp);
	if (pvp)
		VN_RELE(pvp);
	return (error);
}

int
zfsslash2_replay_link(slfid_t pfid, slfid_t fid, char *name,
    struct srt_stat *sstb)
{
	vnode_t *pvp, *svp;
	cred_t cred;
	int error;

	pvp = svp = NULL;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP | FIDLINK_CREATE,
	    NULL, &pvp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, slstrerror(error));
		goto out;
	}
	error = zfsslash2_fidlink(fid, FIDLINK_LOOKUP | FIDLINK_CREATE,
	    NULL, &svp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, slstrerror(error));
		goto out;
	}

	cred.req = NULL;
	cred.cr_uid = sstb->sst_uid;
	cred.cr_gid = sstb->sst_gid;

	error = VOP_LINK(pvp, svp, name, &cred, NULL, 0, NULL);	/* zfs_link() */

 out:
	if (svp)
		VN_RELE(svp);
	if (pvp)
		VN_RELE(pvp);
	return (error);
}

int
zfsslash2_replay_mkdir(slfid_t pfid, char *name, struct srt_stat *sstb)
{
	vnode_t *pvp, *tvp;
	vattr_t vattr;
	cred_t cred;
	int error;

	tvp = pvp = NULL;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP | FIDLINK_CREATE,
	    NULL, &pvp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    sstb->sst_fid, slstrerror(error));
		goto out;
	}

	sstb2vattr(sstb, &vattr);
	vattr.va_type = VDIR;
	vattr.va_mask = AT_TYPE | AT_MODE | AT_ATIME | AT_MTIME |
	    AT_CTIME | AT_SLASH2ATIME | AT_SLASH2MTIME;

	cred.req = NULL;
	cred.cr_uid = sstb->sst_uid;
	cred.cr_gid = sstb->sst_gid;

	error = VOP_MKDIR(pvp, name, &vattr, &tvp, &cred, NULL, 0, NULL,
	    NULL); /* zfs_mkdir() */
	if (error)
		goto out;

	error = zfsslash2_fidlink(sstb->sst_fid, FIDLINK_CREATE, tvp, NULL, __LINE__);

 out:
	if (pvp)
		VN_RELE(pvp);
	if (tvp)
		VN_RELE(tvp);
	return (error);
}

int
zfsslash2_replay_create(slfid_t pfid, char *name, struct srt_stat *sstb)
{
	vnode_t *pvp, *tvp;
	vattr_t vattr;
	cred_t cred;
	int error;

	tvp = pvp = NULL;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP,
	    NULL, &pvp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    sstb->sst_fid, slstrerror(errno));
		goto out;
	}

	sstb2vattr(sstb, &vattr);
	vattr.va_type = VREG;
	vattr.va_mask = AT_TYPE | AT_MODE | AT_ATIME | AT_MTIME |
	    AT_CTIME | AT_SLASH2ATIME | AT_SLASH2MTIME;

	cred.req = NULL;
	cred.cr_uid = sstb->sst_uid;
	cred.cr_gid = sstb->sst_gid;

	error = VOP_CREATE(pvp, name, &vattr, EXCL, 0, &tvp, &cred, 0,
	    NULL, NULL, NULL); /* zfs_create() */
	if (error)
		goto out;

	error = zfsslash2_fidlink(sstb->sst_fid, FIDLINK_CREATE, tvp, NULL, __LINE__);

 out:
	if (tvp)
		VN_RELE(tvp);
	if (pvp)
		VN_RELE(pvp);
	return (error);
}

int
zfsslash2_replay_rmdir(slfid_t pfid, slfid_t fid, char *name,
    __unusedx struct srt_stat *sstb)
{
	vnode_t *dvp, *vp;
	int error;

	vp = NULL;
	dvp = NULL;
	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP, NULL, &dvp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, slstrerror(error));
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

	error = VOP_RMDIR(dvp, name, NULL, &zrootcreds, NULL, 0, NULL);		/* zfs_rmdir() */

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if (error == EEXIST)
		error = ENOTEMPTY;

	if (!error) {
		error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2fid,
		    FIDLINK_REMOVE | FIDLINK_DIR, NULL, NULL, __LINE__);
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
zfsslash2_replay_unlink(slfid_t pfid, slfid_t fid, char *name,
    __unusedx struct srt_stat *sstb)
{
	vnode_t *vp, *dvp;
	int error;

	vp = dvp = NULL;
	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP, NULL, &dvp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    fid, slstrerror(errno));
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

	error = VOP_REMOVE(dvp, name, &zrootcreds, NULL, 0, NULL);

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
		error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2fid,
		    FIDLINK_REMOVE, NULL, NULL, __LINE__);

 out:
	if (vp)
		VN_RELE(vp);
	if (dvp)
		VN_RELE(dvp);
	return (error);
}

int
zfsslash2_replay_setattr(slfid_t fid, uint mask, struct srt_stat *sstb)
{
	int error, flag;
	vattr_t vattr;
	vnode_t *vp;

	vp = NULL;
	error = zfsslash2_fidlink(fid, FIDLINK_LOOKUP, NULL, &vp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID, fid);
		goto out;
	}

	sstb2vattr(sstb, &vattr);
	vattr.va_mask = mask;

	flag = (mask & (AT_ATIME | AT_MTIME)) ? ATTR_UTIME : 0;

	error = VOP_SETATTR(vp, &vattr, flag, &zrootcreds, NULL, NULL);		/* zfs_setattr() */

 out:
	if (vp)
		VN_RELE(vp);
	return (error);
}

int
zfsslash2_replay_rename(slfid_t parent, const char *name, slfid_t
    newparent, const char *newname, __unusedx struct srt_stat *stat)
{
	vnode_t *p_vp, *np_vp;
	int error;

	p_vp = np_vp = NULL;
	error = zfsslash2_fidlink(parent, FIDLINK_LOOKUP, NULL, &p_vp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    parent, slstrerror(errno));
		goto out;
	}
	error = zfsslash2_fidlink(newparent, FIDLINK_LOOKUP, NULL, &np_vp, __LINE__);
	if (error) {
		psclog_errorx("failed to look up fid "SLPRI_FID": %s",
		    newparent, slstrerror(errno));
		goto out;
	}

	error = VOP_RENAME(p_vp, (char *)name, np_vp, (char *)newname,
	    &zrootcreds, NULL, 0, NULL);  /* zfs_rename() */
 out:
	if (p_vp)
		VN_RELE(p_vp);
	if (np_vp)
		VN_RELE(np_vp);
	return (error);
}
