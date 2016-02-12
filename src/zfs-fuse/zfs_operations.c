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

#include "fuse.h"

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

#include <errno_compat.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "util.h"
#include "fuse_listener.h"
#include <syslog.h>

#include "slashrpc.h"

#include "slashd/mdsio.h"
#include "slashd/inode.h"

#define ZFS_MAGIC 0x2f52f5

// #define VERBOSE

#ifdef VERBOSE
#define print_debug printf
#else
#define print_debug
#endif

 /* the command-line options */
int block_cache, page_cache;
int cf_enable_xattr = 1;
float fuse_attr_timeout, fuse_entry_timeout;

static void
zfsfuse_getcred(fuse_req_t req, cred_t *cred)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);

	cred->cr_uid = ctx->uid;
	cred->cr_gid = ctx->gid;
	cred->req = req;
}

static void
zfsfuse_destroy(void *userdata)
{
	vfs_t *vfs = (vfs_t *) userdata;

#ifdef DEBUG
	fprintf(stderr, "Calling do_umount()... force %d\n",
	    exit_fuse_listener);
#endif

	/*
	 * If exit_fuse_listener is true, then we received a signal
	 * and we're terminating the process. Therefore we need to
	 * force unmount since there could still be opened files
	 */
	sync();
	while (do_umount(vfs, exit_fuse_listener) != 0)
		sync();
#ifdef DEBUG
	fprintf(stderr, "do_umount() done\n");
#endif
}

static void
zfsfuse_statfs(fuse_req_t req, fuse_ino_t ino)
{
	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);

	struct statvfs64 zfs_stat;

	int ret = VFS_STATVFS(vfs, &zfs_stat);
	if (ret != 0) {
		fuse_reply_err(req, ret);
		return;
	}

	struct statvfs stat = { 0 };

	/*
	 * There's a bug somewhere in FUSE, in the kernel or in df(1)
	 * where f_bsize is being used to calculate filesystem size
	 * instead of f_frsize, so we must use that instead.
	 */
	/* Still there with fuse 2.7.4 apparently (you get a size in To so it shows a lot !) */
	stat.f_bsize = zfs_stat.f_frsize;
	stat.f_frsize = zfs_stat.f_frsize;
	stat.f_blocks = zfs_stat.f_blocks;
	stat.f_bfree = zfs_stat.f_bfree;
	stat.f_bavail = zfs_stat.f_bavail;
	stat.f_files = zfs_stat.f_files;
	stat.f_ffree = zfs_stat.f_ffree;
	stat.f_favail = zfs_stat.f_favail;
	stat.f_fsid = zfs_stat.f_fsid;
	stat.f_flag = zfs_stat.f_flag;
	stat.f_namemax = zfs_stat.f_namemax;

	fuse_reply_statfs(req, &stat);
}

static int
zfsfuse_stat(vnode_t *vp, struct stat *stbuf, cred_t *cred)
{
	ASSERT(vp);
	ASSERT(stbuf);

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;
#ifdef STANDALONE_SLASH2_ATTRS
	vattr.va_mask |= AT_SLASH2SIZE | AT_SLASH2MTIME |
	    AT_SLASH2CTIME;
#endif

	int error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);
	if (error)
		return error;

	memset(stbuf, 0, sizeof(struct stat));

	stbuf->st_dev = vattr.va_fsid;
	stbuf->st_ino = vattr.va_nodeid == 3 ? 1 : vattr.va_nodeid;
	stbuf->st_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	stbuf->st_nlink = vattr.va_nlink;
	stbuf->st_uid = vattr.va_uid;
	stbuf->st_gid = vattr.va_gid;
	if (S_ISCHR(stbuf->st_mode) || S_ISBLK(stbuf->st_mode))
		stbuf->st_rdev = vattr.va_rdev;
	stbuf->st_size = vattr.va_size;
	stbuf->st_blksize = vattr.va_blksize;
	stbuf->st_blocks = vattr.va_nblocks;
#ifdef STANDALONE_SLASH2_ATTRS
	stbuf->st_atime = vattr.va_s2size;
	TIMESTRUC_TO_TIME(vattr.va_s2mtime, &stbuf->st_mtime);
	TIMESTRUC_TO_TIME(vattr.va_ctime, &stbuf->st_ctime);
#else
	TIMESTRUC_TO_TIME(vattr.va_atime, &stbuf->st_atime);
	TIMESTRUC_TO_TIME(vattr.va_mtime, &stbuf->st_mtime);
	TIMESTRUC_TO_TIME(vattr.va_ctime, &stbuf->st_ctime);
#endif

	return 0;
}

static int
zfsfuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	struct stat stbuf;
	error = zfsfuse_stat(vp, &stbuf, &cred);

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_attr(req, &stbuf, fuse_attr_timeout);

	return error;
}

static void
zfsfuse_getattr_helper(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_getattr(req, real_ino, fi);
	if (error)
		fuse_reply_err(req, error);
}

static int
int_zfs_enter(zfsvfs_t *zfsvfs) {
	ZFS_ENTER(zfsvfs);
	return 0;
}

// This macro allows to call ZFS_ENTER from a void function without warning
#define ZFS_VOID_ENTER(a)						\
	if (int_zfs_enter(zfsvfs) != 0) return;

#define XATTR_COMMON()							\
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);			\
	zfsvfs_t *zfsvfs = vfs->vfs_data;				\
	if (ino == 1) ino = 3;						\
									\
	ZFS_VOID_ENTER(zfsvfs);						\
									\
	znode_t *znode;							\
									\
	int error = zfs_zget(zfsvfs, ino, &znode, B_FALSE);		\
	if (error) {							\
		ZFS_EXIT(zfsvfs);					\
		fuse_reply_err(req, error == EEXIST ? ENOENT : error);	\
		return;							\
	}								\
									\
	ASSERT(znode != NULL);						\
	vnode_t *dvp = ZTOV(znode);					\
	ASSERT(dvp != NULL);						\
									\
	vnode_t *vp = NULL;						\
									\
	cred_t cred;							\
	zfsfuse_getcred(req, &cred);

/*
 * This macro makes the lookup for the xattr directory, necessary for
 * listxattr, getxattr and setxattr.
 */
#define MY_LOOKUP_XATTR(flg)						\
	error = VOP_LOOKUP(dvp, "", &vp, NULL, LOOKUP_XATTR | (flg),	\
	    NULL, &cred, NULL, NULL, NULL);				\
	if (error || vp == NULL) {					\
		if (error == ENOENT)					\
			error = ENOATTR;				\
		else if (error != EACCES)				\
			error = ENOSYS;					\
		goto out;						\
	}

static void
zfsfuse_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	if (!cf_enable_xattr) {
		fuse_reply_err(req, ENOSYS);
		return;
	}
	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN)];
		struct dirent64 dirent;
	} entry;

	XATTR_COMMON();
	/* It's like a lookup, but passing LOOKUP_XATTR as a flag to VOP_LOOKUP */
	MY_LOOKUP_XATTR(0);

	error = VOP_OPEN(&vp, FREAD, &cred, NULL);
	if (error)
		goto out;

	// Now try a readdir...
	char *outbuf = NULL;
	int alloc = 0,used = 0;

	struct stat fstat = { 0 };

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

		error = VOP_READDIR(vp, &uio, &cred, &eofp, NULL, 0);	/* zfs_readdir() */
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
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	if (error)
		fuse_reply_err(req,error);
}

static void
zfsfuse_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
    const char *value, size_t size, int flags)
{
	if (!cf_enable_xattr) {
		fuse_reply_err(req, ENOSYS);
		return;
	}
	XATTR_COMMON();
	MY_LOOKUP_XATTR(CREATE_XATTR_DIR);

	/*
	 * Now the idea is to create a file inside the xattr directory with
	 * the wanted attribute.
	 */

	vattr_t vattr;
	vattr.va_type = VREG;
	vattr.va_mode = 0660;
	vattr.va_mask = AT_TYPE|AT_MODE|AT_SIZE;
	vattr.va_size = 0;

	vnode_t *new_vp;
	error = VOP_CREATE(vp, (char *) name, &vattr, NONEXCL, VWRITE,
	    &new_vp, &cred, &cred, 0, NULL, NULL, NULL);
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

	error = VOP_WRITE(vp, &uio, FWRITE, &cred, NULL, NULL, NULL);
	if (error)
		goto out;
	error = VOP_CLOSE(vp, FWRITE, 1, (offset_t) 0, &cred, NULL);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	/*
	 * The fuse_reply_err at the end seems to be an mandatory even
	 * if there is no error.
	 */
	fuse_reply_err(req,error);
}

void
zfsfuse_fill_sstb(const vnode_t *vp, const vattr_t *vattr,
    struct srt_stat *sstb)
{
	sstb->sst_fid = VTOZ(vp)->z_phys->zp_s2fid;
	sstb->sst_gen = VTOZ(vp)->z_phys->zp_s2gen;
	sstb->sst_dev = vattr->va_fsid;
	sstb->sst_ptruncgen = vattr->va_ptruncgen;
	sstb->sst_utimgen = vattr->va_s2utimgen;
	sstb->sst_mode = VTTOIF(vattr->va_type) | vattr->va_mode;
	sstb->sst_nlink = vattr->va_nlink;
	if (sstb->sst_nlink > 1)
		sstb->sst_nlink--;
	sstb->sst_uid = vattr->va_uid;
	sstb->sst_gid = vattr->va_gid;
	sstb->sst_rdev = vattr->va_rdev;
	sstb->sst_blksize = 512 * 1024;
	sstb->sst_size = vattr->va_s2size;
	sstb->sst_blocks = vattr->va_s2nblks;
	sstb->sst_atime = vattr->va_atime.tv_sec;
	sstb->sst_atime_ns = vattr->va_atime.tv_nsec;
	sstb->sst_mtime = vattr->va_s2mtime.tv_sec;
	sstb->sst_mtime_ns = vattr->va_s2mtime.tv_nsec;
	sstb->sst_ctime = vattr->va_ctime.tv_sec;
	sstb->sst_ctime_ns = vattr->va_ctime.tv_nsec;
}

int
zfsfuse_simple_read(vnode_t *vp, cred_t *cr, void *buf, off_t off,
    size_t len, size_t *outsz)
{
	int error;

	iovec_t iov;
	uio_t uio;

	iov.iov_base = buf;
	iov.iov_len = len;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;
	uio.uio_resid = len;
	uio.uio_loffset = off;

	error = VOP_READ(vp, &uio, FREAD, cr, NULL);
	*outsz = uio.uio_loffset - off;
	return (error);
}

struct fullattrs {
	uint64_t		metasize;
	struct srt_stat		sstb;
	struct slm_ino_od	ino;
	uint64_t		ino_crc;
	struct slm_inox_od	inox;
	uint64_t		inox_crc;
};

int
zfsfuse_getxattr_sl2(fuse_req_t req, vnode_t *vp, cred_t *cr,
    const char *name, size_t size)
{
	union {
		struct fullattrs fullattrs;
		char field[32];
	} buf;
	struct fullattrs *fa = &buf.fullattrs;
	struct slm_inox_od *inox = &fa->inox;
	struct slm_ino_od *ino = &fa->ino;
	struct srt_stat *sstb = &fa->sstb;
	int tn, n = 0, error, e2 = 0;
	vattr_t vattr;
	size_t rc;

	memset(&vattr, 0, sizeof(vattr));
	error = VOP_GETATTR(vp, &vattr, 0, cr, NULL);
	if (error)
		return (error);

	if (strcmp(name, SLXAT_FSIZE) == 0) {
		n = snprintf(buf.field, size ? sizeof(buf.field) : 0,
		    "%llu", vattr.va_s2size);
		if (n != -1)
			n++;
	} else if (strcmp(name, SLXAT_NBLKS) == 0) {
		n = snprintf(buf.field, size ? sizeof(buf.field) : 0,
		    "%lu", vattr.va_s2nblks);
		if (n != -1)
			n++;
	} else if (strcmp(name, SLXAT_FGEN) == 0) {
		n = snprintf(buf.field, size ? sizeof(buf.field) : 0,
		    "%lu", vattr.va_s2gen);
		if (n != -1)
			n++;
	} else if (strcmp(name, SLXAT_FID) == 0) {
		n = snprintf(buf.field, size ? sizeof(buf.field) : 0,
		    "%"PRIx64, VTOZ(vp)->z_phys->zp_s2fid);
		if (n != -1)
			n++;
	} else if (strcmp(name, SLXAT_STAT) == 0) {
		fa->metasize = vattr.va_size;
		zfsfuse_fill_sstb(vp, &vattr, sstb);
		n = sizeof(fa->metasize) + sizeof(*sstb);
	} else if (strcmp(name, SLXAT_INOSTAT) == 0) {
		n = sizeof(fa->metasize) + sizeof(*sstb);
		fa->metasize = vattr.va_size;
		zfsfuse_fill_sstb(vp, &vattr, sstb);

		error = VOP_OPEN(&vp, FREAD, cr, NULL);
		if (error)
			goto out;
		tn = sizeof(*ino) + sizeof(fa->ino_crc);
		n += tn;
		error = zfsfuse_simple_read(vp, cr, ino, 0, tn, &rc);
		if (error == 0 && rc != tn)
			error = EIO;
		e2 = VOP_CLOSE(vp, FREAD, 1, (offset_t)0, cr, NULL);
		if (e2)
			error = e2;

	} else if (strcmp(name, SLXAT_INOXSTAT) == 0) {
		n = sizeof(fa->metasize) + sizeof(*sstb);
		fa->metasize = vattr.va_size;
		zfsfuse_fill_sstb(vp, &vattr, sstb);

		error = VOP_OPEN(&vp, FREAD, cr, NULL);
		if (error)
			goto out;

		tn = sizeof(*ino) + sizeof(fa->ino_crc);
		n += tn;
		error = zfsfuse_simple_read(vp, cr, ino, 0, tn, &rc);
		if (error == 0 && rc != tn)
			error = EIO;

		tn = sizeof(*inox) + sizeof(fa->inox_crc);
		n += tn;
		e2 = zfsfuse_simple_read(vp, cr, inox,
		    SL_EXTRAS_START_OFF, tn, &rc);
		if (e2)
			error = e2;
		else if (rc != tn)
			error = EIO;

		e2 = VOP_CLOSE(vp, FREAD, 1, (offset_t)0, cr, NULL);
		if (e2)
			error = e2;
	} else {
		error = ENOATTR;
	}

 out:
	if (error)
		return (error);
	if (n == -1)
		return (errno);
	if (size && size < n)
		return (ERANGE);
	if (size == 0)
		fuse_reply_xattr(req, n);
	else
		fuse_reply_buf(req, buf.field, n);
	return (0);
}

static void
zfsfuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
    size_t size)
{
	if (!cf_enable_xattr) {
		fuse_reply_err(req, ENOSYS);
		return;
	}
	XATTR_COMMON();

	if (strncmp(name, ".sl2-", 5) == 0) {
		error = zfsfuse_getxattr_sl2(req, dvp, &cred, name,
		    size);
		goto out;
	}

	MY_LOOKUP_XATTR(0);

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
	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;

	/*
	 * We are obliged to get the size 1st because of the stupid
	 * handling of the size parameter.
	 */
	error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL);
	if (error)
		goto out;
	if (size == 0) {
		fuse_reply_xattr(req,vattr.va_size);
		goto out;
	} else if (size < vattr.va_size) {
		// fuse_reply_err ?
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
	// XXX size is not checked
	fuse_reply_buf(req,buf,vattr.va_size);
	free(buf);
	error = VOP_CLOSE(vp, FREAD, 1, (offset_t) 0, &cred, NULL);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	if (error)
		fuse_reply_err(req,error);
}

static void
zfsfuse_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	if (!cf_enable_xattr) {
		fuse_reply_err(req, ENOSYS);
		return;
	}
	XATTR_COMMON();
	MY_LOOKUP_XATTR(0);
	error = VOP_REMOVE(vp, (char *) name, &cred, NULL, 0, NULL, NULL);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	if (error == ENOENT)
		error = ENOATTR;
	fuse_reply_err(req,error);
}

static int zfsfuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	if (strlen(name) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_TRUE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;

	cred_t cred;
	zfsfuse_getcred(req, &cred);
	struct fuse_entry_param e = { 0 };

	/* > 0.0 gives a 40% performance boost in bonnie 0-byte file tests */
	e.attr_timeout = fuse_attr_timeout;
	/* > 0.0 gives you a 10000% performance boost in stat() calls, but unfortunately you get a security issue. */
	e.entry_timeout = fuse_entry_timeout;

	error = VOP_LOOKUP(dvp, (char *) name, &vp, NULL, 0, NULL,
	    &cred, NULL, NULL, NULL);
	if (error) {
		if (error == ENOENT) {
			error = 0;
			e.ino = 0;
		}
		goto out;
	}

	if (vp == NULL)
		goto out;

	e.ino = VTOZ(vp)->z_id;
	if (e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_entry(req, &e);

	return error;
}

static void
zfsfuse_lookup_helper(fuse_req_t req, fuse_ino_t parent,
    const char *name)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_lookup(req, real_parent, name);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_opendir(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	/*
	 * Check permissions.
	 */
	if (!(vfs->fuse_attribute & FUSE_VFS_HAS_DEFAULT_PERM)) {
		if (error = VOP_ACCESS(vp, VREAD | VEXEC, 0, &cred, NULL))
			goto out;
	}

	vnode_t *old_vp = vp;

	/* XXX: not sure about flags */
	error = VOP_OPEN(&vp, FREAD, &cred, NULL);

	ASSERT(old_vp == vp);

	if (!error) {
		file_info_t *info = kmem_cache_alloc(file_info_cache,
		    KM_NOSLEEP);
		if (info == NULL) {
			error = ENOMEM;
			goto out;
		}

		info->vp = vp;
		info->flags = FREAD;

		fi->fh = (uint64_t) (uintptr_t) info;
	}

 out:
	if (error)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_open(req, fi);

	return error;
}

static void
zfsfuse_opendir_helper(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_opendir(req, real_ino, fi);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);
	ASSERT(VTOZ(info->vp)->z_id == ino);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int error = VOP_CLOSE(info->vp, info->flags, 1, (offset_t) 0,
	    &cred, NULL);
	if (error)
		syslog(LOG_WARNING, "zfsfuse_release: stale inode (%s)?",
		    strerror(error));
	else {
		VN_RELE(info->vp);
		kmem_cache_free(file_info_cache, info);
	}

	ZFS_EXIT(zfsvfs);

	return error;
}

static void
zfsfuse_release_helper(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_release(req, real_ino, fi);
	/* Release events always reply_err */
	fuse_reply_err(req, error);
}

static int
zfsfuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	vnode_t *vp = ((file_info_t *)(uintptr_t) fi->fh)->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

	if (vp->v_type != VDIR)
		return ENOTDIR;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	char *outbuf = kmem_alloc(size, KM_NOSLEEP);
	if (outbuf == NULL)
		return ENOMEM;

	ZFS_ENTER(zfsvfs);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN)];
		struct dirent64 dirent;
	} entry;

	struct stat fstat = { 0 };

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

		/* No more room */
		int dsize = fuse_add_direntry(req, NULL, 0,
		    entry.dirent.d_name, NULL, 0);
		if (dsize > outbuf_resid)
			break;

		fstat.st_ino = entry.dirent.d_ino;
		fstat.st_mode = entry.dirent.d_type << 12;

		outbuf_resid -= dsize;
		fuse_add_direntry(req, outbuf + outbuf_off, dsize,
		    entry.dirent.d_name, &fstat, entry.dirent.d_off);

		outbuf_off += dsize;
		next = entry.dirent.d_off;
	}

 out:
	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_buf(req, outbuf, outbuf_off);

	kmem_free(outbuf, size);

	return error;
}

static void
zfsfuse_readdir_helper(fuse_req_t req, fuse_ino_t ino, size_t size,
    off_t off, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_readdir(req, real_ino, size, off, fi);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_opencreate(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi, int fflags, mode_t createmode,
    const char *name)
{
	if (name && strlen(name) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	if (flags & FCREAT) {
		enum vcexcl excl;

		/*
		 * Wish to create a file.
		 */
		vattr_t vattr;
		memset(&vattr, 0, sizeof(vattr_t));
		vattr.va_type = VREG;
		vattr.va_mode = createmode;
		vattr.va_mask = AT_TYPE|AT_MODE;
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
		error = VOP_CREATE(vp, (char *) name, &vattr, excl,
		    mode, &new_vp, &cred, &cred, 0, NULL, NULL, NULL);

		if (error)
			goto out;

		VN_RELE(vp);
		vp = new_vp;
	} else {
		/*
		 * Get the attributes to check whether file is large.
		 * We do this only if the O_LARGEFILE flag is not set and
		 * only for regular files.
		 */
		if (!(flags & FOFFMAX) && (vp->v_type == VREG)) {
			vattr_t vattr;
			vattr.va_mask = AT_SIZE;
			if ((error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL)))
				goto out;

			if (vattr.va_size > (u_offset_t) MAXOFF32_T) {
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
			if (error = VOP_ACCESS(vp, mode, 0, &cred, NULL)) {
				print_debug("open fails on access\n");
				goto out;
			}
		}
	}

	if ((flags & FNOFOLLOW) && vp->v_type == VLNK) {
		error = ELOOP;
		goto out;
	}

	vnode_t *old_vp = vp;

	error = VOP_OPEN(&vp, flags, &cred, NULL);

	ASSERT(old_vp == vp);

	if (error)
		goto out;

	struct fuse_entry_param e = { 0 };

	if (flags & FCREAT) {
		error = zfsfuse_stat(vp, &e.attr, &cred);
		if (error)
			goto out;
	}

	file_info_t *info = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if (info == NULL) {
		error = ENOMEM;
		goto out;
	}

	info->vp = vp;
	info->flags = flags;

	fi->fh = (uint64_t) (uintptr_t) info;
	/* by setting these as int directly, we save one CMP operation per file open. */
	/* but, honestly, we mostly get readability of the code */
	fi->keep_cache = page_cache;
	fi->direct_io = block_cache ? 0 : 1;

	if (flags & FCREAT) {
		e.attr_timeout = fuse_attr_timeout;
		e.entry_timeout = fuse_entry_timeout;
		e.ino = VTOZ(vp)->z_id;
		if (e.ino == 3)
			e.ino = 1;
		e.generation = VTOZ(vp)->z_phys->zp_gen;
	}

 out:
	if (error) {
		ASSERT(vp->v_count > 0);
		VN_RELE(vp);
	}

	ZFS_EXIT(zfsvfs);

	if (!error) {
		if (!(flags & FCREAT))
			fuse_reply_open(req, fi);
		else
			fuse_reply_create(req, &e, fi);
	}
	return error;
}

static void
zfsfuse_open_helper(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_opencreate(req, real_ino, fi, fi->flags, 0,
	    NULL);
	if (error)
		fuse_reply_err(req, error);
}

static void
zfsfuse_create_helper(fuse_req_t req, fuse_ino_t parent,
    const char *name, mode_t mode, struct fuse_file_info *fi)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_opencreate(req, real_parent, fi, fi->flags |
	    O_CREAT, mode, name);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	char buffer[PATH_MAX + 1];

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;
	iovec.iov_base = buffer;
	iovec.iov_len = sizeof(buffer) - 1;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = 0;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_READLINK(vp, &uio, &cred, NULL);

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if (!error) {
		VERIFY(uio.uio_loffset < sizeof(buffer));
		buffer[uio.uio_loffset] = '\0';
		fuse_reply_readlink(req, buffer);
	}

	return error;
}

static void
zfsfuse_readlink_helper(fuse_req_t req, fuse_ino_t ino)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_readlink(req, real_ino);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;

	vnode_t *vp = info->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	char *outbuf = kmem_alloc(size, KM_NOSLEEP);
	if (outbuf == NULL)
		return ENOMEM;

	ZFS_ENTER(zfsvfs);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = outbuf;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = off;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int error = VOP_READ(vp, &uio, info->flags, &cred, NULL);

	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_buf(req, outbuf, uio.uio_loffset - off);

	kmem_free(outbuf, size);

	return error;
}

static void
zfsfuse_read_helper(fuse_req_t req, fuse_ino_t ino, size_t size,
    off_t off, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_read(req, real_ino, size, off, fi);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
    mode_t mode)
{
	if (strlen(name) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;

	vattr_t vattr = { 0 };
	vattr.va_type = VDIR;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_MKDIR(dvp, (char *) name, &vattr, &vp, &cred, &cred, NULL,
	    0, NULL, NULL);  /* zfs_mkdir() */
	if (error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = fuse_attr_timeout;
	e.entry_timeout = fuse_entry_timeout;

	e.ino = VTOZ(vp)->z_id;
	if (e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_entry(req, &e);

	return error;
}

static void
zfsfuse_mkdir_helper(fuse_req_t req, fuse_ino_t parent,
    const char *name, mode_t mode)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_mkdir(req, real_parent, name, mode);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	if (strlen(name) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	/* FUSE doesn't care if we remove the current working directory
	   so we just pass NULL as the cwd parameter (no problem for ZFS) */
	error = VOP_RMDIR(dvp, (char *) name, NULL, &cred, NULL, 0, NULL);

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if (error == EEXIST)
		error = ENOTEMPTY;

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

static void
zfsfuse_rmdir_helper(fuse_req_t req, fuse_ino_t parent,
    const char *name)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_rmdir(req, real_parent, name);
	/* rmdir events always reply_err */
	fuse_reply_err(req, error);
}

static int
zfsfuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
    int to_set, struct fuse_file_info *fi)
{
	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	vnode_t *vp;
	boolean_t release;

	int error;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	if (fi == NULL) {
		znode_t *znode;

		error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
		if (error) {
			ZFS_EXIT(zfsvfs);
			/* If the inode we are trying to get was recently deleted
			   dnode_hold_impl will return EEXIST instead of ENOENT */
			return error == EEXIST ? ENOENT : error;
		}
		ASSERT(znode != NULL);
		vp = ZTOV(znode);
		release = B_TRUE;
	} else {
		file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
		vp = info->vp;
		release = B_FALSE;

		/*
		 * Special treatment for ftruncate().
		 * This is needed because otherwise ftruncate() would
		 * fail with permission denied on read-only files.
		 * (Solaris calls VOP_SPACE instead of VOP_SETATTR on
		 * ftruncate).
		 */
		if (to_set & FUSE_SET_ATTR_SIZE) {
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
			bf.l_start = attr->st_size;
			bf.l_type = F_WRLCK;
			bf.l_len = (off_t) 0;

			/* FIXME: check locks */
			error = VOP_SPACE(vp, F_FREESP, &bf,
			    info->flags, 0, &cred, NULL);
			if (error)
				goto out;

			to_set &= ~FUSE_SET_ATTR_SIZE;
			if (to_set == 0)
				goto out;
		}
	}

	ASSERT(vp != NULL);

	vattr_t vattr = { 0 };

	if (to_set & FUSE_SET_ATTR_MODE) {
		vattr.va_mask |= AT_MODE;
		vattr.va_mode = attr->st_mode;
	}
	if (to_set & FUSE_SET_ATTR_UID) {
		vattr.va_mask |= AT_UID;
		vattr.va_uid = attr->st_uid;
		if (vattr.va_uid > MAXUID) {
			error = EINVAL;
			goto out;
		}
	}
	if (to_set & FUSE_SET_ATTR_GID) {
		vattr.va_mask |= AT_GID;
		vattr.va_gid = attr->st_gid;
		if (vattr.va_gid > MAXUID) {
			error = EINVAL;
			goto out;
		}
	}
	if (to_set & FUSE_SET_ATTR_SIZE) {
		vattr.va_mask |= AT_SIZE;
		vattr.va_size = attr->st_size;
	}
	if (to_set & FUSE_SET_ATTR_ATIME) {
		vattr.va_mask |= AT_ATIME;
		TIME_TO_TIMESTRUC(attr->st_atime, &vattr.va_atime);
	}
	if (to_set & FUSE_SET_ATTR_MTIME) {
		vattr.va_mask |= AT_MTIME;
		TIME_TO_TIMESTRUC(attr->st_mtime, &vattr.va_mtime);
	}

	int flags = (to_set & (FUSE_SET_ATTR_ATIME |
	    FUSE_SET_ATTR_MTIME)) ? ATTR_UTIME : 0;
	error = VOP_SETATTR(vp, &vattr, flags, &cred, NULL, NULL);

 out:
	;
	struct stat stat_reply;

	if (!error)
		error = zfsfuse_stat(vp, &stat_reply, &cred);

	/* Do not release if vp was an opened inode */
	if (release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_attr(req, &stat_reply, fuse_attr_timeout);

	return error;
}

static void
zfsfuse_setattr_helper(fuse_req_t req, fuse_ino_t ino,
    struct stat *attr, int to_set, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_setattr(req, real_ino, attr, to_set, fi);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	if (strlen(name) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_REMOVE(dvp, (char *) name, &cred, NULL, 0, NULL,
	    NULL);

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

static void
zfsfuse_unlink_helper(fuse_req_t req, fuse_ino_t parent,
    const char *name)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_unlink(req, real_parent, name);
	/* unlink events always reply_err */
	fuse_reply_err(req, error);
}

static int
zfsfuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
    size_t size, off_t off, struct fuse_file_info *fi)
{
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;

	vnode_t *vp = info->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = (void *) buf;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = off;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int error = VOP_WRITE(vp, &uio, info->flags, &cred, NULL, NULL,
	    NULL);

	ZFS_EXIT(zfsvfs);

	if (!error) {
		/* When not using direct_io, we must always write 'size' bytes */
		VERIFY(uio.uio_resid == 0);
		fuse_reply_write(req, size - uio.uio_resid);
	}

	return error;
}

static void
zfsfuse_write_helper(fuse_req_t req, fuse_ino_t ino, const char *buf,
    size_t size, off_t off, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_write(req, real_ino, buf, size, off, fi);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
    mode_t mode, dev_t rdev)
{
	if (strlen(name) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	vattr_t vattr;
	vattr.va_type = IFTOVT(mode);
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;

	if (mode & (S_IFCHR | S_IFBLK)) {
		vattr.va_rdev = rdev;
		vattr.va_mask |= AT_RDEV;
	}

	vnode_t *vp = NULL;

	/* FIXME: check filesystem boundaries */
	error = VOP_CREATE(dvp, (char *) name, &vattr, EXCL, 0, &vp,
	    &cred, &cred, 0, NULL, NULL, NULL);

	VN_RELE(dvp);

	if (error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = fuse_attr_timeout;
	e.entry_timeout = fuse_entry_timeout;

	e.ino = VTOZ(vp)->z_id;
	if (e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_entry(req, &e);

	return error;
}

static void
zfsfuse_mknod_helper(fuse_req_t req, fuse_ino_t parent,
    const char *name, mode_t mode, dev_t rdev)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_mknod(req, real_parent, name, mode, rdev);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
    const char *name)
{
	if (strlen(name) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	vattr_t vattr;
	vattr.va_type = VLNK;
	vattr.va_mode = 0777;
	vattr.va_mask = AT_TYPE | AT_MODE;

	error = VOP_SYMLINK(dvp, (char *) name, &vattr, (char *) link,
	    &cred, &cred, NULL, 0, NULL);

	vnode_t *vp = NULL;

	if (error)
		goto out;

	error = VOP_LOOKUP(dvp, (char *) name, &vp, NULL, 0, NULL,
	    &cred, NULL, NULL, NULL);
	if (error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = fuse_attr_timeout;
	e.entry_timeout = fuse_entry_timeout;

	e.ino = VTOZ(vp)->z_id;
	if (e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);

	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_entry(req, &e);

	return error;
}

static void
zfsfuse_symlink_helper(fuse_req_t req, const char *link,
    fuse_ino_t parent, const char *name)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_symlink(req, link, real_parent, name);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
    fuse_ino_t newparent, const char *newname)
{
	if (strlen(name) >= MAXNAMELEN)
		return ENAMETOOLONG;
	if (strlen(newname) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *p_znode, *np_znode;

	int error = zfs_zget(zfsvfs, parent, &p_znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(p_znode != NULL);

	error = zfs_zget(zfsvfs, newparent, &np_znode, B_FALSE);
	if (error) {
		VN_RELE(ZTOV(p_znode));
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(np_znode != NULL);

	vnode_t *p_vp = ZTOV(p_znode);
	vnode_t *np_vp = ZTOV(np_znode);
	ASSERT(p_vp != NULL);
	ASSERT(np_vp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_RENAME(p_vp, (char *) name, np_vp, (char *) newname,
	    &cred, NULL, 0, NULL, NULL);

	VN_RELE(p_vp);
	VN_RELE(np_vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

static void
zfsfuse_rename_helper(fuse_req_t req, fuse_ino_t parent,
    const char *name, fuse_ino_t newparent, const char *newname)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;
	fuse_ino_t real_newparent = newparent == 1 ? 3 : newparent;

	int error = zfsfuse_rename(req, real_parent, name,
	    real_newparent, newname);

	/* rename events always reply_err */
	fuse_reply_err(req, error);
}

static int
zfsfuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);
	ASSERT(VTOZ(info->vp)->z_id == ino);

	vnode_t *vp = info->vp;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int error = VOP_FSYNC(vp, datasync ? FDSYNC : FSYNC, &cred,
	    NULL);

	ZFS_EXIT(zfsvfs);

	return error;
}

static void
zfsfuse_fsync_helper(fuse_req_t req, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_fsync(req, real_ino, datasync, fi);

	/* fsync events always reply_err */
	fuse_reply_err(req, error);
}

static int
zfsfuse_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
    const char *newname)
{
	if (strlen(newname) >= MAXNAMELEN)
		return ENAMETOOLONG;

	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *td_znode, *s_znode;

	int error = zfs_zget(zfsvfs, ino, &s_znode, B_FALSE);
	if (error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(s_znode != NULL);

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
	ASSERT(svp != NULL);
	ASSERT(tdvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_LINK(tdvp, svp, (char *) newname, &cred, NULL, 0,
	    NULL);

	vnode_t *vp = NULL;

	if (error)
		goto out;

	error = VOP_LOOKUP(tdvp, (char *) newname, &vp, NULL, 0, NULL,
	    &cred, NULL, NULL, NULL);
	if (error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = fuse_attr_timeout;
	e.entry_timeout = fuse_entry_timeout;

	e.ino = VTOZ(vp)->z_id;
	if (e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(tdvp);
	VN_RELE(svp);

	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_entry(req, &e);

	return error;
}

static void
zfsfuse_link_helper(fuse_req_t req, fuse_ino_t ino,
    fuse_ino_t newparent, const char *newname)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;
	fuse_ino_t real_newparent = newparent == 1 ? 3 : newparent;

	int error = zfsfuse_link(req, real_ino, real_newparent, newname);
	if (error)
		fuse_reply_err(req, error);
}

static int
zfsfuse_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	print_debug("function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

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

static void
zfsfuse_access_helper(fuse_req_t req, fuse_ino_t ino, int mask)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_access(req, real_ino, mask);

	/* access events always reply_err */
	fuse_reply_err(req, error);
}

struct fuse_lowlevel_ops zfs_operations = {
	.open       = zfsfuse_open_helper,
	.read       = zfsfuse_read_helper,
	.write      = zfsfuse_write_helper,
	.release    = zfsfuse_release_helper,
	.opendir    = zfsfuse_opendir_helper,
	.readdir    = zfsfuse_readdir_helper,
	.releasedir = zfsfuse_release_helper,
	.lookup     = zfsfuse_lookup_helper,
	.getattr    = zfsfuse_getattr_helper,
	.readlink   = zfsfuse_readlink_helper,
	.mkdir      = zfsfuse_mkdir_helper,
	.rmdir      = zfsfuse_rmdir_helper,
	.create     = zfsfuse_create_helper,
	.unlink     = zfsfuse_unlink_helper,
	.mknod      = zfsfuse_mknod_helper,
	.symlink    = zfsfuse_symlink_helper,
	.link       = zfsfuse_link_helper,
	.rename     = zfsfuse_rename_helper,
	.setattr    = zfsfuse_setattr_helper,
	.fsync      = zfsfuse_fsync_helper,
	.fsyncdir   = zfsfuse_fsync_helper,
	.access     = zfsfuse_access_helper,
	.statfs     = zfsfuse_statfs,
	.destroy    = zfsfuse_destroy,
	.listxattr  = zfsfuse_listxattr,
	.setxattr   = zfsfuse_setxattr,
	.getxattr   = zfsfuse_getxattr,
	.removexattr= zfsfuse_removexattr,
};
