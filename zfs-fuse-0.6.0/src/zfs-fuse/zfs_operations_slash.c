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

#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/cred_impl.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/mode.h>
#include <sys/fcntl.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "util.h"

#include "fid.h"
#include "slashrpc.h"
#include "zfs_slashlib.h"
#include "slashd/mdsio.h"

kmem_cache_t	*file_info_cache;
cred_t		 zrootcreds;
vfs_t		*zfsVfs;			/* initialized by do_mount() */

/* flags for zfsslash2_fidlink() */
#define	FIDLINK_CREATE		0x01
#define	FIDLINK_LOOKUP		0x02
#define	FIDLINK_REMOVE		0x04

#define SL_PATH_PREFIX	".sl"
#define SL_PATH_FIDNS	".slfidns"

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
			fgp->fg_fid = VTOZ(vp)->z_phys->zp_s2id;
		fgp->fg_gen = VTOZ(vp)->z_phys->zp_s2gen;
	}
	if (mfp)
		*mfp = VTOZ(vp)->z_id;
}

#define ZFS_CONVERT_CREDS(cred, slcrp)				\
	cred_t _credentials = { (slcrp)->uid, (slcrp)->gid };	\
	cred_t *cred = &_credentials

#define FUSE_NAME_OFFSET ((unsigned long) ((struct fuse_dirent *) 0)->name)
#define FUSE_DIRENT_ALIGN(x) (((x) + sizeof(__uint64_t) - 1) & ~(sizeof(__uint64_t) - 1))
#define FUSE_DIRENT_SIZE(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)

struct fuse_dirent {
	uint64_t	ino;
	uint64_t	off;
	uint32_t	namelen;
	uint32_t	type;
	char name[0];
};

size_t fuse_dirent_size(size_t namelen)
{
	return FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
}

char *fuse_add_dirent(char *buf, const char *name, const struct stat *stbuf,
    off_t off)
{
	unsigned namelen = strlen(name);
	unsigned entlen = FUSE_NAME_OFFSET + namelen;
	unsigned entsize = fuse_dirent_size(namelen);
	unsigned padlen = entsize - entlen;
	struct fuse_dirent *dirent = (struct fuse_dirent *)buf;

	dirent->ino = stbuf->st_ino;
	dirent->off = off;
	dirent->namelen = namelen;
	dirent->type = (stbuf->st_mode & 0170000) >> 12;
	strncpy(dirent->name, name, namelen);
	if (padlen)
		memset(buf + entlen, 0, padlen);

	return buf + entsize;
}

size_t fuse_add_direntry(fuse_req_t req, char *buf, size_t bufsize,
    const char *name, const struct stat *stbuf, off_t off)
{
	size_t entsize;

	(void)req;
	entsize = fuse_dirent_size(strlen(name));
	if (entsize <= bufsize && buf)
		fuse_add_dirent(buf, name, stbuf, off);
	return entsize;
}

static __inline int
hide_vnode(vnode_t *dvp, vnode_t *vp, const char *cpn)
{
	if (FID_GET_FLAGS(VTOZ(vp)->z_phys->zp_s2id) & SLFIDF_HIDE_DENTRY)
		return (1);

	if (VTOZ(dvp)->z_id == MDSIO_FID_ROOT &&
	    strncmp(cpn, SL_PATH_PREFIX, strlen(SL_PATH_PREFIX)) == 0)
		return (1);
	return (0);
}

void
zfsslash2_destroy(void)
{
	struct timespec req;
	req.tv_sec = 0;
	req.tv_nsec = 100000000; /* 100 ms */

#ifdef DEBUG
	fprintf(stderr, "Calling do_umount()...\n");
#endif
	/*
	 * If exit_fuse_listener is true, then we received a signal
	 * and we're terminating the process. Therefore we need to
	 * force unmount since there could still be opened files
	 */
	while (do_umount(zfsVfs, 0) != 0)
		nanosleep(&req, NULL);
#ifdef DEBUG
	fprintf(stderr, "do_umount() done\n");
#endif
}

int
zfsslash2_statfs(struct statvfs *stat)
{
	struct statvfs64 zfs_stat;

	int ret = VFS_STATVFS(zfsVfs, &zfs_stat);
	if (ret != 0)
		return (ret);

	/* There's a bug somewhere in FUSE, in the kernel or in df(1) where
	   f_bsize is being used to calculate filesystem size instead of
	   f_frsize, so we must use that instead */
	/* Still there with fuse 2.7.4 apparently (you get a size in To so it shows a lot !) */
	stat->f_bsize = zfs_stat.f_frsize;
	stat->f_frsize = zfs_stat.f_frsize;
	stat->f_blocks = zfs_stat.f_blocks;
	stat->f_bfree = zfs_stat.f_bfree;
	stat->f_bavail = zfs_stat.f_bavail;
	stat->f_files = zfs_stat.f_files;
	stat->f_ffree = zfs_stat.f_ffree;
	stat->f_favail = zfs_stat.f_favail;
	stat->f_fsid = zfs_stat.f_fsid;
	stat->f_flag = zfs_stat.f_flag;
	stat->f_namemax = zfs_stat.f_namemax;

	return (0);
}

int
zfsslash2_stat(vnode_t *vp, struct srt_stat *sstb, cred_t *cred)
{
	struct slash_fidgen fg;

	ASSERT(vp != NULL);
	ASSERT(sstb != NULL);

	vattr_t vattr;

	int error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);	/* zfs_getattr() */
	if (error)
		return error;

	get_vnode_fids(vp, &fg, NULL);

	memset(sstb, 0, sizeof(*sstb));
	sstb->sst_dev = vattr.va_fsid;
	sstb->sst_ino = fg.fg_fid;
	sstb->sst_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	sstb->sst_nlink = vattr.va_nlink;
	sstb->sst_uid = vattr.va_uid;
	sstb->sst_gid = vattr.va_gid;
	sstb->sst_rdev = vattr.va_rdev;
	sstb->sst_gen = vattr.va_s2gen;
	if (S_ISDIR(sstb->sst_mode))
		sstb->sst_size = vattr.va_blksize * vattr.va_nblocks;
	else
		sstb->sst_size = vattr.va_s2size;
	sstb->sst_blksize = vattr.va_blksize;
	sstb->sst_blocks = vattr.va_nblocks;
	TIMESTRUC_TO_TIME(vattr.va_atime, &sstb->sst_atime);
	TIMESTRUC_TO_TIME(vattr.va_mtime, &sstb->sst_mtime);
	TIMESTRUC_TO_TIME(vattr.va_ctime, &sstb->sst_ctime);
	sstb->sst_ptruncgen = vattr.va_ptruncgen;

	/* subtract 1 for immutable namespace link */
	if (sstb->sst_nlink > 1)
		sstb->sst_nlink--;
	return 0;
}

int
zfsslash2_getattr(mdsio_fid_t ino, const struct slash_creds *slcrp,
    struct srt_stat *sstb)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	error = zfsslash2_stat(vp, sstb, cred);

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_lookup(mdsio_fid_t parent, const char *name,
    struct slash_fidgen *fg, mdsio_fid_t *mfp,
    const struct slash_creds *slcrp, struct srt_stat *sstb)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;

	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, cred, NULL, NULL, NULL);
	if (error)
		goto out;

	if (vp == NULL) {
		error = ENOENT;
		goto out;
	}

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);
	if (error)
		goto out;

	get_vnode_fids(vp, fg, mfp);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/* XXX replace fuse_file_info with something meaningful for slash d_ino cache
 */
int
zfsslash2_opendir(mdsio_fid_t ino, const struct slash_creds *slcrp,
    struct slash_fidgen *fg, struct srt_stat *sstb, void **finfo)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}
	/*
	 * Check permissions.
	 */
	if (error = VOP_ACCESS(vp, VREAD | VEXEC, 0, cred, NULL))
		goto out;

	vnode_t *old_vp = vp;

	/* XXX: not sure about flags */
	error = VOP_OPEN(&vp, FREAD, cred, NULL);

	ASSERT(old_vp == vp);

	if (error)
		goto out;

	/* XXX convert to the slash d_ino cache */
	*finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if (*finfo == NULL) {
		error = ENOMEM;
		goto out;
	}

	((file_info_t *)(*finfo))->vp = vp;
	((file_info_t *)(*finfo))->flags = FREAD;

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);
	get_vnode_fids(vp, fg, NULL);

 out:
	if (error)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/*  XXX convert to the slash d_ino cache .. same as above
 */
int
zfsslash2_release(const struct slash_creds *slcrp, void *finfo)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;
	file_info_t *info = finfo;

	ZFS_ENTER(zfsvfs);

	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);

	int error = VOP_CLOSE(info->vp, info->flags, 1, (offset_t) 0, cred, NULL); /* zfs_close() */
	VERIFY(error == 0);

	VN_RELE(info->vp);

	kmem_cache_free(file_info_cache, info);

	ZFS_EXIT(zfsvfs);

	return error;
}

/*
 * Two buffers are passed in by our callers: outbuf points to the
 * readdir result, attrs points to prefeteched attributes.
 */
int
zfsslash2_readdir(const struct slash_creds *slcrp, size_t size,
    off_t off, void *outbuf, size_t *outbuf_len, void *attrs,
    int nstbprefetch, void *finfo)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	vnode_t *vp = ((file_info_t *)finfo)->vp;

	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);

	if (vp->v_type != VDIR)
		return ENOTDIR;

	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN + 1)];
		struct dirent64 dirent;
	} entry;

	struct stat fstat = { 0 };
	struct srm_getattr_rep *attr = attrs;

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

		error = VOP_READDIR(vp, &uio, cred, &eofp, NULL, 0);	/* zfs_readdir() */
		if (error)
			goto out;

		/* No more directory entries */
		if (iovec.iov_base == entry.buf)
			break;

		/* No more room */
		int dsize = fuse_add_direntry(NULL, NULL, 0, entry.dirent.d_name, NULL, 0);
		if (dsize > outbuf_resid)
			break;

		/* XXX XXX avoid doing a zfs_zget() here XXX XXX */
		znode_t *znode;
		error = zfs_zget(zfsvfs, entry.dirent.d_ino, &znode, B_TRUE);
		if (error)
			break;

		ASSERT(znode != NULL);
		vnode_t *tvp = ZTOV(znode);

		/*
		 * Skip internal SLASH meta-structure.
		 * This check should be pushed out to mount_slash once
		 * we move the fuse dirent packing there.
		 */
		if (hide_vnode(vp, tvp, entry.dirent.d_name))
			goto next_entry;

		struct slash_fidgen tfg;
		mdsio_fid_t tmf;

		get_vnode_fids(tvp, &tfg, &tmf);

		fstat.st_ino = tfg.fg_fid;
		fstat.st_mode = 0;

		outbuf_resid -= dsize;
		fuse_add_direntry(NULL, outbuf + outbuf_off,
		    dsize, entry.dirent.d_name, &fstat, entry.dirent.d_off);

		outbuf_off += dsize;

		if (nstbprefetch) {
			attr->rc = zfsslash2_stat(tvp, &attr->attr, cred);
			nstbprefetch--;
#if 0
			fprintf(stderr, "slash fid: %#"PRIx64", "
			    "zfs ino: %#"PRIx64", name: %s, mode: 0%o\n",
			    attr->attr.sst_ino, entry.dirent.d_ino,
			    entry.dirent.d_name, attr->attr.sst_mode);
#endif
			attr++;
		}
 next_entry:
		VN_RELE(tvp);
		next = entry.dirent.d_off;
	}

 out:
	ZFS_EXIT(zfsvfs);
	*outbuf_len = outbuf_off;

	return error;
}

/*
 * Construct the by-id namespace for our internal use.  This will add an extra link to all files AND
 * directories.  Normally, a user accesses a file or a directory by its name and that is done in the
 * by-name namespace.
 *
 * Note that this function assumes that the upper layers of the by-id namespace have already been
 * created.  We do this when we format the file system.
 */
int
zfsslash2_fidlink(slfid_t fid, int flags, vnode_t *svp, vnode_t **vpp)
{
	int		 i;
	uint8_t		 c;
	vnode_t		*vp;
	vnode_t		*dvp;
	int		 error;
	znode_t		*znode;
	char		 id_name[20];
	zfsvfs_t	*zfsvfs = zfsVfs->vfs_data;

	error = zfs_zget(zfsvfs, MDSIO_FID_ROOT, &znode, B_TRUE);
	if (error)
		return error == EEXIST ? ENOENT : error;

	ASSERT(znode != NULL);
	dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	/*
	 * Map the root of slash2 to the root of the underlying ZFS.
	 */
	if (flags & FIDLINK_LOOKUP) {
		if (fid == 1) {
#if 0
			/*
			 * I have found a place in zfs_mknode() where I can write slash ID 1 into the
			 * root node.  This function is called by dsl_pool_create() twice, once by
			 * zfs_create_fs(), once by zfs_create_share_dir().  Both time I see the
			 * IS_ROOT_NODE flag is used.  I don't know why ZFS seems to create two root
			 * nodes.  But the change seems to fix my problem and make the hack here
			 * unneeded.  I discovered this with gdb while creating a zpool.
			 */
			VTOZ(dvp)->z_phys->zp_s2id = 1;
#endif
			*vpp = dvp;
			return 0;
		}
	}

	error = VOP_LOOKUP(dvp, SL_PATH_FIDNS, &vp, NULL, 0, NULL, &zrootcreds,
	    NULL, NULL, NULL);
	if (error) {
		VN_RELE(dvp);
		return (error);
	}

	/* Release the root dir dvp and stash the .slfidns vp there.
	 */
	VN_RELE(dvp);
	dvp = vp;
	vp = NULL;

	/* Lookup our fid's parent directory in the fid namespace, closing
	 *   parent dvp's along the way.
	 */
	/* XXX use fid_makepath */
	id_name[1] = '\0';
	for (i = 0; i < FID_PATH_DEPTH; i++, VN_RELE(dvp), dvp=vp) {
		/*
		 * Extract BPHXC bits at a time and convert them to a digit or a lower-case
		 * letter to construct our pathname component.  5 means we start with 5th
		 * hex digit from the right side.  If the depth is 3, then we have 0xfff or
		 * 4095 files in a directory in the by-id namespace.
		 */
		c = (uint8_t)((fid & (UINT64_C(0x0000000000f00000) >> i*BPHXC)) >> ((5-i) * BPHXC));
		/* convert a hex digit to its corresponding ascii digit or lower case letter */
		id_name[0] = (c < 10) ? (c += 0x30) : (c += 0x57);

		error = VOP_LOOKUP(dvp, id_name, &vp, NULL, 0, NULL, &zrootcreds,
		    NULL, NULL, NULL);

#ifdef DEBUG
		fprintf(stderr, "id_name=%s parent=%"PRId64" "
		    "child=%"PRId64" error=%d\n",
		    id_name, VTOZ(dvp)->z_id,
		    VTOZ(vp)->z_id, error);
#endif

		if (error) {
			VN_RELE(dvp);
			return (error);
		}
	}
	/* we should have the parent vnode in the by-id namespace now */
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
				FALLOWDIRLINK | FKEEPPARENT);
		} else {
			vattr_t vattr;
			memset(&vattr, 0, sizeof(vattr_t));
			vattr.va_type = VDIR;
			vattr.va_mode = 0711;
			vattr.va_mask = AT_TYPE | AT_MODE;
			vattr.va_fid = fid;
			error = VOP_MKDIR(dvp, id_name, &vattr, vpp, 
				&zrootcreds, NULL, 0, NULL, NULL);
		}
		goto out;
	}
	if (flags & FIDLINK_REMOVE) {
		error = VOP_REMOVE(dvp, id_name, &zrootcreds, NULL, 0);
		goto out;
	}
	error = EINVAL;

 out:

#ifdef DEBUG
	fprintf(stderr, "id_name=%s parent=%"PRId64" linkvp=%"PRId64" error=%d\n",
	    id_name, VTOZ(dvp)->z_id, fid, error);
#endif

	VN_RELE(dvp);

	return (error);
}

int
zfsslash2_lookup_slfid(slfid_t fid, const struct slash_creds *slcrp,
    struct srt_stat *sstb, mdsio_fid_t *mfp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	struct slash_fidgen fg;
	vnode_t *vp;
	int error;

	vp = NULL;
	error = zfsslash2_fidlink(fid, FIDLINK_LOOKUP, NULL, &vp);
	if (error)
		return (error);
	error = zfsslash2_stat(vp, sstb, cred);
	if (error)
		goto out;
	get_vnode_fids(vp, &fg, mfp);

 out:
	VN_RELE(vp);
	return (error);
}

/*
 * Note that ino is the target inode if this is an open, otherwise it is the inode of the parent.
 */
int
zfsslash2_opencreate(mdsio_fid_t ino, const struct slash_creds *slcrp,
    int fflags, mode_t createmode, const char *name,
    struct slash_fidgen *fg, mdsio_fid_t *mfp, struct srt_stat *sstb,
    void **finfo, sl_jlog_cb logfunc, sl_getslfid_cb getslfid)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	if (flags & FCREAT) {
		if (strlen(name) > MAXNAMELEN) {
			error = ENAMETOOLONG;
			goto out;
		}

		enum vcexcl excl;
		struct srt_stat stat;
		timestruc_t now;

		vattr_t vattr;
		memset(&vattr, 0, sizeof(vattr_t));

		vattr.va_type = VREG;
		vattr.va_mode = createmode;
		vattr.va_mask = AT_TYPE|AT_MODE;
		vattr.va_fid = getslfid();

		memset(&stat, 0, sizeof(struct srt_stat));

		stat.sst_mode = createmode;
		stat.sst_uid = cred->cr_uid;
		stat.sst_gid = cred->cr_gid;

		gethrestime(&now);
		vattr.va_atime = now;
		vattr.va_mtime = now;
		vattr.va_mask |= AT_ATIME | AT_MTIME;
		TIMESTRUC_TO_TIME(vattr.va_atime, &stat.sst_atime);
		TIMESTRUC_TO_TIME(vattr.va_mtime, &stat.sst_mtime);

#if 0
		if (logfunc)
			logfunc(MDS_NAMESPACE_OP_CREATE, MDS_NAMESPACE_TYPE_FILE,
				znode->z_phys->zp_s2id, vattr.va_fid, &stat, 0, name);
#endif

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
		error = VOP_CREATE(vp, (char *)name, &vattr, excl, mode, &new_vp, cred, 0, NULL, NULL, logfunc);   /* zfs_create() */

		if (error)
			goto out;

		VN_RELE(vp);
		vp = new_vp;

		if ((error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2id, FIDLINK_CREATE, vp, NULL)))
			goto out;
	} else {
		/*
		 * Get the attributes to check whether file is large.
		 * We do this only if the O_LARGEFILE flag is not set and
		 * only for regular files.
		 */
		if (!(flags & FOFFMAX) && (vp->v_type == VREG)) {
			vattr_t vattr;
			vattr.va_mask = AT_SIZE;
			if ((error = VOP_GETATTR(vp, &vattr, 0, cred, NULL)))
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
		if (error = VOP_ACCESS(vp, mode, 0, cred, NULL))
			goto out;
	}

	if ((flags & FNOFOLLOW) && vp->v_type == VLNK) {
		error = ELOOP;
		goto out;
	}

	vnode_t *old_vp = vp;

	error = VOP_OPEN(&vp, flags, cred, NULL);

	ASSERT(old_vp == vp);

	if (error)
		goto out;

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);
	if (error)
		goto out;

	/* XXX it should not be an error if we can't cache the vnode */
	*finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if (*finfo == NULL) {
		error = ENOMEM;
		goto out;
	}

	((file_info_t *)(*finfo))->vp = vp;
	((file_info_t *)(*finfo))->flags = flags;

	get_vnode_fids(vp, fg, mfp);

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
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;
	iovec.iov_base = buf;
	iovec.iov_len = PATH_MAX;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = 0;

	error = VOP_READLINK(vp, &uio, cred, NULL);

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if (!error) {
		VERIFY(uio.uio_loffset <= PATH_MAX);
		buf[sizeof(buf) - 1] = '\0';
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
	ZFS_CONVERT_CREDS(cred, slcrp);
	file_info_t *info = finfo;
	vnode_t *vp = info->vp;

	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);

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

	int error = VOP_READ(vp, &uio, info->flags, cred, NULL);

	ZFS_EXIT(zfsvfs);

	if (error == 0)
		*nb = uio.uio_loffset - off;
	return (error);
}

/*
 * fg is used as an in and out parameter.  If it is not FID_ANY, then
 * the caller has passed in a pre-determined SLASH_ID for us to use.
 */
int
zfsslash2_mkdir(mdsio_fid_t parent, const char *name, mode_t mode,
    const struct slash_creds *slcrp, struct srt_stat *sstb,
    struct slash_fidgen *fg, mdsio_fid_t *mfp,
    sl_jlog_cb logfunc, sl_getslfid_cb getslfid)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;
	struct srt_stat stat;

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr_t));
	vattr.va_type = VDIR;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;
	vattr.va_fid = getslfid();

	memset(&stat, 0, sizeof(struct srt_stat));
	stat.sst_mode = mode & PERMMASK;
	stat.sst_uid = cred->cr_uid;
	stat.sst_gid = cred->cr_gid;

#if 0
	if (logfunc)
		logfunc(MDS_NAMESPACE_OP_CREATE, MDS_NAMESPACE_TYPE_DIR, 
			znode->z_phys->zp_s2id, vattr.va_fid, &stat, 0, name);
#endif

	error = VOP_MKDIR(dvp, (char *)name, &vattr, &vp, cred, NULL, 0, NULL, logfunc); /* zfs_mkdir() */
	if (error)
		goto out;

	ASSERT(vp != NULL);

	error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2id, FIDLINK_CREATE, vp, NULL);
	if (error)
		goto out;

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);
	if (error)
		goto out;

	get_vnode_fids(vp, fg, mfp);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_rmdir(mdsio_fid_t parent, const char *name,
    const struct slash_creds *slcrp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;
	/*
	 * Hold a reference to the name to be removed, so that I can
	 * remove it from the by-id namespace later.
	 */
	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, cred, NULL, NULL, NULL);
	if (error)
		goto out;

	/* FUSE doesn't care if we remove the current working directory
	   so we just pass NULL as the cwd parameter (no problem for ZFS) */
	error = VOP_RMDIR(dvp, (char *)name, NULL, cred, NULL, 0);		/* zfs_rmdir() */

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if (error == EEXIST)
		error = ENOTEMPTY;

	if (!error)
		error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2id, FIDLINK_REMOVE, NULL, NULL);

	VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

out:
	return error;
}

int
zfsslash2_setattr(mdsio_fid_t ino, const struct srt_stat *sstb_in,
    int to_set, const struct slash_creds *slcrp,
    struct srt_stat *sstb_out, void *finfo, sl_jlog_cb logfunc)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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
		ASSERT(znode != NULL);
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
		if (to_set & SRM_SETATTRF_SIZE) {
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
			error = VOP_SPACE(vp, F_FREESP, &bf, info->flags, 0, cred, NULL);
			if (error)
				goto out;

			to_set &= ~SRM_SETATTRF_SIZE;
			if (to_set == 0)
				goto out;
		}
	}

	ASSERT(vp != NULL);

	vattr_t vattr = { 0 };
	
	if (to_set & SRM_SETATTRF_MODE) {
		vattr.va_mask |= AT_MODE;
		vattr.va_mode = sstb_in->sst_mode;
	}
	if (to_set & SRM_SETATTRF_UID) {
		vattr.va_mask |= AT_UID;
		vattr.va_uid = sstb_in->sst_uid;
		if (vattr.va_uid > MAXUID) {
			error = EINVAL;
			goto out;
		}
	}
	if (to_set & SRM_SETATTRF_GID) {
		vattr.va_mask |= AT_GID;
		vattr.va_gid = sstb_in->sst_gid;
		if (vattr.va_gid > MAXUID) {
			error = EINVAL;
			goto out;
		}
	}
	if (to_set & SRM_SETATTRF_ATIME) {
		vattr.va_mask |= AT_ATIME;
		TIME_TO_TIMESTRUC(sstb_in->sst_atime, &vattr.va_atime);
	}
	if (to_set & SRM_SETATTRF_MTIME) {
		vattr.va_mask |= AT_MTIME;
		TIME_TO_TIMESTRUC(sstb_in->sst_mtime, &vattr.va_mtime);
	}
	if (to_set & SRM_SETATTRF_FSIZE) {
		vattr.va_mask |= AT_SLASH2SIZE;
		vattr.va_s2size = sstb_in->sst_size;
	}
	if (to_set & SRM_SETATTRF_PTRUNCGEN) {
		vattr.va_mask |= AT_PTRUNCGEN;
		vattr.va_ptruncgen = sstb_in->sst_ptruncgen;
	}

	int flags = (to_set & (SRM_SETATTRF_ATIME | SRM_SETATTRF_MTIME)) ? ATTR_UTIME : 0;
	error = VOP_SETATTR(vp, &vattr, flags, cred, NULL, logfunc);	/* zfs_setattr() */

 out:
	if (!error && sstb_out)
		error = zfsslash2_stat(vp, sstb_out, cred);

	/* Do not release if vp was an opened inode */
	if (release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_unlink(mdsio_fid_t parent, const char *name,
    const struct slash_creds *slcrp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp=NULL;
	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, cred,
			   NULL, NULL, NULL);
	if (error)
		goto out;

	error = VOP_REMOVE(dvp, (char *)name, cred, NULL, 0);
	if (error)
		goto out;

	vattr_t vattr = { 0 };
	error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);
	if (error)
		goto out;

	/*
	 * The last remaining link is our FID namespace one,
	 * so remove the file.
	 */
	if (vattr.va_nlink == 1)
		error = zfsslash2_fidlink(VTOZ(vp)->z_phys->zp_s2id, FIDLINK_REMOVE, NULL, NULL);

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
    size_t size, size_t *nb, off_t off, void *finfo)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	file_info_t *info = finfo;

	vnode_t *vp = info->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);

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

	int error = VOP_WRITE(vp, &uio, info->flags, cred, NULL);

	ZFS_EXIT(zfsvfs);

	if (!error) {
		/* When not using direct_io, we must always write 'size' bytes */
		VERIFY(uio.uio_resid == 0);
		*nb = size - uio.uio_resid;
	}

	return error;
}

#if 0
int
zfsslash2_mknod(mdsio_fid_t parent, const char *name, mode_t mode,
    dev_t rdev)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

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
	error = VOP_CREATE(dvp, (char *)name, &vattr, EXCL, 0, &vp, &cred, 0, NULL, NULL);

	VN_RELE(dvp);

	if (error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = 0.0;
	e.entry_timeout = 0.0;

	e.ino = VTOZ(vp)->z_id;
	e.generation = VTOZ(vp)->z_phys->zp_gen;

	if (sstb)
		error = zfsslash2_stat(vp, &e.attr, &cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if (!error)
		fuse_reply_entry(req, &e);

	return error;
}
#endif

int
zfsslash2_symlink(const char *link, mdsio_fid_t parent, const char *name,
    const struct slash_creds *slcrp, struct srt_stat *sstb,
    struct slash_fidgen *fg, mdsio_fid_t *mfp, sl_getslfid_cb getslfid)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr));
	vattr.va_type = VLNK;
	vattr.va_mode = 0777;
	vattr.va_mask = AT_TYPE | AT_MODE;
	vattr.va_fid = getslfid();

	error = VOP_SYMLINK(dvp, (char *)name, &vattr, (char *)link, cred, NULL, 0);

	vnode_t *vp = NULL;

	if (error)
		goto out;

	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, cred, NULL, NULL, NULL);
	if (error)
		goto out;

	ASSERT(vp != NULL);

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);
	if (error)
		goto out;

	get_vnode_fids(vp, fg, mfp);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_rename(mdsio_fid_t parent, const char *name, mdsio_fid_t newparent,
    const char *newname, const struct slash_creds *slcrp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *p_znode, *np_znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;
	if (strlen(newname) > MAXNAMELEN)
		return ENAMETOOLONG;

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

	error = VOP_RENAME(p_vp, (char *)name, np_vp, (char *)newname, cred, NULL, 0);  /* zfs_rename() */

	VN_RELE(p_vp);
	VN_RELE(np_vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_fsync(const struct slash_creds *slcrp, int datasync,
    void *finfo)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	file_info_t *info = finfo;
	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);

	vnode_t *vp = info->vp;

	int error = VOP_FSYNC(vp, datasync ? FDSYNC : FSYNC, cred, NULL);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_link(mdsio_fid_t ino, mdsio_fid_t newparent, const char *newname,
    struct slash_fidgen *fg, const struct slash_creds *slcrp,
    struct srt_stat *sstb)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	error = VOP_LINK(tdvp, svp, (char *)newname, cred, NULL, 0);
	vnode_t *vp = NULL;
	if (error)
		goto out;

	error = VOP_LOOKUP(tdvp, (char *)newname, &vp, NULL, 0, NULL, cred, NULL, NULL, NULL);
	if (error)
		goto out;

	ASSERT(vp != NULL);

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);
	if (error)
		goto out;

	get_vnode_fids(vp, fg, NULL);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(tdvp);
	VN_RELE(svp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_access(mdsio_fid_t ino, int mask, const struct slash_creds *slcrp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
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

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	int mode = 0;
	if (mask & R_OK)
		mode |= VREAD;
	if (mask & W_OK)
		mode |= VWRITE;
	if (mask & X_OK)
		mode |= VEXEC;

	error = VOP_ACCESS(vp, mode, 0, cred, NULL);

	VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

/*
 * The following are functions used to replay a namespace operation happened on a remote MDS.
 * There are two big differences between these functions and those above: (1) we have to
 * operate from the by-id namespace (that's why we start with zfsslash2_fidlink() instead of
 * zfs_zget()); (2) we don't need to log a replayed operation.
 */

int
zfsslash2_replay_symlink(__unusedx slfid_t pfid, __unusedx slfid_t fid, __unusedx int mode, __unusedx char *name)
{
	return (0);
}

int
zfsslash2_replay_link(__unusedx slfid_t pfid, __unusedx slfid_t fid, __unusedx int mode, __unusedx char *name)
{
	return (0);
}

int
zfsslash2_replay_mkdir(__unusedx slfid_t pfid, __unusedx slfid_t fid, __unusedx int mode, __unusedx char *name)
{
	int error;
	vnode_t *pvp;
	vnode_t *tvp;
	vattr_t vattr;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	pvp = NULL;
	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP|FIDLINK_CREATE, NULL, &pvp);
	if (error)
		goto out;

	memset(&vattr, 0, sizeof(vattr_t));
	vattr.va_type = VDIR;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE|AT_MODE;
	vattr.va_fid = fid;
	error = VOP_MKDIR(pvp, (char *)name, &vattr, &tvp, &zrootcreds, NULL, 0, NULL, NULL);
	if (error) {
		VN_RELE(pvp);
		goto out;
	}
	error = zfsslash2_fidlink(fid, FIDLINK_CREATE, tvp, NULL);
	VN_RELE(pvp);
	VN_RELE(tvp);

 out:
	return (error);
}

int
zfsslash2_replay_create(slfid_t pfid, slfid_t fid, int32_t uid, int32_t gid, int mode, char *name)
{
	int error;
	vnode_t *pvp;
	vnode_t *tvp;
	vattr_t vattr;
	cred_t cred;
	timestruc_t now;

	/*
	 * Make sure the parent exists, at least in the by-id namespace.
	 */
	pvp = NULL;
	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP|FIDLINK_CREATE, NULL, &pvp);
	if (error)
		goto out;

	memset(&vattr, 0, sizeof(vattr_t));
	vattr.va_type = VREG;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE|AT_MODE;
	vattr.va_fid = fid;

	cred.cr_uid = uid;
	cred.cr_gid = gid;

	/*
	 * Looks like ZFS allows us to pass in atime and mtime. With this, we can respect
	 * these two timestamps instead of something close.
	 */
	gethrestime(&now);
	vattr.va_atime = now;
	vattr.va_mtime = now;
	vattr.va_mask |= AT_ATIME | AT_MTIME;

	error = VOP_CREATE(pvp, (char *)name, &vattr, EXCL, mode, &tvp, &cred, 0, NULL, NULL, NULL); /* zfs_create() */
	if (error) {
		VN_RELE(pvp);
		goto out;
	}
	error = zfsslash2_fidlink(fid, FIDLINK_CREATE, tvp, NULL);
	VN_RELE(pvp);
	VN_RELE(tvp);

 out:
	return (error);
}

int
zfsslash2_replay_rmdir(__unusedx slfid_t pfid, __unusedx slfid_t fid, __unusedx char *name)
{
	int error;
	vnode_t *dvp;
	dvp = NULL;

	error = zfsslash2_fidlink(pfid, FIDLINK_LOOKUP|FIDLINK_CREATE, NULL, &dvp);
	if (error)
		goto out;

	error = VOP_RMDIR(dvp, (char *)name, NULL, &zrootcreds, NULL, 0);

	VN_RELE(dvp);
out:
	return (error);
}

int
zfsslash2_replay_unlink(__unusedx slfid_t pfid, __unusedx slfid_t fid, __unusedx char *name)
{
	return (0);
}

int
zfsslash2_replay_setattr(slfid_t fid, struct srt_stat * stat, uint mask)
{
	int error;
	vnode_t *vp;
	vattr_t vattr;
	int flag;

	vp = NULL;
	error = zfsslash2_fidlink(fid, FIDLINK_LOOKUP|FIDLINK_CREATE, NULL, &vp);
	if (error)
		goto out;

	vattr.va_mask = mask;
	vattr.va_mode = stat->sst_mode; 
	vattr.va_uid = stat->sst_uid;
	vattr.va_uid = stat->sst_uid;
	TIME_TO_TIMESTRUC(stat->sst_atime, &vattr.va_atime);
	TIME_TO_TIMESTRUC(stat->sst_mtime, &vattr.va_mtime);
	TIME_TO_TIMESTRUC(stat->sst_ctime, &vattr.va_ctime);

	flag = (mask & (AT_ATIME | AT_MTIME)) ? ATTR_UTIME : 0;
	error = VOP_SETATTR(vp, &vattr, flag, &zrootcreds, NULL, NULL); /* zfs_setattr() */

	VN_RELE(vp);
out:
	return (error);
}

