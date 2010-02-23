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
vfs_t		*zfsVfs;

/* flags for zfsslash2_fidlink() */
#define FIDLINK_LOOKUP	1
#define FIDLINK_CREATE	2
#define FIDLINK_REMOVE	3

#define SL_PATH_PREFIX	".sl"
#define SL_PATH_FIDNS	".slfidns"

#define	ZFS_ROOT_ID	3

#define INTERNALIZE_INUM(ip)					\
	do {							\
		if (*(ip) == 1)					\
			*(ip) = 3;				\
	} while (0)

#define EXTERNALIZE_INUM(ip)					\
	do {							\
		if (*(ip) == 3)					\
			*(ip) = 1;				\
	} while (0)

/* get the exportable file ID from a vnode */
static __inline slfid_t
get_vnode_fid(vnode_t *vp)
{
	slfid_t fid;

#ifdef NAMESPACE_EXPERIMENTAL
	fid = VTOZ(vp)->z_fid;
#else
	fid = VTOZ(vp)->z_id;
	EXTERNALIZE_INUM(&fid);
#endif
	return (fid);
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

int zfsslash2_fidlink(zfsvfs_t *zfsvfs, vnode_t **linkvp, uint64_t linkid, int flags);

int
zfsslash2_isreserved(uint64_t ino, const char *cpn)
{
	if (ino == 3 && strncmp(cpn, SL_PATH_PREFIX,
	    strlen(SL_PATH_PREFIX)) == 0)
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
zfsslash2_statfs(struct statvfs *stat, uint64_t ino)
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

void
zfsslash2_export_sstb(struct srt_stat *sstb)
{
	EXTERNALIZE_INUM(&sstb->sst_ino);

	/* subtract 1 for slfidns immutable namespace link */
	if (sstb->sst_nlink > 1)
		sstb->sst_nlink--;

	/* XXX adjust st_nlink of files in repldir */
}

int
zfsslash2_stat(vnode_t *vp, struct srt_stat *sstb, cred_t *cred)
{
	ASSERT(vp != NULL);
	ASSERT(sstb != NULL);

	vattr_t vattr;

	int error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);
	if (error)
		return error;

	memset(sstb, 0, sizeof(*sstb));

	sstb->sst_dev = vattr.va_fsid;
	sstb->sst_ino = vattr.va_nodeid;
	sstb->sst_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	sstb->sst_nlink = vattr.va_nlink;
	sstb->sst_uid = vattr.va_uid;
	sstb->sst_gid = vattr.va_gid;
	sstb->sst_rdev = vattr.va_rdev;
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

	zfsslash2_export_sstb(sstb);

	return 0;
}

int
zfsslash2_getattr(uint64_t ino, const struct slash_creds *slcrp,
    struct srt_stat *sstb, uint64_t *gen)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	INTERNALIZE_INUM(&ino);

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

	if (gen)
		*gen = VTOZ(vp)->z_phys->zp_gen;

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_lookup(uint64_t parent, const char *name,
    struct slash_fidgen *fg, const struct slash_creds *slcrp,
    struct srt_stat *sstb)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	INTERNALIZE_INUM(&parent);

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

	fg->fg_fid = get_vnode_fid(vp);
	fg->fg_gen = VTOZ(vp)->z_phys->zp_gen;

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
zfsslash2_opendir(uint64_t ino, const struct slash_creds *slcrp,
    struct slash_fidgen *fg, struct srt_stat *sstb, void **finfo)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	INTERNALIZE_INUM(&ino);

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

	if (!error) {
		/* XXX convert to the slash d_ino cache */
		*finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
		if (*finfo == NULL) {
			error = ENOMEM;
			goto out;
		}

		((file_info_t *)(*finfo))->vp = vp;
		((file_info_t *)(*finfo))->flags = FREAD;

		fg->fg_fid = get_vnode_fid(vp);
		fg->fg_gen = VTOZ(vp)->z_phys->zp_gen;
	}

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);

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

	int error = VOP_CLOSE(info->vp, info->flags, 1, (offset_t) 0, cred, NULL);
	VERIFY(error == 0);

	VN_RELE(info->vp);

	kmem_cache_free(file_info_cache, info);

	ZFS_EXIT(zfsvfs);

	return error;
}


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

	if (outbuf == NULL)
		return EINVAL;

	ZFS_ENTER(zfsvfs);

	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN + 1)];
		struct dirent64 dirent;
	} entry;

	struct srt_stat sstb;
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

		error = VOP_READDIR(vp, &uio, cred, &eofp, NULL, 0);
		if (error)
			goto out;

		/* No more directory entries */
		if (iovec.iov_base == entry.buf)
			break;

		/*
		 * Skip internal SLASH meta-structure.
		 * This check should be pushed out to mount_slash once
		 * we move the fuse dirent packing there.
		 */
		if (zfsslash2_isreserved(get_vnode_fid(vp),
		    entry.dirent.d_name))
			goto next_entry;

		fstat.st_ino = entry.dirent.d_ino;
		EXTERNALIZE_INUM(&fstat.st_ino);
		fstat.st_mode = 0;

		int dsize = fuse_add_direntry(NULL, NULL, 0, entry.dirent.d_name, NULL, 0);
		if (dsize > outbuf_resid)
			break;

		outbuf_resid -= dsize;
		fuse_add_direntry(NULL, outbuf + outbuf_off,
		    dsize, entry.dirent.d_name, &fstat,
		    entry.dirent.d_off);

		outbuf_off += dsize;

		if (nstbprefetch) {
			attr->rc = zfsslash2_getattr(fstat.st_ino,
			    slcrp, &sstb, &attr->gen);

			attr++;
			nstbprefetch--;
		}
 next_entry:
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
zfsslash2_fidlink(zfsvfs_t *zfsvfs, vnode_t **linkvp, uint64_t linkid, int flags)
{
	int		 i;
	uint8_t		 c;
	vnode_t		*vp;
	vnode_t		*dvp;
	int		 error;
	znode_t		*znode;
	uint64_t	 slashid;
	char		 id_name[20];

	error = zfs_zget(zfsvfs, 3, &znode, B_TRUE);
	if (error)
		return error == EEXIST ? ENOENT : error;

	ASSERT(znode != NULL);
	dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

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

	if (flags != FIDLINK_LOOKUP) {
		ASSERT(*linkvp);
		slashid = get_vnode_fid(*linkvp);
	} else {
		ASSERT(!(*linkvp));
		slashid = linkid;
	}

	/* Lookup our fid's parent directory in the fid namespace, closing
	 *   parent dvp's along the way.
	 */
	id_name[1] = '\0';
	for (i = 0; i < FID_PATH_DEPTH; i++, VN_RELE(dvp), dvp=vp) {
		/*
		 * Extract BPHXC bits at a time and convert them to a digit or a lower-case
		 * letter to construct our pathname component.  5 means we start with 5th
		 * hex digit from the right side.  If the depth is 3, then we have 0xfff or
		 * 4095 files in a directory in the by-id namespace.
		 */
		c = (uint8_t)((slashid & (UINT64_C(0x0000000000f00000) >> i*BPHXC)) >> ((5-i) * BPHXC));
		/* convert a hex digit to its corresponding ascii digit or lower case letter */
		id_name[0] = (c < 10) ? (c += 0x30) : (c += 0x57);

		error = VOP_LOOKUP(dvp, id_name, &vp, NULL, 0, NULL, &zrootcreds,
		    NULL, NULL, NULL);

#ifdef DEBUG
		fprintf(stderr, "id_name=%s parent=%ld child=%ld "
			"error=%d\n",
			id_name, (uint64_t)VTOZ(dvp)->z_id,
			(uint64_t)VTOZ(vp)->z_id, error);

#endif

		if (error) {
			VN_RELE(dvp);
			return (error);
		}
	}
	/* we should have the parent vnode in the by-id namespace now */
	ASSERT(vp);

	snprintf(id_name, sizeof(id_name), "%016"PRIx64, slashid);

	switch (flags) {
	case FIDLINK_LOOKUP:
		*linkvp = vp;
		break;
	case FIDLINK_CREATE:
		error = VOP_LINK(vp, *linkvp, (char *)id_name, &zrootcreds, NULL, FALLOWDIRLINK);
		break;
	case FIDLINK_REMOVE:
		error = VOP_REMOVE(vp, (char *)id_name, &zrootcreds, NULL, 0);
		break;
	default:
		error = EINVAL;
		break;
	}

#ifdef DEBUG
	fprintf(stderr, "id_name=%s parent=%ld linkvp=%ld error=%d\n",
		id_name, (uint64_t)VTOZ(dvp)->z_id,
		slashid, error);
#endif

	if (error)
		VN_RELE(vp);

	return (error);
}

/*
 * Note that ino is the target inode if this is an open, otherwise it is the inode of the parent.
 */
int
zfsslash2_opencreate(uint64_t ino, const struct slash_creds *slcrp,
    int fflags, mode_t createmode, const char *name,
    struct slash_fidgen *fg, struct srt_stat *sstb, void **finfo)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	if (name && strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	INTERNALIZE_INUM(&ino);

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

		/*
		 * Wish to create a file.
		 */
		vattr_t vattr;
		memset(&vattr, 0, sizeof(vattr_t));
		vattr.va_type = VREG;
		vattr.va_mode = createmode;
		vattr.va_mask = AT_TYPE|AT_MODE;

#ifdef NAMESPACE_EXPERIMENTAL
		if (fg)
			vattr.va_fid = fg->fg_fid;
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
		error = VOP_CREATE(vp, (char *)name, &vattr, excl, mode, &new_vp, cred, 0, NULL, NULL);

		if (error)
			goto out;

		VN_RELE(vp);
		vp = new_vp;

		if ((error = zfsslash2_fidlink(zfsvfs, &vp, FID_ANY, FIDLINK_CREATE)))
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

	*finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if (*finfo == NULL) {
		error = ENOMEM;
		goto out;
	}

	((file_info_t *)(*finfo))->vp = vp;
	((file_info_t *)(*finfo))->flags = flags;

	fg->fg_fid = get_vnode_fid(vp);
	fg->fg_gen = VTOZ(vp)->z_phys->zp_gen;

 out:
	if (error) {
		ASSERT(vp->v_count > 0);
		VN_RELE(vp);
	}

	ZFS_EXIT(zfsvfs);

	return error;
}


int
zfsslash2_readlink(uint64_t ino, char *buf,
    const struct slash_creds *slcrp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	INTERNALIZE_INUM(&ino);

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
zfsslash2_mkdir(uint64_t parent, const char *name, mode_t mode,
    const struct slash_creds *slcrp, struct srt_stat *sstb,
    struct slash_fidgen *fg)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	INTERNALIZE_INUM(&parent);

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

	vattr_t vattr;
	memset(&vattr, 0, sizeof(vattr_t));
	vattr.va_type = VDIR;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;

#ifdef NAMESPACE_EXPERIMENTAL
	if (fg)
		vattr.va_fid = fg->fg_fid;
#endif

	error = VOP_MKDIR(dvp, (char *)name, &vattr, &vp, cred, NULL, 0, NULL);
	if (error)
		goto out;

	ASSERT(vp != NULL);

	error = zfsslash2_fidlink(zfsvfs, &vp, FID_ANY, FIDLINK_CREATE);
	if (error)
		goto out;

	if (fg) {
		fg->fg_fid = get_vnode_fid(vp);
		fg->fg_gen = VTOZ(vp)->z_phys->zp_gen;
	}

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}


int
zfsslash2_rmdir(uint64_t parent, const char *name,
    const struct slash_creds *slcrp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	INTERNALIZE_INUM(&parent);

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

	/* FUSE doesn't care if we remove the current working directory
	   so we just pass NULL as the cwd parameter (no problem for ZFS) */
	error = VOP_RMDIR(dvp, (char *)name, NULL, cred, NULL, 0);

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if (error == EEXIST)
		error = ENOTEMPTY;

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_setattr(uint64_t ino, const struct srt_stat *sstb_in,
    int to_set, const struct slash_creds *slcrp,
    struct srt_stat *sstb_out, void *finfo)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;
	file_info_t *info = finfo;

	ZFS_ENTER(zfsvfs);

	vnode_t *vp;
	boolean_t release;

	int error;

	if (!info) {
		znode_t *znode;

		INTERNALIZE_INUM(&ino);
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
	error = VOP_SETATTR(vp, &vattr, flags, cred, NULL);

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
zfsslash2_unlink(uint64_t parent, const char *name,
    const struct slash_creds *slcrp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	INTERNALIZE_INUM(&parent);

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
	if (error) {
		VN_RELE(vp);
		goto out;
	}

	error = zfsslash2_fidlink(zfsvfs, &vp, FID_ANY, FIDLINK_REMOVE);
	VN_RELE(vp);
 out:
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
zfsslash2_mknod(uint64_t parent, const char *name, mode_t mode,
    dev_t rdev)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	INTERNALIZE_INUM(&parent);

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
	EXTERNALIZE_INUM(&e.ino);

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
zfsslash2_symlink(const char *link, uint64_t parent, const char *name,
    const struct slash_creds *slcrp, struct srt_stat *sstb,
    struct slash_fidgen *fg)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	if (strlen(name) > MAXNAMELEN)
		return ENAMETOOLONG;

	INTERNALIZE_INUM(&parent);

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
	vattr.va_type = VLNK;
	vattr.va_mode = 0777;
	vattr.va_mask = AT_TYPE | AT_MODE;

	error = VOP_SYMLINK(dvp, (char *)name, &vattr, (char *)link, cred, NULL, 0);

	vnode_t *vp = NULL;

	if (error)
		goto out;

	error = VOP_LOOKUP(dvp, (char *)name, &vp, NULL, 0, NULL, cred, NULL, NULL, NULL);
	if (error)
		goto out;

	ASSERT(vp != NULL);

	fg->fg_fid = get_vnode_fid(vp);
	fg->fg_gen = VTOZ(vp)->z_phys->zp_gen;

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);

	ZFS_EXIT(zfsvfs);

	return error;
}


int
zfsslash2_rename(uint64_t parent, const char *name, uint64_t newparent,
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

	INTERNALIZE_INUM(&parent);

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

	error = VOP_RENAME(p_vp, (char *)name, np_vp, (char *)newname, cred, NULL, 0);

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
zfsslash2_link(uint64_t ino, uint64_t newparent, const char *newname,
    struct slash_fidgen *fg, const struct slash_creds *slcrp,
    struct srt_stat *sstb)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *td_znode, *s_znode;

	if (strlen(newname) > MAXNAMELEN)
		return ENAMETOOLONG;

	INTERNALIZE_INUM(&ino);
	INTERNALIZE_INUM(&newparent);

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

	fg->fg_fid = get_vnode_fid(vp);
	fg->fg_gen = VTOZ(vp)->z_phys->zp_gen;

	if (sstb)
		error = zfsslash2_stat(vp, sstb, cred);

 out:
	if (vp != NULL)
		VN_RELE(vp);
	VN_RELE(tdvp);
	VN_RELE(svp);

	ZFS_EXIT(zfsvfs);

	return error;
}


int
zfsslash2_access(uint64_t ino, int mask, const struct slash_creds *slcrp)
{
	ZFS_CONVERT_CREDS(cred, slcrp);
	zfsvfs_t *zfsvfs = zfsVfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	INTERNALIZE_INUM(&ino);

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
