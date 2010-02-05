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
#include "zfs_slashlib.h"

/* keep the following in sync with slash_nara/include/fid.h */
#define FID_PATH_DEPTH		3		
#define	BPHXC			4

kmem_cache_t *file_info_cache = NULL;


/* 'to_set' flags in setattr */
#define FUSE_SET_ATTR_MODE	(1 << 0)
#define FUSE_SET_ATTR_UID	(1 << 1)
#define FUSE_SET_ATTR_GID	(1 << 2)
#define FUSE_SET_ATTR_SIZE	(1 << 3)
#define FUSE_SET_ATTR_ATIME	(1 << 4)
#define FUSE_SET_ATTR_MTIME	(1 << 5)

#define SLASH2_SET_ATTR_SIZE    FUSE_SET_ATTR_SIZE

struct fuse_dirent {
	uint64_t	ino;
	uint64_t	off;
	uint32_t	namelen;
	uint32_t	type;
	char name[0];
};

#define SL_PATH_PREFIX	".sl"
#define SL_PATH_FIDNS	".slfidns"

#define TRANSLATE_INUM(ip)					\
	do {							\
		if (*(ip) == 1)					\
			*(ip) = 3;				\
	} while (0)

#define FUSE_NAME_OFFSET ((unsigned long) ((struct fuse_dirent *) 0)->name)
#define FUSE_DIRENT_ALIGN(x) (((x) + sizeof(__uint64_t) - 1) & ~(sizeof(__uint64_t) - 1))
#define FUSE_DIRENT_SIZE(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)


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
    struct fuse_dirent *dirent = (struct fuse_dirent *) buf;

    dirent->ino = stbuf->st_ino;
    dirent->off = off;
    dirent->namelen = namelen;
    dirent->type = (stbuf->st_mode & 0170000) >> 12;
    strncpy(dirent->name, name, namelen);

    if (padlen)
	memset(buf + entlen, 0, padlen);

    return buf + entsize;
}

int
zfsslash2_isreserved(uint64_t ino, const char *cpn)
{
	if (ino == 3 && strncmp(cpn, SL_PATH_PREFIX,
	    strlen(SL_PATH_PREFIX)) == 0)
		return (1);
	return (0);
}

void zfsslash2_destroy(void *userdata)
{
	vfs_t *vfs = (vfs_t *) userdata;

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
	while(do_umount(vfs, 0) != 0)
		nanosleep(&req, NULL);
#ifdef DEBUG
	fprintf(stderr, "do_umount() done\n");
#endif
}

int zfsslash2_statfs(void *vfsdata, struct statvfs *stat, uint64_t ino)
{
	vfs_t *vfs = (vfs_t *)vfsdata;

	struct statvfs64 zfs_stat;

	int ret = VFS_STATVFS(vfs, &zfs_stat);
	if(ret != 0)
		return (ret);

	/* There's a bug somewhere in FUSE, in the kernel or in df(1) where
	   f_bsize is being used to calculate filesystem size instead of
	   f_frsize, so we must use that instead */
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

int zfsslash2_stat(vnode_t *vp, struct stat *stbuf, cred_t *cred)
{
	ASSERT(vp != NULL);
	ASSERT(stbuf != NULL);

	vattr_t vattr;
	//	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;
	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SLASH2SIZE;

	int error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);
	if(error)
		return error;

	memset(stbuf, 0, sizeof(struct stat));

	stbuf->st_dev = vattr.va_fsid;
	stbuf->st_ino = vattr.va_nodeid == 3 ? 1 : vattr.va_nodeid;
	stbuf->st_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	stbuf->st_nlink = MAX(1, vattr.va_nlink - 1);	/* subtract 1 for slfidns */
	/* XXX adjust st_nlink of files in repldir */
	stbuf->st_uid = vattr.va_uid;
	stbuf->st_gid = vattr.va_gid;
	stbuf->st_rdev = vattr.va_rdev;
	stbuf->st_size = vattr.va_s2size;
	stbuf->st_blksize = vattr.va_blksize;
	stbuf->st_blocks = vattr.va_nblocks;
	TIMESTRUC_TO_TIME(vattr.va_atime, &stbuf->st_atime);
	TIMESTRUC_TO_TIME(vattr.va_mtime, &stbuf->st_mtime);
	TIMESTRUC_TO_TIME(vattr.va_ctime, &stbuf->st_ctime);

	return 0;
}

int zfsslash2_getattr(void *vfsdata, uint64_t ino, cred_t *cred, struct stat *stbuf, uint64_t *gen)
{
	vfs_t *vfs = (vfs_t *)vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	uint64_t real_ino = ino == 1 ? 3 : ino;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, real_ino, &znode, B_TRUE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	error = zfsslash2_stat(vp, stbuf, cred);

	if (gen)
		*gen = VTOZ(vp)->z_phys->zp_gen;

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_lookup(void *vfsdata, uint64_t parent, const char *name,
		 fidgen_t *fg, cred_t *cred, struct stat *stb)
{
	if(strlen(name) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	vfs_t *vfs = (vfs_t *)vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	if (parent == 1) parent = 3;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_TRUE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;

	error = VOP_LOOKUP(dvp, (char *) name, &vp, NULL, 0, NULL, cred, NULL, NULL, NULL);
	if(error)
		goto out;

	if(vp == NULL)
		goto out;

	uint64_t ino, gen;

	ino = VTOZ(vp)->z_id;
	if(ino == 3)
		ino = 1;

	if (stb)
		error = zfsslash2_stat(vp, stb, cred);

	if (VTOZ(vp)->z_id == 3) {
		if (stb)
			stb->st_ino = 1;
		fg->fid = 1;
	} else
		fg->fid = VTOZ(vp)->z_id;

	fg->gen = VTOZ(vp)->z_phys->zp_gen;

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/* XXX replace fuse_file_info with something meaningful for slash d_ino cache
 */
int
zfsslash2_opendir(void *vfsdata, uint64_t ino, cred_t *cred,
    struct fidgen *fg, struct stat *stb, void **finfo)
{
	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	if (ino == 1) ino = 3;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	if(vp->v_type != VDIR) {
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

	if(!error) {
		/* XXX convert to the slash d_ino cache */
		*finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
		if(*finfo == NULL) {
			error = ENOMEM;
			goto out;
		}

		((file_info_t *)(*finfo))->vp = vp;
		((file_info_t *)(*finfo))->flags = FREAD;


		if (VTOZ(vp)->z_id == 3)
			fg->fid = 1;
		else
			fg->fid = VTOZ(vp)->z_id;

		fg->gen = VTOZ(vp)->z_phys->zp_gen;
	}

	error = zfsslash2_stat(vp, stb, cred);
	if(error)
		goto out;
out:
	if(error)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	return error;
}

/*  XXX convert to the slash d_ino cache .. same as above
 */
int zfsslash2_release(void *vfsdata, uint64_t ino, cred_t *cred, void *data)
{
	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	file_info_t *info = (file_info_t *)data;

	if (ino == 1) ino = 3;

	ZFS_ENTER(zfsvfs);

	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);
	/* Don't assert if the client sends a bogus inode number.
	 */
	//ASSERT(VTOZ(info->vp)->z_id == ino);
	if (VTOZ(info->vp)->z_id != ino)
		return (EINVAL);

	int error = VOP_CLOSE(info->vp, info->flags, 1, (offset_t) 0, cred, NULL);
	VERIFY(error == 0);

	VN_RELE(info->vp);

	kmem_cache_free(file_info_cache, info);

	ZFS_EXIT(zfsvfs);

	return error;
}


/* XXX caller will have to free outbuf */
int zfsslash2_readdir(void *vfsdata, uint64_t ino, cred_t *cred, size_t size,
    off_t off, void *outbuf, size_t *outbuf_len, void *attrs, int nstbprefetch,
    void *data)
{
	uio_t			uio;
	off_t			next;
	int			error;
	iovec_t			iovec;
	int			eofp = 0;
	int			outbuf_off = 0;
	int			outbuf_resid = size;
	struct stat		stb, fstat = { 0 };
	struct srm_getattr_rep	*attr = attrs;

	vnode_t *vp = ((file_info_t *)(uintptr_t) data)->vp;

	if (ino == 1) ino = 3;

	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

	if(vp->v_type != VDIR)
		return ENOTDIR;

	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	if(outbuf == NULL)
		return EINVAL;

	ZFS_ENTER(zfsvfs);

	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN)]; /* off-by-one */
		struct dirent64 dirent;
	} entry;

	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	next = off;

	for(;;) {
		iovec.iov_base = entry.buf;
		iovec.iov_len = sizeof(entry.buf);
		uio.uio_resid = iovec.iov_len;
		uio.uio_loffset = next;

		error = VOP_READDIR(vp, &uio, cred, &eofp, NULL, 0);
		if(error)
			goto out;

		/* No more directory entries */
		if(iovec.iov_base == entry.buf)
			break;

		fstat.st_ino = entry.dirent.d_ino;
		fstat.st_mode = 0;

		int dsize = fuse_dirent_size(strlen(entry.dirent.d_name));
		if(dsize > outbuf_resid)
			break;

		/* skip internal slash metastructure */
		if (!zfsslash2_isreserved(ino, entry.dirent.d_name)) {
			fuse_add_dirent(outbuf + outbuf_off,
			    entry.dirent.d_name, &fstat,
			    entry.dirent.d_off);
			outbuf_off += dsize;
			outbuf_resid -= dsize;

			if (nstbprefetch) {
				attr->rc = zfsslash2_getattr(vfsdata,
				    entry.dirent.d_ino, cred, &stb,
				    &attr->gen);

				slrpc_externalize_stat(&stb, &attr->attr);

				//fprintf(stderr, "rc=%d st_ino=%lu gen=%lu\n",
				//	attr->rc, attr->attr.st_ino, attr->gen);
				attr++;
				nstbprefetch--;
			}
		}
		next = entry.dirent.d_off;
	}

out:
	ZFS_EXIT(zfsvfs);
	/* XXX caller does free..
	 */
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
zfsslash2_fidlink(zfsvfs_t *zfsvfs, vnode_t *linkvp, int unlink)
{
	int		i;
	uint8_t		c;
	vnode_t		*vp;
	vnode_t		*dvp;
	int		error;
	znode_t		*znode;
	uint64_t	linkid;
	char		fidname[20];
	char		immns_name[2];
	cred_t		creds = {0, 0};

	ASSERT(linkvp);
	error = zfs_zget(zfsvfs, 3, &znode, B_TRUE);
	if (error)
		return error == EEXIST ? ENOENT : error;

	ASSERT(znode != NULL);
	dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	error = VOP_LOOKUP(dvp, SL_PATH_FIDNS, &vp, NULL, 0, NULL, &creds,
			   NULL, NULL, NULL);
	if (error) {
		VN_RELE(dvp);
		return (error);
	}
	/* Release the root dir dvp and stash the .slfidns vp there.
	 */
	VN_RELE(dvp);
	dvp = vp;
	/* Lookup our fid's parent directory in the fid namespace, closing
	 *   parent dvp's along the way.
	 */
	immns_name[1] = '\0';

#ifdef NAMESPACE_EXPERIMENTAL
	linkid = (uint64_t)VTOZ(linkvp)->z_fid;
#else
	linkid = (uint64_t)VTOZ(linkvp)->z_id;
#endif

	for (i = 0; i < FID_PATH_DEPTH; i++, VN_RELE(dvp), dvp=vp) {
		/*
		 * Extract BPHXC bits at a time and convert them to a digit or a lower-case
		 * letter to construct our pathname component.  5 means we start with 5th 
		 * hex digit from the right side.  If the depth is 3, then we have 0xfff or
		 * 4095 files in a directory in the by-id namespace.
		 */
		c = (uint8_t)((linkid & (0x0000000000f00000ULL >> i*BPHXC)) >> ((5-i) * BPHXC));
		immns_name[0] = (c < 10) ? (c += 0x30) : (c += 0x57);

		error = VOP_LOOKUP(dvp, immns_name, &vp, NULL, 0, NULL, &creds,
				   NULL, NULL, NULL);

#ifdef DEBUG
		fprintf(stderr, "immns_name=%s parent=%ld child=%ld "
			"error=%d\n",
			immns_name, (uint64_t)VTOZ(dvp)->z_id,
			(uint64_t)VTOZ(vp)->z_id, error);

#endif

		if (error) {
			VN_RELE(dvp);
			return (error);
		}
	}
	/* Should have the immns parent vp now.
	 */
	snprintf(fidname, 20, "%016"PRIx64, linkid);

	ASSERT(vp);
	if (unlink)
		error = VOP_REMOVE(vp, (char *)fidname, &creds, NULL, 0);
	else
		error = VOP_LINK(vp, linkvp, (char *)fidname, &creds, NULL, FALLOWDIRLINK);

#ifdef DEBUG
	fprintf(stderr, "fidname=%s parent=%ld linkvp=%ld error=%d\n",
		fidname, (uint64_t)VTOZ(dvp)->z_id,
		linkid, error);
#endif

	if (error)
		VN_RELE(vp);

	return (error);
}

int
zfsslash2_opencreate(void *vfsdata, uint64_t ino, cred_t *cred, int fflags,
		     mode_t createmode, const char *name, struct fidgen *fg,
		     struct stat *stb, void **finfo)
{
	if(name && strlen(name) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	uint64_t real_ino = ino == 1 ? 3 : ino;
	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	/* Map flags */
	int mode, flags;

	if(fflags & O_WRONLY) {
		mode = VWRITE;
		flags = FWRITE;
	} else if(fflags & O_RDWR) {
		mode = VREAD | VWRITE;
		flags = FREAD | FWRITE;
	} else {
		mode = VREAD;
		flags = FREAD;
	}

	//fflags |= O_DSYNC;

	if(fflags & O_CREAT)
		flags |= FCREAT;
	if(fflags & O_SYNC)
		flags |= FSYNC;
	if(fflags & O_DSYNC)
		flags |= FDSYNC;
	if(fflags & O_RSYNC)
		flags |= FRSYNC;
	if(fflags & O_APPEND)
		flags |= FAPPEND;
	if(fflags & O_LARGEFILE)
		flags |= FOFFMAX;
	if(fflags & O_NOFOLLOW)
		flags |= FNOFOLLOW;
	if(fflags & O_TRUNC)
		flags |= FTRUNC;
	if(fflags & O_EXCL)
		flags |= FEXCL;

	znode_t *znode;

	int error = zfs_zget(zfsvfs, real_ino, &znode, B_FALSE);
	if(error) {
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
		vattr.va_type = VREG;
		vattr.va_mode = createmode;
		vattr.va_mask = AT_TYPE|AT_MODE;
		if (flags & FTRUNC) {
			vattr.va_size = 0; //XXX fixme, don't wipe out the metadata at the beginning
			vattr.va_mask |= AT_SIZE;
		}
		if (flags & FEXCL)
			excl = EXCL;
		else
			excl = NONEXCL;

		vnode_t *new_vp;
		/* FIXME: check filesystem boundaries */
		error = VOP_CREATE(vp, (char *) name, &vattr, excl, mode, &new_vp, cred, 0, NULL, NULL);

		if(error)
			goto out;

		VN_RELE(vp);
		vp = new_vp;

		if ((error = zfsslash2_fidlink(zfsvfs, vp, 0)))
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

	if(error)
		goto out;

	//if(flags & FCREAT) {
	error = zfsslash2_stat(vp, stb, cred);
	if(error)
		goto out;
	//}
	*finfo = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if (*finfo == NULL) {
		error = ENOMEM;
		goto out;
	}

	((file_info_t *)(*finfo))->vp = vp;
	((file_info_t *)(*finfo))->flags = flags;

	//if(flags & FCREAT) {
	fg->fid = VTOZ(vp)->z_id;
	if(fg->fid == 3) {
		fg->fid = 1;
		stb->st_ino = 1;
	}

	fg->gen = VTOZ(vp)->z_phys->zp_gen;
	//}
out:
	if(error) {
		ASSERT(vp->v_count > 0);
		VN_RELE(vp);
	}

	ZFS_EXIT(zfsvfs);

	return error;
}



int zfsslash2_readlink(void *vfsdata, uint64_t ino, char *buf, cred_t *cred)
{
	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	uint64_t real_ino = ino == 1 ? 3 : ino;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, real_ino, &znode, B_FALSE);
	if(error) {
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

	if(!error) {
		VERIFY(uio.uio_loffset <= PATH_MAX);
		buf[sizeof(buf) - 1] = '\0';
	}

	return error;
}


/*
 * Returns errno on failure, 0 on success.
 */
int
zfsslash2_read(void *vfsdata, uint64_t ino, cred_t *cred,
    void *buf, size_t size, size_t *nb, off_t off, void *data)
{
	file_info_t *info = (file_info_t *)(uintptr_t) data;
	uint64_t real_ino = ino == 1 ? 3 : ino;
	vnode_t *vp = info->vp;

	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == real_ino);

	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

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


#ifdef NAMESPACE_EXPERIMENTAL
int
zfsslash2_mkdir(void *vfsdata, uint64_t parent, uint64_t fid, const char *name,
    mode_t mode, cred_t *cred, struct stat *stb, struct fidgen *fg,
    int suppress_fidlink)
#else
int
zfsslash2_mkdir(void *vfsdata, uint64_t parent, const char *name,
    mode_t mode, cred_t *cred, struct stat *stb, struct fidgen *fg,
    int suppress_fidlink)
#endif
{
	vnode_t		*vp;
	vfs_t		*vfs;
	znode_t		*znode;
	int		 error;
	zfsvfs_t	*zfsvfs;
	uint64_t	 real_parent;
	vattr_t		 vattr = { 0 };

	if (strlen(name) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	vfs = (vfs_t *)vfsdata;
	zfsvfs = vfs->vfs_data;
	real_parent = (parent == 1 ? 3 : parent);

	ZFS_ENTER(zfsvfs);

	error = zfs_zget(zfsvfs, real_parent, &znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vp = NULL;

	vattr.va_type = VDIR;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;

	error = VOP_MKDIR(dvp, (char *) name, &vattr, &vp, cred, NULL, 0, NULL);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	/* we only suppress fid link when called from mds_repl_scandir() */
	if (suppress_fidlink == 0) {
#ifdef NAMESPACE_EXPERIMENTAL
		VTOZ(vp)->z_fid = fid;
#endif
		error = zfsslash2_fidlink(zfsvfs, vp, 0);
	}

	if (fg) {
		fg->fid = VTOZ(vp)->z_id;
		if (fg->fid == 3)
			fg->fid = 1;
		fg->gen = VTOZ(vp)->z_phys->zp_gen;
	}

	if (stb) {
		error = zfsslash2_stat(vp, stb, cred);
		if (stb->st_ino == 3)
			stb->st_ino = 1;
	}

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}


int zfsslash2_rmdir(void *vfsdata, uint64_t parent, const char *name, cred_t *cred)
{
	if(strlen(name) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	uint64_t real_parent = (parent == 1 ? 3 : parent);

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, real_parent, &znode, B_FALSE);
	if(error) {
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
	error = VOP_RMDIR(dvp, (char *) name, NULL, cred, NULL, 0);

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if(error == EEXIST)
		error = ENOTEMPTY;

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_gets2szattr(void *vfsdata, uint64_t ino, off64_t *sizep, void *data)
{
	vfs_t *vfs = vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	file_info_t *info = data;
	vattr_t vattr;
	cred_t cred;
	vnode_t *vp;
	int error = 0;

	ZFS_ENTER(zfsvfs);

	TRANSLATE_INUM(&ino);

	vp = info->vp;

	/* Sanity check */
	if (vp->v_type != VREG) {
		error = EINVAL;
		goto out;
	}

	vattr.va_mask = AT_SLASH2SIZE;
	error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL);
	if (error == 0)
		*sizep = vattr.va_s2size;

 out:
	ZFS_EXIT(zfsvfs);
	return (error);
}

int
zfsslash2_sets2szattr(void *vfsdata, uint64_t ino, off64_t size, void *data)
{
	vfs_t *vfs = vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	uint64_t real_ino = ino == 1 ? 3 : ino;
	file_info_t *info = data;
	int error=0;

	ZFS_ENTER(zfsvfs);

	vnode_t *vp;

	vp = info->vp;

	/* Check if file is opened for writing */
	if((info->flags & FWRITE) == 0) {
		error = EBADF;
		goto out;
	}
	/* Sanity check */
	if(vp->v_type != VREG) {
		error = EINVAL;
		goto out;
	}

	vattr_t vattr = { 0 };
	cred_t cred = { 0 };

	vattr.va_mask |= AT_SLASH2SIZE;
	vattr.va_s2size = size;

	error = VOP_SETATTR(vp, &vattr, 0, &cred, NULL);

 out:
	ZFS_EXIT(zfsvfs);

	return error;
}

int
zfsslash2_setattr(void *vfsdata, uint64_t ino, struct stat *attr,
    int to_set, cred_t *cred, struct stat *out_attr, void *data)
{
	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	uint64_t real_ino = ino == 1 ? 3 : ino;
	file_info_t *info = (file_info_t *)data;

	ZFS_ENTER(zfsvfs);

	vnode_t *vp;
	boolean_t release;


	int error;

	if (!info) {
		znode_t *znode;

		error = zfs_zget(zfsvfs, real_ino, &znode, B_TRUE);
		if(error) {
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
		if(to_set & FUSE_SET_ATTR_SIZE) {
			/* Check if file is opened for writing */
			if((info->flags & FWRITE) == 0) {
				error = EBADF;
				goto out;
			}
			/* Sanity check */
			if(vp->v_type != VREG) {
				error = EINVAL;
				goto out;
			}

			flock64_t bf;

			bf.l_whence = 0; /* beginning of file */
			bf.l_start = attr->st_size;
			bf.l_type = F_WRLCK;
			bf.l_len = (off_t) 0;

			/* FIXME: check locks */
			error = VOP_SPACE(vp, F_FREESP, &bf, info->flags, 0, cred, NULL);
			if(error)
				goto out;

			to_set &= ~FUSE_SET_ATTR_SIZE;
			if(to_set == 0)
				goto out;
		}
	}

	ASSERT(vp != NULL);

	vattr_t vattr = { 0 };

	if(to_set & FUSE_SET_ATTR_MODE) {
		vattr.va_mask |= AT_MODE;
		vattr.va_mode = attr->st_mode;
	}
	if(to_set & FUSE_SET_ATTR_UID) {
		vattr.va_mask |= AT_UID;
		vattr.va_uid = attr->st_uid;
	}
	if(to_set & FUSE_SET_ATTR_GID) {
		vattr.va_mask |= AT_GID;
		vattr.va_gid = attr->st_gid;
	}
	if(to_set & FUSE_SET_ATTR_SIZE) {
		vattr.va_mask |= AT_SLASH2SIZE;
		vattr.va_s2size = attr->st_size;
	}
	if(to_set & FUSE_SET_ATTR_ATIME) {
		vattr.va_mask |= AT_ATIME;
		TIME_TO_TIMESTRUC(attr->st_atime, &vattr.va_atime);
	}
	if(to_set & FUSE_SET_ATTR_MTIME) {
		vattr.va_mask |= AT_MTIME;
		TIME_TO_TIMESTRUC(attr->st_mtime, &vattr.va_mtime);
	}

	int flags = (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) ? ATTR_UTIME : 0;
	error = VOP_SETATTR(vp, &vattr, flags, cred, NULL);

 out:
	if(!error && out_attr)
		error = zfsslash2_stat(vp, out_attr, cred);

	/* Do not release if vp was an opened inode */
	if(release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}


int zfsslash2_unlink(void *vfsdata, uint64_t parent, const char *name, cred_t *cred)
{
	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	uint64_t real_parent = (parent == 1 ? 3 : parent);

	if(strlen(name) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, real_parent, &znode, B_FALSE);
	if(error) {
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

	error = zfsslash2_fidlink(zfsvfs, vp, 1);
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
zfsslash2_write(void *vfsdata, uint64_t ino, cred_t *cred,
    const void *buf, size_t size, size_t *nb, off_t off, void *data)
{
	file_info_t *info = (file_info_t *)(uintptr_t) data;
	uint64_t real_ino = ino == 1 ? 3 : ino;

	vnode_t *vp = info->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == real_ino);

	vfs_t *vfs = (vfs_t *) vfsdata;
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

	int error = VOP_WRITE(vp, &uio, info->flags, cred, NULL);

	ZFS_EXIT(zfsvfs);

	if(!error) {
		/* When not using direct_io, we must always write 'size' bytes */
		VERIFY(uio.uio_resid == 0);
		*nb = size - uio.uio_resid;
	}

	return error;
}


#if 0
int zfsslash2_mknod(void *vfsdata, uint64_t parent, const char *name, mode_t mode, dev_t rdev)
{
	if(strlen(name) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if(error) {
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

	if(mode & (S_IFCHR | S_IFBLK)) {
		vattr.va_rdev = rdev;
		vattr.va_mask |= AT_RDEV;
	}

	vnode_t *vp = NULL;

	/* FIXME: check filesystem boundaries */
	error = VOP_CREATE(dvp, (char *) name, &vattr, EXCL, 0, &vp, &cred, 0, NULL, NULL);

	VN_RELE(dvp);

	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = 0.0;
	e.entry_timeout = 0.0;

	e.ino = VTOZ(vp)->z_id;
	if(e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsslash2_stat(vp, &e.attr, &cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_entry(req, &e);

	return error;
}
#endif


int
zfsslash2_symlink(void *vfsdata, const char *link, uint64_t parent,
    const char *name, cred_t *cred, struct stat *stb, struct fidgen *fg)
{
	if(strlen(name) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	uint64_t real_parent = parent == 1 ? 3 : parent;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, real_parent, &znode, B_FALSE);
	if(error) {
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

	error = VOP_SYMLINK(dvp, (char *) name, &vattr, (char *) link, cred, NULL, 0);

	vnode_t *vp = NULL;

	if(error)
		goto out;

	error = VOP_LOOKUP(dvp, (char *) name, &vp, NULL, 0, NULL, cred, NULL, NULL, NULL);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	fg->fid = VTOZ(vp)->z_id;
	if(fg->fid == 3) {
		fg->fid = 1;
		stb->st_ino = 1;
	}
	fg->gen = VTOZ(vp)->z_phys->zp_gen;

	error = zfsslash2_stat(vp, stb, cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);

	ZFS_EXIT(zfsvfs);

	return error;
}


int
zfsslash2_rename(void *vfsdata, uint64_t parent, const char *name,
    uint64_t newparent, const char *newname, cred_t *cred)
{
	if(strlen(name) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;
	if(strlen(newname) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	if (parent == 1) parent = 3;

	ZFS_ENTER(zfsvfs);

	znode_t *p_znode, *np_znode;

	int error = zfs_zget(zfsvfs, parent, &p_znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(p_znode != NULL);

	error = zfs_zget(zfsvfs, newparent, &np_znode, B_FALSE);
	if(error) {
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

	error = VOP_RENAME(p_vp, (char *) name, np_vp, (char *) newname, cred, NULL, 0);

	VN_RELE(p_vp);
	VN_RELE(np_vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

int zfsslash2_fsync(void *vfsdata, uint64_t ino, cred_t *cred, int datasync, void *data)
{
	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	if (ino == 1) ino = 3;

	ZFS_ENTER(zfsvfs);

	file_info_t *info = (file_info_t *)(uintptr_t) data;
	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);
	ASSERT(VTOZ(info->vp)->z_id == ino);

	vnode_t *vp = info->vp;

	int error = VOP_FSYNC(vp, datasync ? FDSYNC : FSYNC, cred, NULL);

	ZFS_EXIT(zfsvfs);

	return error;
}


int
zfsslash2_link(void *vfsdata, uint64_t ino, uint64_t newparent,
    const char *newname, struct fidgen *fg, cred_t *cred, struct stat *stb)
{
	if(strlen(newname) >= MAXNAMELEN) /* XXX off-by-one */
		return ENAMETOOLONG;

	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	if (newparent == 1) newparent = 3;
	if (ino == 1) ino = 3;

	ZFS_ENTER(zfsvfs);

	znode_t *td_znode, *s_znode;

	int error = zfs_zget(zfsvfs, ino, &s_znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(s_znode != NULL);

	error = zfs_zget(zfsvfs, newparent, &td_znode, B_FALSE);
	if(error) {
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

	error = VOP_LINK(tdvp, svp, (char *) newname, cred, NULL, 0);

	vnode_t *vp = NULL;

	if(error)
		goto out;

	error = VOP_LOOKUP(tdvp, (char *) newname, &vp, NULL, 0, NULL, cred, NULL, NULL, NULL);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	fg->fid = VTOZ(vp)->z_id;
	if(fg->fid == 3) {
		stb->st_ino = 1;
		fg->fid = 1;
	}

	fg->gen = VTOZ(vp)->z_phys->zp_gen;

	error = zfsslash2_stat(vp, stb, cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(tdvp);
	VN_RELE(svp);

	ZFS_EXIT(zfsvfs);

	return error;
}


int zfsslash2_access(void *vfsdata, uint64_t ino, int mask, cred_t *cred)
{
	vfs_t *vfs = (vfs_t *) vfsdata;
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	if (ino == 1) ino = 3;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);


	int mode = 0;
	if(mask & R_OK)
		mode |= VREAD;
	if(mask & W_OK)
		mode |= VWRITE;
	if(mask & X_OK)
		mode |= VEXEC;

	error = VOP_ACCESS(vp, mode, 0, cred, NULL);

	VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}
