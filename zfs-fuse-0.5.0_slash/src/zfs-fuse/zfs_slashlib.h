/* $Id$ */

#ifndef ZFS_SLASHLIB_H
#define ZFS_SLASHLIB_H 1

#include <sys/types.h>
#include <sys/statvfs.h>

#define ZFS_MAGIC 0x2f52f5

#ifdef SLASHLIB
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef struct fidgen {
        uint64_t fid;
        uint64_t gen;
} fidgen_t;
#else
typedef void vnode_t;
typedef struct slash_fidgen fidgen_t;
#endif


typedef struct file_info {
	vnode_t *vp;
	int flags;
} file_info_t;


int zfs_lib_start(const char *, const char *);
void zfs_lib_stop(void);

int zfsslash2_statfs(void *vfsdata, struct statvfs *stat);
int zfsslash2_stat(vnode_t *vp, struct stat *stbuf, cred_t *cred);
int zfsslash2_getattr(void *vfsdata, uint64_t ino, cred_t *cred, struct stat *stbuf, uint64_t *gen);
int zfsslash2_lookup(void *vfsdata, uint64_t parent, const char *name, fidgen_t *fg, cred_t *cred, struct stat *stb);
int zfsslash2_opendir(void *vfsdata, uint64_t ino, cred_t *cred, fidgen_t *fg, void **private);
int zfsslash2_release(void *vfsdata, uint64_t ino, cred_t *cred, void *data);
int zfsslash2_readdir(void *vfsdata, uint64_t ino, cred_t *cred, size_t size, off_t off, char *outbuf, size_t *outbuf_len, void  *attrs, int nstbprefetch, void *data);
int zfsslash2_readlink(void *vfsdata, uint64_t ino, char *buf, cred_t *cred);
int zfsslash2_read(void *vfsdata, uint64_t ino, cred_t *cred, char *buf, size_t size, off_t off, void *data);
int zfsslash2_mkdir(void *vfsdata, uint64_t parent, const char *name, mode_t mode, cred_t *cred, struct stat *stb, fidgen_t *fg);
int zfsslash2_rmdir(void *vfsdata, uint64_t parent, const char *name, cred_t *cred);
int zfsslash2_setattr(void *vfsdata, uint64_t ino, struct stat *attr, int to_set, cred_t *cred, struct stat *out_attr, void *data);
int zfsslash2_unlink(void *vfsdata, uint64_t parent, const char *name, cred_t *cred);
int zfsslash2_write(void *vfsdata, uint64_t ino, cred_t *cred, const char *buf, size_t size, off_t off, void *data);
int zfsslash2_mknod(void *vfsdata, uint64_t parent, const char *name, mode_t mode, dev_t rdev);
int zfsslash2_symlink(void *vfsdata, const char *link, uint64_t parent, const char *name, cred_t *cred, struct stat *stb, fidgen_t *fg);
int zfsslash2_rename(void *vfsdata, uint64_t parent, const char *name, uint64_t newparent, const char *newname, cred_t *cred);
int zfsslash2_fsync(void *vfsdata, uint64_t ino, cred_t *cred, int datasync, void *data);
int zfsslash2_link(void *vfsdata, uint64_t ino, uint64_t newparent, const char *newname, fidgen_t *fg, cred_t *cred, struct stat *stb);
int zfsslash2_access(void *vfsdata, uint64_t ino, int mask, cred_t *cred);
int zfsslash2_opencreate(void *vfsdata, uint64_t ino, cred_t *cred, int fflags,
			 mode_t createmode, const char *name, fidgen_t *fg,
			 struct stat *stb, void **private);

#endif 
