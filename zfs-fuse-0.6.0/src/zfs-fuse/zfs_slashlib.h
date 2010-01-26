/* $Id$ */

#ifndef ZFS_SLASHLIB_H
#define ZFS_SLASHLIB_H

#include <sys/types.h>
#include <sys/statvfs.h>

#define ZFS_MAGIC 0x2f52f5

#ifdef SLASHLIB
typedef struct fidgen {
	uint64_t fid;
	uint64_t gen;
} fidgen_t;

typedef struct file_info {
	vnode_t *vp;
	int flags;
} file_info_t;
#else
typedef struct slash_fidgen fidgen_t;
typedef void vnode_t;
#endif

int	zfs_lib_start(const char *, const char *);
void	zfs_lib_stop(void);

int zfsslash2_access(void *, uint64_t, int, cred_t *);
int zfsslash2_fsync(void *, uint64_t, cred_t *, int, void *);
int zfsslash2_getattr(void *, uint64_t, cred_t *, struct stat *, uint64_t *);
int zfsslash2_gets2szattr(void *, uint64_t, off64_t *, void *);
int zfsslash2_link(void *, uint64_t, uint64_t, const char *, fidgen_t *, cred_t *, struct stat *);
int zfsslash2_lookup(void *, uint64_t, const char *, fidgen_t *, cred_t *, struct stat *);
int zfsslash2_mkdir(void *, uint64_t, const char *, mode_t, cred_t *, struct stat *, fidgen_t *, int);
int zfsslash2_mknod(void *, uint64_t, const char *, mode_t, dev_t);
int zfsslash2_opencreate(void *, uint64_t, cred_t *, int, mode_t, const char *, fidgen_t *, struct stat *, void **);
int zfsslash2_opendir(void *, uint64_t, cred_t *, fidgen_t *, struct stat *, void **);
int zfsslash2_read(void *, uint64_t, cred_t *, void *, size_t, size_t *, off_t, void *);
int zfsslash2_readdir(void *, uint64_t, cred_t *, size_t, off_t, void *, size_t *, void  *, int, void *);
int zfsslash2_readlink(void *, uint64_t, char *, cred_t *);
int zfsslash2_release(void *, uint64_t, cred_t *, void *);
int zfsslash2_rename(void *, uint64_t, const char *, uint64_t, const char *, cred_t *);
int zfsslash2_rmdir(void *, uint64_t, const char *, cred_t *);
int zfsslash2_setattr(void *, uint64_t, struct stat *, int, cred_t *, struct stat *, void *);
int zfsslash2_sets2szattr(void *, uint64_t, off64_t, void *);
int zfsslash2_stat(vnode_t *, struct stat *, cred_t *);
int zfsslash2_statfs(void *, struct statvfs *, uint64_t);
int zfsslash2_symlink(void *, const char *, uint64_t, const char *, cred_t *, struct stat *, fidgen_t *);
int zfsslash2_unlink(void *, uint64_t, const char *, cred_t *);
int zfsslash2_write(void *, uint64_t, cred_t *, const void *, size_t, size_t *, off_t, void *);

int  do_init(void);
void do_exit(void);

#define zfs_init()	do_init()
#define zfs_exit()	do_exit()

extern void *zfsVfs;

#endif
