/* $Id$ */

#ifndef ZFS_SLASHLIB_H
#define ZFS_SLASHLIB_H

#include <sys/types.h>

#include <stdint.h>

#include "fid.h"
#include "slashrpc.h"

struct statvfs;

#ifdef SLASHLIB
typedef struct file_info {
	vnode_t *vp;
	int flags;
} file_info_t;
#endif

int	zfsslash2_access(uint64_t, int, const struct slash_creds *);
int	zfsslash2_fsync(const struct slash_creds *, int, void *);
int	zfsslash2_getattr(uint64_t, const struct slash_creds *, struct srt_stat *, uint64_t *);
int	zfsslash2_link(uint64_t, uint64_t, const char *, struct slash_fidgen *, const struct slash_creds *, struct srt_stat *);
int	zfsslash2_lookup(uint64_t, const char *, struct slash_fidgen *, const struct slash_creds *, struct srt_stat *);
int	zfsslash2_mkdir(uint64_t, const char *, mode_t, const struct slash_creds *, struct srt_stat *, struct slash_fidgen *);
int	zfsslash2_mknod(uint64_t, const char *, mode_t, dev_t);
int	zfsslash2_opencreate(uint64_t, const struct slash_creds *, int, mode_t, const char *, struct slash_fidgen *, struct srt_stat *, void **);
int	zfsslash2_opendir(uint64_t, const struct slash_creds *, struct slash_fidgen *, struct srt_stat *, void **);
int	zfsslash2_read(const struct slash_creds *, void *, size_t, size_t *, off_t, void *);
int	zfsslash2_readdir(const struct slash_creds *, size_t, off_t, void *, size_t *, void  *, int, void *);
int	zfsslash2_readlink(uint64_t, char *, const struct slash_creds *);
int	zfsslash2_release(const struct slash_creds *, void *);
int	zfsslash2_rename(uint64_t, const char *, uint64_t, const char *, const struct slash_creds *);
int	zfsslash2_rmdir(uint64_t, const char *, const struct slash_creds *);
int	zfsslash2_setattr(uint64_t, const struct srt_stat *, int, const struct slash_creds *, struct srt_stat *, void *);
int	zfsslash2_statfs(struct statvfs *, uint64_t);
int	zfsslash2_symlink(const char *, uint64_t, const char *, const struct slash_creds *, struct srt_stat *, struct slash_fidgen *);
int	zfsslash2_unlink(uint64_t, const char *, const struct slash_creds *);
int	zfsslash2_write(const struct slash_creds *, const void *, size_t, size_t *, off_t, void *);

int	do_init(void);
void	do_exit(void);

#define zfs_init()	do_init()
#define zfs_exit()	do_exit()

#endif /* _ZFS_SLASHLIB_H_ */
