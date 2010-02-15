/* $Id$ */

#ifndef ZFS_SLASHLIB_H
#define ZFS_SLASHLIB_H

#include <sys/types.h>

#include <stdint.h>

#include "fid.h"
#include "slashrpc.h"

struct statvfs;

/*
 * To save space, a SLASH ID consists of three parts: 4 bits for flags, 10 bits
 * for site ID, and 50 bits for a sequence number.
 *
 * SLASH ID should be used externally by a client or a peer MDS to identify a
 * file.  The ZFS inode number should ony be used internally.
 */
#ifdef SLASHLIB
typedef struct file_info {
	vnode_t *vp;
	int flags;
} file_info_t;
#endif

int	zfsslash2_access(void *, uint64_t, int, const struct slash_creds *);
int	zfsslash2_fsync(void *, uint64_t, const struct slash_creds *, int, void *);
int	zfsslash2_getattr(void *, uint64_t, const struct slash_creds *, struct srt_stat *, uint64_t *);
int	zfsslash2_link(void *, uint64_t, uint64_t, const char *, struct slash_fidgen *, const struct slash_creds *, struct srt_stat *);
int	zfsslash2_lookup(void *, uint64_t, const char *, struct slash_fidgen *, const struct slash_creds *, struct srt_stat *);
int	zfsslash2_mkdir(void *, uint64_t, const char *, mode_t, const struct slash_creds *, struct srt_stat *, struct slash_fidgen *, int);
int	zfsslash2_mknod(void *, uint64_t, const char *, mode_t, dev_t);
int	zfsslash2_opencreate(void *, uint64_t, const struct slash_creds *, int, mode_t, const char *, struct slash_fidgen *, struct srt_stat *, void **);
int	zfsslash2_opendir(void *, uint64_t, const struct slash_creds *, struct slash_fidgen *, struct srt_stat *, void **);
int	zfsslash2_read(void *, uint64_t, const struct slash_creds *, void *, size_t, size_t *, off_t, void *);
int	zfsslash2_readdir(void *, uint64_t, const struct slash_creds *, size_t, off_t, void *, size_t *, void  *, int, void *);
int	zfsslash2_readlink(void *, uint64_t, char *, const struct slash_creds *);
int	zfsslash2_release(void *, uint64_t, const struct slash_creds *, void *);
int	zfsslash2_rename(void *, uint64_t, const char *, uint64_t, const char *, const struct slash_creds *);
int	zfsslash2_rmdir(void *, uint64_t, const char *, const struct slash_creds *);
int	zfsslash2_setattr(void *, uint64_t, struct srt_stat *, int, const struct slash_creds *, struct srt_stat *, void *);
int	zfsslash2_statfs(void *, struct statvfs *, uint64_t);
int	zfsslash2_symlink(void *, const char *, uint64_t, const char *, const struct slash_creds *, struct srt_stat *, struct slash_fidgen *);
int	zfsslash2_unlink(void *, uint64_t, const char *, const struct slash_creds *);
int	zfsslash2_write(void *, uint64_t, const struct slash_creds *, const void *, size_t, size_t *, off_t, void *);

int	do_init(void);
void	do_exit(void);

#define zfs_init()	do_init()
#define zfs_exit()	do_exit()

extern void *zfsVfs;

#endif
