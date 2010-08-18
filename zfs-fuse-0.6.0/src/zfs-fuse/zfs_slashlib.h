/* $Id$ */

#ifndef _ZFS_SLASHLIB_H_
#define _ZFS_SLASHLIB_H_

#include <sys/types.h>

#include <stdint.h>

#include "fid.h"
#include "slashd/mdsio.h"

struct statvfs;

#ifdef ZFS_SLASHLIB
typedef struct file_info {
	vnode_t *vp;
	int flags;
} file_info_t;
#endif

//XXX shouldn't this be a single bit???
#define SLASH2_CURSOR_FLAG	0x12345678	/* overload the ioflag of zfs_write() */

int	zfsslash2_access(mdsio_fid_t, int, const struct slash_creds *);
int	zfsslash2_fsync(const struct slash_creds *, int, void *);
int	zfsslash2_getattr(mdsio_fid_t, const struct slash_creds *, struct srt_stat *);
int	zfsslash2_link(mdsio_fid_t, mdsio_fid_t, const char *, const struct slash_creds *, struct srt_stat *, sl_log_update_t);
int	zfsslash2_lookup(mdsio_fid_t, const char *, mdsio_fid_t *, const struct slash_creds *, struct srt_stat *);
int	zfsslash2_lookup_slfid(slfid_t, const struct slash_creds *, struct srt_stat *, mdsio_fid_t *);
int	zfsslash2_mkdir(mdsio_fid_t, const char *, mode_t, const struct slash_creds *, struct srt_stat *, mdsio_fid_t *, sl_log_update_t, sl_getslfid_cb_t);
int	zfsslash2_mknod(mdsio_fid_t, const char *, mode_t, dev_t);
int	zfsslash2_opencreate(mdsio_fid_t, const struct slash_creds *, int, int, mode_t, const char *, mdsio_fid_t *, struct srt_stat *, void *, sl_log_update_t, sl_getslfid_cb_t);
int	zfsslash2_opendir(mdsio_fid_t, const struct slash_creds *, struct slash_fidgen *, void *);
int	zfsslash2_read(const struct slash_creds *, void *, size_t, size_t *, off_t, void *);
int	zfsslash2_readdir(const struct slash_creds *, size_t, off_t, void *, size_t *, size_t *, void  *, int, void *);
int	zfsslash2_readlink(mdsio_fid_t, char *, const struct slash_creds *);
int	zfsslash2_release(const struct slash_creds *, void *);
int	zfsslash2_rename(mdsio_fid_t, const char *, mdsio_fid_t, const char *, const struct slash_creds *, sl_log_update_t);
int	zfsslash2_rmdir(mdsio_fid_t, const char *, const struct slash_creds *, sl_log_update_t);
int	zfsslash2_setattr(mdsio_fid_t, const struct srt_stat *, int, const struct slash_creds *, struct srt_stat *, void *, sl_log_update_t);
int	zfsslash2_statfs(struct statvfs *);
int	zfsslash2_symlink(const char *, mdsio_fid_t, const char *, const struct slash_creds *, struct srt_stat *, mdsio_fid_t *, sl_getslfid_cb_t, sl_log_update_t);
int	zfsslash2_unlink(mdsio_fid_t, const char *, const struct slash_creds *, sl_log_update_t);
int	zfsslash2_write(const struct slash_creds *, const void *, size_t, size_t *, off_t, int, void *, sl_log_write_t, void *);

int	zfsslash2_write_cursor(void *, size_t, void *, sl_log_write_t);

int	do_init(void);
void	do_exit(void);

#define zfs_init	do_init
#define zfs_exit	do_exit

int	zfsslash2_replay_create(slfid_t, slfid_t, struct srt_stat *, char *);
int	zfsslash2_replay_link(slfid_t, slfid_t, struct srt_stat *, char *);
int	zfsslash2_replay_mkdir(slfid_t, slfid_t, struct srt_stat *, char *);
int	zfsslash2_replay_rename(slfid_t, const char *, slfid_t, const char *, struct srt_stat *);
int	zfsslash2_replay_rmdir(slfid_t, slfid_t, char *, struct srt_stat *);
int	zfsslash2_replay_setattr(slfid_t, struct srt_stat *, uint);
int	zfsslash2_replay_symlink(slfid_t, slfid_t, struct srt_stat *, char *, char *);
int	zfsslash2_replay_unlink(slfid_t, slfid_t, char *, struct srt_stat *);

uint64_t	zfsslash2_last_synced_txg(void);
uint64_t	zfsslash2_return_synced(void);
void		zfsslash2_wait_synced(uint64_t);

#endif /* _ZFS_SLASHLIB_H_ */
