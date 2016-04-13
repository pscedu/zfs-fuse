/* $Id$ */
/* %GPL_LICENSE% */

#ifndef _ZFS_SLASHLIB_H_
#define _ZFS_SLASHLIB_H_

#include <sys/types.h>

#include <stdint.h>

#define PFL_USE_SYSTEM_STRERROR

#include "pfl/err.h"

#include "fid.h"
#include "slashd/mdsio.h"

struct statvfs;

#ifdef ZFS_SLASHLIB
typedef struct file_info {
	vnode_t		*vp;
	int		 flags;
} file_info_t;
#endif

#define MAX_FILESYSTEMS		1000

typedef struct mount_info {
	uint64_t	 zm_uuid;
	uint64_t	 zm_rootid;
	sl_siteid_t	 zm_siteid;
	int		 zm_flags;
	char		 zm_name[MAXPATHLEN];
	void		*zm_vfs;
	void		*zm_rootinfo;
} mount_info_t;

/* mount_info_t flags */
#define ZFS_SLASH2_NONE		0x00
#define ZFS_SLASH2_MKDIR	0x01
#define ZFS_SLASH2_READY	0x02

//XXX shouldn't this be a single bit???
#define SLASH2_CURSOR_UPDATE	0x12345678	/* overload the ioflag of zfs_write() */

int	zfsslash2_access(int, mdsio_fid_t, int, const struct slash_creds *);
int	zfsslash2_fsync(int, const struct slash_creds *, int, void *);
int	zfsslash2_getattr(int, mdsio_fid_t, void *finfo, const struct slash_creds *, struct srt_stat *);
int	zfsslash2_link(int, mdsio_fid_t, mdsio_fid_t, const char *, const struct slash_creds *, sl_log_update_t);
int	zfsslash2_lookup(int, mdsio_fid_t, const char *, mdsio_fid_t *, const struct slash_creds *, struct srt_stat *, uint32_t *);
int	zfsslash2_lookup_slfid(int, slfid_t, const struct slash_creds *, struct srt_stat *, mdsio_fid_t *);
int	zfsslash2_mkdir(int, mdsio_fid_t, const char *, const struct srt_stat *, int, int, struct srt_stat *, mdsio_fid_t *, sl_log_update_t, sl_getslfid_cb_t, slfid_t);
int	zfsslash2_mknod(int, mdsio_fid_t, const char *, mode_t, const struct slash_creds *, struct srt_stat *, mdsio_fid_t *, sl_log_update_t, sl_getslfid_cb_t);
int	zfsslash2_opencreate(int, mdsio_fid_t, const struct slash_creds *, int, int, mode_t, const char *, mdsio_fid_t *, struct srt_stat *, void *, sl_log_update_t, sl_getslfid_cb_t, slfid_t);
int	zfsslash2_opendir(int, mdsio_fid_t, const struct slash_creds *, struct sl_fidgen *, void *);
int	zfsslash2_preadv(int, const struct slash_creds *, struct iovec *, int, size_t *, off_t, void *);
int	zfsslash2_pwritev(int, const struct slash_creds *, const struct iovec *, int, size_t *, off_t, void *, sl_log_write_t, void *);
int	zfsslash2_read(int, const struct slash_creds *, void *, size_t, size_t *, off_t, void *);
int	zfsslash2_readdir(int, const struct slash_creds *, size_t, off_t, void *, size_t *, int *, struct iovec *, int *, off_t *, void *);
int	zfsslash2_readlink(int, mdsio_fid_t, char *, size_t *, const struct slash_creds *);
int	zfsslash2_release(int, const struct slash_creds *, void *);
int	zfsslash2_rename(int, mdsio_fid_t, const char *, mdsio_fid_t, const char *, const struct slash_creds *, sl_log_update_t, void *);
int	zfsslash2_rmdir(int, mdsio_fid_t, struct sl_fidgen *, const char *, const struct slash_creds *, sl_log_update_t);
int	zfsslash2_setattr(int, mdsio_fid_t, const struct srt_stat *, int, const struct slash_creds *, struct srt_stat *, void *, sl_log_update_t);
int	zfsslash2_statfs(int, struct statvfs *);
int	zfsslash2_symlink(int, const char *, mdsio_fid_t, const char *, const struct slash_creds *, struct srt_stat *, mdsio_fid_t *, sl_log_update_t, sl_getslfid_cb_t, slfid_t);
int	zfsslash2_unlink(int, mdsio_fid_t, struct sl_fidgen *, const char *, const struct slash_creds *, sl_log_update_t, void *);
int	zfsslash2_write(int, const struct slash_creds *, const void *, size_t, size_t *, off_t, void *, sl_log_write_t, void *);

int	zfsslash2_getxattr(int, const struct slash_creds *, const char *, char *, size_t, size_t *, mdsio_fid_t);
int	zfsslash2_hasxattrs(int, const struct slash_creds *, mdsio_fid_t);
int	zfsslash2_listxattr(int, const struct slash_creds *, void *, size_t, size_t *, mdsio_fid_t);
int	zfsslash2_removexattr(int, const struct slash_creds *, const char *, mdsio_fid_t);
int	zfsslash2_setxattr(int, const struct slash_creds *, const char *, const char *, size_t, mdsio_fid_t);

int	zfsslash2_write_cursor(int, void *, size_t, void *, sl_log_write_t);

int	do_init_fusesocket(void);
int	do_init(void);
void	do_exit(void);

#define libzfs_init_fusesocket	do_init_fusesocket
#define libzfs_init		do_init
#define libzfs_exit		do_exit

void		arc_set_slashd(void);
uint64_t	arc_get_maxsize(void);
void		arc_set_maxsize(uint64_t);

int		zfsslash2_build_immns_cache(int);
int		zfsslash2_setattrmask_2_slflags(uint);
uint		zfsslash2_slflags_2_setattrmask(int);
mdsio_fid_t	zfsslash2_getfidlinkdir(slfid_t);

int	zfsslash2_replay_create(int, slfid_t, char *, struct srt_stat *stat);
int	zfsslash2_replay_fidlink(int, slfid_t, const struct slash_creds *);
int	zfsslash2_replay_link(int, slfid_t, slfid_t, char *, struct srt_stat *stat);
int	zfsslash2_replay_mkdir(int, slfid_t, char *, struct srt_stat *stat);
int	zfsslash2_replay_rename(int, slfid_t, const char *, slfid_t, const char *, struct srt_stat *);
int	zfsslash2_replay_rmdir(int, slfid_t, slfid_t, char *);
int	zfsslash2_replay_setattr(int, slfid_t, uint, struct srt_stat *);
int	zfsslash2_replay_symlink(int, slfid_t, slfid_t, char *, char *, struct srt_stat *stat);
int	zfsslash2_replay_unlink(int, slfid_t, slfid_t, char *);
int	zfsslash2_replay_setxattr(int, slfid_t, const char *, const char *, size_t);
int	zfsslash2_replay_removexattr(int, slfid_t, const char *);

uint64_t	zfsslash2_last_synced_txg(void);
uint64_t	zfsslash2_return_synced(void);
void		zfsslash2_wait_synced(uint64_t);

extern int		zfs_nmounts;
extern mount_info_t	zfs_mounts[];

extern int		current_vfsid;

void		(*zfsslash2_cursor_start)(void);
void		(*zfsslash2_cursor_end)(void);

#endif /* _ZFS_SLASHLIB_H_ */
