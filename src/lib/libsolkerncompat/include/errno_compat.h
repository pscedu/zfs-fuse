/* $Id$ */

#include <errno.h>

#ifdef HAVE_ATTR_XATTR_H
# include <attr/xattr.h>
#elif !defined(ENOATTR)
# ifdef ENODATA
#  define ENOATTR ENODATA	/* whatever getxattr(2) returns on nonexistent name */
# else
#  define ENOATTR 5001
# endif
#endif
