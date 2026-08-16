//go:build darwin && cgo

package engine

/*
#include <errno.h>
#include <sys/acl.h>

static int
warptweet_fd_has_extended_acl(int fd, int *has_acl)
{
	acl_t acl;
	acl_entry_t entry;
	int result;
	int saved_errno;

	acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL && errno == ENOENT) {
		*has_acl = 0;
		return 0;
	}
	if (acl == NULL)
		return errno == 0 ? EIO : errno;
	result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
	saved_errno = errno;
	if (acl_free(acl) != 0 && result >= 0)
		return errno == 0 ? EIO : errno;
	if (result < 0)
		return saved_errno == 0 ? EIO : saved_errno;
	*has_acl = result == 0;
	return 0;
}
*/
import "C"

import (
	"errors"
	"os"
	"syscall"
)

func darwinFileHasExtendedACL(file *os.File) (bool, error) {
	if file == nil {
		return false, errors.New("file descriptor is required")
	}
	var hasACL C.int
	errorNumber := C.warptweet_fd_has_extended_acl(C.int(file.Fd()), &hasACL)
	if errorNumber != 0 {
		return false, syscall.Errno(errorNumber)
	}
	return hasACL == 1, nil
}
