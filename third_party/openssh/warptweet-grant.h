#ifndef WARPTWEET_GRANT_H
#define WARPTWEET_GRANT_H

#include <sys/types.h>

int warptweet_grant_register(const u_char *blob, size_t bloblen);
void warptweet_grant_unregister(void);

#endif
