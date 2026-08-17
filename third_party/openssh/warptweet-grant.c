#include "includes.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "digest.h"
#include "log.h"
#include "warptweet-grant.h"

#define WARPTWEET_GRANT_SOCKET "/run/warptweet/server/grant-session.sock"
#define WARPTWEET_GRANT_TIMEOUT_SEC 3

static int
warptweet_grant_exchange(const char *request, size_t request_len)
{
	struct sockaddr_un addr;
	char response[512];
	ssize_t n;
	int fd, ok = -1;
	struct timeval tv;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlcpy(addr.sun_path, WARPTWEET_GRANT_SOCKET,
	    sizeof(addr.sun_path)) >= sizeof(addr.sun_path))
		return -1;
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	tv.tv_sec = WARPTWEET_GRANT_TIMEOUT_SEC;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(fd);
		return -1;
	}
	if (write(fd, request, request_len) != (ssize_t)request_len) {
		close(fd);
		return -1;
	}
	(void)shutdown(fd, SHUT_WR);
	n = read(fd, response, sizeof(response) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	response[n] = '\0';
	if (strstr(response, "\"ok\":true") != NULL)
		ok = 0;
	return ok;
}

int
warptweet_grant_register(const u_char *blob, size_t bloblen)
{
	u_char digest[32];
	char hex[65];
	char request[192];
	size_t i;

	if (blob == NULL || bloblen == 0)
		return -1;
	if (ssh_digest_memory(SSH_DIGEST_SHA256, blob, bloblen, digest,
	    sizeof(digest)) != 0)
		return -1;
	for (i = 0; i < sizeof(digest); i++)
		snprintf(hex + (i * 2), 3, "%02x", digest[i]);
	snprintf(request, sizeof(request),
	    "{\"version\":1,\"action\":\"register\",\"key_sha256\":\"%s\"}\n",
	    hex);
	if (warptweet_grant_exchange(request, strlen(request)) != 0) {
		error("WarpTweet grant authority rejected registration");
		return -1;
	}
	return 0;
}

void
warptweet_grant_unregister(void)
{
	const char *request =
	    "{\"version\":1,\"action\":\"unregister\"}\n";

	(void)warptweet_grant_exchange(request, strlen(request));
}
