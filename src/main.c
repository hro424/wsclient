#include "wsclient.h"
#include <string.h>

int
main(int argc, char *argv[])
{
	char buf[20];
	const char *msg = "Hello";
	int fd = ws_connect("ws://localhost:8080");
	ws_send(fd, msg, strlen(msg));
	ws_recv(fd, buf, 20);
	ws_close(fd);
	return 0;
}
