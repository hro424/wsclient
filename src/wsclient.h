#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <stdlib.h>

int ws_connect(const char *host);
int ws_send(int fd, const void *buf, size_t len);
int ws_recv(int fd, void *buf, size_t len);
void ws_close(int fd);

#endif /* WEBSOCKET_H */
