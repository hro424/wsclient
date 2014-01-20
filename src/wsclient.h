#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <stdint.h>
#include <stdlib.h>
#include <openssl/ssl.h>

struct ws {
	int fd;
	SSL *ssl;
	struct ws_ops *ops;
};

struct ws_ops {
	ssize_t (*read)(struct ws *ws, void *buf, size_t len);
	ssize_t (*write)(struct ws *ws, const void *buf, size_t len);
	void (*close)(struct ws *ws);
};

void ws_set_proxy(const char *host, uint16_t port);
void ws_set_ca_cert(const char *cert);
void ws_unset_ca_cert(void);
void ws_set_client_cert(const char *cert, const char *key, const char *passwd);
void ws_unset_client_cert(void);
struct ws *ws_connect(const char *url, const char *proto);
ssize_t ws_send(struct ws *ws, const void *buf, size_t len);
ssize_t ws_recv(struct ws *ws, void *buf, size_t len);
void ws_close(struct ws *ws);

#endif /* WEBSOCKET_H */
