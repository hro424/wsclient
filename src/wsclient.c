#include <config.h>
#include <wsclient.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#ifdef __MACH__
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#endif

#define SCHEMELEN	8
#define HOSTLEN		64
#define PATHLEN		128
#define MSGLEN		256
#define KEYLEN		25
#define BUFLEN		4096

#ifdef DEBUG
#define ENTER()		printf("ENTER %s\n", __func__)
#define EXIT()		printf("EXIT %s\n", __func__)
#else
#define ENTER()
#define EXIT()
#endif

static const uint16_t HTTP_DEFAULT_PORT = 80;
static const char * const HTTP_VER1_0 = "HTTP/1.0";
static const char * const HTTP_VER1_1 = "HTTP/1.1";
static const char * const HTTP_HEADER_UPGRADE = "Upgrade:";
static const char * const HTTP_HEADER_CONNECTION = "Connection:";
static const char * const HTTP_HEADER_WEBSOCKET_ACCEPT =
	"Sec-WebSocket-Accept:";
static const char * const RESPONSE_LINE_WS =
	"HTTP/1.1 101 Switching Protocols\r\n";
static const char * const WS_KEY_TOKEN =
	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static const uint8_t WS_OPCODE_TEXT = 0x01;
static const uint8_t WS_OPCODE_BINARY = 0x02;
static const uint8_t WS_OPCODE_CLOSE = 0x08;
static const uint8_t WS_OPCODE_PING = 0x09;
static const uint8_t WS_OPCODE_PONG = 0x0A;

#ifdef CLIENT_CERT
static const char * const CACERT_FILE = "etc/cacert.pem";
static const char * const CLIENT_CERT_FILE = "etc/c1-testclient01.crt.pem";
static const char * const CLIENT_KEY_FILE = "etc/c1-testclient01.key.pem";
static char *client_cert_password;
#else
static const char * const CACERT_FILE = "etc/cacert_s.pem";
#endif

static char proxy[HOSTLEN] = {0,};
static uint16_t proxy_port;


/**
 * Parses a given URL.
 *
 * @param url		the URL.
 * @param host		the host part in the URL.
 * @param port		the port part in the URL.
 * @param path		the remaining part in the URL.
 * @return		0 on success, otherwise -1.
 */
static int
parse_url(const char *url, char *scheme, size_t schemelen,
	  char *host, size_t hostlen, uint16_t *port,
	  char *path, size_t pathlen)
{
	const char *p = NULL;

	if (url == NULL || host == NULL) {
		return EINVAL;
	}

	p = strstr(url, "://");
	if (p == NULL) {
		return EINVAL;
	}

	p += 3;
	if (scheme) {
		int len = p - url;
		if (len < schemelen) {
			memcpy(scheme, url, len);
			scheme[len] = '\0';
		}
	}

	if (port) {
		*port = HTTP_DEFAULT_PORT;
	}

	while (*p != '\0' && hostlen > 0) {
		if (*p == '/') {
			break;
		}
		else if (*p == ':') {
			long n;
			p++;
			n = strtol(p, (char **)&p, 10);
			if (port) {
				*port = (int)n;
			}
			break;
		}
		else {
			*host = *p;
		}
		host++;
		p++;
		hostlen--;
	}
	*host = '\0';

	if (path) {
		if (*p != '/') {
			*path = '/';
			path++;
			pathlen--;
		}
		strncpy(path, p, pathlen);
	}

	return 0;
}

static inline char
base64_digit(int i)
{
	static const char * const BASE64_ALPHABET =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if (0 <= i && i < 64) {
		return BASE64_ALPHABET[i];
	}
	else {
		return '=';
	}
}

static inline void
base64_encode0(const unsigned char *in, size_t len, char *out)
{
	char tmp = 0;

	out[2] = out[3] = '=';

	if (len > 2) {
		out[3] = base64_digit(in[2] & 0x3F);
		tmp = (in[2] >> 6) & 0x3;
	}

	if (len > 1) {
		tmp |= (in[1] & 0xF) << 2;
		out[2] = base64_digit(tmp);
		tmp = ((in[1] >> 4) & 0xF);
	}

	tmp |= (in[0] & 0x3) << 4;
	out[1] = base64_digit(tmp);
	out[0] = base64_digit((in[0] >> 2)& 0x3F);
}

/**
 * Base 64 encoding.  The output buffer must be allocated outside the
 * function.  The output buffer is null-terminated if it completes the
 * encoding.
 *
 * @param in		the array of values.
 * @param inlen		the size of the array in bytes.
 * @param out		the output buffer.
 * @param outlen	the size of the buffer in bytes.
 * @return		the size of the encoded string.
 */
static size_t
base64_encode(const unsigned char *in, size_t inlen,
	      char *out, size_t outlen)
{
	size_t r = 0;

	if ((in == NULL) | (out == NULL)) {
		return 0;
	}

	while (inlen >= 3 && r < outlen - 4) {
		base64_encode0(in, 3, out);
		in += 3;
		out += 4;
		inlen -= 3;
		r += 4;
	}

	if (inlen > 0 && r < outlen - 4) {
		base64_encode0(in, inlen, out);
		out += 4;
	}
	*out = '\0';
	return r;
}

static void
generate_key(char *key)
{
	int i;
	unsigned char a[16];

	for (i = 0; i < 4; i++) {
		long v = random();
		a[4 * i] = (unsigned char)(v & 0xFF);
		a[4 * i + 1] = (unsigned char)((v >> 8) & 0xFF);
		a[4 * i + 2] = (unsigned char)((v >> 16) & 0xFF);
		a[4 * i + 3] = (unsigned char)((v >> 24) & 0xFF);
	}

	base64_encode(a, 16, key, KEYLEN);
}

static void
encode_key(const char *in, char *out)
{
	char buf[64];
	unsigned char md[20];

	strcpy(buf, in);
	strcat(buf, WS_KEY_TOKEN);
#ifdef __MACH__
	CC_SHA1(buf, strlen(buf), md);
#else
	SHA1((unsigned char *)buf, strlen(buf), md);
#endif
	base64_encode(md, 20, out, 32);
}

static int
do_connect(const char *host, uint16_t port)
{
	int fd = -1;
	struct addrinfo *info = NULL;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if (getaddrinfo(host, NULL, &hints, &info) != 0) {
		goto exit;
	}

	((struct sockaddr_in *)info->ai_addr)->sin_port = htons(port);
	fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if (fd < 0) {
		goto exit;
	}

	if (connect(fd, info->ai_addr, info->ai_addrlen) < 0) {
		close(fd);
	}

exit:
	if (info) {
		freeaddrinfo(info);
	}
	return fd;
}

static int
parse_rescode(char *msg)
{
	char *t = strtok(msg, " ");

	if (t == NULL) {
		return -1;
	}

	if (strncmp(t, HTTP_VER1_0, strlen(HTTP_VER1_0)) != 0 && 
	    strncmp(t, HTTP_VER1_1, strlen(HTTP_VER1_1)) != 0) {
		return -1;
	}

	t = strtok(NULL, " ");
	if (t == NULL) {
		return -1;
	}

	return strtol(t, NULL, 10);
}

static int
http_connect(int fd, const char *server, uint16_t port)
{
	char buf[MSGLEN];
	int r = -1;

	if (port == 0) {
		port = HTTP_DEFAULT_PORT;
	}

	sprintf(buf,
		"CONNECT %s:%u\x0d\x0aHOST: %s\x0d\x0a"
		"Proxy-Connection: keep-alive\x0d\x0a\x0d\x0a",
		server, port, server);
	r = write(fd, buf, strlen(buf));
	if (r < 0) {
		return r;
	}

	memset(buf, 0, MSGLEN);
	r = read(fd, buf, MSGLEN);
	if (r > 0) {
		r = parse_rescode(buf);
	}
	return r;
}

static int
connect_server(const char *host, uint16_t port, int *code)
{
	int fd;

	if (strlen(proxy) > 0) {
		fd = do_connect(proxy, proxy_port);
		if (fd > 0) {
			int res = http_connect(fd, host, port);
			if (res != 200) {
				close(fd);
				fd = -1;
			}
			if (code) {
				*code = res;
			}
		}
	}
	else {
		fd = do_connect(host, port);
	}

	return fd;
}

#ifdef CLIENT_CERT
static int
passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
	strcpy(buf, client_cert_password);
	return strlen(buf);
}
#endif

static SSL *
init_ssl(void)
{
	SSL_CTX *ctx;

	SSL_load_error_strings();
	SSL_library_init();

	ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	if (!SSL_CTX_load_verify_locations(ctx, CACERT_FILE, NULL))
		goto err;
#ifdef CLIENT_CERT
	SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
	if (!SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE,
					  SSL_FILETYPE_PEM))
		goto err;

	if (!SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE,
					 SSL_FILETYPE_PEM))
		goto err;

	if (!SSL_CTX_check_private_key(ctx))
		goto err;
#endif
	return SSL_new(ctx);
err:
	SSL_CTX_free(ctx);
	return NULL;
}

static void
destroy_ssl(SSL *obj)
{
	SSL_CTX *ctx = SSL_get_SSL_CTX(obj);
	SSL_free(obj);
	SSL_CTX_free(ctx);
}

static ssize_t
wsc_read(struct ws *ws, void *buf, size_t len)
{
	return read(ws->fd, buf, len);
}

static ssize_t
wsc_write(struct ws *ws, const void *buf, size_t len)
{
	return write(ws->fd, buf, len);
}

static void
wsc_close(struct ws *ws)
{
	close(ws->fd);
}

static ssize_t
wss_read(struct ws *ws, void *buf, size_t len)
{
	return SSL_read(ws->ssl, buf, len);
}

static ssize_t
wss_write(struct ws *ws, const void *buf, size_t len)
{
	return SSL_write(ws->ssl, buf, len);
}

static void
wss_close(struct ws *ws)
{
	int fd = SSL_get_fd(ws->ssl);

	SSL_shutdown(ws->ssl);
	destroy_ssl(ws->ssl);

	ERR_free_strings();

	close(fd);
}

static struct ws_ops wsc_ops = {
	.read = wsc_read,
	.write = wsc_write,
	.close = wsc_close,
};

static struct ws_ops wss_ops = {
	.read = wss_read,
	.write = wss_write,
	.close = wss_close,
};


static int
verify(SSL *ssl)
{
	int rc;

	rc = SSL_get_verify_result(ssl);
	if (rc != X509_V_OK) {
		printf("warning: verification faled: %d\n", rc);
#ifdef SSL_WORKAROUND
		// Verification always fails because a local issuer is
		// not defined.
		return -1;
#endif
	}
	return 0;
}

static struct ws *
ws_prepare(const char *scheme, const char *host, uint16_t port)
{
	int fd;
	struct ws *ws;
	SSL *ssl_obj;

	ENTER();
	fd = connect_server(host, port, NULL);
	if (fd < 0)
		return NULL;

	ws = malloc(sizeof(struct ws));
	if (ws == NULL) {
		return NULL;
	}

	ws->fd = fd;

	if (strncmp(scheme, "https", strlen("https")) == 0 ||
	    strncmp(scheme, "wss", strlen("wss")) == 0) {
		ssl_obj = init_ssl();
		if (ssl_obj == NULL) {
			ERR_print_errors_fp(stderr);
			goto err;
		}

		if (SSL_set_fd(ssl_obj, fd) != 1)
			goto ssl_err;

		if (SSL_connect(ssl_obj) != 1)
			goto ssl_err;

		verify(ssl_obj);

		ws->ssl = ssl_obj;
		ws->ops = &wss_ops;
	}
	else {
		ws->ssl = NULL;
		ws->ops = &wsc_ops;
	}

	EXIT();
	return ws;
ssl_err:
	destroy_ssl(ssl_obj);

err:
	if (ws) {
		free(ws);
	}
	close(fd);
	return NULL;
}

static ssize_t
ws_raw_write(struct ws *ws, void *buf, size_t len)
{
	return ws->ops->write(ws, buf, len);
}

static ssize_t
ws_raw_read(struct ws *ws, void *buf, size_t len)
{
	return ws->ops->read(ws, buf, len);
}

/*
static ssize_t
receive(struct ws *ws, void *buf, size_t len)
{
	struct pollfd fds[1] = {{ws->fd, POLLIN, 0}};
	int r;
	ssize_t s = 0;

	while (1) {
		r = poll(fds, 1, 0);
		if (r > 0) {
			s = ws_raw_read(ws, buf, len);
			if (s > 0) {
				break;
			}
		}
	}
	return s;
}
*/

static int
request_upgrade(struct ws *ws, const char *host, uint16_t port,
		const char *path, const char *key, const char *proto)
{
	char buf[MSGLEN];
	ssize_t r;
	int n;

	n = sprintf(buf, "GET %s HTTP/1.1\x0d\x0a", path);
	r = ws_raw_write(ws, buf, n);
	printf("WS: %s", buf);

	n = sprintf(buf, "Host: %s:%u\x0d\x0a", host, port);
	r = ws_raw_write(ws, buf, n);
	printf("WS: %s", buf);

	n = sprintf(buf, "Upgrade: websocket\x0d\x0a");
	r = ws_raw_write(ws, buf, n);
	printf("WS: %s", buf);

	n = sprintf(buf, "Connection: Upgrade\x0d\x0a");
	r = ws_raw_write(ws, buf, n);
	printf("WS: %s", buf);

	n = sprintf(buf, "Sec-WebSocket-Key: %s\x0d\x0a", key);
	r = ws_raw_write(ws, buf, n);
	printf("WS: %s", buf);

	if (proto) {
		n = sprintf(buf, "Sec-WebSocket-Protocol: %s\x0d\x0a", proto);
		r = ws_raw_write(ws, buf, n);
		printf("WS: %s", buf);
	}

	n = sprintf(buf, "Sec-WebSocket-Version: 13\x0d\x0a\x0d\x0a");
	r = ws_raw_write(ws, buf, n);
	printf("WS: %s", buf);

	if (r > 0) {
		return 0;
	}
	else {
		return -1;
	}
}

void
ws_set_proxy(const char *host, uint16_t port)
{
	memcpy(proxy, host, strlen(host));
	proxy_port = port;
}

void
ws_set_passwd(const char *str)
{
#ifdef CLIENT_CERT
	if (str) {
		client_cert_password = malloc(strlen(str) + 1);
		if (client_cert_password) {
			strcpy(client_cert_password, str);
		}
		else {
			fprintf(stderr, "out of memory\n");
		}
	}
#endif
}

int
verify_response(struct ws *ws, const char *key)
{
	int r, upgrade, connection, accept;
	char buf[MSGLEN];
	const char *p, *q;

	do {
		r = ws_raw_read(ws, buf, strlen(RESPONSE_LINE_WS));
	} while (r < 0);

	if (strncmp(buf, RESPONSE_LINE_WS, strlen(RESPONSE_LINE_WS)) != 0) {
		fprintf(stderr, "not equal '%s' '%s'\n", RESPONSE_LINE_WS, buf);
		goto err;
	}

	// XXX: buf[MSGLEN] may not be sufficient to capture the response.
	memset(buf, 0, MSGLEN);
	r = ws_raw_read(ws, buf, MSGLEN - 1);

	upgrade = connection = accept = 0;
	p = buf;
	while (1) {
		q = strstr(p, "\x0d\x0a");
		if (p == q || q == NULL) {
			break;
		}
		else if (strncmp(p, HTTP_HEADER_UPGRADE,
				 strlen(HTTP_HEADER_UPGRADE)) == 0) {
			p += strlen(HTTP_HEADER_UPGRADE);
			while (*p == ' ') p++;

			if (strncasecmp(p, "websocket", strlen("websocket"))
			    == 0) {
				upgrade = 1;
			}
		}
		else if (strncmp(p, HTTP_HEADER_CONNECTION,
				 strlen(HTTP_HEADER_CONNECTION)) == 0) {
			p += strlen(HTTP_HEADER_CONNECTION);
			while (*p == ' ') p++;

			if (strncasecmp(p, "upgrade", strlen("upgrade"))
			    == 0) {
				connection = 1;
			}
		}
		else if (strncmp(p, HTTP_HEADER_WEBSOCKET_ACCEPT,
				 strlen(HTTP_HEADER_WEBSOCKET_ACCEPT)) == 0) {
			p += strlen(HTTP_HEADER_WEBSOCKET_ACCEPT);
			while (*p == ' ') p++;

			if (strncmp(p, key, strlen(key)) == 0) {
				accept = 1;
			}
		}
		p = q + 2;
	}

	if (r == MSGLEN) {	// FIXME
		while (ws_raw_read(ws, buf, MSGLEN) != 0) ;
	}

	if (!(upgrade && connection && accept)) {
		fprintf(stderr, "%s %s %s\n", upgrade ? "upgrade" : "",
			connection ? "connection" : "",
			accept ? "accept" : "");
		goto err;
	}

	return 0;
err:
	return -1;
}

/**
 * Establishes a WebSocket connection.  Schemes "http://", "ws://",
 * "https://" and "wss://" are supported.
 *
 * @param url		the websocket url.
 * @return		file descriptor is return if success, otherwise -1.
 */
struct ws *
ws_connect(const char *url, const char *proto)
{
	struct ws *ws;
	char key[32];
	char scheme[SCHEMELEN];
	char host[HOSTLEN];
	char path[PATHLEN];
	uint16_t port;

	if (parse_url(url, scheme, SCHEMELEN, host, HOSTLEN, 
		      &port, path, PATHLEN))
		return NULL;

	ws = ws_prepare(scheme, host, port);
	if (ws == NULL) {
		return NULL;
	}

	generate_key(key);
	if (request_upgrade(ws, host, port, path, key, proto)) {
		fprintf(stderr, "upgrade failed.\n");
		goto err;
	}

	encode_key(key, key);
	if (verify_response(ws, key)) {
		fprintf(stderr, "response verification failed.\n");
		goto err;
	}

	return ws;
err:
	ws_close(ws);
	return NULL;
}

static inline void
set_fin(unsigned char *frame)
{
	frame[0] |= 0x80;
}

static inline int
set_opcode(unsigned char *frame, uint8_t opcode)
{
	frame[0] |= (opcode & 0xF);
	return 1;
}

/**
 * Sets the length of the payload data in bytes.
 *
 * @param 	the length
 * @param	the frame
 */
static inline int
set_length(unsigned char *frame, unsigned int length)
{
	if (length < 126) {
		frame[1] |= length;
		return 2;
	}
	else if (length < 65536) {
		frame[1] |= 126;
		frame[2] = length >> 8;
		frame[3] = length & 0xFF;
		return 4;
	}
	else {
		frame[1] |= 127;
		//XXX: Large frames unsupported.
		return -1;
	}
}


static inline int
set_mask(unsigned char *frame, int offset, uint32_t mask)
{
	frame[1] |= 0x80;
	frame[offset] = mask >> 24;
	frame[offset + 1] = (mask >> 16) & 0xFF;
	frame[offset + 2] = (mask >> 8) & 0xFF;
	frame[offset + 3] = mask & 0xFF;
	return offset + 4;
}

static inline unsigned int
get_length(unsigned char *frame)
{
	unsigned int len;

	len = frame[1] & 0x7F;
	if (len == 126) {
		len = frame[2] << 8 | frame[3];
	}
	else if (len == 127) {
		//XXX: Large frames unsupported.
		len = (unsigned int)-1;
	}
	return len;
}

/**
 * Delivers the data through WebSocket.
 *
 * @param fd		the file descriptor
 * @param buf		the data to be sent
 * @param len		the length of the data in bytes
 */
ssize_t
ws_send(struct ws *ws, const void *buf, size_t len)
{
	uint32_t mask;
	uint8_t b[BUFLEN];
	int i, r;
	uint32_t *p;

	memset(b, 0, BUFLEN);
	set_fin(b);
	set_opcode(b, WS_OPCODE_TEXT);
	i = set_length(b, len);
	mask = (uint32_t)random();
	i = set_mask(b, i, htonl(mask));
	r = ws_raw_write(ws, b, i);

	while (len > BUFLEN) {
		memcpy(b, buf, BUFLEN);
		for (p = (uint32_t *)b; p < (uint32_t *)(b + BUFLEN); p++) {
			*p ^= mask;
		}
		r += ws_raw_write(ws, b, BUFLEN);
		len -= BUFLEN;
	}

	memcpy(b, buf, len);
	for (p = (uint32_t *)b; p < (uint32_t *)(b + len); p++) {
		*p ^= mask;
	}
	r += ws_raw_write(ws, b, len);

	return r;
}


/**
 * Receives data through WebSocket.
 *
 * @param fd		the file descriptor
 * @param buf		the reception window
 * @param len		the length of the buffer in bytes
 */
ssize_t
ws_recv(struct ws *ws, void *buf, size_t len)
{
	uint8_t b[4];
	int l, r;

	// Read header
	r = ws_raw_read(ws, b, 2);
	if (r < 0) {
		return -1;
	}

	l = b[1] & 0x7F;
	if (l == 126) {
		r = ws_raw_read(ws, b + 2, 2);
		if (r < 0) {
			return -1;
		}
		l = *(int *)(b + 2);
	}
	else if (l == 127) {
		//XXX: unsupported
		return -1;
	}

	l = l > len ? len : l;

	r = ws_raw_read(ws, buf, l);

	return r;
}

/**
 * Closes WebSocket.
 *
 * @param fd	the file descriptor
 */
void
ws_close(struct ws *ws)
{
	uint8_t b[2] = {0, 0};
	int r;

	set_fin(b);
	set_opcode(b, WS_OPCODE_CLOSE); 
	r = ws_raw_write(ws, b, 2);
	if (r < 0) {
		ws->ops->close(ws);
	}
	else {
		ws->ops->close(ws);
	}
	free(ws);
}

