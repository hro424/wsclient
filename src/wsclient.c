#include <wsclient.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __MACH__
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif

#define HOSTLEN		64
#define PATHLEN		128
#define MSGLEN		200
#define KEYLEN		25
#define BUFLEN		4096

static const int HTTP_DEFAULT_PORT = 80;
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

/**
 * Parses a given URL.
 *
 * @param url		the URL.
 * @param host		the host part in the URL.
 * @param port		the port part in the URL. 0 if unspecified.
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
		return -1;
	}

	p = strstr(url, "://");
	if (p == NULL) {
		return -1;
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
		*port = 0;
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

static int
_connect(const char *host, uint16_t port)
{
	int fd;
	int err;
	struct addrinfo *info;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	err = getaddrinfo(host, NULL, &hints, &info);

	fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if (fd < 0) {
		return -1;
	}

	((struct sockaddr_in *)info->ai_addr)->sin_port = htons(port);
	err = connect(fd, info->ai_addr, info->ai_addrlen);

	freeaddrinfo(info);

	if (err < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/**
 * Establishes a WebSocket connection.  Schemes "http://" and "ws://" are
 * supported.
 *
 * @param url		the websocket url.
 * @return		file descriptor is return if success, otherwise -1.
 */
int
ws_connect(const char *url)
{
	int fd, r, upgrade, connection, accept;
	char buf[MSGLEN];
	char host[HOSTLEN];
	uint16_t port = 0;
	char path[PATHLEN];

	const char *p, *q;
	char key[32];
	unsigned char md[20];

	if (parse_url(url, NULL, 0, host, HOSTLEN, &port, path, PATHLEN)) {
		return -1;
	}

	if (port == 0) {
		port = HTTP_DEFAULT_PORT;
	}

	fd = _connect(host, port);
	if (fd < 0) {
		perror("connect");
		return -1;
	}

	sprintf(buf, "GET %s HTTP/1.1\r\n", path);
	r = write(fd, buf, strlen(buf));

	sprintf(buf, "Host: %s:%u\r\n", host, port);
	r = write(fd, buf, strlen(buf));

	sprintf(buf, "Upgrade: websocket\r\n");
	r = write(fd, buf, strlen(buf));

	sprintf(buf, "Connection: Upgrade\r\n");
	r = write(fd, buf, strlen(buf));

	generate_key(key);
	sprintf(buf, "Sec-WebSocket-Key: %s\r\n", key);
	r = write(fd, buf, strlen(buf));

	sprintf(buf, "Sec-WebSocket-Version: 13\r\n\r\n");
	r = write(fd, buf, strlen(buf));
	if (r != strlen(buf)) {
		close(fd);
		return -1;
	}

	strcpy(buf, key);
	strcat(buf, WS_KEY_TOKEN);
#ifdef __MACH__
	CC_SHA1(buf, strlen(buf), md);
#else
	SHA1((unsigned char *)buf, strlen(buf), md);
#endif
	base64_encode(md, 20, key, 32);

	r = read(fd, buf, MSGLEN);
	if (r < 0) {
		close(fd);
		return -1;
	}

	if (strncmp(buf, RESPONSE_LINE_WS, strlen(RESPONSE_LINE_WS)) != 0) {
		close(fd);
		return -1;
	}

	upgrade = connection = accept = 0;
	p = buf + strlen(RESPONSE_LINE_WS);
	while (1) {
		q = strstr(p, "\r\n");
		if (p == q) {
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
		while (read(fd, buf, MSGLEN) != 0) ;
	}

	if (!(upgrade && connection && accept)) {
		close(fd);
		return -1;
	}

	return fd;
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
int
ws_send(int fd, const void *buf, size_t len)
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
	r = write(fd, b, i);

	while (len > BUFLEN) {
		memcpy(b, buf, BUFLEN);
		for (p = (uint32_t *)b; p < (uint32_t *)(b + BUFLEN); p++) {
			*p ^= mask;
		}
		r += write(fd, b, BUFLEN);
		len -= BUFLEN;
	}

	memcpy(b, buf, len);
	for (p = (uint32_t *)b; p < (uint32_t *)(b + len); p++) {
		*p ^= mask;
	}
	r += write(fd, b, len);

	return r;
}

/**
 * Receives data through WebSocket.
 *
 * @param fd		the file descriptor
 * @param buf		the reception window
 * @param len		the length of the buffer in bytes
 */
int
ws_recv(int fd, void *buf, size_t len)
{
	uint8_t b[4];
	int l, r;

	// Read header
	r = read(fd, b, 2);
	if (r < 0) {
		return -1;
	}

	l = b[1] & 0x7F;
	if (l == 126) {
		r = read(fd, b + 2, 2);
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

	r = read(fd, buf, l);

	return r;
}

/**
 * Closes WebSocket.
 *
 * @param fd	the file descriptor
 */
void
ws_close(int fd)
{
	uint8_t b[2] = {0, 0};
	int r;

	set_fin(b);
	set_opcode(b, WS_OPCODE_CLOSE); 
	r = write(fd, b, 2);
	if (r < 0) {
		close(fd);
	}
	else {
		close(fd);
	}
}

