#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include "../src/wsclient.h"

#define KNOWN_HOST_WS	"ws://localhost:8080"
#define KNOWN_HOST_HTTP	"http://localhost:8080"
#define HOST_WS		"ws://example.com"
#define HOST_HTTP	"http://example.com"

START_TEST(test_parse_url_ws)
{
	char scheme[16];
	char host[32];
	uint16_t port;
	char path[200];
	int err;

	err = parse_url(HOST_WS, scheme, 16, host, 32, &port, path, 200);

	fail_if(err < 0, NULL);
	fail_if(strncmp("ws://", scheme, 5) != 0, NULL);
	fail_if(strncmp("example.com", host, strlen("example.com")) != 0, NULL);
	fail_if(port != 80, NULL);
}
END_TEST

START_TEST(test_parse_url_http)
{
	char scheme[16];
	char host[32];
	int port;
	char path[200];
	int err;

	err = parse_url(HOST_HTTP, scheme, 16, host, 32, &port, path, 200);
	fail_if(err < 0, NULL);

	fail_if(strncmp("http://", scheme, 7) != 0, NULL);
	fail_if(strncmp("example.com", host, strlen("example.com")) != 0, NULL);
	fail_if(port != 80, NULL);
}
END_TEST

START_TEST(test_base64_encode)
{
	unsigned char in[16];
	char out[32];
	size_t r;
	int i;

	for (i = 0; i < 16; i++) {
		in[i] = i + 1;
	}

	r = base64_encode(in, 16, out, 32);
	fail_if(r == 0, NULL);
	fail_if(strcmp(out, "AQIDBAUGBwgJCgsMDQ4PEA==") != 0, NULL);
}
END_TEST

START_TEST(test_connect)
{
	int fd;
	fail_if((fd = _connect("localhost", 8080)) < 0, NULL);
	close(fd);
}
END_TEST

START_TEST(test_connect_known_ws)
{
	int fd;
	fd = ws_connect(KNOWN_HOST_WS);
	fail_unless(fd > 0, "connection failed");
	ws_close(fd);
}
END_TEST

START_TEST(test_connect_known_http)
{
	int fd;
	fd = ws_connect(KNOWN_HOST_HTTP);
	fail_unless(fd > 0, "connection failed");
	ws_close(fd);
}
END_TEST

START_TEST(test_connect_unknown_ws)
{
	int fd;
	fd = ws_connect("ws://unknown.com");
	fail_unless(fd < 0, "connection established");
}
END_TEST

START_TEST(test_connect_unknown_http)
{
	int fd;
	fd = ws_connect("http://unknown.com");
	fail_unless(fd < 0, "connection established");
}
END_TEST

static char buf[BUFSIZ];

START_TEST(test_recv)
{
	int fd;
	int r;
	const char *msg = "Hello";

	fd = ws_connect(KNOWN_HOST_WS);
	fail_unless(fd > 0, "connection failed");

	r = ws_send(fd, msg, strlen(msg));
	fail_if(r < 0, "failed to send");

	r = ws_recv(fd, buf, BUFSIZ);
	fail_if(r < 0, "failed to recv");

	ws_close(fd);

	buf[r] = '\0';
	printf("received: %s\n", buf);
}
END_TEST

Suite *
ws_suite(void)
{
	Suite *s = suite_create("WebSocket");

	TCase *tc_core = tcase_create("Core");
	//tcase_add_test(tc_core, test_parse_url_ws);
	//tcase_add_test(tc_core, test_parse_url_http);
	//tcase_add_test(tc_core, test_base64_encode);
	//tcase_add_test(tc_core, test_connect);
	tcase_add_test(tc_core, test_connect_known_ws);
	tcase_add_test(tc_core, test_connect_known_http);
	tcase_add_test(tc_core, test_recv);
	suite_add_tcase(s, tc_core);

	return s;
}

int
main(int argc, char *argv[])
{
	int number_failed;
	Suite *s = ws_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
