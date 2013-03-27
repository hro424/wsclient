TESTS = check_ws
check_PROGRAMS = check_ws
check_ws_SOURCES = check_ws.c $(top_builddir)/src/websocket.h
check_ws_CFLAGS = @CHECK_CFLAGS@
check_ws_LDADD = $(top_builddir)/src/libws.a -lcrypto @CHECK_LIBS@
AUTOMAKE_OPTIONS = color-tests
