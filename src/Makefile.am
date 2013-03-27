lib_LIBRARIES = libws.a
libws_a_SOURCES = wsclient.c
libws_a_CFLAGS = -Wall -Werror

bin_PROGRAMS = wsclient
wsclient_SOURCES = main.c
wsclient_CFLAGS = -Wall -Werror
wsclient_LDADD = libws.a -lcrypto
