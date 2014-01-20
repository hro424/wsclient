AM_CFLAGS = -Wall -Werror --std=gnu99

lib_LTLIBRARIES = libws.la
libws_la_SOURCES = wsclient.c

bin_PROGRAMS = wsclient
wsclient_SOURCES = main.c
wsclient_LDADD = libws.la -lssl -lcrypto
