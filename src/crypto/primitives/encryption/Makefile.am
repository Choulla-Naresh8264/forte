SUBDIRS = internal

PUBLIC_SRCS = \
	cbc_encrypter.c \
	internal/cbc_dummy.c \
	internal/cbc_rsa.c \
	internal/cbc_bebgw.c

PUBLIC_HDRS = \
	cbc_encrypter.h \
	internal/cbc_dummy.h \
	internal/cbc_rsa.h \
	internal/cbc_bebgw.h

commonincludedir = $(includedir)/cbc/primitives/encryption/
nobase_commoninclude_HEADERS = ${PUBLIC_HDRS}

include_HEADERS = ${PUBLIC_HDRS}

BUILT_SOURCES = ${PUBLIC_SRCS} ${PUBLIC_HDRS}
CLEANFILES = ${BUILT_SOURCES}

.PHONY: FORCE

CC=gcc
FLAGS=-Wall -std=c99

all:
	$(CC) $(FLAGS) -c cbc_encrypter.c 
