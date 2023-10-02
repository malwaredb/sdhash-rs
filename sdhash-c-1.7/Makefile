# Makefile for sdhash.  Change options at top if necessary

DESTDIR=
PREFIX=$(DESTDIR)/usr/local
INSTDIR=$(PREFIX)/bin
MANDIR=$(PREFIX)/share/man/man1

SDHASH_SRC = sdhash_opts.c sdbf_api.c sdbf_core.c map_file.c entr64.c base64.c bf_utils.c error.c 

CC = gcc
LD = gcc

UNAME_S := $(shell uname -s)

# BAD, BAD OPTIMIZATION! -fstrict-aliasing 
ifneq ($(MAKECMDGOALS),debug)
CFLAGS = -std=c99 -O3 -fno-strict-aliasing -D_FILE_OFFSET_BITS=64 -D_LARGE_FILE_API -D_BSD_SOURCE -I`brew --prefix openssl`/include/
else
CFLAGS = -std=c99 -O0 -g -pg -D_FILE_OFFSET_BITS=64 -D_LARGE_FILE_API -D_BSD_SOURCE -I`brew --prefix openssl`/include/
endif

LDFLAGS = -lc -lm -lpthread
ifeq ($(UNAME_S),Darwin)
	LDFLAGS += `brew --prefix openssl`/lib/libcrypto.a
endif

SDHASH_OBJ = $(SDHASH_SRC:.c=.o)
SDHASH_CLIENT_OBJ = sdhash.o
SDHASH_BLOCK_OBJ = sdhash-block.o
SDHASH_MEM_OBJ= sdhash-mem.o

EXTRA = 

all: stream block mem

debug: stream block mem

install: stream block mem
	mkdir -p $(INSTDIR)
	mkdir -p $(MANDIR)
	cp sdhash sdhash-dd sdhash-mem $(INSTDIR)
	cp man/sdhash.1 $(MANDIR)

stream: $(SDHASH_OBJ) $(SDHASH_CLIENT_OBJ)
	$(LD) $(SDHASH_OBJ) $(SDHASH_CLIENT_OBJ) -o sdhash $(LDFLAGS)

block: $(SDHASH_OBJ) $(SDHASH_BLOCK_OBJ)
	$(LD) $(SDHASH_OBJ) $(SDHASH_BLOCK_OBJ) -o sdhash-dd $(LDFLAGS)

mem: $(SDHASH_OBJ) $(SDHASH_MEM_OBJ)
	$(LD) $(SDHASH_OBJ) $(SDHASH_MEM_OBJ) -o sdhash-mem $(LDFLAGS)

$(SDHASH_BLOCK_OBJ): EXTRA := -D_DD_BLOCK=16
$(SDHASH_MEM_OBJ): EXTRA := -D_DD_BLOCK=4

sdhash-block.o:
	$(CC) $(CFLAGS) $(EXTRA) $(INCLUDES) -c sdhash.c -o sdhash-block.o
sdhash-mem.o:
	$(CC) $(CFLAGS) $(EXTRA) $(INCLUDES) -c sdhash.c -o sdhash-mem.o
# Longest common substring
lcs: lcs.c map_file.c error.c
	gcc -std=c99 -O3 -o lcs lcs.c map_file.c error.c

pcap: sdhash-pcap.c
	gcc -I/usr/include/pcap -o sdhash-pcap sdhash-pcap.c -lpcap

clean:
	-@rm *.o sdhash sdhash-* 2> /dev/null || true
.c.o:
	$(CC) $(CFLAGS) $(EXTRA) $(INCLUDES) -c $*.c -o $*.o
