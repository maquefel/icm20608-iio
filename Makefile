CC=$(CROSS_COMPILE)gcc

CFLAGS+=-Wall -std=gnu99 -fPIC -D_GNU_SOURCE
LDFLAGS+=-liio

# VERSION
MAJOR=0
MINOR=0
PATCH=0
VERSION = -DVERSION_MAJOR=$(MAJOR) -DVERSION_MINOR=$(MINOR) -DVERSION_PATCH=$(PATCH)

.PHONY: all

all : icm20608d

.PHONY: debug

debug: CFLAGS += -O0 -DDEBUG -g -Wno-unused-variable
debug: all

icm20608d: icm20608d.o loop.o init.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

icm20608d.o: icm20608d.c
	$(CC) $(CFLAGS) -c $^ $(VERSION)

loop.o: loop.c
	$(CC) $(CFLAGS) -c $^

init.o: init.c
	$(CC) $(CFLAGS) -c $^
