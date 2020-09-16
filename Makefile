CC=$(CROSS_COMPILE)gcc

CFLAGS += -Wall -std=gnu99 -fPIC -D_GNU_SOURCE
LDFLAGS += -liio
INCLUDE += -Iinclude/

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

icm20608d: icm20608d.o libiio-loop.o local-loop.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

icm20608d.o: icm20608d.c
	$(CC) $(CFLAGS) -c $^ $(VERSION) $(INCLUDE)

libiio-loop.o: src/libiio-loop.c
	$(CC) $(CFLAGS) -c $^ $(INCLUDE)

local-loop.o: src/local-loop.c
	$(CC) $(CFLAGS) -c $^ $(INCLUDE)

clean::
	-rm icm20608d *.o
