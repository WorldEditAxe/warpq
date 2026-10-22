CC ?= gcc
CFLAGS ?= -Os -std=c99 -D_GNU_SOURCE -Wall -Wextra -ffunction-sections -fdata-sections
LDFLAGS ?= -Wl,--gc-sections -Wl,-s
LIBS ?= -lmbedtls -lmbedx509 -lmbedcrypto

SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)

warpq: $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) $(LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) warpq

.PHONY: clean
