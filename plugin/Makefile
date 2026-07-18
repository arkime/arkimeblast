# Builds the Arkime reader plugin from the arkimeblast generator sources.
# This is intentionally separate from the top-level arkimeblast Makefile and is
# only run on demand (it needs an Arkime source checkout for arkime.h).
#
#   make ARKIME=../../arkime          # path to your arkime checkout
#
# Arkime's own symbols (arkime_*) are left undefined and resolve at load time
# from the capture binary, so nothing from capture/ is linked here.

ARKIME ?= ../../arkime
CC     ?= cc

GEN_SRC = ../src/net_utils.c ../src/session.c \
          ../src/gen_tcp.c ../src/gen_http.c ../src/gen_tls.c ../src/gen_dns.c
SRC     = reader-synthetic.c $(GEN_SRC)
TARGET  = reader-synthetic.so

INCLUDES = -I../src -I$(ARKIME)/capture -I$(ARKIME)/capture/thirdparty \
           $(shell pkg-config --cflags glib-2.0 gmodule-2.0 2>/dev/null)

CFLAGS  = -O2 -ggdb -Wall -fPIC -D_GNU_SOURCE $(INCLUDES)

# Platform-specific shared-object flags. macOS needs dynamic_lookup so the
# undefined arkime_* symbols are resolved when the capture process dlopens us.
UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
SHARED = -shared -undefined dynamic_lookup
else
SHARED = -shared
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SHARED) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f $(TARGET)
