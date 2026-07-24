CC       = gcc

# Version: default to the git tag/describe; falls back to the value compiled
# into src/config-core.h if git is unavailable. Release builds pass an explicit
# VERSION= (see .github/workflows/release.yml).
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null)

# Arch tuning. Defaults to -march=native for a locally optimal dev build.
# Release builds override with ARCH_FLAGS= (empty) for a portable binary that
# runs on any CPU of the target architecture.
ARCH_FLAGS ?= -march=native

# Extra linker flags. Release builds pass EXTRA_LDFLAGS=-static to produce a
# fully self-contained binary with no shared-library dependencies.
EXTRA_LDFLAGS ?=

CFLAGS   = -O2 -Wall -Wextra -pthread $(ARCH_FLAGS)
ifneq ($(VERSION),)
CFLAGS  += -DARKIMEBLAST_VERSION='"$(VERSION)"'
endif
LDFLAGS  = -lpthread $(EXTRA_LDFLAGS)
SRCDIR   = src
SOURCES  = $(wildcard $(SRCDIR)/*.c)
OBJECTS  = $(SOURCES:.c=.o)
TARGET   = arkimeblast

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(SRCDIR)/*.o $(TARGET)
