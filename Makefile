# Buildroot-compatible Makefile for ip2uart

PKG_NAME := ip2uart
PKG_SRC  := ip2uart.c

PREFIX   ?= /usr
SBINDIR  ?= $(PREFIX)/sbin
CONFDIR  ?= /etc
INITDIR  ?= /etc/init.d

CROSS_COMPILE ?=
CC      := $(CROSS_COMPILE)gcc
STRIP   := $(CROSS_COMPILE)strip

CPPFLAGS ?=
CFLAGS   ?= -O2 -pipe
LDFLAGS  ?=

DESTDIR  ?=

BINARY := $(PKG_NAME)

.PHONY: all clean install

all: $(BINARY)

$(BINARY): $(PKG_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: $(BINARY)
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(CONFDIR) $(DESTDIR)$(INITDIR)
	install -m 0755 $(BINARY) $(DESTDIR)$(SBINDIR)/$(BINARY)
	install -m 0644 ip2uart.conf $(DESTDIR)$(CONFDIR)/ip2uart.conf
	install -m 0755 S96ip2uart $(DESTDIR)$(INITDIR)/S96ip2uart
	-$(STRIP) $(DESTDIR)$(SBINDIR)/$(BINARY)

clean:
	rm -f $(BINARY)
