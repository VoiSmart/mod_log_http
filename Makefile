MODULE := mod_log_http
SOURCES := mod_log_http.c
OBJECTS := $(SOURCES:.c=.o)
CONFIG_SRC := conf/autoload_configs/log_http.conf.xml
CONFIG_NAME := $(notdir $(CONFIG_SRC))

PKG_CONFIG ?= pkg-config
CC ?= cc
INSTALL ?= install
RM ?= rm -f

DEFAULT_FS_INCLUDE_DIR ?= /usr/include/freeswitch
DEFAULT_FS_MODULES_DIR ?= /usr/lib/freeswitch/mod
DEFAULT_FS_CONF_DIR ?= /etc/freeswitch/autoload_configs

FS_PKGCONFIG_AVAILABLE := $(shell $(PKG_CONFIG) --exists freeswitch >/dev/null 2>&1 && echo yes || echo no)

ifeq ($(FS_PKGCONFIG_AVAILABLE),yes)
FS_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags freeswitch)
FS_MODULES_DIR ?= $(or $(shell $(PKG_CONFIG) --variable=modulesdir freeswitch 2>/dev/null),$(DEFAULT_FS_MODULES_DIR))
FS_CONF_DIR ?= $(DEFAULT_FS_CONF_DIR)
else
FS_INCLUDE_DIR ?= $(DEFAULT_FS_INCLUDE_DIR)
FS_CFLAGS ?= -I$(FS_INCLUDE_DIR)
FS_MODULES_DIR ?= $(DEFAULT_FS_MODULES_DIR)
FS_CONF_DIR ?= $(DEFAULT_FS_CONF_DIR)
endif

CPPFLAGS += $(FS_CFLAGS)
CFLAGS ?= -O2 -g
CFLAGS += -fPIC -Wall -Wextra -std=gnu99
LDFLAGS += -shared

.DEFAULT_GOAL := all

.PHONY: all clean install uninstall help show-config

all: $(MODULE).so

$(MODULE).so: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

install: $(MODULE).so
	$(INSTALL) -d $(DESTDIR)$(FS_MODULES_DIR)
	$(INSTALL) -m 0755 $(MODULE).so $(DESTDIR)$(FS_MODULES_DIR)/$(MODULE).so
	$(INSTALL) -d $(DESTDIR)$(FS_CONF_DIR)
	$(INSTALL) -m 0644 $(CONFIG_SRC) $(DESTDIR)$(FS_CONF_DIR)/$(CONFIG_NAME)

uninstall:
	$(RM) $(DESTDIR)$(FS_MODULES_DIR)/$(MODULE).so
	$(RM) $(DESTDIR)$(FS_CONF_DIR)/$(CONFIG_NAME)

clean:
	$(RM) $(OBJECTS) $(MODULE).so

help:
	@printf '%s\n' \
		'Targets:' \
		'  make                Build mod_log_http.so' \
		'  make install        Install the module and XML config' \
		'  make uninstall      Remove the installed module and XML config' \
		'  make clean          Remove build artefacts' \
		'' \
		'Variables:' \
		'  FS_CFLAGS="-I/path/to/freeswitch/include"' \
		'  FS_MODULES_DIR=/path/to/freeswitch/mod' \
		'  FS_CONF_DIR=/path/to/freeswitch/conf/autoload_configs' \
		'  DESTDIR=/package/root'

show-config:
	@printf '%s\n' \
		'PKG_CONFIG: $(PKG_CONFIG)' \
		'FS_PKGCONFIG_AVAILABLE: $(FS_PKGCONFIG_AVAILABLE)' \
		'FS_CFLAGS: $(FS_CFLAGS)' \
		'FS_MODULES_DIR: $(FS_MODULES_DIR)' \
		'FS_CONF_DIR: $(FS_CONF_DIR)'
