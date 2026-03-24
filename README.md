# mod_log_http

`mod_log_http` is a FreeSWITCH logging module over HTTP. 
Sends FreeSWITCH logs as JSON via HTTP(S) POST.

Designed for FluentBit/FluentD HTTP input, but works with any HTTP endpoint that accepts JSON POST requests.

## Build
```sh
make
```

If `pkg-config` is not available for FreeSWITCH, pass the include path explicitly:

```sh
make FS_CFLAGS="-I/usr/include/freeswitch"
```

For a custom FreeSWITCH prefix, override the install paths explicitly:

```sh
make \
  FS_CFLAGS="-I/usr/local/freeswitch/include/freeswitch" \
  FS_MODULES_DIR=/usr/local/freeswitch/mod \
  FS_CONF_DIR=/usr/local/freeswitch/conf/autoload_configs
```

## Install

Install the module and its autoload config:

```sh
make install
```

Package builds can stage the files with `DESTDIR`:

```sh
make install DESTDIR=/tmp/pkgroot
```

Use `make show-config` to inspect the resolved build variables.
