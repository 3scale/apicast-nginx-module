BUILD=build
OPENRESTY_VERSION=1.21.4.3

PREFIX ?=          /usr/local
LUA_INCLUDE_DIR ?= $(PREFIX)/include
LUA_LIB_DIR ?=     $(PREFIX)/openresty/lualib
INSTALL ?= install

SHELL := /bin/bash

DOCKER ?= $(shell which docker 2> /dev/null || echo "docker")

createFolder:
	mkdir $(BUILD)

clean:
	rm -r $(BUILD) | exit 0

download: clean createFolder
	wget https://openresty.org/download/openresty-$(OPENRESTY_VERSION).tar.gz -O  $(BUILD)/openresty.tar.gz
	tar xfvz $(BUILD)/openresty.tar.gz -C $(BUILD)

patch:
	patch -p0 < patches/nginx_upstream-$(OPENRESTY_VERSION).diff

compile:
	cd build/openresty-$(OPENRESTY_VERSION) \
	&& ./configure \
	  	--with-cc='ccache gcc -fdiagnostics-color=always' \
		--with-cc-opt="-I/opt/" --with-ld-opt="-L/opt/" --add-module="/opt/" \
		--with-debug \
		--with-pcre-jit \
		--without-http_rds_json_module \
		--without-http_rds_csv_module \
		--without-lua_rds_parser \
		--with-stream \
		--with-stream_ssl_module \
		--with-stream_ssl_preread_module \
		--with-http_v2_module \
		--without-mail_pop3_module \
		--without-mail_imap_module \
		--without-mail_smtp_module \
		--with-http_stub_status_module \
		--with-http_realip_module \
		--with-http_addition_module \
		--with-http_gzip_static_module \
		--with-threads \
		--with-poll_module \
		--with-compat \
		--with-luajit-xcflags='-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT -DLUAJIT_USE_VALGRIND -DLUAJIT_USE_SYSMALLOC -O0' \
		--with-no-pool-patch \
	&& make \
	&& make install

openssl:
	 cd /tmp && \
	 git clone https://github.com/fffonion/lua-resty-openssl.git --depth 1 && \
	 cp -r lua-resty-openssl/lib/resty/openssl $(LUA_LIB_DIR)/resty/

install:
	$(INSTALL) -d $(DESTDIR)$(LUA_LIB_DIR)/resty/
	$(INSTALL) lib/resty/*.lua $(DESTDIR)$(LUA_LIB_DIR)/resty/

development:
	- $(DOCKER) build -t 3scale/apicast-nginx-module .
	$(DOCKER) run --rm -v .:/opt -it 3scale/apicast-nginx-module bash

