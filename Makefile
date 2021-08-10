BUILD=build
OPENRESTY_VERSION=1.19.3.1

createFolder:
	mkdir $(BUILD)

clean:
	rm -r $(BUILD) | exit 0

download: clean createFolder
	wget https://openresty.org/download/openresty-$(OPENRESTY_VERSION).tar.gz -O  $(BUILD)/openresty.tar.gz
	tar xfvz $(BUILD)/openresty.tar.gz -C $(BUILD)

patch:
	patch -p0 < patches/nginx_upstream.diff

compile:
	cd build/openresty-$(OPENRESTY_VERSION) && \
	./configure --with-cc-opt="-I/opt/" --with-ld-opt="-L/opt/" --add-module="/opt/" && \
	make && \
	make install

openssl:
	 cd /tmp && \
	 git clone https://github.com/fffonion/lua-resty-openssl.git --depth 1 && \
	 cp lua-resty-openssl/lib/resty/openssl /usr/local/openresty/lualib/resty -R /
