BUILD=build

createFolder:
	mkdir $(BUILD)

clean:
	rm -r $(BUILD) | exit 0

download: clean createFolder
	wget https://openresty.org/download/openresty-1.15.8.2.tar.gz -O  $(BUILD)/openresty.tar.gz
	tar xfvz $(BUILD)/openresty.tar.gz -C $(BUILD)

#./configure --add-module=/opt/ --with-cc-opt="-I/opt/" --with-ld-opt="-L/opt/"
# make
# make install
