git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git || true
pushd secp256k1 && \
	./autogen.sh && \
	./configure --prefix=/usr/local \
	--with-gnu-ld --enable-module-extrakeys \
	--enable-module-ecdh --enable-module-schnorrsig \
	--enable-examples && make && sudo -s make install && popd
./secp256k1/libtool --finish /usr/local/lib
