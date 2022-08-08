-: secp256k1 nostril

PREFIX := /usr/local

LD_LIBRARY_PATH=/usr/local/lib
export LD_LIBRARY_PATH

CFLAGS = -Wall -Og -Ideps/secp256k1/include
OBJS = sha256.o nostril.o aes.o base64.o
HEADERS = hex.h random.h config.h sha256.h deps/secp256k1/include/secp256k1.h
PREFIX ?= /usr/local
ARS = libsecp256k1.a

SUBMODULES = deps/secp256k1

all: nostril secp256k1 websocat

deps/secp256k1/.git:
	@devtools/refresh-submodules.sh $(SUBMODULES)

deps/secp256k1/include/secp256k1.h: deps/secp256k1/.git

deps/secp256k1/configure: deps/secp256k1/.git
	cd deps/secp256k1; \
	./autogen.sh

deps/secp256k1/config.log: deps/secp256k1/configure
	cd deps/secp256k1; \
	./configure --disable-shared --enable-module-ecdh --enable-module-schnorrsig --enable-module-extrakeys

deps/secp256k1/.libs/libsecp256k1.a: deps/secp256k1/config.log
	cd deps/secp256k1; \
	make -j libsecp256k1.la

libsecp256k1.a: deps/secp256k1/.libs/libsecp256k1.a
	cp $< $@

%.o: %.c $(HEADERS)
	@echo "cc $<"
	@$(CC) $(CFLAGS) -c $< -o $@

nostril: $(HEADERS) $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -lsecp256k1 -o $@

.PHONY: secp256k1
secp256k1:
	git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git || true
	cd secp256k1/ && ./autogen.sh && ./configure --prefix=/usr/local --with-gnu-ld --enable-module-extrakeys --enable-module-ecdh --enable-module-schnorrsig --enable-examples && make && make install
	cd secp256k1 ./libtool  --finish $(PREFIX)/lib

websocat:
	git clone https://github.com/vi/websocat.git websc || true
	mkdir -p /usr/local/bin
	cd websc && cargo install --path=. && install -v target/release/websocat /usr/local/bin

install: nostril
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/lib
	make install -C secp256k1 && install secp256k1/schnorr_example $(PREFIX)/bin/schnorr-key
	cp nostril $(PREFIX)/bin
	cp scripts/* $(PREFIX)/bin


config.h: configurator
	./configurator > $@

configurator: configurator.c
	$(CC) $< -o $@

clean:
	rm -f nostril *.o *.a
	rm -rf deps/secp256k1

tags: fake
	ctags *.c *.h
test:
	nostril --pow 16 --envelope --sec 1a03a2b6ce40340f012043e6d9e717950076b757a708cb6e9ac3d2e3bbe5fb1a --tag nostril test --content test | websocat wss://relay.damus.io

.PHONY: fake
