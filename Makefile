
CFLAGS = -Wall -Og -Ideps/secp256k1/include
OBJS = sha256.o nostril.o aes.o base64.o
HEADERS = hex.h random.h config.h sha256.h deps/secp256k1/include/secp256k1.h
PREFIX ?= /usr/local
ARS = libsecp256k1.a

SUBMODULES = deps/secp256k1
-:
	git submodule update --init
	$(MAKE) all
all: nostril

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

nostril: $(HEADERS) $(OBJS) $(ARS)
	$(CC) $(CFLAGS) $(OBJS) $(ARS) -o $@

install: nostril
	mkdir -p $(PREFIX)/bin
	cp nostril $(PREFIX)/bin

config.h: configurator
	./configurator > $@

configurator: configurator.c
	$(CC) $< -o $@

clean:
	rm -f nostril *.o *.a
	rm -rf deps/secp256k1

tags: fake
	ctags *.c *.h

.PHONY: fake
