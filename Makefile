
CFLAGS = -Wall -O2 -Ideps/secp256k1/include
OBJS = sha256.o nostril.o aes.o base64.o
HEADERS = hex.h random.h config.h sha256.h deps/secp256k1/include/secp256k1.h
PREFIX ?= /usr/local
ARS = libsecp256k1.a

SUBMODULES = deps/secp256k1

all: nostril docs

docs: doc/nostril.1

doc/nostril.1: README.md
	scdoc < $^ > $@

version: nostril.c
	grep '^#define VERSION' $< | sed -En 's,.*"([^"]+)".*,\1,p' > $@

dist: docs version
	@mkdir -p dist
	git ls-files --recurse-submodules | tar --transform 's/^/nostril-$(shell cat version)\//' -T- -caf dist/nostril-$(shell cat version).tar.gz
	@ls -dt dist/* | head -n1 | xargs echo "tgz "
	cd dist;\
	sha256sum *.tar.gz > SHA256SUMS.txt;\
	gpg -u 0x8A478B64FFE30F1095A8736BF5F27EFD1B38DABB --sign --armor --detach-sig --output SHA256SUMS.txt.asc SHA256SUMS.txt
	cp CHANGELOG dist/CHANGELOG.txt
	rsync -avzP dist/ charon:/www/cdn.jb55.com/tarballs/nostril/

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

install: all
	mkdir -p $(PREFIX)/bin
	install -m644 doc/nostril.1 $(PREFIX)/share/man/man1/nostril.1
	install -m755 nostril $(PREFIX)/bin/nostril
	install -m755 nostril-query $(PREFIX)/bin/nostril-query

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
