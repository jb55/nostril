ifneq ($(wildcard /usr/local/bin),)
       PREFIX := /usr/local/bin
else
       PREFIX := /usr/bin
endif
CFLAGS = -Wall -Og
OBJS = sha256.o nostril.o aes.o base64.o
HEADERS = hex.h random.h config.h sha256.h

all: nostril

%.o: %.c config.h
	@echo "cc $<"
	@$(CC) $(CFLAGS) -c $< -o $@

nostril: $(HEADERS) $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -lsecp256k1 -o $@ 

install: nostril
	mkdir -p $(PREFIX)/bin
	cp nostril $(PREFIX)
	cp scripts/* $(PREFIX)/

config.h: configurator                                                          
	./configurator > $@                                                     

configurator: configurator.c                                                    
	$(CC) $< -o $@

clean:
	rm -f nostril *.o

tags: fake
	ctags *.c *.h

.PHONY: fake
