
OBJS = sha256.o nostril.o
HEADERS = hex.h random.h config.h sha256.h

all: nostril

nostril: config.h $(OBJS)
	$(CC) $(OBJS) -lsecp256k1 -o $@ 

config.h: configurator                                                          
	./configurator > $@                                                     

configurator: configurator.c                                                    
	$(CC) $< -o $@

clean:
	rm -f nostril *.o

tags: fake
	ctags *.c *.h

.PHONY: fake
