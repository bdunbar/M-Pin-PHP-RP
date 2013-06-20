CC=gcc
CFLAGS= -m64 -O2 -fPIC `php-config --includes` -I../src/
LINKFLAGS = -L../lib -lmiracl -lm
INSTALLDIR = `php-config --extension-dir`

all: sakke.so eccsi.so aesGcm.so 

sakke.so: $(OBJ) sakke_wrap.o
	$(CC) -shared -fPIC $^ $(LINKFLAGS) -lSAKKE -o $@  

eccsi.so: $(OBJ) eccsi_wrap.o
	$(CC) -shared -fPIC $^ $(LINKFLAGS) -lECCSI -o $@  

aesGcm.so: $(OBJ) aesGcm_wrap.o
	$(CC) -shared -fPIC $^ $(LINKFLAGS) -lAESGCM -o $@  

sakke_wrap.o: sakke_wrap.c
	$(CC) -c $(CFLAGS) $< -o $@

eccsi_wrap.o: eccsi_wrap.c
	$(CC) -c $(CFLAGS) $< -o $@

aesGcm_wrap.o: aesGcm_wrap.c
	$(CC) -c $(CFLAGS) $< -o $@

swig: 
	swig -php aesGcm.i
	swig -php sakke.i
	swig -php eccsi.i

install: 
	cp sakke.so $(INSTALLDIR)
	cp eccsi.so $(INSTALLDIR)
	cp aesGcm.so $(INSTALLDIR)
	chmod 755  $(INSTALLDIR)/sakke.so
	chmod 755  $(INSTALLDIR)/eccsi.so
	chmod 755 $(INSTALLDIR)/aesGcm.so

test: 
	php TestToken.php

clean: 
	rm -rf *.exe
	rm -rf *.o
	rm -rf *~

cleanO: 
	rm -rf *.o
