CC=gcc
CFLAGS= -m64 -O2 -fPIC -I/usr/include/php -I/usr/include/php/main -I/usr/include/php/TSRM -I/usr/include/php/Zend -I/usr/include/php/ext -I/usr/include/php/ext/date/lib -I../src/
LINKFLAGS = -L../lib -lmiracl -lm

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
	cp sakke.so /usr/lib64/php/modules
	cp eccsi.so /usr/lib64/php/modules
	cp aesGcm.so /usr/lib64/php/modules
	chmod 755 /usr/lib64/php/modules/sakke.so
	chmod 755 /usr/lib64/php/modules/eccsi.so
	chmod 755 /usr/lib64/php/modules/aesGcm.so

test: 
	php TestToken.php

clean: 
	rm -rf *.exe
	rm -rf *.o
	rm -rf *~

cleanO: 
	rm -rf *.o
