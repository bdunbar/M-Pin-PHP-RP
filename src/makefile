CC=gcc
CFLAGS=-m64 -O2 -fPIC -I./ 
#CFLAGS=-m64 -O0 -g -fPIC -I./ 
#CFLAGS=-m64 -O0 -fPIC -D DEBUG=DEBUG -I./
#CFLAGS=-m64 -O0 -fPIC -D TEST=TEST -I./ 
LINKFLAGS = -L../lib -lmiracl -lm
OBJ = certivox.o octet.o 

all: libSAKKE.so libECCSI.so libMPIN.so libAESGCM.so

libSAKKE.so: $(OBJ) sakke_bn_c.o sakkeWrapper.o 
	$(CC) -shared -fPIC $^ $(LINKFLAGS) -o $@  

libECCSI.so: $(OBJ) eccsi_c.o eccsiWrapper.o  
	$(CC) -shared -fPIC $^ $(LINKFLAGS) -o $@  

libMPIN.so: $(OBJ) mpin_c.o mpinWrapper.o
	$(CC) -shared -fPIC $^ $(LINKFLAGS) -o $@  

libAESGCM.so: $(OBJ) aesGcmWrapper.o 
	$(CC) -shared -fPIC $^ $(LINKFLAGS) -o $@  

certivox.o: certivox.c  certivox.h
	$(CC) -c $(CFLAGS) $< -o $@

octet.o: octet.c  octet.h
	$(CC) -c $(CFLAGS) $< -o $@

sakke_bn_c.o: sakke_bn_c.c sakke_bn_c.h
	$(CC) -c $(CFLAGS) $< -o $@

sakkeWrapper.o: sakkeWrapper.c sakkeWrapper.h
	$(CC) -c $(CFLAGS) $< -o $@

mpin_c.o: mpin_c.c mpin_c.h
	$(CC) -c $(CFLAGS) $< -o $@

mpinWrapper.o: mpinWrapper.c mpinWrapper.h
	$(CC) -c $(CFLAGS) $< -o $@

eccsi_c.o: eccsi_c.c eccsi_c.h
	$(CC) -c $(CFLAGS) $< -o $@

eccsiWrapper.o: eccsiWrapper.c eccsiWrapper.h
	$(CC) -c $(CFLAGS) $< -o $@

aesGcmWrapper.o: aesGcmWrapper.c aesGcmWrapper.h
	$(CC) -c $(CFLAGS) $< -o $@

install: 
	mv libECCSI.so ../lib
	mv libSAKKE.so ../lib
	mv libAESGCM.so ../lib
	mv libMPIN.so ../lib

clean: 
	rm -rf *.exe
	rm -rf *.o
	rm -rf *~

cleanO: 
	rm -rf *.o
