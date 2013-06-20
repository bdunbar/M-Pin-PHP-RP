To create the MPin lib PHP extensions follow these steps:

First you must install SWIG (http://www.swig.org/) and php-config

1. Generate the SWIG wrappers

make swig

2. Generate the shared libs for a 64 bit Linux machine

make

3. Install php libs

make install (as root)

4. Run example. 

./runExample.bsh

