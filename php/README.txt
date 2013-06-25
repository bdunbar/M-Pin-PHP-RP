To create the MPin lib PHP extensions follow these steps:

1. Install SWIG, php5 and php5-dev

2. Generate the SWIG wrappers

make swig

3. Generate the shared libs for a 64 bit Linux machine

make

4. Install php libs

make install (as root)

5. Run example. 

./runExample.bsh

