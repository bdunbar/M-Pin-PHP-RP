To create the MPin lib PHP extensions follow these steps:

1. Install SWIG and PHP5 (php5 and php5-dev on Ubuntu, oho and php-devel on CentOS)

2. Generate the SWIG wrappers

make swig

3. Generate the shared libs for a 64 bit Linux machine

make

4. Install php libs

make install (as root)

5. in php.ini, set

enable_dl = On

6. Run example. 

./runExample.bsh

