echo "Building 64 bit crypto libraries..."
cd ../src/
make 
make install
echo "Build SWIG wrappers..."
cd ../php/
make swig
make

