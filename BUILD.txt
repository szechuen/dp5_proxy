I. C++ Libraries and Tests

To build the DP5 C++ libraries and test programs just do:
(Explain the dependencies on ntl and percy++)

   $ make

II. Python bindings

To build the python bindings you need to:

1. Build the ntl and percy++ libraries with the -fPIC gcc flag:

   NTL: We need to compile NTL using Position-Independent-Code. Configure it as:
        ./configure PREFIX=/usr/local/lib "CFLAGS=-O2 -fPIC"
        When built make sure to copy the lib to /usr/local/lib by doing:
        sudo cp ntl.a /usr/local/lib/libntl.a
   
   Percy: Also recompile with PIC by adding -fPIC to the CXX flags
          CXXFLAGS= -fPIC -Wall -Wno-vla -Wno-long-long -g -O2 -pedantic -I/usr/local/include/NTL 

2. Install the "python-dev" ubuntu / mint packages

3. Build the Python extension

   $ make python

4. Install python and libraries including
    - python version > 2.7.4 (but version < 3.0) 
    - python module cherrypy version >= 3.2
    - python module requests
