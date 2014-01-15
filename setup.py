#!/usr/bin/python
from distutils.core import setup, Extension
import re

liblists = "/home/george/Desktop/projects/DP5/code/Percy++-prefix/src/Percy++-build/libpercyserver.a;/home/george/Desktop/projects/DP5/code/Percy++-prefix/src/Percy++-build/libpercyclient.a;/usr/local/lib/libntl.a;/usr/local/lib/libgmp.so;/usr/lib/i386-linux-gnu/libssl.so;/usr/lib/i386-linux-gnu/libcrypto.so;/home/george/Desktop/projects/DP5/code/Relic-prefix/lib/librelic_s.a;/usr/local/lib/libgmp.so"
libs = liblists.split(';')

reallibs = ["dp5", "relicwrapper"]
libdirs = { '/home/george/Desktop/projects/DP5/code', '/home/george/Desktop/projects/DP5/code/relicwrapper' }
for lib in libs:
    m = re.match(r'(.*)/lib([^.]+)\.[^.+]', lib)
    if m:
        reallibs.append(m.group(2))
        libdirs.add(m.group(1))
    else:
        reallibs.append(lib)

module1 = Extension('dp5',
                    include_dirs = r"/home/george/Desktop/projects/DP5/code/Relic-prefix/include;/home/george/Desktop/projects/DP5/code/Percy++-prefix/src/Percy++;/usr/local/include/NTL;/usr/local/include;/usr/include;/home/george/Desktop/projects/DP5/code/relicwrapper".split(';'),
                    library_dirs = list(libdirs),
                    libraries = reallibs,
                    sources = ['/home/george/Desktop/projects/DP5/code/dp5py.cpp'],
		    extra_compile_args=['-O0'])

setup (name = 'DP5 Private Presence Library',
        version = '0.0.1',
        description = 'The python bindings for the dp5 service',
        ext_modules = [module1])

