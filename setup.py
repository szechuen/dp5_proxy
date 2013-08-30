from distutils.core import setup, Extension
 
module1 = Extension('dp5', 
                    include_dirs = [r"../percy", r"/usr/local/include/NTL"],
                    library_dirs = [r"./", r"/usr/local/lib", r"../percy"],
                    libraries = ['dp5', 'percyclient', 'percyserver', 'ntl', 'crypto'],
                    sources = ['dp5py.cpp'],
		    extra_compile_args=['-O0'])
 
setup (name = 'DP5 Private Presence Library',
        version = '0.0.1',
        description = 'The python bindings for the pd5 service',
        ext_modules = [module1])

