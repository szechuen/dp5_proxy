from distutils.core import setup, Extension
 
module1 = Extension('dp5', 
                    include_dirs = [r"../percy", r"/usr/local/include/NTL", r"../relic/include", r"relicwrapper/"],
                    library_dirs = [r"./", r"/usr/local/lib", r"../percy", r"../relic/lib", r"relicwrapper/"],
                    libraries = ['dp5', 'percyclient', 'percyserver', 'ntl', 'crypto', 'gmp', "relicwrapper", "relic_s"],
                    sources = ['dp5py.cpp'],
		    extra_compile_args=['-O0'])
 
setup (name = 'DP5 Private Presence Library',
        version = '0.0.1',
        description = 'The python bindings for the pd5 service',
        ext_modules = [module1])

