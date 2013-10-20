from cffi import FFI
ffi = FFI()
ffi.cdef("""

    void * Init_init();
    void Init_cleanup(void * p);

    typedef _Bool bool;

    typedef struct _DHKey DHKey;

    DHKey * DHKey_alloc();
    void DHKey_free(DHKey * vkeys);
    void DHKey_keygen(DHKey * vkeys);
    size_t DHKey_size();
    size_t DHKey_pubsize();

    typedef struct _BLSKey BLSKey;

    BLSKey * BLSKey_alloc();
    void BLSKey_free(BLSKey * keys);
    void BLSKey_keygen(BLSKey * keys);
    size_t BLSKey_size();
    size_t BLSKey_pubsize();


    typedef struct _DP5Config DP5Config;

    DP5Config * Config_alloc(
        unsigned int epoch_len,
        unsigned int dataenc_bytes,
        bool combined);
    unsigned int Config_dataplain_bytes(DP5Config * config);
    unsigned int Config_current_epoch(DP5Config * config);
    void Config_delete(DP5Config * config);

    typedef struct _DP5RegClient DP5RegClient;

    DP5RegClient * RegClient_alloc(
        DP5Config * config, 
        DHKey * keys); 

    int RegClient_start(
        DP5RegClient * reg, 
        DP5Config * config,
        unsigned int epoch,
        unsigned int friends_num,
        char * data,
        void processbuf(size_t, void*));

    int RegClient_complete(
        DP5RegClient * reg,
        unsigned int epoch,
        size_t len,
        char * buffer);

    void RegClient_delete(DP5RegClient * p);

    typedef struct _regserver DP5RegServer;

    DP5RegServer * RegServer_alloc(
        DP5Config * config,
        unsigned int epoch,
        char* regdir,
        char* datadir);

    void RegServer_delete(DP5RegServer * p);

    void RegServer_register(
        DP5RegServer * reg,
        size_t len,
        void * data,
        void processbuf(size_t, const void*));

    unsigned int RegServer_epoch_change(
        DP5RegServer * reg,
        char * metadata,
        char * data);

    """)

C = ffi.dlopen("./libdp5clib.so")  

__initLib = False
__libState = None

def InitLib():
    global __initLib, __libState
    if not __initLib:
        __libState = C.Init_init()
        __initLib = True

def FreeLib():
    global __initLib, __libState
    if __initLib:
        __initLib = False
        C.Init_cleanup(__libState)

class DP5Config:
    def __init__(self, epoch_length, data_size, combined=False):
        self.epoch_length = epoch_length
        self.data_size = data_size
        self.combined = combined

        # Check inputs
        assert 0 < epoch_length 
        assert 16 < data_size

        self._config = C.Config_alloc(epoch_length, data_size, combined)

    def get_ptr(self):
        return self._config

    def current_epoch(self):
        epoch = C.Config_current_epoch(self._config)
        return int(epoch)

    def dataplain_bytes(self):
        dlen = C.Config_dataplain_bytes(self._config)
        return int(dlen)

    def __del__(self):
        C.Config_delete(self._config)

class CryptoKeys:
    def __init__(self):
        self.fun_init = None
        self.fun_gen = None
        self.fun_size = None
        self.fun_psize = None
        self.fun_free = None

        self.ptr = None

    def _init(self):
        assert self.ptr == None
        self.ptr = self.fun_init()

    def gen(self):
        self.fun_gen(self.ptr)

    def size(self):
        return int(self.fun_size())

    def pub_size(self):
        return int(self.fun_psize())

    def pub(self):
        b = ffi.buffer(self.ptr, self.size())[:self.pub_size()]
        return buffer(b)

    def __del__(self):
        self.fun_free(self.ptr)

class DHKeys(CryptoKeys):
    def __init__(self):
        self.fun_init = C.DHKey_alloc
        self.fun_gen = C.DHKey_keygen
        self.fun_size = C.DHKey_size
        self.fun_psize = C.DHKey_pubsize
        self.fun_free = C.DHKey_free

        self.ptr = None
        self._init()

class BLSKeys(CryptoKeys):
    def __init__(self):
        self.fun_init = C.BLSKey_alloc
        self.fun_gen = C.BLSKey_keygen
        self.fun_size = C.BLSKey_size
        self.fun_psize = C.BLSKey_pubsize
        self.fun_free = C.BLSKey_free

        self.ptr = None
        self._init()

## ------- Tests -----------------------

import unittest

class DP5TestCase(unittest.TestCase):
    def setUp(self):
        InitLib()

    def tearDown(self):
        pass

    def test_raw_DHKey(self):
        # Using raw C functions
        x = C.DHKey_alloc();
        C.DHKey_keygen(x)
        xbuf = ffi.buffer(x, C.DHKey_size())
        self.assertEqual( len(xbuf), 2 * 32)
        C.DHKey_free(x)

    def test_py_DHKey(self):
        # Using the wrapper
        dhpy = DHKeys()
        dhpy.gen()
        self.assertEqual( dhpy.size(), 2*32 )
        self.assertEqual( dhpy.pub_size(), 32)
        self.assertEqual( len(dhpy.pub()), 32)
        del dhpy

    def test_raw_BLS(self):
        # Using raw C functions
        b = C.BLSKey_alloc();
        self.assertEqual( C.BLSKey_size(), 96)
        C.BLSKey_keygen(b)
        xbuf = ffi.buffer(b, C.BLSKey_size())
        C.BLSKey_free(b)

    def test_py_BLS(self):
        # Using the wrapper
        blspy = BLSKeys()
        blspy.gen()
        self.assertEqual( blspy.size(), 96)
        self.assertEqual( blspy.pub_size(), 64)
        self.assertEqual( len(blspy.pub()), 64)
        del blspy

    def test_raw_config(self):
        # Using raw C calls
        config = C.Config_alloc(1800, 32, False)
        self.assertEqual( C.Config_dataplain_bytes(config), 16)
        self.assertTrue( type(int(C.Config_current_epoch(config))) == type(0) )
        C.Config_delete(config)

    def test_py_config(self):
        # Using wrapper
        pyconfig = DP5Config(1800, 32, False)
        self.assertEqual(pyconfig.dataplain_bytes(), 16)
        epoch = pyconfig.current_epoch()
        del pyconfig


def _test():

    # libstate = C.Init_init()
    InitLib()

    # print "Start Reg client"
    keys = C.DHKey_alloc();
    config = C.Config_alloc(1800, 32, False)
    C.DHKey_keygen(keys)
    reg = C.RegClient_alloc(config, keys)

    ## Make 10 budies and create a buffer 
    # data buffer for them. This is the first
    # Python heavy lifting.
    friends_num = 10
    PKl = C.DHKey_pubsize()
    Dl = C.Config_dataplain_bytes(config)
    RECl = PKl + Dl
    data = ffi.new("char[]", friends_num*RECl)
    datab = ffi.buffer(data)
    print "Creating buddies"

    for x in range(friends_num):
        fk_p = C.DHKey_alloc()
        fk = ffi.buffer(fk_p, C.DHKey_size())
        datab[x*RECl:x*RECl+PKl] = fk[:PKl]
        d = str(0x99) + "Hello"
        d = d + str(0x00) * (Dl - len(d))
        datab[x*RECl+PKl:(x+1)*RECl] = d
        C.DHKey_free(fk_p)

    def callbackbuffer():
        datax = []

        @ffi.callback("void(size_t, void*)")
        def process_buffer(i, buf):
            mem = ffi.new("char[]", i)
            nbuf = ffi.buffer(mem)
            nbuf[:] = ffi.buffer(buf, i)[:] 
            datax.append((i, mem))

        return datax, process_buffer


    datax, process_buffer = callbackbuffer()

    epoch = C.Config_current_epoch(config)
    err = C.RegClient_start(
        reg, config, epoch,
        friends_num, data, 
        process_buffer)
    assert int(err) == 0
    # assert err == 0x00
    print len(datax[0])

    import os
    try:
        os.mkdir("regdirpy")
        os.mkdir("datadirpy")
    except Exception, e:
        print "Ignore", e

    server = C.RegServer_alloc(config, epoch, "regdirpy", "datadirpy")


    (lmem, mem) = datax[0]
    C.RegServer_register(server, lmem, mem, process_buffer)

    (lmem, mem) = datax[1]
    C.RegClient_complete(reg, epoch, lmem, mem)

    e = C.RegServer_epoch_change(server, "metadatapy.dat", "datapy.dat")

    # C.Init_cleanup(libstate)
    # FreeLib()


if __name__ == "__main__":
    _test()
    unittest.main()
    