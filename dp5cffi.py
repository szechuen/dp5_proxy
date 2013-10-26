from cffi import FFI
ffi = FFI()
ffi.cdef("""


    // Native buffer interface

    typedef struct {
    size_t len;
    char * buf;
    } nativebuffer;

    void nativebuffer_purge(nativebuffer buf);

    /* Init functions */

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
        nativebuffer buf);

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
        nativebuffer data,
        void processbuf(size_t, const void*));

    unsigned int RegServer_epoch_change(
        DP5RegServer * reg,
        char * metadata,
        char * data);

    typedef struct _DP5CombinedRegClient DP5CombinedRegClient;

    DP5CombinedRegClient * RegClientCB_alloc(BLSKey * keys);

    void RegClientCB_delete(DP5CombinedRegClient * p);

    int RegClientCB_start(
        DP5CombinedRegClient * reg, 
        unsigned int epoch,
        nativebuffer data,
        void processbuf(size_t, const void*));

    int RegClientCB_complete(
        DP5CombinedRegClient * reg,
        unsigned int epoch,
        nativebuffer buffer);



    """)

C = ffi.dlopen("./libdp5clib.so")  

__initLib = False
__libState = None

class NativeBuf:
    def __init__(self, buf):
        
        if len(buf) != 0:
            self.inner = ffi.new("char[]", len(buf))
            b = ffi.buffer(self.inner)
            b[:] = buf[:]

            self.nbuf = ffi.new("nativebuffer *", (len(buf), self.inner))
        else:
            self.nbuf = ffi.new("nativebuffer *", (0, ffi.NULL))

    def get(self):
        return self.nbuf[0]

    def get_ptr(self):
        return self.nbuf

    def len(self):
        return self.nbuf[0].len

def callbackbuffer():
    datax = []

    @ffi.callback("void(size_t, void*)")
    def process_buffer(i, buf):
        data = str(ffi.buffer(buf, i)[:])
        datax.append(data)

    return datax, process_buffer


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